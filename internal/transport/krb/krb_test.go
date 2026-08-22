package krb

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/krberror"
	"github.com/jcmturner/gokrb5/v8/messages"
)

// The realm and principal below are synthetic. Nothing in this package's
// tests may name a real realm, host, or account — the integration test
// takes those from the environment.
const (
	testRealm     = "EXAMPLE.TEST"
	testPrincipal = "svc-opengpm"
)

// kdcRefused is how gokrb5 renders a KDC that answered with a KRB_ERROR.
// The type is erased on the way up: client/ASExchange.go hands the
// messages.KRBError to krberror.Errorf, which has no Unwrap and formats
// non-Krberror causes with %s. classify therefore cannot rely on
// errors.As here — this is the shape it will actually be given.
func kdcRefused(code int32) error {
	return krberror.Errorf(
		messages.KRBError{ErrorCode: code, Realm: testRealm},
		krberror.KDCError,
		"AS Exchange Error: kerberos error response from KDC",
	)
}

// decryptFailed is client/ASExchange.go's AS_REP verification path: the
// decrypt error from messages/KDCRep.go, wrapped by ASRep.Verify and then
// by ASExchange. The outermost text is the misleading one SPIKE-T00.md
// warns about — it blames the password for what is often a KVNO label.
func decryptFailed(cause error) error {
	e := krberror.Errorf(cause, krberror.DecryptingError, "error decrypting AS_REP encrypted part")
	e = krberror.Errorf(e, krberror.DecryptingError, "error decrypting EncPart of AS_REP")
	return krberror.Errorf(e, krberror.KRBMsgError, "AS Exchange Error: AS_REP is not valid or client password/keytab incorrect")
}

// noKeytabEntry is keytab.Keytab.GetEncryptionKey's miss. gokrb5 matches
// keytab entries by KVNO exactly, so a keytab whose label is stale relative
// to the KDC misses here even though its key material is current.
func noKeytabEntry(kvno int) error {
	return fmt.Errorf("matching key not found in keytab. Looking for %q realm: %v kvno: %v etype: %v", testPrincipal, testRealm, kvno, 18)
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want error
	}{
		{
			name: "clock skew reported by the KDC",
			err:  kdcRefused(errorcode.KRB_AP_ERR_SKEW),
			want: ErrClockSkew,
		},
		{
			name: "clock skew as a bare KRBError",
			err:  messages.KRBError{ErrorCode: errorcode.KRB_AP_ERR_SKEW, Realm: testRealm},
			want: ErrClockSkew,
		},
		{
			name: "no KDC answered on either transport",
			err: krberror.Errorf(
				fmt.Errorf("failed to communicate with KDC. Attempts made with UDP (%v) and then TCP (%v)",
					"error sending to a KDC: error sending to (kdc:88): dial udp: connect: connection refused",
					"error sending to a KDC: error sending to KDC (kdc:88): dial tcp: connect: connection refused"),
				krberror.NetworkingError, "AS Exchange Error: failed sending AS_REQ to KDC"),
			want: ErrKDCUnreachable,
		},
		{
			name: "KDC dial timed out",
			err: krberror.Errorf(
				&net.OpError{Op: "dial", Net: "tcp", Err: errors.New("i/o timeout")},
				krberror.NetworkingError, "AS Exchange Error: failed sending AS_REQ to KDC"),
			want: ErrKDCUnreachable,
		},
		{
			name: "keytab has no entry for the key version the KDC used",
			err:  decryptFailed(noKeytabEntry(7)),
			want: ErrStaleKVNO,
		},
		{
			name: "KDC reports the key version is unavailable",
			err:  kdcRefused(errorcode.KRB_AP_ERR_BADKEYVER),
			want: ErrStaleKVNO,
		},
		{
			name: "key material is wrong so the integrity check fails",
			err:  decryptFailed(errors.New("error decrypting: integrity verification failed")),
			want: ErrBadKey,
		},
		{
			name: "KDC rejected pre-authentication",
			err:  kdcRefused(errorcode.KDC_ERR_PREAUTH_FAILED),
			want: ErrBadKey,
		},
		{
			name: "KDC reports a failed integrity check",
			err:  kdcRefused(errorcode.KRB_AP_ERR_BAD_INTEGRITY),
			want: ErrBadKey,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classify(tc.err)
			if got == nil {
				t.Fatalf("classify(%v) = nil, want %v", tc.err, tc.want)
			}
			if !errors.Is(got, tc.want) {
				t.Fatalf("classify(%v)\n got: %v\nwant: matching %v", tc.err, got, tc.want)
			}
			// The sentinel's remediation text is the deliverable (PLAN §5).
			// Matching the sentinel while reporting something generic to the
			// operator would pass errors.Is and still earn the support queue.
			if !strings.Contains(got.Error(), tc.want.Error()) {
				t.Errorf("classified error does not carry the sentinel's remediation text\n got: %q\nwant it to contain: %q", got, tc.want)
			}
		})
	}
}

func TestClassifyNil(t *testing.T) {
	if err := classify(nil); err != nil {
		t.Fatalf("classify(nil) = %v, want nil", err)
	}
}

// An unrecognised cause must not be dressed up as one of the four known
// failures. Reporting the wrong knob is worse than reporting none.
func TestClassifyDoesNotGuess(t *testing.T) {
	got := classify(errors.New("krb5: unrelated failure nobody has seen before"))
	if got == nil {
		t.Fatal("classify(unknown) = nil, want an error")
	}
	for _, s := range []error{ErrClockSkew, ErrKDCUnreachable, ErrBadKey, ErrStaleKVNO} {
		if errors.Is(got, s) {
			t.Errorf("classify(unknown) matched %v", s)
		}
	}
}

// The sentinels are the ticket's deliverable, so pin what each one has to
// tell an operator. Each must name the thing to go and change.
func TestSentinelsAreActionable(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		mention []string
	}{
		{"ErrClockSkew", ErrClockSkew, []string{"clock", "skew", "5 minutes"}},
		{"ErrKDCUnreachable", ErrKDCUnreachable, []string{"KDC", "88", "KRB5_CONFIG"}},
		{"ErrBadKey", ErrBadKey, []string{"keytab", "re-export"}},
		{"ErrStaleKVNO", ErrStaleKVNO, []string{"KVNO", "keytab"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.err.Error()
			if !strings.HasPrefix(msg, "krb: ") {
				t.Errorf("%s = %q, want a %q prefix", tc.name, msg, "krb: ")
			}
			for _, m := range tc.mention {
				if !strings.Contains(msg, m) {
					t.Errorf("%s = %q, want it to mention %q", tc.name, msg, m)
				}
			}
			// "authentication failed" is precisely the non-answer this
			// ticket exists to prevent.
			if strings.Contains(strings.ToLower(msg), "auth failed") ||
				strings.Contains(strings.ToLower(msg), "authentication failed") {
				t.Errorf("%s = %q, which is the generic failure the ticket forbids", tc.name, msg)
			}
		})
	}
}

func TestSentinelsAreDistinct(t *testing.T) {
	all := []error{ErrClockSkew, ErrKDCUnreachable, ErrBadKey, ErrStaleKVNO}
	for i, a := range all {
		for j, b := range all {
			if i != j && errors.Is(a, b) {
				t.Errorf("sentinel %d matches sentinel %d; they must be tellable apart", i, j)
			}
		}
	}
}

// The single retry needs the KDC's own key version to relabel the keytab
// entry with (SPIKE-T00.md), so recovering it is testable without a KDC.
func TestKDCKVNO(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantKVNO int
		wantOK   bool
	}{
		{"from the keytab miss", noKeytabEntry(7), 7, true},
		{"through gokrb5's wrapping", decryptFailed(noKeytabEntry(12)), 12, true},
		{"multi-digit", noKeytabEntry(105), 105, true},
		{"no KVNO in the error", errors.New("dial tcp: connection refused"), 0, false},
		{"wrong key, not a stale label", decryptFailed(errors.New("error decrypting: integrity verification failed")), 0, false},
		{"nil", nil, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kvno, ok := kdcKVNO(tc.err)
			if ok != tc.wantOK || kvno != tc.wantKVNO {
				t.Fatalf("kdcKVNO(%v) = (%d, %t), want (%d, %t)", tc.err, kvno, ok, tc.wantKVNO, tc.wantOK)
			}
		})
	}
}

// Reading the keytab happens before anything touches the network, so this
// path is unit-testable. An operator who mounted the secret at the wrong
// path needs to be told which path was tried.
func TestFromKeytabMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.keytab")
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("test setup: %s should not exist", path)
	}
	_, err := FromKeytab(path, testPrincipal, testRealm)
	if err == nil {
		t.Fatal("FromKeytab with a missing keytab = nil error, want an error")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("FromKeytab error = %q, want it to name the keytab path %q", err, path)
	}
}

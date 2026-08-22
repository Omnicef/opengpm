// Package krb obtains and holds a Kerberos TGT sourced from a keytab.
//
// Both Kerberos consumers in OpenGPM — the LDAP GSSAPI bind (D-01) and the
// SMB session (T-03, cloudsoda/go-smb2) — take their client from here, so
// there is one keytab, one TGT and one clock-skew code path. SPIKE-T00.md
// established that both consume jcmturner/gokrb5/v8 *client.Client; the
// BACKLOG's "gssapi.Client" is indicative, not literal.
package krb

import (
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/krberror"
)

// The failure modes an operator must be able to tell apart on first run.
//
// Kerberos startup failures are operational, not logical (BACKLOG T-01,
// PLAN §5): the operator needs to know which knob to turn. gokrb5's native
// errors do not say — a stale keytab KVNO reports as "AS_REP is not valid
// or client password/keytab incorrect", which sends people to reset a
// password that was never wrong (SPIKE-T00.md). So FromKeytab classifies
// every gokrb5 failure into one of these sentinels and never returns a
// bare wrapped gokrb5 error.
//
// These message strings are part of the contract, not decoration. They are
// the ticket's deliverable and the unit tests pin them.
var (
	// ErrClockSkew is the KDC reporting KRB_AP_ERR_SKEW. Containers inherit
	// host clock problems and Kerberos dies past ~5 minutes of drift, which
	// PLAN §5 expects to be the single most common support issue.
	ErrClockSkew = errors.New("krb: clock skew between this host and the KDC exceeds the Kerberos tolerance of 5 minutes; synchronise this container's clock with the domain controller")

	// ErrKDCUnreachable is a transport failure reaching any KDC for the
	// realm, as distinct from a KDC that answered and refused.
	ErrKDCUnreachable = errors.New("krb: no KDC for the realm could be reached; check DNS SRV resolution, egress to TCP and UDP port 88, and the kdc entries in the file named by KRB5_CONFIG")

	// ErrBadKey is the KDC rejecting the key material itself: the keytab
	// holds a key for a password the account no longer has, or for the
	// wrong principal.
	ErrBadKey = errors.New("krb: the KDC rejected the keytab's key; the key material does not match the account's current password, or the principal in the keytab is not the one requested — re-export the keytab")

	// ErrStaleKVNO is the SPIKE-T00 defect: key material is current but the
	// keytab's KVNO label is not, and gokrb5 matches keytab entries by KVNO
	// exactly. FromKeytab retries once relabelled to the KDC's KVNO before
	// returning this.
	ErrStaleKVNO = errors.New("krb: the keytab's KVNO label does not match the key version the KDC issued; re-export the keytab from the DC, or relabel its entries with the KDC's KVNO")
)

// KDC refusals whose error code names the knob to turn. gokrb5 renders the
// code through errorcode.Lookup whether the KRBError reaches us typed or
// already flattened into a Krberror's text, so matching that rendering
// covers both shapes without depending on errors.As reaching through a
// wrapper that has no Unwrap.
var kdcCodes = map[int32]error{
	errorcode.KRB_AP_ERR_SKEW:          ErrClockSkew,
	errorcode.KRB_AP_ERR_BADKEYVER:     ErrStaleKVNO,
	errorcode.KDC_ERR_PREAUTH_FAILED:   ErrBadKey,
	errorcode.KRB_AP_ERR_BAD_INTEGRITY: ErrBadKey,
}

// keytabMiss is keytab.Keytab.GetEncryptionKey's miss text. The KVNO it
// reports is the one the KDC put in the AS_REP's EncPart, i.e. the live key
// version, which is what the retry relabels the keytab entries to.
var keytabMiss = regexp.MustCompile(`matching key not found in keytab.*kvno: (\d+)`)

// Client is an authenticated Kerberos context sourced from a keytab.
type Client struct {
	gss *client.Client
}

// FromKeytab loads the keytab at path, obtains a TGT for principal@realm
// and returns a Client. Realm-to-KDC resolution comes from the krb5.conf
// named by KRB5_CONFIG.
//
// It retries the exchange once if the KDC reports a key version the keytab
// labels differently, relabelling the keytab entry to the KDC's KVNO
// (SPIKE-T00.md).
//
// Every failure is reported through classify, so the returned error always
// satisfies errors.Is against one of this package's sentinels where the
// cause is recognised.
func FromKeytab(path, principal, realm string) (*Client, error) {
	kt, err := keytab.Load(path)
	if err != nil {
		return nil, fmt.Errorf("krb: reading the keytab at %s: %w", path, err)
	}
	confPath := os.Getenv("KRB5_CONFIG")
	if confPath == "" {
		confPath = "/etc/krb5.conf"
	}
	conf, err := config.Load(confPath)
	if err != nil {
		return nil, fmt.Errorf("krb: reading the Kerberos configuration at %s (set KRB5_CONFIG to point elsewhere): %w", confPath, err)
	}

	// The keytab and the caller may both spell the principal with its realm;
	// gokrb5 wants the bare name and the realm separately.
	name, _, _ := strings.Cut(principal, "@")

	// DisablePAFXFAST because Active Directory does not answer gokrb5's
	// PA_REQ_ENC_PA_REP, and its silence fails AS_REP verification as
	// "KDC did not respond appropriately to FAST negotiation" — another
	// misleading first-run error. Encrypted-timestamp pre-authentication is
	// unaffected; only the encrypted-PA-REP negotiation is dropped.
	//
	// Login establishes the TGT session, and gokrb5's addSession starts the
	// goroutine that refreshes it at five sixths of its lifetime, so a
	// long-lived Client keeps a live TGT with nothing further from us.
	cl := client.NewWithKeytab(name, realm, kt, conf, client.DisablePAFXFAST(true))
	err = cl.Login()

	// SPIKE-T00's defect: the key material is current but the keytab's KVNO
	// label is behind the KDC, and gokrb5 matches entries by KVNO exactly.
	// Relabel to the version the KDC just used and try once more. Keys and
	// etypes are untouched, so this cannot turn a wrong key into a login.
	//
	// The bounds restate what kdcKVNO already guarantees; they are here so
	// the conversions below are provably in range at the point of use rather
	// than one function away, which is the only form gosec G115 accepts.
	if kvno, ok := kdcKVNO(err); ok && kvno > 0 && int64(kvno) <= math.MaxUint32 {
		for i := range kt.Entries {
			kt.Entries[i].KVNO = uint32(kvno)
			if kvno <= math.MaxUint8 {
				kt.Entries[i].KVNO8 = uint8(kvno)
			}
		}
		err = cl.Login()
	}
	if err != nil {
		return nil, classify(err)
	}
	return &Client{gss: cl}, nil
}

// GSSAPIClient returns the underlying gokrb5 client that the LDAP bind
// (D-01) and the SMB session (T-03) consume.
func (c *Client) GSSAPIClient() *client.Client {
	return c.gss
}

// classify maps a gokrb5 failure onto one of this package's sentinels,
// wrapping err so the native text stays available to logs. It returns nil
// for a nil error, and for a cause it does not recognise it returns an
// error that matches no sentinel — never a bare wrap presented as an
// answer.
//
// It is deliberately a pure function of the error value: the live failure
// modes need a deliberately broken KDC and belong to V-03, so this is the
// seam that makes them testable without one.
//
// gokrb5 loses type information on the way up — client/network.go formats
// nested errors with %v — so classify must recognise both the typed errors
// (messages.KRBError, krberror.Krberror, net.Error) and their rendered
// strings.
func classify(err error) error {
	if err == nil {
		return nil
	}
	msg := err.Error()

	// The KDC answered and refused, and said why.
	for code, sentinel := range kdcCodes {
		if strings.Contains(msg, errorcode.Lookup(code)) {
			return fmt.Errorf("%w [%v]", sentinel, err)
		}
	}

	switch {
	// The keytab held no entry for the key version the KDC used. Reaching
	// classify means the relabelled retry did not fix it either.
	case keytabMiss.MatchString(msg):
		return fmt.Errorf("%w [%v]", ErrStaleKVNO, err)

	// No entry at all for the principal or etype asked for, rather than a
	// version mismatch — the keytab is for the wrong account.
	case strings.Contains(msg, "matching key not found in keytab"):
		return fmt.Errorf("%w [%v]", ErrBadKey, err)

	// The entry was found and its key did not decrypt the AS_REP.
	case strings.Contains(msg, "integrity verification failed"):
		return fmt.Errorf("%w [%v]", ErrBadKey, err)

	case isNetworkError(err) || strings.Contains(msg, krberror.NetworkingError):
		return fmt.Errorf("%w [%v]", ErrKDCUnreachable, err)
	}

	// Naming the wrong knob is worse than naming none.
	return fmt.Errorf("krb: Kerberos login failed for a reason this package does not recognise, so it has no remediation to offer: %w", err)
}

func isNetworkError(err error) bool {
	var nerr net.Error
	return errors.As(err, &nerr)
}

// kdcKVNO reports the key version number the KDC used, recovered from a
// decrypt failure, so FromKeytab can relabel the keytab entry for its
// single retry. ok is false when err carries no KVNO, or carries one the
// keytab's uint32 KVNO field cannot hold.
func kdcKVNO(err error) (kvno int, ok bool) {
	if err == nil {
		return 0, false
	}
	m := keytabMiss.FindStringSubmatch(err.Error())
	if m == nil {
		return 0, false
	}
	// ParseUint's 32-bit size rejects an arbitrarily long digit run rather
	// than letting it truncate silently into the keytab's uint32 KVNO.
	//
	// GetEncryptionKey treats a zero KVNO as "any version", so a miss at
	// zero is not a stale label and relabelling to it would match nothing.
	v, cerr := strconv.ParseUint(m[1], 10, 32)
	if cerr != nil || v == 0 {
		return 0, false
	}
	return int(v), true
}

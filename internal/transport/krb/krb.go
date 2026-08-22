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

	"github.com/jcmturner/gokrb5/v8/client"
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

// errNotImplemented marks the contract stubs. The implementation session
// (T-01) removes it; the unit tests are expected to fail against it.
var errNotImplemented = errors.New("krb: not implemented")

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
	return nil, errNotImplemented
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
	return errNotImplemented
}

// kdcKVNO reports the key version number the KDC used, recovered from a
// decrypt failure, so FromKeytab can relabel the keytab entry for its
// single retry. ok is false when err carries no KVNO.
func kdcKVNO(err error) (kvno int, ok bool) {
	return 0, false
}

// Package ldapx binds to one pinned domain controller and searches it.
//
// It does no Kerberos of its own. The GSSAPI/SPNEGO bind authenticates with
// the *client.Client that krb.Client.GSSAPIClient() hands over (T-01),
// which go-ldap's own ldap/v3/gssapi.Client accepts directly — it is pure
// Go over gokrb5 and embeds *client.Client as an exported field, so there
// is no second keytab, no second TGT and no second place that sets
// Kerberos options (SPIKE-T00.md, and krb's package comment).
//
// The connection is pinned to ONE domain controller (PLAN §4.1) and DC
// reports which, so smbx can mount SYSVOL from the same replica. Reading
// the GPC from one DC and the GPT from another turns replication lag into
// false "AD and SYSVOL are out of sync" alerts on the flagship health
// check.
//
// # The protected channel
//
// D-01 asks for a GSSAPI bind with sign+seal "so the channel is encrypted
// without a cert". go-ldap cannot do that and says so twice: bind.go
// carries "NOTE: SASL security layers are not supported currently", and
// ldap/v3/gssapi's NegotiateSaslAuth hardcodes the client's selected layer
// to zero under the comment "We never want a security layer". A GSSAPI
// bind therefore proves who we are and leaves everything after the bind in
// the clear. There is no option to flip; the layer would mean wrapping and
// unwrapping every LDAP message, and go-ldap exposes no seam for it.
//
// So encryption comes from TLS, which is what PLAN §5 asks for anyway
// ("LDAPS with a mounted CA bundle"): set Config.TLS and Dial speaks
// ldaps://, whatever the bind. GSSAPI supplies the identity, TLS supplies
// the channel.
package ldapx

import (
	"context"
	"crypto/tls"
	"errors"

	"github.com/go-ldap/ldap/v3"
	"github.com/jcmturner/gokrb5/v8/client"
)

// The refusals a config can earn before anything is dialed. Dial validates
// first and connects second: a config that cannot produce a protected
// channel must fail without a packet leaving the process, so these are
// reachable — and tested — with no network at all.
var (
	// ErrNoDC is an empty Config.DC. There is no fallback to a domain name
	// here: resolving one would let DNS round-robin choose a different
	// replica per connection, which is the failure §4.1 pins against.
	ErrNoDC = errors.New("ldapx: Config.DC is empty; the pinned domain controller is the only host this package dials")

	// ErrNoCredentials is a config with neither a Kerberos client nor a
	// simple-bind DN and password. Anonymous binds read nothing useful and
	// hide a misconfiguration behind an empty result set.
	ErrNoCredentials = errors.New("ldapx: Config has neither Krb nor BindDN and Password; set Krb from krb.Client.GSSAPIClient(), or supply the service account's DN and password for the LDAPS fallback")

	// ErrPlaintext is a simple bind with no TLS, which would put the
	// service account's password on the wire in the clear — the one thing
	// PLAN §5 names outright. The fallback is a simple bind over LDAPS, not
	// a simple bind.
	ErrPlaintext = errors.New("ldapx: refusing a simple bind without TLS; the password would cross the network in the clear, so the fallback path requires Config.TLS and the mounted CA bundle (PLAN §5)")
)

// Config is what Dial needs to reach one domain controller.
type Config struct {
	// DC is the host of the pinned domain controller (T-02's choice,
	// §4.1). It is the only host this package dials.
	DC string

	// Krb is the Kerberos client from krb.Client.GSSAPIClient(). When it is
	// set the bind is GSSAPI/SPNEGO and no password is needed. ldapx adds
	// no Kerberos options of its own.
	Krb *client.Client

	// BindDN and Password are the documented fallback (§5): a service
	// account simple bind, which is refused unless TLS is set. They are
	// ignored when Krb is set.
	BindDN   string
	Password string

	// TLS carries the mounted CA bundle. Non-nil selects ldaps://; nil
	// selects ldap://, which is permitted only for the GSSAPI bind, where
	// no secret crosses the connection.
	//
	// ponytail: the GSSAPI-over-389 case still exposes policy content to a
	// passive observer, because go-ldap negotiates no SASL security layer
	// (see the package comment). Supply TLS wherever the DC serves LDAPS;
	// the ceiling lifts only if go-ldap grows the security layer.
	TLS *tls.Config
}

// searcher is the part of *ldap.Conn that SearchSD uses, so the control it
// attaches can be asserted without a domain controller — the same seam, for
// the same reason, as transport.Resolver in DiscoverDCs.
//
// This is part of the contract, not an implementation detail: the unit
// tests build a Conn around a recording searcher, so Conn must keep holding
// its connection through this interface.
type searcher interface {
	Search(req *ldap.SearchRequest) (*ldap.SearchResult, error)
}

// Conn is a bound LDAP connection to one pinned domain controller.
type Conn struct {
	dc   string
	conn searcher
}

// Dial connects to cfg.DC and binds.
//
// The bind is GSSAPI/SPNEGO when cfg.Krb is set, and a simple bind with
// cfg.BindDN and cfg.Password otherwise. cfg.TLS selects ldaps://:636 over
// ldap://:389; a simple bind without it is refused with ErrPlaintext, as is
// an empty cfg.DC with ErrNoDC and a credential-less config with
// ErrNoCredentials. Validation happens before the connection, so a refused
// config never touches the network.
//
// The service principal to request is "ldap/<cfg.DC>": the pinned host,
// never a domain name.
func Dial(cfg Config) (*Conn, error) {
	return nil, errors.New("ldapx: Dial: not implemented")
}

// DC reports the domain controller this Conn is bound to, so the SYSVOL
// read (T-03) can mount the same replica (§4.1).
func (c *Conn) DC() string {
	return ""
}

// Close unbinds and closes the connection.
func (c *Conn) Close() error {
	return errors.New("ldapx: Close: not implemented")
}

// SearchSD searches base with filter for attrs, requesting security
// descriptors in the form a low-privilege account can actually read.
//
// It MUST attach the LDAP_SERVER_SD_FLAGS_OID control, OID
// "1.2.840.113556.1.4.801", whose value is the BER encoding of
//
//	SEQUENCE { INTEGER flags }
//
// with flags = OWNER(0x1) | GROUP(0x2) | DACL(0x4) = 0x7 — and NOT
// SACL(0x8), which would make flags 0xF.
//
// This is the §4.6 trap and the reason D-01 is not a green ticket. Reading
// the SACL needs SeSecurityPrivilege, which svc-opengpm does not have and
// must not be given. Ask for it, or omit the control entirely and let AD
// default, and AD does not fail the search: it returns the entries with
// nTSecurityDescriptor SILENTLY ABSENT. Security filtering and delegation
// then read as "no data" rather than as an error, for exactly the
// least-privilege account this product is designed to run as.
//
// So the control is unconditional. It is attached whether or not attrs
// names nTSecurityDescriptor, because a caller that asks for the SD and
// does not get it has no way to tell the difference from a GPO that has
// none.
//
// ctx bounds the search.
func (c *Conn) SearchSD(ctx context.Context, base, filter string, attrs []string) ([]*ldap.Entry, error) {
	return nil, errors.New("ldapx: SearchSD: not implemented")
}

// dialURL reports the URL Dial connects to, pinned to cfg.DC.
//
// It is "ldaps://<DC>:636" when cfg.TLS is set and "ldap://<DC>:389" when
// it is not, with the host written by net.JoinHostPort so that a literal
// IPv6 DC is bracketed. It returns ErrNoDC for an empty host and
// ErrPlaintext for the one combination that would send a password in the
// clear.
func dialURL(cfg Config) (string, error) {
	return "", errors.New("ldapx: dialURL: not implemented")
}

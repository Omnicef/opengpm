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
// # There is no cleartext path
//
// Every connection this package makes is LDAPS. Not preferably, not by
// default — there is no field that selects otherwise and no port 389 in the
// code.
//
// That is not the shape D-01 first described, which asked for a GSSAPI bind
// with sign+seal "so the channel is encrypted without a cert". go-ldap
// cannot do that, and says so twice: bind.go carries "NOTE: SASL security
// layers are not supported currently", and ldap/v3/gssapi's
// NegotiateSaslAuth hardcodes the client's selected layer to zero under the
// comment "We never want a security layer". There is no option to flip; the
// layer would mean wrapping and unwrapping every LDAP message, and go-ldap
// exposes no seam for it. A GSSAPI bind proves who we are and encrypts
// nothing.
//
// PLAN §5 requires refusing plaintext LDAP entirely, and it means the data
// and not merely the password: what this tool reads IS the domain's
// security posture, so GPO content, ACLs and security filtering crossing a
// network in the clear is the disclosure the product exists to analyse.
// So GSSAPI supplies the identity and TLS supplies the channel: the bind,
// whichever it is, happens over an ldaps:// connection verified against the
// mounted CA bundle in Config.CACert. A config without one is refused with
// ErrPlaintext rather than downgraded, and the certificate is verified
// properly — nothing in this package sets InsecureSkipVerify.
package ldapx

import (
	"context"
	"crypto/tls"
	"errors"

	"github.com/go-ldap/ldap/v3"
	"github.com/jcmturner/gokrb5/v8/client"
)

// The refusals a config can earn before anything is dialed. Dial validates
// first and connects second: a config that cannot produce a verified,
// encrypted channel must fail without a packet leaving the process, so
// these are reachable — and tested — with no network at all.
var (
	// ErrNoDC is an empty Config.DC. There is no fallback to a domain name
	// here: resolving one would let DNS round-robin choose a different
	// replica per connection, which is the failure §4.1 pins against.
	ErrNoDC = errors.New("ldapx: Config.DC is empty; the pinned domain controller is the only host this package dials")

	// ErrNoCredentials is a config with neither a Kerberos client nor a
	// simple-bind DN and password. Anonymous binds read nothing useful and
	// hide a misconfiguration behind an empty result set.
	ErrNoCredentials = errors.New("ldapx: Config has neither Krb nor BindDN and Password; set Krb from krb.Client.GSSAPIClient(), or supply the service account's DN and password for the simple-bind fallback")

	// ErrPlaintext is a config with no CA bundle. It applies to both binds
	// alike: GSSAPI authenticates without encrypting, so a GSSAPI config
	// without TLS is exactly as much of a cleartext connection as a simple
	// bind without TLS, and this package will not open either.
	ErrPlaintext = errors.New("ldapx: Config.CACert is empty; every bind runs over LDAPS and there is no cleartext fallback, so mount the CA bundle that verifies the domain controller's certificate (PLAN §5)")
)

// Config is what Dial needs to reach one domain controller.
type Config struct {
	// DC is the host of the pinned domain controller (T-02's choice,
	// §4.1). It is the only host this package dials, and it is also the
	// name the DC's certificate is verified against, so it must be the
	// name in that certificate rather than an address or an alias.
	DC string

	// Krb is the Kerberos client from krb.Client.GSSAPIClient(). When it is
	// set the bind is GSSAPI/SPNEGO and no password is needed. ldapx adds
	// no Kerberos options of its own.
	//
	// It supplies identity only. The encryption comes from LDAPS either
	// way; see the package comment.
	Krb *client.Client

	// BindDN and Password are the documented fallback (§5): a service
	// account simple bind, over the same LDAPS connection. They are
	// ignored when Krb is set.
	BindDN   string
	Password string

	// CACert is the path to the mounted PEM bundle that verifies the
	// domain controller's LDAPS certificate. It is required — for every
	// bind, not only the simple one — because it is the only thing that
	// encrypts the connection.
	//
	// Note: a bundle is a file rather than a *tls.Config so that there is
	// no field through which a caller can hand in InsecureSkipVerify. The
	// verification posture is this package's, not the caller's.
	CACert string
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

// Conn is a bound LDAPS connection to one pinned domain controller.
type Conn struct {
	dc   string
	conn searcher
}

// Dial connects to cfg.DC over LDAPS and binds.
//
// The bind is GSSAPI/SPNEGO when cfg.Krb is set, and a simple bind with
// cfg.BindDN and cfg.Password otherwise. Both run over the same verified
// TLS connection: a config with no cfg.CACert is refused with ErrPlaintext
// whichever bind it names, an empty cfg.DC with ErrNoDC, and a
// credential-less config with ErrNoCredentials. Validation happens before
// the connection, so a refused config never touches the network.
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
// It is always "ldaps://<DC>:636". There is no scheme selection and no
// plaintext port; the host is written by net.JoinHostPort so that a literal
// IPv6 DC is bracketed. It returns ErrNoDC for an empty host.
func dialURL(cfg Config) (string, error) {
	return "", errors.New("ldapx: dialURL: not implemented")
}

// tlsConfig builds the TLS configuration Dial connects with, from the PEM
// bundle at cfg.CACert.
//
// The returned configuration verifies the domain controller properly:
// RootCAs holds the mounted bundle and nothing else, ServerName is cfg.DC
// so the certificate is checked against the host that was pinned, and
// InsecureSkipVerify is false. There is no argument, field or environment
// variable that changes any of those — a lab without a usable certificate
// is a lab that does not run this code, not a reason to weaken it.
//
// It returns ErrPlaintext for an empty cfg.CACert, and an error naming the
// path for a bundle that cannot be read or holds no certificate. An
// unreadable bundle must never degrade into an empty pool.
func tlsConfig(cfg Config) (*tls.Config, error) {
	return nil, errors.New("ldapx: tlsConfig: not implemented")
}

package ldapx

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/jcmturner/gokrb5/v8/client"
)

// Nothing about a real domain is committed. .test is reserved by RFC 6761
// and cannot resolve, which matters for the Dial tests: those configs must
// be rejected before anything is dialed, so a case that reached the network
// would hang rather than quietly pass.
const (
	testDC       = "dc01.example.test"
	testBaseDN   = "CN=Policies,CN=System,DC=example,DC=test"
	testFilter   = "(objectClass=groupPolicyContainer)"
	svcDN        = "CN=svc-opengpm,CN=Users,DC=example,DC=test"
	testPassword = "hunter2"
)

// kerberosClient stands in for the client krb.Client.GSSAPIClient() hands
// over. It is never used to talk to a KDC: these tests reach only the code
// above the socket, and what matters is that Config.Krb is non-nil, which
// is what selects the GSSAPI path.
var kerberosClient client.Client

// sdFlagsOID is written out here, not imported from the implementation. A
// test that took the OID from the code under test would agree with it about
// a typo; this is the value MS-ADTS names and the value that must go on the
// wire.
const sdFlagsOID = "1.2.840.113556.1.4.801"

// recorder is a searcher that captures the request and answers nothing.
// SearchSD's job at this level is what it puts on the wire, so an empty
// result is a complete answer.
type recorder struct {
	got *ldap.SearchRequest
}

func (r *recorder) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	r.got = req
	return &ldap.SearchResult{}, nil
}

// searchSD runs SearchSD against a recording connection and returns the
// request it built.
func searchSD(t *testing.T, attrs []string) *ldap.SearchRequest {
	t.Helper()
	r := &recorder{}
	c := &Conn{dc: testDC, conn: r}
	if _, err := c.SearchSD(t.Context(), testBaseDN, testFilter, attrs); err != nil {
		t.Fatalf("SearchSD: %v", err)
	}
	if r.got == nil {
		t.Fatal("SearchSD returned without searching")
	}
	return r.got
}

// TestSearchSDRequestsDACLOwnerGroupNotSACL is the load-bearing test of
// this package, and it decodes rather than pattern-matches.
//
// The regression it guards is silent: with the control absent, or present
// but asking for the SACL that svc-opengpm has no privilege to read, AD
// returns the entries and omits nTSecurityDescriptor instead of failing.
// Nothing upstream can tell that from a GPO with no descriptor, so the only
// place this can be caught cheaply is here, on the bytes.
func TestSearchSDRequestsDACLOwnerGroupNotSACL(t *testing.T) {
	req := searchSD(t, []string{"cn", "nTSecurityDescriptor"})

	var found ldap.Control
	for _, c := range req.Controls {
		if c.GetControlType() == sdFlagsOID {
			found = c
		}
	}
	if found == nil {
		t.Fatalf("SearchSD sent %d controls, none with OID %s; without it AD omits nTSecurityDescriptor for a non-admin bind instead of failing the search (PLAN §4.6)", len(req.Controls), sdFlagsOID)
	}

	flags := sdFlags(t, found)
	if flags&0x8 != 0 {
		t.Errorf("SD flags = 0x%x, which requests the SACL; reading the SACL needs SeSecurityPrivilege, which the service account does not have, and AD answers by omitting nTSecurityDescriptor entirely", flags)
	}
	if flags != 0x7 {
		t.Errorf("SD flags = 0x%x, want 0x7 = OWNER(0x1)|GROUP(0x2)|DACL(0x4); 0xF is the wrong answer that looks more thorough", flags)
	}
}

// The control is not conditional on the caller naming the attribute. A
// caller that asks for the SD and does not get one cannot distinguish a
// missing control from a GPO without a descriptor, so there is no config in
// which sending it is wrong.
func TestSearchSDAlwaysSendsTheControl(t *testing.T) {
	for _, attrs := range [][]string{nil, {}, {"cn"}, {"nTSecurityDescriptor"}} {
		req := searchSD(t, attrs)
		var ok bool
		for _, c := range req.Controls {
			ok = ok || c.GetControlType() == sdFlagsOID
		}
		if !ok {
			t.Errorf("SearchSD(attrs=%v) sent no %s control", attrs, sdFlagsOID)
		}
	}
}

// The search itself still has to be the search that was asked for.
func TestSearchSDPassesTheSearchThrough(t *testing.T) {
	attrs := []string{"cn", "nTSecurityDescriptor"}
	req := searchSD(t, attrs)

	if req.BaseDN != testBaseDN {
		t.Errorf("BaseDN = %q, want %q", req.BaseDN, testBaseDN)
	}
	if req.Filter != testFilter {
		t.Errorf("Filter = %q, want %q", req.Filter, testFilter)
	}
	if len(req.Attributes) != len(attrs) {
		t.Fatalf("Attributes = %v, want %v", req.Attributes, attrs)
	}
	for i, a := range attrs {
		if req.Attributes[i] != a {
			t.Errorf("Attributes[%d] = %q, want %q", i, req.Attributes[i], a)
		}
	}
}

// The URL is always LDAPS on 636, pinned to the configured host. There is
// no scheme to select and no plaintext port to fall back to, so what is
// left to get wrong is the host: a domain name here, or a hand-built
// "host:port" that mangles a literal IPv6 address, and the connection is no
// longer pinned to the replica §4.1 chose.
func TestDialURL(t *testing.T) {
	ca := writeCABundle(t)

	tests := []struct {
		name string
		cfg  Config
		want string
		err  error
	}{
		{
			"gssapi bind",
			Config{DC: testDC, Krb: &kerberosClient, CACert: ca},
			"ldaps://" + testDC + ":636",
			nil,
		},
		{
			"simple bind fallback uses the same URL",
			Config{DC: testDC, BindDN: svcDN, Password: testPassword, CACert: ca},
			"ldaps://" + testDC + ":636",
			nil,
		},
		{
			// net.JoinHostPort brackets a literal address; string
			// concatenation does not, and the result parses as a different
			// host entirely.
			"IPv6 DC is bracketed",
			Config{DC: "2001:db8::1", Krb: &kerberosClient, CACert: ca},
			"ldaps://[2001:db8::1]:636",
			nil,
		},
		{
			"no DC is refused",
			Config{Krb: &kerberosClient, CACert: ca},
			"",
			ErrNoDC,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := dialURL(tt.cfg)
			if !errors.Is(err, tt.err) {
				t.Fatalf("dialURL error = %v, want %v", err, tt.err)
			}
			if got != tt.want {
				t.Errorf("dialURL = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestDialRefusesPlaintext is the design change this package is built
// around: TLS is not preferred, it is the only thing there is.
//
// Both binds are listed because the GSSAPI one is the case that looks safe
// and is not. go-ldap negotiates no SASL security layer, so a GSSAPI bind
// authenticates and encrypts nothing — every GPO, ACL and security filter
// this tool reads would cross the network in the clear, which is precisely
// the disclosure PLAN §5 refuses. A config with no CA bundle names no
// connection this package is willing to open, whichever credential it
// carries.
func TestDialRefusesPlaintext(t *testing.T) {
	for _, tt := range []struct {
		name string
		cfg  Config
	}{
		{
			"gssapi without TLS",
			Config{DC: testDC, Krb: &kerberosClient},
		},
		{
			"simple bind without TLS",
			Config{DC: testDC, BindDN: svcDN, Password: testPassword},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, err := Dial(tt.cfg)
			if !errors.Is(err, ErrPlaintext) {
				t.Fatalf("Dial error = %v, want %v", err, ErrPlaintext)
			}
			if c != nil {
				t.Errorf("Dial returned a Conn alongside an error")
			}
		})
	}
}

// The rest of what Dial refuses before it dials. Every case here names a
// host that cannot resolve, so an implementation that validated after
// connecting would fail this rather than pass it slowly.
func TestDialRefuses(t *testing.T) {
	ca := writeCABundle(t)

	tests := []struct {
		name string
		cfg  Config
		want error
	}{
		{
			"no credentials at all",
			Config{DC: testDC, CACert: ca},
			ErrNoCredentials,
		},
		{
			"password without a DN is not a credential",
			Config{DC: testDC, Password: testPassword, CACert: ca},
			ErrNoCredentials,
		},
		{
			"no DC",
			Config{Krb: &kerberosClient, CACert: ca},
			ErrNoDC,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := Dial(tt.cfg)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Dial error = %v, want %v", err, tt.want)
			}
			if c != nil {
				t.Errorf("Dial returned a Conn alongside an error")
			}
		})
	}
}

// The verification posture, pinned field by field.
//
// This is the one that stops the lab shortcut from shipping. Every failure
// to connect to a domain controller over LDAPS looks like a certificate
// problem, and the fix that always works is InsecureSkipVerify — at which
// point the connection is encrypted against whoever answered, the CA bundle
// §5 asks for is decorative, and nothing else in this package notices.
func TestTLSConfig(t *testing.T) {
	ca := writeCABundle(t)

	got, err := tlsConfig(Config{DC: testDC, Krb: &kerberosClient, CACert: ca})
	if err != nil {
		t.Fatalf("tlsConfig: %v", err)
	}
	if got.InsecureSkipVerify {
		t.Error("InsecureSkipVerify is set; the CA bundle is then decorative and the connection is encrypted to whoever answered")
	}
	if got.RootCAs == nil {
		t.Error("RootCAs is nil, so the bundle at Config.CACert was never loaded and the host roots are trusted instead")
	}
	// The certificate has to be checked against the host that was pinned,
	// not against whatever name the dialer happened to derive.
	if got.ServerName != testDC {
		t.Errorf("ServerName = %q, want %q", got.ServerName, testDC)
	}
	if got.MinVersion < tls.VersionTLS12 {
		t.Errorf("MinVersion = 0x%x, want at least TLS 1.2 (0x%x)", got.MinVersion, tls.VersionTLS12)
	}
}

// A bundle that is not there, or is not a bundle, is an error naming the
// path. The failure mode this guards is quieter than it looks: ignoring the
// read leaves an empty pool, which trusts nothing, which surfaces one
// handshake later as an unrelated certificate error.
func TestTLSConfigRejectsUnusableBundle(t *testing.T) {
	junk := filepath.Join(t.TempDir(), "junk.pem")
	if err := os.WriteFile(junk, []byte("this is not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name string
		cfg  Config
		want error
	}{
		{
			"no bundle at all",
			Config{DC: testDC, Krb: &kerberosClient},
			ErrPlaintext,
		},
		{
			"bundle that does not exist",
			Config{DC: testDC, Krb: &kerberosClient, CACert: filepath.Join(t.TempDir(), "absent.pem")},
			nil,
		},
		{
			"bundle holding no certificate",
			Config{DC: testDC, Krb: &kerberosClient, CACert: junk},
			nil,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tlsConfig(tt.cfg)
			if err == nil {
				t.Fatalf("tlsConfig = %+v, want an error", got)
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Fatalf("tlsConfig error = %v, want %v", err, tt.want)
			}
			if tt.cfg.CACert != "" && !strings.Contains(err.Error(), tt.cfg.CACert) {
				t.Errorf("tlsConfig error = %v, want it to name %s", err, tt.cfg.CACert)
			}
		})
	}
}

// writeCABundle writes a PEM file holding one self-signed CA certificate
// and returns its path.
//
// It is generated rather than committed because none of these tests
// handshake with anything: what is being pinned is that the bundle is
// loaded and verification is left on, so any certificate that parses will
// do, and a checked-in one would only acquire an expiry date.
func writeCABundle(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "opengpm test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A live LDAPS simple bind is deliberately not tested here. The selection
// logic — which URL, which bind, which refusal, which verification posture
// — is entirely above the socket and pinned by the tests above. The live
// half would go in integration_test.go beside TestSDFlagsControl.

// sdFlags decodes the flags integer out of an SD flags control, all the way
// from the control's own encoding.
//
// The decode is by hand rather than through the BER library go-ldap uses.
// That is the point: a test that re-used the implementation's decoder would
// happily agree with it about the wrong bytes. These encodings are five
// bytes long and short-form, so a hand parse costs nothing and pins the
// actual wire format.
func sdFlags(t *testing.T, c ldap.Control) int64 {
	t.Helper()

	// Control ::= SEQUENCE { controlType OCTET STRING,
	//                        criticality BOOLEAN DEFAULT FALSE,
	//                        controlValue OCTET STRING OPTIONAL }
	//
	// Encode() is reached without naming its package: the *ber.Packet is
	// only ever a receiver here, so this file needs no BER import.
	outer := tlvs(t, "control", c.Encode().Bytes())
	if len(outer) != 1 || outer[0].tag != 0x30 {
		t.Fatalf("control %s does not encode as a single SEQUENCE: %+v", c.GetControlType(), outer)
	}
	parts := tlvs(t, "control body", outer[0].value)
	if len(parts) == 0 || parts[0].tag != 0x04 {
		t.Fatalf("control %s does not start with an OCTET STRING control type: %+v", c.GetControlType(), parts)
	}
	if got := string(parts[0].value); got != sdFlagsOID {
		t.Fatalf("encoded control type = %q, want %q", got, sdFlagsOID)
	}

	// The value is the OCTET STRING after the control type; criticality, if
	// present at all, sits between them as a BOOLEAN.
	var value []byte
	for _, p := range parts[1:] {
		if p.tag == 0x04 {
			value = p.value
		}
	}
	if value == nil {
		t.Fatalf("control %s carries no value, so it requests no SD flags at all; AD reads that as the default and omits nTSecurityDescriptor for a non-admin", sdFlagsOID)
	}

	// SDFlagsRequestValue ::= SEQUENCE { Flags INTEGER }
	seq := tlvs(t, "control value", value)
	if len(seq) != 1 || seq[0].tag != 0x30 {
		t.Fatalf("control value is not a single SEQUENCE: %+v", seq)
	}
	inner := tlvs(t, "flags sequence", seq[0].value)
	if len(inner) != 1 || inner[0].tag != 0x02 {
		t.Fatalf("SEQUENCE holds %+v, want exactly one INTEGER", inner)
	}
	if len(inner[0].value) == 0 {
		t.Fatal("flags INTEGER is empty")
	}

	var flags int64
	for _, b := range inner[0].value {
		flags = flags<<8 | int64(b)
	}
	return flags
}

// tlv is one BER element: its tag byte and its raw contents.
type tlv struct {
	tag   byte
	value []byte
}

// tlvs splits a definite-length, short-form BER encoding into its top-level
// elements. Everything it reads here is a handful of bytes, so long-form
// lengths, high tag numbers and indefinite lengths are failures rather than
// features — an SD flags control that needed any of them would not be one.
func tlvs(t *testing.T, what string, b []byte) []tlv {
	t.Helper()
	var out []tlv
	for len(b) > 0 {
		if len(b) < 2 {
			t.Fatalf("%s: truncated element at %d bytes remaining", what, len(b))
		}
		tag, n := b[0], int(b[1])
		if tag&0x1f == 0x1f {
			t.Fatalf("%s: high-tag-number form (0x%x) is not expected here", what, tag)
		}
		if n > 0x7f {
			t.Fatalf("%s: long-form or indefinite length (0x%x) is not expected here", what, n)
		}
		if len(b) < 2+n {
			t.Fatalf("%s: element of length %d with only %d bytes left", what, n, len(b)-2)
		}
		out = append(out, tlv{tag: tag, value: b[2 : 2+n]})
		b = b[2+n:]
	}
	return out
}

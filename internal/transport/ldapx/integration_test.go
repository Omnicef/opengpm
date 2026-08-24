//go:build integration

package ldapx_test

import (
	"os"
	"strings"
	"testing"

	"github.com/Omnicef/opengpm/internal/transport/krb"
	"github.com/Omnicef/opengpm/internal/transport/ldapx"
)

// Nothing about the test domain is committed. The set is T-01's, plus the
// two things LDAP needs that Kerberos does not:
//
//   - The DC to bind is OPENGPM_TEST_KDC. Every KDC in Active Directory is
//     a domain controller, and §4.1 requires LDAP and SMB to read the same
//     replica — reusing the variable is the pinning requirement expressed
//     as configuration, exactly as smbx does.
//   - OPENGPM_TEST_CACERT is the PEM bundle that verifies the DC's LDAPS
//     certificate. It is required, not optional: this package has no
//     cleartext path and does not skip verification, so without a bundle
//     there is no connection to make and nothing to test. A lab whose DC
//     serves a self-signed LDAPS certificate points this at that
//     certificate; one behind an enterprise CA points it at the chain.
//   - OPENGPM_TEST_BASEDN overrides the base DN. Without it the realm is
//     converted the obvious way, GPLAB.LOCAL to DC=gplab,DC=local, which is
//     right for every domain whose DN follows its DNS name.
//
// KRB5_CONFIG is required here rather than merely mentioned, as D-01 asks:
// realm-to-KDC resolution comes out of it and a bind that silently used
// /etc/krb5.conf would be testing a different domain than the operator
// configured.
const (
	envKeytab    = "OPENGPM_TEST_KEYTAB"
	envPrincipal = "OPENGPM_TEST_PRINCIPAL"
	envRealm     = "OPENGPM_TEST_REALM"
	envKDC       = "OPENGPM_TEST_KDC"
	envCACert    = "OPENGPM_TEST_CACERT"
	envKrb5Conf  = "KRB5_CONFIG"
	envBaseDN    = "OPENGPM_TEST_BASEDN"
)

type testEnv struct {
	keytab, principal, realm, kdc, caCert string
	baseDN                                string
}

// requireEnv skips unless the whole set is present. A half-configured
// environment is an operator mistake, not a reason to run half a test, so
// the skip message names every variable that is missing.
func requireEnv(t *testing.T) testEnv {
	t.Helper()
	var missing []string
	get := func(k string) string {
		v := os.Getenv(k)
		if v == "" {
			missing = append(missing, k)
		}
		return v
	}
	e := testEnv{
		keytab:    get(envKeytab),
		principal: get(envPrincipal),
		realm:     get(envRealm),
		kdc:       get(envKDC),
		caCert:    get(envCACert),
	}
	get(envKrb5Conf)
	if len(missing) > 0 {
		t.Skipf("no test domain configured; set %s to run", strings.Join(missing, ", "))
	}
	e.baseDN = os.Getenv(envBaseDN)
	if e.baseDN == "" {
		e.baseDN = baseDNFromRealm(e.realm)
	}
	return e
}

// baseDNFromRealm converts GPLAB.LOCAL to DC=gplab,DC=local. AD names the
// Kerberos realm after the DNS domain in upper case, and the default naming
// context follows the same labels; a domain where the two genuinely differ
// sets OPENGPM_TEST_BASEDN.
func baseDNFromRealm(realm string) string {
	labels := strings.Split(strings.ToLower(realm), ".")
	for i, l := range labels {
		labels[i] = "DC=" + l
	}
	return strings.Join(labels, ",")
}

// dial builds the whole stack the product uses: one keytab, one TGT from
// krb (T-01), handed to ldapx as the bind's GSSAPI client. ldapx does no
// Kerberos of its own, so a failure to get a TGT here is a T-01 failure.
//
// The connection is ldaps://<DC>:636, verified against the bundle at
// OPENGPM_TEST_CACERT. GSSAPI supplies the identity and TLS supplies the
// channel, because go-ldap negotiates no SASL security layer and so a
// GSSAPI bind encrypts nothing (see the package comment). Verification is
// real: nothing here or in the package sets InsecureSkipVerify, so a
// handshake failure means the bundle is wrong or the certificate does not
// carry the pinned name — OPENGPM_TEST_KDC has to be the name in the DC's
// certificate. That is a lab to fix, not a check to switch off.
func dial(t *testing.T) (testEnv, *ldapx.Conn) {
	t.Helper()
	e := requireEnv(t)

	k, err := krb.FromKeytab(e.keytab, e.principal, e.realm)
	if err != nil {
		t.Fatalf("krb.FromKeytab(%s, %s, %s): %v", e.keytab, e.principal, e.realm, err)
	}
	c, err := ldapx.Dial(ldapx.Config{DC: e.kdc, Krb: k.GSSAPIClient(), CACert: e.caCert})
	if err != nil {
		t.Fatalf("ldapx.Dial(%s, ca=%s): %v", e.kdc, e.caCert, err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return e, c
}

// TestSDFlagsControl is D-01's Accept command and the empirical proof of
// the whole ticket.
//
// It reads nTSecurityDescriptor off real groupPolicyContainer objects while
// bound as the NON-ADMIN service account. That account has no
// SeSecurityPrivilege, so if SearchSD omits the LDAP_SERVER_SD_FLAGS_OID
// control — or sends it asking for the SACL as well — Active Directory does
// NOT fail this search. It returns exactly these entries with
// nTSecurityDescriptor silently absent, and this test fails at the
// "carries no nTSecurityDescriptor" assertion below. That is the entire
// §4.6 trap, and this is the only place it can be observed for real:
// against a domain admin bind it would pass either way, which is why the
// principal matters more than the assertion.
func TestSDFlagsControl(t *testing.T) {
	e, c := dial(t)

	base := "CN=Policies,CN=System," + e.baseDN
	entries, err := c.SearchSD(t.Context(), base, "(objectClass=groupPolicyContainer)", []string{"cn", "nTSecurityDescriptor"})
	if err != nil {
		t.Fatalf("SearchSD(%s): %v", base, err)
	}
	if len(entries) == 0 {
		// Every domain has at least the Default Domain Policy and the
		// Default Domain Controllers Policy, so an empty answer is a
		// permissions or base DN problem, not a domain without GPOs.
		t.Fatalf("SearchSD(%s) returned no groupPolicyContainer objects; check that %s can read the Policies container", base, e.principal)
	}

	var withSD int
	for _, ent := range entries {
		sd := ent.GetRawAttributeValue("nTSecurityDescriptor")
		if len(sd) == 0 {
			t.Errorf("%s carries no nTSecurityDescriptor; AD omits it rather than erroring when the SD flags control is missing or asks for the SACL (PLAN §4.6)", ent.DN)
			continue
		}
		// A self-relative SECURITY_DESCRIPTOR starts with Revision = 1
		// (MS-DTYP 2.4.6). Checking it separates "we got a descriptor"
		// from "we got some bytes", which is all D-01 owes; parsing the
		// ACEs is F-02's job.
		if sd[0] != 1 {
			t.Errorf("%s: nTSecurityDescriptor revision = %d, want 1", ent.DN, sd[0])
		}
		withSD++
	}
	if withSD == 0 {
		t.Fatalf("none of the %d GPOs under %s returned a security descriptor; that is the signature of the missing SD flags control, which fails for every entry at once", len(entries), base)
	}
}

// The connection is pinned to one named DC and says which, so that smbx can
// mount SYSVOL from the same replica (§4.1). A DC() that answered a domain
// name, an address, or a host:port would each let the SMB side resolve
// somewhere else and turn replication lag into a false version mismatch.
func TestConnDCIsPinned(t *testing.T) {
	e, c := dial(t)

	if got := c.DC(); got != e.kdc {
		t.Errorf("DC() = %q, want %q", got, e.kdc)
	}
}

// Deliberately not here: a live simple bind. It needs the service account's
// password in the environment, a secret this suite would rather not hold
// for a path that shares its connection, its controls and its search with
// the GSSAPI one — everything below the bind is already covered above. The
// selection logic is pinned without a socket by conn_test.go. If the
// fallback ever earns a live test it belongs here: dial with Config{DC,
// BindDN, Password, CACert} and run the same SearchSD assertion, proving
// the fallback carries the SD flags control too.

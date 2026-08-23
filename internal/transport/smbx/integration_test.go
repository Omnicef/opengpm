//go:build integration

package smbx_test

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/Omnicef/opengpm/internal/transport/krb"
	"github.com/Omnicef/opengpm/internal/transport/smbx"
)

// Nothing about the test domain is committed. The set is T-01's, unchanged
// and deliberately not extended:
//
//   - The DC to dial is OPENGPM_TEST_KDC. Every KDC in Active Directory is
//     a domain controller, and §4.1 requires the SMB read to hit the same
//     one the Kerberos and LDAP paths use — reusing the variable is the
//     pinning requirement expressed as configuration.
//   - The UNC domain component is OPENGPM_TEST_REALM lower-cased. AD names
//     the Kerberos realm after the DNS domain in upper case, so the realm
//     is the domain. A domain whose DNS name genuinely differs from its
//     realm would need its own variable; none of the ones this product
//     targets does.
const (
	envKeytab    = "OPENGPM_TEST_KEYTAB"
	envPrincipal = "OPENGPM_TEST_PRINCIPAL"
	envRealm     = "OPENGPM_TEST_REALM"
	envKDC       = "OPENGPM_TEST_KDC"
)

// defaultDomainPolicy is the GUID every AD domain has. It is a constant of
// the product, not a fact about any deployment.
const defaultDomainPolicy = "{31B2F340-016D-11D2-945F-00C04FB984F9}"

type testEnv struct {
	keytab, principal, realm, kdc string
}

// domain is the UNC domain component, which is a name to resolve and not
// the host smbx dials — that is e.kdc, and the difference is the whole
// point of dialTarget.
func (e testEnv) domain() string { return strings.ToLower(e.realm) }

// sysvolPath spells a path under the domain's SYSVOL the way
// gPCFileSysPath does, backslashes included.
func (e testEnv) sysvolPath(elem ...string) string {
	d := e.domain()
	return `\\` + d + `\SysVol\` + d + `\` + strings.Join(elem, `\`)
}

// requireEnv skips unless the whole set is present. A half-configured
// environment is an operator mistake, not a reason to run half a test, so
// the skip message names every variable.
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
	}
	if len(missing) > 0 {
		t.Skipf("no test domain configured; set %s (and KRB5_CONFIG) to run", strings.Join(missing, ", "))
	}
	return e
}

// dial builds the whole stack the product uses: one keytab, one TGT from
// krb (T-01), handed to smbx as the SMB session's initiator. smbx does no
// Kerberos of its own, so a failure here is a T-01 failure.
func dial(t *testing.T) (testEnv, *smbx.Client) {
	t.Helper()
	e := requireEnv(t)

	k, err := krb.FromKeytab(e.keytab, e.principal, e.realm)
	if err != nil {
		t.Fatalf("krb.FromKeytab(%s, %s, %s): %v", e.keytab, e.principal, e.realm, err)
	}
	c, err := smbx.Dial(t.Context(), smbx.Config{DC: e.kdc, Krb: k.GSSAPIClient()})
	if err != nil {
		t.Fatalf("smbx.Dial(%s): %v", e.kdc, err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return e, c
}

// The file the T-00 spike read: the Default Domain Policy's GPT.INI, which
// exists in every domain and whose Version= is the value §4.1's mismatch
// check compares against the GPC's versionNumber.
func TestOpenGPTINI(t *testing.T) {
	e, c := dial(t)

	unc := e.sysvolPath("Policies", defaultDomainPolicy, "GPT.INI")
	f, err := c.Open(unc)
	if err != nil {
		t.Fatalf("Open(%s): %v", unc, err)
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("reading %s: %v", unc, err)
	}
	// Some tools write GPT.INI with a UTF-8 BOM. Strip it so the assertion
	// is about the content and not the encoding.
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})

	if !bytes.HasPrefix(data, []byte("[General]")) {
		t.Errorf("%s starts %q, want it to start with [General]", unc, first(data, 32))
	}
	if !bytes.Contains(data, []byte("Version=")) {
		t.Errorf("%s = %q, want it to contain Version=", unc, first(data, 128))
	}
}

// Enumeration is what S-01 does to find GPOs and GPP types, so it has to
// work over the wire and not just against os.DirFS.
func TestReadDirPolicies(t *testing.T) {
	e, c := dial(t)

	unc := e.sysvolPath("Policies")
	ents, err := c.ReadDir(unc)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", unc, err)
	}
	for _, ent := range ents {
		if ent.Name() == defaultDomainPolicy {
			if !ent.IsDir() {
				t.Errorf("%s in %s is not reported as a directory", defaultDomainPolicy, unc)
			}
			return
		}
	}
	t.Errorf("ReadDir(%s) listed %d entries, none named %s", unc, len(ents), defaultDomainPolicy)
}

// The surface S-01 consumes. CloudSoda's own Share.DirFS() is not an
// fs.ReadDirFS and its files are not fs.ReadDirFile, so fs.WalkDir fails
// over it while succeeding over os.DirFS — the failure a parser tested
// offline would only meet here. smbx_test.go pins the wrapper that fixes
// it; this asserts the wrapper is actually what FS returns.
func TestFSWalksLikeOSDirFS(t *testing.T) {
	e, c := dial(t)

	unc := e.sysvolPath("Policies")
	fsys, err := c.FS(unc)
	if err != nil {
		t.Fatalf("FS(%s): %v", unc, err)
	}
	if _, ok := fsys.(fs.ReadDirFS); !ok {
		t.Errorf("FS(%s) returned %T, which is not an fs.ReadDirFS; S-01's Walk cannot enumerate it", unc, fsys)
	}

	want := defaultDomainPolicy + "/GPT.INI"
	var found bool
	err = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == want {
			found = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("fs.WalkDir over FS(%s): %v", unc, err)
	}
	if !found {
		t.Errorf("fs.WalkDir over FS(%s) never visited %s", unc, want)
	}
}

func first(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

// Deliberately not here: asserting the session negotiated signing or SMB3
// encryption. A library's "signing required" readout is client||server, so
// it cannot prove the server required anything, and CloudSoda does not
// export the negotiated state at all (SPIKE-T00 §4). Proving the DC's
// posture needs a no-login NEGOTIATE probe and an NTLM attempt that must be
// refused — that is V-03/dcverify's job, not a test that would pass here
// for the wrong reason.

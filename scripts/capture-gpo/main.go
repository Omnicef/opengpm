// Command capture-gpo records the test domain's groupPolicyContainer
// entries into testdata/ldap/gpo_entries.json, the fixture D-02's parser is
// tested against.
//
// # It records, it does not interpret
//
// Every attribute value lands in the JSON exactly as Active Directory
// returned it. versionNumber stays the packed DWORD as a string and is not
// split into its user and computer halves; objectGUID stays the raw 16
// bytes and is not rendered as a {GUID}; flags and
// gPCFunctionalityVersion stay strings and are not decoded;
// gPC*ExtensionNames keep their bracketed CSE syntax unparsed. That is
// D-02's job. A capture tool that did any of it would be a second
// implementation of the parser, agreeing with the first by construction —
// so the fixture could no longer catch the parser being wrong, which is the
// only reason it exists. Same rule as O-03, for the same reason.
//
// The one shape decision here is mechanical and attribute-agnostic: an
// attribute AD returned once is a JSON scalar, one it returned several
// times is a JSON array, and the two attributes with Octet String syntax
// (nTSecurityDescriptor, objectGUID) are base64 of their raw bytes rather
// than a lossy string. Attributes AD did not return are absent, not empty:
// "the DC sent nothing" and "the DC sent an empty value" are different
// facts and D-02 should be able to tell them apart.
//
// It runs against the same environment as the ldapx integration test, and
// builds the same stack the product does: one keytab, one TGT from krb, an
// LDAPS bind through ldapx, and SearchSD so the LDAP_SERVER_SD_FLAGS_OID
// control is attached. Reading a non-empty nTSecurityDescriptor here while
// bound as the non-admin service account is the §4.6 proof that the
// control works — without it AD omits the attribute silently rather than
// failing (PLAN §4.6).
//
// Usage, from the repository root:
//
//	OPENGPM_TEST_KEYTAB=... OPENGPM_TEST_PRINCIPAL=... OPENGPM_TEST_REALM=... \
//	OPENGPM_TEST_KDC=... OPENGPM_TEST_CACERT=... KRB5_CONFIG=... \
//	go run ./scripts/capture-gpo
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-ldap/ldap/v3"

	"github.com/Omnicef/opengpm/internal/transport/krb"
	"github.com/Omnicef/opengpm/internal/transport/ldapx"
)

// outPath is relative to the repository root, which is where `go run
// ./scripts/capture-gpo` is run from.
const outPath = "testdata/ldap/gpo_entries.json"

// attrs is PLAN §4.1's table of groupPolicyContainer attributes, plus
// objectGUID. Asking for a fixed list rather than for everything keeps the
// fixture stable across domains and keeps operational noise (uSNChanged,
// dSCorePropagationData) out of the specification.
var attrs = []string{
	"cn",
	"displayName",
	"gPCFileSysPath",
	"versionNumber",
	"flags",
	"gPCFunctionalityVersion",
	"gPCMachineExtensionNames",
	"gPCUserExtensionNames",
	"gPCWQLFilter",
	"nTSecurityDescriptor",
	"objectGUID",
	"whenCreated",
	"whenChanged",
}

// binaryAttrs are the requested attributes whose LDAP syntax is Octet
// String. Their bytes are not text and must not be round-tripped through
// one: a security descriptor put through Go's string-to-JSON path loses
// every byte that is not valid UTF-8 to U+FFFD, silently, which would make
// the fixture unparseable and blame D-02 for it.
var binaryAttrs = map[string]bool{
	"nTSecurityDescriptor": true,
	"objectGUID":           true,
}

// entry is one groupPolicyContainer as it goes into the fixture: its DN and
// whatever attributes came back, keyed by the name AD used. Marshalling a
// map sorts the keys, so the file is byte-stable between runs.
type entry struct {
	DN         string         `json:"dn"`
	Attributes map[string]any `json:"attributes"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "capture-gpo: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	e, err := readEnv()
	if err != nil {
		return err
	}

	k, err := krb.FromKeytab(e.keytab, e.principal, e.realm)
	if err != nil {
		return fmt.Errorf("kerberos login for %s: %w", e.principal, err)
	}
	c, err := ldapx.Dial(ldapx.Config{DC: e.kdc, Krb: k.GSSAPIClient(), CACert: e.caCert})
	if err != nil {
		return fmt.Errorf("binding to %s: %w", e.kdc, err)
	}
	defer func() { _ = c.Close() }()

	base := "CN=Policies,CN=System," + e.baseDN
	found, err := c.SearchSD(context.Background(), base, "(objectClass=groupPolicyContainer)", attrs)
	if err != nil {
		return fmt.Errorf("searching %s: %w", base, err)
	}
	if len(found) == 0 {
		// Every domain has at least the Default Domain Policy and the
		// Default Domain Controllers Policy, so this is a base DN or a
		// permissions problem, not a domain without GPOs.
		return fmt.Errorf("no groupPolicyContainer objects under %s; check that %s can read the Policies container", base, e.principal)
	}

	entries := make([]entry, 0, len(found))
	for _, ent := range found {
		entries = append(entries, record(ent))
	}
	// Sorted by cn — the GPO's {GUID} — so re-running produces the same
	// file. AD returns entries in no guaranteed order. The DN breaks ties
	// only so the sort is total; two GPOs cannot share a cn.
	sort.Slice(entries, func(i, j int) bool {
		ci, cj := cn(entries[i]), cn(entries[j])
		if ci != cj {
			return ci < cj
		}
		return entries[i].DN < entries[j].DN
	})

	for _, ent := range entries {
		fmt.Printf("%s  displayName=%q  nTSecurityDescriptor=%s\n",
			cn(ent), str(ent, "displayName"), present(ent, "nTSecurityDescriptor"))
	}

	if err := write(entries); err != nil {
		return err
	}
	fmt.Printf("wrote %d entries to %s\n", len(entries), outPath)
	return nil
}

// record converts one search result into its fixture form, taking every
// attribute AD actually returned rather than every attribute that was
// asked for.
func record(ent *ldap.Entry) entry {
	out := entry{DN: ent.DN, Attributes: make(map[string]any, len(ent.Attributes))}
	for _, a := range ent.Attributes {
		vals := make([]any, 0, len(a.Values))
		for i, v := range a.Values {
			if binaryAttrs[a.Name] {
				// The same bytes GetRawAttributeValue would hand back;
				// ByteValues is where it reads them from, and indexing it
				// keeps multi-valued attributes intact.
				vals = append(vals, base64.StdEncoding.EncodeToString(a.ByteValues[i]))
				continue
			}
			vals = append(vals, v)
		}
		if len(vals) == 1 {
			out.Attributes[a.Name] = vals[0]
			continue
		}
		out.Attributes[a.Name] = vals
	}
	return out
}

func write(entries []entry) error {
	b, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding %s: %w", outPath, err)
	}
	b = append(b, '\n')
	if err := os.MkdirAll(filepath.Dir(outPath), 0o750); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(outPath), err)
	}
	if err := os.WriteFile(outPath, b, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", outPath, err)
	}
	return nil
}

// cn, str and present read the recorded values back for the summary lines
// only. Nothing they return is written to the fixture.
func cn(e entry) string { return str(e, "cn") }

func str(e entry, name string) string {
	s, _ := e.Attributes[name].(string)
	return s
}

func present(e entry, name string) string {
	v, ok := e.Attributes[name].(string)
	if !ok || v == "" {
		return "ABSENT"
	}
	return "present"
}

// The environment is the ldapx integration test's, so that a lab already
// configured to run `go test -tags integration ./internal/transport/ldapx`
// can run this with no further setup. KRB5_CONFIG is required rather than
// defaulted: realm-to-KDC resolution comes out of it, and silently using
// /etc/krb5.conf would capture a different domain than the operator
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

type config struct {
	keytab, principal, realm, kdc, caCert string
	baseDN                                string
}

// readEnv fails naming every missing variable at once. A half-configured
// environment is an operator mistake, and finding it one variable per run
// is five runs.
func readEnv() (config, error) {
	var missing []string
	get := func(k string) string {
		v := os.Getenv(k)
		if v == "" {
			missing = append(missing, k)
		}
		return v
	}
	c := config{
		keytab:    get(envKeytab),
		principal: get(envPrincipal),
		realm:     get(envRealm),
		kdc:       get(envKDC),
		caCert:    get(envCACert),
	}
	get(envKrb5Conf)
	if len(missing) > 0 {
		return config{}, fmt.Errorf("no test domain configured; set %s", strings.Join(missing, ", "))
	}
	c.baseDN = os.Getenv(envBaseDN)
	if c.baseDN == "" {
		c.baseDN = baseDNFromRealm(c.realm)
	}
	return c, nil
}

// baseDNFromRealm converts GPLAB.LOCAL to DC=gplab,DC=local, as the ldapx
// integration test does. AD names the Kerberos realm after the DNS domain
// in upper case and the default naming context follows the same labels; a
// domain where the two genuinely differ sets OPENGPM_TEST_BASEDN.
func baseDNFromRealm(realm string) string {
	labels := strings.Split(strings.ToLower(realm), ".")
	for i, l := range labels {
		labels[i] = "DC=" + l
	}
	return strings.Join(labels, ",")
}

package directory

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Omnicef/opengpm/internal/model"
)

// oracleDir holds the O-03 capture: for each case, the raw gPLink
// attribute read off the OU and the link order GPMC reported for it.
// It is the specification for ordering. Nothing in this file reasons
// about which end of the string wins — the expectations are read out of
// the fixtures.
const oracleDir = "../../testdata/oracle/gplink"

// reportedLink is one row of a fixture's reported[] array: what GPMC
// displayed. Order is GPMC's link order, 1 = highest precedence.
type reportedLink struct {
	DisplayName string `json:"displayName"`
	GpoID       string `json:"gpoId"`
	Order       int    `json:"order"`
	Enabled     bool   `json:"enabled"`
	Enforced    bool   `json:"enforced"`
}

// oracleCase mirrors one testdata/oracle/gplink/*.json file. The
// fixtures were written by PowerShell and use its capitalisation
// ("GpoId", "Order"); encoding/json matches field tags
// case-insensitively, so they bind unchanged.
//
// gPOptions is deliberately absent: it is the OU's block-inheritance
// flag, not part of the gPLink string, and belongs to D-04.
type oracleCase struct {
	Case string `json:"case"`
	// RawGPLink is JSON null on an OU with no links (35_block_empty),
	// which decodes to "" — the empty case ParseGPLink must accept.
	RawGPLink string         `json:"rawGPLink"`
	Reported  []reportedLink `json:"reported"`
}

// canonicalGUID is the form these tests require ParseGPLink to produce
// for Link.GPO: braced and upper-case.
//
// Normalisation is not optional. Raw gPLink strings hold the GUID as
// cn={...} in *both* cases — the GUI-created fixtures are upper-case and
// the raw-written ones (29-32) are lower — while the oracle reports
// GpoId bare and lower-case. Both sides are folded through this helper
// so the assertion compares identity, not spelling.
//
// Braced upper-case is the choice because it is what Active Directory
// stores as the GPC object's CN, so a Link joins to a model.GPO.ID with
// no folding at the join, and internal/model/gpo.go documents model.GUID
// as the "{...}" form.
//
// REVIEWER: bare lower-case is equally defensible — it is what the
// oracle reports and what model.ApplyGroupPolicy uses. D-02 has not yet
// pinned the spelling of model.GPO.ID. If D-02 lands on bare, change
// this one helper and D-03 follows.
func canonicalGUID(s string) model.GUID {
	return model.GUID("{" + strings.ToUpper(strings.Trim(s, "{}")) + "}")
}

// Enabled and Enforced are derived from gPLinkOptions, never stored
// (internal/model/som.go). Note options 3: the oracle reports it as
// disabled *and* enforced, so the two bits are read independently —
// whether a disabled-and-enforced link is then ignored is PR-02's
// question, not this parser's.
func linkEnabled(o uint32) bool  { return o&1 == 0 }
func linkEnforced(o uint32) bool { return o&2 != 0 }

// parseNoPanic calls ParseGPLink and converts a panic into a named
// failure. gPLink is attacker-adjacent data read from the directory, so
// "returns a specific error" and "does not panic" are separate promises
// and this pins the second one.
func parseNoPanic(t *testing.T, in string) ([]model.Link, error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ParseGPLink(%q) panicked: %v", in, r)
		}
	}()
	return ParseGPLink(in)
}

func TestParseGPLinkOracle(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(oracleDir, "*.json"))
	if err != nil {
		t.Fatalf("globbing %s: %v", oracleDir, err)
	}
	// D-03 accepts "all 30+ observed cases" and O-03 committed 36. A
	// short glob means the oracle is missing or truncated, which must
	// fail loudly rather than pass vacuously.
	if len(files) < 30 {
		t.Fatalf("found %d fixtures in %s, want >= 30 — is O-03 present?", len(files), oracleDir)
	}

	for _, f := range files {
		t.Run(strings.TrimSuffix(filepath.Base(f), ".json"), func(t *testing.T) {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatalf("reading fixture: %v", err)
			}
			var c oracleCase
			if err := json.Unmarshal(b, &c); err != nil {
				t.Fatalf("decoding fixture: %v", err)
			}

			// The fixture indexes its expectations by GPMC's link
			// order, so check that index is well formed before
			// trusting it to judge the parser.
			byOrder := make(map[int]reportedLink, len(c.Reported))
			for _, r := range c.Reported {
				if prev, dup := byOrder[r.Order]; dup {
					t.Fatalf("fixture reports Order %d twice (%s and %s)", r.Order, prev.GpoID, r.GpoID)
				}
				byOrder[r.Order] = r
			}

			got, err := parseNoPanic(t, c.RawGPLink)
			if err != nil {
				t.Fatalf("ParseGPLink(%q) = error %v, want %d links", c.RawGPLink, err, len(c.Reported))
			}

			// Count first: the same GPO appears two and three times
			// in cases 29-32, and a parser that dedupes by GUID
			// silently changes precedence.
			if len(got) != len(c.Reported) {
				t.Fatalf("ParseGPLink(%q) returned %d links, want %d (links are never deduped by GPO)",
					c.RawGPLink, len(got), len(c.Reported))
			}

			// ParseGPLink returns highest precedence first, and
			// GPMC's Order 1 is the highest, so got[i] must be the
			// entry the oracle reports as Order i+1.
			for i, g := range got {
				want, ok := byOrder[i+1]
				if !ok {
					t.Fatalf("link %d: fixture has no entry with Order %d", i, i+1)
				}
				if g.Order != i+1 {
					t.Errorf("link %d (%s): Order = %d, want %d", i, want.DisplayName, g.Order, i+1)
				}
				if wantGUID := canonicalGUID(want.GpoID); g.GPO != wantGUID {
					t.Errorf("link %d: GPO = %q, want %q (%s at Order %d)", i, g.GPO, wantGUID, want.DisplayName, i+1)
				}
				if e := linkEnabled(g.Options); e != want.Enabled {
					t.Errorf("link %d (%s): Options %d gives Enabled = %v, want %v", i, want.DisplayName, g.Options, e, want.Enabled)
				}
				if e := linkEnforced(g.Options); e != want.Enforced {
					t.Errorf("link %d (%s): Options %d gives Enforced = %v, want %v", i, want.DisplayName, g.Options, e, want.Enforced)
				}
			}
		})
	}
}

// Everything below is not in the oracle: O-03 captured one domain, and
// every fixture is well-formed because GPMC wrote it.

// testGUID is one of the oracle's GPOs, reused so the two bodies of
// tests speak about the same identity.
const (
	testGUID = "{1A045CC9-F93C-4BEF-A58C-FEA04757401D}"
	sameDN   = "cn=" + testGUID + ",cn=policies,cn=system,DC=gplab,DC=local"
	otherDN  = "cn=" + testGUID + ",cn=policies,cn=system,DC=other,DC=test"
)

func TestParseGPLinkEmpty(t *testing.T) {
	got, err := parseNoPanic(t, "")
	if err != nil {
		t.Fatalf(`ParseGPLink("") = error %v, want no error`, err)
	}
	if len(got) != 0 {
		t.Errorf(`ParseGPLink("") returned %d links, want none`, len(got))
	}
}

// A gPLink may name a GPO in another domain (PLAN §4.2); the collector
// groups DNs by domain and rebinds. Parsing must therefore not assume
// the SOM's own domain, and must hand back the DN untouched for that
// grouping to work.
func TestParseGPLinkCrossDomain(t *testing.T) {
	in := "[LDAP://" + otherDN + ";0]"
	got, err := parseNoPanic(t, in)
	if err != nil {
		t.Fatalf("ParseGPLink(%q) = error %v, want one link", in, err)
	}
	if len(got) != 1 {
		t.Fatalf("ParseGPLink(%q) returned %d links, want 1", in, len(got))
	}
	want := model.Link{GPO: canonicalGUID(testGUID), GPODN: otherDN, Options: 0, Order: 1}
	if got[0] != want {
		t.Errorf("ParseGPLink(%q) = %+v, want %+v", in, got[0], want)
	}
}

// gPLink is written by whatever tool created the link, and the oracle
// itself contains the GUID in both cases. The scheme and the DN's
// attribute types are case-insensitive per RFC 4514, so they are folded
// for identity — but GPODN is passed through verbatim, because the
// rebinding in §4.2 wants the DN as stored, not a normalised guess.
func TestParseGPLinkGUIDCanonicalization(t *testing.T) {
	tests := []struct {
		name string
		dn   string
		s    string
	}{
		{"upper-case scheme and GUID", sameDN, "LDAP://"},
		{"lower-case scheme", sameDN, "ldap://"},
		{"mixed-case scheme", sameDN, "Ldap://"},
		{"lower-case GUID", strings.ToLower(sameDN), "LDAP://"},
		{"upper-case attribute types", strings.ReplaceAll(sameDN, "cn=", "CN="), "LDAP://"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := "[" + tt.s + tt.dn + ";2]"
			got, err := parseNoPanic(t, in)
			if err != nil {
				t.Fatalf("ParseGPLink(%q) = error %v, want one link", in, err)
			}
			if len(got) != 1 {
				t.Fatalf("ParseGPLink(%q) returned %d links, want 1", in, len(got))
			}
			want := model.Link{GPO: canonicalGUID(testGUID), GPODN: tt.dn, Options: 2, Order: 1}
			if got[0] != want {
				t.Errorf("ParseGPLink(%q) = %+v, want %+v", in, got[0], want)
			}
		})
	}
}

// gPLink is read from the directory, so it is untrusted input: every one
// of these must come back as an error value, and none of them may panic
// or return a partial list. A half-parsed gPLink is worse than a
// rejected one — dropping an entry silently changes precedence.
func TestParseGPLinkMalformed(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"not a gPLink at all", "hello world"},
		{"no brackets", "LDAP://" + sameDN + ";0"},
		{"missing closing bracket", "[LDAP://" + sameDN + ";0"},
		{"missing opening bracket", "LDAP://" + sameDN + ";0]"},
		{"unbalanced opening bracket", "[[LDAP://" + sameDN + ";0]"},
		{"missing options segment", "[LDAP://" + sameDN + "]"},
		{"empty options segment", "[LDAP://" + sameDN + ";]"},
		{"non-numeric options", "[LDAP://" + sameDN + ";abc]"},
		{"negative options", "[LDAP://" + sameDN + ";-1]"},
		{"options overflows uint32", "[LDAP://" + sameDN + ";4294967296]"},
		{"truncated entry", "[LDAP://cn={1A045CC9"},
		{"empty entry", "[]"},
		{"missing DN", "[LDAP://;0]"},
		{"missing scheme", "[" + sameDN + ";0]"},
		{"GUID missing braces", "[LDAP://cn=1A045CC9-F93C-4BEF-A58C-FEA04757401D,cn=policies,cn=system,DC=gplab,DC=local;0]"},
		{"stray characters before an entry", "junk[LDAP://" + sameDN + ";0]"},
		{"stray characters between entries", "[LDAP://" + sameDN + ";0]junk[LDAP://" + sameDN + ";0]"},
		{"stray characters after an entry", "[LDAP://" + sameDN + ";0]junk"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseNoPanic(t, tt.in)
			if err == nil {
				t.Fatalf("ParseGPLink(%q) = %+v, want an error", tt.in, got)
			}
			if len(got) != 0 {
				t.Errorf("ParseGPLink(%q) returned %d links alongside its error, want none", tt.in, len(got))
			}
		})
	}
}

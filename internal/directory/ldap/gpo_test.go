package ldap

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/Omnicef/opengpm/internal/model"
)

// fixturePath holds the D-02 capture: eight real groupPolicyContainer
// entries read off the lab DC by scripts/capture-gpo — the two policies
// every domain ships with, plus six d02-* GPOs created to exercise the
// version packing, the flags, and the CSE lists.
//
// The fixture is the specification. capture-gpo records every value
// exactly as Active Directory returned it and interprets nothing, so
// these tests can judge the parser instead of agreeing with it.
const fixturePath = "../../../testdata/ldap/gpo_entries.json"

// binaryAttrs are the fixture's Octet String attributes: their JSON
// values are base64 of the raw bytes, not text (scripts/capture-gpo).
// Everything else is the string AD returned.
var binaryAttrs = map[string]bool{
	"nTSecurityDescriptor": true,
	"objectGUID":           true,
}

// genTime is the LDAP generalized-time layout the fixture's whenCreated
// and whenChanged use ("20260824033153.0Z"). Parsing one with the
// standard library here is deliberate: parseGPOEntry must agree with
// time.Parse, and TestParseGPOEntryFields additionally pins one
// timestamp as a literal so a shared misreading of the layout cannot
// pass both sides.
const genTime = "20060102150405.0Z0700"

// wantDomainDN is the domain naming context every fixture entry lives
// in. DomainDN is the DN suffix from its first DC= RDN onward: D-04
// groups GPOs by domain and rebinds cross-domain links (PLAN §4.2),
// which needs the NC, not the whole GPC DN.
const wantDomainDN = "DC=gplab,DC=local"

// fixtureEntry mirrors one record of the fixture file. An attribute AD
// returned once is a JSON string and one it returned several times is a
// JSON array, so the values are held raw and decoded per attribute.
// Attributes AD did not return are absent from the map rather than
// empty — "the DC sent nothing" and "the DC sent an empty value" are
// different facts.
type fixtureEntry struct {
	DN         string                     `json:"dn"`
	Attributes map[string]json.RawMessage `json:"attributes"`
}

func loadFixture(t *testing.T) []fixtureEntry {
	t.Helper()
	b, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("reading %s: %v", fixturePath, err)
	}
	var entries []fixtureEntry
	if err := json.Unmarshal(b, &entries); err != nil {
		t.Fatalf("decoding %s: %v", fixturePath, err)
	}
	if len(entries) != len(want) {
		t.Fatalf("%s holds %d entries, want %d — was it recaptured?", fixturePath, len(entries), len(want))
	}
	return entries
}

// fixtureByName indexes the capture by displayName, which is how the
// expectations below name each GPO. displayName is not unique in Active
// Directory (PLAN §4.1) but it is unique in this fixture, and a
// recapture that broke that must fail here rather than silently drop a
// case.
func fixtureByName(t *testing.T) map[string]fixtureEntry {
	t.Helper()
	out := make(map[string]fixtureEntry)
	for _, f := range loadFixture(t) {
		name := f.value(t, "displayName")
		if prev, dup := out[name]; dup {
			t.Fatalf("fixture has two GPOs named %q (%s and %s)", name, prev.DN, f.DN)
		}
		out[name] = f
	}
	return out
}

// values decodes one attribute to the list of values AD returned for
// it, or nil if AD returned it not at all.
func (f fixtureEntry) values(t *testing.T, name string) []string {
	t.Helper()
	raw, ok := f.Attributes[name]
	if !ok {
		return nil
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		t.Fatalf("%s: attribute %s is neither a string nor an array: %s", f.DN, name, raw)
	}
	return many
}

// value is values for the single-valued attributes, and "" for absent.
func (f fixtureEntry) value(t *testing.T, name string) string {
	t.Helper()
	v := f.values(t, name)
	if len(v) == 0 {
		return ""
	}
	if len(v) != 1 {
		t.Fatalf("%s: attribute %s has %d values, want 1", f.DN, name, len(v))
	}
	return v[0]
}

// rawValue is the decoded bytes of a binary attribute — what
// GetRawAttributeValue hands the parser.
func (f fixtureEntry) rawValue(t *testing.T, name string) []byte {
	t.Helper()
	if !binaryAttrs[name] {
		t.Fatalf("%s is not a binary attribute", name)
	}
	v := f.value(t, name)
	if v == "" {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		t.Fatalf("%s: decoding %s: %v", f.DN, name, err)
	}
	return b
}

// entry reconstructs the *ldap.Entry the parser will be handed. Values
// and ByteValues are both filled, as go-ldap fills them from a real
// search result: the string form for text attributes, and for the two
// Octet String attributes the raw bytes, which is where
// GetRawAttributeValue reads from.
func (f fixtureEntry) entry(t *testing.T) *ldap.Entry {
	t.Helper()
	e := &ldap.Entry{DN: f.DN}
	for _, name := range slices.Sorted(maps.Keys(f.Attributes)) {
		a := &ldap.EntryAttribute{Name: name}
		for _, v := range f.values(t, name) {
			raw := []byte(v)
			if binaryAttrs[name] {
				raw = f.rawValue(t, name)
			}
			a.Values = append(a.Values, string(raw))
			a.ByteValues = append(a.ByteValues, raw)
		}
		e.Attributes = append(e.Attributes, a)
	}
	return e
}

// with returns a copy carrying a different value for one text
// attribute; without returns one where the attribute is absent, as it
// is on an entry the DC did not return it for. Neither touches the
// fixture on disk.
func (f fixtureEntry) with(t *testing.T, name, value string) fixtureEntry {
	t.Helper()
	if binaryAttrs[name] {
		t.Fatalf("with(%s): binary attributes are base64 in the fixture", name)
	}
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("encoding %s=%q: %v", name, value, err)
	}
	out := fixtureEntry{DN: f.DN, Attributes: maps.Clone(f.Attributes)}
	out.Attributes[name] = b
	return out
}

func (f fixtureEntry) without(name string) fixtureEntry {
	out := fixtureEntry{DN: f.DN, Attributes: maps.Clone(f.Attributes)}
	delete(out.Attributes, name)
	return out
}

// parseNoPanic calls parseGPOEntry and turns a panic into a named
// failure. A groupPolicyContainer is read from the directory, so
// "returns an error" and "does not panic" are separate promises and
// this pins the second one.
func parseNoPanic(t *testing.T, e *ldap.Entry, parseSD func([]byte) (*model.SecurityDescriptor, error)) (gpo model.GPO, err error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("parseGPOEntry(%s) panicked: %v", e.DN, r)
		}
	}()
	return parseGPOEntry(e, parseSD)
}

// noSD is the injected parser for the tests that are not about the
// security descriptor: it fails the test if it is called with nothing,
// and otherwise returns a marker so Security is non-nil.
func noSD(t *testing.T) func([]byte) (*model.SecurityDescriptor, error) {
	t.Helper()
	return func(b []byte) (*model.SecurityDescriptor, error) {
		if len(b) == 0 {
			t.Errorf("parseSD called with %d bytes; an absent security descriptor must not reach it", len(b))
		}
		return &model.SecurityDescriptor{Owner: "S-1-5-32-TEST"}, nil
	}
}

// gpoWant is the expected parse of one fixture entry. Every field here
// is a value the parser must derive rather than copy: the identity's
// spelling, the two halves of the packed version, the flags, and the
// CSE GUIDs pulled out of the bracketed extension lists. The
// pass-through fields (gPCFileSysPath, the timestamps, the DN) are
// checked against the fixture itself in TestParseGPOEntryFields, so
// they are not restated here.
type gpoWant struct {
	id       model.GUID
	user     uint16
	computer uint16
	flags    model.GPOFlags
	funcVer  int
	machine  []model.CSERef
	usercse  []model.CSERef
}

// want is the specification, keyed by displayName.
//
// The version pairs are the headline gotcha. versionNumber is a packed
// DWORD: user = v>>16, computer = v&0xFFFF (PLAN §4.1). d02-both is
// 196609 = 0x00030001, so it must give User 3 and Computer 1 — a parser
// that swapped the halves would report 1/3 and a parser that forgot to
// shift would report 0/196609 or 3/3. d02-user-only (65536 = 0x10000)
// and d02-computer-only (1) pin each half on its own, so no single
// mistake passes all three.
//
// ID is the cn braced and UPPER-CASE. That is the spelling D-03 pinned
// for model.Link.GPO (canonicalGUID in internal/directory/gplink_test.go)
// and the form model.GUID is documented as, so a Link joins to a GPO
// with no folding at the join. "Default Domain Controllers Policy"
// carries a lower-case f in its cn as AD stores it, which is the case
// that fails if the parser passes cn through unchanged.
var want = map[string]gpoWant{
	"d02-both": {
		id:       "{07C15512-4B5B-4B59-94A4-85E82B7446A8}",
		user:     3, // 196609 = 0x00030001
		computer: 1,
		flags:    model.GPOEnabled,
		funcVer:  2,
		machine:  []model.CSERef{"{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"},
		usercse:  []model.CSERef{"{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"},
	},
	"Default Domain Policy": {
		id:       "{31B2F340-016D-11D2-945F-00C04FB984F9}",
		user:     0, // 3 = 0x00000003
		computer: 3,
		flags:    model.GPOEnabled,
		funcVer:  2,
		machine: []model.CSERef{
			"{35378EAC-683F-11D2-A89A-00C04FBBCFA2}",
			"{827D319E-6EAC-11D2-A4EA-00C04F79F83A}",
			"{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}",
		},
	},
	"d02-user-only": {
		id:       "{675047A2-7CA9-4666-AF7C-10927A958A7B}",
		user:     1, // 65536 = 0x00010000
		computer: 0,
		flags:    model.GPOEnabled,
		funcVer:  2,
		usercse:  []model.CSERef{"{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"},
	},
	"Default Domain Controllers Policy": {
		// cn is {6AC1786C-016F-11D2-945F-00C04fB984F9} — note the
		// lower-case f. ID upper-cases it.
		id:       "{6AC1786C-016F-11D2-945F-00C04FB984F9}",
		user:     0,
		computer: 1,
		flags:    model.GPOEnabled,
		funcVer:  2,
		machine:  []model.CSERef{"{827D319E-6EAC-11D2-A4EA-00C04F79F83A}"},
	},
	"d02-all-disabled": {
		id:      "{84B43AD8-64B4-445D-89B4-9E92D59685A2}",
		flags:   model.GPOAllDisabled,
		funcVer: 2,
	},
	"d02-computer-only": {
		id:       "{A038F50F-25A5-4179-95C2-00B71F47680B}",
		user:     0,
		computer: 1,
		flags:    model.GPOEnabled,
		funcVer:  2,
		machine:  []model.CSERef{"{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"},
	},
	"d02-user-disabled": {
		id:      "{AE2DF948-3097-4ABE-B31C-1453DCCF1A1C}",
		flags:   model.GPOUserDisabled,
		funcVer: 2,
	},
	"d02-computer-disabled": {
		id:      "{E7B37CD2-12E4-49C1-B7B7-404CA80E20DD}",
		flags:   model.GPOComputerDisabled,
		funcVer: 2,
	},
}

// TestParseGPOEntryFixture drives the parser with every entry in the
// capture and checks the derived fields against the table above.
func TestParseGPOEntryFixture(t *testing.T) {
	for name, f := range fixtureByName(t) {
		t.Run(name, func(t *testing.T) {
			w, ok := want[name]
			if !ok {
				t.Fatalf("fixture has a GPO named %q with no expectation — was it recaptured?", name)
			}

			got, err := parseNoPanic(t, f.entry(t), noSD(t))
			if err != nil {
				t.Fatalf("parseGPOEntry(%s) = error %v, want a GPO", f.DN, err)
			}

			if got.ID != w.id {
				t.Errorf("ID = %q, want %q (braced upper-case, the join key D-03 uses for Link.GPO)", got.ID, w.id)
			}
			if got.DisplayName != name {
				t.Errorf("DisplayName = %q, want %q", got.DisplayName, name)
			}
			// Reported together: the failure mode is the pair being
			// swapped or unshifted, which is unreadable one field at
			// a time.
			if got.UserVersion != w.user || got.ComputerVersion != w.computer {
				t.Errorf("versionNumber %s gives User/Computer = %d/%d, want %d/%d (user = v>>16, computer = v&0xFFFF)",
					f.value(t, "versionNumber"), got.UserVersion, got.ComputerVersion, w.user, w.computer)
			}
			if got.Flags != w.flags {
				t.Errorf("flags %q gives Flags = %d, want %d", f.value(t, "flags"), got.Flags, w.flags)
			}
			if got.FunctionalityVersion != w.funcVer {
				t.Errorf("FunctionalityVersion = %d, want %d", got.FunctionalityVersion, w.funcVer)
			}
			if !slices.Equal(got.MachineExtensions, w.machine) {
				t.Errorf("gPCMachineExtensionNames %q gives MachineExtensions = %q, want %q (the CSE GUID is the FIRST of each bracketed pair)",
					f.value(t, "gPCMachineExtensionNames"), got.MachineExtensions, w.machine)
			}
			if !slices.Equal(got.UserExtensions, w.usercse) {
				t.Errorf("gPCUserExtensionNames %q gives UserExtensions = %q, want %q",
					f.value(t, "gPCUserExtensionNames"), got.UserExtensions, w.usercse)
			}
		})
	}
}

// TestParseGPOEntryFields checks the fields the parser copies or
// reshapes rather than decodes, against the fixture's own values.
func TestParseGPOEntryFields(t *testing.T) {
	for name, f := range fixtureByName(t) {
		t.Run(name, func(t *testing.T) {
			got, err := parseNoPanic(t, f.entry(t), noSD(t))
			if err != nil {
				t.Fatalf("parseGPOEntry(%s) = error %v, want a GPO", f.DN, err)
			}

			if w := f.value(t, "gPCFileSysPath"); got.FileSysPath != w {
				t.Errorf("FileSysPath = %q, want %q (verbatim; the collector resolves it over SMB)", got.FileSysPath, w)
			}
			if got.DomainDN != wantDomainDN {
				t.Errorf("DN %q gives DomainDN = %q, want %q", f.DN, got.DomainDN, wantDomainDN)
			}
			for _, tc := range []struct {
				attr string
				got  time.Time
			}{
				{"whenCreated", got.WhenCreated},
				{"whenChanged", got.WhenChanged},
			} {
				raw := f.value(t, tc.attr)
				w, err := time.Parse(genTime, raw)
				if err != nil {
					t.Fatalf("fixture %s = %q is not an LDAP generalized time: %v", tc.attr, raw, err)
				}
				if !tc.got.Equal(w) {
					t.Errorf("%s %q gives %s, want %s", tc.attr, raw, tc.got, w)
				}
			}

			// The SYSVOL halves come from GPT.INI (S-02) and are not
			// on the LDAP entry at all; leaving them zero is what
			// makes the version-mismatch check meaningful.
			if got.SysvolUserVersion != 0 || got.SysvolComputerVersion != 0 {
				t.Errorf("Sysvol versions = %d/%d, want 0/0 — they come from GPT.INI (S-02), not from LDAP",
					got.SysvolUserVersion, got.SysvolComputerVersion)
			}
		})
	}
}

// TestParseGPOEntryTimeLiteral pins one timestamp as a literal, so that
// a misreading of the generalized-time layout cannot pass by being
// shared with the time.Parse in TestParseGPOEntryFields. The fixture
// records d02-both as created 20260824033152.0Z, one second before it
// was changed.
func TestParseGPOEntryTimeLiteral(t *testing.T) {
	f := fixtureByName(t)["d02-both"]
	got, err := parseNoPanic(t, f.entry(t), noSD(t))
	if err != nil {
		t.Fatalf("parseGPOEntry(%s) = error %v, want a GPO", f.DN, err)
	}
	created := time.Date(2026, time.August, 24, 3, 31, 52, 0, time.UTC)
	changed := time.Date(2026, time.August, 24, 3, 31, 53, 0, time.UTC)
	if !got.WhenCreated.Equal(created) {
		t.Errorf("WhenCreated = %s, want %s", got.WhenCreated, created)
	}
	if !got.WhenChanged.Equal(changed) {
		t.Errorf("WhenChanged = %s, want %s", got.WhenChanged, changed)
	}
}

// TestParseGPOEntrySecurity is the "do not drop GPOs with unreadable
// security descriptors" gotcha. The descriptor parser is injected
// because D-06 does not exist yet: D-02 owes the caller a GPO either
// way, and Security == nil is how it says the filtering could not be
// read. A GPO that vanished because its SD would not parse is a GPO
// missing from the report with nothing to show for it.
func TestParseGPOEntrySecurity(t *testing.T) {
	f := fixtureByName(t)["d02-both"]
	raw := f.rawValue(t, "nTSecurityDescriptor")
	if len(raw) == 0 {
		t.Fatalf("fixture d02-both has no nTSecurityDescriptor; this test needs one")
	}
	parsed := &model.SecurityDescriptor{Owner: "S-1-5-32-TEST"}
	sdErr := errors.New("malformed security descriptor")

	// The rest of the GPO must be identical in all three cases, so it
	// is taken from the succeeding one and compared field by field.
	reference, err := parseNoPanic(t, f.entry(t), func([]byte) (*model.SecurityDescriptor, error) {
		return parsed, nil
	})
	if err != nil {
		t.Fatalf("parseGPOEntry(%s) = error %v, want a GPO", f.DN, err)
	}
	if reference.Security != parsed {
		t.Fatalf("Security = %+v, want the descriptor the injected parser returned", reference.Security)
	}

	t.Run("bytes reach the parser", func(t *testing.T) {
		var seen [][]byte
		if _, err := parseNoPanic(t, f.entry(t), func(b []byte) (*model.SecurityDescriptor, error) {
			seen = append(seen, b)
			return parsed, nil
		}); err != nil {
			t.Fatalf("parseGPOEntry(%s) = error %v, want a GPO", f.DN, err)
		}
		if len(seen) != 1 {
			t.Fatalf("parseSD called %d times, want 1", len(seen))
		}
		// The raw bytes, not the string round-trip: an SD put through
		// a string loses every byte that is not valid UTF-8.
		if !bytes.Equal(seen[0], raw) {
			t.Errorf("parseSD got %d bytes, want the entry's %d raw nTSecurityDescriptor bytes", len(seen[0]), len(raw))
		}
	})

	t.Run("unparseable descriptor", func(t *testing.T) {
		got, err := parseNoPanic(t, f.entry(t), func([]byte) (*model.SecurityDescriptor, error) {
			return nil, sdErr
		})
		if err != nil {
			t.Fatalf("parseGPOEntry(%s) = error %v, want the GPO with Security nil — an unreadable SD must not drop the GPO", f.DN, err)
		}
		if got.Security != nil {
			t.Errorf("Security = %+v, want nil — nil is how an unreadable descriptor is flagged", got.Security)
		}
		assertSameExceptSecurity(t, got, reference)
	})

	t.Run("absent descriptor", func(t *testing.T) {
		e := f.without("nTSecurityDescriptor").entry(t)
		called := false
		got, err := parseNoPanic(t, e, func([]byte) (*model.SecurityDescriptor, error) {
			called = true
			return parsed, nil
		})
		if err != nil {
			t.Fatalf("parseGPOEntry(%s) = error %v, want the GPO with Security nil", e.DN, err)
		}
		if called {
			t.Errorf("parseSD was called for an entry with no nTSecurityDescriptor")
		}
		if got.Security != nil {
			t.Errorf("Security = %+v, want nil", got.Security)
		}
		assertSameExceptSecurity(t, got, reference)
	})
}

// assertSameExceptSecurity checks that losing the security descriptor
// cost nothing else: the GPO still carries its identity, versions and
// paths, so it can be reported with its filtering marked unknown.
func assertSameExceptSecurity(t *testing.T, got, want model.GPO) {
	t.Helper()
	got.Security, want.Security = nil, nil
	if got.ID != want.ID || got.DisplayName != want.DisplayName ||
		got.UserVersion != want.UserVersion || got.ComputerVersion != want.ComputerVersion ||
		got.Flags != want.Flags || got.FunctionalityVersion != want.FunctionalityVersion ||
		got.FileSysPath != want.FileSysPath || got.DomainDN != want.DomainDN ||
		!got.WhenCreated.Equal(want.WhenCreated) || !got.WhenChanged.Equal(want.WhenChanged) ||
		!slices.Equal(got.MachineExtensions, want.MachineExtensions) ||
		!slices.Equal(got.UserExtensions, want.UserExtensions) {
		t.Errorf("GPO = %+v, want everything but Security unchanged: %+v", got, want)
	}
}

// TestParseGPOEntryFixtureGaps records what the lab did not have, so a
// later capture that fills a gap fails here rather than quietly
// leaving these fields untested.
//
//   - No GPO has gPCWQLFilter: nothing in the lab has a WMI filter
//     linked, so WMIFilter nil is the only outcome the fixture can
//     pin. Reading the attribute is D-05's ticket.
//   - Every GPO has gPCFunctionalityVersion 2. Anything else is a
//     health signal (PLAN §4.1) and no fixture exercises it.
func TestParseGPOEntryFixtureGaps(t *testing.T) {
	for name, f := range fixtureByName(t) {
		t.Run(name, func(t *testing.T) {
			if v := f.value(t, "gPCWQLFilter"); v != "" {
				t.Fatalf("fixture now has gPCWQLFilter = %q; D-05 owns it and this test needs updating", v)
			}
			if v := f.value(t, "gPCFunctionalityVersion"); v != "2" {
				t.Fatalf("fixture now has gPCFunctionalityVersion = %q, want 2", v)
			}
			got, err := parseNoPanic(t, f.entry(t), noSD(t))
			if err != nil {
				t.Fatalf("parseGPOEntry(%s) = error %v, want a GPO", f.DN, err)
			}
			if got.WMIFilter != nil {
				t.Errorf("WMIFilter = %q, want nil — the entry has no gPCWQLFilter", *got.WMIFilter)
			}
		})
	}
}

// TestParseGPOEntryMalformed pins the shape of failure. A GPC comes off
// the wire, so a value that is present but unreadable is an error
// value, never a zero value and never a panic (AGENTS.md style).
//
// Absence is not covered here and is not the same thing: only
// nTSecurityDescriptor's absence is specified, above.
func TestParseGPOEntryMalformed(t *testing.T) {
	base := fixtureByName(t)["d02-both"]
	if v := base.value(t, "versionNumber"); v != strconv.Itoa(196609) {
		t.Fatalf("fixture d02-both has versionNumber %q, want 196609", v)
	}

	tests := []struct {
		name string
		e    fixtureEntry
	}{
		{"versionNumber not a number", base.with(t, "versionNumber", "three")},
		{"versionNumber negative", base.with(t, "versionNumber", "-1")},
		{"versionNumber wider than a DWORD", base.with(t, "versionNumber", "4294967296")},
		{"versionNumber empty", base.with(t, "versionNumber", "")},
		{"flags not a number", base.with(t, "flags", "disabled")},
		{"gPCFunctionalityVersion not a number", base.with(t, "gPCFunctionalityVersion", "two")},
		{"whenCreated not a generalized time", base.with(t, "whenCreated", "2026-08-24T03:31:52Z")},
		{"whenChanged not a generalized time", base.with(t, "whenChanged", "yesterday")},
		// cn is the identity a Link joins to; without it, or braced
		// differently, the GPO cannot be joined to anything.
		{"cn absent", base.without("cn")},
		{"cn not braced", base.with(t, "cn", "07C15512-4B5B-4B59-94A4-85E82B7446A8")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseNoPanic(t, tt.e.entry(t), noSD(t))
			if err == nil {
				t.Fatalf("parseGPOEntry = %+v, want an error", got)
			}
		})
	}
}

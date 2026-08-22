package smbx

import (
	"errors"
	"io/fs"
	"net"
	"os"
	"strings"
	"testing"
	"testing/fstest"
)

// Nothing about a real domain is committed. These are synthetic, and the
// integration test takes the live names from the environment.
const (
	testDomain = "example.test"

	// defaultDomainPolicy is the well-known GUID every domain has. It is a
	// constant of Active Directory, not a fact about any deployment.
	defaultDomainPolicy = "{31B2F340-016D-11D2-945F-00C04FB984F9}"
)

// parseNoPanic calls ParseUNC and converts a panic into a named failure.
// gPCFileSysPath is attacker-adjacent data read from the directory, so
// "returns a specific error" and "does not panic" are separate promises and
// this pins the second one.
func parseNoPanic(t *testing.T, in string) (UNC, error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ParseUNC(%q) panicked: %v", in, r)
		}
	}()
	return ParseUNC(in)
}

func TestParseUNC(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want UNC
	}{
		{
			"canonical gPCFileSysPath",
			`\\` + testDomain + `\SysVol\` + testDomain + `\Policies\` + defaultDomainPolicy + `\GPT.INI`,
			UNC{testDomain, SysvolShare, testDomain + "/Policies/" + defaultDomainPolicy + "/GPT.INI"},
		},
		// Share names are case-insensitive on the wire and AD spells this
		// one at least three ways across tools, so the parse canonicalises
		// rather than making every caller fold.
		{"lower-case share", `\\` + testDomain + `\sysvol\a\b.ini`, UNC{testDomain, SysvolShare, "a/b.ini"}},
		{"upper-case share", `\\` + testDomain + `\SYSVOL\a\b.ini`, UNC{testDomain, SysvolShare, "a/b.ini"}},

		// gPCFileSysPath is written by whatever tool created the GPO, and
		// callers concatenate onto it, so separators arrive in any mix.
		{"forward slashes throughout", "//" + testDomain + "/SysVol/a/b.ini", UNC{testDomain, SysvolShare, "a/b.ini"}},
		{"mixed separators", `\\` + testDomain + `/SysVol\a/b.ini`, UNC{testDomain, SysvolShare, "a/b.ini"}},
		{"trailing separator", `\\` + testDomain + `\SysVol\a\b\`, UNC{testDomain, SysvolShare, "a/b"}},
		{"repeated separators within the path", `\\` + testDomain + `\SysVol\a\\b\`, UNC{testDomain, SysvolShare, "a/b"}},

		// The share root is the fs.FS root, spelled "." — not "" and not
		// "/", so it can be handed straight to fs.WalkDir.
		{"share root", `\\` + testDomain + `\SysVol`, UNC{testDomain, SysvolShare, "."}},
		{"share root with trailing separator", `\\` + testDomain + `\SysVol\`, UNC{testDomain, SysvolShare, "."}},

		// The package is not SYSVOL-only by accident of parsing: NETLOGON
		// is the same shape and D-0x may want it.
		{"another share", `\\` + testDomain + `\NETLOGON\logon.bat`, UNC{testDomain, "NETLOGON", "logon.bat"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseNoPanic(t, tc.in)
			if err != nil {
				t.Fatalf("ParseUNC(%q) = %v, want %+v", tc.in, err, tc.want)
			}
			if got != tc.want {
				t.Errorf("ParseUNC(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseUNCMalformed(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want error
	}{
		{"empty", "", ErrNotUNC},
		{"no leading separators", testDomain + `\SysVol\a`, ErrNotUNC},
		{"one leading separator", `\` + testDomain + `\SysVol`, ErrNotUNC},
		{"local windows path", `C:\Windows\System32`, ErrNotUNC},
		{"unix path", "/etc/krb5.keytab", ErrNotUNC},

		{"separators only", `\\`, ErrNoDomain},
		{"empty domain component", `\\\SysVol\a`, ErrNoDomain},

		{"domain but no share", `\\` + testDomain, ErrNoShare},
		{"domain and a trailing separator", `\\` + testDomain + `\`, ErrNoShare},

		// Deliberate: separators are only collapsed inside the path. A
		// doubled separator where the share belongs is rejected rather than
		// guessed at, because guessing here picks which tree to mount.
		{"empty share component", `\\` + testDomain + `\\SysVol\a`, ErrNoShare},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseNoPanic(t, tc.in)
			if !errors.Is(err, tc.want) {
				t.Fatalf("ParseUNC(%q) = (%+v, %v), want error %v", tc.in, got, err, tc.want)
			}
		})
	}
}

// The domain component of a UNC path is a domain name, and resolving it is
// not DNS's job here: §4.1 requires LDAP and SMB to read the same replica,
// so SMB goes to the DC that T-02 pinned. Dialing \\<domain> verbatim would
// let a round-robin answer land on a different DC and turn replication lag
// into false "AD and SYSVOL out of sync" reports on the flagship check.
//
// pinnedDC and testDomain deliberately share no substring, so the
// containment assertions below cannot pass by accident.
func TestDialTargetResolvesToPinnedDC(t *testing.T) {
	const pinnedDC = "dc7.pinned.invalid"

	u := UNC{Domain: testDomain, Share: SysvolShare, Path: testDomain + "/Policies"}
	addr, spn := dialTarget(pinnedDC, u)

	if want := net.JoinHostPort(pinnedDC, "445"); addr != want {
		t.Errorf("dialTarget(%q, %+v) addr = %q, want %q", pinnedDC, u, addr, want)
	}
	// The ticket names the pinned DC, so the service ticket must too —
	// asking for cifs/<domain> gets a ticket for the wrong host.
	if want := "cifs/" + pinnedDC; spn != want {
		t.Errorf("dialTarget(%q, %+v) spn = %q, want %q", pinnedDC, u, spn, want)
	}

	if strings.Contains(addr, u.Domain) {
		t.Errorf("dialTarget addr = %q, which contains the UNC domain %q; the domain is a name to resolve, never an address to dial", addr, u.Domain)
	}
	if strings.Contains(spn, u.Domain) {
		t.Errorf("dialTarget spn = %q, which contains the UNC domain %q; the service ticket must name the pinned DC", spn, u.Domain)
	}
}

// cloudsodaFS mimics what CloudSoda's Share.DirFS() actually returns: Open
// works, but the FS is not fs.ReadDirFS, and the files it hands back carry
// os.File's Readdir(int) ([]os.FileInfo, error) rather than
// fs.ReadDirFile's ReadDir(int) ([]fs.DirEntry, error).
//
// Built over testing/fstest.MapFS so the shape can be tested with no DC.
type cloudsodaFS struct{ inner fs.FS }

func (c cloudsodaFS) Open(name string) (fs.File, error) {
	f, err := c.inner.Open(name)
	if err != nil {
		return nil, err
	}
	return osStyleFile{inner: f}, nil
}

// osStyleFile exposes only what *smb2.File exposes: fs.File plus Readdir.
// The embedded interface is deliberately not promoted — that is the whole
// point of the double.
type osStyleFile struct{ inner fs.File }

func (f osStyleFile) Stat() (fs.FileInfo, error) { return f.inner.Stat() }
func (f osStyleFile) Read(p []byte) (int, error) { return f.inner.Read(p) }
func (f osStyleFile) Close() error               { return f.inner.Close() }

func (f osStyleFile) Readdir(n int) ([]os.FileInfo, error) {
	d, ok := f.inner.(fs.ReadDirFile)
	if !ok {
		return nil, errors.New("not a directory")
	}
	ents, err := d.ReadDir(n)
	if err != nil {
		return nil, err
	}
	infos := make([]os.FileInfo, 0, len(ents))
	for _, e := range ents {
		fi, err := e.Info()
		if err != nil {
			return nil, err
		}
		infos = append(infos, fi)
	}
	return infos, nil
}

// gptTree is a miniature SYSVOL: two GPOs, one with a Machine subtree, so a
// walk has to descend more than one level and order two siblings.
func gptTree() fs.FS {
	const other = "{6AC1786C-016F-11D2-945F-00C04FB984F9}"
	return fstest.MapFS{
		"Policies/" + defaultDomainPolicy + "/GPT.INI":              {Data: []byte("[General]\r\nVersion=65539\r\n")},
		"Policies/" + defaultDomainPolicy + "/Machine/Registry.pol": {Data: []byte("PReg")},
		"Policies/" + other + "/GPT.INI":                            {Data: []byte("[General]\r\nVersion=1\r\n")},
	}
}

// This is the trap the wrapper exists for, and the reason FS() promises
// fs.ReadDirFS rather than handing Share.DirFS() out raw.
//
// S-01's Walk(fsys fs.FS, root string) reaches directories through
// fs.ReadDir, which needs either an fs.ReadDirFS or files implementing
// fs.ReadDirFile. CloudSoda provides neither, while os.DirFS and
// testing/fstest.MapFS provide both — so a parser tested offline passes and
// then fails against a real DC. Same family as the KVNO and PA-FX-FAST
// lessons in SPIKE-T00: green in the lab, wrong in the domain.
func TestReadDirFSMakesWalkDirWork(t *testing.T) {
	raw := cloudsodaFS{inner: gptTree()}

	// The premise. If this ever starts passing, CloudSoda grew fs.ReadDirFS
	// and readDirFS can be deleted — which is worth being told about.
	if _, err := fs.ReadDir(raw, "Policies"); err == nil {
		t.Error("fs.ReadDir over a CloudSoda-shaped FS succeeded; the wrapper may no longer be needed")
	}

	const other = "{6AC1786C-016F-11D2-945F-00C04FB984F9}"
	want := []string{
		".",
		"Policies",
		"Policies/" + defaultDomainPolicy,
		"Policies/" + defaultDomainPolicy + "/GPT.INI",
		"Policies/" + defaultDomainPolicy + "/Machine",
		"Policies/" + defaultDomainPolicy + "/Machine/Registry.pol",
		"Policies/" + other,
		"Policies/" + other + "/GPT.INI",
	}

	var got []string
	err := fs.WalkDir(readDirFS{inner: raw}, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		got = append(got, p)
		return nil
	})
	if err != nil {
		t.Fatalf("fs.WalkDir over readDirFS: %v", err)
	}
	// Order is part of the contract: fs.ReadDirFS requires entries sorted by
	// name, and fs.WalkDir relies on it for a deterministic walk.
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("fs.WalkDir visited\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A directory entry has to answer IsDir correctly or a walk cannot tell a
// GPO folder from a file, and Preferences/*/ enumeration (S-01) breaks.
func TestReadDirFSEntriesReportIsDir(t *testing.T) {
	ents, err := readDirFS{inner: cloudsodaFS{inner: gptTree()}}.ReadDir("Policies/" + defaultDomainPolicy)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	got := map[string]bool{}
	for _, e := range ents {
		got[e.Name()] = e.IsDir()
	}
	want := map[string]bool{"GPT.INI": false, "Machine": true}
	if len(got) != len(want) {
		t.Fatalf("ReadDir returned %v, want entries %v", got, want)
	}
	for name, isDir := range want {
		if d, ok := got[name]; !ok || d != isDir {
			t.Errorf("ReadDir entry %q IsDir = %t (present %t), want %t", name, d, ok, isDir)
		}
	}
}

// Signing is required, never negotiated down (BACKLOG T-03). The negotiated
// result is not readable from CloudSoda's public API, so this pins what the
// client demands; whether the DC also requires it is V-03/dcverify's.
func TestNegotiatorRequiresSigning(t *testing.T) {
	if !negotiator.RequireMessageSigning {
		t.Error("negotiator.RequireMessageSigning = false; SYSVOL carries the policy clients enforce, so the session must be signed")
	}
}

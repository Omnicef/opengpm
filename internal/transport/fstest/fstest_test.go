package fstest

import (
	"errors"
	"io/fs"
	"reflect"
	"sort"
	"testing"
	stdfstest "testing/fstest"
)

// gptTree is a realistic slice of a GPT: the version stamp at the root, a
// machine-side Registry.pol, and one GPP type nested three levels deep. S-01
// walks exactly this shape, so the doubles have to survive it.
func gptTree() map[string][]byte {
	return map[string][]byte{
		"GPT.INI":                            []byte("[General]\nVersion=65539\n"),
		"Machine/Registry.pol":               []byte("PReg\x01\x00\x00\x00"),
		"User/Preferences/Drives/Drives.xml": []byte(`<?xml version="1.0"?><Drives/>`),
	}
}

func TestGPTFSReadFile(t *testing.T) {
	files := gptTree()
	fsys := GPTFS(files)

	for name, want := range files {
		got, err := fs.ReadFile(fsys, name)
		if err != nil {
			t.Errorf("ReadFile(%q): %v", name, err)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("ReadFile(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestGPTFSMissingFile(t *testing.T) {
	fsys := GPTFS(gptTree())

	_, err := fs.ReadFile(fsys, "Machine/Scripts/scripts.ini")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("ReadFile of absent path: err = %v, want fs.ErrNotExist", err)
	}
}

// Intermediate directories are implied by the file paths — nothing declares
// "User/Preferences" but it must still list.
func TestGPTFSReadDirImpliedDirs(t *testing.T) {
	fsys := GPTFS(gptTree())

	cases := map[string][]string{
		".":                       {"GPT.INI", "Machine", "User"},
		"Machine":                 {"Registry.pol"},
		"User":                    {"Preferences"},
		"User/Preferences":        {"Drives"},
		"User/Preferences/Drives": {"Drives.xml"},
	}
	for dir, want := range cases {
		entries, err := fs.ReadDir(fsys, dir)
		if err != nil {
			t.Errorf("ReadDir(%q): %v", dir, err)
			continue
		}
		var got []string
		for _, e := range entries {
			got = append(got, e.Name())
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("ReadDir(%q) = %v, want %v (sorted, per fs.ReadDir)", dir, got, want)
		}
	}
}

func TestGPTFSReadDirEntryIsDir(t *testing.T) {
	fsys := GPTFS(gptTree())

	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		t.Fatalf("ReadDir(.): %v", err)
	}
	want := map[string]bool{"GPT.INI": false, "Machine": true, "User": true}
	for _, e := range entries {
		isDir, ok := want[e.Name()]
		if !ok {
			t.Errorf("unexpected root entry %q", e.Name())
			continue
		}
		if e.IsDir() != isDir {
			t.Errorf("%q: IsDir() = %v, want %v", e.Name(), e.IsDir(), isDir)
		}
	}
}

// This is how S-01 consumes the tree: one WalkDir over the whole GPT,
// discovering GPP types from the directories it finds rather than a list.
func TestGPTFSWalkDir(t *testing.T) {
	fsys := GPTFS(gptTree())

	var got []string
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			path += "/"
		}
		got = append(got, path)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}

	want := []string{
		"./",
		"GPT.INI",
		"Machine/",
		"Machine/Registry.pol",
		"User/",
		"User/Preferences/",
		"User/Preferences/Drives/",
		"User/Preferences/Drives/Drives.xml",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("WalkDir visited\n %v\nwant\n %v", got, want)
	}
}

func TestGPTFSEmpty(t *testing.T) {
	for name, fsys := range map[string]fs.FS{
		"nil map":   GPTFS(nil),
		"empty map": GPTFS(map[string][]byte{}),
	} {
		entries, err := fs.ReadDir(fsys, ".")
		if err != nil {
			t.Errorf("%s: ReadDir(.): %v", name, err)
			continue
		}
		if len(entries) != 0 {
			t.Errorf("%s: ReadDir(.) = %v, want no entries", name, entries)
		}
		if err := stdfstest.TestFS(fsys); err != nil {
			t.Errorf("%s: TestFS: %v", name, err)
		}
	}
}

// The standard library's own conformance check. If GPTFS passes this, every
// stdlib fs helper works against it.
func TestGPTFSConformsToTestFS(t *testing.T) {
	files := gptTree()
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)

	if err := stdfstest.TestFS(GPTFS(files), names...); err != nil {
		t.Fatalf("TestFS: %v", err)
	}
}

var errDenied = errors.New("access denied")

func TestFaultFSOpenFaultedPath(t *testing.T) {
	fsys := FaultFS(GPTFS(gptTree()), map[string]error{"Machine/Registry.pol": errDenied})

	_, err := fs.ReadFile(fsys, "Machine/Registry.pol")
	if err == nil {
		t.Fatal("ReadFile of faulted path succeeded, want error")
	}
	if !errors.Is(err, errDenied) {
		t.Errorf("err = %v, want errors.Is(err, errDenied)", err)
	}
}

// Faults carry sentinel identity through, so callers can distinguish
// "not there" from "not allowed".
func TestFaultFSPreservesSentinel(t *testing.T) {
	fsys := FaultFS(GPTFS(gptTree()), map[string]error{"GPT.INI": fs.ErrPermission})

	_, err := fs.ReadFile(fsys, "GPT.INI")
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("err = %v, want fs.ErrPermission", err)
	}
	if errors.Is(err, fs.ErrNotExist) {
		t.Errorf("err = %v, must not read as fs.ErrNotExist", err)
	}
}

func TestFaultFSPassthrough(t *testing.T) {
	inner := GPTFS(gptTree())
	fsys := FaultFS(inner, map[string]error{"Machine/Registry.pol": errDenied})

	for _, name := range []string{"GPT.INI", "User/Preferences/Drives/Drives.xml"} {
		want, wantErr := fs.ReadFile(inner, name)
		got, gotErr := fs.ReadFile(fsys, name)
		if gotErr != nil || wantErr != nil {
			t.Errorf("ReadFile(%q): got err %v, inner err %v", name, gotErr, wantErr)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("ReadFile(%q) = %q, want inner's %q", name, got, want)
		}
	}

	for _, dir := range []string{".", "User", "User/Preferences"} {
		want, wantErr := fs.ReadDir(inner, dir)
		got, gotErr := fs.ReadDir(fsys, dir)
		if gotErr != nil || wantErr != nil {
			t.Errorf("ReadDir(%q): got err %v, inner err %v", dir, gotErr, wantErr)
			continue
		}
		if len(got) != len(want) {
			t.Errorf("ReadDir(%q) = %d entries, want inner's %d", dir, len(got), len(want))
			continue
		}
		for i := range got {
			if got[i].Name() != want[i].Name() || got[i].IsDir() != want[i].IsDir() {
				t.Errorf("ReadDir(%q)[%d] = %q/%v, want %q/%v",
					dir, i, got[i].Name(), got[i].IsDir(), want[i].Name(), want[i].IsDir())
			}
		}
	}

	if _, err := fs.ReadFile(fsys, "Machine/Missing.pol"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("absent non-faulted path: err = %v, want fs.ErrNotExist", err)
	}
}

// A denied subtree is the common real failure: the walk must see the error at
// the directory, not silently skip it.
func TestFaultFSFaultedDirectory(t *testing.T) {
	fsys := FaultFS(GPTFS(gptTree()), map[string]error{"User/Preferences": errDenied})

	if _, err := fs.ReadDir(fsys, "User/Preferences"); !errors.Is(err, errDenied) {
		t.Errorf("ReadDir of faulted dir: err = %v, want errors.Is(err, errDenied)", err)
	}

	var walkErr error
	seen := map[string]bool{}
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			walkErr = err
			return fs.SkipDir
		}
		seen[path] = true
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}
	if !errors.Is(walkErr, errDenied) {
		t.Errorf("WalkDir surfaced err = %v, want errors.Is(err, errDenied)", walkErr)
	}
	if !seen["GPT.INI"] || !seen["Machine/Registry.pol"] {
		t.Errorf("walk stopped short of unfaulted files: visited %v", seen)
	}
}

func TestFaultFSNoFaults(t *testing.T) {
	fsys := FaultFS(GPTFS(gptTree()), nil)

	if err := stdfstest.TestFS(fsys, "GPT.INI", "Machine/Registry.pol", "User/Preferences/Drives/Drives.xml"); err != nil {
		t.Fatalf("TestFS on unfaulted FaultFS: %v", err)
	}
}

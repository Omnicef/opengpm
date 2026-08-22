// Package fstest provides fs.FS doubles for GPT trees, so parser tests can
// run against an in-memory directory with no domain controller and no SMB.
package fstest

import (
	"io/fs"
	stdfstest "testing/fstest"
)

// GPTFS builds an in-memory fs.FS representing a GPT directory tree from
// path→content pairs. Paths use forward slashes and are fs.FS-style: no
// leading slash, no "." or ".." elements. Intermediate directories named by
// a path are implied — callers list them without declaring them.
//
// An empty or nil map yields a valid, empty FS rather than an error.
func GPTFS(files map[string][]byte) fs.FS {
	m := stdfstest.MapFS{}
	for p, data := range files {
		m[p] = &stdfstest.MapFile{Data: data}
	}
	return m
}

// FaultFS wraps an fs.FS, returning the configured error for exactly the
// given paths, wrapped so errors.Is reports it. A faulted path fails on Open
// and on ReadDir; every other path passes through to inner unchanged.
//
// Faulting a directory is how tests reach the "SYSVOL denied us a subtree"
// case that a real read-only service account hits often.
func FaultFS(inner fs.FS, faults map[string]error) fs.FS {
	return faultFS{inner: inner, faults: faults}
}

type faultFS struct {
	inner  fs.FS
	faults map[string]error
}

func (f faultFS) Open(name string) (fs.File, error) {
	if err, ok := f.faults[name]; ok {
		return nil, err
	}
	return f.inner.Open(name)
}

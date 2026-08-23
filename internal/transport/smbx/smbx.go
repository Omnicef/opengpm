// Package smbx reads SYSVOL over SMB3 and exposes it as an fs.FS, so the
// GPT parsers (S-01) stay transport-agnostic and testable against
// os.DirFS or internal/transport/fstest.
//
// It does no Kerberos of its own. The session authenticates with the
// *client.Client that krb.Client.GSSAPIClient() hands over (T-01), wrapped
// in cloudsoda/go-smb2's Krb5Initiator: one keytab, one TGT, one clock-skew
// code path (SPIKE-T00.md). The PA-FX-FAST workaround that every gokrb5
// login against AD needs belongs to krb and must not be repeated here — a
// second place that touches Kerberos options is a second place to get them
// wrong.
package smbx

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"sort"
	"strings"
	"sync"

	smb2 "github.com/cloudsoda/go-smb2"
	"github.com/jcmturner/gokrb5/v8/client"
)

// The UNC parse failures an operator can act on. gPCFileSysPath arrives
// from AD, not from our own code, so a malformed one is data to be
// rejected with a specific error — never a panic, and never a silent
// fallback that dials something unintended.
var (
	// ErrNotUNC is a path that is not a UNC path at all: no leading
	// separator pair, a bare local path, or the empty string.
	ErrNotUNC = errors.New(`smbx: not a UNC path; gPCFileSysPath is spelled \\<domain>\SysVol\<domain>\Policies\<GUID>\GPT.INI`)

	// ErrNoDomain is a UNC path whose domain component is empty.
	ErrNoDomain = errors.New(`smbx: UNC path has no domain component; the name between the leading \\ and the next separator identifies the domain to resolve`)

	// ErrNoShare is a UNC path that names a domain but no share, so it
	// identifies no tree to mount.
	ErrNoShare = errors.New(`smbx: UNC path names no share; \\<domain> alone identifies no SYSVOL tree`)
)

// negotiator is the only negotiation posture this package uses. Signing is
// required rather than requested: SYSVOL carries the policy that every
// client in the domain enforces, so an unsigned session is a tampering
// position, and a library that negotiates it away leaves no trace in the
// result. It is a package-level value, not a per-call option, so there is
// no code path that can dial without it.
//
// SpecifiedDialect is deliberately left zero, which offers CloudSoda's full
// list from SMB 3.1.1 down. Pinning a dialect is the only way to lose SMB3
// encryption, so not pinning one is how "prefer encryption" is expressed;
// the DC's encryption-required session flag then applies (SPIKE-T00 §4).
//
// This states what the CLIENT demands. Whether the SERVER also requires it
// cannot be read back from the public CloudSoda API (SPIKE-T00 §4), so
// proving the DC's posture is V-03/dcverify's job.
var negotiator = smb2.Negotiator{RequireMessageSigning: true}

// SysvolShare is the share every GPT lives in. Share names are
// case-insensitive on the wire, and ParseUNC canonicalises to upper case so
// callers can compare without folding.
const SysvolShare = "SYSVOL"

// smbPort is the only port this package dials. SMB over NetBIOS (139) is
// not offered: a DC that requires signing and SMB3 serves 445.
const smbPort = "445"

// UNC is a parsed gPCFileSysPath.
//
// Domain is the single most misread field in this package. In
// \\<domain>\SysVol\... the first component is a DOMAIN NAME, not a host:
// it is what §4.1 requires be resolved to the *pinned* DC, so that LDAP and
// SMB read the same replica and version comparisons do not produce false
// "AD and SYSVOL out of sync" alerts. Dialing it verbatim would let DNS
// round-robin pick a different DC on every connection. Parsing keeps it
// separate from anything dialable for exactly that reason; see dialTarget.
type UNC struct {
	// Domain is the domain name to resolve. It is never an address.
	Domain string

	// Share is the share name, canonicalised to upper case (SYSVOL).
	Share string

	// Path is the path within the share as an fs.FS path: forward slashes,
	// no leading or trailing slash, and "." for the share root.
	Path string
}

// isSep reports whether r separates UNC components. gPCFileSysPath is
// written by whatever tool created the GPO, so both spellings arrive, in
// any mix, within one path.
func isSep(r rune) bool { return r == '\\' || r == '/' }

// ParseUNC splits a gPCFileSysPath into its domain, share and in-share
// path.
//
// It accepts backslashes and forward slashes interchangeably, in any mix,
// because gPCFileSysPath is written by whatever tool created the GPO.
// Repeated and trailing separators are collapsed, the share is upper-cased,
// and a path naming only the share yields Path ".".
//
// It returns ErrNotUNC, ErrNoDomain or ErrNoShare for input it cannot
// split, and never panics regardless of input.
func ParseUNC(uncPath string) (UNC, error) {
	r := []rune(uncPath)
	if len(r) < 2 || !isSep(r[0]) || !isSep(r[1]) {
		return UNC{}, fmt.Errorf("%w: %q", ErrNotUNC, uncPath)
	}
	rest := string(r[2:])

	// Domain and share are split one separator at a time rather than by
	// collapsing first: an empty component here is rejected, because
	// guessing at it picks which domain to resolve or which tree to mount.
	domain, after, hasShare := cutFunc(rest, isSep)
	if domain == "" {
		return UNC{}, fmt.Errorf("%w: %q", ErrNoDomain, uncPath)
	}
	if !hasShare {
		return UNC{}, fmt.Errorf("%w: %q", ErrNoShare, uncPath)
	}
	share, tail, _ := cutFunc(after, isSep)
	if share == "" {
		return UNC{}, fmt.Errorf("%w: %q", ErrNoShare, uncPath)
	}

	// Only inside the share are repeated and trailing separators collapsed,
	// which is what turns a wire path into an fs.FS path. FieldsFunc drops
	// empty components, so "." is what remains of the share root.
	path := strings.Join(strings.FieldsFunc(tail, isSep), "/")
	if path == "" {
		path = "."
	}
	return UNC{Domain: domain, Share: strings.ToUpper(share), Path: path}, nil
}

// cutFunc is strings.Cut with a rune predicate instead of a literal
// separator, so a component can end at either spelling.
func cutFunc(s string, sep func(rune) bool) (before, after string, found bool) {
	if i := strings.IndexFunc(s, sep); i >= 0 {
		return s[:i], s[i+1:], true
	}
	return s, "", false
}

// dialTarget reports the address to connect to and the service principal to
// request for u, given the pinned DC from Config.
//
// Both are derived from dc and NEVER from u.Domain. This function is the
// single place that decision is made, so that "resolve the domain to the
// pinned DC" is a property of the package rather than a rule each call site
// is trusted to remember; the unit tests assert u.Domain reaches neither
// return value.
func dialTarget(dc string, u UNC) (addr, spn string) {
	_ = u // present so the rule is visible at every call site, never read.
	return net.JoinHostPort(dc, smbPort), "cifs/" + dc
}

// Config is what a Client needs to reach SYSVOL.
type Config struct {
	// DC is the host of the pinned domain controller (T-02's choice, §4.1).
	// It is the only host this package dials, whatever domain a UNC path
	// names.
	DC string

	// Krb is the Kerberos client from krb.Client.GSSAPIClient(). smbx wraps
	// it in an smb2.Krb5Initiator and adds no Kerberos options of its own.
	Krb *client.Client
}

// Client is an SMB session against one pinned DC.
//
// A GPO walk touches one share hundreds of times, so an implementation is
// expected to mount each share once and keep it for the session's life
// rather than issuing a tree connect per file.
type Client struct {
	dc      string
	session *smb2.Session

	mu     sync.Mutex
	shares map[string]*smb2.Share
}

// Dial establishes an SMB session to cfg.DC authenticated by cfg.Krb.
//
// Message signing is required, not negotiated: SYSVOL carries the policy
// that clients enforce, so an unsigned session is a tampering position.
// SMB3 encryption is preferred and left to the server to require. The
// negotiated state of neither is readable from the public CloudSoda API
// (SPIKE-T00 §4), so proving the server's posture belongs to V-03/dcverify,
// not to a test here.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.DC == "" {
		return nil, errors.New("smbx: Config.DC is empty; the pinned domain controller is the only host this package dials")
	}
	if cfg.Krb == nil {
		return nil, errors.New("smbx: Config.Krb is nil; the SMB session authenticates with the client from krb.Client.GSSAPIClient()")
	}

	// The UNC is zero because neither return value may depend on one: the
	// address and the service ticket name the pinned DC, always.
	addr, spn := dialTarget(cfg.DC, UNC{})
	d := &smb2.Dialer{
		Negotiator: negotiator,
		Initiator:  &smb2.Krb5Initiator{Client: cfg.Krb, TargetSPN: spn},
	}

	// ctx covers the dial only. CloudSoda's session deliberately does not
	// inherit it, and binding one would make Close fail for any caller
	// whose context ends before its cleanup runs.
	s, err := d.Dial(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("smbx: dialing %s as %s: %w", addr, spn, err)
	}
	return &Client{dc: cfg.DC, session: s, shares: map[string]*smb2.Share{}}, nil
}

// Close logs off the session and unmounts every cached share.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var errs []error
	for name, s := range c.shares {
		if err := s.Umount(); err != nil {
			errs = append(errs, fmt.Errorf("smbx: unmounting %s: %w", name, err))
		}
	}
	clear(c.shares)
	if err := c.session.Logoff(); err != nil {
		errs = append(errs, fmt.Errorf("smbx: logging off from %s: %w", c.dc, err))
	}
	return errors.Join(errs...)
}

// resolve parses a full UNC path and returns the mounted share it names
// together with the path within it.
func (c *Client) resolve(uncPath string) (*smb2.Share, string, error) {
	u, err := ParseUNC(uncPath)
	if err != nil {
		return nil, "", err
	}
	s, err := c.mount(u.Share)
	if err != nil {
		return nil, "", err
	}
	return s, u.Path, nil
}

// mount returns the cached tree connect for a share, making it on first
// use. A GPO walk touches one share hundreds of times, so the connect is
// kept for the session's life rather than repeated per file.
//
// The share is mounted on the pinned DC by name, not on the UNC's domain,
// and not on the dialed address — a port in the mount path would reach the
// server as part of the tree name.
func (c *Client) mount(share string) (*smb2.Share, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if s, ok := c.shares[share]; ok {
		return s, nil
	}
	name := `\\` + c.dc + `\` + share
	s, err := c.session.Mount(name)
	if err != nil {
		return nil, fmt.Errorf("smbx: mounting %s: %w", name, err)
	}
	c.shares[share] = s
	return s, nil
}

// Open opens the file named by a full UNC path.
func (c *Client) Open(uncPath string) (fs.File, error) {
	s, path, err := c.resolve(uncPath)
	if err != nil {
		return nil, err
	}
	f, err := s.Open(path)
	if err != nil {
		return nil, fmt.Errorf("smbx: opening %s: %w", uncPath, err)
	}
	return f, nil
}

// ReadDir lists the directory named by a full UNC path.
//
// CloudSoda's Share.ReadDir answers []os.FileInfo, so this converts with
// fs.FileInfoToDirEntry rather than inventing a DirEntry type.
func (c *Client) ReadDir(uncPath string) ([]fs.DirEntry, error) {
	s, path, err := c.resolve(uncPath)
	if err != nil {
		return nil, err
	}
	infos, err := s.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("smbx: listing %s: %w", uncPath, err)
	}
	return dirEntries(infos), nil
}

// FS returns the subtree at a full UNC path as an fs.FS rooted there, which
// is the surface S-01's Walk(fsys fs.FS, root string) consumes.
//
// The returned FS satisfies fs.ReadDirFS. That is not decoration: CloudSoda
// gives us Share.DirFS(), but its FS implements only Open, Stat, ReadFile
// and Glob, and the files it opens carry the os-style Readdir(int)
// ([]os.FileInfo, error) rather than fs.ReadDirFile's ReadDir(int)
// ([]fs.DirEntry, error). fs.ReadDir therefore fails on it with "not
// implemented", and fs.WalkDir with it — while both succeed against
// os.DirFS and testing/fstest.MapFS. A parser tested offline would pass and
// then fail against a real DC. readDirFS closes that gap, and the unit
// tests pin it.
func (c *Client) FS(uncPath string) (fs.FS, error) {
	s, path, err := c.resolve(uncPath)
	if err != nil {
		return nil, err
	}
	return readDirFS{inner: s.DirFS(path)}, nil
}

// readDirFS adapts an fs.FS whose directories are readable only through
// the os.File-style Readdir(n int) ([]os.FileInfo, error) — which is what
// CloudSoda's *smb2.File provides in place of fs.ReadDirFile — into one
// satisfying fs.ReadDirFS, so fs.WalkDir works over it.
//
// Entries are sorted by name, as fs.ReadDirFS requires, and converted with
// fs.FileInfoToDirEntry rather than a hand-rolled DirEntry.
type readDirFS struct {
	inner fs.FS
}

// Compile-time proof of the property the whole wrapper exists for.
var _ fs.ReadDirFS = readDirFS{}

// osStyleDir is the directory shape CloudSoda hands back in place of
// fs.ReadDirFile.
type osStyleDir interface {
	Readdir(n int) ([]os.FileInfo, error)
}

func (f readDirFS) Open(name string) (fs.File, error) {
	return f.inner.Open(name)
}

func (f readDirFS) ReadDir(name string) ([]fs.DirEntry, error) {
	d, err := f.inner.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = d.Close() }()

	dir, ok := d.(osStyleDir)
	if !ok {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: errors.New("smbx: not a directory this FS can enumerate")}
	}
	// -1 asks for every entry in one call, which is the only form that
	// reports the end of the listing as nil rather than io.EOF.
	infos, err := dir.Readdir(-1)
	if err != nil {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: err}
	}
	return dirEntries(infos), nil
}

// dirEntries converts and sorts by name, which fs.ReadDirFS requires and
// fs.WalkDir relies on for a deterministic walk.
func dirEntries(infos []os.FileInfo) []fs.DirEntry {
	ents := make([]fs.DirEntry, len(infos))
	for i, fi := range infos {
		ents[i] = fs.FileInfoToDirEntry(fi)
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].Name() < ents[j].Name() })
	return ents
}

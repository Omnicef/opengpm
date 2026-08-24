package directory

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/Omnicef/opengpm/internal/model"
)

// gPLink entry syntax: [LDAP://<GPO DN>;<gPLinkOptions>], concatenated
// with no separator. Both literals are matched case-insensitively —
// the URL scheme and the DN's attribute types are case-insensitive
// (RFC 4514), and the oracle holds the GUID in both cases.
const (
	linkScheme = "LDAP://"
	guidRDN    = "cn="
)

// ParseGPLink parses a gPLink attribute string into links in PRECEDENCE
// order, highest precedence first. Per O-03: the LAST entry in the
// string has the highest precedence, so parse left-to-right then reverse.
//
// The string is a concatenation of [LDAP://<GPO DN>;<gPLinkOptions>]
// entries (PLAN §4.2). Each entry becomes one model.Link with Order set
// to its 1-based position in the returned slice, which is the link order
// GPMC reports. Entries are never deduped: the same GPO may be linked to
// one SOM more than once with independent options (MS-GPOL 2.2.2).
//
// Do not reimplement the ordering from spec prose or from a PFE script.
// testdata/oracle/gplink/ is the specification; an implementation that
// disagrees with a fixture is wrong (AGENTS.md rule 5).
//
// Enabled and Enforced are derived from Options by callers, not stored:
//
//	Enabled  = (Options & 1) == 0
//	Enforced = (Options & 2) != 0
//
// A malformed entry fails the whole attribute rather than yielding the
// entries around it: a silently dropped entry is a silently changed
// precedence order, which is worse than a rejected gPLink.
func ParseGPLink(s string) ([]model.Link, error) {
	rest := strings.TrimSpace(s)
	if rest == "" {
		return nil, nil
	}

	var links []model.Link
	for rest != "" {
		if rest[0] != '[' {
			return nil, fmt.Errorf("parsing gPLink: expected an entry at %q", rest)
		}
		end := strings.IndexByte(rest, ']')
		if end < 0 {
			return nil, fmt.Errorf("parsing gPLink: unterminated entry at %q", rest)
		}
		link, err := parseGPLinkEntry(rest[1:end])
		if err != nil {
			return nil, err
		}
		links = append(links, link)
		rest = rest[end+1:]
	}

	// The string runs lowest precedence first, so precedence order is
	// the reverse and Order is then just the 1-based position.
	slices.Reverse(links)
	for i := range links {
		links[i].Order = i + 1
	}
	return links, nil
}

// parseGPLinkEntry parses one entry's interior, without its brackets.
// Order is left unset; only the whole attribute knows a link's position.
func parseGPLinkEntry(entry string) (model.Link, error) {
	if len(entry) < len(linkScheme) || !strings.EqualFold(entry[:len(linkScheme)], linkScheme) {
		return model.Link{}, fmt.Errorf("parsing gPLink entry %q: missing %s prefix", entry, linkScheme)
	}
	body := entry[len(linkScheme):]

	// A DN may itself contain an escaped semicolon, so the options
	// segment is the last one, not the first.
	semi := strings.LastIndexByte(body, ';')
	if semi < 0 {
		return model.Link{}, fmt.Errorf("parsing gPLink entry %q: missing %q options separator", entry, ";")
	}
	dn, rawOptions := body[:semi], body[semi+1:]

	options, err := strconv.ParseUint(rawOptions, 10, 32)
	if err != nil {
		return model.Link{}, fmt.Errorf("parsing gPLink entry %q: gPLinkOptions %q: %w", entry, rawOptions, err)
	}

	guid, err := gpoGUIDFromDN(dn)
	if err != nil {
		return model.Link{}, fmt.Errorf("parsing gPLink entry %q: %w", entry, err)
	}

	// GPODN is stored verbatim: the collector groups DNs by domain and
	// rebinds cross-domain links using the DN exactly as the directory
	// holds it (PLAN §4.2).
	return model.Link{GPO: guid, GPODN: dn, Options: uint32(options)}, nil
}

// gpoGUIDFromDN reads the GPO's identity out of the leading cn={...} RDN
// of a GPC DN and returns it braced and upper-case, the form Active
// Directory stores as the object's CN.
func gpoGUIDFromDN(dn string) (model.GUID, error) {
	rdn := dn
	if i := strings.IndexByte(rdn, ','); i >= 0 {
		rdn = rdn[:i]
	}
	if len(rdn) < len(guidRDN) || !strings.EqualFold(rdn[:len(guidRDN)], guidRDN) {
		return "", fmt.Errorf("DN %q does not start with a %s RDN", dn, guidRDN)
	}
	guid := rdn[len(guidRDN):]
	if len(guid) < 3 || guid[0] != '{' || guid[len(guid)-1] != '}' {
		return "", fmt.Errorf("DN %q: GPO GUID %q is not braced", dn, guid)
	}
	return model.GUID(strings.ToUpper(guid)), nil
}

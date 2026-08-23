package directory

import (
	"errors"

	"github.com/Omnicef/opengpm/internal/model"
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
func ParseGPLink(s string) ([]model.Link, error) {
	return nil, errors.New("parsing gPLink: not implemented")
}

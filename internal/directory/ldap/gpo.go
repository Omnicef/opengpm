// Package ldap implements directory.Reader against a live Active
// Directory over LDAP (PLAN §4.1). It is the only package that knows
// LDAP attribute names; everything above it speaks model types.
package ldap

import (
	"errors"

	"github.com/go-ldap/ldap/v3"

	"github.com/Omnicef/opengpm/internal/model"
)

// parseGPOEntry converts one groupPolicyContainer LDAP entry into a
// model.GPO. It never drops an entry: a GPO whose security descriptor
// is absent or unparseable is still returned, with Security nil.
func parseGPOEntry(e *ldap.Entry, parseSD func([]byte) (*model.SecurityDescriptor, error)) (model.GPO, error) {
	return model.GPO{}, errors.New("parsing groupPolicyContainer: parseGPOEntry is not implemented (D-02)")
}

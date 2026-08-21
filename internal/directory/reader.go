// Package directory defines the read interface to Active Directory.
//
// Per PLAN §3.5 it exists now so a Writer can be added later without
// reshaping callers; only read is in scope for this project.
package directory

import (
	"context"

	"github.com/Omnicef/opengpm/internal/model"
)

// Reader is the read-only view of a domain's Group Policy state.
//
// GPOChildren covers the AD-stored settings (wireless/wired policy,
// packageRegistration) that do not live in SYSVOL (PLAN §4.1).
type Reader interface {
	GPOs(ctx context.Context, domainDN string) ([]model.GPO, error)
	SOMTree(ctx context.Context, domainDN string) (*model.SOM, error)
	Sites(ctx context.Context) ([]model.SOM, error)
	WMIFilters(ctx context.Context, domainDN string) ([]model.WMIFilter, error)
	GPOChildren(ctx context.Context, gpoDN string) ([]model.ADChildSetting, error)
	ResolveSIDs(ctx context.Context, sids []model.SID) (map[model.SID]string, error)
}

// Package store defines the content-addressed snapshot store (PLAN §3.3).
//
// Everything is keyed by (tenant, domain) from day one (PLAN §3.6);
// a single-domain deployment is just one implicit tenant.
package store

import (
	"context"
	"time"

	"github.com/Omnicef/opengpm/internal/model"
)

// TenantID identifies a tenant (one UI can front many collectors).
type TenantID string

// DomainID identifies a domain within a tenant.
type DomainID string

// SnapshotID is the content hash of a Snapshot. Equal content, equal
// ID; the store never rewrites or deletes a stored snapshot.
type SnapshotID string

// Snapshot is the immutable, content-addressed result of one sweep of
// a domain (PLAN §3.3). Settings are joined to GPOs by GPO ID.
type Snapshot struct {
	TakenAt    time.Time
	GPOs       []model.GPO
	Settings   map[model.GUID][]model.Setting
	SOM        *model.SOM
	Sites      []model.SOM
	WMIFilters []model.WMIFilter
}

// SnapshotInfo is the metadata of one stored snapshot, as returned by
// ListSnapshots.
type SnapshotInfo struct {
	ID      SnapshotID
	TakenAt time.Time
}

// Scope bounds a Search. Empty fields mean "all": no domain = every
// domain of the tenant, no GPO = every GPO, no snapshot = the latest.
type Scope struct {
	Tenant   TenantID
	Domain   DomainID
	GPO      model.GUID
	Snapshot SnapshotID
}

// Hit is one matched setting in a Search result.
type Hit struct {
	Snapshot SnapshotID
	GPO      model.GUID
	Key      model.SettingKey
	Setting  model.Setting
}

// Store persists and queries domain snapshots.
type Store interface {
	// PutSnapshot stores snap under (tenant, domain) and returns its
	// content-derived SnapshotID.
	PutSnapshot(ctx context.Context, tenant TenantID, domain DomainID, snap Snapshot) (SnapshotID, error)

	// GetSnapshot returns the stored snapshot with the given ID, or an
	// error if it does not exist for (tenant, domain).
	GetSnapshot(ctx context.Context, tenant TenantID, domain DomainID, id SnapshotID) (*Snapshot, error)

	// ListSnapshots returns the metadata of all stored snapshots for
	// (tenant, domain), newest first.
	ListSnapshots(ctx context.Context, tenant TenantID, domain DomainID) ([]SnapshotInfo, error)

	// Search finds settings matching query within scope.
	Search(ctx context.Context, query string, scope Scope) ([]Hit, error)
}

package model

// SOMKind classifies a scope of management.
type SOMKind uint8

const (
	SOMDomain SOMKind = iota
	SOMOU
	SOMSite
)

// Link is one gPLink entry (PLAN §4.2). Order is the 1-based position
// in the gPLink string: 1 is highest precedence. The same GPO may be
// linked more than once to one SOM; entries are not deduped by GUID.
type Link struct {
	GPO     GUID
	GPODN   string // the linked GPO may live in another domain
	Options uint32 // gPLinkOptions: 0 enabled, 1 disabled, 2 enforced, 3 disabled+enforced (behaves as disabled)
	Order   int
}

// SOM is a scope of management: a domain, an OU, or a site.
type SOM struct {
	DN               string
	Name             string
	Kind             SOMKind
	Links            []Link
	BlockInheritance bool // gPOptions == 1
	Children         []*SOM
}

// WMIFilter is an msWMI-Som object (PLAN §4.2). Query is for display
// only and is never executed.
type WMIFilter struct {
	GUID  GUID // msWMI-Id
	Name  string
	Query string // msWMI-Parm2
}

// ADChildSetting is a setting stored as an AD child object of the GPC
// rather than in SYSVOL (PLAN §4.1): wireless/wired policy and
// software installation.
type ADChildSetting struct {
	Kind       string // "ieee80211" | "ieee8023" | "software"
	Payload    string // raw object content, best-effort
	Unresolved bool
}

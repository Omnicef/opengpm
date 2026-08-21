package model

import "time"

// GUID is a GPO identity ({...}) or other GUID-form identifier.
type GUID string

// SID is a Windows security identifier (S-1-...).
type SID string

// Class selects the policy half a setting applies to.
type Class uint8

const (
	ClassMachine Class = iota
	ClassUser
	ClassBoth
)

// GPOFlags is the packed gPC flags attribute (PLAN §4.1).
type GPOFlags uint8

const (
	GPOEnabled          GPOFlags = 0
	GPOUserDisabled     GPOFlags = 1
	GPOComputerDisabled GPOFlags = 2
	GPOAllDisabled      GPOFlags = 3
)

// CSERef identifies a client-side extension by its GUID
// (gPCMachineExtensionNames / gPCUserExtensionNames).
type CSERef string

// WMIFilterRef references the WMI filter attached to a GPO by its
// msWMI-Id (gPCWQLFilter).
type WMIFilterRef GUID

// GPO is the canonical form of a groupPolicyContainer (PLAN §4.1),
// joined with the SYSVOL-side versions from GPT.INI.
type GPO struct {
	ID                    GUID
	DisplayName           string
	DomainDN              string
	FileSysPath           string
	UserVersion           uint16 // high 16 bits of versionNumber
	ComputerVersion       uint16 // low 16 bits
	SysvolUserVersion     uint16 // from GPT.INI
	SysvolComputerVersion uint16
	Flags                 GPOFlags
	FunctionalityVersion  int
	MachineExtensions     []CSERef
	UserExtensions        []CSERef
	WMIFilter             *WMIFilterRef
	Security              *SecurityDescriptor
	WhenCreated           time.Time
	WhenChanged           time.Time
}

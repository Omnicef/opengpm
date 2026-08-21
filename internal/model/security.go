package model

// ReadRight is the DACL access-mask bit for Read.
const ReadRight uint32 = 0x00020000

// ApplyGroupPolicy is the Apply Group Policy extended right
// (edacfd8f-ffb3-11d1-b41d-00a0c968f939, PLAN §4.6).
const ApplyGroupPolicy = GUID("edacfd8f-ffb3-11d1-b41d-00a0c968f939")

// ACEType distinguishes allow and deny ACEs.
type ACEType uint8

const (
	ACEAllow ACEType = iota
	ACEDeny
)

// ACE is one access-control entry of a DACL.
type ACE struct {
	Type           ACEType
	SID            SID
	AccessMask     uint32
	ExtendedRights []GUID
}

// SecurityDescriptor is the parsed nTSecurityDescriptor of a GPC
// (PLAN §4.6).
type SecurityDescriptor struct {
	Owner SID
	Group SID
	ACEs  []ACE
}

// AppliesTo reports whether both Read and the Apply Group Policy
// extended right are granted to the union of sids — the
// security-filtering test (PLAN §4.6).
//
// A right is DENIED if any deny ACE matching any SID in sids carries
// it; deny wins over allow regardless of ACE order. A right is GRANTED
// if it is not denied and at least one allow ACE matching any SID in
// sids carries it. AppliesTo is true iff both rights are granted.
//
// Caveat: this is a deliberate simplification of Windows first-match
// ACE evaluation. In canonical DACLs explicit denies precede allows,
// so deny-wins agrees with Windows on canonical ACLs and fails safe on
// non-canonical ones.
func (sd *SecurityDescriptor) AppliesTo(sids []SID) bool {
	if sd == nil {
		return false
	}
	var allowMask, denyMask uint32
	allowAGP, denyAGP := false, false
	for _, ace := range sd.ACEs {
		if !containsSID(ace.SID, sids) {
			continue
		}
		hasAGP := containsGUID(ApplyGroupPolicy, ace.ExtendedRights)
		switch ace.Type {
		case ACEAllow:
			allowMask |= ace.AccessMask
			allowAGP = allowAGP || hasAGP
		case ACEDeny:
			denyMask |= ace.AccessMask
			denyAGP = denyAGP || hasAGP
		}
	}
	readGranted := allowMask&ReadRight != 0 && denyMask&ReadRight == 0
	agpGranted := allowAGP && !denyAGP
	return readGranted && agpGranted
}

func containsSID(sid SID, sids []SID) bool {
	for _, s := range sids {
		if s == sid {
			return true
		}
	}
	return false
}

func containsGUID(g GUID, guids []GUID) bool {
	for _, x := range guids {
		if x == g {
			return true
		}
	}
	return false
}

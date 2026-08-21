package model

// ReadRight is the DACL access-mask bit for Read.
const ReadRight uint32 = 0x00020000

// ApplyGroupPolicy is the Apply Group Policy extended right
// (edacfd8f-ffb3-11d1-b41d-00a0c968f939, PLAN §4.6).
const ApplyGroupPolicy = GUID("edacfd8f-ffb3-11d1-b41d-00a0c968f939")

// ACE is one access-control entry of a DACL.
type ACE struct {
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

// AppliesTo reports whether the union of the access granted to any of
// sids includes both Read and the Apply Group Policy extended right —
// the security-filtering test (PLAN §4.6).
//
// ponytail: grant-only evaluation; deny ACEs are ignored. Add deny
// handling if a managed domain actually uses deny ACEs on GPCs.
func (sd *SecurityDescriptor) AppliesTo(sids []SID) bool {
	if sd == nil {
		return false
	}
	var mask uint32
	hasAGP := false
	for _, ace := range sd.ACEs {
		matched := false
		for _, sid := range sids {
			if sid == ace.SID {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		mask |= ace.AccessMask
		for _, er := range ace.ExtendedRights {
			if er == ApplyGroupPolicy {
				hasAGP = true
			}
		}
	}
	return mask&ReadRight != 0 && hasAGP
}

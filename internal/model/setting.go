package model

// SettingSource identifies where a Setting came from (PLAN §4.5).
type SettingSource uint8

const (
	SourceRegistry SettingSource = iota
	SourceSecEdit
	SourceGPP
	SourceScript
	SourceFolderRedirect
	SourceAudit
	SourceWireless
	SourceSoftware
)

// SettingState is the tri-state a setting renders as.
type SettingState uint8

const (
	StateEnabled SettingState = iota
	StateDisabled
	StateNotConfigured
)

// Element is one resolved ADMX element value of a Setting.
type Element struct {
	Name  string
	Value string
}

// RawValue is a raw registry value. Settings always retain their raw
// values, resolved or not (PLAN §4.4).
type RawValue struct {
	Key   string // full registry key path
	Value string // value name; "" for key-level values
	Type  uint32 // REG_* value type
	Data  []byte
}

// Setting is one rendered policy setting.
type Setting struct {
	Class      Class
	Source     SettingSource
	Category   []string // breadcrumb, e.g. ["Administrative Templates", "System"]
	Name       string   // ADMX display name, or raw path if unresolved
	State      SettingState
	Elements   []Element // resolved ADMX element values
	Raw        []RawValue
	Comment    string
	Unresolved bool // true = no ADMX definition matched
}

// SettingKey is the snapshot-stable identity of a Setting. Stability
// across snapshots is what diff (PLAN §6.5) relies on.
type SettingKey struct {
	Class  Class
	Source SettingSource
	ID     string
}

// Key derives the SettingKey. For registry-sourced settings the ID is
// the primary registry key/value path, which survives ADMX catalog
// changes; for other sources it is the setting name.
func (s Setting) Key() SettingKey {
	id := s.Name
	if s.Source == SourceRegistry && len(s.Raw) > 0 {
		id = s.Raw[0].Key + "\\" + s.Raw[0].Value
	}
	return SettingKey{Class: s.Class, Source: s.Source, ID: id}
}

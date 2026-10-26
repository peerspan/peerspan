package host

import "encoding/json"

// Rust's persisted tool_servers record nests the definition, discovery snapshot
// and health. Go's existing writer stores those fields flat. Read either exact
// persisted form without rewriting it merely because the daemon was switched.
func (r *toolServerRecord) UnmarshalJSON(raw []byte) error {
	type flat toolServerRecord
	var fields map[string]json.RawMessage
	if e := json.Unmarshal(raw, &fields); e != nil {
		return e
	}
	definition, present := fields["definition"]
	if !present {
		var value flat
		if e := json.Unmarshal(raw, &value); e != nil {
			return e
		}
		*r = toolServerRecord(value)
		return nil
	}
	if string(definition) == "null" {
		return ErrInvalid
	}
	var nested struct {
		Definition ToolServerDefinition `json:"definition"`
		Workspace  string               `json:"workspace"`
		Shareable  bool                 `json:"shareable"`
		Reason     *string              `json:"reason"`
		Missing    []string             `json:"missing_env"`
		AuthMode   *string              `json:"auth_mode"`
		Challenge  *authChallenge       `json:"challenge"`
		Snapshot   *struct {
			Tools     []SnapshotTool     `json:"tools"`
			Resources []SnapshotResource `json:"resources"`
			Taken     string             `json:"taken_at"`
			Reach     *GHReach           `json:"reach"`
		} `json:"snapshot"`
		Error  *string `json:"snapshot_error"`
		Health struct {
			Start               *string `json:"start_failed_at"`
			Auth                *string `json:"auth_error_at"`
			InsufficientScopeAt *string `json:"insufficient_scope_at"`
			InsufficientScope   *string `json:"insufficient_scope"`
		} `json:"health"`
	}
	if e := json.Unmarshal(raw, &nested); e != nil {
		return e
	}
	if nested.Definition.Name == "" || nested.Definition.Transport == "" || nested.Definition.Source == "" {
		return ErrInvalid
	}
	*r = toolServerRecord{ToolServerDefinition: nested.Definition, Workspace: nested.Workspace, Shareable: nested.Shareable, Reason: nested.Reason, MissingEnv: nested.Missing, AuthMode: nested.AuthMode, Challenge: nested.Challenge, toolSnapshotState: toolSnapshotState{SnapshotError: nested.Error, StartFailedAt: nested.Health.Start, AuthErrorAt: nested.Health.Auth, InsufficientScopeAt: nested.Health.InsufficientScopeAt, InsufficientScope: nested.Health.InsufficientScope}}
	if snapshot := nested.Snapshot; snapshot != nil {
		r.Tools = snapshot.Tools
		r.Resources = snapshot.Resources
		r.SnapshotAt = &snapshot.Taken
		r.Reach = snapshot.Reach
	}
	return nil
}

package membership

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Owner access policy (milestone 2b, slice 3). An owner signs, in SSHSIG
// format, one policy per network that grants persons, groups, or every member
// host access to the owner's agents. Policies name persons by ID, never by
// label. For each owner the highest valid version applies.

const (
	PolicyActionMessage = "message.append"
	PolicyActionTask    = "task.submit"
	PolicyMaxRules      = 64
	PolicyMaxPrincipals = 64
	// PolicyMaxArtifactBytes bounds a rule's max_artifact_bytes (1 GiB).
	PolicyMaxArtifactBytes = 1 << 30
	PolicyMinValidity      = 24 * time.Hour
	PolicyMaxValidity      = 90 * 24 * time.Hour
	// PolicySkew is the clock skew allowed before issued_at.
	PolicySkew = 5 * time.Minute
	// PrincipalNetwork matches every member host of the policy's network.
	PrincipalNetwork = "network"
	// PolicyAgentAll is the rule agent meaning every agent of the owner. A
	// receiver applies the rules naming an agent if there are any, and
	// otherwise the * rules. Agents cannot be registered under this name.
	PolicyAgentAll = "*"

	// PolicyFormat2 is the peerspan-policy-v2 statement, with capability
	// rules and trusted hosts. Signers always produce it; version 1 is still
	// read.
	PolicyFormat2            = 2
	PolicyMaxCapabilityRules = 64
	PolicyMaxTrustedHosts    = 64
	PolicyMaxInputBytes      = 262144
	PolicyMaxCallsPerHour    = 10000
	// OperationRead is the operation that reads a capability's resources;
	// no capability may be named after it.
	OperationRead = "read"
)

var capabilityNames = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// ValidName reports whether a server or capability name is
// [a-z0-9][a-z0-9_-]{0,62}.
func ValidName(name string) bool { return capabilityNames.MatchString(name) }

// ValidCapabilityName reports whether a capability may have this name: it
// matches the name pattern and is not the reserved operation read.
func ValidCapabilityName(name string) bool { return ValidName(name) && name != OperationRead }

// checkCapabilityRule validates one capability rule.
func checkCapabilityRule(r CapabilityRule) error {
	if !ValidHostID(r.Host) {
		return fmt.Errorf("%w: a capability rule's host is a host ID, not %q", ErrInvalid, r.Host)
	}
	if !ValidCapabilityName(r.Capability) {
		return fmt.Errorf("%w: invalid capability name %q in a capability rule", ErrInvalid, r.Capability)
	}
	if len(r.Principals) == 0 || len(r.Principals) > PolicyMaxPrincipals {
		return fmt.Errorf("%w: a capability rule needs 1 to %d principals", ErrInvalid, PolicyMaxPrincipals)
	}
	for _, principal := range r.Principals {
		if !ValidPrincipal(principal) {
			return fmt.Errorf("%w: invalid principal %q", ErrInvalid, principal)
		}
	}
	if r.MaxInputBytes < 1 || r.MaxInputBytes > PolicyMaxInputBytes {
		return fmt.Errorf("%w: max_input_bytes must be 1 to %d", ErrInvalid, PolicyMaxInputBytes)
	}
	if r.MaxCallsPerHour < 1 || r.MaxCallsPerHour > PolicyMaxCallsPerHour {
		return fmt.Errorf("%w: max_calls_per_hour must be 1 to %d", ErrInvalid, PolicyMaxCallsPerHour)
	}
	return nil
}

// RuleApplies reports whether a rule applies to the agent named agent, given
// whether the policy has any rule naming that agent.
func RuleApplies(rule PolicyRule, agent string, named bool) bool {
	if named {
		return rule.Agent == agent
	}
	return rule.Agent == PolicyAgentAll
}

// NamesAgent reports whether any rule names agent exactly.
func NamesAgent(p Policy, agent string) bool {
	for _, r := range p.Rules {
		if r.Agent == agent {
			return true
		}
	}
	return false
}

type PolicyRule struct {
	Agent           string   `json:"agent"`
	Principals      []string `json:"principals"`
	Actions         []string `json:"actions"`
	MaxMessageBytes int64    `json:"max_message_bytes"`
	// MaxArtifactBytes bounds a task's input and result artifacts together;
	// 0, the default, refuses artifacts. It is omitted from JSON when 0.
	MaxArtifactBytes  int64 `json:"max_artifact_bytes,omitempty"`
	AllowDisconnected bool  `json:"allow_disconnected"`
}

type Policy struct {
	// Format is 2 for a peerspan-policy-v2 statement; 0 is version 1, whose
	// JSON has no format, capability_rules, or trusted_hosts.
	Format          int          `json:"format,omitempty"`
	NetworkID       string       `json:"network_id"`
	PersonPublicKey string       `json:"person_public_key"`
	Version         int64        `json:"version"`
	IssuedAt        string       `json:"issued_at"`
	ValidUntil      string       `json:"valid_until"`
	Rules           []PolicyRule `json:"rules"`
	// CapabilityRules and TrustedHosts exist only in format 2.
	CapabilityRules []CapabilityRule `json:"capability_rules,omitempty"`
	TrustedHosts    []string         `json:"trusted_hosts,omitempty"`
	Signature       string           `json:"signature"`
}

// CapabilityRule is a v2 share: its principals may call the operations of
// the capability on the host it names, within its bounds. Only that host
// honours it.
type CapabilityRule struct {
	Host              string   `json:"host"`
	Capability        string   `json:"capability"`
	Principals        []string `json:"principals"`
	MaxInputBytes     int64    `json:"max_input_bytes"`
	AllowDisconnected bool     `json:"allow_disconnected"`
	MaxCallsPerHour   int64    `json:"max_calls_per_hour"`
}

func (r *CapabilityRule) UnmarshalJSON(data []byte) error {
	type plain CapabilityRule
	return Strict(data, (*plain)(r), "host", "capability", "principals", "max_input_bytes", "allow_disconnected", "max_calls_per_hour")
}

// MarshalJSON writes a version 1 policy in its original shape, and a format
// 2 policy with format, capability_rules, and trusted_hosts, never omitted.
func (p Policy) MarshalJSON() ([]byte, error) {
	if p.Format != PolicyFormat2 {
		type v1 struct {
			NetworkID       string       `json:"network_id"`
			PersonPublicKey string       `json:"person_public_key"`
			Version         int64        `json:"version"`
			IssuedAt        string       `json:"issued_at"`
			ValidUntil      string       `json:"valid_until"`
			Rules           []PolicyRule `json:"rules"`
			Signature       string       `json:"signature"`
		}
		return json.Marshal(v1{p.NetworkID, p.PersonPublicKey, p.Version, p.IssuedAt, p.ValidUntil, p.Rules, p.Signature})
	}
	type v2 struct {
		Format          int              `json:"format"`
		NetworkID       string           `json:"network_id"`
		PersonPublicKey string           `json:"person_public_key"`
		Version         int64            `json:"version"`
		IssuedAt        string           `json:"issued_at"`
		ValidUntil      string           `json:"valid_until"`
		Rules           []PolicyRule     `json:"rules"`
		CapabilityRules []CapabilityRule `json:"capability_rules"`
		TrustedHosts    []string         `json:"trusted_hosts"`
		Signature       string           `json:"signature"`
	}
	capabilities, trusted := p.CapabilityRules, p.TrustedHosts
	if capabilities == nil {
		capabilities = []CapabilityRule{}
	}
	if trusted == nil {
		trusted = []string{}
	}
	return json.Marshal(v2{p.Format, p.NetworkID, p.PersonPublicKey, p.Version, p.IssuedAt, p.ValidUntil, p.Rules, capabilities, trusted, p.Signature})
}

// UnmarshalJSON accepts exactly the rule's fields; max_artifact_bytes is
// optional.
func (r *PolicyRule) UnmarshalJSON(data []byte) error {
	type plain PolicyRule
	fields := []string{"agent", "principals", "actions", "max_message_bytes", "allow_disconnected"}
	var raw map[string]json.RawMessage
	if json.Unmarshal(data, &raw) == nil {
		if _, ok := raw["max_artifact_bytes"]; ok {
			fields = append(fields, "max_artifact_bytes")
		}
	}
	return Strict(data, (*plain)(r), fields...)
}

// UnmarshalJSON accepts a version 1 policy exactly, or a format 2 policy,
// which also has format, capability_rules, and trusted_hosts.
func (p *Policy) UnmarshalJSON(data []byte) error {
	type plain Policy
	fields := []string{"network_id", "person_public_key", "version", "issued_at", "valid_until", "rules", "signature"}
	var raw map[string]json.RawMessage
	v2 := false
	if json.Unmarshal(data, &raw) == nil {
		if _, v2 = raw["format"]; v2 {
			fields = append(fields, "format", "capability_rules", "trusted_hosts")
		}
	}
	*p = Policy{}
	if err := Strict(data, (*plain)(p), fields...); err != nil {
		return err
	}
	if v2 && p.Format != PolicyFormat2 {
		return fmt.Errorf("%w: unknown policy format %d", ErrInvalid, p.Format)
	}
	return nil
}

// Message is the policy's signed lines: a header, then five lines per rule
// in JSON order. A nonzero max_artifact_bytes is appended to the fifth line,
// so policies without artifacts sign as before. A format 2 policy has the
// header peerspan-policy-v2, then six lines per capability rule, and a final
// line of trusted followed by the sorted trusted host IDs.
func (p Policy) Message() []byte {
	header := "peerspan-policy-v1"
	if p.Format == PolicyFormat2 {
		header = "peerspan-policy-v2"
	}
	lines := []string{header, p.NetworkID, p.PersonPublicKey, strconv.FormatInt(p.Version, 10), p.IssuedAt, p.ValidUntil}
	for _, r := range p.Rules {
		bounds := strconv.FormatInt(r.MaxMessageBytes, 10) + " " + strconv.FormatBool(r.AllowDisconnected)
		if r.MaxArtifactBytes != 0 {
			bounds += " " + strconv.FormatInt(r.MaxArtifactBytes, 10)
		}
		lines = append(lines, "rule", r.Agent, strings.Join(r.Principals, " "), strings.Join(r.Actions, " "), bounds)
	}
	if p.Format != PolicyFormat2 {
		return statement(lines...)
	}
	for _, r := range p.CapabilityRules {
		bounds := strconv.FormatInt(r.MaxInputBytes, 10) + " " + strconv.FormatBool(r.AllowDisconnected) + " " + strconv.FormatInt(r.MaxCallsPerHour, 10)
		lines = append(lines, "capability_rule", r.Host, r.Capability, strings.Join(r.Principals, " "), bounds, "end")
	}
	trusted := append([]string{}, p.TrustedHosts...)
	sort.Strings(trusted)
	lines = append(lines, strings.Join(append([]string{"trusted"}, trusted...), " "))
	return statement(lines...)
}

// ValidPrincipal reports whether a principal is person:<person ID>,
// group:<name>, network, or agent:<host ID>/<agent ID>.
func ValidPrincipal(p string) bool {
	switch {
	case p == PrincipalNetwork:
		return true
	case strings.HasPrefix(p, "agent:"):
		_, _, ok := AgentPrincipal(p)
		return ok
	case strings.HasPrefix(p, "person:"):
		return ValidPersonID(strings.TrimPrefix(p, "person:"))
	case strings.HasPrefix(p, "group:"):
		return ValidGroupName(strings.TrimPrefix(p, "group:"))
	}
	return false
}

// policyWindow returns the policy's parsed validity window.
func policyWindow(p Policy) (time.Time, time.Time, error) {
	issued, err1 := ParseTime(p.IssuedAt)
	until, err2 := ParseTime(p.ValidUntil)
	if err1 != nil || err2 != nil {
		return issued, until, fmt.Errorf("%w: policy times must be RFC3339", ErrInvalid)
	}
	return issued, until, nil
}

// CheckPolicy validates a policy's shape, without its signature or window.
func CheckPolicy(network string, p Policy) error {
	if p.NetworkID != network {
		return fmt.Errorf("%w: policy is for a different network", ErrInvalid)
	}
	if _, err := DecodeKey(p.PersonPublicKey); err != nil {
		return fmt.Errorf("%w: invalid policy owner key", ErrInvalid)
	}
	if p.Version < 1 {
		return fmt.Errorf("%w: policy version must be at least 1", ErrInvalid)
	}
	issued, until, err := policyWindow(p)
	if err != nil {
		return err
	}
	if d := until.Sub(issued); d < PolicyMinValidity || d > PolicyMaxValidity {
		return fmt.Errorf("%w: a policy must be valid for 1 to 90 days", ErrInvalid)
	}
	if p.Rules == nil || len(p.Rules) > PolicyMaxRules {
		return fmt.Errorf("%w: a policy has at most %d rules", ErrInvalid, PolicyMaxRules)
	}
	for _, r := range p.Rules {
		if !ValidLabel(r.Agent) {
			return fmt.Errorf("%w: invalid agent name %q in a policy rule", ErrInvalid, r.Agent)
		}
		if len(r.Principals) == 0 || len(r.Principals) > PolicyMaxPrincipals {
			return fmt.Errorf("%w: a rule needs 1 to %d principals", ErrInvalid, PolicyMaxPrincipals)
		}
		for _, principal := range r.Principals {
			if !ValidPrincipal(principal) {
				return fmt.Errorf("%w: invalid principal %q; use person:<person ID>, group:<name>, network, or agent:<host ID>/<agent ID>", ErrInvalid, principal)
			}
		}
		if len(r.Actions) == 0 {
			return fmt.Errorf("%w: a rule needs an action", ErrInvalid)
		}
		for _, action := range r.Actions {
			if !ValidPolicyAction(action) {
				return fmt.Errorf("%w: actions are %s, %s, and %s", ErrInvalid, PolicyActionMessage, PolicyActionTask, PolicyActionDelegate)
			}
		}
		if r.MaxMessageBytes < 1 || r.MaxMessageBytes > 65536 {
			return fmt.Errorf("%w: max_message_bytes must be 1 to 65536", ErrInvalid)
		}
		if r.MaxArtifactBytes < 0 || r.MaxArtifactBytes > PolicyMaxArtifactBytes {
			return fmt.Errorf("%w: max_artifact_bytes must be 0 to %d", ErrInvalid, PolicyMaxArtifactBytes)
		}
		if r.MaxArtifactBytes != 0 && !hasPolicyAction(r.Actions, PolicyActionTask) && !hasPolicyAction(r.Actions, PolicyActionDelegate) {
			return fmt.Errorf("%w: max_artifact_bytes needs the action %s or %s", ErrInvalid, PolicyActionTask, PolicyActionDelegate)
		}
	}
	switch p.Format {
	case 0:
		if p.CapabilityRules != nil || p.TrustedHosts != nil {
			return fmt.Errorf("%w: a version 1 policy has no capability rules or trusted hosts", ErrInvalid)
		}
	case PolicyFormat2:
		if p.CapabilityRules == nil || len(p.CapabilityRules) > PolicyMaxCapabilityRules {
			return fmt.Errorf("%w: a policy has at most %d capability rules", ErrInvalid, PolicyMaxCapabilityRules)
		}
		names := map[string]bool{}
		for _, r := range p.CapabilityRules {
			if err := checkCapabilityRule(r); err != nil {
				return err
			}
			// A name is bound to one host, with one rule, per policy.
			if names[r.Capability] {
				return fmt.Errorf("%w: capability %q has more than one rule", ErrInvalid, r.Capability)
			}
			names[r.Capability] = true
		}
		if p.TrustedHosts == nil || len(p.TrustedHosts) > PolicyMaxTrustedHosts {
			return fmt.Errorf("%w: a policy has at most %d trusted hosts", ErrInvalid, PolicyMaxTrustedHosts)
		}
		seen := map[string]bool{}
		for _, h := range p.TrustedHosts {
			if !ValidHostID(h) || seen[h] {
				return fmt.Errorf("%w: trusted hosts are distinct host IDs; %q is not", ErrInvalid, h)
			}
			seen[h] = true
		}
	default:
		return fmt.Errorf("%w: unknown policy format %d", ErrInvalid, p.Format)
	}
	return nil
}

// PolicyBody is what an owner signs in a policy besides its header: rules,
// capability rules, and trusted hosts.
type PolicyBody struct {
	Rules           []PolicyRule
	CapabilityRules []CapabilityRule
	TrustedHosts    []string
}

// Body is the policy's rules, capability rules, and trusted hosts, copied.
func (p Policy) Body() PolicyBody {
	b := PolicyBody{Rules: []PolicyRule{}, CapabilityRules: []CapabilityRule{}, TrustedHosts: append([]string{}, p.TrustedHosts...)}
	for _, r := range p.Rules {
		r.Principals = append([]string{}, r.Principals...)
		r.Actions = append([]string{}, r.Actions...)
		b.Rules = append(b.Rules, r)
	}
	for _, r := range p.CapabilityRules {
		r.Principals = append([]string{}, r.Principals...)
		b.CapabilityRules = append(b.CapabilityRules, r)
	}
	return b
}

// SignPolicyV2 signs a format 2 policy as its owner. Rules, capability rules, and
// their lists are copied in the given order, which the signature covers;
// trusted hosts are sorted.
func SignPolicyV2(owner PersonSigner, network string, version int64, issued time.Time, validFor time.Duration, body PolicyBody) (Policy, error) {
	p := Policy{Format: PolicyFormat2, NetworkID: network, PersonPublicKey: EncodeKey(owner.PublicKey()), Version: version, IssuedAt: Timestamp(issued), ValidUntil: Timestamp(issued.Add(validFor))}
	b := Policy{Rules: body.Rules, CapabilityRules: body.CapabilityRules, TrustedHosts: body.TrustedHosts}.Body()
	p.Rules, p.CapabilityRules, p.TrustedHosts = b.Rules, b.CapabilityRules, b.TrustedHosts
	sort.Strings(p.TrustedHosts)
	if err := CheckPolicy(network, p); err != nil {
		return p, err
	}
	var err error
	p.Signature, err = SignSSHSIG(owner, p.Message())
	return p, err
}

// VerifyPolicy checks a policy's shape and its owner's SSHSIG signature. It
// does not check the validity window: an expired newest version still
// prevents an older one from applying.
func VerifyPolicy(network string, p Policy) error {
	if err := CheckPolicy(network, p); err != nil {
		return err
	}
	key, _ := DecodeKey(p.PersonPublicKey)
	return VerifySSHSIG(key, p.Message(), p.Signature)
}

// PolicyActive reports whether now falls within the policy's window, with
// PolicySkew allowed before issued_at.
func PolicyActive(p Policy, now time.Time) bool {
	issued, until, err := policyWindow(p)
	return err == nil && !now.Before(issued.Add(-PolicySkew)) && now.Before(until)
}

// PolicyExpiresSoon reports whether less than a quarter of the policy's
// validity remains at now.
func PolicyExpiresSoon(p Policy, now time.Time) bool {
	issued, until, err := policyWindow(p)
	if err != nil {
		return false
	}
	return until.Sub(now) < until.Sub(issued)/4
}

// SignPolicy signs a policy as its owner. Rules are copied; principals and
// actions keep the given order, which the signature covers.
func SignPolicy(owner PersonSigner, network string, version int64, issued time.Time, validFor time.Duration, rules []PolicyRule) (Policy, error) {
	p := Policy{NetworkID: network, PersonPublicKey: EncodeKey(owner.PublicKey()), Version: version, IssuedAt: Timestamp(issued), ValidUntil: Timestamp(issued.Add(validFor)), Rules: []PolicyRule{}}
	for _, r := range rules {
		r.Principals = append([]string{}, r.Principals...)
		r.Actions = append([]string{}, r.Actions...)
		p.Rules = append(p.Rules, r)
	}
	if err := CheckPolicy(network, p); err != nil {
		return p, err
	}
	var err error
	p.Signature, err = SignSSHSIG(owner, p.Message())
	return p, err
}

// Renewal returns the policy's rules, capability rules, and trusted hosts re-signed
// at version+1 with the same duration, issued at now. A renewal is always a
// format 2 policy; a version 1 policy renews with no capability rules or trusted
// hosts.
func Renewal(owner PersonSigner, current Policy, now time.Time) (Policy, error) {
	issued, until, err := policyWindow(current)
	if err != nil {
		return Policy{}, err
	}
	if !owner.PublicKey().Equal(ed25519.PublicKey(mustKey(current.PersonPublicKey))) {
		return Policy{}, fmt.Errorf("%w: renewing key is not the policy owner", ErrInvalid)
	}
	return SignPolicyV2(owner, current.NetworkID, current.Version+1, now, until.Sub(issued), current.Body())
}

func mustKey(value string) []byte {
	key, _ := DecodeKey(value)
	return key
}

// PolicyHash is the lowercase hex SHA-256 of the policy's signed statement.
func PolicyHash(p Policy) string {
	sum := sha256.Sum256(p.Message())
	return hex.EncodeToString(sum[:])
}

// PolicyPreferred reports whether a verified candidate replaces the stored
// policy of the same owner: it has a higher version, or the same version and
// a lower statement hash. The tie-break lets an owner's hosts converge on one
// of several policies signed concurrently at the same version.
func PolicyPreferred(candidate, stored Policy) bool {
	if candidate.Version != stored.Version {
		return candidate.Version > stored.Version
	}
	return PolicyHash(candidate) < PolicyHash(stored)
}

// DecodePolicy parses one policy strictly.
func DecodePolicy(data []byte) (Policy, error) {
	var p Policy
	err := json.Unmarshal(data, &p)
	return p, err
}

var (
	hostIDs  = regexp.MustCompile(`^host_[0-9a-f]{64}$`)
	agentIDs = regexp.MustCompile(`^agent_[0-9a-f]{32}$`)
)

// AgentPrincipal splits agent:<host ID>/<agent ID>. It matches only requests
// from that authenticated host whose asserted origin is that agent.
func AgentPrincipal(p string) (host, agent string, ok bool) {
	rest, found := strings.CutPrefix(p, "agent:")
	if !found {
		return "", "", false
	}
	host, agent, found = strings.Cut(rest, "/")
	return host, agent, found && hostIDs.MatchString(host) && agentIDs.MatchString(agent)
}

func hasPolicyAction(actions []string, want string) bool {
	for _, action := range actions {
		if action == want {
			return true
		}
	}
	return false
}

// ValidPolicyAction reports whether an action may appear in a policy rule or
// grant: appending a message, submitting a task, or submitting one that the
// receiving agent may pass on (task.delegate, which implies task.submit).
func ValidPolicyAction(action string) bool {
	return action == PolicyActionMessage || action == PolicyActionTask || action == PolicyActionDelegate
}

// TaskAction reports whether an action authorizes task submission.
func TaskAction(action string) bool {
	return action == PolicyActionTask || action == PolicyActionDelegate
}

// ValidRouteAction reports whether an action may appear on an adapter route:
// a route sends messages or submits tasks, and never carries task.delegate.
func ValidRouteAction(action string) bool {
	return action == PolicyActionMessage || action == PolicyActionTask
}

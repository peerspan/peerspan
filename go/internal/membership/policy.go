package membership

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
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
	PolicyMaxRules      = 64
	PolicyMaxPrincipals = 64
	PolicyMinValidity   = 24 * time.Hour
	PolicyMaxValidity   = 90 * 24 * time.Hour
	// PolicySkew is the clock skew allowed before issued_at.
	PolicySkew = 5 * time.Minute
	// PrincipalNetwork matches every member host of the policy's network.
	PrincipalNetwork = "network"
)

type PolicyRule struct {
	Agent             string   `json:"agent"`
	Principals        []string `json:"principals"`
	Actions           []string `json:"actions"`
	MaxMessageBytes   int64    `json:"max_message_bytes"`
	AllowDisconnected bool     `json:"allow_disconnected"`
}

type Policy struct {
	NetworkID       string       `json:"network_id"`
	PersonPublicKey string       `json:"person_public_key"`
	Version         int64        `json:"version"`
	IssuedAt        string       `json:"issued_at"`
	ValidUntil      string       `json:"valid_until"`
	Rules           []PolicyRule `json:"rules"`
	Signature       string       `json:"signature"`
}

func (r *PolicyRule) UnmarshalJSON(data []byte) error {
	type plain PolicyRule
	return Strict(data, (*plain)(r), "agent", "principals", "actions", "max_message_bytes", "allow_disconnected")
}
func (p *Policy) UnmarshalJSON(data []byte) error {
	type plain Policy
	return Strict(data, (*plain)(p), "network_id", "person_public_key", "version", "issued_at", "valid_until", "rules", "signature")
}

// Message is the policy's signed lines: a header, then five lines per rule
// in JSON order.
func (p Policy) Message() []byte {
	lines := []string{"capsule-policy-v1", p.NetworkID, p.PersonPublicKey, strconv.FormatInt(p.Version, 10), p.IssuedAt, p.ValidUntil}
	for _, r := range p.Rules {
		lines = append(lines, "rule", r.Agent, strings.Join(r.Principals, " "), strings.Join(r.Actions, " "),
			strconv.FormatInt(r.MaxMessageBytes, 10)+" "+strconv.FormatBool(r.AllowDisconnected))
	}
	return statement(lines...)
}

// ValidPrincipal reports whether a principal is person:<person ID>,
// group:<name>, or network.
func ValidPrincipal(p string) bool {
	switch {
	case p == PrincipalNetwork:
		return true
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
				return fmt.Errorf("%w: invalid principal %q; use person:<person ID>, group:<name>, or network", ErrInvalid, principal)
			}
		}
		if len(r.Actions) == 0 {
			return fmt.Errorf("%w: a rule needs an action", ErrInvalid)
		}
		for _, action := range r.Actions {
			if action != PolicyActionMessage {
				return fmt.Errorf("%w: the only action is %s", ErrInvalid, PolicyActionMessage)
			}
		}
		if r.MaxMessageBytes < 1 || r.MaxMessageBytes > 65536 {
			return fmt.Errorf("%w: max_message_bytes must be 1 to 65536", ErrInvalid)
		}
	}
	return nil
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

// Renewal returns the policy's rules re-signed at version+1 with the same
// duration, issued at now.
func Renewal(owner PersonSigner, current Policy, now time.Time) (Policy, error) {
	issued, until, err := policyWindow(current)
	if err != nil {
		return Policy{}, err
	}
	if !owner.PublicKey().Equal(ed25519.PublicKey(mustKey(current.PersonPublicKey))) {
		return Policy{}, fmt.Errorf("%w: renewing key is not the policy owner", ErrInvalid)
	}
	return SignPolicy(owner, current.NetworkID, current.Version+1, now, until.Sub(issued), current.Rules)
}

func mustKey(value string) []byte {
	key, _ := DecodeKey(value)
	return key
}

// DecodePolicy parses one policy strictly.
func DecodePolicy(data []byte) (Policy, error) {
	var p Policy
	err := json.Unmarshal(data, &p)
	return p, err
}

package membership

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Delegation chains (milestone 6, slice 4). Each link passes a task's
// authority from its issuer host to its audience host, never wider than the
// link before it. Links are line-encoded statements signed with host keys,
// in the same style as every other signed statement.

const (
	// DelegationMaxLinks is the longest chain: 3 hops past the originator.
	DelegationMaxLinks = 3
	// DelegationMaxPrincipals bounds a link's principals.
	DelegationMaxPrincipals = 16
	// DelegationMaxDepth is link 0's largest depth.
	DelegationMaxDepth = 2
	// DelegationNone is link 0's previous.
	DelegationNone = "none"
	// PolicyActionDelegate implies task.submit and lets the receiving agent
	// pass the task on.
	PolicyActionDelegate = "task.delegate"
)

// Link is one signed hop of a delegation chain.
type Link struct {
	NetworkID         string   `json:"network_id"`
	Index             int64    `json:"index"`
	Previous          string   `json:"previous"`
	IssuerHostID      string   `json:"issuer_host_id"`
	AudienceHostID    string   `json:"audience_host_id"`
	TaskID            string   `json:"task_id"`
	OriginatorAgentID string   `json:"originator_agent_id"`
	Principals        []string `json:"principals"`
	Deadline          string   `json:"deadline"`
	Depth             int64    `json:"depth"`
	Signature         string   `json:"signature"`
}

var linkFields = []string{"network_id", "index", "previous", "issuer_host_id", "audience_host_id", "task_id", "originator_agent_id", "principals", "deadline", "depth", "signature"}

// UnmarshalJSON accepts exactly the link's fields, none null.
func (l *Link) UnmarshalJSON(data []byte) error {
	type plain Link
	return Strict(data, (*plain)(l), linkFields...)
}

// Message is the link's signed statement.
func (l Link) Message() []byte {
	return statement("capsule-delegation-v1", l.NetworkID, strconv.FormatInt(l.Index, 10), l.Previous, l.IssuerHostID, l.AudienceHostID, l.TaskID, l.OriginatorAgentID, strings.Join(l.Principals, " "), l.Deadline, strconv.FormatInt(l.Depth, 10))
}

// Hash is what the next link's previous names: the SHA-256 of this link's
// statement, a newline, and its signature.
func (l Link) Hash() string {
	sum := sha256.Sum256(append(append(l.Message(), '\n'), l.Signature...))
	return hex.EncodeToString(sum[:])
}

// SignLink sets the link's signature with the issuer's host key. It does not
// validate the link, so tests can sign adversarial ones.
func SignLink(key ed25519.PrivateKey, l Link) Link {
	l.Signature = sign(key, l.Message())
	return l
}

// VerifyLink checks the link's signature under the issuer's host key.
func VerifyLink(key ed25519.PublicKey, l Link) error {
	return verify(key, l.Message(), l.Signature)
}

var (
	networkIDs = regexp.MustCompile(`^net_[0-9a-f]{64}$`)
	taskIDs    = regexp.MustCompile(`^task_[0-9a-f]{32}$`)
	hashes     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidHostID reports whether value is host_ and 64 lowercase hex digits.
func ValidHostID(value string) bool { return hostIDs.MatchString(value) }

// ValidDelegationPrincipal reports whether p is network, person:<person ID>,
// or host:<host ID>.
func ValidDelegationPrincipal(p string) bool {
	switch {
	case p == PrincipalNetwork:
		return true
	case strings.HasPrefix(p, "person:"):
		return ValidPersonID(strings.TrimPrefix(p, "person:"))
	case strings.HasPrefix(p, "host:"):
		return ValidHostID(strings.TrimPrefix(p, "host:"))
	}
	return false
}

// CheckLink validates a link's shape, without its signature or any relation
// to other links. A failure makes the request malformed.
func CheckLink(l Link) error {
	bad := func(what string) error { return fmt.Errorf("%w: link %s", ErrInvalid, what) }
	switch {
	case !networkIDs.MatchString(l.NetworkID):
		return bad("network_id")
	case l.Index < 0 || l.Depth < 0:
		return bad("index or depth")
	case l.Previous != DelegationNone && !hashes.MatchString(l.Previous):
		return bad("previous")
	case !ValidHostID(l.IssuerHostID) || !ValidHostID(l.AudienceHostID):
		return bad("host ID")
	case !taskIDs.MatchString(l.TaskID):
		return bad("task_id")
	case !agentIDs.MatchString(l.OriginatorAgentID):
		return bad("originator_agent_id")
	case len(l.Principals) < 1 || len(l.Principals) > DelegationMaxPrincipals:
		return bad("principals")
	}
	for i, p := range l.Principals {
		if !ValidDelegationPrincipal(p) || (i > 0 && l.Principals[i-1] >= p) {
			return bad("principals")
		}
	}
	if _, err := ParseTime(l.Deadline); err != nil || !strings.HasSuffix(l.Deadline, "Z") {
		return bad("deadline")
	}
	if _, err := canonical(l.Signature, ed25519.SignatureSize); err != nil {
		return bad("signature")
	}
	return nil
}

// PrincipalCovers reports whether principal a covers principal b. boundTo
// returns the person a host is bound to in the chain's network, or "".
func PrincipalCovers(a, b string, boundTo func(host string) string) bool {
	switch {
	case a == PrincipalNetwork || a == b:
		return true
	case strings.HasPrefix(a, "person:") && strings.HasPrefix(b, "host:"):
		person := boundTo(strings.TrimPrefix(b, "host:"))
		return person != "" && "person:"+person == a
	}
	return false
}

// PrincipalsCover reports whether some principal of set covers p.
func PrincipalsCover(set []string, p string, boundTo func(host string) string) bool {
	for _, a := range set {
		if PrincipalCovers(a, p, boundTo) {
			return true
		}
	}
	return false
}

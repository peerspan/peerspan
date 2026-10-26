package decentralized

import (
	"encoding/base64"
	"encoding/json"
	"sort"
	"strconv"
	"time"

	"github.com/peerspan/peerspan/go/internal/membership"
)

const Protocol = "peerspan-decentralized-v1"

// Failure exposes only the stable protocol category and exact missing IDs.
// It never contains untrusted text or a partial authority result.
type Failure struct {
	Code        string
	RequiredIDs []string
}

func (e *Failure) Error() string { return e.Code }
func failure(code string, ids ...string) error {
	ids = append([]string{}, ids...)
	sort.Strings(ids)
	unique := ids[:0]
	for _, id := range ids {
		if len(unique) == 0 || unique[len(unique)-1] != id {
			unique = append(unique, id)
		}
	}
	if code != "proof_required" {
		unique = []string{}
	}
	return &Failure{Code: code, RequiredIDs: unique}
}
func Code(err error) string {
	if e, ok := err.(*Failure); ok {
		return e.Code
	}
	return "invalid"
}
func RequiredIDs(err error) []string {
	if e, ok := err.(*Failure); ok {
		return append([]string{}, e.RequiredIDs...)
	}
	return []string{}
}

type Descriptor struct {
	Format               uint64 `json:"format"`
	Protocol             string `json:"protocol"`
	NetworkID            string `json:"network_id"`
	Name                 string `json:"name"`
	GenesisRootPublicKey string `json:"genesis_root_public_key"`
	ContextID            string `json:"-"`
	Raw                  []byte `json:"-"`
}

func ReadDescriptor(raw []byte) (Descriptor, error) {
	var d Descriptor
	o, e := parse(raw)
	if e != nil {
		return d, e
	}
	if fields(o, "format protocol network_id name genesis_root_public_key") != nil || version(o, 1) != nil {
		return d, invalid()
	}
	if json.Unmarshal(raw, &d) != nil || d.Protocol != Protocol || !membership.ValidLabel(d.Name) || !key(d.GenesisRootPublicKey) {
		return d, invalid()
	}
	pub, _ := membership.DecodeKey(d.GenesisRootPublicKey)
	if membership.NetworkID(pub) != d.NetworkID {
		return d, invalid()
	}
	d.ContextID = "ctx_" + digest(message("peerspan-decentralized-context-v1", Protocol, d.NetworkID, d.Name, d.GenesisRootPublicKey))
	d.Raw = append([]byte{}, raw...)
	return d, nil
}

// DecisionTime uses only the caller's local time/guard. Signed object timestamps
// never feed this function. The caller persists its result only at the named
// mutation boundary; reads do not advance durable time.
func DecisionTime(now, guard string) (string, error) {
	n, e := stamp(now)
	if e != nil {
		return "", e
	}
	if guard == "-" {
		return now, nil
	}
	g, e := stamp(guard)
	if e != nil {
		return "", e
	}
	if g.Unix()-n.Unix() > 300 {
		return "", failure("clock_rollback")
	}
	if g.After(n) {
		return guard, nil
	}
	return now, nil
}
func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
func validInterval(issued, before, after string, max int64) error {
	i, e := stamp(issued)
	if e != nil {
		return e
	}
	b, e := stamp(before)
	if e != nil {
		return e
	}
	a, e := stamp(after)
	if e != nil {
		return e
	}
	if i.After(b) || !b.Before(a) || a.Unix()-i.Unix() > max {
		return invalid()
	}
	return nil
}
func atTime(before, after string, now time.Time, access bool) error {
	b, _ := stamp(before)
	a, _ := stamp(after)
	if now.Before(b) {
		return failure("not_yet_valid")
	}
	if !now.Before(a) {
		if access {
			return failure("expired")
		}
		return failure("authority_expired")
	}
	return nil
}
func ids(o Object, k, prefix string) ([]string, error) {
	a, e := stringsOf(o, k)
	if e != nil {
		return nil, e
	}
	if !sorted(a) {
		return nil, invalid()
	}
	for _, v := range a {
		if !identifier(v, prefix) {
			return nil, invalid()
		}
	}
	return a, nil
}
func literalOrID(s, prefix string) bool { return s == "-" || identifier(s, prefix) }
func literalOrKey(s string) bool        { return s == "-" || key(s) }
func readObject(raw []byte, names string) (Object, error) {
	o, e := parse(raw)
	if e != nil {
		return nil, e
	}
	if fields(o, names) != nil {
		return nil, invalid()
	}
	return o, nil
}
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func uintString(v uint64) string { return strconv.FormatUint(v, 10) }

package decentralized

import (
	"bytes"
	"encoding/json"
	"github.com/peerspan/peerspan/go/internal/membership"
	"sort"
)

type Maximum struct {
	Stream       []string `json:"stream"`
	Sequence     uint64   `json:"sequence"`
	StatementIDs []string `json:"statement_ids"`
	HeadIDs      []string `json:"head_ids"`
}

// Prior is private durable admission metadata. No public catalog or peer route
// can instantiate it; the pure probe receives it only from its trusted caller.
type Prior struct {
	Format               uint64    `json:"format"`
	ContextID            string    `json:"context_id"`
	CatalogBase64        string    `json:"catalog_base64"`
	AdmittedStatements   []string  `json:"admitted_statement_ids"`
	AdmittedRestrictions []string  `json:"admitted_restriction_ids"`
	AdmittedActivations  []string  `json:"admitted_activation_ids"`
	RootHeads            []string  `json:"root_head_ids"`
	Maxima               []Maximum `json:"maxima"`
	Migration            string    `json:"migration_proposal_id"`
	ClockGuard           string    `json:"clock_guard"`
	Raw                  []byte    `json:"-"`
	catalog              *Catalog
}

func readPrior(d Descriptor, raw []byte) (*Prior, error) {
	return readPriorMode(d, raw, false)
}

// Only an already admitted read can retain unavailable historical bodies.
// The exact metadata remains unchanged and supplies no replacement proof;
// every current consumer still resolves its required DS through the graph.
func readPriorMode(d Descriptor, raw []byte, reading bool) (*Prior, error) {
	if bytes.Equal(bytes.TrimSpace(raw), []byte(`"-"`)) {
		return nil, nil
	}
	o, e := parseLimit(raw, MaxProbe)
	if e != nil {
		return nil, e
	}
	if fields(o, "format context_id catalog_base64 admitted_statement_ids admitted_restriction_ids admitted_activation_ids root_head_ids maxima migration_proposal_id clock_guard") != nil || version(o, 1) != nil || stringField(o, "context_id") != d.ContextID {
		return nil, invalid()
	}
	var p Prior
	if json.Unmarshal(raw, &p) != nil || !literalOrID(p.Migration, "ds_") {
		return nil, invalid()
	}
	if p.ClockGuard != "-" {
		if _, e := stamp(p.ClockGuard); e != nil {
			return nil, e
		}
	}
	for _, field := range []struct{ name, prefix string }{{"admitted_statement_ids", "ds_"}, {"admitted_restriction_ids", "ds_"}, {"admitted_activation_ids", "da_"}, {"root_head_ids", "ds_"}} {
		if _, e := ids(o, field.name, field.prefix); e != nil {
			return nil, e
		}
	}
	catalogRaw, e := decode(p.CatalogBase64, MaxCatalog)
	if e != nil {
		return nil, e
	}
	p.catalog, e = ReadCatalog(d, catalogRaw)
	if e != nil {
		return nil, e
	}
	var rows []json.RawMessage
	if json.Unmarshal(o["maxima"], &rows) != nil || rows == nil {
		return nil, invalid()
	}
	if len(rows) > MaxObjects {
		return nil, failure("quota_exceeded")
	}
	previous := []string{}
	rootMax := false
	for _, raw := range rows {
		row, e := readObject(raw, "stream sequence statement_ids head_ids")
		if e != nil {
			return nil, e
		}
		var m Maximum
		if json.Unmarshal(raw, &m) != nil || !validStream(m.Stream) || m.Stream[0] != "root" && m.Sequence == 0 || compareStreams(previous, m.Stream) >= 0 {
			return nil, invalid()
		}
		if _, e = ids(row, "statement_ids", "ds_"); e != nil {
			return nil, e
		}
		if _, e = ids(row, "head_ids", "ds_"); e != nil {
			return nil, e
		}
		for _, id := range m.HeadIDs {
			if !contains(p.AdmittedStatements, id) {
				return nil, invalid()
			}
			if s := p.catalog.Statements[id]; s != nil && (!equalStrings(s.stream(), m.Stream) || s.sequence() > m.Sequence) {
				return nil, invalid()
			}
		}
		for _, id := range m.StatementIDs {
			if !contains(m.HeadIDs, id) {
				return nil, invalid()
			}
		}
		for _, id := range m.StatementIDs {
			if !contains(p.AdmittedStatements, id) {
				return nil, invalid()
			}
			if s := p.catalog.Statements[id]; s != nil && (!equalStrings(s.stream(), m.Stream) || s.sequence() != m.Sequence) {
				return nil, invalid()
			}
		}
		if m.Stream[0] == "root" {
			rootMax = true
			if !equalStrings(m.HeadIDs, p.RootHeads) {
				return nil, invalid()
			}
		}
		previous = m.Stream
	}
	if len(p.RootHeads) > 0 && !rootMax {
		return nil, invalid()
	}
	for _, id := range p.RootHeads {
		if !contains(p.AdmittedStatements, id) {
			return nil, invalid()
		}
		if s := p.catalog.Statements[id]; s != nil && s.Root == nil {
			return nil, invalid()
		}
	}
	for _, id := range p.AdmittedRestrictions {
		if s := p.catalog.Statements[id]; s != nil {
			if s.Restriction == nil {
				return nil, invalid()
			}
		} else {
			return nil, failure("proof_required", id)
		}
	}
	for _, id := range p.AdmittedActivations {
		if p.catalog.Activations[id] == nil {
			return nil, failure("proof_required", id)
		}
	}
	for _, id := range p.AdmittedStatements {
		s := p.catalog.Statements[id]
		if s != nil {
			if len(s.stream()) == 0 || s.Restriction != nil {
				return nil, invalid()
			}
			found := false
			for _, m := range p.Maxima {
				if equalStrings(m.Stream, s.stream()) && m.Sequence >= s.sequence() {
					found = true
					break
				}
			}
			if !found {
				return nil, invalid()
			}
			continue
		}
		missingAllowed := false
		for _, m := range p.Maxima {
			if (contains(m.StatementIDs, id) || contains(m.HeadIDs, id)) && (m.Stream[0] == "policy" || m.Stream[0] == "group" || m.Stream[0] == "root") {
				missingAllowed = true
			}
		}
		if !missingAllowed && !reading {
			return nil, failure("proof_required", id)
		}
	}
	p.Raw = append([]byte{}, raw...)
	return &p, nil
}
func validStream(s []string) bool {
	if len(s) == 1 {
		return s[0] == "root"
	}
	if len(s) == 2 {
		switch s[0] {
		case "admin", "person", "host", "binding", "policy":
			return key(s[1])
		case "group":
			return validGroup(s[1])
		}
		return false
	}
	return len(s) == 3 && s[0] == "device" && key(s[1]) && key(s[2])
}
func compareStreams(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}
func keysSorted(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for id, yes := range m {
		if yes {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func validGroup(s string) bool { return membership.ValidGroupName(s) }

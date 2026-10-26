package decentralized

import (
	"bytes"
	"encoding/json"
	"sort"

	"github.com/peerspan/peerspan/go/internal/membership"
)

type CatalogObject struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	BodyBase64 string `json:"body_base64"`
	Body       []byte `json:"-"`
}
type Catalog struct {
	Format           uint64                       `json:"format"`
	ContextID        string                       `json:"context_id"`
	Objects          []CatalogObject              `json:"objects"`
	Raw              []byte                       `json:"-"`
	Statements       map[string]*Statement        `json:"-"`
	Proofs           map[string]*Statement        `json:"-"`
	Activations      map[string]*ParsedActivation `json:"-"`
	Migrations       []*ParsedMigration           `json:"-"`
	Sources          map[string][]string          `json:"-"`
	ActivationProofs []*ParsedActivation          `json:"-"`
}

func validMember(s string) bool                              { return membership.ValidLabel(s) }
func ReadCatalog(d Descriptor, raw []byte) (*Catalog, error) { return readCatalog(d, raw, true) }
func readCatalog(d Descriptor, raw []byte, allowMigration bool) (*Catalog, error) {
	o, e := parseLimit(raw, MaxCatalog)
	if e != nil {
		return nil, e
	}
	if fields(o, "format context_id objects") != nil || version(o, 1) != nil || stringField(o, "context_id") != d.ContextID {
		return nil, invalid()
	}
	var rows []json.RawMessage
	if json.Unmarshal(o["objects"], &rows) != nil || rows == nil {
		return nil, invalid()
	}
	if len(rows) > MaxObjects {
		return nil, failure("quota_exceeded")
	}
	c := &Catalog{Format: 1, ContextID: d.ContextID, Objects: []CatalogObject{}, Raw: append([]byte{}, raw...), Statements: map[string]*Statement{}, Proofs: map[string]*Statement{}, Activations: map[string]*ParsedActivation{}, Migrations: []*ParsedMigration{}}
	c.Sources = map[string][]string{}
	c.ActivationProofs = []*ParsedActivation{}
	total := 0
	last := ""
	for _, raw := range rows {
		o, e := readObjectLimit(raw, "id kind body_base64", MaxCatalog)
		if e != nil {
			return nil, e
		}
		a, e := texts(o, "id", "kind", "body_base64")
		if e != nil || !identifier(a[0], "dp_") || a[0] <= last {
			return nil, invalid()
		}
		body, e := decode(a[2], MaxObject)
		if e != nil {
			return nil, e
		}
		if ProofID(a[1], body) != a[0] {
			return nil, invalid()
		}
		total += len(body)
		if total > MaxDecodedCatalog {
			return nil, failure("quota_exceeded")
		}
		entry := CatalogObject{ID: a[0], Kind: a[1], BodyBase64: a[2], Body: body}
		switch a[1] {
		case "activation":
			activation, e := readActivation(d, body)
			if e != nil {
				return nil, e
			}
			if old := c.Activations[activation.ID]; old != nil && old.ManifestID != activation.ManifestID {
				return nil, failure("operation_conflict")
			}
			c.Activations[activation.ID] = activation
			c.ActivationProofs = append(c.ActivationProofs, activation)
			for _, packet := range []*Packet{activation.Administrator, activation.Finalization} {
				if packet == nil {
					continue
				}
				for _, s := range packet.Statements {
					if s.Kind != "binding_lease" {
						if e = c.index(s); e != nil {
							return nil, e
						}
						c.addSource(s.ID, entry.ID)
					}
				}
			}
		case "migration":
			if !allowMigration {
				return nil, invalid()
			}
			migration, e := readMigration(d, body)
			if e != nil {
				return nil, e
			}
			c.Migrations = append(c.Migrations, migration)
			prepared, e := readCatalog(d, migration.PreparedCatalog, false)
			if e != nil {
				return nil, e
			}
			for _, s := range prepared.Proofs {
				if e = c.index(s); e != nil {
					return nil, e
				}
				c.addSource(s.ID, entry.ID)
			}
			for id, activation := range prepared.Activations {
				c.Activations[id] = activation
			}
			c.ActivationProofs = append(c.ActivationProofs, prepared.ActivationProofs...)
		default:
			s, e := ReadStatement(d, body)
			if e != nil {
				return nil, e
			}
			if s.Kind != a[1] {
				return nil, invalid()
			}
			if e = c.index(s); e != nil {
				return nil, e
			}
			c.addSource(s.ID, entry.ID)
		}
		c.Objects = append(c.Objects, entry)
		last = a[0]
	}
	return c, nil
}
func (c *Catalog) addSource(statement, proof string) {
	if !contains(c.Sources[statement], proof) {
		c.Sources[statement] = append(c.Sources[statement], proof)
	}
}
func readObjectLimit(raw []byte, names string, limit int) (Object, error) {
	o, e := parseLimit(raw, limit)
	if e != nil {
		return nil, e
	}
	if fields(o, names) != nil {
		return nil, invalid()
	}
	return o, nil
}
func (c *Catalog) index(s *Statement) error {
	if old := c.Statements[s.ID]; old != nil && (old.Kind != s.Kind || !bytes.Equal(old.Payload, s.Payload)) {
		return invalid()
	}
	c.Statements[s.ID] = s
	c.Proofs[s.ProofID] = s
	return nil
}
func (c *Catalog) ProofIDs() []string {
	ids := make([]string, 0, len(c.Objects))
	for _, o := range c.Objects {
		ids = append(ids, o.ID)
	}
	return ids
}
func (c *Catalog) ID() string {
	parts := []string{"peerspan-decentralized-catalog-v1", c.ContextID, uintString(uint64(len(c.Objects)))}
	parts = append(parts, c.ProofIDs()...)
	return "cat_" + digest(message(parts...))
}
func UnionCatalog(d Descriptor, catalogs ...*Catalog) (*Catalog, error) {
	entries := map[string]CatalogObject{}
	for _, c := range catalogs {
		if c == nil {
			continue
		}
		for _, entry := range c.Objects {
			if old, ok := entries[entry.ID]; ok && (old.Kind != entry.Kind || !bytes.Equal(old.Body, entry.Body)) {
				return nil, invalid()
			}
			entries[entry.ID] = entry
		}
	}
	ids := make([]string, 0, len(entries))
	for id := range entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	wire := struct {
		Format  uint64          `json:"format"`
		Context string          `json:"context_id"`
		Objects []CatalogObject `json:"objects"`
	}{1, d.ContextID, []CatalogObject{}}
	for _, id := range ids {
		wire.Objects = append(wire.Objects, entries[id])
	}
	raw, e := json.Marshal(wire)
	if e != nil {
		return nil, invalid()
	}
	return ReadCatalog(d, raw)
}

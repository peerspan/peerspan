package host

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type linkCatalogObject struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	BodyBase64 string `json:"body_base64"`
}

func (o *linkCatalogObject) UnmarshalJSON(raw []byte) error {
	type plain linkCatalogObject
	return linking.DecodeStoredJSON(raw, "id kind body_base64", (*plain)(o))
}

type linkCatalog struct {
	Format    uint64              `json:"format"`
	NetworkID string              `json:"network_id"`
	Objects   []linkCatalogObject `json:"objects"`
}

func linkProofID(kind string, body []byte) string {
	return "pf_" + linkHash(linkMessage("peerspan-link-proof-v1", kind, linkHash(body)))
}
func decodeLinkCatalog(raw []byte, network string) (linkCatalog, error) {
	var catalog linkCatalog
	if len(raw) > linking.MaxStoredCatalog || linking.DecodeStoredJSON(raw, "format network_id objects", &catalog) != nil || catalog.Format != 1 || catalog.NetworkID != network || catalog.Objects == nil || len(catalog.Objects) > 4096 {
		return catalog, linkFail("invalid", "-", "catalog")
	}
	previous := ""
	total := 0
	for _, entry := range catalog.Objects {
		body, e := linkBytes(entry.BodyBase64, linking.MaxObject)
		if e != nil || !linkID(entry.ID, "pf_") || entry.ID <= previous || entry.ID != linkProofID(entry.Kind, body) {
			return catalog, linkFail("invalid", "-", "catalog")
		}
		total += len(body)
		if total > linking.MaxStoredBodies {
			return catalog, linkFail("quota_exceeded", "-", "catalog")
		}
		previous = entry.ID
	}
	return catalog, nil
}
func readLinkCatalog(ctx context.Context, q dbQuerier, network string) ([]byte, error) {
	rows, e := q.QueryContext(ctx, `SELECT proof_id,kind,body FROM link_objects WHERE network_id=? ORDER BY proof_id`, network)
	if e != nil {
		return nil, e
	}
	catalog := linkCatalog{Format: 1, NetworkID: network, Objects: []linkCatalogObject{}}
	for rows.Next() {
		var entry linkCatalogObject
		var body []byte
		if e = rows.Scan(&entry.ID, &entry.Kind, &body); e != nil {
			_ = rows.Close()
			return nil, e
		}
		entry.BodyBase64 = base64.StdEncoding.EncodeToString(body)
		catalog.Objects = append(catalog.Objects, entry)
	}
	e = rows.Err()
	_ = rows.Close()
	if e != nil {
		return nil, e
	}
	raw, e := linkJSON(catalog)
	if e != nil {
		return nil, e
	}
	if _, e = decodeLinkCatalog(raw, network); e != nil {
		return nil, linkFail("state_conflict", "-", "storage")
	}
	return raw, nil
}
func mergeLinkCatalog(network string, bodies ...[]byte) ([]byte, error) {
	objects := map[string]linkCatalogObject{}
	for _, raw := range bodies {
		catalog, e := decodeLinkCatalog(raw, network)
		if e != nil {
			return nil, e
		}
		for _, entry := range catalog.Objects {
			if old, ok := objects[entry.ID]; ok && old != entry {
				return nil, linkFail("state_conflict", "-", "catalog")
			}
			objects[entry.ID] = entry
		}
	}
	ids := make([]string, 0, len(objects))
	for id := range objects {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	merged := linkCatalog{Format: 1, NetworkID: network, Objects: []linkCatalogObject{}}
	for _, id := range ids {
		merged.Objects = append(merged.Objects, objects[id])
	}
	raw, e := linkJSON(merged)
	if e != nil {
		return nil, e
	}
	if _, e = decodeLinkCatalog(raw, network); e != nil {
		return nil, e
	}
	return raw, nil
}
func linkCatalogEpoch(catalog linkCatalog) (uint64, error) {
	var epoch uint64
	for _, entry := range catalog.Objects {
		if entry.Kind == "rotation" {
			raw, e := linkBytes(entry.BodyBase64, linking.MaxObject)
			if e != nil {
				return 0, e
			}
			var rotation struct {
				Epoch uint64 `json:"epoch"`
			}
			if json.Unmarshal(raw, &rotation) != nil {
				return 0, linkFail("invalid", "-", "catalog")
			}
			if rotation.Epoch > epoch {
				epoch = rotation.Epoch
			}
		}
	}
	return epoch, nil // Only a verification target; signed contiguous lineage must prove it.
}

type linkFeatureRecord struct {
	State           string            `json:"state"`
	Proposal        json.RawMessage   `json:"proposal"`
	Acknowledgments []json.RawMessage `json:"acknowledgments"`
	Activate        bool              `json:"activate"`
}

func readLinkFeature(ctx context.Context, q dbQuerier, network string) (string, *linkFeatureRecord, error) {
	var id, raw string
	e := q.QueryRowContext(ctx, `SELECT feature_id,record FROM link_features WHERE network_id=?`, network).Scan(&id, &raw)
	if errors.Is(e, sql.ErrNoRows) {
		return "-", nil, nil
	}
	if e != nil {
		return "", nil, e
	}
	var record linkFeatureRecord
	if linking.DecodeStoredJSON([]byte(raw), "state proposal acknowledgments activate", &record) != nil || !linkID(id, "lf_") || record.Acknowledgments == nil {
		return "", nil, linkFail("state_conflict", "-", "storage")
	}
	switch record.State {
	case "preparing", "collecting":
		return "-", &record, nil
	case "active":
		return id, &record, nil
	default:
		return "", nil, linkFail("state_conflict", "-", "storage")
	}
}

type linkProjection struct {
	Descriptor, Catalog                       []byte
	Objects                                   linkCatalog
	Network                                   linking.NetworkState
	Access                                    linking.AccessState
	Policies                                  map[string]membership.Policy
	Groups                                    map[string]membership.GroupDefinition
	PolicyAuthorizations, GroupAuthorizations map[string]string
}
type linkFeatureAdoption struct{ FeatureID string }

type linkProjectionState struct {
	feature  string
	policies []linking.PolicyHighWater
	groups   []linking.GroupHighWater
}

func readLinkProjectionState(ctx context.Context, q dbQuerier, network string) (linkProjectionState, error) {
	var state linkProjectionState
	var e error
	state.feature, _, e = readLinkFeature(ctx, q, network)
	if e == nil {
		state.policies, state.groups, e = readLinkHighWater(ctx, q, network)
	}
	return state, e
}

func (s *Store) verifyLinkProjection(ctx context.Context, q dbQuerier, n Network, catalog []byte, now time.Time, adoptions ...*linkFeatureAdoption) (*linkProjection, error) {
	// The supplied candidate is immutable. Its prior feature and maxima must
	// come from one snapshot, without holding that snapshot during verification.
	if db, ok := q.(*sql.DB); ok {
		tx, e := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if e != nil {
			return nil, e
		}
		state, e := readLinkProjectionState(ctx, tx, n.ID)
		_ = tx.Rollback()
		if e != nil {
			return nil, e
		}
		return verifyLinkProjectionState(n, catalog, now, state, adoptions...)
	}
	state, e := readLinkProjectionState(ctx, q, n.ID)
	if e != nil {
		return nil, e
	}
	return verifyLinkProjectionState(n, catalog, now, state, adoptions...)
}

func verifyLinkProjectionState(n Network, catalog []byte, now time.Time, prior linkProjectionState, adoptions ...*linkFeatureAdoption) (*linkProjection, error) {
	objects, e := decodeLinkCatalog(catalog, n.ID)
	if e != nil {
		return nil, e
	}
	epoch, e := linkCatalogEpoch(objects)
	if e != nil {
		return nil, e
	}
	feature := prior.feature
	descriptor, e := linkJSON(linkNetworkDescriptor(n))
	if e != nil {
		return nil, e
	}
	factContext := linking.CatalogFactContext{Network: descriptor, Epoch: epoch, KnownFeatureID: feature, Now: now}
	state, e := linking.VerifyStoredNetworkState(factContext, catalog)
	if e != nil {
		return nil, e
	}
	if feature == "-" {
		if len(adoptions) != 1 || adoptions[0] == nil || !linkID(adoptions[0].FeatureID, "lf_") {
			return nil, linkFail("upgrade_required", "-", "feature")
		}
		if adoptions[0].FeatureID != state.Facts.FeatureID {
			return nil, linkFail("state_conflict", "-", "feature")
		}
		feature = adoptions[0].FeatureID
	}
	certificates := map[string]int{}
	for _, raw := range state.Facts.State.Certificates {
		var certificate struct {
			PersonPublicKey string `json:"person_public_key"`
		}
		if json.Unmarshal(raw, &certificate) != nil {
			return nil, linkFail("invalid", "-", "certificate")
		}
		certificates[certificate.PersonPublicKey]++
		if certificates[certificate.PersonPublicKey] > 4096 {
			return nil, linkFail("quota_exceeded", "-", "certificate")
		}
	}
	access, e := linking.VerifyStoredAccessState(linking.AccessContext{Network: descriptor, Epoch: epoch, KnownFeatureID: feature, Now: now, PriorPolicies: prior.policies, PriorGroups: prior.groups}, catalog)
	if e != nil {
		return nil, e
	}
	projection := &linkProjection{Descriptor: descriptor, Catalog: catalog, Objects: objects, Network: state, Access: access,
		Policies: map[string]membership.Policy{}, Groups: map[string]membership.GroupDefinition{}, PolicyAuthorizations: map[string]string{}, GroupAuthorizations: map[string]string{}}
	for _, selected := range access.Policies {
		if !selected.Active {
			continue
		}
		body, authorization, err := projectedAccessBody(selected.AccessSelection)
		if err != nil {
			return nil, err
		}
		var policy membership.Policy
		if json.Unmarshal(body, &policy) != nil {
			return nil, linkFail("state_conflict", "-", "catalog")
		}
		projection.Policies[selected.PersonPublicKey] = policy
		projection.PolicyAuthorizations[selected.PersonPublicKey] = authorization
	}
	for _, selected := range access.Groups {
		if !selected.Active {
			continue
		}
		body, authorization, err := projectedAccessBody(selected.AccessSelection)
		if err != nil {
			return nil, err
		}
		var group membership.GroupDefinition
		if json.Unmarshal(body, &group) != nil {
			return nil, linkFail("state_conflict", "-", "catalog")
		}
		projection.Groups[selected.Name] = group
		projection.GroupAuthorizations[selected.Name] = authorization
	}
	return projection, nil
}
func (s *Store) readLinkProjection(ctx context.Context, q dbQuerier, n Network, now time.Time) (*linkProjection, error) {
	var snapshot *sql.Tx
	if db, ok := q.(*sql.DB); ok {
		var e error
		snapshot, e = db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
		if e != nil {
			return nil, e
		}
		defer snapshot.Rollback()
		q = snapshot
		// Capture actual durable descriptor/root pins beside the exact catalog
		// and high-water, rather than reusing an earlier network-row read.
		n, e = scanNetwork(q.QueryRowContext(ctx, networkColumns+" WHERE id=?", n.ID))
		if e != nil {
			return nil, e
		}
	}
	state, e := readLinkProjectionState(ctx, q, n.ID)
	if e != nil {
		return nil, e
	}
	if state.feature == "-" {
		return nil, nil
	}
	catalog, e := readLinkCatalog(ctx, q, n.ID)
	if e != nil {
		return nil, e
	}
	if snapshot != nil {
		_ = snapshot.Rollback()
	}
	return verifyLinkProjectionState(n, catalog, now, state)
}
func persistLinkProjection(ctx context.Context, tx *sql.Tx, n Network, p *linkProjection) error {
	for _, entry := range p.Objects.Objects {
		body, e := linkBytes(entry.BodyBase64, linking.MaxObject)
		if e != nil {
			return e
		}
		var oldKind string
		var oldBody []byte
		e = tx.QueryRowContext(ctx, `SELECT kind,body FROM link_objects WHERE network_id=? AND proof_id=?`, n.ID, entry.ID).Scan(&oldKind, &oldBody)
		if e == nil {
			if oldKind != entry.Kind || string(oldBody) != string(body) {
				return linkFail("state_conflict", "-", "storage")
			}
			continue
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO link_objects(network_id,proof_id,kind,body) VALUES(?,?,?,?)`, n.ID, entry.ID, entry.Kind, body); e != nil {
			return e
		}
	}
	feature, old, e := readLinkFeature(ctx, tx, n.ID)
	if e != nil {
		return e
	}
	if feature != "-" && feature != p.Network.Facts.FeatureID {
		return linkFail("state_conflict", "-", "feature")
	}
	var body []byte
	for _, entry := range p.Objects.Objects {
		if entry.Kind == "feature" {
			body, e = linkBytes(entry.BodyBase64, linking.MaxObject)
			if e != nil {
				return e
			}
			break
		}
	}
	if len(body) == 0 {
		return linkFail("proof_required", "-", "feature")
	}
	var signed struct {
		Proposal        json.RawMessage   `json:"proposal"`
		Acknowledgments []json.RawMessage `json:"acknowledgments"`
	}
	if linking.DecodeMutation(body, "proposal acknowledgments", &signed) != nil {
		return linkFail("invalid", "-", "feature")
	}
	record := linkFeatureRecord{State: "active", Proposal: signed.Proposal, Acknowledgments: signed.Acknowledgments}
	if old != nil {
		record.Activate = old.Activate
	}
	raw, e := linkJSON(record)
	if e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO link_features(network_id,feature_id,record) VALUES(?,?,?) ON CONFLICT(network_id) DO UPDATE SET feature_id=excluded.feature_id,record=excluded.record`, n.ID, p.Network.Facts.FeatureID, string(raw)); e != nil {
		return e
	}
	return persistLinkHighWater(ctx, tx, p.Access)
}

// projectedAccessBody is an unsigned local evaluation model. Its '-' signature
// is never submitted or propagated as a legacy statement. Exact authorizations
// remain separate bytes in the public catalog.
func projectedAccessBody(selection linking.AccessSelection) ([]byte, string, error) {
	raw, e := linkBytes(selection.BodyBase64, linking.MaxObject)
	if e != nil {
		return nil, "", e
	}
	if selection.RecordID == "-" {
		return raw, "", nil
	}
	var record struct {
		PayloadBase64 string `json:"payload_base64"`
	}
	if json.Unmarshal(raw, &record) != nil {
		return nil, "", linkFail("state_conflict", "-", "catalog")
	}
	body, e := linkBytes(record.PayloadBase64, linking.MaxPayload)
	if e != nil {
		return nil, "", e
	}
	var payload map[string]json.RawMessage
	if json.Unmarshal(body, &payload) != nil || payload == nil {
		return nil, "", linkFail("state_conflict", "-", "catalog")
	}
	payload["signature"] = json.RawMessage(`"-"`)
	model, e := linkJSON(payload)
	return model, selection.BodyBase64, e
}

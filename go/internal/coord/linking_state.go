package coord

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type linkNetwork struct {
	NetworkID            string `json:"network_id"`
	Name                 string `json:"name"`
	GenesisRootPublicKey string `json:"genesis_root_public_key"`
	CoordinatorAddress   string `json:"coordinator_address"`
	CoordinatorPublicKey string `json:"coordinator_public_key"`
}
type linkProof struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	BodyBase64 string `json:"body_base64"`
}
type linkCatalog struct {
	Format    uint64      `json:"format"`
	NetworkID string      `json:"network_id"`
	Objects   []linkProof `json:"objects"`
}

func linkHash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func linkProofOf(kind string, body []byte) linkProof {
	id := "pf_" + linkHash([]byte("peerspan-link-proof-v1\n"+kind+"\n"+linkHash(body)))
	return linkProof{ID: id, Kind: kind, BodyBase64: base64.StdEncoding.EncodeToString(body)}
}
func (s *Server) linkDescriptor(ctx context.Context, tx *sql.Tx, network string, r *http.Request) (linkNetwork, error) {
	n := linkNetwork{NetworkID: network, CoordinatorAddress: r.Host, CoordinatorPublicKey: s.identities[s.requestSequence(r.Context())].identity.PublicKey}
	if !membership.ValidCoordinatorAddress(n.CoordinatorAddress) {
		return n, linkFailure(400, "invalid")
	}
	err := tx.QueryRowContext(ctx, `SELECT name,root_public_key FROM networks WHERE id=?`, network).Scan(&n.Name, &n.GenesisRootPublicKey)
	if errors.Is(err, sql.ErrNoRows) {
		err = linkFailure(404, "not_found")
	}
	return n, err
}

func activeLinkFeature(ctx context.Context, tx *sql.Tx, network string) (string, error) {
	var id string
	err := tx.QueryRowContext(ctx, `SELECT feature_id FROM link_features WHERE network_id=? AND active=1`, network).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "-", nil
	}
	return id, err
}

// linkCatalogOf includes exact legacy statements at the upgrade boundary and
// all immutable retained public proofs thereafter. No selected view is used as
// a replacement for the underlying signed evidence.
func linkCatalogOf(ctx context.Context, tx *sql.Tx, network string) (linkCatalog, error) {
	c := linkCatalog{Format: 1, NetworkID: network, Objects: []linkProof{}}
	objects := map[string]linkProof{}
	add := func(kind string, raw []byte) { p := linkProofOf(kind, raw); objects[p.ID] = p }
	rows, err := tx.QueryContext(ctx, `SELECT proof_id,kind,body FROM link_objects WHERE network_id=? ORDER BY proof_id`, network)
	if err != nil {
		return c, err
	}
	for rows.Next() {
		var id, kind string
		var body []byte
		if err = rows.Scan(&id, &kind, &body); err != nil {
			break
		}
		p := linkProofOf(kind, body)
		if p.ID != id {
			err = linkFailure(409, "state_conflict")
			break
		}
		objects[id] = p
	}
	err = errors.Join(err, rows.Err(), rows.Close())
	if err != nil {
		return c, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT kind,statement FROM statements WHERE network_id=? ORDER BY kind,subject`, network)
	if err != nil {
		return c, err
	}
	kinds := map[string]string{
		kindRotation: "rotation", kindAttestation: "attestation", kindDelegation: "admin_delegation",
		membership.KindAdmin: "admin_removal", kindHostAdmission: "host_admission", kindBinding: "host_binding",
		membership.KindHost: "host_revocation", membership.KindInvite: "invite_revocation", membership.KindLeave: "host_leave",
		membership.KindPerson: "person_removal", membership.KindUnbind: "host_unbinding", kindGroup: "group", kindPolicy: "policy",
		kindMove: "coordinator_move",
	}
	for rows.Next() {
		var kind string
		var body []byte
		if err = rows.Scan(&kind, &body); err != nil {
			break
		}
		if kind == kindPersonAdmission {
			var p struct {
				Admission  json.RawMessage `json:"admission"`
				Membership json.RawMessage `json:"membership"`
			}
			if err = json.Unmarshal(body, &p); err != nil {
				break
			}
			if len(p.Admission) > 0 && string(p.Admission) != "null" {
				add("person_admission", p.Admission)
			}
			if len(p.Membership) > 0 && string(p.Membership) != "null" {
				add("person_membership", p.Membership)
			}
		} else if mapped, ok := kinds[kind]; ok {
			add(mapped, body)
		}
	}
	err = errors.Join(err, rows.Err(), rows.Close())
	if err != nil {
		return c, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT membership,COALESCE(admission,'') FROM members WHERE network_id=? ORDER BY host_id`, network)
	if err != nil {
		return c, err
	}
	for rows.Next() {
		var member, admission string
		if err = rows.Scan(&member, &admission); err != nil {
			break
		}
		if member != "" {
			add("host_membership", []byte(member))
		}
		if admission != "" {
			add("host_admission", []byte(admission))
		}
	}
	err = errors.Join(err, rows.Err(), rows.Close())
	if err != nil {
		return c, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT successor FROM successors ORDER BY sequence`)
	if err != nil {
		return c, err
	}
	for rows.Next() {
		var body []byte
		if err = rows.Scan(&body); err != nil {
			break
		}
		if _, err = membership.DecodeSuccessor(body); err != nil {
			break
		}
		add("coordinator_successor", body)
	}
	err = errors.Join(err, rows.Err(), rows.Close())
	if err != nil {
		return c, err
	}
	for _, p := range objects {
		c.Objects = append(c.Objects, p)
	}
	sort.Slice(c.Objects, func(i, j int) bool { return c.Objects[i].ID < c.Objects[j].ID })
	return combineLinkCatalog(linkCatalog{Format: 1, NetworkID: network, Objects: []linkProof{}}, c)
}

func mergeLinkCatalog(base linkCatalog, submitted []byte) (linkCatalog, error) {
	if len(submitted) > 1<<20 {
		return base, linkFailure(400, "invalid")
	}
	var added linkCatalog
	if linking.DecodeMutation(submitted, "format network_id objects", &added) != nil || added.Format != 1 || added.NetworkID != base.NetworkID || added.Objects == nil || len(added.Objects) > 4096 {
		return base, linkFailure(400, "invalid")
	}
	var raw struct {
		Objects []json.RawMessage `json:"objects"`
	}
	if err := json.Unmarshal(submitted, &raw); err != nil {
		return base, linkFailure(400, "invalid")
	}
	for _, entry := range raw.Objects {
		var p linkProof
		if linking.DecodeMutation(entry, "id kind body_base64", &p) != nil {
			return base, linkFailure(400, "invalid")
		}
	}
	return combineLinkCatalog(base, added)
}

// combineLinkCatalog merges already decoded durable state. Mutation bytes pass
// the smaller transport parser before reaching this internal helper.
func combineLinkCatalog(base, added linkCatalog) (linkCatalog, error) {
	if base.Format != 1 || added.Format != 1 || base.NetworkID != added.NetworkID || added.Objects == nil {
		return base, linkFailure(400, "invalid")
	}
	byID := map[string]linkProof{}
	for _, p := range base.Objects {
		byID[p.ID] = p
	}
	last := ""
	for _, p := range added.Objects {
		body, err := base64.StdEncoding.Strict().DecodeString(p.BodyBase64)
		if err != nil || len(body) > 1<<20 || base64.StdEncoding.EncodeToString(body) != p.BodyBase64 || p.ID <= last || linkProofOf(p.Kind, body).ID != p.ID {
			return base, linkFailure(400, "invalid")
		}
		last = p.ID
		if old, ok := byID[p.ID]; ok && old != p {
			return base, linkFailure(409, "state_conflict")
		}
		byID[p.ID] = p
	}
	base.Objects = []linkProof{}
	var size int
	for _, p := range byID {
		body, _ := base64.StdEncoding.DecodeString(p.BodyBase64)
		size += len(body)
		base.Objects = append(base.Objects, p)
	}
	if len(base.Objects) > 4096 || size > 8<<20 {
		return base, linkFailure(409, "quota_exceeded")
	}
	sort.Slice(base.Objects, func(i, j int) bool { return base.Objects[i].ID < base.Objects[j].ID })
	return base, nil
}

func storeLinkCatalog(ctx context.Context, tx *sql.Tx, c linkCatalog) error {
	for _, p := range c.Objects {
		body, err := base64.StdEncoding.DecodeString(p.BodyBase64)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO link_objects VALUES(?,?,?,?) ON CONFLICT(network_id,proof_id) DO NOTHING`, c.NetworkID, p.ID, p.Kind, body); err != nil {
			return err
		}
	}
	return nil
}

func linkVerificationError(err error) error {
	if err == nil {
		return nil
	}
	var p *linking.PathError
	if errors.As(err, &p) {
		status := 403
		switch p.Code {
		case "invalid":
			status = 400
		case "proof_required", "state_conflict", "quota_exceeded", "operation_conflict":
			status = 409
		case "upgrade_required":
			status = 426
		case "expired":
			status = 410
		}
		return &linkError{status: status, code: p.Code, requiredIDs: p.RequiredIDs}
	}
	var invalidation *linking.ActionInvalidation
	if errors.As(err, &invalidation) {
		return linkFailure(403, "authority_would_be_invalidated")
	}
	if errors.Is(err, membership.ErrInvalid) {
		return linkFailure(400, "invalid")
	}
	return err
}

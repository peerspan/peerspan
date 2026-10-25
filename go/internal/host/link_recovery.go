package host

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

const kindLinkImportIntent = "link_feature_import_intent"

type FeatureImportRequest struct {
	CoordinatorAddress   string `json:"coordinator_address"`
	CoordinatorPublicKey string `json:"coordinator_public_key"`
	ImportID             string `json:"import_id"`
	Approve              bool   `json:"approve"`
}
type FeatureImportReview struct {
	NetworkID            string `json:"network_id"`
	NetworkName          string `json:"network_name"`
	Epoch                uint64 `json:"epoch"`
	FeatureID            string `json:"feature_id"`
	CoordinatorAddress   string `json:"coordinator_address"`
	CoordinatorPublicKey string `json:"coordinator_public_key"`
	CatalogSHA256        string `json:"catalog_sha256"`
	ExpiresAt            string `json:"expires_at"`
	SignerPublicKey      string `json:"signer_public_key"`
}
type FeatureImportResult struct {
	ImportID        string               `json:"import_id"`
	Review          FeatureImportReview  `json:"review"`
	SigningRequests []LinkSigningRequest `json:"signing_requests"`
	Committed       bool                 `json:"committed"`
}
type linkImportAuthorization struct {
	Format               uint64 `json:"format"`
	NetworkID            string `json:"network_id"`
	NetworkName          string `json:"network_name"`
	Epoch                uint64 `json:"epoch"`
	FeatureID            string `json:"feature_id"`
	CoordinatorAddress   string `json:"coordinator_address"`
	CoordinatorPublicKey string `json:"coordinator_public_key"`
	CatalogSHA256        string `json:"catalog_sha256"`
	IssuedAt             string `json:"issued_at"`
	ExpiresAt            string `json:"expires_at"`
	Signature            string `json:"signature"`
}

func (a linkImportAuthorization) message() []byte {
	return linkMessage("peerspan-link-feature-import-v1", a.NetworkID, a.NetworkName, strconv.FormatUint(a.Epoch, 10), a.FeatureID, a.CoordinatorAddress, a.CoordinatorPublicKey, a.CatalogSHA256, a.IssuedAt, a.ExpiresAt)
}

type linkImportIntent struct {
	Format                      uint64 `json:"format"`
	ImportID                    string `json:"import_id"`
	Approved                    bool   `json:"approved"`
	State                       string `json:"state"`
	NetworkBase64               string `json:"network_base64"`
	CatalogBase64               string `json:"catalog_base64"`
	AuthorizationTemplateBase64 string `json:"authorization_template_base64"`
	Signature                   string `json:"signature"`
	Submitted                   bool   `json:"submitted"`
	ResultMapBase64             string `json:"result_map_base64"`
}

func (i linkImportIntent) materialize(network string) (linkDescriptor, []byte, linkImportAuthorization, error) {
	bad := func() (linkDescriptor, []byte, linkImportAuthorization, error) {
		return linkDescriptor{}, nil, linkImportAuthorization{}, linkFail("state_conflict", "-", "feature_import")
	}
	if i.Format != 1 || !linkID(i.ImportID, "lfi_") || i.State != "review" && i.State != "awaiting_signature" && i.State != "ready" && i.State != "submitted" && i.State != "complete" && i.State != "expired" || i.Submitted && (!i.Approved || i.Signature == "-") || i.Signature != "-" && !i.Approved || i.State == "complete" && (!i.Submitted || i.ResultMapBase64 == "-") {
		return bad()
	}
	net, e := linkBytes(i.NetworkBase64, linking.MaxObject)
	if e != nil {
		return bad()
	}
	var descriptor linkDescriptor
	if linking.DecodeMutation(net, "network_id name genesis_root_public_key coordinator_address coordinator_public_key", &descriptor) != nil || descriptor.NetworkID != network {
		return bad()
	}
	catalog, e := linkBytes(i.CatalogBase64, linking.MaxStoredCatalog)
	if e != nil {
		return bad()
	}
	if _, e = decodeLinkCatalog(catalog, network); e != nil {
		return bad()
	}
	template, e := linkBytes(i.AuthorizationTemplateBase64, linking.MaxObject)
	if e != nil {
		return bad()
	}
	var a linkImportAuthorization
	if linking.DecodeMutation(template, "format network_id network_name epoch feature_id coordinator_address coordinator_public_key catalog_sha256 issued_at expires_at signature", &a) != nil || a.Format != 1 || a.NetworkID != descriptor.NetworkID || a.NetworkName != descriptor.Name || a.CoordinatorAddress != descriptor.CoordinatorAddress || a.CoordinatorPublicKey != descriptor.CoordinatorPublicKey || !linkID(a.FeatureID, "lf_") || a.Signature != "-" || a.CatalogSHA256 != linkHash(catalog) {
		return bad()
	}
	issued, e := linkStamp(a.IssuedAt)
	until, ue := linkStamp(a.ExpiresAt)
	if e != nil || ue != nil || until.Sub(issued) != 300*time.Second || i.ImportID != "lfi_"+linkHash(linkMessage("peerspan-link-feature-import-intent-v1", network, a.CoordinatorAddress, a.CoordinatorPublicKey, a.CatalogSHA256, a.IssuedAt)) {
		return bad()
	}
	return descriptor, catalog, a, nil
}
func readLinkImport(ctx context.Context, q dbQuerier, network, id string) (linkImportIntent, error) {
	var raw string
	if e := q.QueryRowContext(ctx, `SELECT record FROM network_statements WHERE network_id=? AND kind=? AND subject=?`, network, kindLinkImportIntent, id).Scan(&raw); e != nil {
		if errors.Is(e, sql.ErrNoRows) {
			return linkImportIntent{}, linkFail("not_found", "-", "feature_import")
		}
		return linkImportIntent{}, e
	}
	var intent linkImportIntent
	if linking.DecodeStoredJSON([]byte(raw), "format import_id approved state network_base64 catalog_base64 authorization_template_base64 signature submitted result_map_base64", &intent) != nil || intent.ImportID != id {
		return intent, linkFail("state_conflict", "-", "feature_import")
	}
	_, _, _, e := intent.materialize(network)
	return intent, e
}
func (s *Store) saveLinkImport(ctx context.Context, network string, intent linkImportIntent) error {
	if _, _, _, e := intent.materialize(network); e != nil {
		return e
	}
	raw, e := linkJSON(intent)
	if e != nil {
		return e
	}
	_, e = s.db.ExecContext(ctx, `INSERT INTO network_statements(network_id,kind,subject,record) VALUES(?,?,?,?) ON CONFLICT(network_id,kind,subject) DO UPDATE SET record=excluded.record`, network, kindLinkImportIntent, intent.ImportID, string(raw))
	return e
}
func (s *Store) featureImportView(ctx context.Context, n Network, intent linkImportIntent) (FeatureImportResult, error) {
	_, catalog, a, e := intent.materialize(n.ID)
	if e != nil {
		return FeatureImportResult{}, e
	}
	objects, e := decodeLinkCatalog(catalog, n.ID)
	if e != nil {
		return FeatureImportResult{}, e
	}
	chain, e := linkChain(n, &linkProjection{Objects: objects})
	if e != nil || uint64(chain.Epoch()) != a.Epoch {
		return FeatureImportResult{}, linkFail("state_conflict", "-", "feature_import")
	}
	result := FeatureImportResult{ImportID: intent.ImportID, Review: FeatureImportReview{a.NetworkID, a.NetworkName, a.Epoch, a.FeatureID, a.CoordinatorAddress, a.CoordinatorPublicKey, a.CatalogSHA256, a.ExpiresAt, chain.CurrentPublicKey()}, SigningRequests: []LinkSigningRequest{}, Committed: intent.State == "complete"}
	if intent.Approved && intent.Signature == "-" && intent.State != "expired" {
		format := "ed25519"
		if n.RootSSH {
			format = "sshsig"
		}
		result.SigningRequests = append(result.SigningRequests, LinkSigningRequest{"feature_import", base64.StdEncoding.EncodeToString(a.message()), chain.CurrentPublicKey(), format})
	}
	return result, nil
}

func (s *Store) FeatureImport(ctx context.Context, network string, request FeatureImportRequest) (FeatureImportResult, error) {
	s.syncing.Lock()
	defer s.syncing.Unlock()
	n, e := s.Network(ctx, network)
	if e != nil {
		return FeatureImportResult{}, e
	}
	if !membership.ValidCoordinatorAddress(request.CoordinatorAddress) || !linkPublicKey(request.CoordinatorPublicKey) || request.ImportID != "-" && !linkID(request.ImportID, "lfi_") || request.Approve && request.ImportID == "-" {
		return FeatureImportResult{}, linkFail("invalid", "-", "feature_import")
	}
	now, e := linkNow()
	if e != nil {
		return FeatureImportResult{}, e
	}
	var intent linkImportIntent
	if request.ImportID == "-" {
		if e = s.pruneLinkImports(ctx, n.ID, now); e != nil {
			return FeatureImportResult{}, e
		}
		p, e := s.readLinkProjection(ctx, s.db, n, now)
		if e != nil {
			return FeatureImportResult{}, e
		}
		if p == nil {
			return FeatureImportResult{}, linkFail("upgrade_required", "-", "feature")
		}
		target := n
		target.CoordinatorAddress, target.CoordinatorPublicKey = request.CoordinatorAddress, request.CoordinatorPublicKey
		descriptor, e := linkJSON(linkNetworkDescriptor(target))
		if e != nil {
			return FeatureImportResult{}, e
		}
		a := linkImportAuthorization{1, n.ID, n.Name, p.Network.Epoch, p.Network.Facts.FeatureID, target.CoordinatorAddress, target.CoordinatorPublicKey, linkHash(p.Catalog), linkTime(now), linkTime(now.Add(300 * time.Second)), "-"}
		template, e := linkJSON(a)
		if e != nil {
			return FeatureImportResult{}, e
		}
		id := "lfi_" + linkHash(linkMessage("peerspan-link-feature-import-intent-v1", n.ID, a.CoordinatorAddress, a.CoordinatorPublicKey, a.CatalogSHA256, a.IssuedAt))
		intent = linkImportIntent{1, id, false, "review", base64.StdEncoding.EncodeToString(descriptor), base64.StdEncoding.EncodeToString(p.Catalog), base64.StdEncoding.EncodeToString(template), "-", false, "-"}
		if old, err := readLinkImport(ctx, s.db, n.ID, id); err == nil {
			return s.featureImportView(ctx, n, old)
		} else if failure := linkCause(err, "-", "feature_import"); failure.Code != "not_found" {
			return FeatureImportResult{}, err
		}
		var count int
		if e = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM network_statements WHERE network_id=? AND kind=?`, n.ID, kindLinkImportIntent).Scan(&count); e != nil {
			return FeatureImportResult{}, e
		}
		if count >= 8 {
			return FeatureImportResult{}, linkFail("quota_exceeded", "-", "feature_import")
		}
		// Every independently retained proof is relevant to this complete snapshot;
		// refuse before approval if its exact import body cannot fit the writer.
		unsigned, _ := linkJSON(map[string]any{"network": json.RawMessage(descriptor), "catalog": json.RawMessage(p.Catalog), "feature_authorization": a})
		if len(unsigned)+1024 > 1<<20 {
			return FeatureImportResult{}, linkFail("quota_exceeded", "-", "feature_import")
		}
		if e = s.saveLinkImport(ctx, n.ID, intent); e != nil {
			return FeatureImportResult{}, e
		}
		return s.featureImportView(ctx, n, intent)
	}
	intent, e = readLinkImport(ctx, s.db, network, request.ImportID)
	if e != nil {
		return FeatureImportResult{}, e
	}
	descriptor, _, _, e := intent.materialize(network)
	if e != nil {
		return FeatureImportResult{}, e
	}
	if descriptor.CoordinatorAddress != request.CoordinatorAddress || descriptor.CoordinatorPublicKey != request.CoordinatorPublicKey {
		return FeatureImportResult{}, linkFail("operation_conflict", "-", "feature_import")
	}
	if !request.Approve {
		return s.featureImportView(ctx, n, intent)
	}
	if e = s.checkLinkImportCurrent(ctx, n, intent, now); e != nil {
		return FeatureImportResult{}, e
	}
	intent.Approved = true
	if intent.State == "review" {
		intent.State = "awaiting_signature"
	}
	if e = s.saveLinkImport(ctx, n.ID, intent); e != nil {
		return FeatureImportResult{}, e
	}
	return s.advanceLinkImport(ctx, n, intent, "")
}
func (s *Store) checkLinkImportCurrent(ctx context.Context, n Network, intent linkImportIntent, now time.Time) error {
	if intent.State == "complete" || intent.Submitted {
		return nil
	}
	_, catalog, a, e := intent.materialize(n.ID)
	if e != nil {
		return e
	}
	until, _ := linkStamp(a.ExpiresAt)
	issued, _ := linkStamp(a.IssuedAt)
	if now.Before(issued) || !now.Before(until) {
		return linkFail("expired", "-", "feature_import")
	}
	p, e := s.readLinkProjection(ctx, s.db, n, now)
	if e != nil {
		return e
	}
	if p == nil || p.Network.Epoch != a.Epoch || p.Network.Facts.FeatureID != a.FeatureID || linkHash(p.Catalog) != linkHash(catalog) {
		return linkFail("state_conflict", "-", "feature_import")
	}
	return nil
}
func (s *Store) ResumeFeatureImport(ctx context.Context, network, id, signature string) (FeatureImportResult, error) {
	s.syncing.Lock()
	defer s.syncing.Unlock()
	n, e := s.Network(ctx, network)
	if e != nil {
		return FeatureImportResult{}, e
	}
	intent, e := readLinkImport(ctx, s.db, network, id)
	if e != nil {
		return FeatureImportResult{}, e
	}
	if !intent.Approved {
		return s.featureImportView(ctx, n, intent)
	}
	return s.advanceLinkImport(ctx, n, intent, signature)
}
func (s *Store) advanceLinkImport(ctx context.Context, n Network, intent linkImportIntent, signature string) (FeatureImportResult, error) {
	view, e := s.featureImportView(ctx, n, intent)
	if e != nil || view.Committed {
		return view, e
	}
	now, e := linkNow()
	if e != nil {
		return view, e
	}
	if e = s.checkLinkImportCurrent(ctx, n, intent, now); e != nil {
		return view, e
	}
	descriptor, catalog, a, e := intent.materialize(n.ID)
	if e != nil {
		return view, e
	}
	if signature != "" {
		if intent.Signature != "-" && intent.Signature != signature {
			return view, linkFail("operation_conflict", "-", "feature_import")
		}
		intent.Signature = signature
	}
	if intent.Signature == "-" {
		var seed []byte
		if e = s.db.QueryRowContext(ctx, `SELECT root_seed FROM networks WHERE id=?`, n.ID).Scan(&seed); e != nil {
			return view, e
		}
		if len(seed) == ed25519.SeedSize {
			key := ed25519.NewKeyFromSeed(seed)
			if membership.EncodeKey(key.Public().(ed25519.PublicKey)) == view.Review.SignerPublicKey {
				intent.Signature = membership.EncodeKey(ed25519.Sign(key, a.message()))
			}
		}
	}
	if intent.Signature == "-" {
		return view, nil
	}
	a.Signature = intent.Signature
	public, e := membership.DecodeKey(view.Review.SignerPublicKey)
	if e != nil {
		return view, linkFail("invalid", "-", "feature_import")
	}
	valid := membership.VerifySSHSIG(public, a.message(), a.Signature) == nil
	if rawSignature, err := base64.StdEncoding.Strict().DecodeString(a.Signature); err == nil && len(rawSignature) == ed25519.SignatureSize && base64.StdEncoding.EncodeToString(rawSignature) == a.Signature {
		valid = valid || ed25519.Verify(public, a.message(), rawSignature)
	}
	if !valid {
		return view, linkFail("invalid", "-", "feature_import")
	}
	authorization, e := linkJSON(a)
	if e != nil {
		return view, e
	}
	target := n
	target.CoordinatorAddress, target.CoordinatorPublicKey, target.CoordinatorPending = descriptor.CoordinatorAddress, descriptor.CoordinatorPublicKey, nil
	net, _ := linkBytes(intent.NetworkBase64, linking.MaxObject)
	// Already-submitted exact outcomes may be retried beyond expiry; new intent
	// signatures must pass the fixed first-use verifier before any publication.
	if !intent.Submitted {
		if _, e = linking.VerifyStoredFeatureImport(linking.CatalogFactContext{Network: net, Epoch: a.Epoch, KnownFeatureID: a.FeatureID, Now: now}, catalog, authorization); e != nil {
			return view, e
		}
	}
	body, e := linkJSON(map[string]any{"network": json.RawMessage(net), "catalog": json.RawMessage(catalog), "feature_authorization": json.RawMessage(authorization)})
	if e != nil {
		return view, e
	}
	if len(body) > 1<<20 {
		return view, linkFail("quota_exceeded", "-", "feature_import")
	}
	intent.State, intent.Submitted = "submitted", true
	if e = s.saveLinkImport(ctx, n.ID, intent); e != nil {
		return view, e
	}
	raw, e := s.linkCoordinator(ctx, target, http.MethodPost, "/coord/v2/networks/import", body)
	if e != nil {
		return view, e
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return view, e
	}
	defer tx.Rollback()
	wire, e := decodeLinkMap(raw, target)
	if e != nil {
		return view, e
	}
	received, e := decodeLinkCatalog(wire.Catalog, n.ID)
	if e != nil {
		return view, e
	}
	original, e := decodeLinkCatalog(catalog, n.ID)
	if e != nil {
		return view, e
	}
	retained := map[string]bool{}
	for _, object := range received.Objects {
		retained[object.ID] = true
	}
	for _, object := range original.Objects {
		if !retained[object.ID] {
			return view, linkFail("proof_required", "-", "feature_import", object.ID)
		}
	}
	receiptEpoch, e := linkCatalogEpoch(received)
	if e != nil {
		return view, e
	}
	receiptContext := linking.CatalogFactContext{Network: net, Epoch: receiptEpoch, KnownFeatureID: a.FeatureID, Now: now}
	if _, e = linking.VerifyStoredNetworkState(receiptContext, wire.Catalog); e != nil {
		return view, e
	}
	if _, e = linking.VerifyStoredAccessState(linking.AccessContext{Network: net, Epoch: receiptEpoch, KnownFeatureID: a.FeatureID, Now: now}, wire.Catalog); e != nil {
		return view, e
	}
	prior, e := readLinkCatalog(ctx, tx, n.ID)
	if e != nil {
		return view, e
	}
	union, e := mergeLinkCatalog(n.ID, prior, wire.Catalog)
	if e != nil {
		return view, e
	}
	unionObjects, e := decodeLinkCatalog(union, n.ID)
	if e != nil {
		return view, e
	}
	currentEpoch, e := linkCatalogEpoch(unionObjects)
	if e != nil {
		return view, e
	}
	if e = linking.VerifyStoredCatalogRepair(linking.CatalogFactContext{Network: net, Epoch: currentEpoch, KnownFeatureID: a.FeatureID, Now: now}, prior, union); e != nil {
		return view, e
	}
	// Only this exact persisted approved receipt gets historical-union handling.
	// Normal live maps continue to reject every omitted retained proof.
	wire.Catalog = union
	augmented, e := linkJSON(wire)
	if e != nil {
		return view, e
	}
	p, members, e := s.verifyLinkMap(ctx, tx, target, augmented, now)
	if e != nil {
		return view, e
	}
	existing, e := readLinkMembers(ctx, tx, n.ID)
	if e != nil {
		return view, e
	}
	hints := map[string]NetworkMember{}
	for _, member := range members {
		hints[member.PublicKey] = member
	}
	for _, member := range existing {
		if incoming, ok := hints[member.PublicKey]; !ok || member.UpdatedAt >= incoming.UpdatedAt {
			hints[member.PublicKey] = member
		}
	}
	mergedHints := []NetworkMember{}
	for _, member := range hints {
		mergedHints = append(mergedHints, member)
	}
	members = projectedLinkMembers(p, mergedHints, linkTime(now))
	if e = s.applyLinkProjection(ctx, tx, &n, p, members, linkTime(now)); e != nil {
		return view, e
	}
	intent.State, intent.ResultMapBase64 = "complete", base64.StdEncoding.EncodeToString(raw)
	encoded, e := linkJSON(intent)
	if e != nil {
		return view, e
	}
	if _, e = tx.ExecContext(ctx, `UPDATE network_statements SET record=? WHERE network_id=? AND kind=? AND subject=?`, string(encoded), n.ID, kindLinkImportIntent, intent.ImportID); e != nil {
		return view, e
	}
	if e = tx.Commit(); e != nil {
		return view, e
	}
	s.mapApplied(n.ID, members)
	return s.featureImportView(ctx, n, intent)
}

func linkRecoveryRoutes(mux *http.ServeMux, s *Store) {
	mux.HandleFunc("POST /v1/networks/{id}/feature-import", func(w http.ResponseWriter, r *http.Request) {
		var request FeatureImportRequest
		if !decodeLinkMutation(w, r, "coordinator_address coordinator_public_key import_id approve", &request) {
			return
		}
		value, e := s.FeatureImport(r.Context(), r.PathValue("id"), request)
		respondLink(w, http.StatusOK, value, e, "-", "feature_import")
	})
	mux.HandleFunc("POST /v1/networks/{id}/feature-import/{import}/signed", func(w http.ResponseWriter, r *http.Request) {
		var request linkSignature
		if !decodeLinkMutation(w, r, "object_type signature", &request) {
			return
		}
		if request.ObjectType != "feature_import" {
			respondLink(w, 0, nil, linkFail("invalid", "-", "feature_import"), "-", "feature_import")
			return
		}
		value, e := s.ResumeFeatureImport(r.Context(), r.PathValue("id"), r.PathValue("import"), request.Signature)
		respondLink(w, http.StatusOK, value, e, "-", "feature_import")
	})
	mux.HandleFunc("POST /v1/networks/{id}/feature-import/{import}/resume", func(w http.ResponseWriter, r *http.Request) {
		var request struct{}
		if !decodeLinkMutation(w, r, "", &request) {
			return
		}
		value, e := s.ResumeFeatureImport(r.Context(), r.PathValue("id"), r.PathValue("import"), "")
		respondLink(w, http.StatusOK, value, e, "-", "feature_import")
	})
}

package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type DecActionRequest struct {
	claim           string
	rootPreparation bool
	newRootFormat   string
	Kind            string `json:"kind"`
	Provider        string `json:"provider_id"`
	Format          string `json:"signature_format"`
	Payload         string `json:"payload_base64"`
	Approve         bool   `json:"approve"`
}

func (r DecActionRequest) localKind() string {
	if r.claim != "" {
		return "policy_claim"
	}
	return r.Kind
}

type decActionReview struct {
	Kind      string          `json:"kind"`
	Statement string          `json:"statement_id"`
	Provider  DecProviderView `json:"provider"`
	Subject   json.RawMessage `json:"subject"`
	Sequence  uint64          `json:"sequence"`
	After     string          `json:"not_after"`
	Warning   string          `json:"authority_warning"`
}

type decActionResult struct {
	ID        string              `json:"action_id"`
	Review    decActionReview     `json:"review"`
	Signing   []DecSigningRequest `json:"signing_requests"`
	Statement string              `json:"statement_base64"`
	Proof     string              `json:"proof_id"`
	Catalog   any                 `json:"catalog"`
	Committed bool                `json:"committed"`
	Delivery  DecDeliveryView     `json:"delivery"`
}

func decEmptyDelivery() DecDeliveryView { return DecDeliveryView{[]string{}, []DecPeerError{}} }
func decActionSubject(statement *dec.Statement) (json.RawMessage, uint64, string, error) {
	var subject any
	sequence, after := uint64(0), "-"
	switch {
	case statement.Root != nil:
		subject = struct {
			Key   string `json:"root_public_key"`
			Epoch uint64 `json:"epoch"`
		}{statement.Root.Key, statement.Root.Epoch}
		sequence = statement.Root.Epoch
	case statement.Lease != nil:
		subject, sequence, after = statement.Lease.Subject, statement.Lease.Sequence, statement.Lease.After
	case statement.Access != nil:
		if statement.Kind == "policy" {
			var owner string
			if json.Unmarshal(statement.Body["person_public_key"], &owner) != nil {
				return nil, 0, "-", decStorageError()
			}
			subject = struct {
				Person string `json:"person_public_key"`
			}{owner}
		} else {
			var name string
			if json.Unmarshal(statement.Body["name"], &name) != nil {
				return nil, 0, "-", decStorageError()
			}
			subject = struct {
				Name string `json:"name"`
			}{name}
		}
		sequence, after = statement.Access.Sequence, statement.Access.After
	case statement.Restriction != nil:
		subject = statement.Restriction.Target
	default:
		return nil, 0, "-", decFailure("invalid")
	}
	raw, e := json.Marshal(subject)
	return raw, sequence, after, e
}

// Provider resolution never changes the selected row. Explicit external
// original/root slots validate public authority without importing private keys.
func (s *Store) decActionProvider(ctx context.Context, q dbQuerier, snapshot *decSnapshot, p *dec.Projection, id, format string) (DecProviderView, decIntentProvider, dec.Actor, error) {
	var view DecProviderView
	var provider decIntentProvider
	actor := dec.Actor{Person: "-", Host: "-", Device: "-", IssuerID: "-"}
	if format != "auto" && format != "ed25519" && format != "sshsig" {
		return view, provider, actor, decFailure("invalid")
	}
	if len(snapshot.Fenced) > 0 {
		return view, provider, actor, decFailure("migration_pending", snapshot.Fenced...)
	}
	if id == "network_root" {
		if p.Root.Code != "-" {
			return view, provider, actor, decFailure(p.Root.Code, p.Root.RequiredIDs...)
		}
		root := snapshot.Catalog.Statements[p.Root.SelectedID]
		if root == nil || root.Root == nil {
			return view, provider, actor, decFailure("proof_required", p.Root.SelectedID)
		}
		if format == "auto" {
			format = "ed25519"
		}
		if format == "ed25519" {
			if len(snapshot.RootSeed) != 32 || membership.EncodeKey(ed25519.NewKeyFromSeed(snapshot.RootSeed).Public().(ed25519.PublicKey)) != root.Root.Key {
				return view, provider, actor, decFailure("signer_unavailable")
			}
		}
		view = DecProviderView{"network_root", "-", "-", "-", "-", root.ID, 8, "-"}
		provider = decIntentProvider{"root", root.Root.Key, format, "-"}
		actor.IssuerID = root.ID
		return view, provider, actor, nil
	}
	selected := snapshot
	automatic := id == "auto"
	if automatic {
		if snapshot.Provider == nil {
			return view, provider, actor, ErrNotFound
		}
	} else {
		person := id
		if dec.ValidID(id, "ds_") {
			d := snapshot.Catalog.Statements[id]
			if d == nil {
				return view, provider, actor, decFailure("proof_required", id)
			}
			if d.Kind != "device_lease" {
				return view, provider, actor, decFailure("invalid")
			}
			person = d.Lease.Subject.Person
		}
		var e error
		selected, _, e = decRequestedProvider(snapshot, p, DecSelectProvider{Provider: id, Person: person, Host: s.identity.PublicKey})
		if e != nil {
			return view, provider, actor, e
		}
	}
	public, e := decPublicProvider(selected, p)
	if e != nil {
		return view, provider, actor, e
	}
	view = *public
	if selected.Provider.Kind == "device" {
		if format == "sshsig" {
			return view, provider, actor, decFailure("invalid")
		}
		if _, e = decOwnedDeviceSeed(ctx, q, selected.Provider.Device); e != nil {
			return view, provider, actor, e
		}
		provider = decIntentProvider{"device", selected.Provider.Device, "ed25519", selected.Provider.Lease}
		actor = dec.Actor{Person: selected.Provider.Person, Host: s.identity.PublicKey, Device: selected.Provider.Device, IssuerID: selected.Provider.Lease}
	} else {
		if format == "ed25519" {
			return view, provider, actor, decFailure("invalid")
		}
		if automatic {
			available := s.decProviderAvailable(selected, public, nil)
			if available.State != "available" {
				return view, provider, actor, decFailure(available.Code, available.Required...)
			}
		}
		provider = decIntentProvider{"original", selected.Provider.Person, "sshsig", "-"}
		actor.Person = selected.Provider.Person
	}
	return view, provider, actor, nil
}

func decConcreteProvider(provider decIntentProvider) string {
	if provider.Kind == "root" {
		return "network_root"
	}
	if provider.Kind == "device" {
		return provider.Lease
	}
	return provider.Signer
}
func decActorForIntent(i decIntent) dec.Actor {
	actor := dec.Actor{Person: "-", Host: "-", Device: "-", IssuerID: "-"}
	switch i.Record.Provider.Kind {
	case "root":
		actor.IssuerID = i.Record.Root
	case "original":
		actor.Person = i.Record.Person
	case "device":
		actor = dec.Actor{Person: i.Record.Person, Host: i.Record.Host, Device: i.Record.Device, IssuerID: i.Record.Provider.Lease}
	}
	return actor
}
func (s *Store) makeDecAction(snapshot *decSnapshot, p *dec.Projection, request DecActionRequest, view DecProviderView, provider decIntentProvider, actor dec.Actor, now string) (decIntent, error) {
	var i decIntent
	payload, e := decBytes(request.Payload, dec.MaxPayload)
	if e != nil {
		return i, decFailure("invalid")
	}
	statement, e := dec.ReadActionPayload(snapshot.Descriptor, request.Kind, payload)
	if e != nil {
		return i, e
	}
	if request.claim != "" {
		if request.Kind != "policy" {
			return i, decFailure("invalid")
		}
		if e = checkDecClaimPolicy(statement, request.claim, s.identity.ID); e != nil {
			return i, e
		}
	}
	actorRaw, _ := json.Marshal(actor)
	authority, e := dec.VerifyActionIntent(snapshot.Descriptor, snapshot.PriorRaw, snapshot.Catalog.Raw, actorRaw, payload, now, request.Kind)
	if e != nil {
		return i, e
	}
	if authority.Signer != provider.Signer {
		return i, decFailure("forbidden")
	}
	signatures := []dec.Signature{{Role: "issuer", PublicKey: provider.Signer, Format: provider.Format, Signature: "-"}}
	if statement.Root != nil {
		signatures = []dec.Signature{}
		for _, id := range statement.Root.Predecessors {
			root := snapshot.Catalog.Statements[id]
			if root == nil || root.Root == nil {
				return i, decFailure("proof_required", id)
			}
			role := "issuer"
			if len(statement.Root.Predecessors) > 1 {
				role = "root_branch:" + id
			}
			signatures = append(signatures, dec.Signature{Role: role, PublicKey: root.Root.Key, Format: provider.Format, Signature: "-"})
		}
		format := request.newRootFormat
		if format == "" {
			format = provider.Format
		}
		signatures = append(signatures, dec.Signature{Role: "new_root", PublicKey: statement.Root.Key, Format: format, Signature: "-"})
	}
	if statement.Kind == "binding_lease" || statement.Kind == "host_lease" {
		signatures = append(signatures, dec.Signature{Role: "host", PublicKey: statement.Lease.Subject.Host, Format: "ed25519", Signature: "-"})
	}
	template, e := dec.StatementTemplate(snapshot.Descriptor, request.Kind, payload, signatures)
	if e != nil {
		return i, e
	}
	subject, sequence, after, e := decActionSubject(statement)
	if e != nil {
		return i, e
	}
	review := decActionReview{request.localKind(), statement.ID, view, subject, sequence, after, "This locally committed change uses only the exact reviewed authority and hard deadlines. Peer delivery does not prove complete remote history."}
	reviewRaw, e := json.Marshal(review)
	if e != nil {
		return i, e
	}
	id, e := decRandomID("dint_")
	if e != nil {
		return i, e
	}
	issued := ""
	if statement.Root != nil {
		issued = statement.Root.Issued
	}
	if statement.Lease != nil {
		issued = statement.Lease.Issued
	}
	if statement.Access != nil {
		issued = statement.Access.Issued
	}
	if statement.Restriction != nil {
		issued = statement.Restriction.Issued
	}
	at, e := dec.ParseTime(issued)
	if e != nil {
		return i, e
	}
	expires := linkTime(at.Add(300 * time.Second))
	if expires <= now {
		return i, decFailure("expired")
	}
	approvedAt := "-"
	if request.Approve {
		approvedAt = now
	}
	person, host, device := view.Person, view.Host, view.Device
	i = decIntent{ID: id, Network: snapshot.Descriptor.NetworkID, Context: snapshot.Descriptor.ContextID, Kind: func() string {
		if request.rootPreparation {
			return "root_transition"
		}
		if request.claim != "" {
			return "policy_claim"
		}
		return "action"
	}(), Record: decIntentRecord{Format: 1, Operation: dec.ActionID(snapshot.Descriptor.ContextID, request.localKind(), statement.ID, decConcreteProvider(provider)), Approved: request.Approve, ApprovedAt: approvedAt, Review: base64.StdEncoding.EncodeToString(reviewRaw), Provider: provider, Root: actor.IssuerID, Person: person, Host: host, Device: device, Scopes: view.Scopes, NotAfter: authority.After, Created: now, Expires: expires, Templates: []decIntentTemplate{{1, request.Kind, base64.StdEncoding.EncodeToString(template)}}, Signatures: []decIntentSignature{}, Completed: false, Terminal: "-", Result: "-"}}
	i.Record.Root = view.Root
	return i, validateDecIntent(&i.Record)
}

func readDecAction(i decIntent, d dec.Descriptor) (decActionReview, *dec.Statement, []byte, error) {
	var review decActionReview
	if i.Kind != "action" && i.Kind != "root_transition" && i.Kind != "policy_claim" || i.Network != d.NetworkID || i.Context != d.ContextID || len(i.Record.Templates) != 1 || !dec.ValidID(i.Record.Operation, "act_") {
		return review, nil, nil, decStorageError()
	}
	raw, e := decBytes(i.Record.Review, 1<<20)
	if e != nil {
		return review, nil, nil, e
	}
	if e = dec.ReadPrivateRecord(raw, "kind statement_id provider subject sequence not_after authority_warning", &review); e != nil {
		return review, nil, nil, e
	}
	statement, body, e := decFilledTemplate(d, i, i.Record.Templates[0])
	if e != nil {
		return review, nil, nil, e
	}
	if (review.Kind != statement.Kind && !(i.Kind == "policy_claim" && review.Kind == "policy_claim" && statement.Kind == "policy")) || (i.Kind == "policy_claim") != (review.Kind == "policy_claim") || review.Statement != statement.ID || i.Record.Operation != dec.ActionID(d.ContextID, review.Kind, statement.ID, decConcreteProvider(i.Record.Provider)) || i.Record.Root != review.Provider.Root || review.Provider.Person != i.Record.Person || review.Provider.Host != i.Record.Host || review.Provider.Device != i.Record.Device || review.Provider.Scopes != i.Record.Scopes || review.Warning == "" || len(review.Warning) > 1024 {
		return review, nil, nil, decStorageError()
	}
	subject, sequence, after, e := decActionSubject(statement)
	if e != nil {
		return review, nil, nil, e
	}
	if !bytes.Equal(subject, review.Subject) || sequence != review.Sequence || after != review.After {
		return review, nil, nil, decStorageError()
	}
	issuer := i.Record.Provider
	role := "issuer"
	if statement.Root != nil && len(statement.Root.Predecessors) > 1 {
		role = "root_branch:" + statement.Root.Predecessors[0]
		if i.Kind != "root_transition" || i.Record.Root != "-" || i.Record.Scopes != 0 {
			return review, nil, nil, decStorageError()
		}
	}
	matched := false
	for _, sig := range statement.Signatures {
		if sig.Role == role && (sig.PublicKey != issuer.Signer || sig.Format != issuer.Format) {
			return review, nil, nil, decStorageError()
		}
		matched = matched || sig.Role == role
	}
	if !matched || i.Secret != nil && (i.Kind != "root_transition" || statement.Root == nil || membership.EncodeKey(ed25519.NewKeyFromSeed(i.Secret).Public().(ed25519.PublicKey)) != statement.Root.Key) {
		return review, nil, nil, decStorageError()
	}
	return review, statement, body, nil
}

func findDecAction(ctx context.Context, q dbQuerier, network, operation string) (decIntent, error) {
	if !dec.ValidID(operation, "act_") {
		return decIntent{}, decFailure("invalid")
	}
	rows, e := q.QueryContext(ctx, `SELECT intent_id FROM dec_intents WHERE network_id=? AND kind IN ('action','root_transition','policy_claim') ORDER BY intent_id`, network)
	if e != nil {
		return decIntent{}, e
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return decIntent{}, e
		}
		ids = append(ids, id)
		if len(ids) > 4096 {
			rows.Close()
			return decIntent{}, decFailure("quota_exceeded")
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return decIntent{}, e
	}
	var found *decIntent
	for _, id := range ids {
		i, e := readDecIntent(ctx, q, id)
		if e != nil {
			return i, e
		}
		if i.Record.Operation == operation {
			if found != nil {
				return i, decStorageError()
			}
			copy := i
			found = &copy
		}
	}
	if found == nil {
		return decIntent{}, ErrNotFound
	}
	return *found, nil
}
func decActionComplete(statement *dec.Statement) bool {
	for _, sig := range statement.Signatures {
		if sig.Signature == "-" {
			return false
		}
	}
	return true
}
func decActionCandidate(d dec.Descriptor, statement *dec.Statement, body []byte) ([]byte, error) {
	if _, e := dec.ReadStatement(d, body); e != nil {
		return nil, e
	}
	return json.Marshal(struct {
		Format  uint64              `json:"format"`
		Context string              `json:"context_id"`
		Objects []dec.CatalogObject `json:"objects"`
	}{1, d.ContextID, []dec.CatalogObject{{ID: dec.ProofID(statement.Kind, body), Kind: statement.Kind, BodyBase64: base64.StdEncoding.EncodeToString(body)}}})
}
func verifyDecAction(snapshot *decSnapshot, i decIntent, now string) (decActionReview, *dec.Statement, []byte, error) {
	review, statement, body, e := readDecAction(i, snapshot.Descriptor)
	if e != nil {
		return review, nil, nil, e
	}
	if len(snapshot.Fenced) > 0 {
		return review, nil, nil, decFailure("migration_pending", snapshot.Fenced...)
	}
	if i.Record.Terminal != "-" {
		return review, nil, nil, decFailure("state_conflict")
	}
	if statement.Root != nil {
		for _, id := range statement.Root.Predecessors {
			root := snapshot.Catalog.Statements[id]
			if root == nil || root.Root == nil {
				return review, nil, nil, decFailure("proof_required", id)
			}
			role := "issuer"
			if len(statement.Root.Predecessors) > 1 {
				role = "root_branch:" + id
			}
			if statement.Signer(role) != root.Root.Key {
				return review, nil, nil, decStorageError()
			}
		}
	}
	actor := decActorForIntent(i)
	if statement.Root != nil && len(statement.Root.Predecessors) > 1 {
		actor.IssuerID = statement.Root.Predecessors[0]
	}
	actorRaw, _ := json.Marshal(actor)
	authority, e := dec.VerifyActionIntent(snapshot.Descriptor, snapshot.PriorRaw, snapshot.Catalog.Raw, actorRaw, statement.Payload, now, statement.Kind)
	if e != nil {
		return review, nil, nil, e
	}
	if i.Kind == "policy_claim" {
		p, e := verifyDecSnapshot(snapshot, now)
		if e != nil {
			return review, nil, nil, e
		}
		if current, _, e := p.Current([]string{"policy", i.Record.Person}); e == nil {
			before, e := decPolicyBody(current)
			if e != nil {
				return review, nil, nil, e
			}
			after, e := decPolicyBody(statement)
			if e != nil {
				return review, nil, nil, e
			}
			key, e := membership.DecodeKey(i.Record.Host)
			if e != nil {
				return review, nil, nil, e
			}
			host := membership.HostID(key)
			for _, candidate := range after.Capabilities {
				if candidate.Host != host {
					continue
				}
				for _, old := range before.Capabilities {
					if old.Capability == candidate.Capability && old.Host != host {
						return review, nil, nil, decFailure("forbidden")
					}
				}
			}
		}
	}
	if authority.Signer != i.Record.Provider.Signer || authority.After != i.Record.NotAfter || i.Record.Created > authority.DecisionTime || i.Record.Approved && i.Record.ApprovedAt > authority.DecisionTime {
		return review, nil, nil, decFailure("state_conflict")
	}
	return review, statement, body, nil
}

// Policy actions retain the shared tagged reservation/reference semantics.
func checkDecActionEditBoundary(ctx context.Context, q dbQuerier, snapshot *decSnapshot, statement *dec.Statement, ordinary ...bool) error {
	return checkDecPolicyEditBoundary(ctx, q, snapshot, statement, len(ordinary) == 1 && ordinary[0])
}

func decActionSigning(i decIntent, statement *dec.Statement, body []byte) ([]DecSigningRequest, error) {
	requests := []DecSigningRequest{}
	if !i.Record.Approved || i.Record.Terminal != "-" {
		return requests, nil
	}
	for _, sig := range statement.Signatures {
		if sig.Signature != "-" {
			continue
		}
		requests = append(requests, DecSigningRequest{i.ID, 1, statement.Kind, statement.ID, sig.Role, sig.PublicKey, sig.Format, base64.StdEncoding.EncodeToString(body), base64.StdEncoding.EncodeToString(dec.SignatureMessage(statement.ID, sig.Role, sig.PublicKey))})
		if len(requests) == 16 {
			break
		}
	}
	return requests, nil
}

func acceptDecActionSignatures(d dec.Descriptor, i *decIntent, input DecSignatureBatch) error {
	if input.Intent != i.ID {
		return decFailure("invalid")
	}
	_, statement, _, e := readDecAction(*i, d)
	if e != nil {
		return e
	}
	for _, sig := range input.Signatures {
		if sig.Slot != 1 {
			return decFailure("invalid")
		}
		var expected *dec.Signature
		for index := range statement.Signatures {
			if statement.Signatures[index].Role == sig.Role {
				expected = &statement.Signatures[index]
				break
			}
		}
		if expected == nil {
			return decFailure("invalid")
		}
		if e = dec.VerifySignature(expected.PublicKey, expected.Format, dec.SignatureMessage(statement.ID, sig.Role, expected.PublicKey), sig.Signature); e != nil {
			return e
		}
		if decSlotSignature(*i, 1, sig.Role) != "-" {
			if e = addDecSignature(i, sig); e != nil {
				return e
			}
			continue
		}
		if !i.Record.Approved || i.Record.Terminal != "-" {
			return decFailure("operation_conflict")
		}
		if e = addDecSignature(i, sig); e != nil {
			return e
		}
	}
	return nil
}

// Owned auxiliary keys sign only their declared typed role. A held current root
// can fill its exact SSHSIG branch slot alongside external branches; other
// external SSH slots remain fixed requests without importing/substituting keys.
func (s *Store) signDecActionOwned(ctx context.Context, q dbQuerier, snapshot *decSnapshot, i *decIntent, statement *dec.Statement) error {
	for _, sig := range statement.Signatures {
		rootRole := i.Record.Provider.Kind == "root" && (sig.Role == "issuer" || strings.HasPrefix(sig.Role, "root_branch:"))
		if sig.Signature != "-" || sig.Format != "ed25519" && !(rootRole && sig.Format == "sshsig") {
			continue
		}
		current, e := decNow()
		if e != nil {
			return e
		}
		if _, _, _, e = verifyDecAction(snapshot, *i, linkTime(current)); e != nil {
			return e
		}
		if e = decCurrentIntentProvider(ctx, q, snapshot, *i); e != nil {
			return e
		}
		var key ed25519.PrivateKey
		if sig.Role == "host" && sig.PublicKey == s.identity.PublicKey {
			key = s.privateKey
		}
		if i.Record.Provider.Kind == "device" && sig.Role == "issuer" {
			seed, e := decOwnedDeviceSeed(ctx, q, i.Record.Provider.Signer)
			if e != nil {
				return e
			}
			key = ed25519.NewKeyFromSeed(seed)
		}
		if rootRole && len(snapshot.RootSeed) == 32 {
			proposed := ed25519.NewKeyFromSeed(snapshot.RootSeed)
			if membership.EncodeKey(proposed.Public().(ed25519.PublicKey)) == sig.PublicKey {
				key = proposed
			}
		}
		if i.Kind == "root_transition" && sig.Role == "new_root" && len(i.Secret) == 32 {
			proposed := ed25519.NewKeyFromSeed(i.Secret)
			if membership.EncodeKey(proposed.Public().(ed25519.PublicKey)) != sig.PublicKey {
				return decStorageError()
			}
			key = proposed
		}
		if key == nil {
			continue
		}
		message := dec.SignatureMessage(statement.ID, sig.Role, sig.PublicKey)
		var signed string
		if sig.Format == "sshsig" {
			raw := ed25519.Sign(key, membership.SSHSIGSignedData(message))
			signed = base64.StdEncoding.EncodeToString(membership.SSHSIGBlob(key.Public().(ed25519.PublicKey), raw))
		} else {
			signed = base64.StdEncoding.EncodeToString(ed25519.Sign(key, message))
		}
		if e := addDecSignature(i, decIntentSignature{1, sig.Role, signed}); e != nil {
			return e
		}
	}
	return nil
}

func decCurrentIntentProvider(ctx context.Context, q dbQuerier, snapshot *decSnapshot, i decIntent) error {
	if i.Record.Provider.Kind == "device" {
		_, e := decOwnedDeviceSeed(ctx, q, i.Record.Provider.Signer)
		return e
	}
	if i.Record.Provider.Kind == "root" && i.Record.Provider.Format == "ed25519" && i.Record.Root != "-" {
		if len(snapshot.RootSeed) != 32 || membership.EncodeKey(ed25519.NewKeyFromSeed(snapshot.RootSeed).Public().(ed25519.PublicKey)) != i.Record.Provider.Signer {
			return decFailure("signer_unavailable")
		}
	}
	return nil
}

func validateDecActionResult(i decIntent, d dec.Descriptor) (json.RawMessage, error) {
	raw, e := decBytes(i.Record.Result, 32<<20)
	if e != nil {
		return nil, e
	}
	var result decActionResult
	if e = dec.ReadPrivateRecord(raw, "action_id review signing_requests statement_base64 proof_id catalog committed delivery", &result); e != nil {
		return nil, e
	}
	review, statement, body, e := readDecAction(i, d)
	if e != nil {
		return nil, e
	}
	a, _ := json.Marshal(review)
	b, _ := json.Marshal(result.Review)
	if i.Record.Terminal != "applied" || !i.Record.Completed || !result.Committed || result.ID != i.Record.Operation || len(result.Signing) != 0 || result.Signing == nil || !bytes.Equal(a, b) || result.Statement != base64.StdEncoding.EncodeToString(body) || result.Proof != dec.ProofID(statement.Kind, body) {
		return nil, decStorageError()
	}
	if _, e = dec.ReadStatement(d, body); e != nil {
		return nil, e
	}
	catalogRaw, e := json.Marshal(result.Catalog)
	if e != nil {
		return nil, e
	}
	c, e := dec.ReadCatalog(d, catalogRaw)
	if e != nil {
		return nil, e
	}
	found := false
	for _, object := range c.Objects {
		if object.ID == result.Proof && bytes.Equal(object.Body, body) {
			found = true
		}
	}
	if !found {
		return nil, decStorageError()
	}
	return json.RawMessage(raw), nil
}

func decUncommittedAction(i decIntent, review decActionReview, statement *dec.Statement, body []byte, delivery DecDeliveryView) (json.RawMessage, error) {
	requests, e := decActionSigning(i, statement, body)
	if e != nil {
		return nil, e
	}
	return json.Marshal(decActionResult{i.Record.Operation, review, requests, "-", "-", "-", false, delivery})
}

func (s *Store) completedDecActionRequest(ctx context.Context, q dbQuerier, id string, request DecActionRequest) (json.RawMessage, bool, error) {
	_, d, _, e := readDecNetwork(ctx, q, id, s.identity.PublicKey)
	if e != nil {
		return nil, false, e
	}
	payload, e := decBytes(request.Payload, dec.MaxPayload)
	if e != nil {
		return nil, false, decFailure("invalid")
	}
	statement, e := dec.ReadActionPayload(d, request.Kind, payload)
	if e != nil {
		return nil, false, e
	}
	providerID := request.Provider
	if providerID == "auto" {
		var kind, person, lease string
		e = q.QueryRowContext(ctx, `SELECT provider_kind,person_key,lease_id FROM dec_signers WHERE network_id=? AND context_id=?`, id, d.ContextID).Scan(&kind, &person, &lease)
		if errors.Is(e, sql.ErrNoRows) {
			return nil, false, nil
		}
		if e != nil {
			return nil, false, e
		}
		if kind == "original" {
			providerID = person
		} else if kind == "device" {
			providerID = lease
		} else {
			return nil, false, decStorageError()
		}
	}
	if request.Format != "auto" && request.Format != "ed25519" && request.Format != "sshsig" {
		return nil, false, decFailure("invalid")
	}
	if providerID != "network_root" && !dec.ValidPublicKey(providerID) && !dec.ValidID(providerID, "ds_") {
		return nil, false, decFailure("invalid")
	}
	i, e := findDecAction(ctx, q, id, dec.ActionID(d.ContextID, request.localKind(), statement.ID, providerID))
	if errors.Is(e, ErrNotFound) {
		return nil, false, nil
	}
	if e != nil {
		return nil, false, e
	}
	if request.Format != "auto" && i.Record.Provider.Format != request.Format {
		return nil, false, decFailure("operation_conflict")
	}
	if i.Record.Terminal != "applied" {
		return nil, false, nil
	}
	result, e := validateDecActionResult(i, d)
	return result, true, e
}

// Ordinary actions never use a candidate-provided prior marker. Preparation,
// signing and application each revalidate one coherent current private snapshot.
func (s *Store) PrepareDecentralizedAction(ctx context.Context, id string, request DecActionRequest) (json.RawMessage, error) {
	i, direct, facts, e := s.prepareDecActionIntent(ctx, id, request)
	if e != nil || direct != nil {
		return direct, e
	}
	if e = facts.wait(ctx); e != nil {
		return nil, e
	}
	if i.Record.Approved {
		// Consent and the fixed unsigned template are durable before any new owned
		// signature. A crash at approval cannot leave an unapproved signed object.
		i, direct, facts, e = s.persistDecActionSignatures(ctx, id, i.Record.Operation, DecSignatureBatch{Intent: i.ID, Signatures: []decIntentSignature{}})
		if e != nil || direct != nil {
			return direct, e
		}
		if e = facts.wait(ctx); e != nil {
			return nil, e
		}
	}
	return s.applyPreparedDecAction(ctx, i)
}

func (s *Store) prepareDecActionIntent(ctx context.Context, id string, request DecActionRequest) (decIntent, json.RawMessage, decCommittedFacts, error) {
	var i decIntent
	facts := decCommittedFacts{}
	s.syncing.Lock()
	defer s.syncing.Unlock()
	now, e := decNow()
	if e != nil {
		return i, nil, facts, e
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return i, nil, facts, e
	}
	defer tx.Rollback()
	if result, done, e := s.completedDecActionRequest(ctx, tx, id, request); e != nil || done {
		return i, result, facts, e
	}
	snapshot, e := s.loadDecSnapshot(ctx, tx, id)
	if e != nil {
		return i, nil, facts, e
	}
	p, e := verifyDecSnapshot(snapshot, linkTime(now))
	if e != nil {
		return i, nil, facts, e
	}
	view, provider, actor, firstBinding, e := decFirstBindingProvider(snapshot, p, request)
	if e == nil && !firstBinding {
		view, provider, actor, e = s.decActionProvider(ctx, tx, snapshot, p, request.Provider, request.Format)
	}
	if e != nil {
		return i, nil, facts, e
	}
	candidate, e := s.makeDecAction(snapshot, p, request, view, provider, actor, p.DecisionTime)
	if e != nil {
		return i, nil, facts, e
	}
	i, e = findDecAction(ctx, tx, id, candidate.Record.Operation)
	fresh := errors.Is(e, ErrNotFound)
	if fresh {
		if e = decIntentCapacity(ctx, tx); e != nil {
			return i, nil, facts, e
		}
		i = candidate
	} else if e != nil {
		return i, nil, facts, e
	} else {
		if len(i.Record.Templates) != 1 || i.Record.Templates[0].Template != candidate.Record.Templates[0].Template || i.Record.Provider != candidate.Record.Provider {
			return i, nil, facts, decFailure("operation_conflict")
		}
	}
	wasApproved, oldSignatures := i.Record.Approved, len(i.Record.Signatures)
	if request.Approve && !i.Record.Approved {
		i.Record.Approved = true
		i.Record.ApprovedAt = p.DecisionTime
	}
	_, statement, body, e := verifyDecAction(snapshot, i, p.DecisionTime)
	if e != nil {
		return i, nil, facts, e
	}
	if e = checkDecActionEditBoundary(ctx, tx, snapshot, statement, i.Kind == "action"); e != nil {
		return i, nil, facts, e
	}
	if i.Record.Approved {
		if e = decCurrentIntentProvider(ctx, tx, snapshot, i); e != nil {
			return i, nil, facts, e
		}
		if e = s.preflightDecActionOutbox(ctx, tx, snapshot, p, i, statement, body); e != nil {
			return i, nil, facts, e
		}
	}
	if e = storeDecIntent(ctx, tx, i, fresh); e != nil {
		return i, nil, facts, e
	}
	clock, _ := json.Marshal(decClockRecord{1, p.DecisionTime})
	if _, e = tx.ExecContext(ctx, `UPDATE dec_clock SET record=? WHERE network_id=?`, string(clock), id); e != nil {
		return i, nil, facts, e
	}
	if e = tx.Commit(); e != nil {
		return i, nil, facts, e
	}
	facts.operation = i.Record.Operation
	if fresh {
		facts.add("dec.intent.after_commit")
	}
	if i.Record.Approved && !wasApproved {
		facts.add("dec.approval.after_commit")
	}
	if len(i.Record.Signatures) > oldSignatures {
		facts.add("dec.signature.after_commit")
	}
	return i, nil, facts, nil
}

func (s *Store) applyPreparedDecAction(ctx context.Context, expected decIntent) (json.RawMessage, error) {
	if expected.Kind == "policy_claim" {
		return s.DecentralizedAction(ctx, expected.Network, expected.Record.Operation)
	}
	// Preparation and exact signature persistence are complete before this wait;
	// the final transaction acquires a new snapshot after concurrent changes.
	_, d, _, e := readDecNetwork(ctx, s.db, expected.Network, s.identity.PublicKey)
	if e != nil {
		return nil, e
	}
	_, statement, _, e := readDecAction(expected, d)
	if e != nil {
		return nil, e
	}
	if !expected.Record.Approved || !decActionComplete(statement) {
		return s.DecentralizedAction(ctx, expected.Network, expected.Record.Operation)
	}
	if e = decBarrier(ctx, "dec.apply.before_transaction", expected.Record.Operation); e != nil {
		return nil, e
	}
	facts := decCommittedFacts{operation: expected.Record.Operation}
	result, e := func() (json.RawMessage, error) {
		s.syncing.Lock()
		defer s.syncing.Unlock()
		tx, e := s.db.BeginTx(ctx, nil)
		if e != nil {
			return nil, e
		}
		defer tx.Rollback()
		i, e := readDecIntent(ctx, tx, expected.ID)
		if e != nil {
			return nil, e
		}
		if i.Network != expected.Network || i.Context != expected.Context || i.Record.Operation != expected.Record.Operation {
			return nil, decFailure("operation_conflict")
		}
		before, current := expected.Record, i.Record
		before.Signatures, current.Signatures = []decIntentSignature{}, []decIntentSignature{}
		before.ApprovedAt, current.ApprovedAt = "-", "-"
		before.Approved, current.Approved = false, false
		before.Completed, current.Completed = false, false
		before.Terminal, current.Terminal = "-", "-"
		before.Result, current.Result = "-", "-"
		beforeRaw, _ := json.Marshal(before)
		currentRaw, _ := json.Marshal(current)
		if !bytes.Equal(beforeRaw, currentRaw) {
			return nil, decFailure("operation_conflict")
		}
		for _, signature := range expected.Record.Signatures {
			if decSlotSignature(i, signature.Slot, signature.Role) != signature.Signature {
				return nil, decFailure("operation_conflict")
			}
		}
		if expected.Record.Approved && !i.Record.Approved {
			return nil, decFailure("state_conflict")
		}
		if i.Record.Terminal == "applied" {
			return validateDecActionResult(i, d)
		}
		snapshot, e := s.loadDecSnapshot(ctx, tx, i.Network)
		if e != nil {
			return nil, e
		}
		now, e := decNow()
		if e != nil {
			return nil, e
		}
		review, _, _, e := verifyDecAction(snapshot, i, linkTime(now))
		if e != nil {
			return nil, e
		}
		if e = decCurrentIntentProvider(ctx, tx, snapshot, i); e != nil {
			return nil, e
		}
		result, e := s.finishDecAction(ctx, tx, snapshot, i, linkTime(now), review)
		if e != nil {
			return nil, e
		}
		if e = tx.Commit(); e != nil {
			return nil, e
		}
		facts.add("dec.apply.after_commit")
		return result, nil
	}()
	if e != nil {
		return nil, e
	}
	if e = facts.wait(ctx); e != nil {
		return nil, e
	}
	return result, nil
}

func (s *Store) DecentralizedAction(ctx context.Context, id, operation string) (json.RawMessage, error) {
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	i, e := findDecAction(ctx, tx, id, operation)
	if e != nil {
		return nil, e
	}
	if i.Record.Terminal == "applied" {
		_, d, _, e := readDecNetwork(ctx, tx, id, s.identity.PublicKey)
		if e != nil {
			return nil, e
		}
		return validateDecActionResult(i, d)
	}
	snapshot, e := s.loadDecSnapshot(ctx, tx, id)
	if e != nil {
		return nil, e
	}
	if i.Kind == "policy_claim" && i.Record.Completed {
		review, statement, body, e := readDecAction(i, snapshot.Descriptor)
		if e != nil {
			return nil, e
		}
		return decFinishedClaim(snapshot, i, review, statement, body)
	}
	now, e := decNow()
	if e != nil {
		return nil, e
	}
	review, statement, body, e := verifyDecAction(snapshot, i, linkTime(now))
	if e != nil {
		return nil, e
	}
	if e = checkDecActionEditBoundary(ctx, tx, snapshot, statement, i.Kind == "action"); e != nil {
		return nil, e
	}
	return decUncommittedAction(i, review, statement, body, snapshot.Delivery)
}
func (s *Store) SignedDecentralizedAction(ctx context.Context, id, operation string, input DecSignatureBatch) (json.RawMessage, error) {
	if e := validateDecSignatureBatch(input); e != nil {
		return nil, e
	}
	i, direct, facts, e := s.persistDecActionSignatures(ctx, id, operation, input)
	if e != nil || direct != nil {
		return direct, e
	}
	if e = facts.wait(ctx); e != nil {
		return nil, e
	}
	return s.applyPreparedDecAction(ctx, i)
}
func (s *Store) persistDecActionSignatures(ctx context.Context, id, operation string, input DecSignatureBatch) (decIntent, json.RawMessage, decCommittedFacts, error) {
	var i decIntent
	facts := decCommittedFacts{}
	s.syncing.Lock()
	defer s.syncing.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return i, nil, facts, e
	}
	defer tx.Rollback()
	i, e = findDecAction(ctx, tx, id, operation)
	if e != nil {
		return i, nil, facts, e
	}
	if i.Kind == "policy_claim" && i.Record.Completed {
		snapshot, e := s.loadDecSnapshot(ctx, tx, id)
		if e != nil {
			return i, nil, facts, e
		}
		if e = acceptDecActionSignatures(snapshot.Descriptor, &i, input); e != nil {
			return i, nil, facts, e
		}
		review, statement, body, e := readDecAction(i, snapshot.Descriptor)
		if e != nil {
			return i, nil, facts, e
		}
		result, e := decFinishedClaim(snapshot, i, review, statement, body)
		return i, result, facts, e
	}
	if i.Record.Terminal == "applied" {
		_, d, _, e := readDecNetwork(ctx, tx, id, s.identity.PublicKey)
		if e != nil {
			return i, nil, facts, e
		}
		if e = acceptDecActionSignatures(d, &i, input); e != nil {
			return i, nil, facts, e
		}
		result, e := validateDecActionResult(i, d)
		return i, result, facts, e
	}
	snapshot, e := s.loadDecSnapshot(ctx, tx, id)
	if e != nil {
		return i, nil, facts, e
	}
	now, e := decNow()
	if e != nil {
		return i, nil, facts, e
	}
	_, statement, body, e := verifyDecAction(snapshot, i, linkTime(now))
	if e != nil {
		return i, nil, facts, e
	}
	if e = checkDecActionEditBoundary(ctx, tx, snapshot, statement, i.Kind == "action"); e != nil {
		return i, nil, facts, e
	}
	if e = decCurrentIntentProvider(ctx, tx, snapshot, i); e != nil {
		return i, nil, facts, e
	}
	if !i.Record.Approved {
		return i, nil, facts, decFailure("review_required")
	}
	p, e := verifyDecSnapshot(snapshot, linkTime(now))
	if e != nil {
		return i, nil, facts, e
	}
	if e = s.preflightDecActionOutbox(ctx, tx, snapshot, p, i, statement, body); e != nil {
		return i, nil, facts, e
	}
	oldSignatures := len(i.Record.Signatures)
	if e = acceptDecActionSignatures(snapshot.Descriptor, &i, input); e != nil {
		return i, nil, facts, e
	}
	if e = s.signDecActionOwned(ctx, tx, snapshot, &i, statement); e != nil {
		return i, nil, facts, e
	}
	if e = storeDecIntent(ctx, tx, i, false); e != nil {
		return i, nil, facts, e
	}
	clock, _ := json.Marshal(decClockRecord{1, p.DecisionTime})
	if _, e = tx.ExecContext(ctx, `UPDATE dec_clock SET record=? WHERE network_id=?`, string(clock), id); e != nil {
		return i, nil, facts, e
	}
	if e = tx.Commit(); e != nil {
		return i, nil, facts, e
	}
	facts.operation = operation
	if len(i.Record.Signatures) > oldSignatures {
		facts.add("dec.signature.after_commit")
	}
	return i, nil, facts, nil
}

func (s *Store) finishDecAction(ctx context.Context, tx *sql.Tx, snapshot *decSnapshot, i decIntent, now string, review decActionReview) (json.RawMessage, error) {
	current, e := decNow()
	if e != nil {
		return nil, e
	}
	now = linkTime(current)
	_, statement, body, e := verifyDecAction(snapshot, i, now)
	if e != nil {
		return nil, e
	}
	if e = checkDecActionEditBoundary(ctx, tx, snapshot, statement, i.Kind == "action"); e != nil {
		return nil, e
	}
	if !i.Record.Approved || !decActionComplete(statement) {
		decision, e := dec.DecisionTime(now, snapshot.Prior.ClockGuard)
		if e != nil {
			return nil, e
		}
		clock, _ := json.Marshal(decClockRecord{1, decision})
		if _, e = tx.ExecContext(ctx, `UPDATE dec_clock SET record=? WHERE network_id=?`, string(clock), snapshot.Descriptor.NetworkID); e != nil {
			return nil, e
		}
		return decUncommittedAction(i, review, statement, body, snapshot.Delivery)
	}
	candidate, e := decActionCandidate(snapshot.Descriptor, statement, body)
	if e != nil {
		return nil, e
	}
	p, e := dec.Project(snapshot.Descriptor, snapshot.PriorRaw, candidate, now, "fresh")
	if e != nil {
		return nil, e
	}
	next, e := p.AdmittedPrior()
	if e != nil {
		return nil, e
	}
	admitted := decSet(next.AdmittedStatements)
	for _, id := range next.AdmittedRestrictions {
		admitted[id] = true
	}
	if !admitted[statement.ID] {
		return nil, decFailure("forbidden")
	}
	plan, e := s.planDecProofs(ctx, tx, snapshot, p)
	if e != nil {
		return nil, e
	}
	if e = s.storeDecProjection(ctx, tx, snapshot, p); e != nil {
		return nil, e
	}
	if e = s.settleDecPolicyEdits(ctx, tx, snapshot, statement, p.DecisionTime, i.Kind == "action"); e != nil {
		return nil, e
	}
	if e = plan.store(ctx, tx); e != nil {
		return nil, e
	}
	event := "network.statement_applied"
	if statement.Root != nil {
		if p.Root.Code != "-" || p.Root.SelectedID != statement.ID {
			return nil, decFailure("state_conflict")
		}
		var seed any
		if i.Secret != nil {
			seed = i.Secret
		}
		if _, e = tx.ExecContext(ctx, `UPDATE networks SET root_seed=? WHERE id=?`, seed, i.Network); e != nil {
			return nil, e
		}
		event = "network.root_rotated"
	}
	if e = appendEvent(ctx, tx, event, statement.ID, p.DecisionTime); e != nil {
		return nil, e
	}
	stored, e := s.loadDecSnapshot(ctx, tx, snapshot.Descriptor.NetworkID)
	if e != nil {
		return nil, e
	}
	catalogRaw, e := decBytes(next.CatalogBase64, dec.MaxCatalog)
	if e != nil {
		return nil, e
	}
	result, e := json.Marshal(decActionResult{i.Record.Operation, review, []DecSigningRequest{}, base64.StdEncoding.EncodeToString(body), dec.ProofID(statement.Kind, body), json.RawMessage(catalogRaw), true, stored.Delivery})
	if e != nil {
		return nil, e
	}
	if len(result) > 32<<20 {
		return nil, decFailure("quota_exceeded")
	}
	i.Record.Completed = true
	i.Record.Terminal = "applied"
	i.Record.Result = base64.StdEncoding.EncodeToString(result)
	i.Secret = nil
	if _, e = validateDecActionResult(i, snapshot.Descriptor); e != nil {
		return nil, e
	}
	if e = storeDecIntent(ctx, tx, i, false); e != nil {
		return nil, e
	}
	return json.RawMessage(result), nil
}

// Pre-sign accounting uses the fixed-length encoding of each declared Ed25519
// or SSHSIG signature, without producing a signature or treating it as evidence.
// The final signed projection and exact budget are independently rechecked.
func (s *Store) preflightDecActionOutbox(ctx context.Context, q dbQuerier, snapshot *decSnapshot, p *dec.Projection, i decIntent, statement *dec.Statement, body []byte) error {
	if p == nil {
		return decStorageError()
	}
	held, e := heldDecDeliveries(ctx, q)
	if e != nil {
		return e
	}
	// Strict Ed25519/SSHSIG framing fixes every signature's encoded length.
	// Size the exact stored template, preserving cross-language whitespace and
	// key order; these zero bytes are accounting only, never parsed as proof.
	size := len(body)
	for _, sig := range statement.Signatures {
		if sig.Signature != "-" {
			continue
		}
		raw := make([]byte, 64)
		if sig.Format == "sshsig" {
			key, e := membership.DecodeKey(sig.PublicKey)
			if e != nil {
				return e
			}
			raw = membership.SSHSIGBlob(key, raw)
		}
		size += base64.StdEncoding.EncodedLen(len(raw)) - 1
	}
	if size > dec.MaxObject {
		return decFailure("quota_exceeded")
	}
	sized := make([]byte, size)
	objects := append([]dec.CatalogObject{}, snapshot.Catalog.Objects...)
	placeholder := dec.ProofID(statement.Kind, sized)
	objects = append(objects, dec.CatalogObject{ID: placeholder, Kind: statement.Kind, BodyBase64: base64.StdEncoding.EncodeToString(sized)})
	if len(objects) > dec.MaxObjects {
		return decFailure("quota_exceeded")
	}
	sort.Slice(objects, func(a, b int) bool { return objects[a].ID < objects[b].ID })
	catalog, e := json.Marshal(struct {
		Format  uint64              `json:"format"`
		Context string              `json:"context_id"`
		Objects []dec.CatalogObject `json:"objects"`
	}{1, snapshot.Descriptor.ContextID, objects})
	if e != nil {
		return e
	}
	if len(catalog) > dec.MaxCatalog {
		return decFailure("quota_exceeded")
	}
	decoded := len(sized)
	for _, object := range snapshot.Catalog.Objects {
		decoded += len(object.Body)
	}
	if decoded > 8<<20 {
		return decFailure("quota_exceeded")
	}
	publication, e := json.Marshal(struct {
		Catalog json.RawMessage `json:"catalog"`
	}{json.RawMessage(catalog)})
	if e != nil {
		return e
	}
	if len(publication) > 20<<20 {
		return decFailure("quota_exceeded")
	}
	proofs := []string{}
	for _, object := range objects {
		proofs = append(proofs, object.ID)
	}
	heldProofs := decSet(proofs)
	targets := map[string]bool{}
	for _, member := range decMemberViews(p) {
		if member.Host != s.identity.PublicKey {
			targets[member.Host] = true
		}
	}
	if statement.Kind == "host_lease" && statement.Lease.Subject.Host != s.identity.PublicKey {
		targets[statement.Lease.Subject.Host] = true
	}
	if statement.Root != nil {
		// A fork suppresses positive membership views. Size a conservative bound
		// for every already-admitted host that resolution could preserve, rather
		// than treating a currently empty view as zero prospective deliveries.
		for _, id := range snapshot.Prior.AdmittedStatements {
			if host := snapshot.Catalog.Statements[id]; host != nil && host.Kind == "host_lease" && host.Lease.Subject.Host != s.identity.PublicKey {
				targets[host.Lease.Subject.Host] = true
			}
		}
	}
	retired := map[string]bool{}
	for _, row := range held {
		if row.Network == snapshot.Descriptor.NetworkID && row.Context == snapshot.Descriptor.ContextID && targets[row.Target] && row.Record.Kind == "proofs" {
			for _, proof := range row.Record.Proofs {
				if !heldProofs[proof] {
					return decFailure("proof_required", proof)
				}
			}
			var previous struct {
				Catalog json.RawMessage `json:"catalog"`
			}
			if e = dec.ReadPrivateRecord(row.Body, "catalog", &previous); e != nil {
				return e
			}
			old, e := dec.ReadCatalog(snapshot.Descriptor, previous.Catalog)
			if e != nil {
				return e
			}
			for _, proof := range old.ProofIDs() {
				if !heldProofs[proof] {
					return decFailure("proof_required", proof)
				}
			}
			retired[row.ID] = true
		}
	}
	added := []decHeldDelivery{}
	for _, target := range decSorted(targets) {
		record := decDeliveryRecord{1, "proofs", base64.StdEncoding.EncodeToString(publication), proofs, p.DecisionTime, 0, p.DecisionTime, "-", "-"}
		raw, e := json.Marshal(record)
		if e != nil {
			return e
		}
		if len(raw) > dec.MaxPrivateRecord {
			return decFailure("quota_exceeded")
		}
		added = append(added, decHeldDelivery{Target: target, Raw: string(raw), Body: publication})
	}
	return checkDecDeliveryBudget(held, added, retired)
}

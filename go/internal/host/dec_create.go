package host

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/membership"
)

type DecCreateNetwork struct {
	Name    string `json:"name"`
	Member  string `json:"member"`
	Person  string `json:"person_public_key"`
	Approve bool   `json:"approve"`
}
type decCreationReview struct {
	Name       string          `json:"name"`
	Member     string          `json:"member"`
	Descriptor json.RawMessage `json:"descriptor"`
	Root       string          `json:"root_state_id"`
	Person     string          `json:"person_public_key"`
	Host       string          `json:"host_public_key"`
	NotAfter   string          `json:"not_after"`
	Warning    string          `json:"authority_warning"`
}
type decCreationResult struct {
	ID        string              `json:"creation_id"`
	Review    decCreationReview   `json:"review"`
	Signing   []DecSigningRequest `json:"signing_requests"`
	Network   *DecNetworkView     `json:"network"`
	Committed bool                `json:"committed"`
}

func decPublicOperation(prefix string) (string, error) {
	var bytes [32]byte
	if _, e := rand.Read(bytes[:]); e != nil {
		return "", e
	}
	return prefix + hex.EncodeToString(bytes[:]), nil
}
func (s *Store) makeDecCreation(request DecCreateNetwork, root ed25519.PrivateKey, now time.Time) (decIntent, dec.Descriptor, error) {
	var intent decIntent
	if !membership.ValidLabel(request.Name) || !membership.ValidLabel(request.Member) || !dec.ValidPublicKey(request.Person) {
		return intent, dec.Descriptor{}, decFailure("invalid")
	}
	raw, e := json.Marshal(dec.Descriptor{Format: 1, Protocol: dec.Protocol, NetworkID: membership.NetworkID(root.Public().(ed25519.PublicKey)), Name: request.Name, GenesisRootPublicKey: membership.EncodeKey(root.Public().(ed25519.PublicKey))})
	if e != nil {
		return intent, dec.Descriptor{}, e
	}
	d, e := dec.ReadDescriptor(raw)
	if e != nil {
		return intent, d, e
	}
	created := linkTime(now)
	after := linkTime(now.Add(7 * 24 * time.Hour))
	host := s.identity.PublicKey
	templates := []decIntentTemplate{}
	appendTemplate := func(kind string, payload any, signatures []dec.Signature) (*dec.Statement, error) {
		body, e := json.Marshal(payload)
		if e != nil {
			return nil, e
		}
		raw, e := dec.StatementTemplate(d, kind, body, signatures)
		if e != nil {
			return nil, e
		}
		statement, e := dec.ReadStatementTemplate(d, raw)
		if e != nil {
			return nil, e
		}
		templates = append(templates, decIntentTemplate{uint64(len(templates) + 1), kind, base64.StdEncoding.EncodeToString(raw)})
		return statement, nil
	}
	rootSignature := dec.Signature{Role: "issuer", PublicKey: d.GenesisRootPublicKey, Format: "ed25519", Signature: "-"}
	hostSignature := dec.Signature{Role: "host", PublicKey: host, Format: "ed25519", Signature: "-"}
	ownerSignature := dec.Signature{Role: "issuer", PublicKey: request.Person, Format: "sshsig", Signature: "-"}
	r, e := appendTemplate("root_state", dec.RootState{Epoch: 0, Predecessors: []string{}, Resolves: []string{}, Migration: "-", Key: d.GenesisRootPublicKey, Issued: created, Retained: []string{}}, []dec.Signature{rootSignature})
	if e != nil {
		return intent, d, e
	}
	rootIssuer := dec.Issuer{Kind: "root", Person: "-"}
	personIssuer := dec.Issuer{Kind: "person", Person: request.Person}
	lease := func(subject dec.Subject, issuer dec.Issuer, parents []dec.Parent) dec.Lease {
		return dec.Lease{Root: r.ID, Operation: "-", Sequence: 1, Predecessors: []string{}, Resolves: []string{}, Retained: []string{}, Subject: subject, Issuer: issuer, Parents: parents, Issued: created, Before: created, After: after}
	}
	if _, e = appendTemplate("admin_lease", lease(dec.Subject{Person: request.Person, Host: "-", Device: "-", Member: "-", Scopes: 8}, rootIssuer, []dec.Parent{}), []dec.Signature{rootSignature}); e != nil {
		return intent, d, e
	}
	p, e := appendTemplate("person_lease", lease(dec.Subject{Person: request.Person, Host: "-", Device: "-", Member: request.Member, Scopes: 0}, rootIssuer, []dec.Parent{}), []dec.Signature{rootSignature})
	if e != nil {
		return intent, d, e
	}
	h, e := appendTemplate("host_lease", lease(dec.Subject{Person: "-", Host: host, Device: "-", Member: request.Member, Scopes: 0}, rootIssuer, []dec.Parent{}), []dec.Signature{hostSignature, rootSignature})
	if e != nil {
		return intent, d, e
	}
	if _, e = appendTemplate("binding_lease", lease(dec.Subject{Person: request.Person, Host: host, Device: "-", Member: "-", Scopes: 2}, personIssuer, []dec.Parent{{Role: "issuer_person", ID: p.ID}, {Role: "subject_host", ID: h.ID}, {Role: "subject_person", ID: p.ID}}), []dec.Signature{hostSignature, ownerSignature}); e != nil {
		return intent, d, e
	}
	policyAfter := linkTime(now.Add(24 * time.Hour))
	policyBody, e := json.Marshal(map[string]any{"format": 2, "network_id": d.NetworkID, "person_public_key": request.Person, "version": uint64(1), "issued_at": created, "valid_until": policyAfter, "rules": []membership.PolicyRule{}, "capability_rules": []membership.CapabilityRule{}, "trusted_hosts": []string{}, "edits": []membership.PolicyEdit{}})
	if e != nil {
		return intent, d, e
	}
	policy := dec.Access{Root: r.ID, Operation: "-", Sequence: 1, Predecessors: []string{}, Resolves: []string{}, Issuer: personIssuer, Parents: []dec.Parent{{Role: "issuer_person", ID: p.ID}}, Issued: created, Before: created, After: policyAfter, BodyBase64: base64.StdEncoding.EncodeToString(policyBody)}
	if _, e = appendTemplate("policy", policy, []dec.Signature{ownerSignature}); e != nil {
		return intent, d, e
	}
	id, e := decRandomID("dint_")
	if e != nil {
		return intent, d, e
	}
	operation, e := decPublicOperation("create_")
	if e != nil {
		return intent, d, e
	}
	review := decCreationReview{request.Name, request.Member, json.RawMessage(d.Raw), r.ID, request.Person, host, after, "Creator authority uses hard seven-day parent leases; policies last at most 24 hours. Keep the original owner key on this machine for explicit renewal. Additional machines use reviewed device linking."}
	reviewRaw, e := json.Marshal(review)
	if e != nil {
		return intent, d, e
	}
	approvedAt := "-"
	if request.Approve {
		approvedAt = created
	}
	intent = decIntent{ID: id, Network: d.NetworkID, Context: d.ContextID, Kind: "create", Secret: root.Seed(), Record: decIntentRecord{Format: 1, Operation: operation, Approved: request.Approve, ApprovedAt: approvedAt, Review: base64.StdEncoding.EncodeToString(reviewRaw), Provider: decIntentProvider{"original", request.Person, "sshsig", "-"}, Root: r.ID, Person: request.Person, Host: host, Device: "-", Scopes: 15, NotAfter: after, Created: created, Expires: linkTime(now.Add(300 * time.Second)), Templates: templates, Signatures: []decIntentSignature{}, Completed: false, Terminal: "-", Result: "-"}}
	if e = validateDecIntent(&intent.Record); e != nil {
		return intent, d, e
	}
	return intent, d, nil
}
func decCreationDescriptor(i decIntent) (dec.Descriptor, decCreationReview, error) {
	var review decCreationReview
	raw, e := decBytes(i.Record.Review, 1<<20)
	if e != nil {
		return dec.Descriptor{}, review, e
	}
	if e = dec.ReadPrivateRecord(raw, "name member descriptor root_state_id person_public_key host_public_key not_after authority_warning", &review); e != nil {
		return dec.Descriptor{}, review, e
	}
	d, e := dec.ReadDescriptor(review.Descriptor)
	if e != nil {
		return d, review, e
	}
	if i.Kind != "create" || d.NetworkID != i.Network || d.ContextID != i.Context || !dec.ValidID(i.Record.Operation, "create_") || review.Name != d.Name || !membership.ValidLabel(review.Member) || review.Root != i.Record.Root || review.Person != i.Record.Person || review.Host != i.Record.Host || review.NotAfter != i.Record.NotAfter || review.Warning == "" || len(review.Warning) > 1024 {
		return d, review, decStorageError()
	}
	return d, review, nil
}
func (s *Store) checkDecCreation(i decIntent, now string) (dec.Descriptor, decCreationReview, []*dec.Statement, [][]byte, error) {
	d, review, e := decCreationDescriptor(i)
	if e != nil {
		return d, review, nil, nil, e
	}
	if i.Record.Host != s.identity.PublicKey || i.Record.Device != "-" || i.Record.Provider.Kind != "original" || i.Record.Provider.Signer != review.Person {
		return d, review, nil, nil, decStorageError()
	}
	statements, bodies, e := decIntentStatements(d, i)
	if e != nil {
		return d, review, nil, nil, e
	}
	if e = dec.CheckLocalGenesisTemplates(d, bodies, review.Person, review.Host, review.Member, now); e != nil {
		return d, review, nil, nil, e
	}
	if len(statements) != 6 || statements[0].Kind != "root_state" || statements[0].ID != review.Root {
		return d, review, nil, nil, decStorageError()
	}
	if i.Record.Terminal != "applied" {
		if len(i.Secret) != ed25519.SeedSize {
			return d, review, nil, nil, decStorageError()
		}
		key := ed25519.NewKeyFromSeed(i.Secret)
		if membership.EncodeKey(key.Public().(ed25519.PublicKey)) != d.GenesisRootPublicKey {
			return d, review, nil, nil, decStorageError()
		}
	}
	return d, review, statements, bodies, nil
}
func (s *Store) signDecCreationOwned(i *decIntent, now string) error {
	d, _, statements, _, e := s.checkDecCreation(*i, now)
	if e != nil {
		return e
	}
	if !i.Record.Approved {
		return nil
	}
	if i.Record.Terminal != "-" {
		return decFailure("state_conflict")
	}
	complete := true
	for _, statement := range statements {
		if !decActionComplete(statement) {
			complete = false
		}
	}
	if complete {
		return nil
	}
	if e = decCreationApprovalCurrent(*i, now); e != nil {
		return e
	}
	root := ed25519.NewKeyFromSeed(i.Secret)
	for index, statement := range statements {
		for _, signature := range statement.Signatures {
			if signature.Signature != "-" {
				continue
			}
			var key ed25519.PrivateKey
			if signature.PublicKey == s.identity.PublicKey && signature.Format == "ed25519" && signature.Role == "host" {
				key = s.privateKey
			}
			if signature.PublicKey == d.GenesisRootPublicKey && signature.Format == "ed25519" && signature.Role == "issuer" {
				key = root
			}
			if key == nil {
				continue
			}
			signed := base64.StdEncoding.EncodeToString(ed25519.Sign(key, dec.SignatureMessage(statement.ID, signature.Role, signature.PublicKey)))
			if e = addDecSignature(i, decIntentSignature{uint64(index + 1), signature.Role, signed}); e != nil {
				return e
			}
		}
	}
	return nil
}
func (s *Store) decCreationSigning(i decIntent, now string) ([]DecSigningRequest, error) {
	requests := []DecSigningRequest{}
	_, _, statements, bodies, e := s.checkDecCreation(i, now)
	if e != nil {
		return nil, e
	}
	if !i.Record.Approved || i.Record.Terminal != "-" {
		return requests, nil
	}
	allComplete := true
	for _, statement := range statements {
		if !decActionComplete(statement) {
			allComplete = false
		}
	}
	if allComplete {
		return requests, nil
	}
	if e = decCreationApprovalCurrent(i, now); e != nil {
		return nil, e
	}
	complete := map[string]bool{}
	for _, statement := range statements {
		filled := true
		for _, signature := range statement.Signatures {
			if signature.Signature == "-" {
				filled = false
			}
		}
		complete[statement.ID] = filled
	}
	for index, statement := range statements {
		ready := true
		rootID := ""
		if statement.Lease != nil {
			rootID = statement.Lease.Root
			for _, parent := range statement.Lease.Parents {
				if !complete[parent.ID] {
					ready = false
				}
			}
		}
		if statement.Access != nil {
			rootID = statement.Access.Root
			for _, parent := range statement.Access.Parents {
				if !complete[parent.ID] {
					ready = false
				}
			}
		}
		if rootID != "" && !complete[rootID] {
			ready = false
		}
		if !ready {
			continue
		}
		for _, signature := range statement.Signatures {
			if signature.Signature != "-" {
				continue
			}
			if signature.PublicKey != i.Record.Person || signature.Format != "sshsig" || signature.Role != "issuer" {
				return nil, decStorageError()
			}
			requests = append(requests, DecSigningRequest{i.ID, uint64(index + 1), statement.Kind, statement.ID, signature.Role, signature.PublicKey, signature.Format, base64.StdEncoding.EncodeToString(bodies[index]), base64.StdEncoding.EncodeToString(dec.SignatureMessage(statement.ID, signature.Role, signature.PublicKey))})
		}
	}
	sort.Slice(requests, func(a, b int) bool {
		return requests[a].Slot < requests[b].Slot || requests[a].Slot == requests[b].Slot && requests[a].Role < requests[b].Role
	})
	if len(requests) > 16 {
		requests = requests[:16]
	}
	return requests, nil
}

// The explicit unchanged-CREATE approve route may refresh only this local
// consent timestamp. It never alters original templates, finite deadlines,
// initial expires_at, or the ordinary action/root signing window.
func decCreationApprovalCurrent(i decIntent, now string) error {
	if !i.Record.Approved || i.Record.ApprovedAt == "-" {
		return decFailure("review_required")
	}
	at, e := dec.ParseTime(now)
	if e != nil {
		return e
	}
	approved, e := dec.ParseTime(i.Record.ApprovedAt)
	if e != nil {
		return e
	}
	if at.Before(approved) {
		return decFailure("clock_rollback")
	}
	if at.Sub(approved) > 300*time.Second {
		return decFailure("review_required")
	}
	return nil
}

func decCreationHasCompleteSignatures(i decIntent) (bool, error) {
	d, _, e := decCreationDescriptor(i)
	if e != nil {
		return false, e
	}
	statements, _, e := decIntentStatements(d, i)
	if e != nil {
		return false, e
	}
	if len(statements) != 6 {
		return false, decStorageError()
	}
	for _, statement := range statements {
		if !decActionComplete(statement) {
			return false, nil
		}
	}
	return true, nil
}

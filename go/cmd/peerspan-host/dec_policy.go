package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"time"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/peerspan/peerspan/go/internal/person"
)

type decCLIPlanning struct {
	Network host.DecNetworkView      `json:"network"`
	Time    string                   `json:"decision_time"`
	Catalog json.RawMessage          `json:"catalog"`
	Streams []host.DecPlanningStream `json:"streams"`
}
type decPolicyEditor struct {
	planning   decCLIPlanning
	descriptor dec.Descriptor
	catalog    *dec.Catalog
	provider   host.DecProviderView
	providerID string
	keyPath    string
	current    *dec.Statement
	content    membership.PolicyBody
}

func decNetworkPath(network string) string { return "/v2/networks/" + url.PathEscape(network) }
func decEmptyContent() membership.PolicyBody {
	return membership.PolicyBody{Rules: []membership.PolicyRule{}, CapabilityRules: []membership.CapabilityRule{}, TrustedHosts: []string{}, Edits: []membership.PolicyEdit{}}
}
func decContent(statement *dec.Statement) (membership.PolicyBody, error) {
	if statement == nil {
		return decEmptyContent(), nil
	}
	var body host.DecPolicyContent
	if statement.Kind != "policy" || statement.Access == nil {
		return membership.PolicyBody{}, errors.New("invalid DEC policy reference")
	}
	raw, e := base64.StdEncoding.Strict().DecodeString(statement.Access.BodyBase64)
	if e != nil || json.Unmarshal(raw, &body) != nil {
		return membership.PolicyBody{}, errors.New("invalid DEC policy body")
	}
	return membership.CombineDuplicateRules(membership.PolicyBody{Rules: body.Rules, CapabilityRules: body.Capabilities, TrustedHosts: body.Trusted, Edits: body.Edits}), nil
}
func decStream(plan decCLIPlanning, kind, subject string) (host.DecPlanningStream, bool) {
	for _, stream := range plan.Streams {
		if stream.Kind == kind && stream.Subject == subject {
			return stream, true
		}
	}
	return host.DecPlanningStream{}, false
}
func decHead(plan decCLIPlanning, kind, subject string) (string, error) {
	stream, ok := decStream(plan, kind, subject)
	if !ok || len(stream.Heads) == 0 {
		return "-", nil
	}
	if len(stream.Heads) != 1 {
		return "", errors.New("state_conflict: resolve the exact DEC stream heads before signing")
	}
	return stream.Heads[0], nil
}
func (editor *decPolicyEditor) reload(ctx context.Context, client host.Client) error {
	plan, e := call[decCLIPlanning](ctx, client, "GET", decNetworkPath(editor.planning.Network.ID)+"/planning")
	if e != nil {
		return e
	}
	if plan.Network.ID != editor.planning.Network.ID || plan.Network.Context != editor.descriptor.ContextID || plan.Network.Person != editor.provider.Person || plan.Network.Host != editor.provider.Host {
		return errors.New("network identity changed; review the same network before signing")
	}
	catalog, e := dec.ReadCatalog(editor.descriptor, plan.Catalog)
	if e != nil {
		return e
	}
	editor.planning, editor.catalog = plan, catalog
	provider := plan.Network.Provider
	if editor.providerID != "auto" {
		preview, e := linkCall[struct {
			Provider *host.DecProviderView `json:"provider"`
		}](ctx, client, "POST", decNetworkPath(plan.Network.ID)+"/provider", host.DecSelectProvider{Provider: editor.providerID, Person: editor.provider.Person, Host: editor.provider.Host, Approve: false})
		if e != nil {
			return e
		}
		provider = preview.Provider
	} else if plan.Network.ProviderState.State != "available" {
		return fmt.Errorf("selected provider requires repair: %s", plan.Network.ProviderState.Code)
	}
	if provider == nil || provider.Person != editor.provider.Person || provider.Host != editor.provider.Host || provider.Scopes&1 == 0 {
		return errors.New("the exact selected provider cannot sign this person's policy")
	}
	if editor.providerID == "auto" && (provider.Kind != editor.provider.Kind || provider.Device != editor.provider.Device || provider.Lease != editor.provider.Lease && provider.Kind == "device") {
		return errors.New("provider selection changed; review it before signing")
	}
	editor.provider = *provider
	editor.current = nil
	id, e := decHead(plan, "policy", provider.Person)
	if e != nil {
		return e
	}
	if id != "-" {
		editor.current = catalog.Statements[id]
		if editor.current == nil {
			return errors.New("proof_required: exact current policy body is missing")
		}
		// The exact retained head is an unsigned edit/renewal baseline even when
		// inactive. Its old body supplies no execution or issuer authority.

	}
	editor.content, e = decContent(editor.current)
	return e
}
func tryDecOwner(ctx context.Context, client host.Client, network, keyPath string) (*ownerContext, bool, error) {
	networks, e := call[[]host.DecNetworkView](ctx, client, "GET", "/v2/networks")
	if e != nil {
		return nil, true, e
	}
	var selected *host.DecNetworkView
	for _, n := range networks {
		if n.ID == network || n.Name == network {
			copy := n
			selected = &copy
			break
		}
	}
	if selected == nil {
		return nil, false, nil
	}
	if selected.Authority.State != "usable" || selected.Person == "-" {
		return nil, true, fmt.Errorf("network authority requires repair: %s", selected.Authority.State)
	}
	d, e := decLinkDescriptor(*selected)
	if e != nil {
		return nil, true, e
	}
	providerID := "auto"
	var signer person.Signer
	if keyPath != "" {
		signer, e = person.Load(keyPath)
		if e != nil {
			return nil, true, e
		}
		providerID = membership.EncodeKey(signer.PublicKey())
		if providerID != selected.Person {
			_ = signer.Close()
			return nil, true, errors.New("the explicit original key does not match this machine's bound person")
		}
	}
	provider := selected.Provider
	if keyPath != "" {
		preview, err := linkCall[struct {
			Provider *host.DecProviderView `json:"provider"`
		}](ctx, client, "POST", decNetworkPath(selected.ID)+"/provider", host.DecSelectProvider{Provider: providerID, Person: selected.Person, Host: selected.Host, Approve: false})
		if err != nil {
			_ = signer.Close()
			return nil, true, err
		}
		provider = preview.Provider
	}
	if provider == nil {
		if signer != nil {
			_ = signer.Close()
		}
		return nil, true, errors.New("choose an explicit current policy provider; no original-key fallback is inferred")
	}
	public, e := membership.DecodeKey(selected.Person)
	if e != nil {
		if signer != nil {
			_ = signer.Close()
		}
		return nil, true, e
	}
	editor := &decPolicyEditor{planning: decCLIPlanning{Network: *selected}, descriptor: d, provider: *provider, providerID: providerID, keyPath: keyPath}
	o := &ownerContext{signer: signer, dec: editor, ownerKey: selected.Person, ownerID: membership.PersonID(public), network: selected.ID}
	identity, e := call[host.Identity](ctx, client, "GET", "/v1/host")
	if e == nil {
		o.hostID = identity.ID
		e = editor.reload(ctx, client)
	}
	if e == nil {
		o.persons, e = decPersons(ctx, client, editor)
	}
	if e != nil {
		o.close()
		return nil, true, e
	}
	return o, true, nil
}

// This converts verified public identity facts for existing CLI principal
// resolution only. It supplies no grant, policy signature or selected provider.
func decPersons(ctx context.Context, client host.Client, editor *decPolicyEditor) ([]host.Person, error) {
	return decCurrentPeople(ctx, client, editor.planning.Network)
}
func (o *ownerContext) policyView() any {
	if o.dec != nil {
		if o.dec.current != nil {
			return json.RawMessage(o.dec.current.Raw)
		}
		return nil
	}
	if o.current == nil {
		return nil
	}
	return o.current
}

// Called only by a mutating command, before its change closure/body is built.
// Pure reads and preflights never use this signing path.
func (o *ownerContext) decReapplyBeforeMutation(ctx context.Context, client host.Client) error {
	if o.dec == nil {
		return nil
	}
	editor := o.dec
	if e := editor.reload(ctx, client); e != nil {
		return e
	}
	raw, e := client.Call(ctx, "POST", decNetworkPath(o.network)+"/policy-edits/reapply-preview", map[string]string{"provider_id": editor.providerID})
	if e != nil {
		return e
	}
	var preview host.DecPolicyReapplyPreview
	if dec.ReadPrivateRecord(raw, "context_id person_public_key host_public_key provider payload_base64 unsettled_seqs", &preview) != nil || preview.Unsettled == nil {
		return errors.New("invalid exact policy reapplication preview")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || dec.ReadPrivateRecord(fields["provider"], "kind person_public_key host_public_key device_public_key lease_id root_state_id scopes not_after", &preview.Provider) != nil {
		return errors.New("invalid exact policy provider preview")
	}
	provider := preview.Provider
	if preview.Context != editor.descriptor.ContextID || preview.Person != o.ownerKey || preview.Host != editor.provider.Host || provider.Person != o.ownerKey || provider.Host != preview.Host || provider.Scopes&1 == 0 || provider.Scopes > 15 || provider.Kind != editor.provider.Kind || provider.Device != editor.provider.Device || provider.Lease != editor.provider.Lease || provider.Root != editor.provider.Root {
		return errors.New("policy reapplication changed the exact owner/provider; review current state")
	}
	for i, seq := range preview.Unsettled {
		if seq <= 0 || i > 0 && preview.Unsettled[i-1] >= seq {
			return errors.New("invalid unsettled policy sequence list")
		}
	}
	if len(preview.Unsettled) == 0 {
		if preview.Payload != "-" {
			return errors.New("unexpected reapplication without an unsettled edit")
		}
		return nil
	}
	if len(preview.Payload) > base64.StdEncoding.EncodedLen(dec.MaxPayload) {
		return errors.New("quota_exceeded: policy reapplication payload")
	}
	payload, e := base64.StdEncoding.Strict().DecodeString(preview.Payload)
	if e != nil || len(payload) > dec.MaxPayload || base64.StdEncoding.EncodeToString(payload) != preview.Payload {
		return errors.New("invalid policy reapplication payload encoding")
	}
	fixed, e := dec.ReadActionPayload(editor.descriptor, "policy", payload)
	if e != nil {
		return e
	}
	body, e := decContent(fixed)
	if e != nil {
		return e
	}
	stream, _ := decStream(editor.planning, "policy", o.ownerKey)
	pred, _ := json.Marshal(fixed.Access.Predecessors)
	heads, _ := json.Marshal(append([]string{}, stream.Heads...))
	if stream.Version == ^uint64(0) || fixed.Access.Sequence != stream.Version+1 || fixed.Access.Root != provider.Root || !bytes.Equal(pred, heads) || len(fixed.Access.Resolves) != 0 || decOwnEdit(body, o.hostID) != preview.Unsettled[len(preview.Unsettled)-1] {
		return errors.New("policy reapplication changes current generation or frozen edit sequence")
	}
	concrete := provider.Person
	if provider.Kind == "device" {
		concrete = provider.Lease
	} else if provider.Kind != "original_person" {
		return errors.New("policy reapplication requires the exact owner provider")
	}
	if _, e = o.decSubmitPolicyPayload(ctx, client, payload, "", concrete); e != nil {
		return e
	}
	// Only actual application can establish the next command's baseline.
	return editor.reload(ctx, client)
}

func decOwnEdit(body membership.PolicyBody, host string) int64 {
	for _, edit := range body.Edits {
		if edit.Host == host {
			return edit.Seq
		}
	}
	return 0
}

func (o *ownerContext) decWritePolicy(ctx context.Context, client host.Client, body membership.PolicyBody, reserve bool, claims ...string) (json.RawMessage, error) {
	claim := ""
	if len(claims) > 0 {
		claim = claims[0]
	}
	if len(claims) > 1 {
		return nil, errors.New("invalid claim selection")
	}
	editor := o.dec
	baseline, err := decHead(editor.planning, "policy", o.ownerKey)
	if err != nil {
		return nil, err
	}
	if e := editor.reload(ctx, client); e != nil {
		return nil, e
	}
	current, e := decHead(editor.planning, "policy", o.ownerKey)
	if e != nil {
		return nil, e
	}
	if current != baseline {
		return nil, errors.New("policy changed during review; restart the exact edit")
	}
	var reservation host.DecEditReservation
	if reserve {
		var e error
		reservation, e = linkCall[host.DecEditReservation](ctx, client, "POST", decNetworkPath(o.network)+"/policy-edits", map[string]string{"provider_id": editor.providerID})
		if e != nil {
			return nil, e
		}
		if reservation.Person != o.ownerKey || reservation.Context != editor.descriptor.ContextID || reservation.Seq <= 0 {
			return nil, errors.New("policy reservation changes the reviewed identity")
		}
		body.Edits = membership.WithEdit(body.Edits, o.hostID, reservation.Seq)
		if e = editor.reload(ctx, client); e != nil {
			return nil, e
		}
		current, e = decHead(editor.planning, "policy", o.ownerKey)
		if e != nil {
			return nil, e
		}
		if current != baseline {
			return nil, errors.New("policy changed after reservation; review the retained edit")
		}
	}
	stream, _ := decStream(editor.planning, "policy", o.ownerKey)
	maximum := stream.Version
	if maximum == ^uint64(0) {
		return nil, errors.New("version_exhausted")
	}
	if reserve && maximum != reservation.Version {
		return nil, errors.New("policy changed after reservation; review the retained edit before retrying")
	}
	now, e := host.DecentralizedDecisionTime()
	if e != nil {
		return nil, e
	}
	// Actual operation time is fixed once. The daemon revalidates the same
	// payload and latest authority again before every signature and atomic apply.
	issued := now.Format(time.RFC3339)
	until := now.Add(24 * time.Hour)
	// The public provider summary may also describe administrative power.
	// Policy scope1 uses its actual declared finite ancestry below, so an
	// unrelated administrator deadline cannot shorten an owner's policy.
	pID, e := decHead(editor.planning, "person", o.ownerKey)
	if e != nil {
		return nil, e
	}
	if pID == "-" {
		return nil, errors.New("proof_required: current person lease is missing")
	}
	parents := []dec.Parent{{Role: "issuer_person", ID: pID}}
	issuer := dec.Issuer{Kind: "person", Person: o.ownerKey}
	if editor.provider.Kind == "device" {
		issuer.Kind = "device"
		parents = append(parents, dec.Parent{Role: "issuer_device", ID: editor.provider.Lease})
	}
	sort.Slice(parents, func(i, j int) bool { return parents[i].Role < parents[j].Role })
	// Every referenced finite ancestor is a hard ceiling, including an old
	// retained ancestor. Literal retained proof lists are not authority edges.
	visited := map[string]bool{}
	var ceiling func(string) error
	ceiling = func(id string) error {
		if visited[id] {
			return nil
		}
		visited[id] = true
		s := editor.catalog.Statements[id]
		if s == nil {
			return errors.New("proof_required: exact policy ancestor is missing")
		}
		if s.Lease != nil {
			at, e := dec.ParseTime(s.Lease.After)
			if e != nil {
				return e
			}
			if at.Before(until) {
				until = at
			}
			for _, parent := range s.Lease.Parents {
				if e = ceiling(parent.ID); e != nil {
					return e
				}
			}
		}
		return nil
	}
	for _, parent := range parents {
		if e = ceiling(parent.ID); e != nil {
			return nil, e
		}
	}
	if !until.After(now) {
		return nil, errors.New("authority_expired")
	}
	if body.Rules == nil {
		body.Rules = []membership.PolicyRule{}
	}
	if body.CapabilityRules == nil {
		body.CapabilityRules = []membership.CapabilityRule{}
	}
	if body.TrustedHosts == nil {
		body.TrustedHosts = []string{}
	}
	if body.Edits == nil {
		body.Edits = []membership.PolicyEdit{}
	}
	content := host.DecPolicyContent{Format: 2, Network: o.network, Person: o.ownerKey, Version: maximum + 1, Before: issued, After: until.Format(time.RFC3339), Rules: body.Rules, Capabilities: body.CapabilityRules, Trusted: body.TrustedHosts, Edits: body.Edits}
	contentRaw, e := json.Marshal(content)
	if e != nil {
		return nil, e
	}
	predecessors := append([]string{}, stream.Heads...)
	payload, e := json.Marshal(dec.Access{Root: editor.planning.Network.Root, Operation: "-", Sequence: maximum + 1, Predecessors: predecessors, Resolves: []string{}, Issuer: issuer, Parents: parents, Issued: issued, Before: issued, After: content.After, BodyBase64: base64.StdEncoding.EncodeToString(contentRaw)})
	if e != nil {
		return nil, e
	}
	return o.decSubmitPolicyPayload(ctx, client, payload, claim, editor.providerID)
}

// Submit the EXACT reviewed candidate, including a pure reapply preview's
// original timestamp/parents/body. Retries keep its retained action and slots.
func (o *ownerContext) decSubmitPolicyPayload(ctx context.Context, client host.Client, payload []byte, claim, providerID string) (data json.RawMessage, err error) {
	editor := o.dec
	fixed, e := dec.ReadActionPayload(editor.descriptor, "policy", payload)
	if e != nil {
		return nil, e
	}
	if fixed.Access.Issuer.Person != o.ownerKey {
		return nil, errors.New("policy payload changes the exact owner")
	}
	now, e := dec.ParseTime(fixed.Access.Issued)
	if e != nil {
		return nil, e
	}
	until, e := dec.ParseTime(fixed.Access.After)
	if e != nil {
		return nil, e
	}
	body, e := decContent(fixed)
	if e != nil {
		return nil, e
	}
	route := "/actions"
	kind := "policy"
	var request any = host.DecActionRequest{Kind: "policy", Provider: providerID, Format: "auto", Payload: base64.StdEncoding.EncodeToString(payload), Approve: true}
	if claim != "" {
		route = "/policy-claims"
		kind = "policy_claim"
		request = host.DecPolicyClaimRequest{Capability: claim, Provider: providerID, Format: "auto", Payload: base64.StdEncoding.EncodeToString(payload), Approve: true}
	}
	result, e := linkCall[host.DecActionResult](ctx, client, "POST", decNetworkPath(o.network)+route, request)
	if e != nil {
		return nil, e
	}
	defer func() {
		if err != nil && dec.ValidID(result.ID, "act_") {
			err = fmt.Errorf("retain exact policy action %s for resume: %w", result.ID, err)
		}
	}()
	approvedReview, e := json.Marshal(result.Review)
	if e != nil {
		return nil, e
	}
	concrete := editor.provider.Person
	if editor.provider.Kind == "device" {
		concrete = editor.provider.Lease
	}
	if result.ID != dec.ActionID(editor.descriptor.ContextID, kind, fixed.ID, concrete) || result.Review.Statement != fixed.ID || result.Review.Kind != kind || result.Review.Provider.Person != o.ownerKey || result.Review.Provider.Kind != editor.provider.Kind || result.Review.Provider.Host != editor.provider.Host || result.Review.Provider.Device != editor.provider.Device || result.Review.Provider.Lease != editor.provider.Lease || result.Review.Provider.Root != editor.provider.Root || result.Review.Sequence != fixed.Access.Sequence || result.Review.After != fixed.Access.After {
		return nil, errors.New("policy signing review changes the exact approved edit")
	}
	if len(result.Signing) > 0 {
		if len(result.Signing) != 1 {
			return nil, errors.New("the exact policy action is incomplete; resume its retained action ID")
		}
		slot := result.Signing[0]
		if slot.Type != "policy" || slot.Role != "issuer" || slot.Public != o.ownerKey || slot.Format != "sshsig" || slot.Object != fixed.ID || slot.Slot != 1 {
			return nil, errors.New("unexpected policy signing slot")
		}
		raw, e := base64.StdEncoding.Strict().DecodeString(slot.Template)
		if e != nil {
			return nil, e
		}
		template, e := dec.ReadStatementTemplate(editor.descriptor, raw)
		if e != nil || template.ID != fixed.ID || !bytes.Equal(template.Payload, payload) || len(template.Signatures) != 1 || template.Signatures[0].Role != "issuer" || template.Signatures[0].PublicKey != o.ownerKey || template.Signatures[0].Format != "sshsig" || template.Signatures[0].Signature != "-" {
			return nil, errors.New("policy signing template differs from the exact approved payload")
		}
		message := dec.SignatureMessage(fixed.ID, "issuer", o.ownerKey)
		supplied, e := base64.StdEncoding.Strict().DecodeString(slot.Message)
		if e != nil || !bytes.Equal(message, supplied) {
			return nil, errors.New("policy slot message differs from its typed template")
		}
		at, e := host.DecentralizedDecisionTime()
		if e != nil {
			return nil, e
		}
		if at.Before(now) || at.Sub(now) > 300*time.Second || !at.Before(until) {
			return nil, errors.New("the exact policy signing window expired; review the retained action")
		}
		signer := o.signer
		if signer == nil {
			signer, e = person.Load(editor.keyPath)
			if e != nil {
				return nil, e
			}
			defer signer.Close()
		}
		if membership.EncodeKey(signer.PublicKey()) != o.ownerKey {
			return nil, errors.New("the original signer differs from the reviewed person")
		}
		signed, e := membership.SignSSHSIG(signer, message)
		if e != nil {
			return nil, e
		}
		completed, e := linkCall[host.DecActionResult](ctx, client, "POST", decNetworkPath(o.network)+route+"/"+url.PathEscape(result.ID)+"/signed", map[string]any{"intent_id": slot.Intent, "signatures": []map[string]any{{"slot_id": slot.Slot, "role": slot.Role, "signature": signed}}})
		if e != nil {
			return nil, e
		}
		completedReview, e := json.Marshal(completed.Review)
		if e != nil || completed.ID != result.ID || !bytes.Equal(approvedReview, completedReview) {
			return nil, errors.New("signed policy response changes the retained action or review")
		}
		result = completed
	}
	if claim != "" && result.Committed || claim == "" && !result.Committed || result.Statement == "-" || len(result.Signing) != 0 {
		return nil, errors.New("the exact policy signing/application state is incomplete or inconsistent; resume its retained action ID")
	}
	envelope, e := base64.StdEncoding.Strict().DecodeString(result.Statement)
	if e != nil {
		return nil, e
	}
	final, e := dec.ReadStatement(editor.descriptor, envelope)
	if e != nil || final.ID != fixed.ID || !bytes.Equal(final.Payload, payload) || result.Proof != dec.ProofID("policy", envelope) {
		return nil, errors.New("applied policy differs from its exact reviewed payload")
	}
	if claim != "" {
		return json.Marshal(result)
	}
	editor.current = final
	editor.content = body
	return envelope, nil
}

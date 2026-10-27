package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/helper"
)

// Complete publication has no mailbox capability and carries no new consent.
// It goes only to exact signed transcript participants over actual pinned TLS.
func (s *Store) publishDecCompletion(parent context.Context, p decPending) error {
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	activation, catalog, parsed, e := decPendingActivation(p)
	if e != nil {
		return e
	}
	body := append([]byte(`{"activation":`), activation...)
	body = append(body, []byte(`,"catalog":`)...)
	body = append(body, catalog.Raw...)
	body = append(body, '}')
	if len(body) > 20<<20 {
		return decFailure("quota_exceeded")
	}
	carriers, e := decCompletionCarriers(p)
	if e != nil {
		return e
	}
	targets := map[string][]decCarrier{}
	for _, carrier := range carriers {
		if carrier.Kind == "participant" && carrier.Key != s.identity.PublicKey && decActivationParticipant(parsed, carrier.Key) {
			targets[carrier.Key] = append(targets[carrier.Key], carrier)
		}
	}
	// The transcript has at most three actual host participants. Start every
	// other target within ONE overall deadline; an unreachable first participant
	// cannot consume the entire attempt before a healthy participant is tried.
	keys := make([]string, 0, len(targets))
	for key := range targets {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	results := make([]chan error, len(keys))
	for index, key := range keys {
		result := make(chan error, 1)
		results[index] = result
		go func() {
			last := decTransportFailure()
			for _, carrier := range targets[key] {
				if ctx.Err() != nil {
					break
				}
				raw, status, e := s.decParticipantExchange(ctx, p, carrier, "POST", "/bootstrap/v1/activations", body)
				if e != nil {
					last = decTransportFailure()
					continue
				}
				if status != 200 {
					last = decTransportFailure()
					continue
				}
				if e = decVerifyParticipantOutcome(p.Descriptor, parsed, raw, carrier.Key); e != nil {
					last = e
					continue
				}
				result <- nil
				return
			}
			result <- last
		}()
	}
	var first error
	for _, result := range results {
		if e := <-result; e != nil && first == nil {
			first = e
		}
	}
	// Delivery receipts describe only their actual participants. Missing paths
	// preserve linked plus attention and never undo local application.
	return first
}

func decVerifyParticipantOutcome(d dec.Descriptor, expected *dec.ParsedActivation, raw []byte, writer string) error {
	var response decParticipantOutcome
	if dec.ReadPrivateRecord(raw, "outcome activation catalog", &response) != nil {
		return decTransportFailure()
	}
	activation, e := dec.ReadActivation(d, response.Activation)
	if e != nil {
		return e
	}
	if activation.ID != expected.ID || activation.ManifestID != expected.ManifestID || !bytes.Equal(activation.Request.Raw, expected.Request.Raw) || !decActivationParticipant(activation, writer) {
		return decFailure("operation_conflict")
	}
	catalog, e := dec.ReadCatalog(d, response.Catalog)
	if e != nil {
		return e
	}
	// The returned catalog is proof evidence only; it never replaces our own
	// current state, immutable local outcome or selected provider.
	found := false
	for _, object := range catalog.Objects {
		if object.Kind == "activation" && bytes.Equal(object.Body, response.Activation) {
			found = true
		}
	}
	if !found {
		return decFailure("proof_required", dec.ProofID("activation", response.Activation))
	}
	outcome, e := dec.ReadPacket(d, response.Outcome)
	if e != nil {
		return e
	}
	var fields struct {
		Context    string `json:"context_id"`
		Request    string `json:"request_id"`
		Manifest   string `json:"manifest_id"`
		Activation string `json:"activation_id"`
		Hash       string `json:"activation_sha256"`
		Root       string `json:"observed_root_state_id"`
		At         string `json:"applied_at"`
	}
	if json.Unmarshal(outcome.Payload, &fields) != nil {
		return decFailure("invalid")
	}
	hash := sha256.Sum256(response.Activation)
	if outcome.Role != "outcome" || outcome.Writer != writer || outcome.RequestID != expected.Request.RequestID || fields.Context != d.ContextID || fields.Request != expected.Request.RequestID || fields.Manifest != expected.ManifestID || fields.Activation != expected.ID || fields.Hash != hex.EncodeToString(hash[:]) {
		return decFailure("invalid")
	}
	return nil
}

// A participant can lose its opaque mailbox before learning the final commit.
// Only exact transcript peers are queried, without a bearer or replacement
// signing attempt. The ordinary strict completion path retains every local
// consent/pin and independently evaluates current authority before application.
func (s *Store) recoverDecCompletion(ctx context.Context, p decPending) (bool, error) {
	if p.Record.Finalization == "-" || p.Record.Owner == "-" || p.Record.Migration != "-" || containsString(p.Record.Roles, "requester") && !p.Record.Committed {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var last error
	queried := map[string]bool{}
	carriers, e := decCompletionCarriers(p)
	if e != nil {
		return false, e
	}
	for _, carrier := range carriers {
		if carrier.Kind != "participant" || carrier.Key == s.identity.PublicKey || queried[carrier.Key] {
			continue
		}
		// The endpoint is an untrusted hint. Its TLS key must independently match
		// an already reviewed request/owner/administrator packet in this attempt.
		participant := carrier.Key == p.Request.Writer
		for _, body := range []string{p.Record.Owner, p.Record.Administrator} {
			if body == "-" {
				continue
			}
			packet, e := dec.ReadPacket(p.Descriptor, mustDecBytes(body))
			if e != nil {
				return false, e
			}
			participant = participant || packet.Writer == carrier.Key
		}
		if !participant {
			continue
		}
		raw, status, e := s.decParticipantExchange(ctx, p, carrier, "GET", "/bootstrap/v1/operations/"+p.ID, nil)
		if e != nil || status != 200 {
			if e == nil {
				queried[carrier.Key] = true
			}
			if status != 404 {
				last = e
				if last == nil {
					last = decTransportFailure()
				}
			}
			continue
		}
		queried[carrier.Key] = true
		var result decParticipantOutcome
		if e = dec.ReadPrivateRecord(raw, "outcome activation catalog", &result); e != nil {
			return false, e
		}
		activation, e := dec.ReadActivation(p.Descriptor, result.Activation)
		if e != nil {
			return false, e
		}
		if !bytes.Equal(activation.Request.Raw, p.Request.Raw) || !bytes.Equal(activation.Owner.Raw, mustDecBytes(p.Record.Owner)) || p.Record.Selection != "-" && !bytes.Equal(activation.Selection.Raw, mustDecBytes(p.Record.Selection)) || p.Record.Finalization != "-" && !bytes.Equal(activation.Finalization.Raw, mustDecBytes(p.Record.Finalization)) {
			return false, decFailure("operation_conflict")
		}
		if p.Record.Administrator != "-" && (activation.Administrator == nil || !bytes.Equal(activation.Administrator.Raw, mustDecBytes(p.Record.Administrator))) {
			return false, decFailure("operation_conflict")
		}
		if e = decVerifyParticipantOutcome(p.Descriptor, activation, raw, carrier.Key); e != nil {
			return false, e
		}
		body := append([]byte(`{"activation":`), result.Activation...)
		body = append(body, []byte(`,"catalog":`)...)
		body = append(body, result.Catalog...)
		body = append(body, '}')
		if len(body) > 20<<20 {
			return false, decFailure("quota_exceeded")
		}
		// HostPublicKey came from the pinned TLS exchange above, never from
		// asserted HTTP metadata. This invokes no owner-local administration.
		applied, e := s.completeDecParticipant(ctx, helper.ParticipantRequest{HostPublicKey: carrier.Key, Method: "POST", Path: "/bootstrap/v1/activations", Body: body})
		if e != nil {
			return false, e
		}
		if applied.Status != 200 {
			var refusal struct {
				Code    string          `json:"code"`
				Error   string          `json:"error"`
				Details decErrorDetails `json:"details"`
			}
			if dec.ReadPrivateRecord(applied.Body, "code error details", &refusal) != nil {
				return false, decStorageError()
			}
			return false, decFailure(refusal.Code, refusal.Details.Required...)
		}
		return true, nil
	}
	return false, last
}

func decCachedCommitInput(p decPending) DecLinkFinalization {
	person := "-"
	if p.Record.Owner != "-" {
		if raw, e := base64.StdEncoding.DecodeString(p.Record.Owner); e == nil {
			if packet, e := dec.ReadPacket(p.Descriptor, raw); e == nil {
				person = packet.Person
			}
		}
	}
	return DecLinkFinalization{Owner: p.Record.OwnerID, Selection: p.Record.SelectionID, Administrator: p.Record.AdministratorID, Network: p.Descriptor.NetworkID, Context: p.Descriptor.ContextID, Person: person, Host: p.Record.Host, Device: p.Record.Device, Approve: true}
}

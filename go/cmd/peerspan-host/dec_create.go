package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"time"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/peerspan/peerspan/go/internal/person"
	"github.com/spf13/pflag"
)

type decCLICreationReview struct {
	Name       string          `json:"name"`
	Member     string          `json:"member"`
	Descriptor json.RawMessage `json:"descriptor"`
	Root       string          `json:"root_state_id"`
	Person     string          `json:"person_public_key"`
	Host       string          `json:"host_public_key"`
	NotAfter   string          `json:"not_after"`
	Warning    string          `json:"authority_warning"`
}
type decCLICreation struct {
	ID        string                   `json:"creation_id"`
	Review    decCLICreationReview     `json:"review"`
	Signing   []host.DecSigningRequest `json:"signing_requests"`
	Network   *host.DecNetworkView     `json:"network"`
	Committed bool                     `json:"committed"`
}

func verifyDecCreateReview(result decCLICreation, name, member, personKey, hostKey string) (dec.Descriptor, error) {
	d, e := dec.ReadDescriptor(result.Review.Descriptor)
	if e != nil {
		return d, e
	}
	if !dec.ValidID(result.ID, "create_") || result.Review.Name != name || d.Name != name || result.Review.Member != member || result.Review.Person != personKey || result.Review.Host != hostKey || !dec.ValidID(result.Review.Root, "ds_") || result.Review.Warning == "" || result.Signing == nil {
		return d, errors.New("the creation review does not match the requested owner and machine")
	}
	if _, e = dec.ParseTime(result.Review.NotAfter); e != nil {
		return d, e
	}
	if result.Committed && (result.Network == nil || result.Network.ID != d.NetworkID || result.Network.Context != d.ContextID || result.Network.Person != personKey || result.Network.Host != hostKey) {
		return d, errors.New("the completed creation does not match its exact review")
	}
	return d, nil
}
func decCreateSlot(d dec.Descriptor, review decCLICreationReview, request host.DecSigningRequest, public string, reviewedAt time.Time) ([]byte, error) {
	raw, e := base64.StdEncoding.Strict().DecodeString(request.Template)
	if e != nil || base64.StdEncoding.EncodeToString(raw) != request.Template {
		return nil, errors.New("invalid typed creation template")
	}
	statement, e := dec.ReadStatementTemplate(d, raw)
	if e != nil {
		return nil, e
	}
	if request.Intent == "" || request.Slot == 0 || request.Object != statement.ID || request.Type != statement.Kind || request.Role != "issuer" || request.Public != public || request.Format != "sshsig" {
		return nil, errors.New("the creation slot does not match the original owner")
	}
	found := false
	for _, signature := range statement.Signatures {
		if signature.Role == request.Role && signature.PublicKey == public && signature.Format == request.Format && signature.Signature == "-" {
			found = true
		}
	}
	if !found {
		return nil, errors.New("the creation slot is not an unfilled matching original-owner role")
	}
	if statement.Lease != nil {
		l := statement.Lease
		if statement.Kind != "binding_lease" || l.Root != review.Root || l.Operation != "-" || l.Sequence != 1 || len(l.Predecessors) != 0 || len(l.Resolves) != 0 || len(l.Retained) != 0 || l.Subject.Person != public || l.Subject.Host != review.Host || l.Subject.Scopes != 2 || l.Issuer.Kind != "person" || l.Issuer.Person != public || l.After != review.NotAfter {
			return nil, errors.New("the binding template changes the reviewed creation")
		}
	} else if statement.Access != nil {
		a := statement.Access
		if statement.Kind != "policy" || a.Root != review.Root || a.Operation != "-" || a.Sequence != 1 || len(a.Predecessors) != 0 || len(a.Resolves) != 0 || a.Issuer.Kind != "person" || a.Issuer.Person != public || a.After > review.NotAfter {
			return nil, errors.New("the policy template changes the reviewed creation")
		}
		body, e := base64.StdEncoding.Strict().DecodeString(a.BodyBase64)
		if e != nil {
			return nil, e
		}
		var policy struct {
			Rules        []json.RawMessage `json:"rules"`
			Capabilities []json.RawMessage `json:"capability_rules"`
			Trusted      []string          `json:"trusted_hosts"`
			Edits        []json.RawMessage `json:"edits"`
		}
		if json.Unmarshal(body, &policy) != nil || len(policy.Rules) != 0 || len(policy.Capabilities) != 0 || len(policy.Trusted) != 0 || len(policy.Edits) != 0 {
			return nil, errors.New("the initial policy is not the reviewed empty creator policy")
		}
	} else {
		return nil, errors.New("unexpected original-person creation object")
	}
	now, e := host.DecentralizedDecisionTime()
	if e != nil {
		return nil, e
	}
	issued, before, after := "", "", ""
	if statement.Lease != nil {
		issued, before, after = statement.Lease.Issued, statement.Lease.Before, statement.Lease.After
	}
	if statement.Access != nil {
		issued, before, after = statement.Access.Issued, statement.Access.Before, statement.Access.After
	}
	at, e := dec.ParseTime(issued)
	if e != nil {
		return nil, e
	}
	start, e := dec.ParseTime(before)
	if e != nil {
		return nil, e
	}
	end, e := dec.ParseTime(after)
	if e != nil {
		return nil, e
	}
	if now.Before(at) || now.Before(start) || !now.Before(end) || now.Before(reviewedAt) || now.Sub(reviewedAt) > 300*time.Second {
		return nil, errors.New("creation signing window expired or not yet valid; review the exact retained creation")
	}
	message := dec.SignatureMessage(statement.ID, request.Role, public)
	supplied, e := base64.StdEncoding.Strict().DecodeString(request.Message)
	if e != nil || !bytes.Equal(message, supplied) {
		return nil, errors.New("the typed creation message does not match its template")
	}
	return message, nil
}
func onboardDecCreate(ctx context.Context, client host.Client, positional []string, fs *pflag.FlagSet, errOut io.Writer, complete func(map[string]any) error) error {
	name, _ := fs.GetString("name")
	if len(positional) == 1 {
		if fs.Changed("name") {
			return errors.New("give the network name once")
		}
		name = positional[0]
	}
	member, _ := fs.GetString("as")
	alias, _ := fs.GetString("member")
	if fs.Changed("as") && fs.Changed("member") {
		return errors.New("give at most one of --as and --member")
	}
	if alias != "" {
		member = alias
	}
	if member == "" {
		member = loginName()
	}
	if !membership.ValidLabel(name) || !membership.ValidLabel(member) {
		return errors.New("network create needs a valid name and member label")
	}
	if fs.Changed("coordinator") || fs.Changed("coordinator-key") {
		return errors.New("new networks are coordinator-free; use network migrate for existing legacy history")
	}
	noPerson, _ := fs.GetBool("no-person")
	if noPerson {
		return errors.New("coordinator-free creation requires an original owner; omit --no-person")
	}
	path, _ := fs.GetString("person-key")
	if fs.Lookup("person-key-file") != nil {
		alias, _ := fs.GetString("person-key-file")
		if alias != "" {
			if path != "" {
				return errors.New("give the original key once")
			}
			path = alias
		}
	}
	if trusted, _ := fs.GetBool("trusted"); trusted {
		return errors.New("create the network first, then explicitly review trust with peerspan trust")
	}
	existing, e := call[[]host.DecNetworkView](ctx, client, "GET", "/v2/networks")
	if e != nil {
		return e
	}
	var existingPerson string
	for _, network := range existing {
		if network.Name == name {
			existingPerson = network.Person
			break
		}
	}
	if _, e = host.DecentralizedDecisionTime(); e != nil {
		return e
	}
	choice, e := person.Choose(path)
	if e != nil {
		return e
	}
	defer choice.Close()
	if existingPerson != "" && membership.EncodeKey(choice.PublicKey()) != existingPerson {
		return errors.New("this network already has an owner identity; use that exact original key or resume reviewed machine linking")
	}
	identity, e := call[host.Identity](ctx, client, "GET", "/v1/host")
	if e != nil {
		return e
	}
	// Fix a newly generated original identity before the first potentially
	// uncertain creation POST. It stays protected and only on this machine.
	if e = choice.Save(fmt.Sprintf("peerspan original owner %s", member)); e != nil {
		return e
	}
	public := membership.EncodeKey(choice.PublicKey())
	request := host.DecCreateNetwork{Name: name, Member: member, Person: public, Approve: true}
	raw, e := client.Call(ctx, "POST", "/v2/networks", request)
	if e != nil {
		var refusal *host.ClientError
		if !errors.As(e, &refusal) || refusal.Code != "review_required" {
			return e
		}
		// Fetch the exact existing review without refreshing consent. A stale
		// pending creation needs a separate visible default-no confirmation.
		request.Approve = false
		raw, e = client.Call(ctx, "POST", "/v2/networks", request)
		if e != nil {
			return e
		}
	}
	var result decCLICreation
	if json.Unmarshal(raw, &result) != nil {
		return errors.New("invalid creation response")
	}
	reviewedAt, e := host.DecentralizedDecisionTime()
	if e != nil {
		return e
	}
	for round := 0; round < 8; round++ {
		d, e := verifyDecCreateReview(result, name, member, public, identity.PublicKey)
		if e != nil {
			return e
		}
		if result.Committed {
			var view map[string]any
			raw, e = json.Marshal(result.Network)
			if e != nil {
				return e
			}
			if e = json.Unmarshal(raw, &view); e != nil {
				return e
			}
			if choice.Source == person.SourceNew {
				fmt.Fprintln(errOut, "Back up this machine's original person key. Approve additional machines with peerspan link; keep this key here.")
			}
			return complete(view)
		}
		if len(result.Signing) == 0 {
			if e = printJSON(errOut, result.Review); e != nil {
				return e
			}
			if !isTerminal(os.Stdin) || !askYes(errOut, "Approve this exact retained network creation?") {
				return fmt.Errorf("network creation is incomplete; review the exact creation %s before approving", result.ID)
			}
			reviewedAt, e = host.DecentralizedDecisionTime()
			if e != nil {
				return e
			}
			raw, e = client.Call(ctx, "POST", "/v2/network-creations/"+url.PathEscape(result.ID)+"/approve", host.DecCreationApproval{Context: d.ContextID, Root: result.Review.Root, Person: public, Host: identity.PublicKey, Approve: true})
			if e != nil {
				return e
			}
			if json.Unmarshal(raw, &result) != nil {
				return errors.New("invalid retained creation approval response")
			}
			continue
		}
		signatures := []map[string]any{}
		intent := ""
		for _, slot := range result.Signing {
			if intent == "" {
				intent = slot.Intent
			} else if intent != slot.Intent {
				return errors.New("mixed creation signing intentions")
			}
			message, e := decCreateSlot(d, result.Review, slot, public, reviewedAt)
			if e != nil {
				return e
			}
			signature, e := membership.SignSSHSIG(choice, message)
			if e != nil {
				return e
			}
			signatures = append(signatures, map[string]any{"slot_id": slot.Slot, "role": slot.Role, "signature": signature})
		}
		raw, e = client.Call(ctx, "POST", "/v2/network-creations/"+url.PathEscape(result.ID)+"/signed", map[string]any{"intent_id": intent, "signatures": signatures})
		if e != nil {
			return e
		}
		if json.Unmarshal(raw, &result) != nil {
			return errors.New("invalid signed creation response")
		}
	}
	return errors.New("network creation remains incomplete; resume the retained creation ID")
}

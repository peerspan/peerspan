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
	"strings"
	"time"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/peerspan/peerspan/go/internal/person"
	"github.com/spf13/pflag"
)

type decCLILink struct {
	host.DecLinkView
	Code string `json:"display_code,omitempty"`
}

func decLinkBase(id string) string { return "/v2/link/requests/" + url.PathEscape(id) }
func decLinkOutput(out io.Writer, view decCLILink, display bool) error {
	if !display {
		view.Code = ""
	}
	if e := printJSON(out, view); e != nil {
		return e
	}
	if view.State != "linked" {
		return exitStatus(1)
	}
	return nil
}
func decLinkViewOutput(out io.Writer, view host.DecLinkView) error {
	return decLinkOutput(out, decCLILink{DecLinkView: view}, false)
}
func decLinkNetwork(ctx context.Context, client host.Client, name string) (host.DecNetworkView, error) {
	networks, e := linkCall[[]host.DecNetworkView](ctx, client, "GET", "/v2/networks")
	if e != nil {
		return host.DecNetworkView{}, e
	}
	for _, network := range networks {
		if network.ID == name || network.Name == name {
			return network, nil
		}
	}
	if name == "-" && len(networks) == 1 {
		return networks[0], nil
	}
	return host.DecNetworkView{}, fmt.Errorf("choose an existing coordinator-free network with --network: %w", errNotJoined)
}
func decLinkDescriptor(network host.DecNetworkView) (dec.Descriptor, error) {
	raw, _ := json.Marshal(dec.Descriptor{Format: 1, Protocol: dec.Protocol, NetworkID: network.ID, Name: network.Name, GenesisRootPublicKey: network.Genesis})
	d, e := dec.ReadDescriptor(raw)
	if e == nil && d.ContextID != network.Context {
		e = errors.New("network descriptor does not match its context")
	}
	return d, e
}

func sameDecLinkReview(prior, next host.DecCeremonyReview) error {
	if prior.Network != next.Network || prior.Context != next.Context || prior.Person != next.Person || prior.Host != next.Host || prior.Device != next.Device || prior.Scopes != next.Scopes || prior.NotAfter != next.NotAfter {
		return errors.New("link signing changed the reviewed target or finite powers")
	}
	for _, ref := range [][2]string{{prior.Root, next.Root}, {prior.Owner, next.Owner}, {prior.Selection, next.Selection}, {prior.Administrator, next.Administrator}, {prior.PersonLease, next.PersonLease}, {prior.HostLease, next.HostLease}, {prior.BindingLease, next.BindingLease}, {prior.DeviceLease, next.DeviceLease}} {
		if ref[0] != "-" && ref[0] != ref[1] {
			return errors.New("link signing changed an already fixed ceremony reference")
		}
	}
	a, b := prior.Provider, next.Provider
	if a.Kind == "original_person" && a.Scopes == 0 {
		// Pending original-person self-consent can learn its concrete admitted
		// parents, but its original person and local machine never change.
		if a.Kind != b.Kind || a.Person != b.Person || a.Host != b.Host || a.Device != b.Device {
			return errors.New("pending self-consent changed its exact original provider")
		}
		for _, ref := range [][2]string{{a.Root, b.Root}, {a.Lease, b.Lease}, {a.NotAfter, b.NotAfter}} {
			if ref[0] != "-" && ref[0] != ref[1] {
				return errors.New("pending self-consent changed an already fixed provider reference")
			}
		}
	} else if a != b || prior.Root != next.Root {
		return errors.New("link signing changed the approved provider or root")
	}
	return nil
}

func decSigningMessage(d dec.Descriptor, review host.DecCeremonyReview, view host.DecLinkView, slot host.DecSigningRequest) ([]byte, error) {
	raw, e := base64.StdEncoding.Strict().DecodeString(slot.Template)
	if e != nil || base64.StdEncoding.EncodeToString(raw) != slot.Template || slot.Slot == 0 || slot.Format != "sshsig" || slot.Public == "-" {
		return nil, errors.New("invalid typed signing slot")
	}
	if review.Provider.Kind == "original_person" && slot.Public != review.Provider.Person {
		return nil, errors.New("slot signer does not match the explicitly reviewed provider")
	}
	var message []byte
	if strings.HasSuffix(slot.Type, "_packet") {
		packet, e := dec.ReadPacketTemplate(d, raw)
		if e != nil {
			return nil, e
		}
		wanted := map[string]string{"owner_offer_packet": "owner", "administrator_packet": "administrator", "owner_finalization_packet": "owner_finalization"}[slot.Type]
		if wanted == "" || packet.Role != wanted || slot.Role != "authority" || packet.ID != slot.Object || packet.RequestID != view.Request || packet.Signer != slot.Public || packet.AuthorityFormat != slot.Format || packet.AuthoritySignature != "-" {
			return nil, errors.New("packet slot changes the reviewed signer or role")
		}
		if review.Provider.Kind == "network_root" {
			if packet.Person != "-" || packet.Issuer != review.Root {
				return nil, errors.New("root packet does not match the reviewed root")
			}
		} else if packet.Person != review.Provider.Person {
			return nil, errors.New("packet changes the reviewed original owner")
		}
		field := func(name string) string {
			var value string
			_ = json.Unmarshal(packet.Object[name], &value)
			return value
		}
		switch packet.Role {
		case "owner":
			var scopes uint64
			_ = json.Unmarshal(packet.Object["scopes"], &scopes)
			if field("request_packet_id") != view.RequestPacket || field("root_state_id") != review.Root || field("person_lease_id") != review.PersonLease || field("host_public_key") != review.Host || field("device_public_key") != review.Device || field("not_after") != review.NotAfter || scopes != review.Scopes {
				return nil, errors.New("owner packet changes the exact reviewed target or powers")
			}
		case "administrator":
			if field("owner_offer_id") != review.Owner || field("selection_id") != review.Selection || field("root_state_id") != review.Root {
				return nil, errors.New("administrator packet changes the selected ceremony")
			}
		case "owner_finalization":
			if field("selection_id") != review.Selection || field("administrator_offer_id") != review.Administrator || field("root_state_id") != review.Root || field("person_lease_id") != review.PersonLease || field("host_lease_id") != review.HostLease {
				return nil, errors.New("finalization packet changes its reviewed parents")
			}
		}
		message = packet.Message
	} else {
		statement, e := dec.ReadStatementTemplate(d, raw)
		if e != nil {
			return nil, e
		}
		if slot.Role != "issuer" || statement.ID != slot.Object || statement.Kind != slot.Type || statement.Lease == nil || statement.Lease.Operation != view.Request || statement.Lease.Root != review.Root || statement.Lease.After != review.NotAfter {
			return nil, errors.New("grant slot changes the reviewed operation or finite terms")
		}
		reference := map[string]string{"person_lease": review.PersonLease, "host_lease": review.HostLease, "binding_lease": review.BindingLease, "device_lease": review.DeviceLease}[statement.Kind]
		if statement.ID != reference {
			return nil, errors.New("grant slot differs from its exact reviewed lease reference")
		}
		for _, parent := range statement.Lease.Parents {
			want := ""
			switch parent.Role {
			case "subject_person":
				want = review.PersonLease
			case "subject_host":
				want = review.HostLease
			case "subject_binding":
				want = review.BindingLease
			}
			if want != "" && parent.ID != want {
				return nil, errors.New("grant slot changes an exact reviewed subject parent")
			}
		}
		subject := statement.Lease.Subject
		switch statement.Kind {
		case "person_lease":
			if subject.Person != review.Person {
				return nil, errors.New("person grant changes the reviewed person")
			}
		case "host_lease":
			if subject.Host != review.Host {
				return nil, errors.New("host grant changes the reviewed machine")
			}
		case "binding_lease":
			if subject.Person != review.Person || subject.Host != review.Host {
				return nil, errors.New("binding changes the reviewed identity")
			}
		case "device_lease":
			if subject.Person != review.Person || subject.Host != review.Host || subject.Device != review.Device || subject.Scopes != review.Scopes {
				return nil, errors.New("device grant changes the reviewed powers or machine")
			}
		default:
			return nil, errors.New("unexpected ceremony grant")
		}
		found := false
		for _, signature := range statement.Signatures {
			if signature.Role == slot.Role && signature.PublicKey == slot.Public && signature.Format == slot.Format && signature.Signature == "-" {
				found = true
			}
		}
		if !found {
			return nil, errors.New("the exact reviewed issuer slot is not ready")
		}
		message = dec.SignatureMessage(statement.ID, slot.Role, slot.Public)
	}
	expected, e := base64.StdEncoding.Strict().DecodeString(slot.Message)
	if e != nil || !bytes.Equal(expected, message) {
		return nil, errors.New("typed signing message differs from its exact template")
	}
	now, e := host.DecentralizedDecisionTime()
	if e != nil {
		return nil, e
	}
	expires, e := dec.ParseTime(view.Expires)
	if e != nil || !now.Before(expires) {
		return nil, errors.New("the exact linking signing window expired; resume the retained request")
	}
	return message, nil
}
func signDecLink(ctx context.Context, client host.Client, result host.DecApprovalResult, fs *pflag.FlagSet) (host.DecApprovalResult, error) {
	network, e := decLinkNetwork(ctx, client, result.Review.Network)
	var d dec.Descriptor
	rootKey := network.RootKey
	if result.Request.Migration != "-" {
		prepared, err := readCLIMigrationPreparation(ctx, client, result.Review.Network, result.Request.Migration)
		if err != nil {
			return result, err
		}
		if result.Review.Context != prepared.Descriptor.ContextID || result.Request.Context != prepared.Descriptor.ContextID || result.Review.Root != prepared.Root {
			return result, errors.New("staged signing changes the exact proposal context/root")
		}
		d, rootKey, e = prepared.Descriptor, prepared.RootKey, nil
	} else if e == nil {
		d, e = decLinkDescriptor(network)
	} else if errors.Is(e, errNotJoined) && result.Review.Provider.Kind == "original_person" && result.Review.Provider.Person == result.Review.Person && result.Request.Role == "requester" && result.Request.Mode == "new" && (result.Review.Provider.Scopes == 0 || result.Review.Stage == "owner_finalization" && result.Review.Provider.Scopes == 7) {
		identity, err := call[host.Identity](ctx, client, "GET", "/v1/host")
		if err != nil {
			return result, err
		}
		if result.Review.Host != identity.PublicKey || result.Request.Host != identity.PublicKey || result.Review.Provider.Host != identity.PublicKey || result.Review.Person != result.Request.Person || result.Review.Device != result.Request.Device || result.Review.Context != result.Request.Context || result.Review.Network != result.Request.Network || !dec.ValidID(result.Review.Context, "ctx_") || !dec.ValidID(result.Review.Network, "net_") {
			return result, errors.New("pending self-consent does not match this exact requester")
		}
		// This is a decoder context for exact external self-consent templates,
		// never an adoptable descriptor/network or a current authority claim.
		d = dec.Descriptor{ContextID: result.Review.Context, NetworkID: result.Review.Network}
		e = nil
	}
	if e != nil {
		return result, e
	}
	for count := 0; len(result.Signing) > 0; count++ {
		if count >= 64 {
			return result, errors.New("too many dependent linking slots")
		}
		slot := result.Signing[0]
		if result.Review.Provider.Kind == "network_root" && slot.Public != rootKey {
			return result, errors.New("the root slot does not match the independently reviewed current root")
		}
		message, e := decSigningMessage(d, result.Review, result.Request, slot)
		if e != nil {
			return result, e
		}
		paths := []string{}
		for _, flag := range []string{"person-key", "root-key"} {
			if fs.Lookup(flag) != nil {
				path, _ := fs.GetString(flag)
				if path != "" {
					paths = append(paths, path)
				}
			}
		}
		if len(paths) == 0 {
			paths = append(paths, "")
		}
		var signer person.Signer
		for _, path := range paths {
			candidate, e := person.Load(path)
			if e != nil {
				return result, e
			}
			if membership.EncodeKey(candidate.PublicKey()) == slot.Public {
				signer = candidate
				break
			}
			_ = candidate.Close()
		}
		if signer == nil {
			return result, errors.New("use the same explicitly reviewed original key on its own machine")
		}
		signature, e := membership.SignSSHSIG(signer, message)
		_ = signer.Close()
		if e != nil {
			return result, e
		}
		batch := map[string]any{"intent_id": slot.Intent, "signatures": []map[string]any{{"slot_id": slot.Slot, "role": slot.Role, "signature": signature}}}
		next, e := linkCall[host.DecApprovalResult](ctx, client, "POST", decLinkBase(result.Request.Request)+"/signed", batch)
		if e != nil {
			return result, e
		}
		if next.Request.Request != result.Request.Request || next.Request.RequestPacket != result.Request.RequestPacket || next.Request.Role != result.Request.Role || next.Request.Mode != result.Request.Mode || next.Request.Migration != result.Request.Migration || next.Request.Created != result.Request.Created || next.Request.Expires != result.Request.Expires {
			return result, errors.New("link signing response changed the immutable request")
		}
		if e = sameDecLinkReview(result.Review, next.Review); e != nil {
			return result, e
		}
		result = next
	}
	return result, nil
}

func runLinkWithCodeDisplay(ctx context.Context, client host.Client, args []string, fs *pflag.FlagSet, out, errOut io.Writer, display bool) error {
	command := "link"
	if len(args) > 1 {
		command = args[1]
	}
	if fs.Lookup("coordinator") != nil && (fs.Changed("coordinator") || fs.Changed("coordinator-key")) {
		return errors.New("new linking is coordinator-free; use explicit network migration for legacy state")
	}
	switch command {
	case "status":
		path := "/v2/link/requests"
		if len(args) == 3 {
			path += "/" + url.PathEscape(args[2])
		}
		raw, e := client.Call(ctx, "GET", path, nil)
		if e != nil {
			return e
		}
		if len(args) == 3 {
			var view host.DecLinkView
			if e = json.Unmarshal(raw, &view); e != nil {
				return e
			}
			return decLinkViewOutput(out, view)
		}
		return printJSON(out, json.RawMessage(raw))
	case "cancel":
		view, e := linkCall[host.DecLinkView](ctx, client, "POST", decLinkBase(args[2])+"/cancel", map[string]any{})
		if e != nil {
			return e
		}
		return decLinkViewOutput(out, view)
	case "select", "commit", "finalize":
		view, e := linkCall[host.DecLinkView](ctx, client, "GET", decLinkBase(args[2]))
		if e != nil {
			return e
		}
		approve, _ := fs.GetBool("approve")
		value := func(flag, fallback string) string {
			v := linkFlag(fs, flag)
			if v == "-" {
				return fallback
			}
			return v
		}
		selection := host.DecLinkSelection{Owner: value("owner-offer", view.Owner), Network: value("network", view.Network), Context: value("context", view.Context), Person: value("expect-person", view.Person), Host: value("expect-host-key", view.Host), Device: value("expect-device-key", view.Device), Approve: approve}
		if command == "select" {
			result, e := linkCall[host.DecConfirmationResult](ctx, client, "POST", decLinkBase(args[2])+"/selection", selection)
			if e != nil {
				return e
			}
			return decLinkViewOutput(out, result.Request)
		}
		if command == "finalize" {
			input := host.DecLinkFinalization{Owner: selection.Owner, Selection: value("selection", view.Selection), Administrator: value("administrator-offer", view.Administrator), Network: selection.Network, Context: selection.Context, Person: selection.Person, Host: selection.Host, Device: selection.Device, Approve: approve}
			result, e := linkCall[host.DecApprovalResult](ctx, client, "POST", decLinkBase(args[2])+"/finalization", input)
			if e != nil {
				return e
			}
			if approve {
				result, e = signDecLink(ctx, client, result, fs)
				if e != nil {
					return e
				}
			}
			return decLinkViewOutput(out, result.Request)
		}
		input := host.DecLinkCommit{Owner: selection.Owner, Selection: value("selection", view.Selection), Administrator: value("administrator-offer", view.Administrator), Finalization: value("owner-finalization", view.Finalization), Network: selection.Network, Context: selection.Context, Person: selection.Person, Host: selection.Host, Device: selection.Device, Approve: approve}
		result, e := linkCall[host.DecConfirmationResult](ctx, client, "POST", decLinkBase(args[2])+"/commit", input)
		if e != nil {
			return e
		}
		return decLinkViewOutput(out, result.Request)
	case "approve", "admit":
		return runDecLinkApproval(ctx, client, command, fs, out, errOut)
	case "link", "resume":
		var result decCLILink
		var e error
		if command == "link" {
			renew, _ := fs.GetBool("renew")
			mode := "new"
			if renew {
				mode = "renew"
			}
			input := host.DecLinkCreate{Mode: mode, Network: linkFlag(fs, "network"), Person: linkFlag(fs, "expect-person"), Migration: "-", Invitation: "-", Helpers: []dec.ContactRelay{}}
			result, e = linkCall[decCLILink](ctx, client, "POST", "/v2/link/requests", input)
		} else {
			result, e = linkCall[decCLILink](ctx, client, "POST", decLinkBase(args[2])+"/resume", map[string]any{})
		}
		if e != nil {
			return e
		}
		if result.State == "linked" || result.State == "migration_prepared" || result.State == "migration_adopted" {
			return decLinkOutput(out, result, false)
		}
		if result.Role == "approver" {
			approval, e := linkCall[host.DecApprovalResult](ctx, client, "GET", decLinkBase(result.Request)+"/approval")
			if e != nil {
				return e
			}
			approval, e = signDecLink(ctx, client, approval, fs)
			if e != nil {
				return e
			}
			return decLinkViewOutput(out, approval.Request)
		}
		if !isTerminal(os.Stdin) {
			return decLinkOutput(out, result, display)
		}
		return guideDecLink(ctx, client, result, out, errOut, display)
	}
	return invalidCommand()
}

func guideDecLink(ctx context.Context, client host.Client, result decCLILink, out, errOut io.Writer, display bool) error {
	if display && result.Code != "" {
		fmt.Fprintf(errOut, "On an existing machine, approve this private code: %s\n", result.Code)
	}
	// After the one explicit display, ordinary polling never prints the secret.
	result.Code = ""
	for result.State != "linked" {
		base := decLinkBase(result.Request)
		switch result.State {
		case "needs_selection":
			input := host.DecLinkSelection{Owner: result.Owner, Network: result.Network, Context: result.Context, Person: result.Person, Host: result.Host, Device: result.Device}
			preview, e := linkCall[host.DecConfirmationResult](ctx, client, "POST", base+"/selection", input)
			if e != nil {
				return e
			}
			r := preview.Review
			fmt.Fprintf(errOut, "Select network %s, person %s, host %s, device %s, scopes %d, expires %s, provider %s\n", r.Network, r.Person, r.Host, r.Device, r.Scopes, r.NotAfter, r.Provider.Kind)
			if !askYes(errOut, "Select this exact owner offer?") {
				return decLinkViewOutput(out, preview.Request)
			}
			input.Approve = true
			selected, e := linkCall[host.DecConfirmationResult](ctx, client, "POST", base+"/selection", input)
			if e != nil {
				return e
			}
			if e = sameDecLinkReview(preview.Review, selected.Review); e != nil {
				return e
			}
			result.DecLinkView = selected.Request
		case "needs_commit":
			input := host.DecLinkCommit{Owner: result.Owner, Selection: result.Selection, Administrator: result.Administrator, Finalization: result.Finalization, Network: result.Network, Context: result.Context, Person: result.Person, Host: result.Host, Device: result.Device}
			preview, e := linkCall[host.DecConfirmationResult](ctx, client, "POST", base+"/commit", input)
			if e != nil {
				return e
			}
			r := preview.Review
			fmt.Fprintf(errOut, "Final network %s, person %s, owner %s, selection %s, administrator %s, finalization %s, binding %s, device lease %s, scopes %d, expires %s\n", r.Network, r.Person, r.Owner, r.Selection, r.Administrator, result.Finalization, r.BindingLease, r.DeviceLease, r.Scopes, r.NotAfter)
			if !askYes(errOut, "Commit this exact machine link?") {
				return decLinkViewOutput(out, preview.Request)
			}
			input.Approve = true
			committed, e := linkCall[host.DecConfirmationResult](ctx, client, "POST", base+"/commit", input)
			if e != nil {
				return e
			}
			if e = sameDecLinkReview(preview.Review, committed.Review); e != nil {
				return e
			}
			result.DecLinkView = committed.Request
		case "cancelled", "expired", "blocked", "migration_prepared":
			return decLinkOutput(out, result, false)
		default:
			fmt.Fprintln(errOut, "Linking:", result.State, strings.Join(result.Next, ", "))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second):
			}
			next, e := linkCall[decCLILink](ctx, client, "POST", base+"/resume", map[string]any{})
			if e != nil {
				return e
			}
			result = next
			result.Code = ""
		}
	}
	return decLinkOutput(out, result, false)
}

func runDecLinkApproval(ctx context.Context, client host.Client, command string, fs *pflag.FlagSet, out, errOut io.Writer) error {
	code, e := linkCodeInput(fs, errOut)
	if e != nil {
		return e
	}
	token, e := dec.ReadPairingToken(code)
	if e != nil {
		return e
	}
	now, e := host.DecentralizedDecisionTime()
	if e != nil {
		return e
	}
	if e = token.Current(now.UTC().Format("2006-01-02T15:04:05Z")); e != nil {
		return e
	}
	if token.Terms.Migration != "-" {
		return runDecMigrationLinkApproval(ctx, client, command, code, token, fs, out, errOut)
	}
	networkName := linkFlag(fs, "network")
	if networkName == "-" {
		networkName = token.Terms.Network
	}
	network, e := decLinkNetwork(ctx, client, networkName)
	possession := false
	if e != nil {
		if !errors.Is(e, errNotJoined) || command != "approve" || token.Terms.Mode != "new" || !dec.ValidID(token.Terms.Network, "net_") || !dec.ValidPublicKey(token.Terms.Person) || networkName != token.Terms.Network {
			return e
		}
		possession = true
	}
	networkID := network.ID
	if possession {
		networkID = token.Terms.Network
	}
	target := linkFlag(fs, "person")
	if target == "-" {
		target = token.Terms.Person
	}
	if target == "-" && command == "approve" {
		target = network.Person
	}
	if !dec.ValidPublicKey(target) {
		return errors.New("review the exact target original person public key with --person")
	}
	provider := linkFlag(fs, "signer")
	if provider == "person_root" {
		provider = target
	}
	if possession {
		if provider != "auto" && provider != "-" && provider != target {
			return errors.New("pending self consent requires that exact original person")
		}
		provider = target
	}
	format := "auto"
	if provider == "network_root" {
		format = "ed25519"
		if root, _ := fs.GetString("root-key"); root != "" {
			format = "sshsig"
		}
	} else if dec.ValidPublicKey(provider) {
		format = "sshsig"
	}
	expectedHost, expectedDevice := linkFlag(fs, "expect-host-key"), linkFlag(fs, "expect-device-key")
	if expectedHost == "-" {
		expectedHost = token.Terms.Host
	}
	if expectedDevice == "-" {
		expectedDevice = token.Terms.Device
	}
	approve, _ := fs.GetBool("approve")
	var result host.DecApprovalResult
	var submit func(bool) (host.DecApprovalResult, error)
	if command == "approve" {
		scopes, _ := fs.GetUint64("scopes")
		deadline, _ := fs.GetString("not-after")
		path := network.Provider
		if possession {
			if !fs.Changed("scopes") {
				scopes = 7
			}
		} else {
			if path == nil {
				return errors.New("this network has no selected owner provider; explicitly select the reviewed original/device provider")
			}
			if provider != "auto" && provider != "-" {
				preview, e := linkCall[struct {
					Provider *host.DecProviderView `json:"provider"`
				}](ctx, client, "POST", decNetworkPath(networkID)+"/provider", host.DecSelectProvider{Provider: provider, Person: target, Host: network.Host, Approve: false})
				if e != nil {
					return e
				}
				path = preview.Provider
			}
			if path == nil || path.Person != target {
				return errors.New("the reviewed owner does not match the selected provider")
			}
			if !fs.Changed("scopes") {
				scopes &= path.Scopes
			}
		}
		if deadline == "" {
			created, e := dec.ParseTime(token.Terms.Created)
			if e != nil {
				return e
			}
			deadline = created.Add(7 * 24 * time.Hour).UTC().Format("2006-01-02T15:04:05Z")
			if path != nil && path.NotAfter != "-" && path.NotAfter < deadline {
				deadline = path.NotAfter
			}
		}
		input := host.DecOwnerApproval{Code: code, Network: networkID, Person: target, Provider: provider, Format: format, Scopes: scopes, NotAfter: deadline, Host: expectedHost, Device: expectedDevice}
		submit = func(consent bool) (host.DecApprovalResult, error) {
			input.Approve = consent
			return linkCall[host.DecApprovalResult](ctx, client, "POST", "/v2/link/approvals", input)
		}
	} else {
		owner, selection := linkFlag(fs, "owner-offer"), linkFlag(fs, "selection")
		if owner == "-" || selection == "-" {
			return errors.New("administrator review requires --owner-offer and --selection")
		}
		input := host.DecAdministratorApproval{Code: code, Network: networkID, Person: target, Provider: provider, Format: format, Owner: owner, Selection: selection, Host: expectedHost, Device: expectedDevice}
		submit = func(consent bool) (host.DecApprovalResult, error) {
			input.Approve = consent
			return linkCall[host.DecApprovalResult](ctx, client, "POST", "/v2/link/admissions", input)
		}
	}
	result, e = submit(false)
	if e != nil {
		return e
	}
	if !approve && isTerminal(os.Stdin) {
		r := result.Review
		fmt.Fprintf(errOut, "Network %s, owner %s, host %s, device %s, scopes %d, expires %s, provider %s\n", r.Network, r.Person, r.Host, r.Device, r.Scopes, r.NotAfter, r.Provider.Kind)
		approve = askYes(errOut, "Approve this exact machine?")
	}
	if approve {
		preview := result.Review
		result, e = submit(true)
		if e != nil {
			return e
		}
		if e = sameDecLinkReview(preview, result.Review); e != nil {
			return e
		}
		result, e = signDecLink(ctx, client, result, fs)
		if e != nil {
			return e
		}
	}
	return decLinkViewOutput(out, result.Request)
}

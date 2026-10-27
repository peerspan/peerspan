package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/peerspan/peerspan/go/internal/person"
	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"
)

func decInvitationInput(ctx context.Context, fs *pflag.FlagSet, errOut io.Writer) (string, error) {
	fromStdin, _ := fs.GetBool("invite-stdin")
	path, _ := fs.GetString("invite-file")
	if fromStdin && path != "" {
		return "", errors.New("give only one private invitation input")
	}
	if path != "" {
		fd, e := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		if e != nil {
			return "", errors.New("cannot open the private invitation file")
		}
		file := os.NewFile(uintptr(fd), path)
		defer file.Close()
		info, e := file.Stat()
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return "", errors.New("the private invitation file must be regular and readable only by its owner")
		}
		var stat unix.Stat_t
		if e = unix.Fstat(fd, &stat); e != nil || stat.Uid != uint32(os.Geteuid()) {
			return "", errors.New("the private invitation file must belong to the current user")
		}
		raw, e := io.ReadAll(io.LimitReader(file, dec.MaxPairingToken+2))
		if e != nil || len(raw) > dec.MaxPairingToken+1 {
			return "", errors.New("invalid private invitation size")
		}
		value := strings.TrimSuffix(string(raw), "\n")
		if strings.ContainsAny(value, "\r\n") || len(value) > dec.MaxPairingToken {
			return "", errors.New("give one exact private invitation")
		}
		return value, nil
	}
	if fromStdin {
		value := readLine()
		if len(value) > dec.MaxPairingToken {
			return "", errors.New("invalid private invitation size")
		}
		return value, nil
	}
	return setupPrompt(ctx, errOut, "Private invitation (hidden)", "", true)
}
func inspectDecInvitation(token string) (*dec.ContactInvitation, error) {
	invitation, e := dec.ReadContactInvitation(token)
	if e != nil {
		return nil, e
	}
	now, e := host.DecentralizedDecisionTime()
	if e != nil {
		return nil, e
	}
	if e = invitation.Current(now.Format("2006-01-02T15:04:05Z")); e != nil {
		return nil, e
	}
	return invitation, nil
}
func createDecJoin(ctx context.Context, client host.Client, token, keyPath string, errOut io.Writer) (decCLILink, error) {
	var result decCLILink
	invitation, e := inspectDecInvitation(token)
	if e != nil {
		return result, e
	}
	// Introduction framing, signature, identity and current window are reviewed
	// before key choice or any local enrollment/service mutation.
	genesis, e := membership.DecodeKey(invitation.Descriptor.GenesisRootPublicKey)
	if e != nil {
		return result, e
	}
	fingerprint := sha256.Sum256(genesis)
	fmt.Fprintf(errOut, "Introduction: network %s (%s), context %s, genesis fingerprint SHA256:%x, inviter host %s, proposed member %s, person-key pin %s. An administrator must still approve this exact machine.\n", invitation.Descriptor.Name, invitation.Descriptor.NetworkID, invitation.Context, fingerprint, invitation.Host, invitation.Member, invitation.Person)
	var choice *person.Choice
	if keyPath != "" {
		choice, e = person.Choose(keyPath)
	} else {
		choice, e = person.DiscoverChoice()
		if e != nil {
			return result, e
		}
		question := "Create a new original person on this machine? (y/N)"
		if choice != nil {
			public := membership.EncodeKey(choice.PublicKey())
			if invitation.Person != "-" && public != invitation.Person {
				_ = choice.Close()
				return result, errors.New("the existing original differs from the introduction; select the exact --person-key on its own machine")
			}
			question = "Use existing original person " + public + "? (y/N)"
		} else if invitation.Person != "-" {
			return result, errors.New("the pinned original key is unavailable; select the exact --person-key on its own machine")
		}
		answer, err := setupPrompt(ctx, errOut, question, "no", false)
		if err != nil || !strings.EqualFold(strings.TrimSpace(answer), "y") && !strings.EqualFold(strings.TrimSpace(answer), "yes") {
			if choice != nil {
				_ = choice.Close()
			}
			if err != nil {
				return result, err
			}
			return result, errors.New("original identity not selected; use --person-key for an explicit selection")
		}
		if choice == nil {
			choice, e = person.Choose("")
			if e == nil && choice.Source != person.SourceNew {
				_ = choice.Close()
				return result, errors.New("an existing original appeared during review; select its exact --person-key")
			}
		}
	}
	if e != nil {
		return result, e
	}
	defer choice.Close()
	public := membership.EncodeKey(choice.PublicKey())
	if invitation.Person != "-" && public != invitation.Person {
		return result, errors.New("the selected original key does not match this exact invitation; keep each original key on its own machine")
	}
	fmt.Fprintf(errOut, "Selected original person: %s\n", public)
	if e = choice.Save("peerspan original person " + invitation.Member); e != nil {
		return result, e
	}
	result, e = linkCall[decCLILink](ctx, client, "POST", "/v2/link/requests", host.DecLinkCreate{Mode: "new", Network: invitation.Descriptor.NetworkID, Person: public, Migration: "-", Invitation: token, Helpers: invitation.Helpers})
	if e != nil {
		return result, e
	}
	if result.Network != invitation.Descriptor.NetworkID || result.Context != invitation.Context || result.Person != public {
		return result, errors.New("request creation changed the reviewed introduction or original identity")
	}
	fmt.Fprintln(errOut, "Return the private reply code to the inviting machine for explicit approval. No membership has been granted by the introduction.")
	return result, nil
}
func onboardDecJoin(ctx context.Context, client host.Client, fs *pflag.FlagSet, errOut io.Writer, complete func(map[string]any) error) error {
	for _, flag := range []string{"token", "descriptor", "coordinator", "coordinator-key", "no-person"} {
		if fs.Lookup(flag) != nil && fs.Changed(flag) {
			return errors.New("new join uses a private psi2 introduction; use --invite-stdin/--invite-file and explicit approved linking")
		}
	}
	token, e := decInvitationInput(ctx, fs, errOut)
	if e != nil {
		return e
	}
	result, e := createDecJoin(ctx, client, token, personKey(fs), errOut)
	if e != nil {
		return e
	}
	var output bytes.Buffer
	var guideError error
	if isTerminal(os.Stdin) {
		guideError = guideDecLink(ctx, client, result, &output, errOut, true)
	} else {
		if e = printJSON(&output, result); e != nil {
			return e
		}
		if result.State != "linked" {
			guideError = exitStatus(1)
		}
	}
	if output.Len() > 0 {
		var value map[string]any
		if e = json.Unmarshal(output.Bytes(), &value); e != nil {
			return e
		}
		if e = complete(value); e != nil {
			return e
		}
	}
	return guideError
}

func runDecInvitation(ctx context.Context, client host.Client, fs *pflag.FlagSet, out, errOut io.Writer) error {
	for _, flag := range []string{"expires-at", "expires-in", "host-only", "person-key", "root-key"} {
		if fs.Lookup(flag) != nil && fs.Changed(flag) {
			return errors.New("a psi2 introduction has a fixed five-minute contact window and grants no authority; use explicit machine approval")
		}
	}
	network, e := decLinkNetwork(ctx, client, linkFlag(fs, "network"))
	if e != nil {
		return e
	}
	member, _ := fs.GetString("member")
	if !membership.ValidLabel(member) {
		return errors.New("invite needs the reviewed member label")
	}
	raw, e := client.Call(ctx, "POST", decNetworkPath(network.ID)+"/invitations", host.DecInvitationRequest{Member: member, Person: "-"})
	if e != nil {
		return e
	}
	fmt.Fprintln(errOut, "This private introduction grants no membership. The joining machine returns a private reply code for explicit owner and administrator approval.")
	return printJSON(out, json.RawMessage(raw))
}

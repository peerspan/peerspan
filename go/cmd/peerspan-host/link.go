package main

import (
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

	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/peerspan/peerspan/go/internal/person"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"
)

func linkCall[T any](ctx context.Context, client host.Client, method, path string, bodies ...any) (T, error) {
	var value T
	var body any
	if len(bodies) > 0 {
		body = bodies[0]
	}
	raw, err := client.Call(ctx, method, path, body)
	if err != nil {
		return value, err
	}
	err = json.Unmarshal(raw, &value)
	return value, err
}

func configureLinkFlags(cmd *cobra.Command, args []string) {
	fs := cmd.Flags()
	command := args[len(args)-1]
	switch command {
	case "link":
		fs.Bool("renew", false, "renew the same existing host and device")
		fs.String("network", "", "expected network ID")
		fs.String("expect-person", "", "expected original person public key")
		fs.String("coordinator", "", "pinned coordinator HOST:PORT")
		fs.String("coordinator-key", "", "pinned coordinator public key")
	case "approve", "admit":
		fs.String("network", "", "network ID")
		fs.String("person", "", "reviewed selected owner's person ID")
		fs.String("expect-host-key", "", "reviewed host public key")
		fs.String("expect-device-key", "", "reviewed device public key")
		fs.String("signer", "auto", "auto, person_root, network_root or exact device certificate ID")
		fs.Bool("code-stdin", false, "read the private code from stdin")
		fs.Bool("approve", false, "approve the exact reviewed person and host/device keys")
		fs.String("person-key", "", "original person SSH key")
		fs.String("root-key", "", "original network root SSH key")
	case "select", "commit":
		fs.String("owner-offer", "", "exact reviewed owner offer ID")
		fs.String("network", "", "reviewed network ID")
		fs.String("expect-person", "", "reviewed original person public key")
		fs.String("expect-host-key", "", "reviewed host public key")
		fs.String("expect-device-key", "", "reviewed device public key")
		fs.Bool("approve", false, "consent to every exact reviewed reference")
		if command == "commit" {
			fs.String("selection", "", "exact reviewed selection ID")
			fs.String("administrator-offer", "", "exact reviewed administrator offer ID, or - for renew")
		}
	case "resume":
		fs.String("person-key", "", "the same reviewed original person SSH key")
		fs.String("root-key", "", "the same reviewed original network root SSH key")
	}
}
func linkFlag(fs *pflag.FlagSet, name string) string {
	value, _ := fs.GetString(name)
	if value == "" {
		return "-"
	}
	return value
}
func linkCodeInput(fs *pflag.FlagSet, errOut io.Writer) (string, error) {
	fromStdin, _ := fs.GetBool("code-stdin")
	if fromStdin {
		return readLine(), nil
	}
	if !isTerminal(os.Stdin) {
		return "", errors.New("enter the private linking code with --code-stdin")
	}
	fd := int(os.Stdin.Fd())
	settings, e := unix.IoctlGetTermios(fd, unix.TCGETS)
	if e != nil {
		return "", e
	}
	hidden := *settings
	hidden.Lflag &^= unix.ECHO
	if e = unix.IoctlSetTermios(fd, unix.TCSETS, &hidden); e != nil {
		return "", e
	}
	defer unix.IoctlSetTermios(fd, unix.TCSETS, settings)
	fmt.Fprint(errOut, "Private linking code: ")
	code := readLine()
	fmt.Fprintln(errOut)
	return code, nil
}
func signLinkRequests(ctx context.Context, client host.Client, result host.LinkApprovalResult, fs *pflag.FlagSet) (host.LinkApprovalResult, error) {
	for len(result.SigningRequests) > 0 {
		request := result.SigningRequests[0]
		keyPath, _ := fs.GetString("person-key")
		rootPath, _ := fs.GetString("root-key")
		paths := []string{}
		if keyPath != "" {
			paths = append(paths, keyPath)
		}
		if rootPath != "" && rootPath != keyPath {
			paths = append(paths, rootPath)
		}
		if len(paths) == 0 {
			paths = append(paths, "")
		}
		var signer person.Signer
		for _, path := range paths {
			chosen, e := person.Load(path)
			if e != nil {
				return result, e
			}
			if membership.EncodeKey(chosen.PublicKey()) == request.SignerPublicKey {
				signer = chosen
				break
			}
			_ = chosen.Close()
		}
		if signer == nil {
			return result, errors.New("the explicitly selected original keys do not match the reviewed signer")
		}
		message, e := base64.StdEncoding.Strict().DecodeString(request.MessageBase64)
		if e != nil {
			_ = signer.Close()
			return result, e
		}
		signature, e := membership.SignSSHSIG(signer, message)
		_ = signer.Close()
		if e != nil {
			return result, e
		}
		data, e := client.Call(ctx, "POST", "/v1/link/requests/"+url.PathEscape(result.Request.RequestID)+"/signed", map[string]string{"object_type": request.ObjectType, "signature": signature})
		if e != nil {
			return result, e
		}
		if e = json.Unmarshal(data, &result); e != nil {
			return result, e
		}
	}
	return result, nil
}
func runLinkFeature(ctx context.Context, client host.Client, fs *pflag.FlagSet, out io.Writer) error {
	network := linkFlag(fs, "network")
	result, e := linkCall[host.LinkFeatureView](ctx, client, "POST", "/v1/networks/"+url.PathEscape(network)+"/link-feature", map[string]bool{"activate": true})
	if e != nil {
		return e
	}
	if len(result.SigningRequests) > 0 {
		request := result.SigningRequests[0]
		path, _ := fs.GetString("root-key")
		if path == "" {
			if e = printJSON(out, result); e != nil {
				return e
			}
			return errors.New("the current root key is required; use --root-key with the reviewed root")
		}
		signer, e := person.Load(path)
		if e != nil {
			return e
		}
		defer signer.Close()
		if membership.EncodeKey(signer.PublicKey()) != request.SignerPublicKey {
			return errors.New("the explicit root key does not match the current network root")
		}
		message, e := base64.StdEncoding.Strict().DecodeString(request.MessageBase64)
		if e != nil {
			return e
		}
		signature, e := membership.SignSSHSIG(signer, message)
		if e != nil {
			return e
		}
		result, e = linkCall[host.LinkFeatureView](ctx, client, "POST", "/v1/networks/"+url.PathEscape(network)+"/link-feature/signed", map[string]string{"signature": signature})
		if e != nil {
			return e
		}
	}
	if e = printJSON(out, result); e != nil {
		return e
	}
	if result.State != "active" {
		return exitStatus(1)
	}
	return nil
}
func runLink(ctx context.Context, client host.Client, args []string, fs *pflag.FlagSet, out, errOut io.Writer) error {
	return runLinkWithCodeDisplay(ctx, client, args, fs, out, errOut, true)
}

func runLinkWithCodeDisplay(ctx context.Context, client host.Client, args []string, fs *pflag.FlagSet, out, errOut io.Writer, displayCode bool) error {
	command := "link"
	if len(args) > 1 {
		command = args[1]
	}
	switch command {
	case "approve", "admit":
		code, e := linkCodeInput(fs, errOut)
		if e != nil {
			return e
		}
		approve, _ := fs.GetBool("approve")
		input := host.ApproveLink{Code: code, NetworkID: linkFlag(fs, "network"), ExpectedPersonID: linkFlag(fs, "person"), ExpectedHostKey: linkFlag(fs, "expect-host-key"), ExpectedDeviceKey: linkFlag(fs, "expect-device-key"), Signer: linkFlag(fs, "signer"), Approve: approve}
		path := "/v1/link/approvals"
		if command == "admit" {
			path = "/v1/link/admissions"
		}
		result, e := linkCall[host.LinkApprovalResult](ctx, client, "POST", path, input)
		if e != nil {
			return e
		}
		if !approve && isTerminal(os.Stdin) {
			fmt.Fprintf(errOut, "Network %s, person %s, host %s, device %s, scopes %d, expires %s, signer %s\n", result.Review.NetworkID, result.Review.PersonID, result.Review.HostPublicKey, result.Review.DevicePublicKey, result.Review.Scopes, result.Review.NotAfter, result.Review.SignerPublicKey)
			if askYes(errOut, "Approve this exact machine?") {
				input.Approve = true
				input.ExpectedPersonID, input.ExpectedHostKey, input.ExpectedDeviceKey = result.Review.PersonID, result.Review.HostPublicKey, result.Review.DevicePublicKey
				result, e = linkCall[host.LinkApprovalResult](ctx, client, "POST", path, input)
				if e != nil {
					return e
				}
				approve = true
			}
		}
		if approve {
			result, e = signLinkRequests(ctx, client, result, fs)
			if e != nil {
				return e
			}
		}
		return printJSON(out, result)
	case "status":
		path := "/v1/link/requests"
		if len(args) == 3 {
			path += "/" + url.PathEscape(args[2])
		}
		raw, e := client.Call(ctx, "GET", path, nil)
		if e != nil {
			return e
		}
		return printJSON(out, json.RawMessage(raw))
	case "cancel":
		raw, e := client.Call(ctx, "POST", "/v1/link/requests/"+url.PathEscape(args[2])+"/cancel", map[string]any{})
		if e != nil {
			return e
		}
		return printJSON(out, json.RawMessage(raw))
	case "select":
		approve, _ := fs.GetBool("approve")
		input := host.SelectLink{OwnerOfferID: linkFlag(fs, "owner-offer"), NetworkID: linkFlag(fs, "network"), PersonPublicKey: linkFlag(fs, "expect-person"), HostPublicKey: linkFlag(fs, "expect-host-key"), DevicePublicKey: linkFlag(fs, "expect-device-key"), Approve: approve}
		raw, e := client.Call(ctx, "POST", "/v1/link/requests/"+url.PathEscape(args[2])+"/selection", input)
		if e != nil {
			return e
		}
		return printJSON(out, json.RawMessage(raw))
	case "commit":
		approve, _ := fs.GetBool("approve")
		input := host.CommitLink{OwnerOfferID: linkFlag(fs, "owner-offer"), SelectionID: linkFlag(fs, "selection"), AdministratorOfferID: linkFlag(fs, "administrator-offer"), NetworkID: linkFlag(fs, "network"), PersonPublicKey: linkFlag(fs, "expect-person"), HostPublicKey: linkFlag(fs, "expect-host-key"), DevicePublicKey: linkFlag(fs, "expect-device-key"), Approve: approve}
		raw, e := client.Call(ctx, "POST", "/v1/link/requests/"+url.PathEscape(args[2])+"/commit", input)
		if e != nil {
			return e
		}
		return printJSON(out, json.RawMessage(raw))
	case "link", "resume":
		var result host.LinkRequestResult
		var e error
		if command == "link" {
			renew, _ := fs.GetBool("renew")
			mode := "new"
			if renew {
				mode = "renew"
			}
			result, e = linkCall[host.LinkRequestResult](ctx, client, "POST", "/v1/link/requests", host.CreateLinkRequest{Mode: mode, NetworkID: linkFlag(fs, "network"), PersonPublicKey: linkFlag(fs, "expect-person"), CoordinatorAddress: linkFlag(fs, "coordinator"), CoordinatorPublicKey: linkFlag(fs, "coordinator-key")})
		} else {
			result, e = linkCall[host.LinkRequestResult](ctx, client, "POST", "/v1/link/requests/"+url.PathEscape(args[2])+"/resume", map[string]any{})
		}
		if e != nil {
			return e
		}
		if command == "resume" {
			approval, readErr := linkCall[host.LinkApprovalResult](ctx, client, "GET", "/v1/link/requests/"+url.PathEscape(result.RequestID)+"/approval")
			var failure *host.ClientError
			if readErr == nil {
				approval, e = signLinkRequests(ctx, client, approval, fs)
				if e != nil {
					return e
				}
				if e = printJSON(out, approval.Request); e != nil {
					return e
				}
				if approval.Request.State != "linked" {
					return exitStatus(1)
				}
				return nil
			} else if !errors.As(readErr, &failure) || failure.Status != 409 {
				return readErr
			}
		}
		if !isTerminal(os.Stdin) {
			if e = printJSON(out, result); e != nil {
				return e
			}
			if result.State != "linked" {
				return exitStatus(1)
			}
			return nil
		}
		if displayCode && result.DisplayCode != "" {
			fmt.Fprintf(errOut, "On an existing machine, approve this private code: %s\n", result.DisplayCode)
		}
		for result.State != "linked" {
			base := "/v1/link/requests/" + url.PathEscape(result.RequestID)
			if result.State == "waiting_selection" {
				preview, e := linkCall[host.LinkSelectionResult](ctx, client, "POST", base+"/selection", host.SelectLink{OwnerOfferID: "-", NetworkID: "-", PersonPublicKey: "-", HostPublicKey: "-", DevicePublicKey: "-"})
				if e != nil {
					return e
				}
				review := preview.Review
				fmt.Fprintf(errOut, "Select network %s, person %s, host %s, device %s, scopes %d, expires %s, issuer %s\n", review.NetworkID, review.PersonID, review.HostPublicKey, review.DevicePublicKey, review.Scopes, review.NotAfter, review.SignerPublicKey)
				if !askYes(errOut, "Select this exact owner offer?") {
					return printJSON(out, preview)
				}
				selected, e := linkCall[host.LinkSelectionResult](ctx, client, "POST", base+"/selection", host.SelectLink{OwnerOfferID: review.OwnerOfferID, NetworkID: review.NetworkID, PersonPublicKey: review.PersonPublicKey, HostPublicKey: review.HostPublicKey, DevicePublicKey: review.DevicePublicKey, Approve: true})
				if e != nil {
					return e
				}
				result.LinkRequestView = selected.Request
			}
			if result.State == "ready_to_commit" {
				preview, e := linkCall[host.LinkCommitResult](ctx, client, "POST", base+"/commit", host.CommitLink{OwnerOfferID: "-", SelectionID: "-", AdministratorOfferID: "-", NetworkID: "-", PersonPublicKey: "-", HostPublicKey: "-", DevicePublicKey: "-"})
				if e != nil {
					return e
				}
				review := preview.Review
				fmt.Fprintf(errOut, "Final network %s, person %s, owner %s, selection %s, administrator %s, admission %s, administrator signer %s\n", review.NetworkID, review.PersonID, review.OwnerOfferID, review.SelectionID, review.AdministratorOfferID, review.AdmissionRecordID, review.AdministratorSignerPublicKey)
				if !askYes(errOut, "Commit this exact machine link?") {
					return printJSON(out, preview)
				}
				committed, e := linkCall[host.LinkCommitResult](ctx, client, "POST", base+"/commit", host.CommitLink{OwnerOfferID: review.OwnerOfferID, SelectionID: review.SelectionID, AdministratorOfferID: review.AdministratorOfferID, NetworkID: review.NetworkID, PersonPublicKey: review.PersonPublicKey, HostPublicKey: review.HostPublicKey, DevicePublicKey: review.DevicePublicKey, Approve: true})
				if e != nil {
					return e
				}
				result.LinkRequestView = committed.Request
				continue
			}
			if result.State == "cancelled" || result.State == "expired" || result.State == "incomplete" {
				if e = printJSON(out, result); e != nil {
					return e
				}
				return exitStatus(1)
			}
			fmt.Fprintln(errOut, "Linking:", result.State, strings.Join(result.Next, ", "))
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second):
			}
			result, e = linkCall[host.LinkRequestResult](ctx, client, "POST", base+"/resume", map[string]any{})
			if e != nil {
				return e
			}
		}
		return printJSON(out, result.LinkRequestView)
	}
	return invalidCommand()
}

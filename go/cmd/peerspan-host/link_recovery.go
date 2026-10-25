package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"

	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/peerspan/peerspan/go/internal/person"
	"github.com/spf13/pflag"
)

func runFeatureImport(ctx context.Context, client host.Client, network string, fs *pflag.FlagSet, out, errOut io.Writer) error {
	address, key := linkFlag(fs, "coordinator"), linkFlag(fs, "coordinator-key")
	if address == "-" || key == "-" {
		return errors.New("network repair requires paired --coordinator and --coordinator-key")
	}
	approve, _ := fs.GetBool("approve")
	id := linkFlag(fs, "import-id")
	if approve && id == "-" && !isTerminal(os.Stdin) {
		return errors.New("preview network repair first, then use --approve --import-id with its exact reviewed intent")
	}
	base := "/v1/networks/" + url.PathEscape(network) + "/feature-import"
	input := host.FeatureImportRequest{CoordinatorAddress: address, CoordinatorPublicKey: key, ImportID: id, Approve: approve && id != "-"}
	result, e := linkCall[host.FeatureImportResult](ctx, client, "POST", base, input)
	if e != nil {
		return e
	}
	if !approve && !result.Committed || approve && id == "-" {
		fmt.Fprintf(errOut, "Network %s (%s), feature %s, target %s, key %s, snapshot %s, expires %s, current root %s\n", result.Review.NetworkName, result.Review.NetworkID, result.Review.FeatureID, result.Review.CoordinatorAddress, result.Review.CoordinatorPublicKey, result.Review.CatalogSHA256, result.Review.ExpiresAt, result.Review.SignerPublicKey)
		if isTerminal(os.Stdin) && askYes(errOut, "Approve this exact root recovery?") {
			input.ImportID, input.Approve = result.ImportID, true
			result, e = linkCall[host.FeatureImportResult](ctx, client, "POST", base, input)
			if e != nil {
				return e
			}
			approve = true
		}
	}
	if approve && !result.Committed && len(result.SigningRequests) == 0 {
		result, e = linkCall[host.FeatureImportResult](ctx, client, "POST", base+"/"+url.PathEscape(result.ImportID)+"/resume", map[string]any{})
		if e != nil {
			return e
		}
	}
	for approve && len(result.SigningRequests) > 0 {
		request := result.SigningRequests[0]
		path, _ := fs.GetString("root-key")
		if path == "" {
			if e = printJSON(out, result); e != nil {
				return e
			}
			return errors.New("the exact reviewed current root key is required; use --root-key")
		}
		signer, e := person.Load(path)
		if e != nil {
			return e
		}
		if membership.EncodeKey(signer.PublicKey()) != request.SignerPublicKey {
			_ = signer.Close()
			return errors.New("the original root key does not match the reviewed current root")
		}
		message, e := base64.StdEncoding.Strict().DecodeString(request.MessageBase64)
		if e != nil {
			_ = signer.Close()
			return e
		}
		signature, e := membership.SignSSHSIG(signer, message)
		_ = signer.Close()
		if e != nil {
			return e
		}
		result, e = linkCall[host.FeatureImportResult](ctx, client, "POST", base+"/"+url.PathEscape(result.ImportID)+"/signed", map[string]string{"object_type": "feature_import", "signature": signature})
		if e != nil {
			return e
		}
	}
	if e = printJSON(out, result); e != nil {
		return e
	}
	if !result.Committed {
		return exitStatus(1)
	}
	return nil
}

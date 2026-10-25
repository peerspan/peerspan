package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/peerspan/peerspan/go/internal/host"
	"github.com/peerspan/peerspan/go/internal/membership"
)

func localInviteCatalog(ctx context.Context, client host.Client, network string) ([]byte, error) {
	var result struct {
		Catalog json.RawMessage `json:"catalog"`
	}
	raw, e := client.Call(ctx, "GET", "/v1/networks/"+url.PathEscape(network)+"/link-catalog", nil)
	if e != nil {
		var failure *host.ClientError
		if errors.As(e, &failure) && (failure.Status == 426 || failure.Status == 404) {
			return nil, nil
		}
		return nil, e
	}
	if json.Unmarshal(raw, &result) != nil || len(result.Catalog) == 0 {
		return nil, errors.New("invalid verified invitation catalog")
	}
	return result.Catalog, nil
}

type linkInviteSubmission struct {
	Network  host.Network
	Selected host.LinkSignerView
	Route    string
	Request  host.CreateInvite
}

func (s linkInviteSubmission) submit(ctx context.Context, client host.Client) (json.RawMessage, error) {
	if !membership.ValidLabel(s.Request.Member) {
		return nil, errors.New("invalid member label")
	}
	now, e := host.LinkingDecisionTime()
	if e != nil {
		return nil, e
	}
	expires, e := membership.ParseTime(s.Request.ExpiresAt)
	if e != nil {
		return nil, e
	}
	expires = expires.UTC().Truncate(time.Second)
	if s.Selected.NotAfter != "-" {
		limit, e := membership.ParseTime(s.Selected.NotAfter)
		if e != nil {
			return nil, e
		}
		if limit.Before(expires) {
			expires = limit
		}
	}
	if !expires.After(now) || expires.After(now.Add(30*24*time.Hour)) {
		return nil, errors.New("invite expiration must be in the next 30 days and within the selected path")
	}
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, e
	}
	mode := "member"
	if s.Request.HostOnly {
		mode = "host"
	}
	if strings.HasSuffix(s.Route, "/person-invites") {
		mode = "person"
	}
	var hostInvite, personInvite, catalog []byte
	base := "/v1/networks/" + url.PathEscape(s.Network.ID)
	for _, half := range []string{"host", "person"} {
		if half == "host" && mode == "person" || half == "person" && mode == "host" {
			continue
		}
		kind := "peerspan-invite-v1"
		fields := map[string]any{"network_id": s.Network.ID, "invite_public_key": membership.PublicKey(key), "member": s.Request.Member, "invite_expires_at": expires.Format(time.RFC3339)}
		if half == "person" {
			kind = "peerspan-person-invite-v1"
			fields["invite_epoch"] = s.Network.RootEpoch
		}
		payload, e := json.Marshal(fields)
		if e != nil {
			return nil, e
		}
		result, e := linkCall[host.LinkActionResult](ctx, client, "POST", base+"/link-actions", host.LinkActionRequest{Kind: kind, PayloadBase64: base64.StdEncoding.EncodeToString(payload), CertificateID: s.Selected.CertificateID})
		if e != nil {
			return nil, e
		}
		record, e := base64.StdEncoding.Strict().DecodeString(result.RecordBase64)
		if e != nil {
			return nil, e
		}
		if half == "host" {
			hostInvite = record
		} else {
			personInvite = record
		}
		catalog = result.Catalog
	}
	inner, e := host.NewAuthorizedInvite(s.Network, mode, membership.Seed(key), hostInvite, personInvite, catalog)
	if e != nil {
		return nil, e
	}
	unsigned, _, e := host.InviteFeatureIntent(s.Network, catalog, inner, "person", s.Selected.PersonPublicKey, s.Selected.CertificateID, s.Selected.DevicePublicKey, now)
	if e != nil {
		return nil, e
	}
	binding, e := linkCall[host.LinkActionResult](ctx, client, "POST", base+"/link-actions", host.LinkActionRequest{Kind: "invite_feature", PayloadBase64: base64.StdEncoding.EncodeToString(unsigned), CertificateID: s.Selected.CertificateID})
	if e != nil {
		return nil, e
	}
	public, e := base64.StdEncoding.Strict().DecodeString(binding.RecordBase64)
	if e != nil {
		return nil, e
	}
	token, e := host.EncodeFeatureInvite(s.Network, inner, binding.Catalog, public, now)
	if e != nil {
		return nil, e
	}
	return client.Call(ctx, "POST", s.Route, host.CreateInvite{Token: token})
}

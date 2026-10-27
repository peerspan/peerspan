package host

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
)

// Only the read-only status call installs this local decision-time sample.
// It is not an input field, remote timestamp, admission or authorization flag.
type decStatusReadKey struct{}

func decProductReadNow(ctx context.Context) (time.Time, error) {
	if now, ok := ctx.Value(decStatusReadKey{}).(time.Time); ok {
		return now, nil
	}
	return decNow()
}

type DecStatusView struct {
	HostID       string             `json:"host_id"`
	Version      string             `json:"version"`
	Networks     []json.RawMessage  `json:"networks"`
	Blocks       int64              `json:"blocks"`
	Agents       []AgentStatus      `json:"agents"`
	Artifacts    ArtifactUsage      `json:"artifacts"`
	Capabilities CapabilitiesStatus `json:"capabilities"`
	Attention    []AttentionItem    `json:"attention"`
}
type decLegacyHistoryView struct {
	NetworkStatus
	Mode              string `json:"mode"`
	MigrationRequired bool   `json:"migration_required"`
}

func decStatusUnavailable(snapshot *decSnapshot, e error) DecNetworkView {
	n, d := snapshot.Network, snapshot.Descriptor
	view := DecNetworkView{ID: d.NetworkID, Name: d.Name, Mode: "decentralized", Context: d.ContextID, Genesis: d.GenesisRootPublicKey, Root: "-", RootKey: "-", Member: n.Own.Member, Host: n.Own.Host, Person: n.Own.Person, Created: n.Created, Authority: DecAuthorityView{dec.Code(e), "-", dec.RequiredIDs(e), []string{}}, Delivery: snapshot.Delivery, ProviderState: DecProviderState{"not_selected", "-", "-", []string{}}}
	for _, row := range snapshot.Prior.Maxima {
		if len(row.Stream) == 1 && row.Stream[0] == "root" {
			view.RootEpoch = row.Sequence
		}
	}
	if selected := snapshot.Provider; selected != nil {
		kind := "original_person"
		if selected.Kind == "device" {
			kind = "device"
		}
		view.Provider = &DecProviderView{kind, selected.Person, n.Own.Host, selected.Device, selected.Lease, "-", 0, "-"}
		view.ProviderState = decUnavailable(e)
	}
	return view
}
func decNetworkAttention(view DecNetworkView, guard string) *AttentionItem {
	state := view.Authority.State
	if state == "usable" {
		return nil
	}
	kind := "network_authority_expired"
	command := "peerspan network sync " + view.ID
	detail := "network authority requires repair: " + state
	switch state {
	case "proof_required":
		kind = "network_proof_required"
	case "state_conflict":
		kind = "network_state_conflict"
	case "clock_rollback":
		kind = "network_clock_rollback"
		detail += "; correct local UTC or wait until retained guard " + guard + " and rerun the command; the guard cannot be lowered or reset"
	case "migration_pending":
		kind = "network_migration_pending"
		command = "peerspan network migrate resume " + view.ID
	}
	if view.Authority.NotAfter != "-" {
		detail += "; deadline " + view.Authority.NotAfter
	}
	if len(view.Authority.Required) > 0 {
		detail += "; required_ids " + strings.Join(view.Authority.Required, ",")
	}
	if len(view.Authority.Conflicts) > 0 {
		detail += "; conflict_ids " + strings.Join(view.Authority.Conflicts, ",")
	}
	return &AttentionItem{kind, view.ID, detail, command}
}
func (s *Store) DecentralizedStatus(ctx context.Context) (DecStatusView, error) {
	now, e := decNow()
	if e != nil {
		return DecStatusView{}, e
	}
	ctx = context.WithValue(ctx, decStatusReadKey{}, now)
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return DecStatusView{}, e
	}
	defer tx.Rollback()
	common, e := s.statusIn(ctx, tx, time.Now(), true)
	if e != nil {
		return DecStatusView{}, e
	}
	result := DecStatusView{common.HostID, common.Version, []json.RawMessage{}, common.Blocks, common.Agents, common.Artifacts, common.Capabilities, common.Attention}
	byID := map[string]json.RawMessage{}
	for _, legacy := range common.Networks {
		raw, e := json.Marshal(decLegacyHistoryView{legacy, "legacy_history", true})
		if e != nil {
			return result, e
		}
		byID[legacy.ID] = raw
	}
	ids, e := s.networkIDs(ctx, tx)
	if e != nil {
		return result, e
	}
	for _, id := range ids {
		if _, legacy := byID[id]; legacy {
			continue
		}
		snapshot, e := s.loadDecSnapshot(ctx, tx, id)
		if e != nil {
			return result, e
		}
		projection, projectionError := verifyDecSnapshot(snapshot, linkTime(now))
		var view DecNetworkView
		if projectionError != nil {
			if dec.Code(projectionError) != "clock_rollback" {
				return result, projectionError
			}
			view = decStatusUnavailable(snapshot, projectionError)
		} else {
			view = s.decNetworkView(snapshot, projection)
		}
		if item := decNetworkAttention(view, snapshot.Prior.ClockGuard); item != nil {
			result.Attention = append(result.Attention, *item)
		}
		if snapshot.Provider != nil {
			providerError := projectionError
			var provider *DecProviderView
			if providerError == nil {
				provider, providerError = decPublicProvider(snapshot, projection)
			}
			if providerError == nil && (provider == nil || provider.Person != snapshot.Provider.Person || provider.Scopes&1 == 0) {
				providerError = decFailure("forbidden")
			}
			state := decUnavailable(providerError)
			if providerError == nil {
				state = s.decProviderAvailable(snapshot, provider, nil)
			}
			if state.State != "available" && (snapshot.Provider.Kind == "device" || state.Code == "signer_unavailable") {
				kind := "person_agent_unreachable"
				detail := "the selected original provider is unavailable: " + state.Code
				if snapshot.Provider.Kind == "device" {
					kind = "person_device_signer_unavailable"
					detail = "the selected device policy provider is unavailable: " + state.Code
				}
				if len(state.Required) > 0 {
					detail += "; required_ids " + strings.Join(state.Required, ",")
				}
				result.Attention = append(result.Attention, AttentionItem{kind, id, detail, "peerspan network sync " + id})
			}
		}
		raw, e := json.Marshal(view)
		if e != nil {
			return result, fmt.Errorf("status view: %w", e)
		}
		byID[id] = raw
	}
	keys := sortedKeys(byID)
	sort.Strings(keys)
	for _, id := range keys {
		result.Networks = append(result.Networks, byID[id])
	}
	SortAttention(result.Attention)
	return result, nil
}

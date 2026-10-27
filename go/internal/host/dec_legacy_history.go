package host

import (
	"context"
	"database/sql"
	"net/http"
	"strings"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

func (s *Store) publicDecRuntime() bool {
	s.decTransport.mu.RLock()
	defer s.decTransport.mu.RUnlock()
	return s.decTransport.Configured
}

func (s *Store) decHistoryPeerMutation(r *http.Request) bool {
	return s.publicDecRuntime() && r.Method != http.MethodGet && strings.HasPrefix(r.URL.Path, "/peer/v1/networks/")
}

func (s *Store) decHistoryRoutes(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.publicDecRuntime() && r.Method != "GET" && (r.URL.Path == "/v1/networks" || strings.HasPrefix(r.URL.Path, "/v1/networks/") || strings.HasPrefix(r.URL.Path, "/v1/link/")) {
			parts := strings.Split(r.URL.Path, "/")
			if r.Method == "POST" && len(parts) == 6 && parts[1] == "v1" && parts[2] == "link" && parts[3] == "requests" && (parts[5] == "resume" || parts[5] == "cancel") {
				var input struct{}
				if !decodeLinkMutation(w, r, "", &input) {
					return
				}
				if parts[5] == "resume" {
					value, e := s.resumeHistoricalLink(r.Context(), parts[4])
					respondLink(w, 200, value, e, parts[4], "resume")
					return
				}
				pending, e := readLinkPending(r.Context(), s.db, parts[4])
				if e == nil && (pending.Record.CommitApproved || pending.Record.CommitPacketBase64 != "-") {
					e = linkFail("recovery_required", parts[4], "resume")
				}
				if e != nil {
					respondLink(w, 0, nil, e, parts[4], "cancel")
					return
				}
				value, e := s.CancelLinkRequest(r.Context(), parts[4])
				respondLink(w, 200, value, e, parts[4], "cancel")
				return
			}
			respondDec(w, 0, nil, decFailure("upgrade_required"), "-", "-", "-", "migration")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// The old protocol can recover an already signed, already committed outcome.
// It cannot POST a previously unknown activation or generate any new consent,
// approval, admission signature, device, packet or publication frame.
func (s *Store) resumeHistoricalLink(ctx context.Context, id string) (LinkRequestResult, error) {
	s.linkMu.Lock()
	defer s.linkMu.Unlock()
	p, e := readLinkPending(ctx, s.db, id)
	if e != nil {
		return LinkRequestResult{}, e
	}
	now, e := linkNow()
	if e != nil {
		return LinkRequestResult{}, e
	}
	refuse := func() (LinkRequestResult, error) {
		return LinkRequestResult{}, linkFail("recovery_required", id, "resume")
	}
	if !p.Record.CommitApproved || p.Record.CommitPacketBase64 == "-" {
		return refuse()
	}
	var result []byte
	var retained string
	e = s.db.QueryRowContext(ctx, `SELECT record FROM link_operations WHERE request_id=?`, id).Scan(&retained)
	if e == nil {
		result = []byte(retained)
	} else if e != sql.ErrNoRows {
		return LinkRequestResult{}, e
	}
	if result == nil && p.Record.ResultPacketBase64 != "-" {
		result, e = linkBytes(p.Record.ResultPacketBase64, linking.MaxObject)
		if e != nil {
			return refuse()
		}
	}
	if result == nil {
		raw, e := linkBytes(p.Record.NetworkBase64, linking.MaxObject)
		if e != nil {
			return refuse()
		}
		var descriptor linkDescriptor
		if linking.DecodeMutation(raw, "network_id name genesis_root_public_key coordinator_address coordinator_public_key", &descriptor) != nil {
			return refuse()
		}
		n := Network{ID: descriptor.NetworkID, Name: descriptor.Name, RootPublicKey: descriptor.GenesisRootPublicKey, CoordinatorAddress: p.Record.CoordinatorAddress, CoordinatorPublicKey: p.Record.CoordinatorPublicKey}
		result, e = s.linkCoordinator(ctx, n, http.MethodGet, "/coord/v2/networks/"+n.ID+"/link-operations/"+p.ID, nil)
		if e != nil {
			return refuse()
		}
	}
	s.syncing.Lock()
	e = s.applyLinkResult(ctx, &p, result, now)
	s.syncing.Unlock()
	if e != nil {
		return refuse()
	}
	return LinkRequestResult{LinkRequestView: s.linkView(p, now)}, nil
}

// A retained exact legacy host key authenticates bounded accepted-work/result
// routes only. It does not put the old network into a fresh authority view.
func (s *Store) retainedLegacyPeer(ctx context.Context, id string) (Peer, error) {
	rows, e := s.db.QueryContext(ctx, `SELECT m.record FROM network_members m JOIN networks n ON n.id=m.network_id WHERE m.host_id=? AND COALESCE(json_extract(n.record,'$.mode'),'')!='decentralized' ORDER BY n.id`, id)
	if e != nil {
		return Peer{}, e
	}
	defer rows.Close()
	for rows.Next() {
		m, e := readJSON[NetworkMember](rows)
		if e != nil {
			return Peer{}, e
		}
		key, e := membership.DecodeKey(m.PublicKey)
		if e != nil || m.HostID != id || membership.HostID(key) != id {
			return Peer{}, decStorageError()
		}
		return Peer{ID: id, PublicKey: m.PublicKey, Address: m.Address}, nil
	}
	if e = rows.Err(); e != nil {
		return Peer{}, e
	}
	return Peer{}, ErrNotFound
}

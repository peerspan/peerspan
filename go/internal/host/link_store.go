package host

import (
	"context"
	"database/sql"
	"encoding/binary"
	"math"

	"github.com/peerspan/peerspan/go/internal/linking"
	"github.com/peerspan/peerspan/go/internal/membership"
)

// Schema 19 is shared with Rust. It preserves all preexisting identity,
// network, policy, session and service records. Private device seeds and pending
// code seeds never appear in public proof or operation tables.
const linkingSchema = `
CREATE TABLE link_device_keys (
 public_key TEXT PRIMARY KEY, seed BLOB NOT NULL CHECK(length(seed) = 32),
 created_at TEXT NOT NULL
);
CREATE TABLE link_pending (
 request_id TEXT PRIMARY KEY, role TEXT NOT NULL, state TEXT NOT NULL,
 deadline TEXT NOT NULL, record TEXT NOT NULL, secret BLOB
);
CREATE TABLE link_frames (
 request_id TEXT NOT NULL, role TEXT NOT NULL, writer_key TEXT NOT NULL,
 frame_id TEXT NOT NULL, record TEXT NOT NULL,
 PRIMARY KEY(request_id, role, writer_key, frame_id)
);
CREATE TABLE link_operations (
 request_id TEXT PRIMARY KEY, network_id TEXT NOT NULL,
 manifest_id TEXT NOT NULL, record TEXT NOT NULL, locally_applied INTEGER NOT NULL
);
CREATE TABLE link_objects (
 network_id TEXT NOT NULL, proof_id TEXT NOT NULL, kind TEXT NOT NULL,
 body BLOB NOT NULL, PRIMARY KEY(network_id, proof_id)
);
CREATE TABLE link_features (
 network_id TEXT PRIMARY KEY, feature_id TEXT NOT NULL, record TEXT NOT NULL
);
CREATE TABLE link_signers (
 network_id TEXT PRIMARY KEY, person_key TEXT NOT NULL, device_key TEXT NOT NULL,
 certificate_id TEXT NOT NULL
);
CREATE TABLE link_highwater (
 network_id TEXT NOT NULL, kind TEXT NOT NULL, subject TEXT NOT NULL,
 version INTEGER NOT NULL, record_hash TEXT NOT NULL,
 PRIMARY KEY(network_id, kind, subject)
);
PRAGMA user_version = 19;
`

// SQLite preserves BLOBs under INTEGER affinity. This canonical encoding keeps
// every verified u64 version without numeric coercion or a permissive rollback.
func linkVersionValue(version uint64) any {
	if version <= math.MaxInt64 {
		return int64(version)
	}
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, version)
	return b
}
func linkVersion(value any) (uint64, error) {
	switch v := value.(type) {
	case int64:
		if v > 0 {
			return uint64(v), nil
		}
	case []byte:
		if len(v) == 8 && v[0]&128 != 0 {
			return binary.BigEndian.Uint64(v), nil
		}
	}
	return 0, linkFail("state_conflict", "-", "storage")
}
func readLinkHighWater(ctx context.Context, q dbQuerier, network string) ([]linking.PolicyHighWater, []linking.GroupHighWater, error) {
	policies, groups := []linking.PolicyHighWater{}, []linking.GroupHighWater{}
	rows, e := q.QueryContext(ctx, `SELECT kind,subject,version,record_hash FROM link_highwater WHERE network_id=? ORDER BY kind,subject`, network)
	if e != nil {
		return nil, nil, e
	}
	defer rows.Close()
	for rows.Next() {
		var kind, subject, hash string
		var stored any
		if e = rows.Scan(&kind, &subject, &stored, &hash); e != nil {
			return nil, nil, e
		}
		version, e := linkVersion(stored)
		if e != nil {
			return nil, nil, e
		}
		if !linkID(hash, "") {
			return nil, nil, linkFail("state_conflict", "-", "storage")
		}
		w := linking.AccessHighWater{Version: version, MessageHash: hash}
		switch kind {
		case "policy":
			if !linkPublicKey(subject) {
				return nil, nil, linkFail("state_conflict", "-", "storage")
			}
			policies = append(policies, linking.PolicyHighWater{PersonPublicKey: subject, AccessHighWater: w})
		case "group":
			if !membership.ValidGroupName(subject) {
				return nil, nil, linkFail("state_conflict", "-", "storage")
			}
			groups = append(groups, linking.GroupHighWater{Name: subject, AccessHighWater: w})
		default:
			return nil, nil, linkFail("state_conflict", "-", "storage")
		}
	}
	return policies, groups, rows.Err()
}
func persistLinkHighWater(ctx context.Context, tx *sql.Tx, state linking.AccessState) error {
	policies, groups, e := readLinkHighWater(ctx, tx, state.NetworkID)
	if e != nil {
		return e
	}
	oldPolicies, oldGroups := map[string]linking.AccessHighWater{}, map[string]linking.AccessHighWater{}
	for _, p := range policies {
		oldPolicies[p.PersonPublicKey] = p.AccessHighWater
	}
	for _, g := range groups {
		oldGroups[g.Name] = g.AccessHighWater
	}
	put := func(kind, subject string, w linking.AccessHighWater, old map[string]linking.AccessHighWater) error {
		if w.Version == 0 || !linkID(w.MessageHash, "") {
			return linkFail("state_conflict", "-", "storage")
		}
		if previous, exists := old[subject]; exists {
			if w.Version < previous.Version || w.Version == previous.Version && (kind == "group" && w.MessageHash != previous.MessageHash || kind == "policy" && w.MessageHash > previous.MessageHash) {
				return linkFail("state_conflict", "-", "storage")
			}
		}
		_, e := tx.ExecContext(ctx, `INSERT INTO link_highwater(network_id,kind,subject,version,record_hash) VALUES(?,?,?,?,?) ON CONFLICT(network_id,kind,subject) DO UPDATE SET version=excluded.version,record_hash=excluded.record_hash`, state.NetworkID, kind, subject, linkVersionValue(w.Version), w.MessageHash)
		return e
	}
	for _, p := range state.Policies {
		if e = put("policy", p.PersonPublicKey, p.AccessHighWater, oldPolicies); e != nil {
			return e
		}
	}
	for _, g := range state.Groups {
		if e = put("group", g.Name, g.AccessHighWater, oldGroups); e != nil {
			return e
		}
	}
	return nil
}

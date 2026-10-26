package host

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// Schema 23 is additive and shared with Rust. Public objects, private admission
// provenance, exact intents and private transport secrets remain separate.
// No existing network or product record is rewritten by opening this schema.
const decentralizedSchema = `
CREATE TABLE dec_contexts (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, record TEXT NOT NULL,
 PRIMARY KEY(network_id, context_id)
);

CREATE TABLE dec_objects (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, proof_id TEXT NOT NULL,
 kind TEXT NOT NULL, body BLOB NOT NULL,
 PRIMARY KEY(network_id, context_id, proof_id)
);
CREATE TABLE dec_admissions (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, statement_id TEXT NOT NULL,
 record TEXT NOT NULL,
 PRIMARY KEY(network_id, context_id, statement_id)
);
CREATE TABLE dec_restrictions (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, restriction_id TEXT NOT NULL,
 record TEXT NOT NULL,
 PRIMARY KEY(network_id, context_id, restriction_id)
);
CREATE TABLE dec_activations (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, activation_id TEXT NOT NULL,
 request_id TEXT NOT NULL, record TEXT NOT NULL,
 PRIMARY KEY(network_id, context_id, activation_id)
);

CREATE TABLE dec_heads (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, stream_kind TEXT NOT NULL,
 subject TEXT NOT NULL, subject2 TEXT NOT NULL, record TEXT NOT NULL,
 PRIMARY KEY(network_id, context_id, stream_kind, subject, subject2)
);
CREATE TABLE dec_highwater (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, stream_kind TEXT NOT NULL,
 subject TEXT NOT NULL, subject2 TEXT NOT NULL, version INTEGER NOT NULL,
 record TEXT NOT NULL,
 PRIMARY KEY(network_id, context_id, stream_kind, subject, subject2)
);

CREATE TABLE dec_signers (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, provider_kind TEXT NOT NULL,
 person_key TEXT NOT NULL, device_key TEXT NOT NULL, lease_id TEXT NOT NULL,
 PRIMARY KEY(network_id, context_id)
);
CREATE TABLE dec_clock (
 network_id TEXT PRIMARY KEY, record TEXT NOT NULL
);

CREATE TABLE dec_intents (
 intent_id TEXT PRIMARY KEY, network_id TEXT NOT NULL, context_id TEXT NOT NULL,
 kind TEXT NOT NULL, record TEXT NOT NULL, secret BLOB
);

CREATE TABLE dec_pending (
 request_id TEXT PRIMARY KEY, deadline TEXT NOT NULL, record TEXT NOT NULL,
 secret BLOB, terminal_read_cap BLOB
);
CREATE TABLE dec_frames (
 request_id TEXT NOT NULL, role TEXT NOT NULL, writer_key TEXT NOT NULL,
 frame_id TEXT NOT NULL, record TEXT NOT NULL,
 PRIMARY KEY(request_id, role, writer_key, frame_id)
);

CREATE TABLE dec_operations (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, request_id TEXT NOT NULL,
 activation_id TEXT NOT NULL, manifest_id TEXT NOT NULL, record TEXT NOT NULL,
 locally_applied INTEGER NOT NULL CHECK(locally_applied = 1),
 PRIMARY KEY(network_id, context_id, request_id)
);
CREATE TABLE dec_outbox (
 delivery_id TEXT PRIMARY KEY, network_id TEXT NOT NULL, context_id TEXT NOT NULL,
 target_key TEXT NOT NULL, record TEXT NOT NULL
);

CREATE TABLE dec_migrations (
 network_id TEXT NOT NULL, proposal_id TEXT NOT NULL, record TEXT NOT NULL,
 PRIMARY KEY(network_id, proposal_id)
);

CREATE TABLE dec_contacts (
 network_id TEXT NOT NULL, context_id TEXT NOT NULL, host_key TEXT NOT NULL,
 sequence INTEGER NOT NULL, record TEXT NOT NULL,
 PRIMARY KEY(network_id, context_id, host_key)
);
CREATE TABLE dec_helpers (
 kind TEXT NOT NULL, address TEXT NOT NULL, public_key TEXT NOT NULL,
 record TEXT NOT NULL, credential BLOB,
 PRIMARY KEY(kind, address, public_key)
);

`

type decTableShape struct{ name, columns, primary string }

var decTableShapes = []decTableShape{
	{"dec_contexts", "network_id context_id record", "network_id context_id"},
	{"dec_objects", "network_id context_id proof_id kind body", "network_id context_id proof_id"},
	{"dec_admissions", "network_id context_id statement_id record", "network_id context_id statement_id"},
	{"dec_restrictions", "network_id context_id restriction_id record", "network_id context_id restriction_id"},
	{"dec_activations", "network_id context_id activation_id request_id record", "network_id context_id activation_id"},
	{"dec_heads", "network_id context_id stream_kind subject subject2 record", "network_id context_id stream_kind subject subject2"},
	{"dec_highwater", "network_id context_id stream_kind subject subject2 version record", "network_id context_id stream_kind subject subject2"},
	{"dec_signers", "network_id context_id provider_kind person_key device_key lease_id", "network_id context_id"},
	{"dec_clock", "network_id record", "network_id"},
	{"dec_intents", "intent_id network_id context_id kind record secret", "intent_id"},
	{"dec_pending", "request_id deadline record secret terminal_read_cap", "request_id"},
	{"dec_frames", "request_id role writer_key frame_id record", "request_id role writer_key frame_id"},
	{"dec_operations", "network_id context_id request_id activation_id manifest_id record locally_applied", "network_id context_id request_id"},
	{"dec_outbox", "delivery_id network_id context_id target_key record", "delivery_id"},
	{"dec_migrations", "network_id proposal_id record", "network_id proposal_id"},
	{"dec_contacts", "network_id context_id host_key sequence record", "network_id context_id host_key"},
	{"dec_helpers", "kind address public_key record credential", "kind address public_key"},
}

func checkDecNamespaceUnused(ctx context.Context, tx *sql.Tx) error {
	for _, shape := range decTableShapes {
		var count int
		if e := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_schema WHERE name=? COLLATE NOCASE`, shape.name).Scan(&count); e != nil {
			return e
		}
		if count != 0 {
			return fmt.Errorf("schema 23 name already exists: %s", shape.name)
		}
	}
	return nil
}
func validateDecSchema(ctx context.Context, tx *sql.Tx) error {
	for _, shape := range decTableShapes {
		var name, kind, definition string
		if e := tx.QueryRowContext(ctx, `SELECT name,type,sql FROM sqlite_schema WHERE name=? COLLATE NOCASE`, shape.name).Scan(&name, &kind, &definition); e != nil {
			return fmt.Errorf("invalid schema 23 object %s: %w", shape.name, e)
		}
		if name != shape.name || kind != "table" {
			return fmt.Errorf("invalid schema 23 table: %s", shape.name)
		}
		rows, e := tx.QueryContext(ctx, `PRAGMA table_xinfo('`+shape.name+`')`)
		if e != nil {
			return e
		}
		columns, primary := strings.Fields(shape.columns), strings.Fields(shape.primary)
		index := 0
		for rows.Next() {
			var cid, notNull, pk, hidden int
			var column, typ string
			var defaultValue any
			if e = rows.Scan(&cid, &column, &typ, &notNull, &defaultValue, &pk, &hidden); e != nil {
				rows.Close()
				return e
			}
			if index >= len(columns) {
				rows.Close()
				return fmt.Errorf("extra schema 23 column: %s.%s", shape.name, column)
			}
			expectedType := "TEXT"
			switch column {
			case "body", "secret", "terminal_read_cap", "credential":
				expectedType = "BLOB"
			case "version", "sequence", "locally_applied":
				expectedType = "INTEGER"
			}
			expectedPK := 0
			for i, key := range primary {
				if key == column {
					expectedPK = i + 1
				}
			}
			expectedNull := 1
			if column == "secret" || column == "terminal_read_cap" || column == "credential" || len(primary) == 1 && primary[0] == column {
				expectedNull = 0
			}
			if cid != index || column != columns[index] || typ != expectedType || notNull != expectedNull || pk != expectedPK || hidden != 0 || defaultValue != nil {
				rows.Close()
				return fmt.Errorf("invalid schema 23 column: %s.%s", shape.name, column)
			}
			index++
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		if index != len(columns) {
			return fmt.Errorf("missing schema 23 column: %s", shape.name)
		}
		if shape.name == "dec_operations" {
			normalized := strings.ToLower(strings.Join(strings.Fields(definition), ""))
			normalized = strings.NewReplacer("\"", "", "`", "", "[", "", "]", "").Replace(normalized)
			if !strings.Contains(normalized, "check(locally_applied=1)") {
				return fmt.Errorf("invalid schema 23 outcome constraint")
			}
		}
	}
	return nil
}

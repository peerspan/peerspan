package host

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	dec "github.com/peerspan/peerspan/go/internal/decentralized"
	"github.com/peerspan/peerspan/go/internal/membership"
	"github.com/peerspan/peerspan/go/internal/tlsid"
)

const DecRepairALPN = "peerspan-state-repair/1"

// This is a disclosure/transport view, never a positive authority projection.
// The exact statement ID in durable admission metadata pins the host subject.
// A present original container must actually supply that statement; missing
// origin/container bytes can be fetched, but cannot be used for any action.
type decRepairView struct {
	Descriptor dec.Descriptor
	Catalog    *dec.Catalog
	Hosts      map[string]bool
	Contacts   map[string]*dec.Contact
}

func (s *Store) loadDecRepairView(ctx context.Context, q dbQuerier, id string) (*decRepairView, error) {
	n, d, _, e := readDecNetwork(ctx, q, id, s.identity.PublicKey)
	if e != nil {
		return nil, e
	}
	var raw string
	if e = q.QueryRowContext(ctx, `SELECT record FROM dec_contexts WHERE network_id=? AND context_id=?`, id, d.ContextID).Scan(&raw); e != nil {
		return nil, decStorageError()
	}
	var pin decContextRecord
	if e = dec.ReadPrivateRecord([]byte(raw), "format descriptor_base64 origin initial_root_state_id origin_proof_id migration_proposal_id adopted_at", &pin); e != nil {
		return nil, e
	}
	if pin.Format != 1 || pin.Descriptor != n.Descriptor || !dec.ValidID(pin.InitialRoot, "ds_") || !dec.ValidID(pin.OriginProof, "dp_") || pin.Origin != "genesis" && pin.Origin != "migration" || pin.Origin == "genesis" && pin.Proposal != "-" || pin.Origin == "migration" && !dec.ValidID(pin.Proposal, "ds_") {
		return nil, decStorageError()
	}
	if _, e = dec.ParseTime(pin.Adopted); e != nil {
		return nil, e
	}
	if e = q.QueryRowContext(ctx, `SELECT record FROM dec_clock WHERE network_id=?`, id).Scan(&raw); e != nil {
		return nil, decStorageError()
	}
	var clock decClockRecord
	if dec.ReadPrivateRecord([]byte(raw), "format largest_local_time", &clock) != nil || clock.Format != 1 || clock.Largest < n.Created || clock.Largest < pin.Adopted {
		return nil, decStorageError()
	}
	if _, e = dec.ParseTime(clock.Largest); e != nil {
		return nil, e
	}
	catalog, e := readDecCatalog(ctx, q, d)
	if e != nil {
		return nil, e
	}
	view := &decRepairView{Descriptor: d, Catalog: catalog, Hosts: map[string]bool{}}
	for _, table := range []string{"dec_admissions", "dec_restrictions"} {
		column := "statement_id"
		if table == "dec_restrictions" {
			column = "restriction_id"
		}
		rows, e := q.QueryContext(ctx, `SELECT `+column+`,record FROM `+table+` WHERE network_id=? AND context_id=? ORDER BY `+column, id, d.ContextID)
		if e != nil {
			return nil, e
		}
		for rows.Next() {
			var statementID, raw string
			if e = rows.Scan(&statementID, &raw); e != nil {
				rows.Close()
				return nil, e
			}
			var record decAdmissionRecord
			if dec.ReadPrivateRecord([]byte(raw), "format kind proof_id admitted_at basis", &record) != nil || record.Format != 1 || !dec.ValidID(statementID, "ds_") || !dec.ValidID(record.Proof, "dp_") || !decEvidence(record.Basis.Evidence) || record.At > clock.Largest {
				rows.Close()
				return nil, decStorageError()
			}
			if _, e = dec.ParseTime(record.At); e != nil {
				rows.Close()
				return nil, e
			}
			if record.Basis.Kind != "current" && record.Basis.Kind != "migration" && (table == "dec_admissions" && record.Basis.Kind != "retention" || table == "dec_restrictions" && record.Basis.Kind != "ratification") {
				rows.Close()
				return nil, decStorageError()
			}
			if table == "dec_admissions" && record.Kind != "host_lease" || table == "dec_restrictions" && record.Kind != "host_revoke" {
				continue
			}
			statement := catalog.Statements[statementID]
			if statement == nil {
				if table == "dec_admissions" {
					continue
				}
				rows.Close()
				return nil, decFailure("proof_required", record.Proof)
			}
			if statement.Kind != record.Kind || (table == "dec_restrictions") != (statement.Restriction != nil) {
				rows.Close()
				return nil, decStorageError()
			}
			for _, object := range catalog.Objects {
				if object.ID == record.Proof && !containsDecID(catalog.Sources[statementID], record.Proof) {
					rows.Close()
					return nil, decStorageError()
				}
			}
			if table == "dec_admissions" {
				view.Hosts[statement.Lease.Subject.Host] = true
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return nil, e
		}
	}
	// Sticky admitted host revocation is independent of a missing current head
	// or an unrelated fork. No candidate can clear or replace this evidence.
	rows, e := q.QueryContext(ctx, `SELECT restriction_id FROM dec_restrictions WHERE network_id=? AND context_id=?`, id, d.ContextID)
	if e != nil {
		return nil, e
	}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return nil, e
		}
		statement := catalog.Statements[id]
		if statement == nil {
			continue
		}
		if statement.Kind == "host_revoke" {
			delete(view.Hosts, statement.Restriction.Target.Host)
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	now, e := decProductReadNow(ctx)
	if e != nil {
		return nil, e
	}
	decision, e := dec.DecisionTime(linkTime(now), clock.Largest)
	if e != nil {
		return nil, e
	}
	view.Contacts, e = readDecProductContacts(ctx, q, &decSnapshot{Descriptor: d}, decision)
	return view, e
}

func (s *Store) decRepairSnapshot(ctx context.Context, id string) (*decRepairView, error) {
	tx, e := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	return s.loadDecRepairView(ctx, tx, id)
}

// Inserting untrusted exact bodies occurs ONLY inside the transaction which
// reconstructs the normal strict snapshot and verifies its complete union.
// Any refusal rolls those insertions back with every projection/outbox change.
func (s *Store) applyDecRepairCatalog(ctx context.Context, id, writer string, candidate []byte) error {
	s.syncing.Lock()
	defer s.syncing.Unlock()
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	remembered, e := s.loadDecRepairView(ctx, tx, id)
	if e != nil {
		return e
	}
	if !remembered.Hosts[writer] {
		return decFailure("forbidden")
	}
	catalog, e := dec.ReadCatalog(remembered.Descriptor, candidate)
	if e != nil {
		return e
	}
	for _, object := range catalog.Objects {
		if _, e = tx.ExecContext(ctx, `INSERT INTO dec_objects(network_id,context_id,proof_id,kind,body) VALUES(?,?,?,?,?) ON CONFLICT(network_id,context_id,proof_id) DO NOTHING`, id, remembered.Descriptor.ContextID, object.ID, object.Kind, object.Body); e != nil {
			return e
		}
	}
	snapshot, e := s.loadDecSnapshot(ctx, tx, id)
	if e != nil {
		return e
	}
	now, e := decNow()
	if e != nil {
		return e
	}
	if e = validateDecOrigin(snapshot, linkTime(now)); e != nil {
		return e
	}
	p, e := dec.Project(snapshot.Descriptor, snapshot.PriorRaw, candidate, linkTime(now), "repair")
	if e != nil {
		return e
	}
	// Recheck the current guard/expiry using the actual final transaction's
	// time, then persist that exact decision and its admitted union together.
	now, e = decNow()
	if e != nil {
		return e
	}
	p, e = dec.Project(snapshot.Descriptor, snapshot.PriorRaw, candidate, linkTime(now), "repair")
	if e != nil {
		return e
	}
	before := *snapshot
	before.Catalog = remembered.Catalog
	plan, e := s.planDecProofs(ctx, tx, &before, p)
	if e != nil {
		return e
	}
	if e = s.storeDecProjection(ctx, tx, snapshot, p); e != nil {
		return e
	}
	if e = plan.store(ctx, tx); e != nil {
		return e
	}
	return tx.Commit()
}

func (s *Store) serveDecRepair(ctx context.Context, conn *tls.Conn) {
	s.serveDecRepairConnection(ctx, conn, conn.ConnectionState())
}
func (s *Store) serveDecRepairConnection(ctx context.Context, conn net.Conn, state tls.ConnectionState) {
	defer conn.Close()
	peer, e := tlsid.PeerKey(state)
	if e != nil {
		return
	}
	writer := base64.StdEncoding.EncodeToString(peer)
	source, e := decBootstrapSource(conn.RemoteAddr())
	if e != nil {
		return
	}
	releaseSlot, ok := s.reserveDecRepairSlot(writer, source)
	if !ok {
		return
	}
	defer releaseSlot()
	allowed := s.decRepairReadAllowed(writer, source)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReaderSize(conn, 16<<10)
	header := []byte{}
	for len(header) < 16<<10 {
		b, e := reader.ReadByte()
		if e != nil {
			return
		}
		header = append(header, b)
		if bytes.HasSuffix(header, []byte("\r\n\r\n")) {
			break
		}
	}
	if !bytes.HasSuffix(header, []byte("\r\n\r\n")) {
		return
	}
	lines := strings.Split(string(header), "\r\n")
	if len(lines) > 67 {
		return
	}
	lengths := 0
	for _, line := range lines[1 : len(lines)-2] {
		name, value, ok := strings.Cut(line, ":")
		if !ok || name == "" || strings.ContainsAny(name, " \t") {
			return
		}
		if strings.EqualFold(name, "Transfer-Encoding") {
			return
		}
		if strings.EqualFold(name, "Content-Length") {
			lengths++
			value = strings.TrimSpace(value)
			if lengths != 1 || value != "0" {
				return
			}
		}
	}
	request, e := http.ReadRequest(bufio.NewReader(bytes.NewReader(header)))
	if e != nil {
		return
	}
	defer request.Body.Close()
	if request.Method != "GET" || request.Proto != "HTTP/1.1" || request.RequestURI != request.URL.EscapedPath() || request.URL.RawQuery != "" || request.URL.ForceQuery || request.ContentLength > 0 || len(request.TransferEncoding) > 0 || reader.Buffered() != 0 {
		return
	}
	path := strings.Split(request.URL.EscapedPath(), "/")
	if len(path) != 6 || path[1] != "repair" || path[2] != "v1" || path[3] != "networks" || path[5] != "catalog" {
		return
	}
	id, e := url.PathUnescape(path[4])
	if e != nil || !dec.ValidID(id, "net_") || url.PathEscape(id) != path[4] {
		return
	}
	release, e := s.reserveDecExchange(decPublicationLimit)
	if e != nil {
		return
	}
	defer release()
	var view *decRepairView
	if !allowed {
		e = decFailure("rate_limited")
	} else {
		view, e = s.decRepairSnapshot(ctx, id)
	}
	if e == nil && !view.Hosts[writer] {
		e = decFailure("forbidden")
	}
	response := &decRepairResponse{header: make(http.Header)}
	var value any
	if e == nil {
		value = struct {
			Catalog json.RawMessage `json:"catalog"`
		}{view.Catalog.Raw}
	}
	boundedDecPeerResponse(response, value, e, id, decPublicationLimit)
	result := &http.Response{StatusCode: response.status, ProtoMajor: 1, ProtoMinor: 1, Header: response.header, Body: io.NopCloser(bytes.NewReader(response.body.Bytes())), ContentLength: int64(response.body.Len()), Close: true}
	result.Header.Set("Content-Length", strconv.Itoa(response.body.Len()))
	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_ = result.Write(conn)
}

type decRepairResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (r *decRepairResponse) Header() http.Header    { return r.header }
func (r *decRepairResponse) WriteHeader(status int) { r.status = status }
func (r *decRepairResponse) Write(body []byte) (int, error) {
	if r.status == 0 {
		r.status = 200
	}
	return r.body.Write(body)
}

func (s *Store) decRepairReadAllowed(writer, source string) bool {
	s.decTransport.mu.Lock()
	defer s.decTransport.mu.Unlock()
	if s.decTransport.RepairRates == nil {
		s.decTransport.RepairRates = map[string]decRepairRate{}
	}
	now := time.Now()
	keys := []string{"host:" + writer, "source:" + source}
	added := 0
	for _, key := range keys {
		if _, ok := s.decTransport.RepairRates[key]; !ok {
			added++
		}
	}
	if len(s.decTransport.RepairRates)+added > 4096 {
		for key, row := range s.decTransport.RepairRates {
			if now.Sub(row.At) > time.Minute {
				delete(s.decTransport.RepairRates, key)
			}
		}
		added = 0
		for _, key := range keys {
			if _, ok := s.decTransport.RepairRates[key]; !ok {
				added++
			}
		}
		if len(s.decTransport.RepairRates)+added > 4096 {
			return false
		}
	}
	rows := make([]decRepairRate, len(keys))
	allowed := true
	for i, key := range keys {
		row, ok := s.decTransport.RepairRates[key]
		if !ok {
			row = decRepairRate{4, now}
		}
		row.Tokens += now.Sub(row.At).Seconds()
		if row.Tokens > 4 {
			row.Tokens = 4
		}
		row.At = now
		if row.Tokens < 1 {
			allowed = false
		}
		rows[i] = row
	}
	for i, key := range keys {
		if allowed {
			rows[i].Tokens--
		}
		s.decTransport.RepairRates[key] = rows[i]
	}
	return allowed
}

type decRepairRate struct {
	Tokens float64
	At     time.Time
}

func (s *Store) reserveDecRepairSlot(key, source string) (func(), bool) {
	s.decTransport.mu.Lock()
	defer s.decTransport.mu.Unlock()
	if s.decTransport.RepairActive >= 128 || s.decTransport.RepairKeys[key] >= 4 || s.decTransport.RepairSources[source] >= 16 {
		return nil, false
	}
	if s.decTransport.RepairKeys == nil {
		s.decTransport.RepairKeys = map[string]int{}
		s.decTransport.RepairSources = map[string]int{}
	}
	s.decTransport.RepairActive++
	s.decTransport.RepairKeys[key]++
	s.decTransport.RepairSources[source]++
	return func() {
		s.decTransport.mu.Lock()
		defer s.decTransport.mu.Unlock()
		s.decTransport.RepairActive--
		s.decTransport.RepairKeys[key]--
		s.decTransport.RepairSources[source]--
		if s.decTransport.RepairKeys[key] == 0 {
			delete(s.decTransport.RepairKeys, key)
		}
		if s.decTransport.RepairSources[source] == 0 {
			delete(s.decTransport.RepairSources, source)
		}
	}, true
}

func (s *Store) fetchDecRepair(ctx context.Context, network string, target decSyncTarget) error {
	if target.Contact == nil {
		return decTransportFailure()
	}
	view, e := s.decRepairSnapshot(ctx, network)
	if e != nil {
		return e
	}
	if !view.Hosts[target.Key] {
		return decFailure("forbidden")
	}
	var last error = decTransportFailure()
	for _, address := range target.Contact.Addresses.Bootstrap {
		carrier := decCarrier{"participant", address, target.Key}
		raw, status, e := s.decStateRepairExchange(ctx, carrier, "/repair/v1/networks/"+url.PathEscape(network)+"/catalog")
		if e != nil {
			last = e
			continue
		}
		if e = decPeerResponse(status, raw); e != nil {
			return e
		}
		catalog, e := decResponseCatalog(view.Descriptor, raw)
		if e != nil {
			return e
		}
		return s.applyDecRepairCatalog(ctx, network, target.Key, catalog.Raw)
	}
	key, e := membership.DecodeKey(target.Key)
	if e != nil {
		return e
	}
	for _, address := range target.Contact.Addresses.QUIC {
		release, e := s.reserveDecExchange(decPublicationLimit)
		if e != nil {
			return e
		}
		status, raw, e := s.decPinnedQUICRequest(ctx, Peer{ID: membership.HostID(key), PublicKey: target.Key, Address: address}, "GET", "/repair/v1/networks/"+url.PathEscape(network)+"/catalog", nil, decPublicationLimit, DecRepairALPN)
		release()
		if e != nil {
			last = decTransportFailure()
			continue
		}
		if e = decPeerResponse(status, raw); e != nil {
			return e
		}
		catalog, e := decResponseCatalog(view.Descriptor, raw)
		if e != nil {
			return e
		}
		return s.applyDecRepairCatalog(ctx, network, target.Key, catalog.Raw)
	}
	return last
}

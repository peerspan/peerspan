// capsule-peer-probe is a conformance test client for the peer wire format. It
// presents a certificate for the given host key but performs no pin check, so
// suites can exercise the peer router directly. It is not a daemon client.
//
// Subcommands let suites forge delegation chains:
//
//	capsule-peer-probe sign-link (--state DIR | --seed-hex HEX) --network-id ID --index N --previous P
//	    --issuer HOST --audience HOST --task-id ID --originator-agent ID --principal P [--principal P ...]
//	    --deadline TIME --depth N
//	capsule-peer-probe link-hash < LINK_JSON
//	capsule-peer-probe submit-task (--state DIR | --seed-hex HEX) --address IP:PORT --request JSON --chain JSON
//
// sign-link prints the link signed with that host key, exactly as given:
// principals keep their order and nothing is validated. link-hash prints the
// previous value a following link names. submit-task posts the request to
// /peer/v1/tasks with delegation set to the chain.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/host"
	"github.com/Cerebral-Systems/capsule/go/internal/membership"
	"github.com/Cerebral-Systems/capsule/go/internal/tlsid"
	"github.com/quic-go/quic-go"
)

func main() {
	var err error
	args := os.Args[1:]
	switch {
	case len(args) > 0 && args[0] == "sign-link":
		err = signLink(args[1:])
	case len(args) > 0 && args[0] == "link-hash":
		err = linkHash()
	case len(args) > 0 && args[0] == "submit-task":
		err = submitTask(args[1:])
	default:
		err = run(args)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

type repeated []string

func (r *repeated) String() string         { return fmt.Sprint([]string(*r)) }
func (r *repeated) Set(value string) error { *r = append(*r, value); return nil }

// hostKey reads a host key from --seed-hex or from a state directory's
// database; a running daemon may hold the directory.
func hostKey(seedHex, state string) (ed25519.PrivateKey, error) {
	if (seedHex == "") == (state == "") {
		return nil, errors.New("give exactly one of --seed-hex or --state")
	}
	var seed []byte
	if state != "" {
		dsn := (&url.URL{Scheme: "file", Path: filepath.Join(state, "host.db"), RawQuery: "mode=ro&_pragma=busy_timeout(10000)"}).String()
		db, err := sql.Open("sqlite", dsn)
		if err != nil {
			return nil, err
		}
		defer db.Close()
		var key []byte
		if err = db.QueryRow(`SELECT private_key FROM identity WHERE singleton = 1`).Scan(&key); err != nil {
			return nil, err
		}
		if len(key) != ed25519.PrivateKeySize {
			return nil, errors.New("invalid stored host key")
		}
		seed = key[:ed25519.SeedSize]
	} else {
		var err error
		if seed, err = hex.DecodeString(seedHex); err != nil || len(seed) != ed25519.SeedSize {
			return nil, errors.New("--seed-hex must be 32 bytes of hex")
		}
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func signLink(args []string) error {
	fs := flag.NewFlagSet("sign-link", flag.ContinueOnError)
	seedHex := fs.String("seed-hex", "", "32-byte Ed25519 seed, hex")
	state := fs.String("state", "", "host state directory whose key signs")
	var l membership.Link
	var principals repeated
	fs.StringVar(&l.NetworkID, "network-id", "", "network_id")
	fs.Int64Var(&l.Index, "index", 0, "index")
	fs.StringVar(&l.Previous, "previous", membership.DelegationNone, "previous")
	fs.StringVar(&l.IssuerHostID, "issuer", "", "issuer_host_id; default the signing host")
	fs.StringVar(&l.AudienceHostID, "audience", "", "audience_host_id")
	fs.StringVar(&l.TaskID, "task-id", "", "task_id")
	fs.StringVar(&l.OriginatorAgentID, "originator-agent", "", "originator_agent_id")
	fs.Var(&principals, "principal", "principal, in the given order; repeatable")
	fs.StringVar(&l.Deadline, "deadline", "", "deadline")
	fs.Int64Var(&l.Depth, "depth", 0, "depth")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("sign-link takes no positional arguments")
	}
	key, err := hostKey(*seedHex, *state)
	if err != nil {
		return err
	}
	if l.IssuerHostID == "" {
		l.IssuerHostID = membership.HostID(key.Public().(ed25519.PublicKey))
	}
	l.Principals = []string(principals)
	if l.Principals == nil {
		l.Principals = []string{}
	}
	return json.NewEncoder(os.Stdout).Encode(membership.SignLink(key, l))
}

func linkHash() error {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	// Plain decoding, so a deliberately malformed link still hashes.
	type plain membership.Link
	var l plain
	if err = json.Unmarshal(data, &l); err != nil {
		return err
	}
	_, err = fmt.Println(membership.Link(l).Hash())
	return err
}

func submitTask(args []string) error {
	fs := flag.NewFlagSet("submit-task", flag.ContinueOnError)
	seedHex := fs.String("seed-hex", "", "32-byte Ed25519 seed, hex")
	state := fs.String("state", "", "host state directory whose key authenticates")
	address := fs.String("address", "", "peer IP:PORT")
	request := fs.String("request", "", "task request JSON object, without delegation")
	chain := fs.String("chain", "", "delegation chain JSON, sent verbatim")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var body map[string]json.RawMessage
	if err := json.Unmarshal([]byte(*request), &body); err != nil || body == nil {
		return errors.New("--request must be a JSON object")
	}
	if !json.Valid([]byte(*chain)) {
		return errors.New("--chain must be JSON")
	}
	body["delegation"] = json.RawMessage(*chain)
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	key, err := hostKey(*seedHex, *state)
	if err != nil {
		return err
	}
	return exchange(key, *address, host.PeerALPN, "POST", "/peer/v1/tasks", payload)
}

func run(args []string) error {
	fs := flag.NewFlagSet("capsule-peer-probe", flag.ContinueOnError)
	seedHex := fs.String("seed-hex", "", "32-byte Ed25519 seed, hex")
	state := fs.String("state", "", "host state directory whose key authenticates, instead of --seed-hex")
	address := fs.String("address", "", "peer IP:PORT")
	method := fs.String("method", "GET", "HTTP method")
	path := fs.String("path", "/", "request path")
	body := fs.String("body", "", "raw request body, sent verbatim")
	stdin := fs.Bool("body-stdin", false, "read the raw request body from standard input")
	alpn := fs.String("alpn", host.PeerALPN, "ALPN to offer")
	if err := fs.Parse(args); err != nil {
		return err
	}
	key, err := hostKey(*seedHex, *state)
	if err != nil {
		return err
	}
	var payload []byte
	if *stdin {
		if payload, err = io.ReadAll(os.Stdin); err != nil {
			return err
		}
	} else if *body != "" {
		payload = []byte(*body)
	}
	return exchange(key, *address, *alpn, *method, *path, payload)
}

// exchange sends one request and prints {status, body}.
func exchange(key ed25519.PrivateKey, address, alpn, method, path string, payload []byte) error {
	cert, err := tlsid.Certificate(key, "capsule-peer-probe", time.Now())
	if err != nil {
		return err
	}
	config := tlsid.Config()
	config.NextProtos = []string{alpn}
	config.Certificates = []tls.Certificate{cert}
	config.InsecureSkipVerify = true
	addr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr.String(), config, host.PeerQUICConfig(false))
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "done")
	status, data, err := host.PeerStreamRequest(ctx, conn, address, method, path, payload)
	if err != nil {
		return err
	}
	var value any
	if len(data) > 0 {
		if json.Unmarshal(data, &value) != nil {
			value = string(data)
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"status": status, "body": value})
}

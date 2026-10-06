// capsule-peer-probe is a conformance test client for the peer wire format. It
// presents a certificate for the given host key but performs no pin check, so
// suites can exercise the peer router directly. It is not a daemon client.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/Cerebral-Systems/capsule/go/internal/host"
	"github.com/Cerebral-Systems/capsule/go/internal/tlsid"
	"github.com/quic-go/quic-go"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	seedHex := flag.String("seed-hex", "", "32-byte Ed25519 seed, hex")
	address := flag.String("address", "", "peer IP:PORT")
	method := flag.String("method", "GET", "HTTP method")
	path := flag.String("path", "/", "request path")
	body := flag.String("body", "", "raw request body, sent verbatim")
	stdin := flag.Bool("body-stdin", false, "read the raw request body from standard input")
	alpn := flag.String("alpn", host.PeerALPN, "ALPN to offer")
	flag.Parse()
	seed, err := hex.DecodeString(*seedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		return errors.New("--seed-hex must be 32 bytes of hex")
	}
	key := ed25519.NewKeyFromSeed(seed)
	cert, err := tlsid.Certificate(key, "capsule-peer-probe", time.Now())
	if err != nil {
		return err
	}
	config := tlsid.Config()
	config.NextProtos = []string{*alpn}
	config.Certificates = []tls.Certificate{cert}
	config.InsecureSkipVerify = true
	addr, err := net.ResolveUDPAddr("udp", *address)
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
	var payload []byte
	if *stdin {
		if payload, err = io.ReadAll(os.Stdin); err != nil {
			return err
		}
	} else if *body != "" {
		payload = []byte(*body)
	}
	status, data, err := host.PeerStreamRequest(ctx, conn, *address, *method, *path, payload)
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

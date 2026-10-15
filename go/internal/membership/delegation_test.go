package membership

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
)

// vectorKeys are the test-vector host keys: seeds 0x00..0x1f and 0x20..0x3f.
func vectorKeys() (ed25519.PrivateKey, ed25519.PrivateKey) {
	seed0, seed1 := make([]byte, 32), make([]byte, 32)
	for i := range seed0 {
		seed0[i], seed1[i] = byte(i), byte(32+i)
	}
	return ed25519.NewKeyFromSeed(seed0), ed25519.NewKeyFromSeed(seed1)
}

func vectorLinks() (Link, Link) {
	k0, k1 := vectorKeys()
	h0, h1 := HostID(k0.Public().(ed25519.PublicKey)), HostID(k1.Public().(ed25519.PublicKey))
	l0 := SignLink(k0, Link{NetworkID: "net_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Index: 0, Previous: DelegationNone, IssuerHostID: h0, AudienceHostID: h1, TaskID: "task_00112233445566778899aabbccddeeff", OriginatorAgentID: "agent_0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f", Principals: []string{"network"}, Deadline: "2026-10-10T00:00:00Z", Depth: 2})
	l1 := SignLink(k1, Link{NetworkID: l0.NetworkID, Index: 1, Previous: l0.Hash(), IssuerHostID: h1, AudienceHostID: "host_fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", TaskID: "task_ffeeddccbbaa99887766554433221100", OriginatorAgentID: l0.OriginatorAgentID, Principals: []string{"network"}, Deadline: "2026-10-09T12:00:00Z", Depth: 1})
	return l0, l1
}

func TestDelegationLinkVector(t *testing.T) {
	k0, k1 := vectorKeys()
	l0, l1 := vectorLinks()
	if l0.IssuerHostID != "host_56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c" || l1.IssuerHostID != "host_24f6ed6acbfe1009c030d7ca567c33ca4830911498236b5561a6c82abec5de28" {
		t.Fatalf("host IDs: %s %s", l0.IssuerHostID, l1.IssuerHostID)
	}
	statement := "peerspan-delegation-v1\nnet_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n0\nnone\nhost_56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c\nhost_24f6ed6acbfe1009c030d7ca567c33ca4830911498236b5561a6c82abec5de28\ntask_00112233445566778899aabbccddeeff\nagent_0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f\nnetwork\n2026-10-10T00:00:00Z\n2"
	if string(l0.Message()) != statement {
		t.Fatalf("statement: %q", l0.Message())
	}
	if l0.Signature != "S2sFkjmIIkmXC6D4qNIerxRpeYZ0GNL22iWGjG2TPLCX1PnV+x0sGr7rG8BfOHS4hzyQRiSh//2Rh8ZwhhliCQ==" {
		t.Fatalf("signature 0: %s", l0.Signature)
	}
	if l0.Hash() != "bc5f57c2363071701a685c896296288dbb90d293604e20ee6ca38153bbc474a3" || l1.Previous != l0.Hash() {
		t.Fatalf("hash 0: %s", l0.Hash())
	}
	if l1.Signature != "p084GJDwcslS5CxDwZqspuxecXittC3XEV2UyGHMSX26xoCN49NAOFeWdfzKpRNfYoSBYaEe5nO4AGAXqyzuDA==" || l1.Hash() != "3b01028b7cb9b4d5ed6f23ba49e92966030711983a17792a11edd23834926d1c" {
		t.Fatalf("link 1: %s %s", l1.Signature, l1.Hash())
	}
	if VerifyLink(k0.Public().(ed25519.PublicKey), l0) != nil || VerifyLink(k1.Public().(ed25519.PublicKey), l1) != nil {
		t.Fatal("vector does not verify")
	}
	if VerifyLink(k1.Public().(ed25519.PublicKey), l0) == nil {
		t.Fatal("verified under another key")
	}
	changed := l0
	changed.Depth = 1
	if VerifyLink(k0.Public().(ed25519.PublicKey), changed) == nil {
		t.Fatal("changed link verified")
	}
	// JSON keys follow the table order.
	data, _ := json.Marshal(l0)
	if !strings.HasPrefix(string(data), `{"network_id":"net_0123`) || !strings.Contains(string(data), `"principals":["network"],"deadline":"2026-10-10T00:00:00Z","depth":2,"signature":"S2sF`) {
		t.Fatalf("json: %s", data)
	}
	var back Link
	if err := json.Unmarshal(data, &back); err != nil || back.Hash() != l0.Hash() {
		t.Fatalf("round trip: %v", err)
	}
}

func TestDelegationLinkShape(t *testing.T) {
	l0, _ := vectorLinks()
	if err := CheckLink(l0); err != nil {
		t.Fatal(err)
	}
	host := "host:host_" + strings.Repeat("1", 64)
	person := "person:person_" + strings.Repeat("2", 64)
	for name, change := range map[string]func(*Link){
		"network":      func(l *Link) { l.NetworkID = "net_x" },
		"index":        func(l *Link) { l.Index = -1 },
		"depth":        func(l *Link) { l.Depth = -1 },
		"previous":     func(l *Link) { l.Previous = "NONE" },
		"issuer":       func(l *Link) { l.IssuerHostID = "host_ABC" },
		"task":         func(l *Link) { l.TaskID = "task_1" },
		"agent":        func(l *Link) { l.OriginatorAgentID = "agent_" },
		"empty":        func(l *Link) { l.Principals = []string{} },
		"unsorted":     func(l *Link) { l.Principals = []string{"network", host} },
		"duplicate":    func(l *Link) { l.Principals = []string{host, host} },
		"group":        func(l *Link) { l.Principals = []string{"group:team"} },
		"too many":     func(l *Link) { l.Principals = strings.Split(strings.Repeat("network ", 17), " ")[:17] },
		"offset":       func(l *Link) { l.Deadline = "2026-10-10T02:00:00+02:00" },
		"not a time":   func(l *Link) { l.Deadline = "tomorrow" },
		"signature":    func(l *Link) { l.Signature = "AAAA" },
		"noncanon sig": func(l *Link) { l.Signature = l.Signature[:len(l.Signature)-3] + "B==" },
	} {
		l := l0
		change(&l)
		if CheckLink(l) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	l := l0
	l.Principals = []string{host, "network", person}
	if err := CheckLink(l); err != nil {
		t.Fatalf("sorted principals: %v", err)
	}
	for _, body := range []string{
		`{}`,
		strings.Replace(mustJSON(l0), `"depth":2`, `"depth":null`, 1),
		strings.Replace(mustJSON(l0), `"depth":2`, `"depth":2,"extra":1`, 1),
		strings.Replace(mustJSON(l0), `"depth":2`, `"depth":"2"`, 1),
		strings.Replace(mustJSON(l0), `"depth":2`, `"depth":2.5`, 1),
	} {
		var back Link
		if json.Unmarshal([]byte(body), &back) == nil {
			t.Errorf("decoded %s", body)
		}
	}
}

func mustJSON(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func TestDelegationCoverage(t *testing.T) {
	h1, h2 := "host_"+strings.Repeat("1", 64), "host_"+strings.Repeat("2", 64)
	p := "person_" + strings.Repeat("3", 64)
	bound := func(host string) string {
		if host == h1 {
			return p
		}
		return ""
	}
	cases := []struct {
		a, b string
		want bool
	}{
		{"network", "host:" + h2, true},
		{"network", "person:" + p, true},
		{"network", "network", true},
		{"person:" + p, "person:" + p, true},
		{"person:" + p, "host:" + h1, true},
		{"person:" + p, "host:" + h2, false},
		{"person:" + p, "network", false},
		{"host:" + h1, "host:" + h1, true},
		{"host:" + h1, "host:" + h2, false},
		{"host:" + h1, "person:" + p, false},
	}
	for _, c := range cases {
		if PrincipalCovers(c.a, c.b, bound) != c.want {
			t.Errorf("%s covers %s: want %v", c.a, c.b, c.want)
		}
	}
	if !PrincipalsCover([]string{"host:" + h2, "person:" + p}, "host:"+h1, bound) || PrincipalsCover([]string{"host:" + h2}, "host:"+h1, bound) {
		t.Fatal("set coverage")
	}
}

var vectorTime, _ = ParseTime("2026-10-10T00:00:00Z")

func TestDelegateAction(t *testing.T) {
	if !ValidPolicyAction(PolicyActionDelegate) || ValidRouteAction(PolicyActionDelegate) || !TaskAction(PolicyActionDelegate) || TaskAction(PolicyActionMessage) {
		t.Fatal("action predicates")
	}
	owner := KeySigner{Key: ed25519.NewKeyFromSeed(make([]byte, 32))}
	network := "net_" + strings.Repeat("0", 64)
	// task.delegate alone, with an artifact bound, is a valid rule.
	rule := PolicyRule{Agent: "reviewer", Principals: []string{"network"}, Actions: []string{PolicyActionDelegate}, MaxMessageBytes: 10, MaxArtifactBytes: 100}
	p, err := SignPolicy(owner, network, 1, vectorTime, PolicyMinValidity, []PolicyRule{rule})
	if err != nil || VerifyPolicy(network, p) != nil {
		t.Fatalf("delegate policy: %v", err)
	}
	if !strings.Contains(string(p.Message()), "\ntask.delegate\n10 false 100") {
		t.Fatalf("statement: %q", p.Message())
	}
}

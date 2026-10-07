package membership

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Policy vector from docs/coordination-contract.md.
const policyVector = "U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgbnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/EAAAARY2Fwc3VsZS1wZXJzb24tdjEAAAAAAAAABnNoYTUxMgAAAFMAAAALc3NoLWVkMjU1MTkAAABAy54wZKMJ5nBPfB3XakG7muQtkw2rjuhFVU+oWwluflHQKmEqNNa3l4MB1x5cdPmyXJduUMs9R24za8w4kW0bDg=="

func vectorPolicy(t *testing.T) Policy {
	t.Helper()
	owner := KeySigner{mustSeed(t, personSeed)}
	issued, _ := ParseTime("2026-10-10T00:00:00Z")
	p, err := SignPolicy(owner, vector.NetworkID, 1, issued, 7*24*time.Hour, []PolicyRule{
		{Agent: "reviewer", Principals: []string{"person:" + otherIDVector, "group:backend"}, Actions: []string{PolicyActionMessage}, MaxMessageBytes: 65536},
		{Agent: "triage", Principals: []string{PrincipalNetwork}, Actions: []string{PolicyActionMessage}, MaxMessageBytes: 4096, AllowDisconnected: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPolicyVectorReproduces(t *testing.T) {
	p := vectorPolicy(t)
	if p.ValidUntil != "2026-10-17T00:00:00Z" {
		t.Fatalf("valid_until %s", p.ValidUntil)
	}
	if p.Signature != policyVector {
		t.Fatalf("policy signature %s, want %s", p.Signature, policyVector)
	}
	want := strings.Join([]string{"capsule-policy-v1", vector.NetworkID, personPublic, "1", "2026-10-10T00:00:00Z", "2026-10-17T00:00:00Z",
		"rule", "reviewer", "person:" + otherIDVector + " group:backend", "message.append", "65536 false",
		"rule", "triage", "network", "message.append", "4096 true"}, "\n")
	if string(p.Message()) != want {
		t.Fatalf("policy lines:\n%s", p.Message())
	}
	if err := VerifyPolicy(vector.NetworkID, p); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodePolicy(data)
	if err != nil || VerifyPolicy(vector.NetworkID, back) != nil {
		t.Fatalf("round trip: %v", err)
	}
}

func TestPolicyRejectsTamperingAndBadShapes(t *testing.T) {
	good := vectorPolicy(t)
	mutate := func(f func(*Policy)) Policy {
		p := good
		p.Rules = append([]PolicyRule{}, good.Rules...)
		for i := range p.Rules {
			p.Rules[i].Principals = append([]string{}, good.Rules[i].Principals...)
		}
		f(&p)
		return p
	}
	cases := map[string]Policy{
		"version":    mutate(func(p *Policy) { p.Version = 2 }),
		"agent":      mutate(func(p *Policy) { p.Rules[0].Agent = "other" }),
		"principal":  mutate(func(p *Policy) { p.Rules[0].Principals[1] = "group:frontend" }),
		"bytes":      mutate(func(p *Policy) { p.Rules[1].MaxMessageBytes = 4097 }),
		"disconnect": mutate(func(p *Policy) { p.Rules[0].AllowDisconnected = true }),
		"order": mutate(func(p *Policy) {
			p.Rules[0].Principals[0], p.Rules[0].Principals[1] = p.Rules[0].Principals[1], p.Rules[0].Principals[0]
		}),
		"network": mutate(func(p *Policy) { p.NetworkID = "net_" + strings.Repeat("0", 64) }),
		"owner":   mutate(func(p *Policy) { p.PersonPublicKey = otherPublic }),
		"until":   mutate(func(p *Policy) { p.ValidUntil = "2026-10-18T00:00:00Z" }),
	}
	for name, p := range cases {
		if VerifyPolicy(vector.NetworkID, p) == nil {
			t.Errorf("tampered %s verified", name)
		}
	}
	owner := KeySigner{mustSeed(t, personSeed)}
	now := time.Now()
	rule := PolicyRule{Agent: "a", Principals: []string{PrincipalNetwork}, Actions: []string{PolicyActionMessage}, MaxMessageBytes: 1}
	shapes := map[string]func() (Policy, error){
		"short validity": func() (Policy, error) {
			return SignPolicy(owner, vector.NetworkID, 1, now, time.Hour, []PolicyRule{rule})
		},
		"long validity": func() (Policy, error) {
			return SignPolicy(owner, vector.NetworkID, 1, now, 91*24*time.Hour, []PolicyRule{rule})
		},
		"bad principal": func() (Policy, error) {
			r := rule
			r.Principals = []string{"person:bob"}
			return SignPolicy(owner, vector.NetworkID, 1, now, 24*time.Hour, []PolicyRule{r})
		},
		"bad action": func() (Policy, error) {
			r := rule
			r.Actions = []string{"shell.exec"}
			return SignPolicy(owner, vector.NetworkID, 1, now, 24*time.Hour, []PolicyRule{r})
		},
		"zero bytes": func() (Policy, error) {
			r := rule
			r.MaxMessageBytes = 0
			return SignPolicy(owner, vector.NetworkID, 1, now, 24*time.Hour, []PolicyRule{r})
		},
		"control agent": func() (Policy, error) {
			r := rule
			r.Agent = "a\nb"
			return SignPolicy(owner, vector.NetworkID, 1, now, 24*time.Hour, []PolicyRule{r})
		},
		"version zero": func() (Policy, error) {
			return SignPolicy(owner, vector.NetworkID, 0, now, 24*time.Hour, []PolicyRule{rule})
		},
	}
	for name, f := range shapes {
		if _, err := f(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Unknown and null fields are refused.
	data, _ := json.Marshal(good)
	var fields map[string]any
	_ = json.Unmarshal(data, &fields)
	fields["extra"] = 1
	extra, _ := json.Marshal(fields)
	if _, err := DecodePolicy(extra); err == nil {
		t.Error("unknown field accepted")
	}
	delete(fields, "extra")
	fields["rules"] = nil
	null, _ := json.Marshal(fields)
	if _, err := DecodePolicy(null); err == nil {
		t.Error("null rules accepted")
	}
}

func TestPolicyWindowAndRenewal(t *testing.T) {
	p := vectorPolicy(t)
	issued, _ := ParseTime(p.IssuedAt)
	until, _ := ParseTime(p.ValidUntil)
	if !PolicyActive(p, issued.Add(-4*time.Minute)) || PolicyActive(p, issued.Add(-6*time.Minute)) {
		t.Error("issued_at skew not applied")
	}
	if PolicyActive(p, until) || !PolicyActive(p, until.Add(-time.Second)) {
		t.Error("valid_until is exclusive")
	}
	if PolicyExpiresSoon(p, issued.Add(time.Hour)) || !PolicyExpiresSoon(p, until.Add(-41*time.Hour)) {
		t.Error("expires_soon is under a quarter of the validity")
	}
	owner := KeySigner{mustSeed(t, personSeed)}
	now := issued.Add(6 * 24 * time.Hour)
	next, err := Renewal(owner, p, now)
	if err != nil {
		t.Fatal(err)
	}
	if next.Version != 2 || next.IssuedAt != Timestamp(now) || next.ValidUntil != Timestamp(now.Add(7*24*time.Hour)) || len(next.Rules) != 2 || VerifyPolicy(vector.NetworkID, next) != nil {
		t.Fatalf("renewal %+v", next)
	}
	if _, err = Renewal(KeySigner{mustSeed(t, otherSeed)}, p, now); err == nil {
		t.Error("another key renewed the policy")
	}
}

func TestAgentPrincipal(t *testing.T) {
	host, agent := "host_"+strings.Repeat("a", 64), "agent_"+strings.Repeat("b", 32)
	if h, a, ok := AgentPrincipal("agent:" + host + "/" + agent); !ok || h != host || a != agent || !ValidPrincipal("agent:"+host+"/"+agent) {
		t.Fatalf("agent principal: %q %q %v", h, a, ok)
	}
	for _, bad := range []string{"agent:" + host, "agent:/" + agent, "agent:" + agent + "/" + host, "agent:" + host + "/" + agent + "/x", "agent:" + strings.ToUpper(host) + "/" + agent, "agent:" + host + "/agent_x", "person:" + host + "/" + agent} {
		if _, _, ok := AgentPrincipal(bad); ok || ValidPrincipal(bad) {
			t.Errorf("principal %q accepted", bad)
		}
	}
	rule := PolicyRule{Agent: "a", Principals: []string{"agent:" + host + "/" + agent}, Actions: []string{PolicyActionMessage}, MaxMessageBytes: 1}
	owner := KeySigner{mustSeed(t, personSeed)}
	if _, err := SignPolicy(owner, vector.NetworkID, 1, time.Now(), 24*time.Hour, []PolicyRule{rule}); err != nil {
		t.Fatalf("policy with an agent principal: %v", err)
	}
	rule.Principals = []string{"agent:" + host}
	if _, err := SignPolicy(owner, vector.NetworkID, 1, time.Now(), 24*time.Hour, []PolicyRule{rule}); err == nil {
		t.Fatal("policy with a malformed agent principal")
	}
}

// Policy vector with max_artifact_bytes, cross-checked with ssh-keygen -Y sign.
const policyArtifactVector = "U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgbnoc3Smwt4/ROvTFWY/v9O8qlxZuPKby5Pv8zYBQW/EAAAARY2Fwc3VsZS1wZXJzb24tdjEAAAAAAAAABnNoYTUxMgAAAFMAAAALc3NoLWVkMjU1MTkAAABAGaZoSLXB4mfYtcitytb/FSRHPWfWO9ccCJCeCjSHNdTcKmOAqDW7dIY4AQIIaVkOU0M+rQMJGDYfvkT+5dnQBw=="

func TestPolicyArtifactVector(t *testing.T) {
	owner := KeySigner{mustSeed(t, personSeed)}
	issued, _ := ParseTime("2026-10-10T00:00:00Z")
	p, err := SignPolicy(owner, vector.NetworkID, 2, issued, 7*24*time.Hour, []PolicyRule{
		{Agent: "reviewer", Principals: []string{"person:" + otherIDVector}, Actions: []string{PolicyActionMessage, PolicyActionTask}, MaxMessageBytes: 65536, MaxArtifactBytes: 1048576},
		{Agent: "triage", Principals: []string{PrincipalNetwork}, Actions: []string{PolicyActionTask}, MaxMessageBytes: 4096, AllowDisconnected: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Join([]string{"capsule-policy-v1", vector.NetworkID, personPublic, "2", "2026-10-10T00:00:00Z", "2026-10-17T00:00:00Z",
		"rule", "reviewer", "person:" + otherIDVector, "message.append task.submit", "65536 false 1048576",
		"rule", "triage", "network", "task.submit", "4096 true"}, "\n")
	if string(p.Message()) != want {
		t.Fatalf("policy lines:\n%s", p.Message())
	}
	if p.Signature != policyArtifactVector {
		t.Fatalf("policy signature %s, want %s", p.Signature, policyArtifactVector)
	}
	data, err := json.Marshal(p.Rules)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"max_message_bytes":65536,"max_artifact_bytes":1048576,"allow_disconnected":false`) || strings.Count(string(data), "max_artifact_bytes") != 1 {
		t.Fatalf("rule JSON: %s", data)
	}
	encoded, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodePolicy(encoded)
	if err != nil || VerifyPolicy(vector.NetworkID, back) != nil || back.Rules[0].MaxArtifactBytes != 1048576 {
		t.Fatalf("round trip: %v", err)
	}
	// The bound is signed: changing it breaks the signature.
	back.Rules[0].MaxArtifactBytes = 1048577
	if VerifyPolicy(vector.NetworkID, back) == nil {
		t.Fatal("changed bound verified")
	}
	// An explicit 0 decodes; the bound needs task.submit and at most 1 GiB.
	var r PolicyRule
	if err = json.Unmarshal([]byte(`{"agent":"a","principals":["network"],"actions":["message.append"],"max_message_bytes":1,"max_artifact_bytes":0,"allow_disconnected":false}`), &r); err != nil {
		t.Fatal(err)
	}
	if json.Unmarshal([]byte(`{"agent":"a","principals":["network"],"actions":["message.append"],"max_message_bytes":1,"max_artifact_bytes":null,"allow_disconnected":false}`), &r) == nil {
		t.Fatal("null bound decoded")
	}
	for _, bad := range []PolicyRule{
		{Agent: "a", Principals: []string{PrincipalNetwork}, Actions: []string{PolicyActionMessage}, MaxMessageBytes: 1, MaxArtifactBytes: 1},
		{Agent: "a", Principals: []string{PrincipalNetwork}, Actions: []string{PolicyActionTask}, MaxMessageBytes: 1, MaxArtifactBytes: 1<<30 + 1},
		{Agent: "a", Principals: []string{PrincipalNetwork}, Actions: []string{PolicyActionTask}, MaxMessageBytes: 1, MaxArtifactBytes: -1},
	} {
		if _, err = SignPolicy(owner, vector.NetworkID, 1, time.Now(), 24*time.Hour, []PolicyRule{bad}); err == nil {
			t.Errorf("rule %+v accepted", bad)
		}
	}
}

package main

import (
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func requestBody(t *testing.T, args ...string) (map[string]any, error) {
	t.Helper()
	_, _, body, err := request(args, io.Discard)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err = json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	return fields, nil
}

func TestMessageSendOrigin(t *testing.T) {
	send := []string{"message", "send", "--peer", "host_x", "--agent", "agent_y", "--deadline", "2099-01-01T00:00:00Z", "--content", "hi"}
	body, err := requestBody(t, send...)
	if _, ok := body["origin"]; err != nil || ok {
		t.Fatalf("owner send without --from-agent: %v %v", body, err)
	}
	body, err = requestBody(t, append(send, "--from-agent", "agent_a")...)
	if origin, _ := json.Marshal(body["origin"]); err != nil || string(origin) != `{"agent_id":"agent_a"}` {
		t.Fatalf("--from-agent: %s %v", origin, err)
	}
	body, err = requestBody(t, append(send, "--from-agent", "agent_a", "--from-session", "session_s")...)
	if origin, _ := json.Marshal(body["origin"]); err != nil || string(origin) != `{"agent_id":"agent_a","session_id":"session_s"}` {
		t.Fatalf("--from-session: %s %v", origin, err)
	}
	if _, err = requestBody(t, append(send, "--from-session", "session_s")...); err == nil || !strings.Contains(err.Error(), "--from-agent") {
		t.Fatalf("--from-session alone: %v", err)
	}
}

func TestGrantCreateRequesterAgent(t *testing.T) {
	create := []string{"grant", "create", "--peer", "host_x", "--agent", "agent_y", "--expires-at", "2099-01-01T00:00:00Z"}
	body, err := requestBody(t, create...)
	if _, ok := body["requester_agent_id"]; err != nil || ok {
		t.Fatalf("grant without --from-agent: %v %v", body, err)
	}
	body, err = requestBody(t, append(create, "--from-agent", "agent_a")...)
	if err != nil || body["requester_agent_id"] != "agent_a" {
		t.Fatalf("grant --from-agent: %v %v", body, err)
	}
}

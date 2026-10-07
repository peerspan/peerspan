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

func TestTaskCommands(t *testing.T) {
	grant := []string{"grant", "create", "--peer", "host_x", "--agent", "agent_y", "--expires-at", "2099-01-01T00:00:00Z"}
	if body, err := requestBody(t, grant...); err != nil || body["action"] != nil {
		t.Fatalf("default grant action is sent: %v %v", body, err)
	}
	if body, err := requestBody(t, append(grant, "--action", "task.submit")...); err != nil || body["action"] != "task.submit" {
		t.Fatalf("grant --action: %v %v", body, err)
	}
	submit := []string{"task", "submit", "--peer", "host_x", "--agent", "agent_y", "--input", "work"}
	body, err := requestBody(t, submit...)
	if err != nil || body["input"] != "work" || body["peer_host_id"] != "host_x" || body["grant_id"] != nil || body["deadline"] != nil || body["task_id"] != nil {
		t.Fatalf("task submit: %v %v", body, err)
	}
	if _, err = requestBody(t, append(submit, "--from-session", "session_s")...); err == nil {
		t.Fatal("--from-session without --from-agent accepted")
	}
	for args, want := range map[string]string{
		"task events --peer host_x task_1 --after 3": "GET /v1/tasks/host_x/task_1/events?after=3&limit=100",
		"task events --after 2 --peer host_x task_1": "GET /v1/tasks/host_x/task_1/events?after=2&limit=100",
		"task inspect --peer host_x task_1":          "GET /v1/tasks/host_x/task_1",
		"task cancel --peer host_x task_1":           "POST /v1/tasks/host_x/task_1/cancel",
		"task list --after 5 --limit 7":              "GET /v1/tasks?after=5&limit=7",
	} {
		method, path, _, err := request(strings.Fields(args), io.Discard)
		if err != nil || method+" "+path != want {
			t.Errorf("%s: %s %s %v", args, method, path, err)
		}
	}
	for _, args := range []string{"task inspect task_1", "task inspect --peer host_x", "task inspect --peer host_x a b"} {
		if _, _, _, err := request(strings.Fields(args), io.Discard); err == nil {
			t.Errorf("%s accepted", args)
		}
	}
}

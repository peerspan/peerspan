package demo_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Cerebral-Systems/capsule/internal/session"
)

func TestPeeringDemo(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("workcells require root")
	}
	for _, cmd := range []string{"nsenter", "python3"} {
		if _, err := exec.LookPath(cmd); err != nil {
			t.Skipf("demo requires %s", cmd)
		}
	}

	cmd := exec.Command("./peering.sh")
	out, err := cmd.CombinedOutput()
	log := string(out)
	if err != nil {
		t.Fatalf("demo failed: %v\n%s", err, log)
	}
	evidencePath := evidencePath(log)
	if evidencePath == "" {
		t.Fatalf("demo did not print an evidence path\n%s", log)
	}
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(filepath.Dir(filepath.Dir(evidencePath)))) })

	data, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "STAGING_TOKEN") {
		t.Fatal("evidence bundle contains the unshared secret")
	}
	var evidence session.Evidence
	if err := json.Unmarshal(data, &evidence); err != nil {
		t.Fatal(err)
	}
	checkEvidence(t, filepath.Dir(evidencePath), evidence)
	checkRun(t, log)
}

func evidencePath(log string) string {
	const marker = "Evidence: "
	for _, line := range strings.Split(log, "\n") {
		if rest, ok := strings.CutPrefix(line, marker); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

func checkEvidence(t *testing.T, sessionDir string, evidence session.Evidence) {
	t.Helper()
	if evidence.Status != session.StatusRevoked || evidence.EndedAt == nil {
		t.Fatalf("status=%q ended=%v", evidence.Status, evidence.EndedAt)
	}
	if evidence.Task != "acme-sdk fails only in staging" {
		t.Fatalf("task = %q", evidence.Task)
	}
	opened := participant(t, evidence, "opened")
	joined := participant(t, evidence, "joined")
	if opened.Owner != "customer" || joined.Owner != "vendor" {
		t.Fatalf("owners = %q %q", opened.Owner, joined.Owner)
	}
	if !sameStrings(opened.Allow, []string{"logs/failure.txt"}) || !sameStrings(joined.Allow, []string{"notes/diag.txt"}) {
		t.Fatalf("allowlists = %v %v", opened.Allow, joined.Allow)
	}
	if !contains(opened.Capabilities, "share") || !contains(opened.Capabilities, "exec") {
		t.Fatalf("customer capabilities = %v", opened.Capabilities)
	}
	if !contains(joined.Capabilities, "share:approval-required") || !contains(joined.Capabilities, "exec") {
		t.Fatalf("vendor capabilities = %v", joined.Capabilities)
	}
	if len(evidence.Transcript) != 2 {
		t.Fatalf("transcript = %+v", evidence.Transcript)
	}
	openedEP := reach(t, evidence, opened.CapsuleID)
	joinedEP := reach(t, evidence, joined.CapsuleID)
	if openedEP.IP == "" || joinedEP.IP == "" {
		t.Fatalf("reachability = %+v", evidence.Reachability)
	}
	if openedEP.Name != opened.CapsuleID+".capsule.local" || joinedEP.Name != joined.CapsuleID+".capsule.local" {
		t.Fatalf("reachability names = %+v", evidence.Reachability)
	}
	if len(evidence.Artifacts) != 2 {
		t.Fatalf("artifacts = %+v", evidence.Artifacts)
	}
	checkArtifact(t, sessionDir, evidence.Artifacts, opened.CapsuleID, "logs/failure.txt", "acme-sdk 1.4.2\nstaging: dial timeout after 30s\n")
	checkArtifact(t, sessionDir, evidence.Artifacts, joined.CapsuleID, "notes/diag.txt", "Known issue: sdk 1.4.2 times out when staging DNS still points at the old edge.\n")
	if !granted(evidence, joined.CapsuleID, "share notes/diag.txt") {
		t.Fatalf("approvals = %+v", evidence.Approvals)
	}
	checkCommands(t, evidence, opened.CapsuleID, joined.CapsuleID, joinedEP.Name)
	for _, eventType := range []string{"session.created", "session.accepted", "session.shared", "share.denied", "command.denied", "approval.pending", "session.approved", "session.revoked"} {
		if !auditHas(evidence, eventType) {
			t.Fatalf("audit missing %s: %+v", eventType, evidence.Audit)
		}
	}
	if !auditMentions(evidence, "share.denied", "secrets/token.txt") || !auditMentions(evidence, "command.denied", "cat secrets/token.txt") {
		t.Fatalf("audit = %+v", evidence.Audit)
	}
}

func checkRun(t *testing.T, log string) {
	t.Helper()
	for _, want := range []string{
		"2 logs/failure.txt",
		"1 received, 0% packet loss",
		"Network is unreachable",
		"Name or service not known",
		`path "secrets/token.txt" is not allowlisted`,
		"approval required for share notes/diag.txt",
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("demo output missing %q", want)
		}
	}
	ls := outputLineAfter(log, "ls /workspace")
	if ls != "notes" {
		t.Fatalf("vendor workspace = %q", ls)
	}
}

func checkCommands(t *testing.T, evidence session.Evidence, customer, vendor, vendorName string) {
	t.Helper()
	want := map[string]bool{
		customer + " wc -l logs/failure.txt":                false,
		customer + " /usr/bin/ping -c 1 -W 1 " + vendorName: false,
		vendor + " ls /workspace":                           false,
	}
	for _, cmd := range evidence.Commands {
		if cmd.ExitCode != 0 {
			t.Fatalf("recorded command failed: %+v", cmd)
		}
		if strings.Contains(strings.Join(cmd.Argv, " "), "token") {
			t.Fatalf("secret command was recorded: %+v", cmd)
		}
		key := cmd.CapsuleID + " " + strings.Join(cmd.Argv, " ")
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for key, saw := range want {
		if !saw {
			t.Fatalf("evidence missing command %q from %+v", key, evidence.Commands)
		}
	}
}

func checkArtifact(t *testing.T, sessionDir string, artifacts []session.Artifact, capsuleID, path, body string) {
	t.Helper()
	for _, artifact := range artifacts {
		if artifact.CapsuleID != capsuleID || artifact.Path != path {
			continue
		}
		sum := sha256.Sum256([]byte(body))
		if artifact.SHA256 != hex.EncodeToString(sum[:]) {
			t.Fatalf("%s hash = %s", path, artifact.SHA256)
		}
		saved, err := os.ReadFile(filepath.Join(sessionDir, filepath.FromSlash(artifact.SavedAs)))
		if err != nil {
			t.Fatal(err)
		}
		if string(saved) != body {
			t.Fatalf("saved %s = %q", path, saved)
		}
		return
	}
	t.Fatalf("missing artifact %s from %s", path, capsuleID)
}

func reach(t *testing.T, evidence session.Evidence, capsuleID string) session.Endpoint {
	t.Helper()
	if evidence.Reachability == nil {
		t.Fatal("missing reachability")
	}
	for _, ep := range evidence.Reachability.Endpoints {
		if ep.CapsuleID == capsuleID {
			return ep
		}
	}
	t.Fatalf("missing endpoint for %s in %+v", capsuleID, evidence.Reachability)
	return session.Endpoint{}
}

func participant(t *testing.T, evidence session.Evidence, role string) session.Participant {
	t.Helper()
	for _, p := range evidence.Participants {
		if p.Role == role {
			return p
		}
	}
	t.Fatalf("missing %s participant in %+v", role, evidence.Participants)
	return session.Participant{}
}

func granted(evidence session.Evidence, capsuleID, action string) bool {
	for _, approval := range evidence.Approvals {
		if approval.CapsuleID == capsuleID && approval.Action == action && approval.Status == session.ApprovalGranted {
			return true
		}
	}
	return false
}

func auditHas(evidence session.Evidence, eventType string) bool {
	for _, event := range evidence.Audit {
		if event.Type == eventType {
			return true
		}
	}
	return false
}

func auditMentions(evidence session.Evidence, eventType, text string) bool {
	for _, event := range evidence.Audit {
		if event.Type == eventType && strings.Contains(event.Message, text) {
			return true
		}
	}
	return false
}

func outputLineAfter(log, command string) string {
	lines := strings.Split(log, "\n")
	for i, line := range lines {
		if strings.Contains(line, command) && i+1 < len(lines) {
			return lines[i+1]
		}
	}
	return ""
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

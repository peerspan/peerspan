#!/usr/bin/env bash
# Scoped agent peering, as the local CLI can run it today.
#
# A customer and a vendor each get a workcell. They open a session, exchange
# messages, and share only allowlisted files. One share waits for approval.
# Each workcell can reach the other by name for the life of the session.
# A secret stays in the customer workspace. A third capsule cannot use the
# link. Revoke removes it. The evidence bundle remains on disk.
#
# Requires Linux, root, nsenter, and python3. Uses a throwaway data directory.
# go test ./demo runs this script and checks the evidence bundle.
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
	echo "workcells require root" >&2
	exit 1
fi
for cmd in nsenter python3; do
	if ! command -v "$cmd" >/dev/null; then
		echo "demo requires $cmd" >&2
		exit 1
	fi
done

root=$(cd "$(dirname "$0")/.." && pwd)
data=$(mktemp -d /tmp/capsule-demo.XXXXXX)
bin="$data/capsule"
addr="127.0.0.1:8099"
export CAPSULE_ADDR="http://$addr"

say() { printf '\n== %s\n' "$*"; }
run() { printf '+' >&2; printf ' %q' "$@" >&2; printf '\n' >&2; "$@"; }
# refuse runs a command that should fail and shows its error.
refuse() {
	printf '+' >&2
	printf ' %q' "$@" >&2
	printf '\n' >&2
	set +e
	"$@"
	status=$?
	set -e
	if [[ "$status" -eq 0 ]]; then
		echo "demo: expected this to be refused" >&2
		exit 1
	fi
}

cleanup() {
	status=$?
	if [[ -n "${customer:-}" ]]; then "$bin" destroy "$customer" >/dev/null 2>&1 || true; fi
	if [[ -n "${vendor:-}" ]]; then "$bin" destroy "$vendor" >/dev/null 2>&1 || true; fi
	if [[ -n "${other:-}" ]]; then "$bin" destroy "$other" >/dev/null 2>&1 || true; fi
	if [[ -n "${serve_pid:-}" ]]; then kill "$serve_pid" >/dev/null 2>&1 || true; fi
	if [[ "$status" -ne 0 ]]; then
		echo "demo failed; data left at $data" >&2
	fi
}
trap cleanup EXIT

say "Build the CLI and start the control plane"
(cd "$root" && go build -o "$bin" ./cmd/capsule)
"$bin" serve --addr "$addr" --data "$data" >"$data/serve.log" 2>&1 &
serve_pid=$!
for _ in $(seq 1 50); do
	if "$bin" list >/dev/null 2>&1; then
		break
	fi
	sleep 0.1
done
"$bin" list >/dev/null

say "Customer workcell: a failure log, and a secret that will not be shared"
customer=$(run "$bin" create \
	--owner customer \
	--task "acme-sdk fails only in staging" \
	--capability share \
	--capability exec \
	--setup 'mkdir -p logs secrets && printf "%s\n" "acme-sdk 1.4.2" "staging: dial timeout after 30s" > logs/failure.txt && printf "%s\n" "STAGING_TOKEN=do-not-share" > secrets/token.txt')

say "Vendor workcell: a diagnostic note that needs approval before it is shared"
vendor=$(run "$bin" create \
	--owner vendor \
	--task "debug the staging failure" \
	--capability share:approval-required \
	--capability exec \
	--setup 'mkdir -p notes && printf "%s\n" "Known issue: sdk 1.4.2 times out when staging DNS still points at the old edge." > notes/diag.txt')

say "A third capsule, not invited to the session"
other=$(run "$bin" create \
	--owner bystander \
	--task "not a participant" \
	--capability exec)

customer_name=$("$bin" inspect "$customer" | python3 -c 'import json,sys; print(json.load(sys.stdin)["network"]["name"])')
vendor_name=$("$bin" inspect "$vendor" | python3 -c 'import json,sys; print(json.load(sys.stdin)["network"]["name"])')
printf 'customer %s  %s\n' "$customer" "$customer_name"
printf 'vendor   %s  %s\n' "$vendor" "$vendor_name"

say "Customer opens a session. Only the failure log and two commands are allowlisted"
session=$(run "$bin" session create \
	--capsule "$customer" \
	--task "acme-sdk fails only in staging" \
	--ttl 30m \
	--allow logs/failure.txt \
	--allow-exec "wc -l logs/failure.txt" \
	--allow-exec "/usr/bin/ping -c 1 -W 1 $vendor_name")

say "Vendor joins and publishes their own allowlist"
run "$bin" session accept "$session" \
	--capsule "$vendor" \
	--allow notes/diag.txt \
	--allow-exec "ls /workspace" \
	--allow-exec "/usr/bin/ping -c 1 -W 1 $customer_name" >/dev/null

say "The two sides exchange messages"
run "$bin" session message "$session" --from "$customer" --text "Failure is only in staging. Log attached next. I am not sharing the staging token." >/dev/null
run "$bin" session message "$session" --from "$vendor" --text "Send the failure log. I have a note on sdk 1.4.2, but it needs your approval before I share it." >/dev/null

say "The allowlisted log is copied into the session. The secret is refused"
run "$bin" session share "$session" --from "$customer" --path logs/failure.txt >/dev/null
refuse "$bin" session share "$session" --from "$customer" --path secrets/token.txt
refuse "$bin" exec "$customer" -- cat secrets/token.txt

say "The customer can run the allowlisted command, and nothing else"
run "$bin" exec "$customer" -- wc -l logs/failure.txt
refuse "$bin" exec "$customer" -- cat secrets/token.txt

say "The vendor workspace does not contain the customer's files"
run "$bin" exec "$vendor" -- ls /workspace

say "The vendor's note waits for approval, then shares on the second try"
refuse "$bin" session share "$session" --from "$vendor" --path notes/diag.txt
run "$bin" session approve "$session" --by "$vendor" --action "share notes/diag.txt" >/dev/null
run "$bin" session share "$session" --from "$vendor" --path notes/diag.txt >/dev/null

say "Each workcell can reach the other by name. The bystander cannot"
run "$bin" exec "$customer" -- /usr/bin/ping -c 1 -W 1 "$vendor_name"
customer_ip=$("$bin" inspect "$customer" | python3 -c 'import json,sys; print(json.load(sys.stdin)["network"]["endpoints"][0])')
printf 'customer endpoint %s\n' "$customer_ip"
refuse "$bin" exec "$other" -- /usr/bin/ping -c 1 -W 1 "$customer_ip"

say "Revoke removes the path"
run "$bin" session revoke "$session" >/dev/null
refuse "$bin" exec "$customer" -- /usr/bin/ping -c 1 -W 1 "$vendor_name"
endpoints=$("$bin" inspect "$customer" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["network"].get("endpoints") or []))')
if [[ "$endpoints" -ne 0 ]]; then
	echo "demo: expected the endpoint to be cleared" >&2
	exit 1
fi

say "Evidence bundle"
run "$bin" session export "$session"
printf '\nData directory: %s\n' "$data"
printf 'Evidence: %s/sessions/%s/evidence.json\n' "$data" "$session"

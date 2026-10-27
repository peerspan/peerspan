#!/usr/bin/env python3
"""New PR138 actual sibling deny/untrust and external-native recovery controls.

Only the first three named cases are bound here. Collision/old-alias fixtures,
the two timing cases, and final-head/installed/whole-migration acceptance are
separate scopes. No older positive case function is called.
"""
from __future__ import annotations

import argparse
import ast
import copy
import json
import os
from pathlib import Path
import re
import sys
import time
from urllib.parse import quote

from decentralized_fixtures import b64, raw_json, sha, unb64
from decentralized_policy_preparation_timing import without_clock, statement_id, sqlite_rows
from decentralized_policy_reapplication_fixture import PolicyPair
from decentralized_storage import CheckFailure, require
from decentralized_vectors import strict_output


PIN = "d96e17ac80cdf72f7e00c87f89a017970a366463"
SPEC = Path(__file__).with_name("decentralized_policy_reapplication_cases.json")
PLAN = Path(__file__).with_name("decentralized_policy_reapplication_plan.json")
BINDING = Path(__file__).with_name("decentralized_policy_withdrawal_recovery_binding.json")
CASES = [row["name"] for row in json.loads(SPEC.read_bytes())["cases"]][:3]
PREVIEW_FIELDS = set("context_id person_public_key host_public_key provider payload_base64 unsettled_seqs".split())
FIXED_EDIT = ("start", "signed", "signed_version", "signed_at", "reserved_at", "dropped", "dropped_at")

MCP = '''#!/usr/bin/env python3
import json,sys
from pathlib import Path
log=Path(sys.argv[1])
for line in sys.stdin:
 value=json.loads(line)
 if 'id' not in value:continue
 method=value['method']
 if method=='initialize':
  result={'protocolVersion':value['params']['protocolVersion'],'capabilities':{'tools':{},'resources':{}},'serverInfo':{'name':'independent-reapply','version':'1'}}
 elif method=='tools/list':
  result={'tools':[{'name':'inspect','description':'Fixture only','inputSchema':{'type':'object','properties':{}},'annotations':{'readOnlyHint':True}}]}
 elif method=='resources/list':result={'resources':[]}
 elif method=='tools/call':
  with log.open('a') as out:out.write(json.dumps({'method':method,'name':value['params']['name']})+'\\n')
  result={'content':[{'type':'text','text':'independent fixture result'}]}
 else:
  print(json.dumps({'jsonrpc':'2.0','id':value['id'],'error':{'code':-32601,'message':'fixture method absent'}}),flush=True);continue
 print(json.dumps({'jsonrpc':'2.0','id':value['id'],'result':result}),flush=True)
'''


class Recovery:
    def __init__(self, args):
        self.args, self.rows, self.pairs, self.trace = args, [], {}, []

    def case(self, index, call):
        began = time.monotonic()
        try:
            call()
        except BaseException as error:
            self.rows.append({"name":CASES[index], "passed":False, "error_type":type(error).__name__,
                "detail":str(error) if isinstance(error, CheckFailure) else "fixture/transport failure; protected receipts retained",
                "seconds":round(time.monotonic()-began, 3)})
            raise
        self.rows.append({"name":CASES[index], "passed":True, "seconds":round(time.monotonic()-began, 3)})

    def native(self, pair, label, *arguments):
        if label == "A":
            arguments = (*arguments, "--person-key", str(pair.original.path))
        return pair.cli(label, *arguments)

    def agent(self, pair, name):
        return pair.a.api("POST", "/v1/agents", {"name":name, "owner":"Independent Alice"}, status=201)[0]

    def initialize(self, label):
        pair = PolicyPair(self.args, self.args.work_dir/label); self.pairs[label] = pair
        pair.start()
        pair.narrow_optional_admin()
        pair.agents = {name:self.agent(pair, name) for name in ("reviewer", "sibling-only", "fresh-native")}
        self.native(pair, "A", "allow", "network", "--network", pair.network["id"], "--agent", "reviewer", "--no-tasks")
        rules = [rule for rule in pair.current("A")[3]["rules"] if rule["agent"] == "reviewer"]
        require(len(rules) == 1 and rules[0]["principals"] == ["network"] and rules[0]["actions"] == ["message.append"] and
            rules[0]["max_message_bytes"] == 65536 and rules[0].get("max_artifact_bytes", 0) == 0 and
            rules[0]["allow_disconnected"] is False, "top-level allow --no-tasks changed its exact documented message-only scope")
        if label == "untrust":
            self.native(pair, "A", "trust", pair.b.identity["id"], "--network", pair.network["id"])
            self.source(pair)
        pair.import_from("B", "A")
        pair.baseline = pair.current("A")
        require(pair.current("B")[0] == pair.baseline[0], "fixture siblings did not retain the identical actual starting policy")
        self.probe_permission(pair, label, allowed=True)
        pair.before_rows = pair.edit_rows("A")
        # The baseline publication's own outbox may be acknowledged in the
        # background; retire it first so the purity check observes only the read.
        pair.quiesce_deliveries()
        before_preview = pair.pure_snapshot("A")
        empty = pair.a.api("POST", pair.route+"/policy-edits/reapply-preview", {"provider_id":pair.original.person})[0]
        require(set(empty) == PREVIEW_FIELDS and empty["payload_base64"] == "-" and empty["unsettled_seqs"] == [] and
            pair.pure_snapshot("A") == before_preview, "empty reapply-preview changed durable state or invented unsettled content")
        return pair

    def source(self, pair):
        script = pair.root/"source_fixture.py"; script.write_text(MCP); script.chmod(0o700)
        pair.source_log = pair.root/"source_invocations.public.jsonl"
        pair.a.api("PUT", "/v1/agents/"+pair.agents["reviewer"]["id"]+"/tool-servers", {
            "workspace":str(pair.root), "servers":[{"name":"fixture", "transport":"stdio", "command":str(Path(sys.executable).resolve()),
                "args":[str(script), str(pair.source_log)], "env":{}, "url":None, "source":"claude-code:project"}], "values":{}}, timeout=40)
        pair.a.api("POST", "/v1/sources/open-to", {"host_id":pair.b.identity["id"]}, status=201)
        require(pair.a.api("GET", "/v1/grants")[0] == [], "untrust fixture has an independent manual-grant fallback")
        pair.sources = self.source_configuration(pair)

    def source_configuration(self, pair):
        return {"tool_servers":sha(raw_json(sqlite_rows(pair.a.host, "tool_servers", "agent_id,name,record"))),
            "tool_values":sha(raw_json(sqlite_rows(pair.a.host, "tool_values", "agent_id,server,field,value"))),
            "open_list":sha(raw_json(sqlite_rows(pair.a.host, "source_access", "host_id,created_at")))}

    def probe_permission(self, pair, label, *, allowed):
        person = "person_"+sha(unb64(pair.original.person))
        if label == "deny":
            identifier = "request_"+os.urandom(16).hex()
            body = {"request_id":identifier, "target_agent_id":pair.agents["reviewer"]["id"],
                "deadline":pair.creator.at(600), "content":"independent retained-withdrawal check",
                "policy":{"person_id":person, "version":pair.versions("A")["version"]}}
            value = pair.wire("A", "B", "POST", "/peer/v1/messages", body, status=200 if allowed else 403)
            messages = pair.a.api("GET", "/v1/messages?limit=1000")[0]
            accepted = [row for row in messages if row["request"]["request_id"] == identifier]
            require(bool(accepted) is allowed, "actual denied reviewer append persisted accepted work or baseline was not accepted")
            if allowed:
                require(value["request_id"] == identifier and value["sender_host_id"] == pair.b.identity["id"],
                    "baseline peer receipt changed sender/request")
        else:
            listing = pair.wire("A", "B", "GET", "/peer/v1/capabilities?network="+pair.network["id"])
            require(type(listing) is list, "self-source listing is not an array")
            sources = [row for row in listing if row["kind"] == "source" and row["capability"] == "reviewer/fixture"]
            require(bool(sources) is allowed, "unsettled untrust did not filter the actual source/self listing")
            if allowed:
                require(all(row["kind"] == "self" for row in sources[0]["via"]), "untrust baseline has independent policy fallback")
            prior_calls = pair.source_log.read_bytes() if pair.source_log.exists() else b""
            identifier = "call_"+os.urandom(16).hex()
            request = {"call_id":identifier, "capability":"reviewer/fixture", "operation":"inspect", "input":{},
                "deadline":pair.creator.at(600), "self":{"person_id":person, "network_id":pair.network["id"]}}
            pair.wire("A", "B", "POST", "/peer/v1/calls", request, status=200 if allowed else 403)
            received = [row for row in sqlite_rows(pair.a.host, "received_calls", "sender,call_id") if row[1] == identifier]
            require(bool(received) is allowed, "denied self call persisted accepted work or baseline was never accepted")
            if allowed:
                until = time.monotonic()+40  # Existing bounded reader, not a2s tool-latency promise.
                state = {"state":"unobserved"}
                while time.monotonic() < until:
                    state = pair.wire("A", "B", "GET", "/peer/v1/calls/"+identifier, timeout=max(.1, until-time.monotonic()))
                    if state["state"] == "succeeded":
                        break
                    require(state["state"] in {"queued", "running"}, "fixture source baseline call failed")
                    time.sleep(.1)
                require(state["state"] == "succeeded" and pair.source_log.read_bytes() != prior_calls,
                    "baseline self source never actually invoked its deterministic fixture tool")
            else:
                require((pair.source_log.read_bytes() if pair.source_log.exists() else b"") == prior_calls and
                    self.source_configuration(pair) == pair.sources,
                    "denied self call invoked source or source fixture/open-list changed")
        pair.trace.append({"actual_authorization":label, "expected_allowed":allowed, "fresh_request_id":identifier,
            "no_live_model_claim":True})

    def guard_refusal(self, pair, call):
        before = pair.pure_snapshot("A")
        value = call()
        pair.a.error(value, "state_conflict")
        after = pair.pure_snapshot("A")
        require(without_clock(before["databases"]) == without_clock(after["databases"]) and
            before["selected_provider"] == after["selected_provider"] and
            before["actual_provider_state"] == after["actual_provider_state"] and
            before["original_key_sha256"] == after["original_key_sha256"],
            "unsettled guard signed/applied/reserved or changed non-clock state")

    def withdrawal(self, label):
        pair = self.initialize(label)
        # Transport partition for the two signed siblings. Each host's signed
        # contact carries its real bootstrap listener, and a remembered member
        # may legitimately pull repair proofs over it during anti-entropy, so
        # dead advertised peer ports alone do not isolate them. Keep exactly one
        # sibling running while the other signs its edit; restarts change no state.
        pair.b.host.stop()
        if label == "deny":
            self.native(pair, "A", "deny", "network", "--network", pair.network["id"], "--agent", "reviewer")
        else:
            self.native(pair, "A", "untrust", pair.b.identity["id"], "--network", pair.network["id"])
        new_rows = pair.edit_rows("A")
        changed = set(new_rows)-set(pair.before_rows)
        require(len(changed) == 1, "actual native withdrawal did not produce exactly one local signed edit")
        pair.withdraw_seq = changed.pop(); pair.withdraw_row = copy.deepcopy(new_rows[pair.withdraw_seq]["record"])
        require(pair.withdraw_row["state"] == "settled" and pair.withdraw_row["signed"] != "-", "native withdrawal was not actually admitted/settled")
        pair.reference(pair.withdraw_row["start"]); pair.reference(pair.withdraw_row["signed"])
        pair.reservation = pair.reserve()
        pair.unsigned_seq = pair.reservation["seq"]
        require(pair.unsigned_seq > pair.withdraw_seq and pair.edit_rows("A")[pair.unsigned_seq]["record"]["state"] == "reserved",
            "fixture did not reserve one newer still-unsigned sequence before displacement")
        local = pair.current("A")
        pair.a.host.stop(); pair.b.host.start()
        self.native(pair, "B", "access", "allow", "--network", pair.network["id"], "--agent", "sibling-only",
            "--principal", "network", "--allow-disconnected")
        sibling = pair.current("B")
        pair.a.host.start()
        require(pair.a.host.api("GET", "/v1/host") == pair.a.identity and pair.b.host.api("GET", "/v1/host") == pair.b.identity,
            "partition restart replaced an actual sibling host identity")
        pair.trace.append({"sibling_partition":"one daemon stopped while the other signed; no store/key copy or clock change"})
        require(local[2]["predecessors"] == sibling[2]["predecessors"] == [pair.baseline[0]] and local[0] != sibling[0],
            "fixture did not produce two actual same-predecessor signed siblings")
        pair.import_from("A", "B")
        heads = sorted([local[0], sibling[0]])
        require(pair.versions("A")["head_ids"] == heads, "real policy fork was discarded or assigned a branch winner")
        for method, path, body in (("GET", pair.route+"/policy/"+quote(pair.original.person, safe=""), None),
            ("POST", pair.route+"/policy-edits/reapply-preview", {"provider_id":pair.original.person}),
            ("POST", pair.route+"/policy-edits", {"provider_id":pair.original.person})):
            value = pair.a.api(method, path, body, status=409)[0]; pair.a.error(value, "state_conflict")
        pair.resolve_branch("A", sibling)
        pair.resolved = pair.current("A")
        rows = pair.edit_rows("A")
        require(rows[pair.withdraw_seq]["record"]["state"] == "unsettled" and
            rows[pair.unsigned_seq]["record"]["state"] == "reserved", "resolver absorbed omitted withdrawal or signed the unused reservation")
        pair.quiesce_deliveries()
        self.guard_refusal(pair, lambda:pair.a.api("POST", pair.route+"/policy-edits", {"provider_id":pair.original.person}, status=409)[0])
        body = copy.deepcopy(pair.resolved[3])
        entries = {row["host"]:row["seq"] for row in body["edits"]}; entries[pair.a.identity["id"]] = pair.unsigned_seq
        body["edits"] = [{"host":host, "seq":entries[host]} for host in sorted(entries)]
        candidate = pair.original_payload("A", body, predecessors=[pair.resolved[0]])
        self.guard_refusal(pair, lambda:pair.action("A", candidate, status=409))
        body["capability_rules"].append({"host":pair.a.identity["id"], "capability":"guarded-claim", "principals":[],
            "max_input_bytes":1024, "allow_disconnected":True, "max_calls_per_hour":100})
        claim = pair.original_payload("A", body, predecessors=[pair.resolved[0]])
        self.guard_refusal(pair, lambda:pair.action("A", claim, claim="guarded-claim", status=409))
        # The selected public branch itself still permits the action. Denial
        # below must come from the independently retained local withdrawal.
        if label == "deny":
            require(any(row["agent"] == "reviewer" and "network" in row["principals"] for row in pair.resolved[3]["rules"]),
                "selected sibling content already denied reviewer permission")
        else:
            require(pair.b.identity["id"] in pair.resolved[3]["trusted_hosts"], "selected sibling content already untrusted B")
        self.probe_permission(pair, label, allowed=False)
        self.trace.append({"fixture":label, "actual_fork_heads":heads, "exact_selected_branch":sibling[0],
            "resolver_id":pair.resolved[0], "unsettled_withdrawal_seq":pair.withdraw_seq,
            "untouched_reserved_seq":pair.unsigned_seq, "frozen_withdrawal_sha256":sha(raw_json(pair.withdraw_row))})

    def external_recovery(self):
        for label, pair in self.pairs.items():
            pair.quiesce_deliveries()
            before = pair.pure_snapshot("A")
            root_refused = pair.a.api("POST", pair.route+"/policy-edits/reapply-preview", {"provider_id":"network_root"}, status=403)[0]
            pair.a.error(root_refused, "forbidden")
            require(pair.pure_snapshot("A") == before, "forbidden root preview changed policy/provider/private state")
            preview = pair.a.api("POST", pair.route+"/policy-edits/reapply-preview", {"provider_id":pair.original.person})[0]
            require(set(preview) == PREVIEW_FIELDS and preview["context_id"] == pair.network["context_id"] and
                preview["person_public_key"] == pair.original.person and preview["host_public_key"] == pair.a.identity["public_key"] and
                preview["provider"]["kind"] == "original_person" and preview["unsettled_seqs"] == [pair.withdraw_seq] and
                pair.pure_snapshot("A") == before, "exact reapply preview changed state/identity/provider or unsettled sequence")
            payload = strict_output(unb64(preview["payload_base64"]))
            body = strict_output(unb64(payload["body_base64"]))
            require(payload["root_state_id"] == pair.network["root_state_id"] and payload["predecessors"] == [pair.resolved[0]] and
                payload["sequence"] == pair.versions("A")["version"]+1 and
                payload["not_after"] > pair.short_admin_deadline and
                next(row["seq"] for row in body["edits"] if row["host"] == pair.a.identity["id"]) == pair.withdraw_seq,
                "preview did not pin exact current root/predecessor/max+1/old edit sequence")
            if label == "deny":
                require(not any(rule["agent"] == "reviewer" and "network" in rule["principals"] for rule in body["rules"]),
                    "reapply candidate restored the local reviewer withdrawal")
            else:
                require(pair.b.identity["id"] not in body["trusted_hosts"], "reapply candidate restored the local untrust")
            for entry in pair.resolved[3]["edits"]:
                if entry["host"] != pair.a.identity["id"]:
                    require(entry in body["edits"], "reapply preview changed another host's reflected edit")
            # Independent previews are reads, not persisted timestamp consent.
            time.sleep(1.05)
            again = pair.a.api("POST", pair.route+"/policy-edits/reapply-preview", {"provider_id":pair.original.person})[0]
            require(set(again) == PREVIEW_FIELDS and again["unsettled_seqs"] == [pair.withdraw_seq] and
                pair.pure_snapshot("A") == before, "second preview persisted consent/time/state")
            self.native(pair, "A", "allow", "network", "--network", pair.network["id"], "--agent", "fresh-native", "--no-tasks")
            after = pair.current("A"); rows = pair.edit_rows("A")
            fresh = [seq for seq in rows if seq > pair.unsigned_seq]
            require(len(fresh) == 1 and rows[fresh[0]]["record"]["state"] == "settled", "native recovery did not reserve/apply exactly one later unrelated edit")
            original = rows[pair.withdraw_seq]["record"]
            require(original["state"] in {"settled", "closed"} and all(original[key] == pair.withdraw_row[key] for key in FIXED_EDIT),
                "native reapply replaced frozen withdrawal history or failed to finish it")
            start = rows[fresh[0]]["record"]["start"]
            reapplied, reapplied_body = pair.reference(start)
            require(reapplied["predecessors"] == [pair.resolved[0]] and reapplied["sequence"] == payload["sequence"] and
                after[2]["predecessors"] == [start["statement_id"]] and after[2]["sequence"] == reapplied["sequence"]+1 and
                next(row["seq"] for row in reapplied_body["edits"] if row["host"] == pair.a.identity["id"]) == pair.withdraw_seq,
                "new native edit did not start from an actually admitted separate old-sequence reapply")
            require(rows[pair.unsigned_seq]["record"]["state"] == "reserved" and rows[pair.unsigned_seq]["record"]["signed"] == "-",
                "native recovery fabricated a signed reference for abandoned unsigned reservation")
            self.probe_permission(pair, label, allowed=False)
            pair.quiesce_deliveries()
            before_empty = pair.pure_snapshot("A")
            empty = pair.a.api("POST", pair.route+"/policy-edits/reapply-preview", {"provider_id":pair.original.person})[0]
            require(empty["payload_base64"] == "-" and empty["unsettled_seqs"] == [] and pair.pure_snapshot("A") == before_empty,
                "post-recovery empty preview signed or changed state")
            identity = pair.a.identity; retained_rows = pair.edit_rows("A")
            pair.a.host.stop(); pair.a.host.start()
            require(pair.a.host.api("GET", "/v1/host") == identity and pair.current("A")[0] == after[0] and
                pair.edit_rows("A") == retained_rows and sha(pair.original.path.read_bytes()) == pair.original_file_hash,
                "reopen replaced current policy/edit history/actual host/original")
            self.probe_permission(pair, label, allowed=False)
            self.trace.append({"fixture":label, "actual_old_sequence_reapplication":start["statement_id"],
                "later_new_native_policy":after[0], "new_native_edit_seq":fresh[0], "external_original_only":True})


def binding():
    directory = Path(__file__).parent; pending, found = [Path(__file__).resolve()], set()
    while pending:
        path = pending.pop()
        if path in found:
            continue
        found.add(path)
        for node in ast.walk(ast.parse(path.read_bytes(), filename=str(path))):
            names = [node.module] if isinstance(node, ast.ImportFrom) and node.level == 0 else (
                [item.name for item in node.names] if isinstance(node, ast.Import) else [])
            for name in names:
                target = directory/(name.split(".")[0]+".py")
                if target.is_file():
                    pending.append(target.resolve())
    found |= {SPEC.resolve(), PLAN.resolve()}
    return {"format":1, "contract_merge":PIN, "scope":CASES, "state":"frozen executable; explicit runtime offer required",
        "files":{str(path.relative_to(directory.parent)):sha(path.read_bytes()) for path in sorted(found)},
        "artifact":None, "probe":None, "source":None,
        "excluded_scopes":["collision groups", "historical aliases", "timing", "final head", "installed", "whole migration"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--emit-binding", type=Path)
    for name in ("host", "probe", "work-dir", "results"):
        parser.add_argument("--"+name, type=Path)
    for name in ("source", "host-sha256", "probe-sha256"):
        parser.add_argument("--"+name)
    args = parser.parse_args()
    if args.emit_binding:
        args.emit_binding.write_bytes(raw_json(binding())+b"\n"); return
    require(all((args.host, args.probe, args.source, args.host_sha256, args.probe_sha256, args.work_dir, args.results)),
        "runtime requires a complete explicitly reviewed source/artifact binding")
    require(re.fullmatch(r"[0-9a-f]{40}", args.source) is not None and sha(args.host.read_bytes()) == args.host_sha256 and
        sha(args.probe.read_bytes()) == args.probe_sha256, "runtime source/artifact binding differs")
    frozen = strict_output(BINDING.read_bytes())
    require(frozen["scope"] == CASES and frozen["files"] == binding()["files"], "frozen author input hashes changed")
    require(not args.work_dir.exists() and not args.results.exists(), "fresh runtime paths required; preserve all failed fixtures")
    args.work_dir.mkdir(mode=0o700); args.results.parent.mkdir(parents=True, exist_ok=True)
    suite = Recovery(args); failure = None
    try:
        suite.case(0, lambda:suite.withdrawal("deny"))
        suite.case(1, lambda:suite.withdrawal("untrust"))
        suite.case(2, suite.external_recovery)
    except BaseException as error:
        failure = error
    finally:
        for pair in suite.pairs.values():
            try:
                pair.close()
            except BaseException as error:
                failure = failure or error
        result = {"source":args.source, "contract_merge":PIN, "host_sha256":args.host_sha256, "probe_sha256":args.probe_sha256,
            "input_binding":binding(), "cases":suite.rows, "trace":suite.trace,
            "fixture_traces":{label:pair.trace for label,pair in suite.pairs.items()},
            "unevaluated":[name for name in CASES if name not in {row["name"] for row in suite.rows}],
            "all_passed":len(suite.rows) == len(CASES) and all(row["passed"] for row in suite.rows) and failure is None,
            "no_collision_alias_timing_final_head_installed_or_whole_migration_claim":True}
        args.results.write_bytes(raw_json(result)+b"\n"); args.results.chmod(0o600)
    if failure:
        raise failure


if __name__ == "__main__":
    main()

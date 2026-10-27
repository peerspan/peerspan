#!/usr/bin/env python3
"""NEW public legacy source for M07; no old positive test function is called.

This is uncounted fixture construction, not a writer/adoption test result.
Only Carol's fixture-owned ORIGINAL key signs her public pending targets/bans.
Actual daemon keys remain in their actual states and authenticate via --state.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta
import json
from pathlib import Path
import socket
import subprocess
import time
import traceback
from types import SimpleNamespace

from decentralized_complete_link import statement_id
from decentralized_fixtures import FixtureKeys, b64, lines, raw_json, sha, unb64
from decentralized_migration_identity import LegacyFixture, stamp
from decentralized_native_introduction import Introduction, ssh_public
from decentralized_runtime import CreationSuite
from decentralized_storage import CheckFailure, require
from decentralized_vectors import strict_output


def external_original_signature(key, message, folder, name):
    """Run only in that original person's signer fixture; never in a daemon."""
    path = folder/name; path.write_bytes(message); path.chmod(0o600)
    signature = path.with_name(path.name+".sig"); signature.unlink(missing_ok=True)
    result = subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", "peerspan-person-v1", "-q", str(path)],
        capture_output=True, timeout=10)
    require(result.returncode == 0, "fixture-owned external original signing failed")
    signature.chmod(0o600)
    return "".join(v for v in signature.read_text().splitlines() if not v.startswith("-----"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("baseline", "coordinator", "probe", "host", "fixture-dir", "results"):
        parser.add_argument("--"+name, type=Path, required=True)
    parser.add_argument("--source", required=True); args = parser.parse_args()
    for name in ("baseline", "coordinator", "probe", "host", "fixture_dir", "results"): setattr(args, name, getattr(args, name).resolve())
    args.fixture_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    keys = FixtureKeys(); legacy = None; current = []; failure = detail = None; manifest = None; began = time.monotonic()
    try:
        legacy = LegacyFixture(SimpleNamespace(work_dir=args.fixture_dir, baseline=args.baseline, coordinator=args.coordinator), keys)
        peers = {}
        for label in ("owner", "selected"):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.bind(("127.0.0.1", 0)); peers[label] = "127.0.0.1:"+str(s.getsockname()[1])
            legacy.hosts[label].host.run_arguments = ["--peer-listen", peers[label], "--advertise", peers[label]]
        legacy.build()
        # Legacy creation does not imply a policy stream. Establish this
        # distinct-owner maximum explicitly before any migration snapshot.
        policy_issued = stamp(legacy.now)
        policy_until = stamp(legacy.now+timedelta(days=1))
        policy_message = lines("peerspan-policy-v1", legacy.network, legacy.person, 1, policy_issued, policy_until)
        policy = {"network_id":legacy.network, "person_public_key":legacy.person, "version":1,
            "issued_at":policy_issued, "valid_until":policy_until, "rules":[]}
        policy["signature"] = external_original_signature(legacy.person_file, policy_message, args.fixture_dir, "alice-empty-policy")
        Introduction.verify_original(SimpleNamespace(person=legacy.person, b=legacy.hosts["owner"]), policy["signature"], policy_message)
        legacy.api("owner", "POST", "/v1/networks/"+legacy.network+"/policy", {"policy":policy}, status=201)
        carol = args.fixture_dir/"carol-signer"; carol.mkdir(mode=0o700)
        original = carol/"original-ed25519"
        made = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(original)], capture_output=True, timeout=10)
        require(made.returncode == 0, "independent Carol original generation failed")
        person = ssh_public(original)
        legacy.api("owner", "POST", "/v1/networks/"+legacy.network+"/persons",
            {"person_public_key":person, "member":"Hostless Carol <copies>&proofs"}, status=201)
        records = []; targets = {}
        issued = stamp(legacy.now); expires = stamp(legacy.now+timedelta(days=1))
        for index in range(3):
            device = keys.public("M07-retired-target-"+str(0 if index < 2 else 1))
            nonce = b64(bytes.fromhex(sha(("M07-independent-pending-"+str(index)).encode())))
            request = "link_"+sha(lines("peerspan-link-request-id-v1", legacy.coordinator_key,
                legacy.hosts["selected"].identity["public_key"], device, nonce))
            certificate = {"format":1, "network_id":legacy.network, "person_public_key":person, "device_public_key":device,
                "host_public_key":legacy.hosts["selected"].identity["public_key"], "parent_id":"root", "scopes":7,
                "issued_at":issued, "not_after":expires, "request_id":request}
            message = lines("peerspan-device-certificate-v1", legacy.network, person, device, certificate["host_public_key"],
                "root", 7, issued, expires, request)
            certificate_id = "dc_"+sha(message)
            certificate["signature"] = external_original_signature(original, message, carol, "pending-%d" % index)
            verifier = SimpleNamespace(person=person, b=legacy.hosts["owner"])
            Introduction.verify_original(verifier, certificate["signature"], message)
            revocation = {"format":1, "network_id":legacy.network, "person_public_key":person, "target_device_public_key":device,
                "target_certificate_id":certificate_id, "issuer_certificate_id":"root", "revoked_at":issued}
            message = lines("peerspan-device-revoke-v1", legacy.network, person, device, certificate_id, "root", issued)
            revocation["signature"] = external_original_signature(original, message, carol, "ban-%d" % index)
            Introduction.verify_original(verifier, revocation["signature"], message)
            for kind, body in (("certificate", certificate), ("device_revocation", revocation)):
                raw = raw_json(body); proof = "pf_"+sha(lines("peerspan-link-proof-v1", kind, sha(raw)))
                records.append({"id":proof, "kind":kind, "body_base64":b64(raw)})
                if kind == "device_revocation": targets.setdefault(device, []).append(proof)
        captures = args.fixture_dir/"public-source-wire"; captures.mkdir(mode=0o700)
        def wire(method, body=None):
            result = subprocess.run([str(args.probe), "--state", str(legacy.hosts["selected"].host.state),
                "--address", peers["owner"], "--alpn", "peerspan-peer/1", "--method", method,
                "--path", "/peer/v1/networks/"+legacy.network+"/link-catalog", *(["--body-stdin"] if body is not None else [])],
                input=None if body is None else raw_json(body), capture_output=True,
                env=legacy.hosts["selected"].host.environment, timeout=35)
            index = len(list(captures.glob("*.json")))+1
            (captures/("%03d.stdout" % index)).write_bytes(result.stdout)
            (captures/("%03d.stderr" % index)).write_bytes(result.stderr)
            (captures/("%03d.stdout" % index)).chmod(0o600)
            (captures/("%03d.stderr" % index)).chmod(0o600)
            require(result.returncode == 0, "legacy fixture authenticated peer transport failed")
            value = strict_output(result.stdout)
            (captures/("%03d.json" % index)).write_bytes(raw_json(value))
            require(value["status"] == 200, "legacy fixture public catalog writer refused exact pending-target/revocation source")
            return value["body"]["catalog"]
        catalog = wire("GET")
        require(catalog["network_id"] == legacy.network, "source peer returned another network")
        catalog["objects"] += records; catalog["objects"].sort(key=lambda v:v["id"])
        legacy.tick(2); wire("POST", {"catalog":catalog}); retained = wire("GET")
        actual = {v["id"]:v for v in retained["objects"]}
        require(all(actual.get(v["id"]) == v for v in records), "source catalog failed to retain exact original target/ban bytes")
        legacy.stop(); legacy = None
        baseline = strict_output((args.fixture_dir/"legacy-public-baseline.json").read_bytes())
        specs = {v["label"]:v for v in baseline["specs"] if v["label"] in ("owner", "selected")}
        decision = stamp(datetime.fromisoformat(baseline["decision_time"].replace("Z", "+00:00"))+timedelta(seconds=12))
        clock = args.fixture_dir/"authority-clock"; clock.write_text(decision); clock.chmod(0o600)
        instances = {}
        for label in ("owner", "selected"):
            root = args.fixture_dir/("prepare-"+label); root.mkdir(mode=0o700)
            suite = CreationSuite(args.host, root, keys); suite.host.state = args.fixture_dir/label/"state"
            suite.host.environment.update(PEERSPAN_DEC_TEST_MODE="1", PEERSPAN_DEC_TEST_CLOCK_FILE=str(clock))
            suite.host.start(); current.append(suite); instances[label] = suite
            require(suite.host.api("GET", "/v1/host")["public_key"] == specs[label]["host_public_key"], "migration setup replaced actual host")
        identities = []
        for label, suite in instances.items():
            value = suite.api("POST", "/v2/networks/"+specs[label]["network_id"]+"/migration/identity",
                {"scopes":specs[label]["scopes"], "approve":True})[0]
            identities.append(value["identity"])
        identities.sort(key=lambda v:v["host_public_key"])
        owner = instances["owner"]; network = specs["owner"]["network_id"]; route = "/v2/networks/"+network+"/migration"
        owner.api("POST", route+"/prepare", {"roster":identities, "signature_format":"ed25519", "approve":True})
        for _ in range(16):
            owner.api("POST", route+"/resume", {})
            view = owner.api("GET", route)[0]
            if view["proposal_id"] == "-": continue
            evidence = owner.api("GET", route+"/evidence")[0]
            if evidence["prepared_catalog_base64"] == "-": continue
            prepared = strict_output(unb64(evidence["prepared_catalog_base64"]))
            persons = [(entry, strict_output(unb64(entry["body_base64"]))) for entry in prepared["objects"] if entry["kind"] == "person_lease"]
            matches = [(entry, value) for entry, value in persons if strict_output(unb64(value["payload_base64"]))["subject"]["person_public_key"] == person]
            if len(matches) == 1 and all(v["signature"] != "-" for v in matches[0][1]["signatures"]): break
        else: raise CheckFailure("public root preparation did not expose complete shared Carol P")
        owner.api("POST", route+"/review", {"proposal_id":view["proposal_id"], "approve":True})
        source = strict_output(unb64(evidence["source_catalog_base64"])); source_state = strict_output(unb64(evidence["source_state_base64"]))
        source_by_id = {v["id"]:v for v in source["objects"]}
        require(all(source_by_id.get(v["id"]) == v for v in records), "root proposal omitted/rewrote exact required original proofs")
        restriction_ids = {v["proof_id"] for v in source_state["admitted_restrictions"] if v["person_public_key"] == person and v["kind"] == "device_revocation"}
        require(restriction_ids == {v for ids in targets.values() for v in ids}, "source bans are not independently retained/endorsed applicable restrictions")
        require(any(v["subject"] != person for v in source_state["access_maxima"]), "source lacks an unrelated-person maximum")
        expected_maximum = {"kind":"policy", "subject":specs["owner"]["person_public_key"], "version":1,
            "message_hash":sha(policy_message)}
        require(expected_maximum in source_state["access_maxima"], "source omitted or changed the independently signed unrelated Alice maximum")
        require(any(strict_output(unb64(v["body_base64"])) == policy for v in source["objects"]),
            "source omitted Alice's exact independently verified legacy policy")
        proposal = strict_output(unb64(evidence["proposal_base64"])); payload = strict_output(unb64(proposal["payload_base64"]))
        require(sha(unb64(evidence["source_catalog_base64"])) == payload["source_catalog_sha256"] and
                sha(unb64(evidence["source_state_base64"])) == payload["source_state_sha256"], "root proposal does not endorse original source bytes")
        descriptor = strict_output(unb64(payload["legacy_descriptor_base64"]))
        require(payload["legacy_epoch"] == 0 and payload["legacy_root_public_key"] == descriptor["genesis_root_public_key"],
            "bounded source setup unexpectedly changed its actual original root")
        admissions = [strict_output(unb64(v["body_base64"])) for v in source["objects"] if v["kind"] == "person_admission"]
        admissions = [v for v in admissions if v["person_public_key"] == person]
        require(len(admissions) == 1 and admissions[0]["network_id"] == network and admissions[0]["epoch"] == 0,
            "Carol has no exact source root admission")
        admission = admissions[0]
        owner.verify_raw(payload["legacy_root_public_key"], lines("peerspan-person-admit-v1", network, 0,
            person, admission["member"], admission["admitted_at"]), admission["signature"])
        require(not any(v["person_public_key"] == person for v in identities), "Carol became a roster host owner")
        source_checks = {"all_original_Carol_certificate_and_revocation_SSHSIGs_verified":True,
            "exact_current_root_Carol_admission_verified":True,
            "stable_targets_independently_constructed":len(targets), "source_revocation_proofs":sum(map(len, targets.values())),
            "Carol_is_hostless_and_distinct_from_actual_writer":True}
        manifest = {"format":1, "network_id":network, "writer_host_public_key":specs["owner"]["host_public_key"],
            "writer_person_public_key":specs["owner"]["person_public_key"], "copy_person_public_key":person,
            "proposal_id":view["proposal_id"], "context_id":view["context_id"], "root_state_id":view["root_state_id"],
            "person_lease_id":statement_id(matches[0][1]), "source_targets":{k:sorted(v) for k,v in sorted(targets.items())},
            "source_records":records, "independent_source_checks":source_checks,
            "access_maxima":source_state["access_maxima"], "evidence":evidence,
            "proposal_window":[payload["issued_at"], payload["expires_at"]], "decision_time":decision,
            "artifact":{"path":str(args.host), "source":args.source, "sha256":sha(args.host.read_bytes())}}
        public = args.fixture_dir/"M07-public-fixture.json"; public.write_bytes(raw_json(manifest)); public.chmod(0o600)
        private = args.fixture_dir/"M07-local-signer.private.json"
        private.write_bytes(raw_json({"original_key_path":str(original), "signer_home":str(carol)})); private.chmod(0o600)
    except BaseException as error:
        failure = type(error).__name__; detail = str(error) if isinstance(error, CheckFailure) else "fixture/transport failure"
        diagnostic = args.fixture_dir/"failure.traceback.private"
        diagnostic.write_text(traceback.format_exc()); diagnostic.chmod(0o600)
    finally:
        for suite in reversed(current): suite.host.stop()
        if legacy is not None: legacy.stop()
        keys.close()
    value = {"setup_only":True, "M07_test_cases_executed":0, "implementation_source_read":False,
        "failure":failure, "detail":detail, "seconds":round(time.monotonic()-began, 3),
        "public_manifest":None if manifest is None else {"path":str(args.fixture_dir/"M07-public-fixture.json"),
            "sha256":sha((args.fixture_dir/"M07-public-fixture.json").read_bytes())},
        "suite_sha256":sha(Path(__file__).read_bytes()), "old_sources_untouched":True, "passed":failure is None}
    args.results.parent.mkdir(parents=True, exist_ok=True); args.results.write_text(json.dumps(value, indent=2)+"\n")
    return 0 if failure is None else 1


if __name__ == "__main__": raise SystemExit(main())

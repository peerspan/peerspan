#!/usr/bin/env python3
"""Genuine merged OAuth22 state through public APIs, for additive preservation.

This fixture uses only PR86's public capability/OAuth contract and our own
earlier black-box storage support. It never reads product source/tests or
populates internal columns. No DEC23 opening expectation is encoded here.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import threading
import time
from urllib.parse import parse_qs, urlencode, urlsplit

from decentralized_fixtures import FixtureKeys, raw_json, sha
from decentralized_storage import (CheckFailure, Host, make_baseline, public_snapshot,
                                   require, retain_public, running, snapshot, tree_hashes)


PIN = "ec1052fa71b83f24921fdf70dfc7468cdd488ea4"


class OAuthFixture:
    """An owned loopback MCP resource and PKCE authorization server."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.private = {name: secrets.token_urlsafe(32) for name in
                        ("client_id", "client_secret", "registration_access_token",
                         "access_token", "refresh_token", "header_token")}
        self.codes: dict[str, tuple[str, str]] = {}
        self.redirects: set[str] = set()
        self.events: list[dict] = []
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *unused) -> None:
                pass

            def setup(self) -> None:
                super().setup()
                self.connection.settimeout(10)

            def respond(self, status: int, value=None, headers: dict | None = None) -> None:
                body = b"" if value is None else raw_json(value)
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                if value is not None:
                    self.send_header("Content-Type", "application/json")
                for key, field in (headers or {}).items():
                    self.send_header(key, field)
                self.end_headers()
                if body:
                    self.wfile.write(body)
                fixture.events.append({"method": self.command,
                    "path": urlsplit(self.path).path, "status": status})

            def do_GET(self) -> None:
                path = urlsplit(self.path).path
                if path == "/metadata":
                    self.respond(200, {"resource": fixture.base + "/mcp/oauth",
                        "authorization_servers": [fixture.base], "scopes_supported": ["read"]})
                elif path == "/.well-known/oauth-authorization-server":
                    self.respond(200, {"issuer": fixture.base,
                        "authorization_endpoint": fixture.base + "/authorize",
                        "token_endpoint": fixture.base + "/token",
                        "registration_endpoint": fixture.base + "/register",
                        "code_challenge_methods_supported": ["S256"],
                        "token_endpoint_auth_methods_supported": ["client_secret_post"]})
                elif path == "/authorize":
                    query = parse_qs(urlsplit(self.path).query, strict_parsing=True)
                    if (query.get("response_type") != ["code"] or
                        query.get("client_id") != [fixture.private["client_id"]] or
                        query.get("redirect_uri", [None])[0] not in fixture.redirects or
                        query.get("code_challenge_method") != ["S256"] or
                        query.get("resource") != [fixture.base + "/mcp/oauth"] or
                        query.get("scope") != ["read"] or
                        len(query.get("state", [])) != 1 or len(query.get("code_challenge", [])) != 1):
                        self.respond(400, {"error": "invalid_request"}); return
                    code = secrets.token_urlsafe(24)
                    redirect = query["redirect_uri"][0]
                    fixture.codes[code] = (query["code_challenge"][0], redirect)
                    self.respond(302, headers={"Location": redirect + "?" + urlencode(
                        {"code": code, "state": query["state"][0]})})
                else:
                    self.respond(404, {"error": "fixture_not_found"})

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 <= length <= 1048576:
                    self.respond(413); return
                raw = self.rfile.read(length)
                path = urlsplit(self.path).path
                if path == "/register":
                    value = json.loads(raw)
                    if (set(value) != {"client_name", "redirect_uris", "grant_types", "response_types",
                                      "token_endpoint_auth_method", "application_type"} or
                        not value["client_name"].startswith("Peerspan") or
                        value["grant_types"] != ["authorization_code", "refresh_token"] or
                        value["response_types"] != ["code"] or
                        value["token_endpoint_auth_method"] != "none" or value["application_type"] != "native" or
                        len(value["redirect_uris"]) != 1):
                        self.respond(400, {"error": "invalid_client_metadata"}); return
                    redirect = value["redirect_uris"][0]
                    uri = urlsplit(redirect)
                    if uri.scheme != "http" or uri.hostname != "127.0.0.1" or uri.path != "/callback":
                        self.respond(400, {"error": "invalid_redirect_uri"}); return
                    fixture.redirects.add(redirect)
                    self.respond(201, {**{name: fixture.private[name] for name in
                        ("client_id", "client_secret", "registration_access_token")},
                        "token_endpoint_auth_method": "client_secret_post"})
                elif path == "/token":
                    fields = parse_qs(raw.decode(), strict_parsing=True)
                    code = fields.get("code", [""])[0]
                    prior = fixture.codes.pop(code, None)
                    verifier = fields.get("code_verifier", [""])[0]
                    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
                    if (prior is None or prior != (challenge, fields.get("redirect_uri", [""])[0]) or
                        fields.get("grant_type") != ["authorization_code"] or
                        fields.get("client_id") != [fixture.private["client_id"]] or
                        fields.get("client_secret") != [fixture.private["client_secret"]] or
                        fields.get("resource") != [fixture.base + "/mcp/oauth"]):
                        self.respond(400, {"error": "invalid_grant"}); return
                    self.respond(200, {"access_token": fixture.private["access_token"],
                        "refresh_token": fixture.private["refresh_token"], "token_type": "Bearer",
                        "expires_in": 86400, "scope": "read"})
                elif path in {"/mcp/oauth", "/mcp/headers"}:
                    token = fixture.private["access_token" if path.endswith("oauth") else "header_token"]
                    if self.headers.get("Authorization") != "Bearer " + token:
                        self.respond(401, headers={"WWW-Authenticate":
                            'Bearer resource_metadata="' + fixture.base + '/metadata", scope="read"'})
                        return
                    request = json.loads(raw)
                    if "id" not in request:
                        self.respond(202); return
                    if request["method"] == "initialize":
                        value = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}, "resources": {}},
                                 "serverInfo": {"name": "independent-oauth22", "version": "1"}}
                    elif request["method"] == "tools/list":
                        value = {"tools": [{"name": "inspect", "description": "Fixture metadata only",
                            "inputSchema": {"type": "object", "properties": {"repo": {"type": "string"}},
                                            "required": ["repo"]}, "annotations": {"readOnlyHint": True}}]}
                    elif request["method"] == "resources/list":
                        value = {"resources": [{"uri": "fixture://remote/catalog", "name": "Fixture remote catalog",
                            "description": "Owned loopback fixture", "mimeType": "application/json"}]}
                    else:
                        self.respond(200, {"jsonrpc": "2.0", "id": request["id"],
                            "error": {"code": -32601, "message": "fixture method absent"}}); return
                    self.respond(200, {"jsonrpc": "2.0", "id": request["id"], "result": value})
                else:
                    self.respond(404, {"error": "fixture_not_found"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.base = "http://127.0.0.1:" + str(self.server.server_address[1])
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def authorize(self, address: str) -> str:
        uri = urlsplit(address)
        require(uri.scheme == "http" and uri.netloc == urlsplit(self.base).netloc and uri.path == "/authorize",
                "login selected an unowned authorization endpoint")
        connection = http.client.HTTPConnection(uri.hostname, uri.port, timeout=10)
        try:
            connection.request("GET", uri.path + "?" + uri.query)
            response = connection.getresponse(); response.read()
            require(response.status == 302, "fixture authorization did not validate the public PKCE request")
            return response.getheader("Location")
        finally:
            connection.close()

    def close(self) -> None:
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=5)


def create_oauth_baseline(binary: Path, root: Path, keys: FixtureKeys, rows: list[dict]) -> tuple[Path, dict, dict]:
    state, _, facts = make_baseline(binary, root, keys, expected_version=22)
    rows.append({"name": "actual22_existing_product_state_created", "passed": True})
    fixture = OAuthFixture(root)
    host = Host(binary, state, root / "oauth-setup", "oauth22")
    try:
        with running(host):
            definitions = [{"name": "fixture", "transport": "stdio", "command": os.path.realpath(os.sys.executable),
                "args": [str(root / "owned_mcp_fixture.py")], "env": {"FIXTURE_SECRET": {"source": "literal"}},
                "url": None, "source": "claude-code:project"}]
            for name in ("oauth", "headers"):
                definitions.append({"name": name, "transport": "remote", "command": None, "args": [], "env": {},
                    "url": fixture.base + "/mcp/" + name, "source": "independent-oauth22:project",
                    "remote": {"protocol": "http", "oauth": None if name == "headers" else
                        {"client_id": None, "scopes": None, "callback_port": None}, "headers_helper": False},
                    "headers": {"Authorization": {"source": "captured", "variables": ["FIXTURE_HEADER_TOKEN"]}}
                        if name == "headers" else {}})
            host.api("PUT", "/v1/agents/" + facts["agent_id"] + "/tool-servers", {"workspace": str(root),
                "servers": definitions, "values": {"fixture": {"env.FIXTURE_SECRET": secrets.token_hex(32)},
                    "headers": {"headers.Authorization": "Bearer " + fixture.private["header_token"],
                                "header_templates.Authorization": "Bearer ${FIXTURE_HEADER_TOKEN}"}}})
            route = "/v1/sources/" + facts["agent_id"] + "/oauth/login"
            login = host.api("POST", route, {"account": "independent fixture account"})
            require(set(login) == {"login_id", "authorization_url", "redirect_uri", "expires_at"},
                    "OAuth login public shape differs")
            completed = host.api("POST", "/v1/oauth/logins/" + login["login_id"] + "/complete",
                                 {"callback_url": fixture.authorize(login["authorization_url"])})
            require(completed["registration"] == "dcr" and completed["issuer"] == fixture.base and
                    completed["scopes"] == "read" and completed["account"] == "independent fixture account",
                    "real DCR/PKCE completion lost the requested credential facts")
            views = public_snapshot(host, facts)
            servers = next(a["servers"] for a in views["sources"]["agents"] if a["agent"]["id"] == facts["agent_id"])
            oauth = next(s for s in servers if s["name"] == "oauth")
            headers = next(s for s in servers if s["name"] == "headers")
            require(oauth["auth"]["mode"] == "oauth" and oauth["auth"]["state"] == "ok" and oauth["shareable"]
                    and oauth["snapshot_error"] is None and oauth["tools"] and oauth["resources"],
                    "OAuth baseline lacks a usable real signed-in source snapshot")
            require(headers["auth"]["mode"] == "headers" and headers["shareable"] and headers["snapshot_error"] is None,
                    "configured header baseline was not usable")
            for secret in fixture.private.values():
                require(secret not in json.dumps(views) and secret not in json.dumps(completed),
                        "a public response exposed a fixture credential")
            retain_public(root, "actual22", views)
            rows.append({"name": "real_dcr_pkce_tokens_headers_and_snapshots", "passed": True,
                         "http_event_count": len(fixture.events)})
    finally:
        fixture.close()
        events = root / "owned-oauth-public-events.json"
        events.write_bytes(raw_json(fixture.events)); events.chmod(0o600)
    stored = snapshot(state)
    require(stored["user_version"] == 22 and stored["tables"].get("oauth_clients", {}).get("rows") and
            stored["tables"].get("oauth_credentials", {}).get("rows"), "public sign-in did not persist actual OAuth22 state")
    facts["snapshot_sha256"] = sha(raw_json(stored))
    facts["state_file_hashes"] = tree_hashes(state)
    return state, views, facts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--results", type=Path, required=True)
    args = parser.parse_args()
    args.work_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    keys, rows, failure = FixtureKeys(), [], None
    started = time.monotonic()
    try:
        state, views, facts = create_oauth_baseline(args.baseline.resolve(), args.work_dir.resolve(), keys, rows)
        facts_file = args.work_dir / "actual22.facts.json"
        facts_file.write_bytes(raw_json(facts)); facts_file.chmod(0o600)
    except BaseException as error:
        failure = {"type": type(error).__name__, "detail": str(error) if isinstance(error, CheckFailure) else "fixture/transport failure"}
    finally:
        keys.close()
    result = {"public_contract_pin": PIN, "implementation_source_read": False,
        "suite_sha256": sha(Path(__file__).read_bytes()), "baseline": str(args.baseline.resolve()),
        "baseline_sha256": sha(args.baseline.read_bytes()), "rows": rows, "failure": failure,
        "seconds": round(time.monotonic()-started, 3), "passed": failure is None,
        "scope": "actual merged OAuth22 baseline creation only; no DEC upgrade or new-mode runtime claim"}
    args.results.parent.mkdir(parents=True, exist_ok=True)
    args.results.write_text(json.dumps(result, indent=2)+"\n")
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

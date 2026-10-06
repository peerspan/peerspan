"""Explicit integration fixture: JSON files and Python, with no MCP or model."""
import json
import os
from pathlib import Path
import sys

request = json.load(sys.stdin)
ctx = request["context"]
mode = ctx["options"].get("mode", "normal")
if mode == "malformed":
    print(json.dumps({"version": "token_" + "a" * 64, "checks": []}))
    sys.exit(0)
if mode == "oversized":
    print("x" * (2 << 20))
    sys.exit(0)
if mode == "stderr":
    print("token_" + "a" * 64, file=sys.stderr)
    sys.exit(1)
response = {"version": 1, "checks": []}
config = {"socket": ctx["adapter_socket"], "credential": ctx["credential_file"]}
if request["operation"] == "prepare":
    response["state"] = {"marker": ctx["options"].get("marker"), "received_keys": sorted(ctx), "transport": "json-file"}
    response["files"] = {"consumer.json": json.dumps(config)}
    if mode == "reserved-file":
        response["files"] = {"credential.json": "forged"}
    if mode == "traversal":
        response["files"] = {"../outside": "forged"}
    if mode == "check-error":
        response["checks"] = [{"name": "health", "status": "error", "detail": "token_" + "a" * 64}]
elif request["operation"] == "check":
    try:
        valid = json.loads((Path(ctx["directory"]) / "consumer.json").read_text()) == config
    except (OSError, ValueError):
        valid = False
    response["checks"] = [{"name": "configuration", "status": "ok" if valid else "error", "detail": "Private consumer configuration must match this attachment."}]
elif request["operation"] == "launch":
    program = Path(__file__).with_name("harness.py")
    response["launch"] = {"program": sys.executable, "args": [str(program), *ctx["arguments"]]}
print(json.dumps(response))

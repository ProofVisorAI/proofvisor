#!/usr/bin/env python3
"""Interoperability test: proofvisord in front of a real third-party MCP server.

The third-party server is the Model Context Protocol reference server
`@modelcontextprotocol/server-everything` (pinned version below), started
with `npx` in its native Streamable HTTP mode (`streamableHttp`, endpoint
`http://127.0.0.1:<PORT>/mcp`). No stdio bridge is needed: the package
speaks Streamable HTTP itself.

The test then starts `proofvisord` with one `[[backends]]` entry that points
at that server (`transport = "mcp"`), and drives the gateway as an MCP
client over plain HTTP:

  1. `initialize` negotiates protocol version 2025-11-25 and returns an
     `MCP-Session-Id`.
  2. `tools/list` shows the third-party `echo` tool with the input schema
     the third-party server published; `get-sum` is withheld because the
     intent map (the allow-list) does not name it.
  3. `tools/call echo` is forwarded and answered by the third-party server.
  4. `tools/call get-sum` is refused by the gateway with `UNMAPPED_TOOL`.
  5. `DELETE /mcp` closes the audited session and returns its signed
     receipt, whose `tool_calls` summary records both calls (one allowed,
     one blocked). When `pvctl` is available the receipt is verified
     offline against the signing key.

Requirements: Python 3 standard library, Node.js 24 or later with `npx`
(network access on the first run to fetch the server package), and a
previously built `proofvisord` (set PROOFVISORD or pass --proofvisord).
Everything runs on loopback with private temporary files.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
import uuid


ROOT = Path(__file__).resolve().parents[1]
SERVER_PACKAGE = "@modelcontextprotocol/server-everything@2.1.0"
PROTOCOL_VERSION = "2025-11-25"
MAX_RESPONSE = 4 * 1024 * 1024
ALLOWED_TOOL = "echo"
BLOCKED_TOOL = "get-sum"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def http(method, url, headers=None, body=None, timeout=30):
    """One HTTP exchange; returns (status, headers, bytes). HTTP errors are
    returned, not raised, so the caller can assert on them."""
    data = json.dumps(body).encode() if body is not None else None
    request = Request(url, data=data, method=method, headers=headers or {})
    try:
        response = build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=timeout)
    except HTTPError as error:
        response = error
    with response:
        payload = response.read(MAX_RESPONSE + 1)
        if len(payload) > MAX_RESPONSE:
            raise RuntimeError("response exceeded the size bound")
        return response.status, dict(response.headers.items()), payload


def decode_rpc(headers, payload):
    """Decode a JSON or SSE-framed JSON-RPC reply into a dict."""
    content_type = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
    text = payload.decode("utf-8", "replace")
    if "text/event-stream" in content_type:
        messages = [json.loads(m.group(1)) for m in re.finditer(r"^data: (\{.*\})\s*$", text, re.M)]
        replies = [m for m in messages if "id" in m and ("result" in m or "error" in m)]
        return replies[-1] if replies else (messages[-1] if messages else {})
    return json.loads(text) if text.strip() else {}


def mint(secret, identity, scopes):
    def encode(value):
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode()
    now = int(time.time())
    claims = {"iss": "mcp-interop-test", "aud": "agentvisor-ai", "sub": "user:interop@example.test",
              "jti": uuid.uuid4().hex, "iat": now, "exp": now + 600,
              "instance_uid": identity, "version": "1", "charter": "interop",
              "scopes": scopes}
    signing = encode(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "dev-hmac"}).encode())
    signing += "." + encode(json.dumps(claims).encode())
    return signing + "." + encode(hmac.new(secret, signing.encode(), hashlib.sha256).digest())


def free_port():
    with socket.socket() as connection:
        connection.bind(("127.0.0.1", 0))
        return connection.getsockname()[1]


def stop(process):
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def wait_until(predicate, process, label, timeout=120):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"{label} exited early with status {process.returncode}")
        try:
            if predicate():
                return
        except (OSError, URLError, ValueError):
            pass
        time.sleep(0.25)
    raise RuntimeError(f"{label} did not become ready within {timeout}s")


def run(args):
    binary = Path(args.proofvisord).resolve()
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError("Set PROOFVISORD to a previously built executable")
    pvctl = Path(args.pvctl).resolve() if args.pvctl else None
    if pvctl is not None and not (pvctl.is_file() and os.access(pvctl, os.X_OK)):
        pvctl = None
    output = Path(args.output_dir).absolute() if args.output_dir else Path(tempfile.mkdtemp(prefix="pv-mcp-interop-"))
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=".work-", dir=output))
    report = {"status": "running", "server_package": args.server_package, "checks": [],
              "binary": str(binary), "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}
    processes = []

    def check(name, condition, detail=None):
        report["checks"].append({"name": name, "passed": bool(condition)})
        print(("PASS " if condition else "FAIL ") + name, flush=True)
        if not condition:
            if detail is not None:
                print("     " + json.dumps(detail, default=str)[:1500], flush=True)
            raise AssertionError(name)

    try:
        # 1. The third-party MCP server, in its own Streamable HTTP mode.
        server_port = free_port()
        server_url = f"http://127.0.0.1:{server_port}/mcp"
        env = dict(os.environ, PORT=str(server_port))
        with (output / "everything-server.log").open("ab") as log:
            server = subprocess.Popen([args.npx, "-y", args.server_package, "streamableHttp"], cwd=work,
                                      env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        processes.append(server)
        rpc_headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                           "clientInfo": {"name": "mcp-interop-test", "version": "1"}}}
        wait_until(lambda: http("POST", server_url, rpc_headers, init)[0] == 200, server,
                   "third-party MCP server", timeout=180)
        status, headers, payload = http("POST", server_url, rpc_headers, init)
        reply = decode_rpc(headers, payload)
        server_info = reply.get("result", {}).get("serverInfo", {})
        report["third_party_server"] = server_info
        check("third-party server answers initialize", status == 200 and server_info.get("name"), reply)
        direct_session = next((v for k, v in headers.items() if k.lower() == "mcp-session-id"), None)
        check("third-party server issues its own session id", bool(direct_session))
        status, headers, payload = http("POST", server_url, {**rpc_headers, "Mcp-Session-Id": direct_session,
                                                              "MCP-Protocol-Version": PROTOCOL_VERSION},
                                        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        direct_tools = {t["name"]: t for t in decode_rpc(headers, payload).get("result", {}).get("tools", [])}
        report["third_party_tools"] = sorted(direct_tools)
        check("third-party server publishes the tools this test relies on",
              ALLOWED_TOOL in direct_tools and BLOCKED_TOOL in direct_tools, sorted(direct_tools))

        # 2. proofvisord with that server as an MCP backend.
        secret = os.urandom(32).hex().encode()
        (work / "hmac.secret").write_bytes(secret)
        os.chmod(work / "hmac.secret", 0o600)
        seed = work / "signing.seed"
        seed.write_text(os.urandom(32).hex())
        os.chmod(seed, 0o600)
        gateway_port = free_port()
        gateway = f"http://127.0.0.1:{gateway_port}"
        values = {"config_version": 1, "listen": f"127.0.0.1:{gateway_port}",
                  "upstream_url": f"http://127.0.0.1:{server_port}",
                  "require_identity": True, "enforce_identity_scopes": True,
                  "identity_hmac_secret_file": str(work / "hmac.secret"),
                  "require_tool_schema": False, "require_intent_mapping": True,
                  "default_workflow": "signed", "dashboard_enabled": False,
                  "atif_spool_dir": str(work / "spool"), "bridge_data_dir": str(work / "bridge"),
                  "mcp_request_timeout_s": 30, "shutdown_drain_timeout_s": 5}
        config = "\n".join(f"{key} = {json.dumps(value)}" for key, value in values.items())
        config += f'\n\n[intent_map]\n{json.dumps(ALLOWED_TOOL)} = "demo.echo"\n'
        config += ('\n[[backends]]\nname = "everything"\n'
                   f'url = {json.dumps(server_url)}\ntransport = "mcp"\n'
                   f'tools = [{json.dumps(ALLOWED_TOOL)}, {json.dumps(BLOCKED_TOOL)}]\n')
        (work / "proofvisor.toml").write_text(config)
        daemon_env = {k: v for k, v in os.environ.items() if not k.startswith("PV_")}
        daemon_env.update(PV_SIGNING_SEED_FILE=str(seed), RUST_LOG="info")
        with (output / "proofvisord.log").open("ab") as log:
            daemon = subprocess.Popen([str(binary), "--config", str(work / "proofvisor.toml")], cwd=work,
                                      env=daemon_env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        processes.append(daemon)
        wait_until(lambda: http("GET", gateway + "/readyz")[0] == 200, daemon, "proofvisord", timeout=60)

        # 3. Drive the gateway as a stock MCP client.
        token = mint(secret, "agent-interop-1",
                     [f"tool:{ALLOWED_TOOL}", f"tool:{BLOCKED_TOOL}", "session:close", "session:promote"])
        auth = {**rpc_headers, "Authorization": "Bearer " + token}
        status, headers, payload = http("POST", gateway + "/mcp", auth, init)
        reply = decode_rpc(headers, payload)
        session = next((v for k, v in headers.items() if k.lower() == "mcp-session-id"), None)
        check("gateway initialize negotiates 2025-11-25 and issues a session",
              status == 200 and reply.get("result", {}).get("protocolVersion") == PROTOCOL_VERSION and session,
              {"status": status, "reply": reply})
        bound = {**auth, "MCP-Session-Id": session, "MCP-Protocol-Version": PROTOCOL_VERSION}
        status, _, _ = http("POST", gateway + "/mcp", bound,
                            {"jsonrpc": "2.0", "method": "notifications/initialized"})
        check("gateway acknowledges notifications/initialized with 202", status == 202, status)

        status, headers, payload = http("POST", gateway + "/mcp", bound,
                                        {"jsonrpc": "2.0", "id": 3, "method": "tools/list"})
        listed = {t["name"]: t for t in decode_rpc(headers, payload).get("result", {}).get("tools", [])}
        report["gateway_tools"] = sorted(listed)
        check("tools/list through the gateway shows the third-party tool",
              status == 200 and ALLOWED_TOOL in listed, {"status": status, "tools": sorted(listed)})
        check("tools/list relays the third-party input schema",
              listed[ALLOWED_TOOL].get("inputSchema") == direct_tools[ALLOWED_TOOL].get("inputSchema"),
              listed.get(ALLOWED_TOOL))
        check("tools/list withholds the tool outside the allow-list", BLOCKED_TOOL not in listed, sorted(listed))

        message = "proofvisor interop " + uuid.uuid4().hex[:8]
        status, headers, payload = http("POST", gateway + "/mcp", bound,
                                        {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                                         "params": {"name": ALLOWED_TOOL, "arguments": {"message": message}}})
        reply = decode_rpc(headers, payload)
        text = (reply.get("result", {}).get("content") or [{}])[0].get("text")
        check("tools/call on the allowed tool is answered by the third-party server",
              status == 200 and text == f"Echo: {message}", {"status": status, "reply": reply})

        status, headers, payload = http("POST", gateway + "/mcp", bound,
                                        {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                                         "params": {"name": BLOCKED_TOOL, "arguments": {"a": 1, "b": 2}}})
        reply = decode_rpc(headers, payload)
        report["blocked_call"] = {"status": status, "reply": reply}
        code = (reply.get("error") or {}).get("data", {}).get("code")
        check("tools/call on the unlisted tool is refused with UNMAPPED_TOOL",
              "error" in reply and code == "UNMAPPED_TOOL", {"status": status, "reply": reply})

        # 4. Close the MCP session; the signed receipt records both calls.
        status, headers, payload = http("DELETE", gateway + "/mcp", bound)
        outcome = json.loads(payload) if payload.strip() else {}
        receipt = outcome.get("receipt", {})
        summary = receipt.get("tool_calls")
        check("DELETE /mcp closes the session and returns a signed receipt",
              status == 200 and outcome.get("kind") == "receipt" and receipt.get("signature_b64"),
              {"status": status, "body": outcome})
        check("receipt records one allowed and one blocked tool call",
              summary == {"total": 2, "allowed": 1, "blocked": 1}, summary)
        (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        spooled = list((work / "spool" / "receipts").glob("*.json"))
        check("receipt is persisted in the spool",
              any(json.loads(p.read_text()).get("receipt_id") == receipt.get("receipt_id") for p in spooled),
              [p.name for p in spooled])
        if pvctl is not None:
            pub = json.loads(subprocess.run([str(pvctl), "pubkey", "--seed", str(seed)], check=True,
                                            capture_output=True, text=True, timeout=30).stdout)["public_key_hex"]
            verify = subprocess.run([str(pvctl), "receipt-verify", str(output / "receipt.json"),
                                     "--public-key-hex", pub], capture_output=True, text=True, timeout=30)
            check("pvctl receipt-verify accepts the receipt offline",
                  verify.returncode == 0 and verify.stdout.startswith("verified"),
                  {"stdout": verify.stdout, "stderr": verify.stderr})
        else:
            print("SKIP pvctl receipt-verify (no pvctl binary found)", flush=True)
        report["status"] = "passed"
    except BaseException as error:
        report["status"] = "failed"
        report["error"] = f"{type(error).__name__}: {error}"[:500]
        raise
    finally:
        for process in processes:
            stop(process)
        shutil.rmtree(work, ignore_errors=True)
        report["passed"] = sum(c["passed"] for c in report["checks"])
        report["failed"] = sum(not c["passed"] for c in report["checks"])
        (output / "result.json").write_text(json.dumps(report, indent=2, default=str) + "\n")
        print(f"result: {report['status']} ({report['passed']} passed, {report['failed']} failed); "
              f"details in {output}", flush=True)
    return 0 if report["status"] == "passed" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--proofvisord", default=os.environ.get("PROOFVISORD", str(ROOT / "target/debug/proofvisord")))
    parser.add_argument("--pvctl", default=os.environ.get("PVCTL", str(ROOT / "target/debug/pvctl")))
    parser.add_argument("--output-dir", default=None, help="where logs, the receipt and result.json are written")
    parser.add_argument("--server-package", default=SERVER_PACKAGE,
                        help="npm package and version of the third-party MCP server")
    parser.add_argument("--npx", default="npx")
    args = parser.parse_args()
    os.umask(0o077)

    def interrupted(*_args):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    try:
        return run(args)
    except BaseException as error:
        print(f"MCP interop test failed: {type(error).__name__}: {error}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

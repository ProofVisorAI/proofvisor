#!/usr/bin/env python3
"""Boot the built daemon on this machine and run one signed session through it.

The point is the platform, not the features: the same steps the container
smoke runs inside Docker, here against the bare binaries, so a CI runner
proves "proofvisord runs on this operating system" rather than "it compiles
here". No Docker, no network: a stand-in OpenAI-compatible provider runs in
this process.

    python3 scripts/boot-smoke.py --daemon target/debug/proofvisord --pvctl target/debug/pvctl

Steps: boot from environment variables only (no config file) -> /readyz ->
`pvctl health` -> a streaming chat completion through the proxy -> close the
session (signed workflow) -> promote the receipt -> `pvctl receipt-verify`
accepts it and refuses a modified copy -> the receipt is on the spool ->
stop the daemon -> restart on the same spool and seed -> the signing key is
unchanged and the closed session is gone. Exit 0 when every step passes.
"""
import argparse
import hashlib
import json
import os
import pathlib
import platform
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROVIDER_KEY = "boot-smoke-provider-key"
MODEL = "boot-smoke"
ANSWER = "hello from the boot-smoke provider"


class Provider(BaseHTTPRequestHandler):
    """Streams one fixed answer; refuses anything but the expected key and model."""

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ready")

    def do_POST(self):
        data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        if (self.path != "/v1/chat/completions"
                or self.headers.get("Authorization") != "Bearer " + PROVIDER_KEY
                or data.get("model") != MODEL):
            self.send_response(400)
            self.end_headers()
            return
        chunk = {"choices": [{"delta": {"content": ANSWER}, "finish_reason": "stop"}],
                 "usage": {"prompt_tokens": 12, "completion_tokens": 6}}
        body = ("data: " + json.dumps(chunk) + "\n\ndata: [DONE]\n\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Smoke:
    def __init__(self, daemon, pvctl, work):
        self.daemon_bin = pathlib.Path(daemon).resolve()
        self.pvctl_bin = pathlib.Path(pvctl).resolve()
        self.work = pathlib.Path(work)
        self.seed = self.work / "signing.seed"
        self.listen = "127.0.0.1:{}".format(free_port())
        self.base = "http://" + self.listen
        self.provider_port = free_port()
        self.daemon = None
        self.log = None
        self.step = 0
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    # -- helpers ---------------------------------------------------------
    def passed(self, message):
        self.step += 1
        print("PASS [{}] {}".format(self.step, message), flush=True)

    def run(self, args, expected=0, timeout=60):
        result = subprocess.run([str(a) for a in args], capture_output=True, text=True, timeout=timeout)
        good = result.returncode == 0 if expected == 0 else result.returncode != 0
        if not good:
            raise RuntimeError("unexpected exit {} from {}: {}{}".format(
                result.returncode, args[:3], result.stdout, result.stderr))
        return result.stdout

    def request(self, path, body=None, headers=None):
        request = urllib.request.Request(self.base + path,
                                         data=None if body is None else json.dumps(body).encode(),
                                         headers=headers or {}, method="GET" if body is None else "POST")
        try:
            with self.opener.open(request, timeout=15) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()

    # -- daemon lifecycle ----------------------------------------------
    def start_daemon(self):
        env = dict(os.environ)
        env.update({
            "PV_LISTEN": self.listen,
            "PV_UPSTREAM_URL": "http://127.0.0.1:{}".format(self.provider_port),
            "PV_UPSTREAM_API_KEY": PROVIDER_KEY,
            "PV_SIGNING_SEED_FILE": str(self.seed),
            "RUST_LOG": "info",
        })
        # No config file: the daemon must come up on built-in defaults plus
        # these variables, with the spool and bridge directories relative
        # to the working directory.
        self.log = open(self.work / "daemon.log", "ab")
        creation = {}
        if platform.system() == "Windows":
            creation["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        self.daemon = subprocess.Popen([str(self.daemon_bin)], cwd=self.work, env=env,
                                       stdout=self.log, stderr=subprocess.STDOUT, **creation)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self.daemon.poll() is not None:
                raise RuntimeError("daemon exited with {} before readiness; see daemon.log".format(self.daemon.returncode))
            try:
                status, body = self.request("/readyz")
                if status == 200 and json.loads(body).get("status") == "ready":
                    return
            except (OSError, ValueError):
                pass
            time.sleep(0.2)
        raise RuntimeError("daemon did not become ready within 60 seconds; see daemon.log")

    def stop_daemon(self):
        if self.daemon is None or self.daemon.poll() is not None:
            return
        if platform.system() == "Windows":
            # The daemon listens for Ctrl-C (tokio::signal::ctrl_c). A
            # console control event cannot be aimed at one child from
            # Python, so the stop is forceful here; durability is proven
            # by the restart below, which must find the receipt on disk.
            self.daemon.terminate()
        else:
            self.daemon.send_signal(signal.SIGTERM)
        try:
            self.daemon.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.daemon.kill()
            self.daemon.wait(timeout=10)
        self.log.close()

    # -- the drill -------------------------------------------------------
    def public_key(self):
        return json.loads(self.run([self.pvctl_bin, "pubkey", "--seed", self.seed]))["public_key_hex"]

    def verify(self, receipt_text, key, expected=0):
        path = self.work / "receipt-under-test.json"
        path.write_text(receipt_text)
        output = self.run([self.pvctl_bin, "receipt-verify", path, "--public-key-hex", key], expected=expected)
        if expected == 0 and not output.startswith("verified "):
            raise RuntimeError("receipt-verify did not report verified: " + output)

    def drill(self):
        print("platform: {} {} ({})".format(platform.system(), platform.release(), platform.machine()), flush=True)
        print("daemon: {}".format(self.run([self.daemon_bin, "--version"]).strip()), flush=True)
        print("pvctl: {}".format(self.run([self.pvctl_bin, "--version"]).strip()), flush=True)

        server = ThreadingHTTPServer(("127.0.0.1", self.provider_port), Provider)
        threading.Thread(target=server.serve_forever, daemon=True).start()

        self.start_daemon()
        self.passed("daemon boots from environment variables only and reports ready on {}".format(self.listen))
        self.run([self.pvctl_bin, "health", "--url", self.base + "/readyz"])
        self.passed("pvctl health reaches the daemon")

        session = "boot-" + uuid.uuid4().hex
        status, body = self.request("/v1/chat/completions", {
            "model": MODEL, "stream": True,
            "messages": [{"role": "user", "content": "hello"}],
        }, {"Content-Type": "application/json", "x-pv-session": session, "x-pv-workflow": "signed"})
        if status != 200 or ANSWER.encode() not in body or b"[DONE]" not in body:
            raise RuntimeError("proxy request failed: {} {}".format(status, body.decode(errors="replace")))
        self.passed("a streaming chat completion goes through the proxy to the provider with the configured key")

        status, body = self.request("/v1/sessions/" + session + "/close", {})
        if status != 200 or json.loads(body).get("kind") != "receipt":
            raise RuntimeError("session close failed: {} {}".format(status, body.decode(errors="replace")))
        status, body = self.request("/v1/sessions/" + session + "/promote", {})
        receipt = json.loads(body)
        if status != 200 or "receipt_id" not in receipt:
            raise RuntimeError("receipt promotion failed: {} {}".format(status, body.decode(errors="replace")))
        self.passed("the signed session closes with a receipt ({})".format(receipt["receipt_id"]))

        key = self.public_key()
        self.verify(body.decode(), key)
        tampered = dict(receipt)
        tampered["cost"] = dict(receipt.get("cost") or {})
        tampered["cost"]["prompt_tokens"] = 999999
        self.verify(json.dumps(tampered), key, expected=1)
        self.passed("pvctl receipt-verify accepts the receipt and refuses a modified copy")

        on_disk = self.work / "spool" / "atif" / "receipts" / (hashlib.sha256(session.encode()).hexdigest()[:32] + ".json")
        if not on_disk.is_file():
            raise RuntimeError("receipt not found on the spool at " + str(on_disk))
        self.passed("the receipt is on the spool ({})".format(on_disk.relative_to(self.work)))

        self.stop_daemon()
        self.passed("daemon stops (exit {})".format(self.daemon.returncode))

        self.start_daemon()
        if self.public_key() != key:
            raise RuntimeError("signing key changed across restart")
        status, _ = self.request("/v1/sessions/" + session + "/promote", {})
        if status != 404:
            raise RuntimeError("closed session still has controls after restart: {}".format(status))
        if not on_disk.is_file():
            raise RuntimeError("receipt disappeared across restart")
        self.passed("restart on the same spool and seed keeps the signing key and the sealed receipt")
        self.stop_daemon()
        server.shutdown()


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--daemon", required=True, help="path to the built proofvisord")
    parser.add_argument("--pvctl", required=True, help="path to the built pvctl")
    parser.add_argument("--work", help="working directory (default: a fresh temporary directory)")
    args = parser.parse_args()
    work = args.work or tempfile.mkdtemp(prefix="pv-boot-smoke-")
    pathlib.Path(work).mkdir(parents=True, exist_ok=True)
    smoke = Smoke(args.daemon, args.pvctl, work)
    try:
        smoke.drill()
    except Exception as error:  # noqa: BLE001 - report every failure the same way
        print("FAIL: {}".format(error), flush=True)
        log = pathlib.Path(work) / "daemon.log"
        if log.is_file():
            print("--- daemon.log (tail) ---", flush=True)
            print("\n".join(log.read_text(errors="replace").splitlines()[-30:]), flush=True)
        smoke.stop_daemon()
        return 1
    print("boot-smoke: {} steps passed on {}".format(smoke.step, platform.system()), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())

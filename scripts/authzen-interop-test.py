#!/usr/bin/env python3
"""AuthZEN 1.0 interoperability test against live public interop PDPs.

The daemon's external policy decision point client (`crates/pv-harness/src/
authzen.rs`) sends an Access Evaluation request of this shape:

    {"subject":  {"type": "user", "id": <human subject>, "properties": {...agent, scopes, issuer}},
     "action":   {"name": <intent>, "properties": {"tool": <tool>}},
     "resource": {"type": <type>, "id": <id>, "properties": {"backend": <backend>}},
     "context":  {"session_id": ..., "missions": [...], "time": <epoch seconds>}}

and reads `{"decision": <bool>, "context": {...}}` from the answer.

The OpenID AuthZEN working group runs public policy decision points for its
"Todo" interop scenario (https://authzen-interop.net). Those PDPs decide the
scenario's fixed actions for five fixed users. The policy for
`can_create_todo` permits users with the `admin` or `editor` role (Rick
Sanchez, `rick@the-citadel.com`) and denies users with only the `viewer`
role (Beth Smith, `beth@the-smiths.com`).

This test sends the daemon's request shape, with the scenario's subject,
action and resource values, to each PDP below and asserts one allow and one
deny decision. It needs outbound HTTPS. When the network is unavailable the
test prints SKIP and exits 0, unless AUTHZEN_INTEROP_REQUIRE_NETWORK=1 is set
(the CI setting), in which case an unreachable PDP fails the test.

PDPs exercised (Access Evaluation endpoint = <base>/access/v1/evaluation):

  * https://topaz-todo-proxy.authzen-interop.net  (Aserto Topaz, run by the interop site)
  * https://authzen-proxy-demo.cerbos.dev          (Cerbos)

The interop site's OPA proxy (https://opa-proxy.authzen-interop.net) denied
every request during authoring (including Rick's), so it is not asserted.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener
import uuid

PDPS = {
    "topaz": "https://topaz-todo-proxy.authzen-interop.net",
    "cerbos": "https://authzen-proxy-demo.cerbos.dev",
}
EVALUATION_PATH = "/access/v1/evaluation"
RICK = "rick@the-citadel.com"   # roles: admin, evil_genius -> may create a todo
BETH = "beth@the-smiths.com"    # roles: viewer           -> may not create a todo
MAX_RESPONSE = 1024 * 1024


def daemon_shaped_request(subject, action, tool, resource_type, resource_id):
    """The exact field layout `authzen::evaluation_request` produces."""
    return {
        "subject": {
            "type": "user",
            "id": subject,
            "properties": {
                "issuer": "https://idp.example.test",
                "agent": {"instance_uid": "agent-todo-1", "charter": "todo-assistant", "version": "1"},
                "azp": None,
                "act": None,
                "scopes": [f"tool:{tool}"],
            },
        },
        "action": {"name": action, "properties": {"tool": tool}},
        "resource": {"type": resource_type, "id": resource_id, "properties": {"backend": "todo"}},
        "context": {"session_id": "interop-" + uuid.uuid4().hex, "missions": [], "time": int(time.time())},
    }


def decision_of(answer):
    """Mirror `authzen::decision_of`: a boolean `decision` or an error."""
    if not isinstance(answer, dict) or not isinstance(answer.get("decision"), bool):
        raise ValueError(f"policy decision point returned no boolean decision: {json.dumps(answer)[:300]}")
    return answer["decision"]


def evaluate(base, body, timeout):
    request = Request(base + EVALUATION_PATH, data=json.dumps(body).encode(), method="POST",
                      headers={"Content-Type": "application/json", "Accept": "application/json",
                               "X-Request-ID": uuid.uuid4().hex})
    response = build_opener(ProxyHandler({})).open(request, timeout=timeout)
    with response:
        payload = response.read(MAX_RESPONSE + 1)
    if len(payload) > MAX_RESPONSE:
        raise ValueError("policy decision point response is too large")
    if response.status != 200:
        raise ValueError(f"policy decision point answered HTTP {response.status}")
    return json.loads(payload)


def network_available(timeout):
    try:
        with socket.create_connection(("topaz-todo-proxy.authzen-interop.net", 443), timeout=timeout):
            return True
    except OSError:
        return False


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pdp", action="append", choices=sorted(PDPS), help="PDP(s) to test (default: all)")
    parser.add_argument("--timeout", type=float, default=15.0, help="per-request timeout in seconds")
    parser.add_argument("--output", help="write a JSON result file here")
    args = parser.parse_args()
    require_network = os.environ.get("AUTHZEN_INTEROP_REQUIRE_NETWORK") == "1"
    selected = {name: PDPS[name] for name in (args.pdp or sorted(PDPS))}
    report = {"status": "running", "pdps": {}, "network": None}

    def finish(status, code):
        report["status"] = status
        if args.output:
            with open(args.output, "w", encoding="utf-8") as handle:
                json.dump(report, handle, indent=2)
                handle.write("\n")
        return code

    if not network_available(args.timeout):
        report["network"] = False
        message = "SKIP: the public AuthZEN interop PDPs are not reachable (no outbound network)"
        if require_network:
            print(message.replace("SKIP", "FAIL") + "; AUTHZEN_INTEROP_REQUIRE_NETWORK=1 forbids skipping")
            return finish("failed", 1)
        print(message)
        return finish("skipped", 0)
    report["network"] = True

    failures = 0
    for name, base in selected.items():
        cases = [
            ("allow", RICK, True),
            ("deny", BETH, False),
        ]
        results = {}
        for label, subject, expected in cases:
            body = daemon_shaped_request(subject, "can_create_todo", "create_todo", "todo", "todo-1")
            try:
                answer = evaluate(base, body, args.timeout)
                decision = decision_of(answer)
                ok = decision == expected
                results[label] = {"subject": subject, "expected": expected, "decision": decision,
                                  "context": answer.get("context"), "passed": ok}
                print(f"{'PASS' if ok else 'FAIL'} {name}: {subject} can_create_todo -> "
                      f"decision={str(decision).lower()} (expected {str(expected).lower()})")
            except (HTTPError, URLError, OSError, ValueError) as error:
                ok = False
                results[label] = {"subject": subject, "expected": expected, "error": str(error)[:300], "passed": False}
                print(f"FAIL {name}: {subject} can_create_todo -> {type(error).__name__}: {str(error)[:200]}")
            failures += not ok
        report["pdps"][name] = {"base_url": base, "endpoint": base + EVALUATION_PATH, "cases": results}

    status = "passed" if failures == 0 else "failed"
    print(f"result: {status} ({len(selected)} PDP(s), {failures} failing check(s))")
    return finish(status, 0 if failures == 0 else 1)


if __name__ == "__main__":
    sys.exit(main())

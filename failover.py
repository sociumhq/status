"""DNS failover for the licence address, run inside the monitor loop (check.py) and by the drill workflow.

Desktop reaches licences through the relay: the A record ``licenses.thredium.app`` points at the relay, which passes
TCP to the main server. If the relay dies while the main server is fine, this module points the record at the main
server; when the relay is healthy again for a while, it points the record back. The main server keeps its port 443
closed to everyone but Cloudflare and the relay, and opens it by itself only while the record points at it
(``licenses-failover/gate.sh`` in socium-infra).

State is the record itself (read from Cloudflare every round), so a restarted run picks up where the last one was.
The module only ever changes the ``content`` of exactly one existing, non-proxied A record whose value is one of the
two known addresses; anything else is reported and left alone.

Environment (repository secrets; without them failover is off):
  CLOUDFLARE_DNS_TOKEN, CLOUDFLARE_ZONE_ID   — token limited to editing DNS of the zone
  FAILOVER_PRIMARY_IP                        — the relay
  FAILOVER_BACKUP_IP                         — the main server
  FAILOVER_RECORD                            — the record to manage (set in the workflow, not a secret)

Drill on a test record (never the live one): ``python3 failover.py drill down|up|cleanup``.
"""
from __future__ import annotations

import http.client
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

CF_API = "https://api.cloudflare.com/client/v4"
USER_AGENT = "socium-status-monitor/1"
LICENCE_HOST = "licenses.thredium.app"      # name the relay serves; probes use it even in a drill
RELAY_PATH = "/health"
ALIVE_URL = "https://thredium.app/health"   # the same application, through Cloudflare: proves the main server is up
TIMEOUT_SECONDS = 15
ATTEMPTS = 2
RETRY_SECONDS = 20
DOWN_ROUNDS = 2   # relay failed this many rounds in a row (each with a retry) → switch to the main server
UP_ROUNDS = 3     # relay healthy this many rounds in a row while switched → switch back
TEST_RECORD = "failover-test.thredium.app"


class Config:
    def __init__(self, record: str | None = None):
        self.token = os.environ.get("CLOUDFLARE_DNS_TOKEN", "")
        self.zone = os.environ.get("CLOUDFLARE_ZONE_ID", "")
        self.primary = os.environ.get("FAILOVER_PRIMARY_IP", "")
        self.backup = os.environ.get("FAILOVER_BACKUP_IP", "")
        self.record = record if record is not None else os.environ.get("FAILOVER_RECORD", "")

    @property
    def enabled(self) -> bool:
        return all((self.token, self.zone, self.primary, self.backup, self.record))


def cloudflare(cfg: Config, method: str, path: str, body: dict | None = None):
    request = urllib.request.Request(
        f"{CF_API}/zones/{cfg.zone}{path}", method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {cfg.token}", "Content-Type": "application/json",
                 "User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.loads(response.read())
    except urllib.error.HTTPError as error:
        data = json.loads(error.read() or b"{}")
    if not data.get("success"):
        codes = [e.get("code") for e in data.get("errors", [])]
        raise RuntimeError(f"Cloudflare {method} failed: {codes}")
    return data["result"]


def a_records(cfg: Config, name: str) -> list:
    return cloudflare(cfg, "GET", f"/dns_records?type=A&name={urllib.parse.quote(name)}") or []


def probe_ip(ip: str, host: str = LICENCE_HOST, path: str = RELAY_PATH) -> tuple[bool, str]:
    """GET https://host/path, connecting to ``ip`` (TLS checked against ``host``)."""
    context = ssl.create_default_context()
    try:
        raw = socket.create_connection((ip, 443), timeout=TIMEOUT_SECONDS)
        connection = http.client.HTTPSConnection(host, timeout=TIMEOUT_SECONDS, context=context)
        connection.sock = context.wrap_socket(raw, server_hostname=host)
        connection.request("GET", path, headers={"User-Agent": USER_AGENT})
        status = connection.getresponse().status
        connection.close()
    except Exception as error:  # noqa: BLE001 — refused, timeout, TLS: all mean «down»
        return False, f"{type(error).__name__}: {str(error)[:120]}"
    return status == 200, f"HTTP {status}"


def probe_url(url: str) -> tuple[bool, str]:
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": USER_AGENT}),
                                    timeout=TIMEOUT_SECONDS) as response:
            return response.status == 200, f"HTTP {response.status}"
    except Exception as error:  # noqa: BLE001
        return False, f"{type(error).__name__}: {str(error)[:120]}"


def with_retry(probe, *args) -> tuple[bool, str]:
    reason = ""
    for attempt in range(ATTEMPTS):
        ok, reason = probe(*args)
        if ok:
            return True, reason
        if attempt + 1 < ATTEMPTS:
            time.sleep(RETRY_SECONDS)
    return False, reason


def step(cfg: Config, state: dict, relay_probe=None, alive_probe=None) -> dict:
    """One round. Returns {"where": "primary"|"backup"|"guard", "changed": bool, "reason": str}.

    ``state`` keeps the counters between rounds of one run (``down``, ``up``).
    """
    relay_probe = relay_probe or (lambda: with_retry(probe_ip, cfg.primary))
    alive_probe = alive_probe or (lambda: with_retry(probe_url, ALIVE_URL))
    rows = a_records(cfg, cfg.record)
    if len(rows) != 1:
        return {"where": "guard", "changed": False, "reason": f"{len(rows)} A records for {cfg.record}, expected 1"}
    record = rows[0]
    if record.get("proxied"):
        return {"where": "guard", "changed": False, "reason": f"{cfg.record} is proxied by Cloudflare"}
    content = record.get("content")
    relay_ok, relay_reason = relay_probe()

    if content == cfg.primary:
        state["up"] = 0
        if relay_ok:
            state["down"] = 0
            return {"where": "primary", "changed": False, "reason": f"relay {relay_reason}"}
        state["down"] = state.get("down", 0) + 1
        if state["down"] < DOWN_ROUNDS:
            return {"where": "primary", "changed": False,
                    "reason": f"relay {relay_reason}, round {state['down']} of {DOWN_ROUNDS}"}
        alive_ok, alive_reason = alive_probe()
        if not alive_ok:
            # The main server is down as well: switching would not help, the outage alerts cover it.
            return {"where": "primary", "changed": False,
                    "reason": f"relay {relay_reason}, main server {alive_reason}: not switching"}
        cloudflare(cfg, "PATCH", f"/dns_records/{record['id']}", {"content": cfg.backup})
        state["down"] = 0
        return {"where": "backup", "changed": True,
                "reason": f"relay {relay_reason} for {DOWN_ROUNDS} rounds, main server {alive_reason}"}

    if content == cfg.backup:
        state["down"] = 0
        if not relay_ok:
            state["up"] = 0
            return {"where": "backup", "changed": False, "reason": f"relay still {relay_reason}"}
        state["up"] = state.get("up", 0) + 1
        if state["up"] < UP_ROUNDS:
            return {"where": "backup", "changed": False,
                    "reason": f"relay {relay_reason}, healthy round {state['up']} of {UP_ROUNDS}"}
        cloudflare(cfg, "PATCH", f"/dns_records/{record['id']}", {"content": cfg.primary})
        state["up"] = 0
        return {"where": "primary", "changed": True, "reason": f"relay {relay_reason} for {UP_ROUNDS} rounds"}

    return {"where": "guard", "changed": False, "reason": f"{cfg.record} points at an unknown address"}


def drill(action: str) -> int:
    """Exercise the real Cloudflare calls on TEST_RECORD with forced probe results."""
    cfg = Config(record=TEST_RECORD)
    if not all((cfg.token, cfg.zone, cfg.primary, cfg.backup)):
        print("drill: Cloudflare or failover secrets are missing")
        return 1
    rows = a_records(cfg, TEST_RECORD)
    if action == "cleanup":
        for row in rows:
            cloudflare(cfg, "DELETE", f"/dns_records/{row['id']}")
        print(f"drill cleanup: removed {len(rows)} record(s) {TEST_RECORD}")
        return 0
    if not rows:
        cloudflare(cfg, "POST", "/dns_records", {"type": "A", "name": TEST_RECORD, "content": cfg.primary,
                                                 "ttl": 60, "proxied": False,
                                                 "comment": "socium-status failover drill, safe to delete"})
        print(f"drill: created {TEST_RECORD} -> relay")
    state: dict = {}
    if action == "down":
        expected, rounds = "backup", DOWN_ROUNDS
        relay = lambda: (False, "forced down (drill)")  # noqa: E731
    elif action == "up":
        expected, rounds = "primary", UP_ROUNDS
        relay = lambda: (True, "forced healthy (drill)")  # noqa: E731
    else:
        print(f"drill: unknown action {action!r}")
        return 1
    result: dict = {}
    for number in range(rounds):
        result = step(cfg, state, relay_probe=relay, alive_probe=lambda: probe_url(ALIVE_URL))
        print(f"drill {action} round {number + 1}: {result}")
    content = a_records(cfg, TEST_RECORD)[0]["content"]
    where = "backup" if content == cfg.backup else "primary" if content == cfg.primary else "unknown"
    print(f"drill {action}: {TEST_RECORD} now points at the {where} address (expected {expected})")
    # Real probes, for the record: the relay must answer directly, the main server through Cloudflare.
    print(f"relay direct: {probe_ip(cfg.primary)}; main server via Cloudflare: {probe_url(ALIVE_URL)}")
    return 0 if where == expected else 1


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "drill":
        sys.exit(drill(sys.argv[2]))
    print(__doc__)
    sys.exit(2)

"""Move one thredium.app A record between the old and the new main server (workflow dns.yml).

  python3 dns.py list            — A/AAAA/CNAME records; known addresses shown as relay/old-main/new-main
  python3 dns.py set NAME old|new — change the content of exactly one A record NAME (proxied flag and TTL kept)

Guards: only names in the zone thredium.app, never licenses.thredium.app (failover.py owns it), only A records that
currently point at the other known main-server address. Secrets: CLOUDFLARE_DNS_TOKEN, CLOUDFLARE_ZONE_ID,
FAILOVER_PRIMARY_IP (relay), OLD_MAIN_IP, NEW_MAIN_IP.
"""
from __future__ import annotations

import os
import sys

import failover

ZONE = "thredium.app"


def label(ip: str) -> str:
    names = {os.environ.get("FAILOVER_PRIMARY_IP"): "relay", os.environ.get("OLD_MAIN_IP"): "old-main",
             os.environ.get("NEW_MAIN_IP"): "new-main"}
    return names.get(ip, "other")


def main() -> int:
    cfg = failover.Config(record="")
    if not (cfg.token and cfg.zone and os.environ.get("OLD_MAIN_IP") and os.environ.get("NEW_MAIN_IP")):
        print("secrets missing")
        return 1
    if sys.argv[1:2] == ["list"]:
        rows = failover.cloudflare(cfg, "GET", "/dns_records?per_page=500") or []
        for row in sorted(rows, key=lambda r: (r["name"], r["type"])):
            if row["type"] in ("A", "AAAA", "CNAME"):
                shown = label(row["content"]) if row["type"] == "A" else row["content"]
                print(f"{row['type']:5} {row['name']:40} {shown:12} proxied={row['proxied']} ttl={row['ttl']}")
        return 0
    if len(sys.argv) == 4 and sys.argv[1] == "set" and sys.argv[3] in ("old", "new"):
        name, side = sys.argv[2].strip().lower(), sys.argv[3]
        if not (name == ZONE or name.endswith("." + ZONE)) or name == failover.LICENCE_HOST:
            print(f"refused: {name}")
            return 1
        want = os.environ["NEW_MAIN_IP" if side == "new" else "OLD_MAIN_IP"]
        other = os.environ["OLD_MAIN_IP" if side == "new" else "NEW_MAIN_IP"]
        rows = failover.a_records(cfg, name)
        if len(rows) != 1:
            print(f"refused: {len(rows)} A records for {name}")
            return 1
        row = rows[0]
        if row["content"] == want:
            print(f"{name}: already {side}-main")
            return 0
        if row["content"] != other:
            print(f"refused: {name} points at {label(row['content'])}, not the other main server")
            return 1
        failover.cloudflare(cfg, "PATCH", f"/dns_records/{row['id']}", {"content": want})
        after = failover.a_records(cfg, name)[0]
        print(f"{name}: {label(row['content'])} -> {label(after['content'])} (proxied={after['proxied']})")
        return 0 if after["content"] == want else 1
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())

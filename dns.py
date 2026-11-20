"""Move one thredium.app A record between the old and the new main server (workflow dns.yml).

  python3 dns.py list            — A/AAAA/CNAME records; known addresses shown as relay/old-main/new-main
  python3 dns.py set NAME old|new — change the content of exactly one A record NAME (proxied flag and TTL kept)
  python3 dns.py replace NAME old|new — socium.tools only: parking A/AAAA/CNAME of NAME -> a main server
  python3 dns.py create NAME old|new — new proxied A record NAME (refused if the name has any record)

Guards: only names in the zone thredium.app, never licenses.thredium.app (failover.py owns it), only A records that
currently point at the other known main-server address. Secrets: CLOUDFLARE_DNS_TOKEN, CLOUDFLARE_ZONE_ID,
FAILOVER_PRIMARY_IP (relay), OLD_MAIN_IP, NEW_MAIN_IP.
"""
from __future__ import annotations

import os
import sys

import failover

ZONE = "thredium.app"
ZONES = ("thredium.app", "socium.tools")


def zone_id(cfg, name: str) -> str:
    """Zone id by name (the token is limited to its zones; CLOUDFLARE_ZONE_ID is thredium.app)."""
    if name == ZONE:
        return cfg.zone
    import urllib.request, json
    request = urllib.request.Request(f"{failover.CF_API}/zones?name={name}", headers={
        "Authorization": f"Bearer {cfg.token}", "User-Agent": failover.USER_AGENT})
    with urllib.request.urlopen(request, timeout=30) as response:
        rows = json.loads(response.read())["result"]
    if len(rows) != 1:
        raise RuntimeError(f"zone {name} not visible to the token")
    return rows[0]["id"]


def label(ip: str) -> str:
    names = {os.environ.get("FAILOVER_PRIMARY_IP"): "relay", os.environ.get("OLD_MAIN_IP"): "old-main",
             os.environ.get("NEW_MAIN_IP"): "new-main"}
    return names.get(ip, "other")


def main() -> int:
    cfg = failover.Config(record="")
    zone = os.environ.get("INPUT_ZONE") or ZONE
    if zone not in ZONES:
        print(f"refused: zone {zone}")
        return 1
    if not (cfg.token and cfg.zone and os.environ.get("OLD_MAIN_IP") and os.environ.get("NEW_MAIN_IP")):
        print("secrets missing")
        return 1
    cfg.zone = zone_id(cfg, zone)
    print(f"zone {zone}")
    if sys.argv[1:2] == ["list"]:
        rows = failover.cloudflare(cfg, "GET", "/dns_records?per_page=500") or []
        for row in sorted(rows, key=lambda r: (r["name"], r["type"])):
            if row["type"] in ("A", "AAAA", "CNAME"):
                shown = label(row["content"]) if row["type"] == "A" else row["content"]
                print(f"{row['type']:5} {row['name']:40} {shown:12} proxied={row['proxied']} ttl={row['ttl']}")
        return 0
    if len(sys.argv) == 4 and sys.argv[1] == "set" and sys.argv[3] in ("old", "new"):
        name, side = sys.argv[2].strip().lower(), sys.argv[3]
        if not (name == zone or name.endswith("." + zone)) or name == failover.LICENCE_HOST:
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
    if len(sys.argv) == 4 and sys.argv[1] == "create" and sys.argv[3] in ("old", "new"):
        # New proxied A record at one of the two main servers; refuses if any record of that name exists.
        name, side = sys.argv[2].strip().lower(), sys.argv[3]
        if not (name == zone or name.endswith("." + zone)) or name == failover.LICENCE_HOST:
            print(f"refused: {name}")
            return 1
        import urllib.parse
        existing = failover.cloudflare(cfg, "GET", f"/dns_records?name={urllib.parse.quote(name)}") or []
        if existing:
            print(f"refused: {name} already has {[r['type'] for r in existing]}")
            return 1
        want = os.environ["NEW_MAIN_IP" if side == "new" else "OLD_MAIN_IP"]
        failover.cloudflare(cfg, "POST", "/dns_records", {"type": "A", "name": name, "content": want, "ttl": 1,
                                                       "proxied": True, "comment": "socium-status dns.py"})
        row = failover.a_records(cfg, name)[0]
        print(f"{name}: created -> {label(row['content'])} (proxied={row['proxied']})")
        return 0
    if len(sys.argv) == 4 and sys.argv[1] == "replace" and sys.argv[3] in ("old", "new"):
        # socium.tools only: drop the registrar's parking A/AAAA/CNAME of NAME and point it at a main server.
        name, side = sys.argv[2].strip().lower(), sys.argv[3]
        if zone != "socium.tools" or not (name == zone or name.endswith("." + zone)):
            print(f"refused: replace works only inside socium.tools ({name})")
            return 1
        import urllib.parse
        rows = failover.cloudflare(cfg, "GET", f"/dns_records?name={urllib.parse.quote(name)}") or []
        rows = [r for r in rows if r["type"] in ("A", "AAAA", "CNAME")]  # MX/TXT of the same name stay
        for r in rows:
            failover.cloudflare(cfg, "DELETE", f"/dns_records/{r['id']}")
            print(f"{name}: removed {r['type']} {label(r['content']) if r['type'] == 'A' else r['content']}")
        want = os.environ["NEW_MAIN_IP" if side == "new" else "OLD_MAIN_IP"]
        failover.cloudflare(cfg, "POST", "/dns_records", {"type": "A", "name": name, "content": want, "ttl": 1,
                                                       "proxied": True, "comment": "socium-status dns.py"})
        print(f"{name}: created -> {label(failover.a_records(cfg, name)[0]['content'])} (proxied)")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())

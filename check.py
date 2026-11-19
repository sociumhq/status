"""Socium uptime check, run by GitHub Actions every 5 minutes (.github/workflows/monitor.yml).

Every check in checks.json is tried twice, 20 seconds apart, so one dropped packet is not an incident. A check that
fails both times opens one issue labelled ``down:<id>`` and sends one Telegram message; when it passes again the
issue is closed with the downtime and a «recovered» message goes out. Open issues are the state, so nothing is kept
between runs and a run never repeats an alert.

Environment: GITHUB_TOKEN and GITHUB_REPOSITORY (given by Actions); TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID
(repository secrets, optional: without them only issues are used).
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ATTEMPTS = 2
RETRY_SECONDS = 20
TIMEOUT_SECONDS = 15
USER_AGENT = "socium-status-monitor/1"
API = "https://api.github.com"


def probe(check: dict) -> tuple[bool, str]:
    """One HTTP GET: (ok, short reason)."""
    request = urllib.request.Request(check["url"], headers={"User-Agent": USER_AGENT})
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            status = response.status
    except urllib.error.HTTPError as error:
        status = error.code
    except Exception as error:  # noqa: BLE001 — DNS, TLS, timeout, refused: all mean «down»
        return False, f"{type(error).__name__}: {str(error)[:160]}"
    elapsed = int((time.monotonic() - started) * 1000)
    if status != check.get("expect_status", 200):
        return False, f"HTTP {status} ({elapsed} ms)"
    return True, f"HTTP {status} ({elapsed} ms)"


def check_with_retry(check: dict) -> tuple[bool, str]:
    reason = ""
    for attempt in range(ATTEMPTS):
        ok, reason = probe(check)
        if ok:
            return True, reason
        if attempt + 1 < ATTEMPTS:
            time.sleep(RETRY_SECONDS)
    return False, reason


def github(method: str, path: str, body: dict | None = None):
    request = urllib.request.Request(
        f"{API}{path}", method=method, data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}", "Accept": "application/vnd.github+json",
                 "User-Agent": USER_AGENT, "X-GitHub-Api-Version": "2022-11-28"})
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read()
    return json.loads(raw) if raw else None


def telegram(text: str) -> None:
    token, chat = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat:
        return
    data = urllib.parse.urlencode({"chat_id": chat, "text": text, "disable_web_page_preview": "true"}).encode()
    try:
        urllib.request.urlopen(urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage", data=data), timeout=20).read()
    except Exception as error:  # noqa: BLE001 — the issue is still there; never fail the run on Telegram
        print(f"telegram failed: {type(error).__name__}", file=sys.stderr)


def main() -> int:
    repo = os.environ["GITHUB_REPOSITORY"]
    checks = json.loads(Path(__file__).with_name("checks.json").read_text(encoding="utf-8"))["checks"]
    # No ?labels= filter: GitHub's label index lags a new issue by seconds, the plain list does not.
    open_issues = github("GET", f"/repos/{repo}/issues?state=open&per_page=100") or []
    by_label = {label["name"]: issue for issue in open_issues for label in issue.get("labels", [])
                if label["name"].startswith("down:")}
    now = datetime.now(timezone.utc)
    stamp = now.strftime("%Y-%m-%d %H:%M UTC")
    failures = 0
    for check in checks:
        ok, reason = check_with_retry(check)
        label = f"down:{check['id']}"
        issue = by_label.get(label)
        print(f"{'OK  ' if ok else 'DOWN'} {check['id']}: {reason}")
        if not ok:
            failures += 1
        if not ok and issue is None:
            level = "🔴 КРИТИЧНО" if check.get("critical") else "🟠"
            github("POST", f"/repos/{repo}/issues", {
                "title": f"{check['name']} не отвечает",
                "body": f"С {stamp}: `{check['url']}` — {reason}.\n\nИсследуйте по `socium-infra` "
                        "(`main-server.md`, `relay/README.md`). Issue закроется сам, когда проверка пройдёт.",
                "labels": ["incident", label]})
            telegram(f"{level} {check['name']} не отвечает\n{check['url']}\n{reason}\n{stamp}")
        elif ok and issue is not None:
            opened = datetime.fromisoformat(issue["created_at"].replace("Z", "+00:00"))
            minutes = max(1, int((now - opened).total_seconds() // 60))
            github("POST", f"/repos/{repo}/issues/{issue['number']}/comments",
                   {"body": f"Восстановилось в {stamp} ({reason}), простой около {minutes} мин."})
            github("PATCH", f"/repos/{repo}/issues/{issue['number']}", {"state": "closed"})
            telegram(f"🟢 {check['name']} снова работает\nпростой около {minutes} мин\n{stamp}")
    print(f"{len(checks) - failures}/{len(checks)} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

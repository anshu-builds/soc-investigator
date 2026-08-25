from __future__ import annotations

import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path


def generate_account_compromise(
    failure_count: int = 8,
    output_path: str | Path | None = None,
) -> list[dict]:
    attacker_ip = "10.10.5.200"
    target_user = "sarah.miller"
    target_host = "workstation-42.corp.local"
    start_time = datetime(2025, 8, 19, 14, 15, 0, tzinfo=timezone.utc)
    rows = []
    t = start_time

    for _ in range(4):
        rows.append({
            "timestamp": (t - timedelta(minutes=random.randint(5, 20))).isoformat(),
            "event_type": "SUCCESSFUL_LOGIN",
            "source_ip": "10.0.0.20",
            "username": "sarah.miller",
            "hostname": target_host,
            "message": "Routine login from corporate network",
        })

    for i in range(failure_count):
        rows.append({
            "timestamp": t.isoformat(),
            "event_type": "FAILED_LOGIN",
            "source_ip": attacker_ip,
            "username": target_user,
            "hostname": target_host,
            "message": "Authentication failed: invalid credentials",
        })
        t += timedelta(seconds=random.uniform(2.0, 8.0))

    t += timedelta(seconds=10)
    rows.append({
        "timestamp": t.isoformat(),
        "event_type": "SUCCESSFUL_LOGIN",
        "source_ip": attacker_ip,
        "username": target_user,
        "hostname": target_host,
        "message": "User sarah.miller authenticated successfully",
    })

    t += timedelta(minutes=2)
    for path in ["/home/sarah.miller/.ssh/id_rsa", "/etc/passwd", "/var/log/auth.log"]:
        rows.append({
            "timestamp": t.isoformat(),
            "event_type": "FILE_READ",
            "source_ip": attacker_ip,
            "username": target_user,
            "hostname": target_host,
            "file_path": path,
            "message": f"File accessed: {path}",
        })
        t += timedelta(seconds=30)

    rows.sort(key=lambda r: r["timestamp"])
    if output_path:
        _write_csv(rows, output_path)
    return rows


def _write_csv(rows: list[dict], path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    all_keys: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for k in row.keys():
            if k not in seen:
                all_keys.append(k)
                seen.add(k)
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=all_keys, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    print(f"[+] Written {len(rows)} rows to {path}")


if __name__ == "__main__":
    generate_account_compromise(
        output_path=Path(__file__).parent.parent / "samples" / "account_compromise_sample.csv"
    )

from __future__ import annotations

import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path


def generate_privilege_escalation(
    failure_count: int = 12,
    output_path: str | Path | None = None,
) -> list[dict]:
    attacker_ip = "172.16.0.99"
    target_user = "admin"
    target_host = "dc01.corp.local"
    start_time = datetime(2025, 8, 19, 22, 0, 0, tzinfo=timezone.utc)
    rows = []
    t = start_time

    for i in range(failure_count):
        rows.append({
            "timestamp": t.isoformat(),
            "event_type": "FAILED_LOGIN",
            "source_ip": attacker_ip,
            "username": target_user,
            "hostname": target_host,
            "message": f"Authentication failure #{i+1} for admin",
        })
        t += timedelta(seconds=random.uniform(0.5, 2.0))

    t += timedelta(seconds=5)
    rows.append({
        "timestamp": t.isoformat(),
        "event_type": "SUCCESSFUL_LOGIN",
        "source_ip": attacker_ip,
        "username": target_user,
        "hostname": target_host,
        "message": "Admin account authentication successful",
    })

    t += timedelta(minutes=1)
    rows.append({
        "timestamp": t.isoformat(),
        "event_type": "4672",
        "source_ip": attacker_ip,
        "username": target_user,
        "hostname": target_host,
        "message": "Special privileges assigned to new logon — admin granted SeDebugPrivilege",
    })

    t += timedelta(minutes=2)
    sensitive_files = [
        "C:\\Windows\\System32\\config\\SAM",
        "C:\\Windows\\System32\\config\\SECURITY",
        "C:\\Windows\\NTDS\\ntds.dit",
        "/etc/shadow",
        "/etc/sudoers",
    ]
    for path in sensitive_files:
        rows.append({
            "timestamp": t.isoformat(),
            "event_type": "FILE_READ",
            "source_ip": attacker_ip,
            "username": target_user,
            "hostname": target_host,
            "file_path": path,
            "message": f"Sensitive file read: {path}",
        })
        t += timedelta(seconds=random.uniform(15, 60))

    t += timedelta(minutes=1)
    rows.append({
        "timestamp": t.isoformat(),
        "event_type": "PROCESS_CREATE",
        "source_ip": attacker_ip,
        "username": target_user,
        "hostname": target_host,
        "process_name": "mimikatz.exe",
        "message": "New process created: mimikatz.exe by admin",
    })

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
    generate_privilege_escalation(
        output_path=Path(__file__).parent.parent / "samples" / "privilege_escalation_sample.csv"
    )

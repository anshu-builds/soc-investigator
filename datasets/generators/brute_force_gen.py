from __future__ import annotations

import csv
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ATTACKER_IP = "192.168.1.55"
TARGET_USER = "admin"
TARGET_HOST = "server01.corp.local"
LEGITIMATE_IP = "10.0.0.5"

FAILURE_MESSAGES = [
    "Invalid password attempt",
    "Authentication failed: bad credentials",
    "Login failure: incorrect password",
    "Failed logon attempt for user",
]

SUCCESS_MESSAGES = [
    "User logged in successfully",
    "Authentication successful",
    "Successful logon",
]

NORMAL_MESSAGES = [
    "Routine authentication check",
    "Scheduled job authentication",
    "Service account login",
]


def generate_brute_force(
    failure_count: int = 15,
    include_success: bool = False,
    start_time: datetime | None = None,
    output_path: str | Path | None = None,
) -> list[dict]:
    if start_time is None:
        start_time = datetime(2025, 8, 19, 10, 31, 0, tzinfo=timezone.utc)

    rows = []
    current_time = start_time

    for i in range(5):
        rows.append({
            "timestamp": (current_time - timedelta(minutes=random.randint(5, 30))).isoformat(),
            "event_type": "SUCCESSFUL_LOGIN",
            "source_ip": LEGITIMATE_IP,
            "username": "jdoe",
            "hostname": TARGET_HOST,
            "message": random.choice(NORMAL_MESSAGES),
        })

    for i in range(failure_count):
        rows.append({
            "timestamp": current_time.isoformat(),
            "event_type": "FAILED_LOGIN",
            "source_ip": ATTACKER_IP,
            "username": TARGET_USER,
            "hostname": TARGET_HOST,
            "message": random.choice(FAILURE_MESSAGES),
        })
        current_time += timedelta(seconds=random.uniform(0.5, 3.0))

    if include_success:
        current_time += timedelta(seconds=5)
        rows.append({
            "timestamp": current_time.isoformat(),
            "event_type": "SUCCESSFUL_LOGIN",
            "source_ip": ATTACKER_IP,
            "username": TARGET_USER,
            "hostname": TARGET_HOST,
            "message": random.choice(SUCCESS_MESSAGES),
        })

    rows.sort(key=lambda r: r["timestamp"])

    if output_path:
        _write_csv(rows, output_path)
    return rows


def _write_csv(rows: list[dict], path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        if rows:
            writer = csv.DictWriter(f, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
    print(f"[+] Written {len(rows)} rows to {path}")


if __name__ == "__main__":
    generate_brute_force(
        failure_count=15,
        include_success=False,
        output_path=Path(__file__).parent.parent / "samples" / "brute_force_sample.csv",
    )

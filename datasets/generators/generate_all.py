from __future__ import annotations

import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from brute_force_gen import generate_brute_force
from account_compromise_gen import generate_account_compromise
from privilege_escalation_gen import generate_privilege_escalation

SAMPLES_DIR = Path(__file__).parent.parent / "samples"


def _write_csv(rows: list[dict], path: Path) -> None:
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
    print(f"[+] Written {len(rows)} rows → {path.name}")


def main() -> None:
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)

    bf_rows = generate_brute_force(failure_count=15, include_success=False)
    _write_csv(bf_rows, SAMPLES_DIR / "brute_force_sample.csv")

    ac_rows = generate_account_compromise(failure_count=8)
    _write_csv(ac_rows, SAMPLES_DIR / "account_compromise_sample.csv")

    pe_rows = generate_privilege_escalation(failure_count=12)
    _write_csv(pe_rows, SAMPLES_DIR / "privilege_escalation_sample.csv")

    normal_rows = _generate_normal_traffic(count=20)
    mixed = bf_rows + ac_rows + pe_rows + normal_rows
    mixed.sort(key=lambda r: r.get("timestamp", ""))
    _write_csv(mixed, SAMPLES_DIR / "mixed_scenario.csv")

    print(f"\n[✓] All sample datasets written to {SAMPLES_DIR}/")


def _generate_normal_traffic(count: int = 20) -> list[dict]:
    rows = []
    base = datetime(2025, 8, 19, 9, 0, 0, tzinfo=timezone.utc)
    users = ["jdoe", "alice", "bob", "charlie", "svc_backup"]
    ips = ["10.0.0.10", "10.0.0.11", "10.0.0.12", "10.0.0.15"]

    for i in range(count):
        rows.append({
            "timestamp": (base + timedelta(minutes=i * 3)).isoformat(),
            "event_type": random.choice(["SUCCESSFUL_LOGIN", "SUCCESSFUL_LOGIN", "FILE_READ"]),
            "source_ip": random.choice(ips),
            "username": random.choice(users),
            "hostname": "workstation-" + str(random.randint(10, 50)) + ".corp.local",
            "message": "Normal system activity",
        })
    return rows


if __name__ == "__main__":
    main()

"""
Normal Traffic Generator

Generates benign background events to make detection more realistic.
"""

from __future__ import annotations

import csv
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path


def generate_normal_traffic(
    output_path: Path,
    num_events: int = 200,
    start_time: datetime | None = None,
) -> None:
    if start_time is None:
        start_time = datetime.now(timezone.utc) - timedelta(days=1)

    ips = [f"192.168.1.{i}" for i in range(10, 50)]
    users = ["alice", "bob", "charlie", "david", "eve", "frank"]
    hosts = ["server-1", "server-2", "db-1", "app-1", "web-1"]

    events = []
    current_time = start_time
    for _ in range(num_events):
        current_time += timedelta(minutes=random.randint(1, 10))
        event_type = random.choices(
            ["AUTH_SUCCESS", "FILE_ACCESS", "PROCESS_EXEC", "AUTH_FAILURE"],
            weights=[60, 20, 15, 5],
            k=1
        )[0]

        ip = random.choice(ips)
        user = random.choice(users)
        host = random.choice(hosts)

        if event_type == "AUTH_FAILURE":
            desc = f"Failed login for {user}"
        elif event_type == "AUTH_SUCCESS":
            desc = f"Successful login for {user}"
        elif event_type == "FILE_ACCESS":
            desc = f"Accessed file /var/log/syslog"
        else:
            desc = f"Executed process /bin/bash"

        events.append({
            "@timestamp": current_time.isoformat(),
            "event_type": event_type,
            "src_ip": ip,
            "user": user,
            "hostname": host,
            "message": desc,
            "status": "success" if event_type != "AUTH_FAILURE" else "failed",
        })

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["@timestamp", "event_type", "src_ip", "user", "hostname", "message", "status"])
        writer.writeheader()
        writer.writerows(events)
    print(f"Generated {num_events} normal events at {output_path}")


if __name__ == "__main__":
    out_dir = Path(__file__).parent.parent / "samples"
    out_dir.mkdir(parents=True, exist_ok=True)
    generate_normal_traffic(out_dir / "normal_traffic.csv")

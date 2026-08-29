"""Wazuh alert test fixtures."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List


def _ts(offset_seconds: int = 0, base: datetime | None = None) -> str:
    if base is None:
        base = datetime(2025, 6, 15, 14, 0, 0, tzinfo=timezone.utc)
    dt = base + timedelta(seconds=offset_seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")


def ssh_auth_failure(
    *,
    offset: int = 0,
    src_ip: str = "192.168.1.100",
    user: str = "admin",
    agent_name: str = "web-server-01",
) -> Dict[str, Any]:
    return {
        "timestamp": _ts(offset),
        "rule": {
            "id": "5503",
            "level": 5,
            "description": "User login failed.",
            "groups": ["sshd", "authentication_failed"],
            "mitre": {
                "id": ["T1110"],
                "tactic": ["Credential Access"],
                "technique": ["Brute Force"],
            },
        },
        "agent": {
            "id": "001",
            "name": agent_name,
            "ip": "10.0.0.50",
        },
        "decoder": {"name": "sshd"},
        "data": {
            "srcip": src_ip,
            "srcuser": user,
            "status": "failed",
        },
        "full_log": f"Jun 15 14:00:{offset:02d} {agent_name} sshd[12345]: Failed password for {user} from {src_ip} port 22 ssh2",
    }


def ssh_auth_success(
    *,
    offset: int = 300,
    src_ip: str = "192.168.1.100",
    user: str = "admin",
    agent_name: str = "web-server-01",
) -> Dict[str, Any]:
    return {
        "timestamp": _ts(offset),
        "rule": {
            "id": "5715",
            "level": 3,
            "description": "User login successful.",
            "groups": ["sshd", "authentication_success"],
            "mitre": {
                "id": ["T1078"],
                "tactic": ["Initial Access"],
                "technique": ["Valid Accounts"],
            },
        },
        "agent": {
            "id": "001",
            "name": agent_name,
            "ip": "10.0.0.50",
        },
        "decoder": {"name": "sshd"},
        "data": {
            "srcip": src_ip,
            "srcuser": user,
            "status": "success",
        },
        "full_log": f"Jun 15 14:05:00 {agent_name} sshd[12345]: Accepted password for {user} from {src_ip} port 22 ssh2",
    }


def sudo_privilege_escalation(
    *,
    offset: int = 360,
    user: str = "admin",
    agent_name: str = "web-server-01",
) -> Dict[str, Any]:
    return {
        "timestamp": _ts(offset),
        "rule": {
            "id": "5401",
            "level": 5,
            "description": "Sudo privilege escalation detected.",
            "groups": ["sudo", "priv_esc"],
            "mitre": {
                "id": ["T1548"],
                "tactic": ["Privilege Escalation"],
                "technique": ["Abuse Elevation Control Mechanism"],
            },
        },
        "agent": {
            "id": "001",
            "name": agent_name,
            "ip": "10.0.0.50",
        },
        "decoder": {"name": "sudo"},
        "data": {
            "srcuser": user,
            "command": "sudo su -",
        },
        "full_log": f"Jun 15 14:06:00 {agent_name} sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; COMMAND=/bin/su -",
    }


def file_integrity_alert(
    *,
    offset: int = 400,
    agent_name: str = "web-server-01",
) -> Dict[str, Any]:
    return {
        "timestamp": _ts(offset),
        "rule": {
            "id": "550",
            "level": 7,
            "description": "Integrity checksum changed.",
            "groups": ["syscheck"],
        },
        "agent": {
            "id": "001",
            "name": agent_name,
            "ip": "10.0.0.50",
        },
        "decoder": {"name": "syscheck"},
        "data": {
            "file": "/etc/passwd",
            "path": "/etc/passwd",
        },
        "full_log": f"Jun 15 14:06:40 {agent_name} syscheck: File '/etc/passwd' checksum changed.",
    }


def minimal_alert() -> Dict[str, Any]:
    return {
        "timestamp": _ts(0),
        "rule": {
            "id": "999",
            "level": 3,
            "description": "Generic alert.",
            "groups": [],
        },
        "agent": {
            "id": "002",
            "name": "generic-host",
        },
    }


def alert_with_no_groups_but_description_keywords() -> Dict[str, Any]:
    return {
        "timestamp": _ts(0),
        "rule": {
            "id": "100200",
            "level": 6,
            "description": "Authentication failure from external source.",
            "groups": [],
        },
        "agent": {
            "id": "003",
            "name": "firewall-01",
            "ip": "10.0.0.99",
        },
        "data": {
            "srcip": "203.0.113.50",
        },
        "full_log": "auth[1234]: authentication failure from 203.0.113.50",
    }


def alert_with_data_status_only() -> Dict[str, Any]:
    return {
        "timestamp": _ts(0),
        "rule": {
            "id": "100300",
            "level": 4,
            "description": "System event observed.",
            "groups": ["generic"],
        },
        "agent": {
            "id": "004",
            "name": "app-server-02",
            "ip": "10.0.0.77",
        },
        "data": {
            "srcip": "172.16.0.10",
            "srcuser": "deploy",
            "status": "denied",
        },
    }


def brute_force_scenario(
    count: int = 7,
    interval_seconds: int = 30,
    src_ip: str = "192.168.1.100",
    user: str = "admin",
) -> List[Dict[str, Any]]:
    """Generate failed login alerts from same IP."""
    return [
        ssh_auth_failure(offset=i * interval_seconds, src_ip=src_ip, user=user)
        for i in range(count)
    ]


def account_compromise_scenario(
    failure_count: int = 5,
    interval_seconds: int = 20,
    src_ip: str = "192.168.1.100",
    user: str = "admin",
) -> List[Dict[str, Any]]:
    """Generate failed logins followed by successful login."""
    alerts = [
        ssh_auth_failure(offset=i * interval_seconds, src_ip=src_ip, user=user)
        for i in range(failure_count)
    ]
    success_offset = failure_count * interval_seconds + 10
    alerts.append(ssh_auth_success(offset=success_offset, src_ip=src_ip, user=user))
    return alerts


def full_attack_scenario(
    failure_count: int = 5,
    src_ip: str = "192.168.1.100",
    user: str = "admin",
) -> List[Dict[str, Any]]:
    """Generate failed logins, success, and privilege escalation."""
    alerts = account_compromise_scenario(failure_count=failure_count, src_ip=src_ip, user=user)
    priv_offset = failure_count * 20 + 60
    alerts.append(sudo_privilege_escalation(offset=priv_offset, user=user))
    return alerts

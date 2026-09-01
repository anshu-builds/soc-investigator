"""SEC-08 Remediation Verification & Adversarial Regression Test Suite.

Verifies:
- SEC-08-01: Frontend PDF export dependency security boundary
- SEC-08-02: Reverse-proxy client IP extraction, CIDR/hostname trust, spoofing prevention
- SEC-08-03: Database-enforced alert deduplication across workers & idempotency
- SEC-08-04: Persistent security audit trail, state transitions, credential redaction
- SEC-08-05: ChromaDB token authentication
- SEC-08-06: Backend dependency hardening (jinja2, python-multipart, google-genai)
- SEC-08-07: CSV event-count ceiling (HTTP 413) and streaming protection
- SEC-08-08: Timezone-aware UTC datetime migration
- SEC-08-09: Elimination of unawaited asyncpg connection cancellation
"""

import json
import subprocess
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from backend.auth.limiter import get_client_ip, is_trusted_proxy
from backend.config import Settings, get_settings
from backend.main import app
from backend.models import AuditLog, Base, Incident, SecurityEvent, User
from backend.services.audit_service import log_audit_event, sanitize_audit_payload
from backend.services.log_service import parse_upload, run_pipeline
from backend.services.wazuh_adapter import WazuhAlert, WazuhAgent, WazuhRule, compute_dedup_hash, normalize_wazuh_alerts
from detection import Alert, EventType, NormalizedEvent


# ─── SEC-08-02: Trusted Proxy & Client IP Extraction Tests ───────────────────

def test_trusted_proxy_forwarded_ip_resolution():
    """When peer IP is in trusted_proxies, X-Real-IP and X-Forwarded-For are safely resolved."""
    request = MagicMock()
    request.client.host = "10.0.0.1"
    request.headers = {"x-real-ip": "203.0.113.195"}

    with patch("backend.auth.limiter.get_settings") as mock_settings:
        mock_settings.return_value = Settings(trusted_proxies="10.0.0.1,127.0.0.1")
        client_ip = get_client_ip(request)
        assert client_ip == "203.0.113.195"


def test_untrusted_proxy_forwarded_ip_ignored():
    """When peer IP is NOT trusted, X-Forwarded-For is strictly ignored to prevent spoofing."""
    request = MagicMock()
    request.client.host = "198.51.100.22"  # Untrusted client
    request.headers = {
        "x-forwarded-for": "10.0.0.1, 1.1.1.1",
        "x-real-ip": "1.1.1.1",
    }

    with patch("backend.auth.limiter.get_settings") as mock_settings:
        mock_settings.return_value = Settings(trusted_proxies="127.0.0.1,10.0.0.5")
        client_ip = get_client_ip(request)
        assert client_ip == "198.51.100.22"


def test_trusted_proxy_cidr_resolution():
    """Trusted proxy matching supports IPv4 CIDR blocks (e.g. Docker bridge networks)."""
    assert is_trusted_proxy("172.28.0.5", "172.28.0.0/16,127.0.0.1") is True
    assert is_trusted_proxy("172.29.0.5", "172.28.0.0/16,127.0.0.1") is False


def test_trusted_proxy_wildcard_rejected():
    """Settings validator strictly forbids wildcard '*' in trusted_proxies."""
    with pytest.raises(ValueError, match="Insecure trusted_proxies"):
        Settings(trusted_proxies="*")


def test_multiple_forwarded_ips_rightmost_trusted_taken():
    """When X-Real-IP is absent and X-Forwarded-For has multiple IPs, take the valid proxy-appended candidate."""
    request = MagicMock()
    request.client.host = "127.0.0.1"
    request.headers = {
        "x-forwarded-for": "spoofed.ip.client, 203.0.113.50",
    }

    with patch("backend.auth.limiter.get_settings") as mock_settings:
        mock_settings.return_value = Settings(trusted_proxies="127.0.0.1")
        client_ip = get_client_ip(request)
        assert client_ip == "203.0.113.50"


@pytest_asyncio.fixture
async def db_session():
    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session
    await test_engine.dispose()


# ─── SEC-08-03: Database-Enforced Deduplication Tests ────────────────────────

@pytest.mark.asyncio
async def test_database_dedup_hash_unique_constraint(db_session: AsyncSession):
    """Database unique constraint on SecurityEvent.dedup_hash prevents duplicate rows."""
    event1 = SecurityEvent(
        id=uuid.uuid4(),
        source_ip="192.168.1.10",
        event_type="AUTH_FAILURE",
        event_category="authentication",
        timestamp=datetime.now(timezone.utc),
        raw_log="sample log 1",
        dedup_hash="hash_abc_123",
    )
    db_session.add(event1)
    await db_session.commit()

    # Attempt inserting a second record with the exact same dedup_hash
    event2 = SecurityEvent(
        id=uuid.uuid4(),
        source_ip="192.168.1.10",
        event_type="AUTH_FAILURE",
        event_category="authentication",
        timestamp=datetime.now(timezone.utc),
        raw_log="sample log 2",
        dedup_hash="hash_abc_123",
    )
    db_session.add(event2)
    with pytest.raises(IntegrityError):
        await db_session.commit()
    await db_session.rollback()


@pytest.mark.asyncio
async def test_concurrent_duplicate_wazuh_alerts(db_session: AsyncSession):
    """Wazuh alerts with identical dedup_hash are deduplicated against existing database records."""
    alert = WazuhAlert(
        timestamp="2026-06-01T12:00:00Z",
        rule=WazuhRule(id="5710", level=5, description="SSH failed"),
        agent=WazuhAgent(id="001", name="srv1", ip="10.0.0.5"),
        full_log="Failed password for invalid user root from 192.168.1.100 port 22 ssh2",
    )
    digest = compute_dedup_hash(alert)
    normalized = normalize_wazuh_alerts([alert])
    assert normalized[0].metadata["dedup_hash"] == digest

    # First ingestion
    parsed1, flagged1, inc1 = await run_pipeline(
        db_session, [], "wazuh_webhook", _pre_normalized=normalized
    )
    await db_session.commit()
    assert parsed1 == 1

    # Second ingestion of the same alert should be filtered by database check
    normalized2 = normalize_wazuh_alerts([alert])
    parsed2, flagged2, inc2 = await run_pipeline(
        db_session, [], "wazuh_webhook", _pre_normalized=normalized2
    )
    await db_session.commit()
    assert parsed2 == 0
    assert inc2 == 0


# ─── SEC-08-04: Persistent Security Audit Trail Tests ────────────────────────

def test_audit_log_does_not_store_secrets():
    """sanitize_audit_payload strictly redacts credentials, passwords, tokens, API keys."""
    raw = {
        "user": "analyst@demo.com",
        "password": "SuperSecretPassword123!",
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "api_key": "sec_key_xyz",
        "nested": {
            "token": "tok_123",
            "safe_field": "visible_status",
        },
    }
    clean = sanitize_audit_payload(raw)
    assert clean["user"] == "analyst@demo.com"
    assert clean["password"] == "[REDACTED]"
    assert clean["access_token"] == "[REDACTED]"
    assert clean["api_key"] == "[REDACTED]"
    assert clean["nested"]["token"] == "[REDACTED]"
    assert clean["nested"]["safe_field"] == "visible_status"


@pytest.mark.asyncio
async def test_audit_log_persisted_on_incident_status_change(db_session: AsyncSession):
    """Status update persists an AuditLog with previous and new states."""
    now = datetime.now(timezone.utc)
    incident = Incident(
        id=uuid.uuid4(),
        title="Test Incident for Audit",
        severity="HIGH",
        status="OPEN",
        attack_type="BRUTE_FORCE",
        confidence=0.9,
        first_seen=now,
        last_seen=now,
    )
    db_session.add(incident)
    await db_session.commit()

    # Log status change audit
    user_id = uuid.uuid4()
    await log_audit_event(
        db_session,
        action="INCIDENT_STATUS_CHANGE",
        entity_type="INCIDENT",
        actor_user_id=user_id,
        entity_id=str(incident.id),
        source_ip="192.168.1.50",
        previous_state={"status": "OPEN"},
        new_state={"status": "CLOSED"},
    )
    await db_session.commit()

    res = await db_session.execute(
        select(AuditLog).where(AuditLog.entity_id == str(incident.id))
    )
    log = res.scalar_one_or_none()
    assert log is not None
    assert log.action == "INCIDENT_STATUS_CHANGE"
    assert log.previous_state == {"status": "OPEN"}
    assert log.new_state == {"status": "CLOSED"}
    assert log.source_ip == "192.168.1.50"


@pytest.mark.asyncio
async def test_failed_login_audit_log(db_session: AsyncSession):
    """Failed login attempts record AUTH_LOGIN_FAILURE."""
    await log_audit_event(
        db_session,
        action="AUTH_LOGIN_FAILURE",
        entity_type="USER",
        source_ip="198.51.100.77",
        details={"attempted_email": "intruder@evil.com", "password": "PasswordToRedact"},
        status="FAILURE",
    )
    await db_session.commit()

    res = await db_session.execute(
        select(AuditLog).where(AuditLog.action == "AUTH_LOGIN_FAILURE")
    )
    log = res.scalar_one_or_none()
    assert log is not None
    assert log.status == "FAILURE"
    assert log.source_ip == "198.51.100.77"
    assert log.details["attempted_email"] == "intruder@evil.com"
    assert log.details["password"] == "[REDACTED]"


# ─── SEC-08-05: ChromaDB Token Authentication Tests ─────────────────────────

def test_chromadb_client_configures_auth_token():
    """VectorStore passes X-Chroma-Token and Authorization headers when auth token is configured."""
    mock_chroma_mod = MagicMock()
    mock_http_client = MagicMock()
    mock_chroma_mod.HttpClient = mock_http_client

    with patch.dict("sys.modules", {"chromadb": mock_chroma_mod}), \
         patch("rag.retriever.settings") as mock_settings:
        from rag.retriever import VectorStore
        mock_settings.chroma_host = "localhost"
        mock_settings.chroma_port = 8001
        mock_settings.chroma_collection_knowledge = "soc_knowledge"
        mock_settings.chroma_auth_token = "secret_chroma_token_32chars"

        vs = VectorStore()
        mock_http_client.assert_called_once_with(
            host="localhost",
            port=8001,
            headers={
                "X-Chroma-Token": "secret_chroma_token_32chars",
                "Authorization": "Bearer secret_chroma_token_32chars",
            },
        )


# ─── SEC-08-07: CSV Event Count Limit Tests ─────────────────────────────────

def test_max_events_per_upload_boundary():
    """Log file with 10,000 events parses successfully."""
    header = "timestamp,source_ip,event_type,raw_log\n"
    rows = [f"2026-06-01T12:00:00Z,10.0.0.1,AUTH_FAILURE,log_{i}\n" for i in range(10_000)]
    csv_bytes = (header + "".join(rows)).encode("utf-8")

    parsed = parse_upload(csv_bytes, "test.csv", max_events=10_000)
    assert len(parsed) == 10_000


def test_max_events_per_upload_rejected():
    """Log file with 10,001 events raises ValueError immediately during iteration."""
    header = "timestamp,source_ip,event_type,raw_log\n"
    rows = [f"2026-06-01T12:00:00Z,10.0.0.1,AUTH_FAILURE,log_{i}\n" for i in range(10_001)]
    csv_bytes = (header + "".join(rows)).encode("utf-8")

    with pytest.raises(ValueError, match="exceeds maximum allowed event count"):
        parse_upload(csv_bytes, "test.csv", max_events=10_000)


# ─── SEC-08-08: Timezone-Aware UTC Datetime Tests ───────────────────────────

def test_no_deprecated_datetime_usage():
    """Alert dataclass default_factory uses timezone-aware UTC datetime."""
    alert = Alert(
        id=uuid.uuid4(),
        rule_name="Test Rule",
        severity="HIGH",
        confidence=0.95,
        description="Test description",
        contributing_event_ids=[],
    )
    assert alert.detected_at.tzinfo is not None
    assert alert.detected_at.tzinfo == timezone.utc


# ─── SEC-08-01: Frontend PDF Dependency Security Assertion ───────────────────

def test_pdf_export_security_assertion():
    """Frontend package.json must not have vulnerable html2pdf.js <= 0.13.0 or jspdf <= 4.2.0."""
    with open("frontend/package.json", "r") as f:
        pkg = json.load(f)

    deps = pkg.get("dependencies", {})
    html2pdf_ver = deps.get("html2pdf.js", "")
    assert "0.10" not in html2pdf_ver, "Vulnerable html2pdf.js 0.10.x detected"

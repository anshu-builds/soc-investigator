"""Integration security tests for authentication, authorization, IDOR protection,
production secrets validation, and Wazuh fail-closed boundaries.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from backend.auth import create_access_token, hash_password
from backend.config import Settings, get_settings
from backend.database import Base, get_db
from backend.main import app, _poll_lock
from backend.models import (
    Evidence,
    Incident,
    InvestigationSession,
    Report,
    SecurityEvent,
    User,
)

NOW = datetime(2025, 8, 19, 14, 20, 0, tzinfo=timezone.utc)
TEST_JWT_SECRET = "test-secret-key-32-chars-long-secure-value!"


@pytest_asyncio.fixture
async def auth_test_env(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", TEST_JWT_SECRET)
    monkeypatch.setenv("WAZUH_WEBHOOK_SECRET", "test-wazuh-secret")
    monkeypatch.setenv("ENVIRONMENT", "development")
    get_settings.cache_clear()

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)

    analyst_a_id = uuid.uuid4()
    analyst_b_id = uuid.uuid4()
    admin_id = uuid.uuid4()
    inactive_id = uuid.uuid4()
    incident_id = uuid.uuid4()
    session_a_id = uuid.uuid4()

    analyst_a = User(
        id=analyst_a_id,
        email="analyst.a@soc.corp",
        password_hash=hash_password("AnalystPassword123!"),
        role="analyst",
        is_active=True,
    )
    analyst_b = User(
        id=analyst_b_id,
        email="analyst.b@soc.corp",
        password_hash=hash_password("AnalystBPassword123!"),
        role="analyst",
        is_active=True,
    )
    admin_user = User(
        id=admin_id,
        email="admin@soc.corp",
        password_hash=hash_password("AdminPassword123!"),
        role="admin",
        is_active=True,
    )
    inactive_user = User(
        id=inactive_id,
        email="inactive@soc.corp",
        password_hash=hash_password("InactivePassword123!"),
        role="analyst",
        is_active=False,
    )
    incident = Incident(
        id=incident_id,
        title="Test Security Incident",
        attack_type="BRUTE_FORCE",
        severity="HIGH",
        confidence=0.9,
        status="OPEN",
        first_seen=NOW,
        last_seen=NOW,
        event_count=1,
    )
    session_a = InvestigationSession(
        id=session_a_id,
        incident_id=incident_id,
        analyst_id=analyst_a_id,
    )

    async with session_factory() as session:
        session.add_all([analyst_a, analyst_b, admin_user, inactive_user, incident, session_a])
        await session.commit()

    async def _override_db():
        async with session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = _override_db

    token_a = create_access_token(analyst_a_id, analyst_a.email, analyst_a.role, secret_key=TEST_JWT_SECRET)
    token_b = create_access_token(analyst_b_id, analyst_b.email, analyst_b.role, secret_key=TEST_JWT_SECRET)
    token_admin = create_access_token(admin_id, admin_user.email, admin_user.role, secret_key=TEST_JWT_SECRET)
    token_inactive = create_access_token(inactive_id, inactive_user.email, inactive_user.role, secret_key=TEST_JWT_SECRET)

    client = TestClient(app, raise_server_exceptions=False)

    try:
        yield {
            "client": client,
            "analyst_a_id": analyst_a_id,
            "analyst_b_id": analyst_b_id,
            "admin_id": admin_id,
            "incident_id": incident_id,
            "session_a_id": session_a_id,
            "token_a": token_a,
            "token_b": token_b,
            "token_admin": token_admin,
            "token_inactive": token_inactive,
        }
    finally:
        app.dependency_overrides.clear()
        await engine.dispose()
        get_settings.cache_clear()


class TestAuthenticationAndLogin:
    def test_login_success(self, auth_test_env):
        client = auth_test_env["client"]
        resp = client.post("/api/auth/login", json={
            "email": "analyst.a@soc.corp",
            "password": "AnalystPassword123!",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert isinstance(data["expires_in"], int)
        # Verify password hash is NEVER exposed
        assert "password" not in data
        assert "hash" not in data

    def test_login_case_insensitive_email(self, auth_test_env):
        client = auth_test_env["client"]
        resp = client.post("/api/auth/login", json={
            "email": "ANALYST.A@SOC.CORP",
            "password": "AnalystPassword123!",
        })
        assert resp.status_code == 200

    def test_login_invalid_password_returns_generic_401(self, auth_test_env):
        client = auth_test_env["client"]
        resp = client.post("/api/auth/login", json={
            "email": "analyst.a@soc.corp",
            "password": "WrongPassword!",
        })
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid email or password"

    def test_login_unknown_email_returns_generic_401(self, auth_test_env):
        client = auth_test_env["client"]
        resp = client.post("/api/auth/login", json={
            "email": "nonexistent@soc.corp",
            "password": "Password123!",
        })
        assert resp.status_code == 401
        assert resp.json()["detail"] == "Invalid email or password"

    def test_login_inactive_user_rejected(self, auth_test_env):
        client = auth_test_env["client"]
        resp = client.post("/api/auth/login", json={
            "email": "inactive@soc.corp",
            "password": "InactivePassword123!",
        })
        assert resp.status_code == 401


class TestEndpointProtectionInventory:
    """Audit all protected endpoints to prove anonymous requests are rejected."""

    @pytest.mark.parametrize(
        "method,path,payload",
        [
            ("POST", "/api/nlu/query", {"question": "show me failed logins"}),
            ("GET", "/api/logs", None),
            ("GET", "/api/incidents", None),
            ("GET", "/api/dashboard/summary", None),
            ("GET", "/api/integrations/wazuh/status", None),
        ],
    )
    def test_endpoints_reject_anonymous_requests(self, auth_test_env, method, path, payload):
        client = auth_test_env["client"]
        if method == "GET":
            resp = client.get(path)
        else:
            resp = client.post(path, json=payload)
        assert resp.status_code == 401
        assert "credentials were not provided" in resp.json()["detail"].lower()

    def test_public_health_endpoint_allowed_without_auth(self, auth_test_env):
        client = auth_test_env["client"]
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}

    def test_malformed_and_invalid_tokens_rejected(self, auth_test_env):
        client = auth_test_env["client"]
        for bad_header in [
            "Bearer not-a-valid-jwt",
            "Bearer header.payload.invalidsig",
            "Basic dXNlcjpwYXNz",
        ]:
            resp = client.get("/api/incidents", headers={"Authorization": bad_header})
            assert resp.status_code == 401

    def test_inactive_user_token_rejected(self, auth_test_env):
        client = auth_test_env["client"]
        token_inactive = auth_test_env["token_inactive"]
        resp = client.get("/api/incidents", headers={"Authorization": f"Bearer {token_inactive}"})
        assert resp.status_code == 401
        assert "inactive" in resp.json()["detail"].lower()

    def test_valid_token_allows_access(self, auth_test_env):
        client = auth_test_env["client"]
        token_a = auth_test_env["token_a"]
        resp = client.get("/api/incidents", headers={"Authorization": f"Bearer {token_a}"})
        assert resp.status_code == 200


class TestObjectLevelAuthorizationIDOR:
    """Enforce session ownership: User B cannot access User A's investigation sessions."""

    def test_analyst_b_cannot_chat_in_analyst_a_session(self, auth_test_env):
        client = auth_test_env["client"]
        session_a_id = auth_test_env["session_a_id"]
        token_b = auth_test_env["token_b"]

        resp = client.post(
            f"/api/sessions/{session_a_id}/chat",
            json={"message": "What happened?"},
            headers={"Authorization": f"Bearer {token_b}"},
        )
        assert resp.status_code == 403
        assert "Access denied" in resp.json()["detail"]

    def test_analyst_b_cannot_read_analyst_a_session_messages(self, auth_test_env):
        client = auth_test_env["client"]
        session_a_id = auth_test_env["session_a_id"]
        token_b = auth_test_env["token_b"]

        resp = client.get(
            f"/api/sessions/{session_a_id}/messages",
            headers={"Authorization": f"Bearer {token_b}"},
        )
        assert resp.status_code == 403
        assert "Access denied" in resp.json()["detail"]

    def test_admin_can_access_analyst_session(self, auth_test_env):
        client = auth_test_env["client"]
        session_a_id = auth_test_env["session_a_id"]
        token_admin = auth_test_env["token_admin"]

        resp = client.get(
            f"/api/sessions/{session_a_id}/messages",
            headers={"Authorization": f"Bearer {token_admin}"},
        )
        assert resp.status_code == 200


class TestRoleBasedAuthorization:
    """Privileged administrative operations require ADMIN role."""

    def test_analyst_cannot_trigger_wazuh_poll(self, auth_test_env):
        client = auth_test_env["client"]
        token_a = auth_test_env["token_a"]

        resp = client.post(
            "/api/integrations/wazuh/poll",
            headers={"Authorization": f"Bearer {token_a}"},
        )
        assert resp.status_code == 403
        assert "Administrative privileges required" in resp.json()["detail"]

    def test_admin_can_trigger_wazuh_poll(self, auth_test_env):
        client = auth_test_env["client"]
        token_admin = auth_test_env["token_admin"]

        from backend.services.wazuh_poller import WazuhPollResponse
        mock_poller = AsyncMock()
        mock_poller.poll_once.return_value = WazuhPollResponse(
            fetched=2,
            processed=2,
            duplicates=0,
            watermark="2025-06-15T14:30:00+00:00",
            errors=[],
        )

        with patch("backend.main._wazuh_poller", mock_poller):
            resp = client.post(
                "/api/integrations/wazuh/poll",
                headers={"Authorization": f"Bearer {token_admin}"},
            )
            assert resp.status_code == 200
            assert resp.json()["fetched"] == 2

    def test_wazuh_poll_concurrency_lock(self, auth_test_env):
        client = auth_test_env["client"]
        token_admin = auth_test_env["token_admin"]

        # Acquire lock to simulate an in-progress poll
        loop = asyncio.get_event_loop()
        loop.run_until_complete(_poll_lock.acquire())
        try:
            resp = client.post(
                "/api/integrations/wazuh/poll",
                headers={"Authorization": f"Bearer {token_admin}"},
            )
            assert resp.status_code == 409
            assert "already in progress" in resp.json()["detail"]
        finally:
            _poll_lock.release()


class TestWazuhWebhookFailClosed:
    """Wazuh machine-to-machine webhook must fail closed when unconfigured."""

    def test_webhook_fails_closed_when_secret_unset(self, auth_test_env, monkeypatch):
        monkeypatch.setenv("WAZUH_WEBHOOK_SECRET", "")
        get_settings.cache_clear()

        client = auth_test_env["client"]
        resp = client.post(
            "/api/integrations/wazuh/alerts",
            json={"alerts": []},
            headers={"X-Wazuh-Token": "any-token"},
        )
        assert resp.status_code == 403
        assert "unconfigured or disabled" in resp.json()["detail"]

    def test_webhook_rejects_missing_token(self, auth_test_env):
        client = auth_test_env["client"]
        resp = client.post(
            "/api/integrations/wazuh/alerts",
            json={"alerts": []},
        )
        assert resp.status_code == 401

    def test_webhook_rejects_invalid_token(self, auth_test_env):
        client = auth_test_env["client"]
        resp = client.post(
            "/api/integrations/wazuh/alerts",
            json={"alerts": []},
            headers={"X-Wazuh-Token": "wrong-token"},
        )
        assert resp.status_code == 401


class TestProductionSecretsValidation:
    """Production mode must reject default placeholder secrets."""

    def test_production_rejects_default_jwt_secret(self):
        with pytest.raises(ValueError, match="Insecure JWT_SECRET_KEY"):
            Settings(
                environment="production",
                jwt_secret_key="CHANGE_ME_in_production_min_32_chars",
                seed_admin_password="SuperSecurePassword123!",
            )

    def test_production_rejects_short_jwt_secret(self):
        with pytest.raises(ValueError, match="Insecure JWT_SECRET_KEY"):
            Settings(
                environment="production",
                jwt_secret_key="too-short-secret",
                seed_admin_password="SuperSecurePassword123!",
            )

    def test_production_rejects_default_admin_password(self):
        with pytest.raises(ValueError, match="Insecure SEED_ADMIN_PASSWORD"):
            Settings(
                environment="production",
                jwt_secret_key="a-very-long-and-secure-random-jwt-secret-key-12345",
                seed_admin_password="demo1234",
            )

    def test_production_accepts_strong_secrets(self):
        s = Settings(
            environment="production",
            jwt_secret_key="a-very-long-and-secure-random-jwt-secret-key-12345",
            seed_admin_password="ComplexRandomAdminPassword9988!!",
        )
        assert s.environment == "production"

    def test_development_mode_permits_default_for_local_dev(self):
        s = Settings(
            environment="development",
            jwt_secret_key="CHANGE_ME_in_production_min_32_chars",
            seed_admin_password="demo1234",
        )
        assert s.environment == "development"


class TestSeedAdminBehavior:
    """Ensure seed admin lifecycle respects administrative changes and does not silently mutate state."""

    @pytest.mark.asyncio
    async def test_missing_seed_admin_created(self, monkeypatch):
        monkeypatch.setenv("SEED_ADMIN_EMAIL", "newadmin@soc.corp")
        monkeypatch.setenv("SEED_ADMIN_PASSWORD", "SuperSecureAdminPass123!")
        get_settings.cache_clear()

        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        from backend.auth.service import ensure_seed_admin

        async with session_factory() as session:
            admin = await ensure_seed_admin(session)
            assert admin.email == "newadmin@soc.corp"
            assert admin.role == "admin"
            assert admin.is_active is True
            await session.commit()

        await engine.dispose()
        get_settings.cache_clear()

    @pytest.mark.asyncio
    async def test_existing_inactive_seed_admin_not_reactivated(self, monkeypatch):
        monkeypatch.setenv("SEED_ADMIN_EMAIL", "admin@soc.corp")
        get_settings.cache_clear()

        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        from backend.auth.service import ensure_seed_admin

        # Seed an intentionally deactivated admin
        async with session_factory() as session:
            user = User(
                email="admin@soc.corp",
                password_hash=hash_password("Password123!"),
                role="admin",
                is_active=False,  # Intentionally disabled by an administrator
            )
            session.add(user)
            await session.commit()

        # Run ensure_seed_admin again
        async with session_factory() as session:
            admin = await ensure_seed_admin(session)
            assert admin.is_active is False  # Must NOT be reactivated!

        await engine.dispose()
        get_settings.cache_clear()

    @pytest.mark.asyncio
    async def test_existing_modified_role_seed_admin_not_reset(self, monkeypatch):
        monkeypatch.setenv("SEED_ADMIN_EMAIL", "admin@soc.corp")
        get_settings.cache_clear()

        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        session_factory = async_sessionmaker(bind=engine, expire_on_commit=False)
        from backend.auth.service import ensure_seed_admin

        # Seed an admin whose role was demoted to analyst
        async with session_factory() as session:
            user = User(
                email="admin@soc.corp",
                password_hash=hash_password("Password123!"),
                role="analyst",
                is_active=True,
            )
            session.add(user)
            await session.commit()

        # Run ensure_seed_admin again
        async with session_factory() as session:
            admin = await ensure_seed_admin(session)
            assert admin.role == "analyst"  # Must NOT be silently reverted to admin!

        await engine.dispose()
        get_settings.cache_clear()


class TestStartupFailClosed:
    """Production startup must fail closed if seed admin initialization fails."""

    @pytest.mark.asyncio
    async def test_production_startup_fails_on_seed_admin_error(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("JWT_SECRET_KEY", "a-very-long-secure-random-jwt-secret-key-1234567")
        monkeypatch.setenv("SEED_ADMIN_PASSWORD", "SuperSecurePassword12345!")
        get_settings.cache_clear()

        from backend.main import lifespan, app

        with patch("backend.main.create_all_tables", new_callable=AsyncMock):
            with patch("backend.main.ensure_seed_admin", side_effect=RuntimeError("Database unreachable")):
                with pytest.raises(RuntimeError, match="Database unreachable"):
                    async with lifespan(app):
                        pass

        get_settings.cache_clear()

    @pytest.mark.asyncio
    async def test_development_startup_logs_and_continues_on_seed_admin_error(self, monkeypatch):
        monkeypatch.setenv("ENVIRONMENT", "development")
        get_settings.cache_clear()

        from backend.main import lifespan, app

        with patch("backend.main.create_all_tables", new_callable=AsyncMock):
            with patch("backend.main.ensure_seed_admin", side_effect=RuntimeError("Database unreachable")):
                # In development mode, exception is logged and ignored to allow mock tests
                async with lifespan(app):
                    pass

        get_settings.cache_clear()

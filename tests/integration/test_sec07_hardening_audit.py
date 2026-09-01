"""SEC-07 Integration & Production Hardening Audit Tests.

Verifies:
- CORS wildcard rejection when credentials are true
- Path traversal and control character sanitization on uploaded filenames
- Database engine pool_pre_ping and pool_recycle configurations
- Dockerfile non-root USER execution invariants
- Docker compose port binding restrictions (127.0.0.1 loopback)
- Nginx server_tokens suppression and header forwarding
- .gitignore protection for reports and key files
"""

from __future__ import annotations

import io
import os
import uuid
from pathlib import Path

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from backend.auth import create_access_token
from backend.config import Settings
from backend.database import Base, engine, get_db
from backend.main import app
from backend.models import User

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
TEST_SECRET = "test-sec07-production-hardening-secret-key-32chars"


@pytest_asyncio.fixture
async def sec07_test_client(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", TEST_SECRET)
    from backend.config import get_settings
    get_settings.cache_clear()

    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    user_id = uuid.uuid4()

    async with session_factory() as session:
        user = User(
            id=user_id,
            email="analyst@soc.corp",
            password_hash="fakehash",
            role="analyst",
            is_active=True,
        )
        session.add(user)
        await session.commit()

    async def override_get_db():
        async with session_factory() as s:
            yield s

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    token = create_access_token(user_id, "analyst@soc.corp", "analyst", secret_key=TEST_SECRET)

    yield {"client": client, "token": token}

    app.dependency_overrides.clear()


class TestCorsConfigurationSecurity:
    """Audit CORS wildcard validation."""

    def test_wildcard_cors_rejected_with_credentials(self):
        with pytest.raises(ValueError, match="Wildcard '\\*' is forbidden"):
            Settings(cors_origins="*")

        with pytest.raises(ValueError, match="Wildcard '\\*' is forbidden"):
            Settings(cors_origins="http://localhost:3000, *")

    def test_valid_cors_origins_accepted(self):
        s = Settings(cors_origins="http://localhost:3000, https://soc.corp.internal")
        assert len(s.cors_origins_list) == 2
        assert "http://localhost:3000" in s.cors_origins_list
        assert "https://soc.corp.internal" in s.cors_origins_list


class TestUploadFilenameSanitization:
    """Audit path traversal and control character stripping on uploaded logs."""

    def test_path_traversal_stripped_from_source_file(self, sec07_test_client):
        client = sec07_test_client["client"]
        token = sec07_test_client["token"]

        csv_content = b"timestamp,event_type,source_ip,username,hostname,message\n2026-09-01T12:00:00Z,AUTH_SUCCESS,10.0.0.1,admin,host-1,OK\n"
        headers = {"Authorization": f"Bearer {token}"}

        # Send malicious traversal in source_name
        response = client.post(
            "/api/logs/upload",
            headers=headers,
            data={"source_name": "../../../../etc/shadow"},
            files={"file": ("logs.csv", io.BytesIO(csv_content), "text/csv")},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["source_file"] == "shadow"
        assert "/" not in data["source_file"]
        assert ".." not in data["source_file"]

    def test_control_characters_purged_from_source_file(self, sec07_test_client):
        client = sec07_test_client["client"]
        token = sec07_test_client["token"]

        csv_content = b"timestamp,event_type,source_ip,username,hostname,message\n2026-09-01T12:00:00Z,AUTH_SUCCESS,10.0.0.1,admin,host-1,OK\n"
        headers = {"Authorization": f"Bearer {token}"}

        response = client.post(
            "/api/logs/upload",
            headers=headers,
            data={"source_name": "malicious\x00file\x08test.csv"},
            files={"file": ("logs.csv", io.BytesIO(csv_content), "text/csv")},
        )
        assert response.status_code == 200
        data = response.json()
        assert "\x00" not in data["source_file"]
        assert "\x08" not in data["source_file"]
        assert data["source_file"] == "maliciousfiletest.csv"


class TestDatabaseResilienceConfiguration:
    """Audit database engine connection pool configuration."""

    def test_database_engine_pre_ping_and_recycle_enabled(self):
        pool = engine.pool
        assert pool._pre_ping is True
        assert pool._recycle == 300


class TestDeploymentAndContainerSecurityInvariants:
    """Audit Dockerfile, compose, nginx, and git configuration security."""

    def test_backend_dockerfile_runs_as_non_root(self):
        dockerfile = (PROJECT_ROOT / "backend" / "Dockerfile").read_text(encoding="utf-8")
        assert "USER soc" in dockerfile
        assert "useradd -r" in dockerfile

    def test_frontend_dockerfile_runs_as_non_root(self):
        dockerfile = (PROJECT_ROOT / "frontend" / "Dockerfile").read_text(encoding="utf-8")
        assert "USER nextjs" in dockerfile
        assert "adduser -S nextjs" in dockerfile

    def test_docker_compose_binds_internal_ports_to_loopback(self):
        compose = (PROJECT_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        # PostgreSQL should not be exposed to 0.0.0.0
        assert "127.0.0.1:5432:5432" in compose
        assert ' - "5432:5432"' not in compose
        # ChromaDB should not be exposed to 0.0.0.0
        assert "127.0.0.1:8001:8001" in compose
        assert ' - "8001:8001"' not in compose
        # Backend should bind to loopback
        assert "127.0.0.1:8000:8000" in compose

    def test_nginx_suppresses_tokens_and_forwards_proto(self):
        nginx_conf = (PROJECT_ROOT / "nginx" / "nginx.conf").read_text(encoding="utf-8")
        assert "server_tokens off;" in nginx_conf
        assert "proxy_set_header X-Forwarded-Proto $scheme;" in nginx_conf
        assert "add_header X-Content-Type-Options" in nginx_conf

    def test_gitignore_protects_generated_reports_and_keys(self):
        gitignore = (PROJECT_ROOT / ".gitignore").read_text(encoding="utf-8")
        assert "generated_reports/" in gitignore
        assert "*.pem" in gitignore
        assert "*.key" in gitignore
        assert ".env" in gitignore

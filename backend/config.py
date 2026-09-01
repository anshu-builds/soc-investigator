from __future__ import annotations

from functools import lru_cache
from typing import List

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        extra="ignore",
    )

    database_url: str = "postgresql+asyncpg://socuser:socpassword@localhost:5432/socdb"
    database_sync_url: str = "postgresql://socuser:socpassword@localhost:5432/socdb"

    environment: str = "development"

    jwt_secret_key: str = "CHANGE_ME_in_production_min_32_chars"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 1440

    @field_validator("jwt_secret_key")
    @classmethod
    def validate_jwt_secret(cls, v: str, info) -> str:
        env = info.data.get("environment", "development") if info.data else "development"
        if env.lower() == "production":
            insecure = {
                "CHANGE_ME_in_production_min_32_chars",
                "CHANGE_ME_in_production",
                "CHANGE_ME",
                "secret",
                "",
            }
            if v in insecure or len(v) < 32:
                raise ValueError(
                    "Insecure JWT_SECRET_KEY: Production requires a random secret of at least 32 characters."
                )
        return v

    @field_validator("seed_admin_password")
    @classmethod
    def validate_seed_admin_password(cls, v: str, info) -> str:
        env = info.data.get("environment", "development") if info.data else "development"
        if env.lower() == "production":
            insecure = {"demo1234", "password", "admin", "12345678", ""}
            if v in insecure:
                raise ValueError(
                    "Insecure SEED_ADMIN_PASSWORD: Default credentials are forbidden in production."
                )
        return v

    @field_validator("cors_origins")
    @classmethod
    def validate_cors_origins(cls, v: str) -> str:
        origins = [o.strip() for o in v.split(",") if o.strip()]
        if "*" in origins:
            raise ValueError(
                "Insecure CORS configuration: Wildcard '*' is forbidden when allow_credentials is enabled."
            )
        return v

    @field_validator("trusted_proxies")
    @classmethod
    def validate_trusted_proxies(cls, v: str) -> str:
        tokens = [t.strip() for t in v.split(",") if t.strip()]
        if "*" in tokens:
            raise ValueError(
                "Insecure trusted_proxies configuration: Wildcard '*' is strictly forbidden."
            )
        return v

    llm_provider: str = "gemini"
    gemini_api_key: str = ""
    openai_api_key: str = ""
    gemini_model: str = "gemini-1.5-flash"
    openai_model: str = "gpt-4o-mini"

    chroma_host: str = "localhost"
    chroma_port: int = 8001
    chroma_collection_knowledge: str = "soc_knowledge"
    chroma_auth_token: str = ""

    cors_origins: str = "http://localhost:3000"

    backend_host: str = "0.0.0.0"
    backend_port: int = 8000
    reports_dir: str = "./generated_reports"
    max_events_per_upload: int = 10000

    seed_admin_email: str = "analyst@demo.com"
    seed_admin_password: str = "demo1234"

    # Wazuh integration
    wazuh_webhook_secret: str = ""
    wazuh_api_enabled: bool = False
    wazuh_api_url: str = ""
    wazuh_api_username: str = ""
    wazuh_api_password: str = ""
    wazuh_api_verify_ssl: bool = True
    wazuh_poll_interval_seconds: int = 30
    wazuh_api_request_timeout: int = 15
    wazuh_api_initial_lookback_minutes: int = 60
    wazuh_allow_private_ips: bool = False
    wazuh_allow_loopback: bool = False

    # Rate Limiting & Resource Protection (SEC-02)
    rate_limit_login_per_minute: int = 5
    rate_limit_nlu_per_minute: int = 30
    rate_limit_chat_per_minute: int = 20
    rate_limit_report_per_minute: int = 5
    rate_limit_log_upload_per_minute: int = 10
    rate_limit_wazuh_poll_per_minute: int = 3
    rate_limit_session_create_per_minute: int = 20
    rate_limit_status_update_per_minute: int = 30

    max_concurrent_llm_requests: int = 5
    max_concurrent_llm_per_user: int = 2
    max_concurrent_reports: int = 2

    trusted_proxies: str = ""

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",")]


@lru_cache
def get_settings() -> Settings:
    return Settings()

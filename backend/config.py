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

    jwt_secret_key: str = "CHANGE_ME_in_production_min_32_chars"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 1440

    llm_provider: str = "gemini"
    gemini_api_key: str = ""
    openai_api_key: str = ""
    gemini_model: str = "gemini-1.5-flash"
    openai_model: str = "gpt-4o-mini"

    chroma_host: str = "localhost"
    chroma_port: int = 8001
    chroma_collection_knowledge: str = "soc_knowledge"

    cors_origins: str = "http://localhost:3000"

    backend_host: str = "0.0.0.0"
    backend_port: int = 8000
    reports_dir: str = "./generated_reports"

    seed_admin_email: str = "analyst@demo.com"
    seed_admin_password: str = "demo1234"

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",")]


@lru_cache
def get_settings() -> Settings:
    return Settings()

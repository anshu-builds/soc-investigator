from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    ARRAY, Boolean, Column, DateTime, Float, ForeignKey,
    Integer, JSON, String, Text, TypeDecorator, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB as PG_JSONB, UUID as PG_UUID
from sqlalchemy.orm import relationship
import uuid as _uuid_mod


class UUID(TypeDecorator):
    """Portable UUID type: native on PostgreSQL, CHAR(36) on SQLite."""
    impl = String(36)
    cache_ok = True

    def __init__(self, as_uuid: bool = True, *args, **kwargs):
        self.as_uuid = as_uuid
        super().__init__(*args, **kwargs)

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_UUID(as_uuid=self.as_uuid))
        return dialect.type_descriptor(String(36))

    def process_bind_param(self, value, dialect):
        if value is None or dialect.name == "postgresql":
            return value
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None or dialect.name == "postgresql":
            return value
        return _uuid_mod.UUID(value) if self.as_uuid else value


def JSONB():
    """Portable JSONB type: native JSONB on PostgreSQL, JSON on SQLite."""
    return PG_JSONB().with_variant(JSON(), "sqlite")

from backend.database import Base


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


def _now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    email           = Column(String(255), unique=True, nullable=False, index=True)
    password_hash   = Column(String(255), nullable=False)
    role            = Column(String(50), nullable=False, default="analyst")
    is_active       = Column(Boolean, nullable=False, default=True)
    created_at      = Column(DateTime(timezone=True), nullable=False, default=_now)

    sessions = relationship("InvestigationSession", back_populates="analyst")


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id               = Column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    source_ip        = Column(String(45), nullable=False)
    destination_ip   = Column(String(45), nullable=True)
    username         = Column(String(255), nullable=True, index=True)
    hostname         = Column(String(255), nullable=True)
    event_type       = Column(String(100), nullable=False, index=True)
    event_category   = Column(String(50), nullable=False, default="unknown")
    timestamp        = Column(DateTime(timezone=True), nullable=False, index=True)
    severity_raw     = Column(String(20), nullable=True)
    description      = Column(Text, nullable=True)
    raw_log          = Column(Text, nullable=False)
    source_file      = Column(String(255), nullable=True)
    ingested_at      = Column(DateTime(timezone=True), nullable=False, default=_now)
    is_flagged       = Column(Boolean, nullable=False, default=False)
    incident_id      = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    extra_metadata   = Column(JSONB(), nullable=True)
    dedup_hash       = Column(String(64), unique=True, nullable=True, index=True)

    incident         = relationship("Incident", back_populates="events", foreign_keys=[incident_id])
    evidence_links   = relationship("Evidence", back_populates="event")


class Incident(Base):
    __tablename__ = "incidents"

    id                = Column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    title             = Column(String(255), nullable=False)
    description       = Column(Text, nullable=True)
    attack_type       = Column(String(100), nullable=False, index=True)
    severity          = Column(String(20), nullable=False, index=True)
    confidence        = Column(Float, nullable=False)
    status            = Column(String(50), nullable=False, default="OPEN", index=True)
    affected_username = Column(String(255), nullable=True)
    affected_host     = Column(String(255), nullable=True)
    source_ip         = Column(String(45), nullable=True)
    first_seen        = Column(DateTime(timezone=True), nullable=False)
    last_seen         = Column(DateTime(timezone=True), nullable=False)
    event_count       = Column(Integer, nullable=False, default=0)
    attack_hypothesis = Column(JSONB(), nullable=True)
    created_at        = Column(DateTime(timezone=True), nullable=False, default=_now)
    updated_at        = Column(DateTime(timezone=True), nullable=False, default=_now, onupdate=_now)

    events            = relationship("SecurityEvent", back_populates="incident", foreign_keys=[SecurityEvent.incident_id])
    evidence          = relationship("Evidence", back_populates="incident", cascade="all, delete-orphan")
    techniques        = relationship("AttackTechnique", back_populates="incident", cascade="all, delete-orphan")
    sessions          = relationship("InvestigationSession", back_populates="incident", cascade="all, delete-orphan")
    reports           = relationship("Report", back_populates="incident", cascade="all, delete-orphan")


class Evidence(Base):
    __tablename__ = "evidence"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    incident_id     = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    event_id        = Column(UUID(as_uuid=True), ForeignKey("security_events.id", ondelete="CASCADE"), nullable=False)
    role            = Column(String(100), nullable=False)
    description     = Column(Text, nullable=True)
    sequence_order  = Column(Integer, nullable=True)
    created_at      = Column(DateTime(timezone=True), nullable=False, default=_now)

    incident        = relationship("Incident", back_populates="evidence")
    event           = relationship("SecurityEvent", back_populates="evidence_links")


class AttackTechnique(Base):
    __tablename__ = "attack_techniques"

    id                 = Column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    incident_id        = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    technique_id       = Column(String(20), nullable=False)
    technique_name     = Column(String(255), nullable=False)
    tactic             = Column(String(100), nullable=False)
    sub_technique_id   = Column(String(25), nullable=True)
    sub_technique_name = Column(String(255), nullable=True)
    confidence         = Column(Float, nullable=False)
    mapping_source     = Column(String(50), nullable=False, default="RULE_BASED")
    url                = Column(String(500), nullable=True)

    incident           = relationship("Incident", back_populates="techniques")


class InvestigationSession(Base):
    __tablename__ = "investigation_sessions"

    id          = Column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    incident_id = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    analyst_id  = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at  = Column(DateTime(timezone=True), nullable=False, default=_now)

    incident    = relationship("Incident", back_populates="sessions")
    analyst     = relationship("User", back_populates="sessions")
    messages    = relationship("ChatMessage", back_populates="session", cascade="all, delete-orphan")


class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    session_id      = Column(UUID(as_uuid=True), ForeignKey("investigation_sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    role            = Column(String(20), nullable=False)
    content         = Column(Text, nullable=False)
    evidence_ids    = Column(JSONB(), nullable=True)
    rag_chunks_used = Column(JSONB(), nullable=True)
    answer_type     = Column(String(20), nullable=True)
    ai_confidence   = Column(Float, nullable=True)
    timestamp       = Column(DateTime(timezone=True), nullable=False, default=_now)

    session         = relationship("InvestigationSession", back_populates="messages")


class Report(Base):
    __tablename__ = "reports"

    id                   = Column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    incident_id          = Column(UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    generated_at         = Column(DateTime(timezone=True), nullable=False, default=_now)
    format               = Column(String(20), nullable=False, default="MARKDOWN")
    content              = Column(Text, nullable=False)
    file_path            = Column(String(500), nullable=True)
    ai_summary           = Column(Text, nullable=True)
    recommended_actions  = Column(JSONB(), nullable=True)

    incident             = relationship("Incident", back_populates="reports")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id             = Column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    timestamp      = Column(DateTime(timezone=True), nullable=False, default=_now, index=True)
    actor_user_id  = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    action         = Column(String(100), nullable=False, index=True)
    entity_type    = Column(String(100), nullable=False, index=True)
    entity_id      = Column(String(255), nullable=True, index=True)
    source_ip      = Column(String(45), nullable=True)
    user_agent     = Column(String(500), nullable=True)
    previous_state = Column(JSONB(), nullable=True)
    new_state      = Column(JSONB(), nullable=True)
    details        = Column(JSONB(), nullable=True)
    status         = Column(String(20), nullable=False, default="SUCCESS")

    actor          = relationship("User", foreign_keys=[actor_user_id])

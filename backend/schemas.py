from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class ORMBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class SecurityEventOut(ORMBase):
    id: uuid.UUID
    source_ip: str
    destination_ip: Optional[str]
    username: Optional[str]
    hostname: Optional[str]
    event_type: str
    event_category: str
    timestamp: datetime
    description: Optional[str]
    raw_log: str
    source_file: Optional[str]
    is_flagged: bool
    incident_id: Optional[uuid.UUID]


class SecurityEventListResponse(BaseModel):
    total: int
    items: List[SecurityEventOut]


class LogUploadResponse(BaseModel):
    job_id: str
    events_parsed: int
    events_flagged: int
    incidents_created: int
    processing_time_ms: int
    source_file: str


class AttackTechniqueOut(ORMBase):
    id: uuid.UUID
    incident_id: uuid.UUID
    technique_id: str
    technique_name: str
    tactic: str
    sub_technique_id: Optional[str]
    sub_technique_name: Optional[str]
    confidence: float
    mapping_source: str
    url: Optional[str]


class EvidenceOut(ORMBase):
    id: uuid.UUID
    incident_id: uuid.UUID
    event_id: uuid.UUID
    role: str
    description: Optional[str]
    sequence_order: Optional[int]
    event: Optional[SecurityEventOut] = None


class EvidenceListResponse(BaseModel):
    evidence: List[EvidenceOut]


class IncidentSummary(ORMBase):
    id: uuid.UUID
    title: str
    attack_type: str
    severity: str
    confidence: float
    status: str
    affected_username: Optional[str]
    source_ip: Optional[str]
    first_seen: datetime
    last_seen: datetime
    event_count: int
    created_at: datetime


class IncidentDetail(ORMBase):
    id: uuid.UUID
    title: str
    description: Optional[str]
    attack_type: str
    severity: str
    confidence: float
    status: str
    affected_username: Optional[str]
    affected_host: Optional[str]
    source_ip: Optional[str]
    first_seen: datetime
    last_seen: datetime
    event_count: int
    attack_hypothesis: Optional[Dict[str, Any]]
    created_at: datetime
    updated_at: datetime
    techniques: List[AttackTechniqueOut] = []
    evidence: List[EvidenceOut] = []


class IncidentListResponse(BaseModel):
    total: int
    items: List[IncidentSummary]


class IncidentStatusUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str = Field(..., pattern="^(OPEN|INVESTIGATING|CLOSED|FALSE_POSITIVE)$")


class SessionCreateResponse(BaseModel):
    session_id: uuid.UUID
    incident_id: uuid.UUID
    created_at: datetime


class ChatMessageOut(ORMBase):
    id: uuid.UUID
    session_id: uuid.UUID
    role: str
    content: str
    evidence_ids: Optional[List[str]]
    rag_chunks_used: Optional[List[Dict[str, Any]]]
    answer_type: Optional[str]
    ai_confidence: Optional[float]
    timestamp: datetime


class ChatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str = Field(..., min_length=1, max_length=2000)


class ChatResponse(BaseModel):
    message_id: uuid.UUID
    answer: str
    evidence_ids: List[str]
    mitre_references: List[str]
    rag_sources: List[str]
    answer_type: str
    confidence: float


class MessageListResponse(BaseModel):
    session_id: uuid.UUID
    messages: List[ChatMessageOut]


class TTSResponse(BaseModel):
    """Bounded audio payload returned for a persisted assistant message."""

    audio_clips_base64: List[Annotated[str, Field(min_length=1, max_length=2_666_668)]] = Field(..., min_length=1, max_length=3)
    content_type: str = "audio/wav"
    chunk_count: int = Field(..., ge=1, le=3)


class ReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    format: str = Field("MARKDOWN", pattern="^(MARKDOWN|JSON|HTML)$")
    include_ai_summary: bool = True


class ReportOut(ORMBase):
    id: uuid.UUID
    incident_id: uuid.UUID
    generated_at: datetime
    format: str
    content: str
    ai_summary: Optional[str]
    recommended_actions: Optional[List[str]]


class ReportCreateResponse(BaseModel):
    report_id: uuid.UUID
    download_url: str


class DashboardSummary(BaseModel):
    total_incidents: int
    open_incidents: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    events_processed_total: int
    events_flagged_total: int
    incidents_by_type: Dict[str, int]
    severity_distribution: Dict[str, int]
    recent_incidents: List[IncidentSummary]


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(..., min_length=3, max_length=255)
    password: str = Field(..., min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class NLQueryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    question: str = Field(..., min_length=1, max_length=500)


class NLQueryResponse(BaseModel):
    answer: str
    needs_clarification: bool
    clarification_question: Optional[str] = None
    clarification_options: List[str] = []
    result_count: int
    # Audit trail: exactly what was searched for, so an analyst (or auditor)
    # can verify the system didn't silently misinterpret the question.
    resolved_intent: Optional[str] = None
    resolved_filters: Optional[Dict[str, Any]] = None

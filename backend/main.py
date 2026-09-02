import asyncio
import base64
import hmac
import inspect
import logging
import os
import re
import sys
import time
import uuid
from collections import OrderedDict
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path
from typing import List, Optional

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from backend.services.audit_service import log_audit_event

sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.auth import (
    authenticate_user,
    check_rate_limit,
    create_access_token,
    ensure_seed_admin,
    get_client_ip,
    get_current_user,
    limiter,
    require_admin,
    require_authenticated_user,
)
from backend.config import get_settings
from backend.database import AsyncSessionLocal, create_all_tables, get_db
from backend.models import (
    AttackTechnique, ChatMessage, Evidence, Incident,
    InvestigationSession, Report, SecurityEvent, User,
)
from backend.schemas import (
    ChatRequest, ChatResponse, DashboardSummary, EvidenceListResponse,
    EvidenceOut, IncidentDetail, IncidentListResponse, IncidentStatusUpdate,
    IncidentSummary, LogUploadResponse, LoginRequest, MessageListResponse,
    NLQueryRequest, NLQueryResponse,
    ReportCreateResponse, ReportOut, ReportRequest, SecurityEventListResponse,
    SecurityEventOut, SessionCreateResponse, TokenResponse, TTSResponse,
)
from backend.services.log_service import parse_upload, run_pipeline
from backend.services.report_service import generate_report
from backend.services.sarvam_tts import SarvamTTSError, TextPreparationError, synthesize
from ai.investigation_chain import run_investigation_chain
from ai.summary_generator import generate_incident_summary
from ai.nlu import answer_question
from backend.services.wazuh_client import WazuhClient
from backend.services.wazuh_poller import WazuhPoller, WazuhPollResponse

settings = get_settings()

_wazuh_poller: Optional[WazuhPoller] = None
_poll_lock = asyncio.Lock()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _wazuh_poller
    await create_all_tables()
    try:
        async with AsyncSessionLocal() as session:
            await ensure_seed_admin(session)
            await session.commit()
    except Exception:
        logging.getLogger("soc.backend").exception("Seed admin initialization failed")
        current_settings = get_settings()
        if current_settings.environment.lower() == "production":
            raise
    try:
        from rag.ingest.ingest_playbooks import ensure_playbooks_ingested
        ensure_playbooks_ingested()
    except Exception as e:
        logging.getLogger("soc.backend").warning("Startup playbook check skipped: %s", e)

    if settings.wazuh_api_enabled:
        try:
            client = WazuhClient(
                base_url=settings.wazuh_api_url,
                username=settings.wazuh_api_username,
                password=settings.wazuh_api_password,
                verify_ssl=settings.wazuh_api_verify_ssl,
                timeout=settings.wazuh_api_request_timeout,
            )
            _wazuh_poller = WazuhPoller(
                client=client,
                session_factory=AsyncSessionLocal,
                poll_interval_seconds=settings.wazuh_poll_interval_seconds,
                initial_lookback_minutes=settings.wazuh_api_initial_lookback_minutes,
                is_duplicate_fn=_is_duplicate,
                record_dedup_fn=_record_dedup,
            )
            await _wazuh_poller.start()
        except Exception as e:
            logging.getLogger("soc.backend").warning("Wazuh poller startup failed: %s", e)

    yield

    if _wazuh_poller:
        await _wazuh_poller.stop()


app = FastAPI(
    title="SOC Investigator API",
    description="Evidence-grounded conversational SOC investigation platform",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    return response


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/api/auth/login", response_model=TokenResponse, tags=["auth"])
async def login(
    body: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Authenticate with email and password to receive a JWT access token."""
    current_settings = get_settings()
    client_ip = get_client_ip(request)
    await check_rate_limit(
        key=f"login:ip:{client_ip}",
        limit=current_settings.rate_limit_login_per_minute,
        window_seconds=60,
        action_name="login attempts",
    )

    user = await authenticate_user(db, body.email, body.password)
    if not user:
        await log_audit_event(
            db,
            action="AUTH_LOGIN_FAILURE",
            entity_type="USER",
            source_ip=client_ip,
            user_agent=request.headers.get("user-agent"),
            details={"attempted_email": body.email},
            status="FAILURE",
        )
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    await log_audit_event(
        db,
        action="AUTH_LOGIN_SUCCESS",
        entity_type="USER",
        actor_user_id=user.id,
        entity_id=str(user.id),
        source_ip=client_ip,
        user_agent=request.headers.get("user-agent"),
        details={"email": user.email, "role": user.role},
        status="SUCCESS",
    )
    await db.commit()

    token = create_access_token(
        user_id=user.id,
        email=user.email,
        role=user.role,
        expires_delta=timedelta(minutes=current_settings.jwt_expire_minutes),
    )
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=current_settings.jwt_expire_minutes * 60,
    )


logger = logging.getLogger("soc.backend")


@app.post("/api/nlu/query", response_model=NLQueryResponse, tags=["investigation"])
async def nl_query(
    body: NLQueryRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Natural-language investigation query. Deterministic entity extraction +
    intent classification + SQL translation — no LLM call on this path, so
    results are exact and auditable.
    """
    current_settings = get_settings()
    await check_rate_limit(
        key=f"nlu:user:{current_user.id}",
        limit=current_settings.rate_limit_nlu_per_minute,
        window_seconds=60,
        action_name="NLU queries",
    )

    try:
        response = await answer_question(db, body.question)
    except Exception:
        logger.exception("NLU query processing error")
        return NLQueryResponse(
            answer="An error occurred while processing your query. Please try rephrasing.",
            needs_clarification=False,
            result_count=0,
        )

    resolved_filters = None
    resolved_intent = None
    if response.query_spec is not None:
        resolved_intent = response.query_spec.intent.value
        e = response.query_spec.entities
        resolved_filters = {
            "ips": e.ips,
            "usernames": e.usernames,
            "hostnames": e.hostnames,
            "event_types": e.event_types,
            "attack_types": e.attack_types,
            "severities": e.severities,
            "mitre_techniques": e.mitre_techniques,
            "time_start": e.time_start.isoformat() if e.time_start else None,
            "time_end": e.time_end.isoformat() if e.time_end else None,
        }

    return NLQueryResponse(
        answer=response.answer,
        needs_clarification=response.needs_clarification,
        clarification_question=response.clarification_question,
        clarification_options=response.clarification_options,
        result_count=response.result_count,
        resolved_intent=resolved_intent,
        resolved_filters=resolved_filters,
    )


@app.post("/api/logs/upload", response_model=LogUploadResponse, tags=["logs"])
async def upload_logs(
    file: UploadFile = File(...),
    source_name: Optional[str] = Form(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    current_settings = get_settings()
    await check_rate_limit(
        key=f"upload:user:{current_user.id}",
        limit=current_settings.rate_limit_log_upload_per_minute,
        window_seconds=60,
        action_name="log uploads",
    )

    max_size = 10 * 1024 * 1024  # 10 MB limit
    if file.size and file.size > max_size:
        raise HTTPException(status_code=413, detail="File exceeds 10MB limit")

    # Read stream incrementally to prevent unbounded memory allocation on chunked transfers
    chunks: List[bytes] = []
    total_bytes = 0
    chunk_size = 64 * 1024  # 64 KB chunks

    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        total_bytes += len(chunk)
        if total_bytes > max_size:
            raise HTTPException(status_code=413, detail="File exceeds 10MB limit")
        chunks.append(chunk)

    content = b"".join(chunks)
    raw_source = source_name or file.filename or "unknown"
    clean_source = os.path.basename(raw_source.replace("\\", "/"))
    clean_source = re.sub(r"[\x00-\x1f\x7f]", "", clean_source).strip() or "upload.csv"
    source_file = clean_source[:255]

    t0 = time.time()
    try:
        raw_rows = parse_upload(
            content,
            file.filename or "upload.csv",
            max_events=current_settings.max_events_per_upload,
        )
        events_parsed, events_flagged, incidents_created = await run_pipeline(db, raw_rows, source_file)
        await db.commit()
    except ValueError as e:
        await db.rollback()
        err_msg = str(e)
        if "exceeds maximum allowed event count" in err_msg:
            raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=err_msg)
        raise HTTPException(status_code=422, detail=f"Invalid log file: {err_msg}")
    except Exception:
        await db.rollback()
        logger.exception("Log upload processing failed")
        raise HTTPException(status_code=422, detail="Failed to process uploaded log file. Please verify CSV format and column headers.")

    elapsed_ms = int((time.time() - t0) * 1000)
    return LogUploadResponse(
        job_id=str(uuid.uuid4()),
        events_parsed=events_parsed,
        events_flagged=events_flagged,
        incidents_created=incidents_created,
        processing_time_ms=elapsed_ms,
        source_file=source_file,
    )


@app.get("/api/logs", response_model=SecurityEventListResponse, tags=["logs"])
async def list_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=500),
    event_type: Optional[str] = None,
    source_ip: Optional[str] = None,
    username: Optional[str] = None,
    is_flagged: Optional[bool] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    q = select(SecurityEvent)
    if event_type:
        q = q.where(SecurityEvent.event_type == event_type)
    if source_ip:
        q = q.where(SecurityEvent.source_ip == source_ip)
    if username:
        q = q.where(SecurityEvent.username == username)
    if is_flagged is not None:
        q = q.where(SecurityEvent.is_flagged == is_flagged)

    total_result = await db.execute(select(func.count()).select_from(q.subquery()))
    total = total_result.scalar() or 0

    q = q.order_by(SecurityEvent.timestamp.desc()).offset((page - 1) * limit).limit(limit)
    result = await db.execute(q)
    events = result.scalars().all()
    return SecurityEventListResponse(total=total, items=events)


@app.get("/api/incidents", response_model=IncidentListResponse, tags=["incidents"])
async def list_incidents(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    attack_type: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    q = select(Incident)
    if severity:
        q = q.where(Incident.severity == severity)
    if status:
        q = q.where(Incident.status == status)
    if attack_type:
        q = q.where(Incident.attack_type == attack_type)

    total_result = await db.execute(select(func.count()).select_from(q.subquery()))
    total = total_result.scalar() or 0

    q = q.order_by(Incident.created_at.desc()).offset((page - 1) * limit).limit(limit)
    result = await db.execute(q)
    incidents = result.scalars().all()
    return IncidentListResponse(total=total, items=incidents)


@app.get("/api/incidents/{incident_id}", response_model=IncidentDetail, tags=["incidents"])
async def get_incident(
    incident_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Incident)
        .where(Incident.id == incident_id)
        .options(
            selectinload(Incident.evidence).selectinload(Evidence.event),
            selectinload(Incident.techniques),
        )
    )
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@app.patch("/api/incidents/{incident_id}/status", response_model=IncidentSummary, tags=["incidents"])
async def update_incident_status(
    incident_id: uuid.UUID,
    body: IncidentStatusUpdate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    current_settings = get_settings()
    await check_rate_limit(
        key=f"incident_status:user:{current_user.id}",
        limit=current_settings.rate_limit_status_update_per_minute,
        window_seconds=60,
        action_name="incident status updates",
    )

    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    old_status = incident.status
    incident.status = body.status
    await log_audit_event(
        db,
        action="INCIDENT_STATUS_CHANGE",
        entity_type="INCIDENT",
        actor_user_id=current_user.id,
        entity_id=str(incident.id),
        source_ip=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        previous_state={"status": old_status},
        new_state={"status": body.status},
        details={"incident_title": incident.title},
        status="SUCCESS",
    )
    await db.commit()
    await db.refresh(incident)
    return incident


@app.get("/api/incidents/{incident_id}/evidence", response_model=EvidenceListResponse, tags=["evidence"])
async def get_evidence(
    incident_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    inc_result = await db.execute(select(Incident.id).where(Incident.id == incident_id))
    if not inc_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Incident not found")

    result = await db.execute(
        select(Evidence)
        .where(Evidence.incident_id == incident_id)
        .options(selectinload(Evidence.event))
        .order_by(Evidence.sequence_order)
    )
    evidence = result.scalars().all()
    return EvidenceListResponse(evidence=evidence)


@app.post("/api/incidents/{incident_id}/sessions", response_model=SessionCreateResponse, tags=["investigation"])
async def create_session(
    incident_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    current_settings = get_settings()
    await check_rate_limit(
        key=f"session_create:user:{current_user.id}",
        limit=current_settings.rate_limit_session_create_per_minute,
        window_seconds=60,
        action_name="investigation session creations",
    )

    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    if incident.status in ("CLOSED", "FALSE_POSITIVE"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot create investigation session for a closed or false positive incident. Reopen the incident first.",
        )

    session = InvestigationSession(incident_id=incident_id, analyst_id=current_user.id)
    db.add(session)
    await db.flush()
    await log_audit_event(
        db,
        action="INVESTIGATION_SESSION_CREATE",
        entity_type="INVESTIGATION_SESSION",
        actor_user_id=current_user.id,
        entity_id=str(session.id),
        source_ip=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        details={"incident_id": str(incident_id)},
        status="SUCCESS",
    )
    await db.commit()
    await db.refresh(session)
    return SessionCreateResponse(
        session_id=session.id,
        incident_id=session.incident_id,
        created_at=session.created_at,
    )


@app.post("/api/sessions/{session_id}/chat", response_model=ChatResponse, tags=["investigation"])
async def chat(
    session_id: uuid.UUID,
    body: ChatRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    current_settings = get_settings()
    await check_rate_limit(
        key=f"chat:user:{current_user.id}",
        limit=current_settings.rate_limit_chat_per_minute,
        window_seconds=60,
        action_name="chat messages",
    )

    user_concurrency_key = f"chat_active:{current_user.id}"
    if not await limiter.acquire_concurrency(user_concurrency_key, current_settings.max_concurrent_llm_per_user):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many concurrent chat requests in progress. Please wait for previous request to complete.",
            headers={"Retry-After": "2"},
        )

    try:
        result = await db.execute(
            select(InvestigationSession).where(InvestigationSession.id == session_id)
        )
        session = result.scalar_one_or_none()
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")

        # Object-level authorization: enforce session ownership (unassigned sessions require admin)
        if (session.analyst_id is None or session.analyst_id != current_user.id) and current_user.role.lower() != "admin":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied to this investigation session")

        # Validate incident status: cannot chat on closed or false-positive incidents
        inc_result = await db.execute(select(Incident).where(Incident.id == session.incident_id))
        incident = inc_result.scalar_one_or_none()
        if incident and incident.status in ("CLOSED", "FALSE_POSITIVE"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot chat on an investigation session for a closed or false positive incident. Reopen the incident first.",
            )

        # Fetch recent conversation history prior to adding the current turn (bounded to last 10)
        history_result = await db.execute(
            select(ChatMessage)
            .where(ChatMessage.session_id == session_id)
            .order_by(ChatMessage.timestamp.desc())
            .limit(10)
        )
        previous_messages = list(reversed(history_result.scalars().all()))

        user_msg = ChatMessage(session_id=session_id, role="user", content=body.message)
        db.add(user_msg)
        await db.flush()

        try:
            from rag.retriever import get_retriever
            retriever = get_retriever()
        except Exception:
            retriever = None

        ai_result = await run_investigation_chain(
            db=db,
            incident_id=session.incident_id,
            user_question=body.message,
            rag_retriever=retriever,
            chat_history=previous_messages,
        )

        assistant_msg = ChatMessage(
            session_id=session_id,
            role="assistant",
            content=ai_result["answer"],
            evidence_ids=ai_result["evidence_ids"],
            rag_chunks_used=ai_result.get("rag_chunks_raw", []),
            answer_type=ai_result["answer_type"],
            ai_confidence=ai_result["confidence"],
        )
        db.add(assistant_msg)
        await db.commit()
        await db.refresh(assistant_msg)

        return ChatResponse(
            message_id=assistant_msg.id,
            answer=ai_result["answer"],
            evidence_ids=ai_result["evidence_ids"],
            mitre_references=ai_result["mitre_references"],
            rag_sources=ai_result["rag_sources"],
            answer_type=ai_result["answer_type"],
            confidence=ai_result["confidence"],
        )
    finally:
        await limiter.release_concurrency(user_concurrency_key)


@app.get("/api/sessions/{session_id}/messages", response_model=MessageListResponse, tags=["investigation"])
async def get_messages(
    session_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    session_result = await db.execute(
        select(InvestigationSession).where(InvestigationSession.id == session_id)
    )
    session = session_result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # Object-level authorization: enforce session ownership (unassigned sessions require admin)
    if (session.analyst_id is None or session.analyst_id != current_user.id) and current_user.role.lower() != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied to this investigation session")

    result = await db.execute(
        select(ChatMessage)
        .where(ChatMessage.session_id == session_id)
        .order_by(ChatMessage.timestamp)
    )
    messages = result.scalars().all()
    return MessageListResponse(session_id=session_id, messages=messages)


async def _log_tts_audit(
    db: AsyncSession,
    *,
    current_user: User,
    request: Request,
    message_id: uuid.UUID,
    session_id: Optional[uuid.UUID],
    status_value: str,
    outcome: str,
    character_count: Optional[int] = None,
    chunk_count: Optional[int] = None,
) -> None:
    """Persist a TTS audit event without storing message or provider content."""
    details = {"outcome": outcome}
    if session_id is not None:
        details["session_id"] = str(session_id)
    if character_count is not None:
        details["character_count"] = character_count
    if chunk_count is not None:
        details["chunk_count"] = chunk_count
    await log_audit_event(
        db,
        action="TTS_SYNTHESIS",
        entity_type="CHAT_MESSAGE",
        actor_user_id=current_user.id,
        entity_id=str(message_id),
        source_ip=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        details=details,
        status=status_value,
    )
    await db.commit()


@app.post("/api/messages/{message_id}/tts", response_model=TTSResponse, tags=["investigation"])
async def message_tts(
    message_id: uuid.UUID,
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate audio only for an authorized persisted assistant message."""
    current_settings = get_settings()
    await check_rate_limit(
        key=f"tts:user:{current_user.id}",
        limit=current_settings.rate_limit_tts_per_minute,
        window_seconds=60,
        action_name="text-to-speech requests",
    )

    # Do not reveal configuration state through message existence or ownership.
    if not current_settings.sarvam_tts_enabled or not current_settings.sarvam_api_key:
        await _log_tts_audit(
            db,
            current_user=current_user,
            request=request,
            message_id=message_id,
            session_id=None,
            status_value="FAILURE",
            outcome="UNAVAILABLE",
        )
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Audio is temporarily unavailable.")

    result = await db.execute(
        select(ChatMessage, InvestigationSession)
        .join(InvestigationSession, ChatMessage.session_id == InvestigationSession.id)
        .where(ChatMessage.id == message_id)
    )
    row = result.one_or_none()
    if row is None:
        await _log_tts_audit(
            db,
            current_user=current_user,
            request=request,
            message_id=message_id,
            session_id=None,
            status_value="FAILURE",
            outcome="NOT_FOUND",
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Message not found")

    message, session = row
    if (session.analyst_id is None or session.analyst_id != current_user.id) and current_user.role.lower() != "admin":
        await _log_tts_audit(
            db,
            current_user=current_user,
            request=request,
            message_id=message_id,
            session_id=session.id,
            status_value="FAILURE",
            outcome="ACCESS_DENIED",
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied to this investigation session")
    if message.role != "assistant":
        await _log_tts_audit(
            db,
            current_user=current_user,
            request=request,
            message_id=message_id,
            session_id=session.id,
            status_value="FAILURE",
            outcome="UNSUPPORTED_MESSAGE_ROLE",
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only assistant messages can be converted to speech.")

    # InMemoryRateLimiter is process-local. This key bounds work in this Uvicorn
    # worker only; a deployment-wide cap requires a shared coordinator.
    process_key = "tts_active:process"
    user_key = f"tts_active:{current_user.id}"
    if not await limiter.acquire_concurrency(process_key, current_settings.max_concurrent_tts_per_process):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many audio requests are in progress. Please try again shortly.",
            headers={"Retry-After": "2"},
        )
    user_slot_acquired = False
    try:
        if not await limiter.acquire_concurrency(user_key, current_settings.max_concurrent_tts_per_user):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many audio requests are in progress. Please try again shortly.",
                headers={"Retry-After": "2"},
            )
        user_slot_acquired = True

        try:
            clips = await synthesize(
                message.content,
                api_key=current_settings.sarvam_api_key,
                language=current_settings.sarvam_tts_language,
                speaker=current_settings.sarvam_tts_speaker,
                timeout_seconds=current_settings.sarvam_tts_timeout,
                max_total_chars=current_settings.sarvam_tts_max_characters,
                max_chunks=current_settings.sarvam_tts_max_chunks,
                max_audio_bytes_per_clip=current_settings.sarvam_tts_max_audio_bytes_per_clip,
                max_total_audio_bytes=current_settings.sarvam_tts_max_total_audio_bytes,
            )
        except TextPreparationError:
            await _log_tts_audit(
                db, current_user=current_user, request=request, message_id=message_id,
                session_id=session.id, status_value="FAILURE", outcome="TEXT_LIMIT_REJECTED",
            )
            raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Audio is temporarily unavailable.")
        except SarvamTTSError:
            await _log_tts_audit(
                db, current_user=current_user, request=request, message_id=message_id,
                session_id=session.id, status_value="FAILURE", outcome="PROVIDER_FAILURE",
            )
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Audio is temporarily unavailable.")
        except Exception:
            logger.exception("Unexpected TTS synthesis failure")
            await _log_tts_audit(
                db, current_user=current_user, request=request, message_id=message_id,
                session_id=session.id, status_value="FAILURE", outcome="INTERNAL_FAILURE",
            )
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Audio is temporarily unavailable.")

        if not clips:
            await _log_tts_audit(
                db, current_user=current_user, request=request, message_id=message_id,
                session_id=session.id, status_value="FAILURE", outcome="EMPTY_CONTENT",
            )
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Audio is temporarily unavailable.")

        encoded_clips = [base64.b64encode(clip.audio_bytes).decode("ascii") for clip in clips]
        await _log_tts_audit(
            db,
            current_user=current_user,
            request=request,
            message_id=message_id,
            session_id=session.id,
            status_value="SUCCESS",
            outcome="SUCCESS",
            character_count=len(message.content),
            chunk_count=len(clips),
        )
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Pragma"] = "no-cache"
        return TTSResponse(audio_clips_base64=encoded_clips, chunk_count=len(encoded_clips))
    finally:
        if user_slot_acquired:
            await limiter.release_concurrency(user_key)
        await limiter.release_concurrency(process_key)


@app.post("/api/incidents/{incident_id}/report", response_model=ReportCreateResponse, tags=["reports"])
async def create_report(
    incident_id: uuid.UUID,
    body: ReportRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    # Verify incident exists first before acquiring concurrency or generating AI summary
    inc_result = await db.execute(select(Incident.id).where(Incident.id == incident_id))
    if not inc_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Incident not found")

    current_settings = get_settings()
    await check_rate_limit(
        key=f"report:user:{current_user.id}",
        limit=current_settings.rate_limit_report_per_minute,
        window_seconds=60,
        action_name="report generations",
    )

    report_concurrency_key = f"report_active:{current_user.id}"
    if not await limiter.acquire_concurrency(report_concurrency_key, current_settings.max_concurrent_reports):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many concurrent report requests in progress. Please wait for previous report to complete.",
            headers={"Retry-After": "5"},
        )

    try:
        ai_summary = None
        if body.include_ai_summary:
            try:
                from rag.retriever import get_retriever
                retriever = get_retriever()
            except Exception:
                retriever = None
            ai_summary = await generate_incident_summary(
                db=db,
                incident_id=incident_id,
                rag_retriever=retriever,
            )

        report = await generate_report(
            db=db,
            incident_id=incident_id,
            format=body.format,
            ai_summary=ai_summary,
        )
        await log_audit_event(
            db,
            action="REPORT_CREATE",
            entity_type="REPORT",
            actor_user_id=current_user.id,
            entity_id=str(report.id),
            source_ip=get_client_ip(request),
            user_agent=request.headers.get("user-agent"),
            details={"incident_id": str(incident_id), "format": body.format},
            status="SUCCESS",
        )
        await db.commit()
        return ReportCreateResponse(
            report_id=report.id,
            download_url=f"/api/reports/{report.id}/download",
        )
    finally:
        await limiter.release_concurrency(report_concurrency_key)


@app.get("/api/reports/{report_id}", response_model=ReportOut, tags=["reports"])
async def get_report(
    report_id: uuid.UUID,
    response: Response,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not current_user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user")
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return report


@app.get("/api/reports/{report_id}/download", tags=["reports"])
async def download_report(
    report_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not current_user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Inactive user")
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    fmt = (report.format or "MARKDOWN").upper()
    if fmt == "HTML":
        filename = f"incident_report_{report.incident_id}.html"
        media_type = "text/html; charset=utf-8"
    else:
        filename = f"incident_report_{report.incident_id}.md"
        media_type = "text/markdown; charset=utf-8"

    return Response(
        content=report.content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store, no-cache, must-revalidate, private",
            "Pragma": "no-cache",
        },
    )


@app.get("/api/dashboard/summary", response_model=DashboardSummary, tags=["dashboard"])
async def dashboard_summary(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    total_result = await db.execute(select(func.count(Incident.id)))
    total_incidents = total_result.scalar() or 0

    open_result = await db.execute(select(func.count(Incident.id)).where(Incident.status == "OPEN"))
    open_incidents = open_result.scalar() or 0

    severity_counts = {}
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        r = await db.execute(select(func.count(Incident.id)).where(Incident.severity == sev))
        severity_counts[sev] = r.scalar() or 0

    events_total = await db.execute(select(func.count(SecurityEvent.id)))
    events_flagged = await db.execute(select(func.count(SecurityEvent.id)).where(SecurityEvent.is_flagged.is_(True)))

    type_result = await db.execute(
        select(Incident.attack_type, func.count(Incident.id))
        .group_by(Incident.attack_type)
    )
    incidents_by_type = {row[0]: row[1] for row in type_result}

    recent_result = await db.execute(
        select(Incident).order_by(Incident.created_at.desc()).limit(5)
    )
    recent = recent_result.scalars().all()

    return DashboardSummary(
        total_incidents=total_incidents,
        open_incidents=open_incidents,
        critical_count=severity_counts.get("CRITICAL", 0),
        high_count=severity_counts.get("HIGH", 0),
        medium_count=severity_counts.get("MEDIUM", 0),
        low_count=severity_counts.get("LOW", 0),
        events_processed_total=events_total.scalar() or 0,
        events_flagged_total=events_flagged.scalar() or 0,
        incidents_by_type=incidents_by_type,
        severity_distribution=severity_counts,
        recent_incidents=recent,
    )


# Wazuh integration

wazuh_logger = logging.getLogger("soc.wazuh")

_DEDUP_MAX = 10_000
_dedup_cache: OrderedDict[str, bool] = OrderedDict()
_dedup_in_flight: set = set()


def _is_duplicate(digest: str) -> bool:
    """Return True if digest has been committed before or is currently in flight."""
    return digest in _dedup_cache or digest in _dedup_in_flight


def _record_dedup(digests: List[str]) -> None:
    """Record digests into LRU cache after successful commit and release in-flight."""
    for digest in digests:
        _dedup_in_flight.discard(digest)
        _dedup_cache[digest] = True
        _dedup_cache.move_to_end(digest)
        while len(_dedup_cache) > _DEDUP_MAX:
            _dedup_cache.popitem(last=False)


def _release_in_flight(digests: List[str]) -> None:
    """Release digests from in-flight tracking on pipeline failure."""
    for digest in digests:
        _dedup_in_flight.discard(digest)


@app.post("/api/integrations/wazuh/alerts", tags=["wazuh"])
async def ingest_wazuh_alerts(
    request: Request,
    x_wazuh_token: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db),
):
    """Ingest Wazuh alerts and run detection/correlation pipeline."""
    from backend.services.wazuh_adapter import (
        WazuhIngestionRequest,
        WazuhIngestionResponse,
        compute_dedup_hash,
        normalize_wazuh_alerts,
    )

    # Authenticate webhook (machine-to-machine, fail-closed)
    current_settings = get_settings()
    secret = current_settings.wazuh_webhook_secret
    if not secret:
        wazuh_logger.error("Wazuh webhook rejected: WAZUH_WEBHOOK_SECRET is unconfigured")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Wazuh webhook ingestion is unconfigured or disabled",
        )

    if not x_wazuh_token or not hmac.compare_digest(x_wazuh_token, secret):
        wazuh_logger.warning("Wazuh webhook auth failed (invalid or missing token)")
        await log_audit_event(
            db,
            action="WAZUH_WEBHOOK_AUTH_FAILURE",
            entity_type="INTEGRATION_WAZUH",
            source_ip=get_client_ip(request),
            user_agent=request.headers.get("user-agent"),
            details={"reason": "Invalid or missing X-Wazuh-Token"},
            status="FAILURE",
        )
        await db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing X-Wazuh-Token")

    # Validate Content-Type
    content_type = request.headers.get("content-type", "")
    if content_type and not content_type.lower().startswith("application/json"):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Invalid Content-Type: webhook requires application/json",
        )

    # Check request size limit (1 MB) via Content-Length header if present
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            cl_int = int(content_length)
            if cl_int > 1_048_576:
                raise HTTPException(status_code=413, detail="Payload exceeds 1 MB limit")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header")

    # Stream chunks with hard byte ceiling (defends against chunked-transfer unbounded payloads)
    chunks: List[bytes] = []
    total_bytes = 0
    max_size = 1_048_576

    async for chunk in request.stream():
        total_bytes += len(chunk)
        if total_bytes > max_size:
            raise HTTPException(status_code=413, detail="Payload exceeds 1 MB limit")
        chunks.append(chunk)

    raw_body = b"".join(chunks)
    try:
        import json as json_lib
        body = json_lib.loads(raw_body.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid JSON payload")

    try:
        payload = WazuhIngestionRequest.model_validate(body)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Validation error: {e}")

    # Deduplicate alerts against both persistent database and in-memory cache
    incoming_digests = [compute_dedup_hash(a) for a in payload.alerts]
    already_persisted = set()
    try:
        db_existing = await db.execute(
            select(SecurityEvent.dedup_hash).where(SecurityEvent.dedup_hash.in_(incoming_digests))
        )
        if hasattr(db_existing, "scalars"):
            sc = db_existing.scalars()
            if hasattr(sc, "all"):
                items = sc.all()
                if not inspect.isawaitable(items):
                    already_persisted = set(items)
    except Exception:
        pass

    duplicates = 0
    errors: List[str] = []
    fresh_alerts = []
    fresh_digests = []

    for alert, digest in zip(payload.alerts, incoming_digests):
        if digest in already_persisted or _is_duplicate(digest):
            duplicates += 1
            continue
        fresh_alerts.append(alert)
        fresh_digests.append(digest)

    if not fresh_alerts:
        return WazuhIngestionResponse(
            received=len(payload.alerts),
            processed=0,
            duplicates=duplicates,
        )

    for d in fresh_digests:
        _dedup_in_flight.add(d)

    try:
        normalized = normalize_wazuh_alerts(fresh_alerts)
        events_parsed, events_flagged, incidents_created = await run_pipeline(
            db, [], "", _pre_normalized=normalized
        )
        await db.commit()
        # Mark as processed only after successful database commit
        _record_dedup(fresh_digests)
    except IntegrityError:
        await db.rollback()
        _release_in_flight(fresh_digests)
        wazuh_logger.info("Wazuh concurrent duplicate caught by database unique constraint")
        return WazuhIngestionResponse(
            received=len(payload.alerts),
            processed=0,
            duplicates=len(payload.alerts),
            errors=[],
        )
    except Exception:
        await db.rollback()
        _release_in_flight(fresh_digests)
        wazuh_logger.exception("Wazuh pipeline processing error")
        raise HTTPException(status_code=500, detail="Internal error processing security alerts")

    wazuh_logger.info(
        "Wazuh ingestion: received=%d processed=%d duplicates=%d flagged=%d incidents=%d",
        len(payload.alerts),
        len(fresh_alerts),
        duplicates,
        events_flagged,
        incidents_created,
    )

    return WazuhIngestionResponse(
        received=len(payload.alerts),
        processed=len(fresh_alerts),
        duplicates=duplicates,
        errors=errors,
    )


@app.post("/api/integrations/wazuh/poll", response_model=WazuhPollResponse, tags=["wazuh"])
async def poll_wazuh_alerts(
    request: Request,
    current_user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Trigger an on-demand poll cycle from the Wazuh REST API (Admin only)."""
    global _wazuh_poller
    current_settings = get_settings()

    await check_rate_limit(
        key=f"wazuh_poll:user:{current_user.id}",
        limit=current_settings.rate_limit_wazuh_poll_per_minute,
        window_seconds=60,
        action_name="Wazuh polling",
    )

    if _poll_lock.locked():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Wazuh polling operation is already in progress",
        )

    if _wazuh_poller is None:
        if not current_settings.wazuh_api_url or not current_settings.wazuh_api_username or not current_settings.wazuh_api_password:
            raise HTTPException(
                status_code=400,
                detail="Wazuh API is not configured (WAZUH_API_URL, WAZUH_API_USERNAME, WAZUH_API_PASSWORD required)",
            )
        client = WazuhClient(
            base_url=current_settings.wazuh_api_url,
            username=current_settings.wazuh_api_username,
            password=current_settings.wazuh_api_password,
            verify_ssl=current_settings.wazuh_api_verify_ssl,
            timeout=current_settings.wazuh_api_request_timeout,
        )
        _wazuh_poller = WazuhPoller(
            client=client,
            session_factory=AsyncSessionLocal,
            poll_interval_seconds=current_settings.wazuh_poll_interval_seconds,
            initial_lookback_minutes=current_settings.wazuh_api_initial_lookback_minutes,
            is_duplicate_fn=_is_duplicate,
            record_dedup_fn=_record_dedup,
        )

    async with _poll_lock:
        try:
            result = await _wazuh_poller.poll_once()
            if db is not None:
                await log_audit_event(
                    db,
                    action="WAZUH_MANUAL_POLL",
                    entity_type="INTEGRATION_WAZUH",
                    actor_user_id=current_user.id,
                    source_ip=get_client_ip(request),
                    user_agent=request.headers.get("user-agent"),
                    details=result.model_dump(mode="json"),
                    status="SUCCESS",
                )
                await db.commit()
            return result
        except HTTPException:
            raise
        except Exception:
            wazuh_logger.exception("Manual Wazuh poll failed")
            raise HTTPException(
                status_code=502,
                detail="Wazuh polling failed. Check server logs for details.",
            )


@app.get("/api/integrations/wazuh/status", tags=["wazuh"])
async def wazuh_status(
    current_user: User = Depends(get_current_user),
):
    """Health check and status for Wazuh webhook and API polling integrations."""
    current_settings = get_settings()
    poller_status = _wazuh_poller.get_status() if _wazuh_poller else {
        "running": False,
        "poll_interval_seconds": current_settings.wazuh_poll_interval_seconds,
        "overlap_seconds": 30,
        "watermark": None,
        "last_attempted_poll": None,
        "last_successful_poll": None,
        "total_alerts_fetched": 0,
        "total_alerts_processed": 0,
        "total_duplicates": 0,
        "consecutive_errors": 0,
        "last_error": None,
    }

    return {
        "status": "ready",
        "authentication": "configured" if current_settings.wazuh_webhook_secret else "unconfigured",
        "dedup_cache_size": len(_dedup_cache),
        "api_polling": {
            "enabled": current_settings.wazuh_api_enabled,
            "configured": bool(current_settings.wazuh_api_url and current_settings.wazuh_api_username),
            "api_url": current_settings.wazuh_api_url if current_settings.wazuh_api_url else None,
            "verify_ssl": current_settings.wazuh_api_verify_ssl,
            **poller_status,
        },
    }

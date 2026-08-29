from __future__ import annotations

import hmac
import logging
import sys
import time
import uuid
from collections import OrderedDict
from contextlib import asynccontextmanager
from pathlib import Path
from typing import List, Optional

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Query, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

sys.path.insert(0, str(Path(__file__).parent.parent))

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
    ReportCreateResponse, ReportOut, ReportRequest, SecurityEventListResponse,
    SecurityEventOut, SessionCreateResponse, TokenResponse,
)
from backend.services.log_service import parse_upload, run_pipeline
from backend.services.report_service import generate_report
from ai.investigation_chain import run_investigation_chain

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await create_all_tables()
    try:
        from rag.ingest.ingest_playbooks import ensure_playbooks_ingested
        ensure_playbooks_ingested()
    except Exception as e:
        logging.getLogger("soc.backend").warning("Startup playbook check skipped: %s", e)
    yield


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


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/api/logs/upload", response_model=LogUploadResponse, tags=["logs"])
async def upload_logs(
    file: UploadFile = File(...),
    source_name: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_db),
):
    if file.size and file.size > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File exceeds 10MB limit")

    content = await file.read()
    source_file = source_name or file.filename or "unknown"

    t0 = time.time()
    try:
        raw_rows = parse_upload(content, file.filename or "upload.csv")
        events_parsed, events_flagged, incidents_created = await run_pipeline(db, raw_rows, source_file)
        await db.commit()
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=422, detail=f"Processing error: {str(e)}")

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
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    incident.status = body.status
    await db.commit()
    await db.refresh(incident)
    return incident


@app.get("/api/incidents/{incident_id}/evidence", response_model=EvidenceListResponse, tags=["evidence"])
async def get_evidence(
    incident_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
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
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Incident not found")

    session = InvestigationSession(incident_id=incident_id)
    db.add(session)
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
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(InvestigationSession).where(InvestigationSession.id == session_id)
    )
    session = result.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

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


@app.get("/api/sessions/{session_id}/messages", response_model=MessageListResponse, tags=["investigation"])
async def get_messages(
    session_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ChatMessage)
        .where(ChatMessage.session_id == session_id)
        .order_by(ChatMessage.timestamp)
    )
    messages = result.scalars().all()
    return MessageListResponse(session_id=session_id, messages=messages)


@app.post("/api/incidents/{incident_id}/report", response_model=ReportCreateResponse, tags=["reports"])
async def create_report(
    incident_id: uuid.UUID,
    body: ReportRequest,
    db: AsyncSession = Depends(get_db),
):
    report = await generate_report(
        db=db,
        incident_id=incident_id,
        format=body.format,
        ai_summary=None,
    )
    await db.commit()
    return ReportCreateResponse(
        report_id=report.id,
        download_url=f"/api/reports/{report.id}/download",
    )


@app.get("/api/reports/{report_id}", response_model=ReportOut, tags=["reports"])
async def get_report(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@app.get("/api/reports/{report_id}/download", tags=["reports"])
async def download_report(
    report_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    filename = f"incident_report_{report.incident_id}.md"
    return Response(
        content=report.content,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/dashboard/summary", response_model=DashboardSummary, tags=["dashboard"])
async def dashboard_summary(
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


def _is_duplicate(digest: str) -> bool:
    """Return True if digest has been committed before."""
    return digest in _dedup_cache


def _record_dedup(digests: List[str]) -> None:
    """Record digests into LRU cache after successful commit."""
    for digest in digests:
        _dedup_cache[digest] = True
        _dedup_cache.move_to_end(digest)
        while len(_dedup_cache) > _DEDUP_MAX:
            _dedup_cache.popitem(last=False)


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

    # Authenticate webhook
    secret = settings.wazuh_webhook_secret
    if secret:
        if not x_wazuh_token or not hmac.compare_digest(x_wazuh_token, secret):
            wazuh_logger.warning("Wazuh webhook auth failed (invalid or missing token)")
            raise HTTPException(status_code=401, detail="Invalid or missing X-Wazuh-Token")
    else:
        wazuh_logger.warning("WAZUH_WEBHOOK_SECRET is not configured — webhook is unauthenticated")

    # Check request size limit (1 MB)
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            cl_int = int(content_length)
            if cl_int > 1_048_576:
                raise HTTPException(status_code=413, detail="Payload exceeds 1 MB limit")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid Content-Length header")

    # Validate payload
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=422, detail="Invalid JSON payload")

    try:
        payload = WazuhIngestionRequest.model_validate(body)
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Validation error: {e}")

    # Deduplicate alerts
    duplicates = 0
    errors: List[str] = []
    fresh_alerts = []
    fresh_digests = []

    for alert in payload.alerts:
        digest = compute_dedup_hash(alert)
        if _is_duplicate(digest):
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

    try:
        normalized = normalize_wazuh_alerts(fresh_alerts)
        events_parsed, events_flagged, incidents_created = await run_pipeline(
            db, [], "", _pre_normalized=normalized
        )
        await db.commit()
        # Mark as processed only after successful database commit
        _record_dedup(fresh_digests)
    except Exception:
        await db.rollback()
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


@app.get("/api/integrations/wazuh/status", tags=["wazuh"])
async def wazuh_status():
    """Health check for the Wazuh integration."""
    return {
        "status": "ready",
        "authentication": "configured" if settings.wazuh_webhook_secret else "unconfigured",
        "dedup_cache_size": len(_dedup_cache),
    }

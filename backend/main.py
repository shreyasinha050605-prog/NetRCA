import json
import math
from contextlib import asynccontextmanager
import datetime

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import TypeAdapter
from sqlalchemy.orm import Session

import database
import models
import schemas
from services.ai_service import run_rca_analysis
from services.audit_service import append_audit_entry
from services.demo_service import build_demo_logs
from services.ingestion_service import ingest_logs as ingest_log_batch
from services.queue_service import rca_queue
from utils.crypto_utils import hmac_enforced, tls_configuration, verify_hmac_signature


@asynccontextmanager
async def lifespan(_: FastAPI):
    rca_queue.start(run_rca_analysis)
    yield
    rca_queue.stop()


app = FastAPI(title="NetRCA AI API", version="2.2.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

database.initialize_database()

LOG_ITEM_ADAPTER = TypeAdapter(list[schemas.LogItem])
METRIC_SEVERITY_WEIGHTS = {
    "info": 1,
    "warning": 2,
    "error": 3,
    "high": 4,
    "critical": 5,
}

def _safe_json_load(value, default):
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def _coerce_correlated_logs(value):
    items = _safe_json_load(value, [])
    if not items or not isinstance(items, list):
        return []
    if isinstance(items[0], dict):
        return items
    return []


def _coerce_ai_report(value):
    report = _safe_json_load(value, None)
    if not isinstance(report, dict):
        return None

    report.setdefault("what_changed", "Not yet derived for this legacy report.")
    report.setdefault("why_it_happened", report.get("reasoning", "Not available."))
    report.setdefault("attack_or_misconfig", "unknown")
    report.setdefault("security_risk_level", "Medium")
    report.setdefault("affected_components", [])
    report.setdefault("security_impact", [])
    report.setdefault("remediation", report.get("ai_fix", ""))
    report.setdefault("remediation_steps", [])
    report.setdefault("confidence", 0.5)
    report.setdefault("reasoning_steps", [])
    return report


def _serialize_incident(incident: models.Incident, db: Session) -> schemas.IncidentOut:
    audits = (
        db.query(models.IncidentAudit)
        .filter(models.IncidentAudit.incident_id == incident.id)
        .order_by(models.IncidentAudit.created_at.desc())
        .all()
    )

    return schemas.IncidentOut(
        incident_ref=incident.incident_ref,
        detected_at=incident.detected_at,
        updated_at=incident.updated_at,
        classification=incident.classification,
        target=incident.target,
        service=incident.service,
        port=incident.port,
        severity=incident.severity,
        severity_score=incident.severity_score,
        status=incident.status,
        correlated_logs=_coerce_correlated_logs(incident.correlated_logs_json),
        causal_chain=_safe_json_load(incident.causal_chain_json, []),
        graph=_safe_json_load(incident.graph_json, None),
        timeline=_safe_json_load(incident.timeline_json, []),
        ai_root_cause=incident.ai_root_cause,
        ai_explanation=incident.ai_explanation,
        ai_fix=incident.ai_fix,
        ai_report=_coerce_ai_report(incident.ai_report_json),
        audit_trail=[
            schemas.IncidentAuditOut(
                action=audit.action,
                actor=audit.actor,
                created_at=audit.created_at,
                details=_safe_json_load(audit.details_json, {}),
            )
            for audit in audits
        ],
    )


@app.post("/api/logs", response_model=schemas.IngestResponse)
async def ingest_logs(request: Request, db: Session = Depends(database.get_db)):
    """
    Ingest a signed batch of logs.
    If NETRCA_HMAC_SECRET is configured, clients must send:
    - X-NetRCA-Timestamp
    - X-NetRCA-Signature: sha512=<digest>
    """
    body = await request.body()
    signature = request.headers.get("X-NetRCA-Signature")
    timestamp = request.headers.get("X-NetRCA-Timestamp")
    source_verified = verify_hmac_signature(body, timestamp, signature)

    if hmac_enforced() and not source_verified:
        raise HTTPException(status_code=401, detail="Invalid HMAC signature")

    try:
        logs = LOG_ITEM_ADAPTER.validate_json(body)
    except Exception as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    correlation_result = ingest_log_batch(db, logs, signature, source_verified)
    return schemas.IngestResponse(
        message=f"Successfully ingested {len(logs)} logs and ran correlation.",
        ingested=len(logs),
        incidents_created=correlation_result["created"],
        incidents_updated=correlation_result["updated"],
        source_verified=source_verified,
    )


@app.get("/api/incidents", response_model=list[schemas.IncidentOut])
def get_incidents(db: Session = Depends(database.get_db)):
    incidents = (
        db.query(models.Incident)
        .order_by(models.Incident.updated_at.desc())
        .all()
    )
    return [_serialize_incident(incident, db) for incident in incidents]


@app.post("/api/analyze/{incident_ref}", response_model=schemas.ActionResponse)
def analyze_incident(
    incident_ref: str,
    db: Session = Depends(database.get_db),
):
    incident = (
        db.query(models.Incident)
        .filter(models.Incident.incident_ref == incident_ref)
        .first()
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    incident.status = "pending"
    append_audit_entry(
        db,
        incident,
        action="ai_rca_requested",
        details={"incident_ref": incident.incident_ref},
        actor="operator",
    )
    db.commit()
    rca_queue.enqueue(incident.id)
    return schemas.ActionResponse(
        message="AI analysis task queued",
        incident=incident.incident_ref,
        status=incident.status,
    )


@app.post("/api/incidents/{incident_ref}/status", response_model=schemas.ActionResponse)
def update_incident_status(
    incident_ref: str,
    status: str,
    db: Session = Depends(database.get_db),
):
    incident = (
        db.query(models.Incident)
        .filter(models.Incident.incident_ref == incident_ref)
        .first()
    )
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    allowed_statuses = {"open", "pending", "analyzing", "completed", "resolved"}
    if status not in allowed_statuses:
        raise HTTPException(status_code=400, detail="Unsupported incident status")

    incident.status = status
    append_audit_entry(
        db,
        incident,
        action="status_changed",
        details={"status": status},
        actor="operator",
    )
    db.commit()
    return schemas.ActionResponse(
        message="Incident status updated",
        incident=incident.incident_ref,
        status=incident.status,
        queued=False,
    )


@app.get("/api/metrics", response_model=schemas.DashboardMetrics)
def get_metrics(db: Session = Depends(database.get_db)):
    logs = (
        db.query(models.LogEvent)
        .order_by(models.LogEvent.timestamp.desc())
        .limit(120)
        .all()
    )
    logs = list(reversed(logs))

    incidents = db.query(models.Incident).all()
    points: list[schemas.MetricsPoint] = []
    bucket_count = 8

    if logs:
        start_time = logs[0].timestamp
        end_time = logs[-1].timestamp
        min_span = datetime.timedelta(minutes=28)
        if end_time - start_time < min_span:
            start_time = end_time - min_span

        span_seconds = max((end_time - start_time).total_seconds(), 1)
        bucket_seconds = max(math.ceil(span_seconds / bucket_count), 1)
        buckets = [
            {"time": start_time + datetime.timedelta(seconds=index * bucket_seconds), "logs": []}
            for index in range(bucket_count)
        ]

        for log in logs:
            offset_seconds = (log.timestamp - start_time).total_seconds()
            bucket_index = min(bucket_count - 1, max(0, int(offset_seconds // bucket_seconds)))
            buckets[bucket_index]["logs"].append(log)

        for bucket in buckets:
            bucket_logs = bucket["logs"]
            alert_weight = sum(
                METRIC_SEVERITY_WEIGHTS.get(log.severity.lower(), 1)
                for log in bucket_logs
            )
            packets = len(bucket_logs) * 140
            alerts = alert_weight * 6
            load = min(100, 18 + alert_weight * 7) if bucket_logs else 8
            points.append(
                schemas.MetricsPoint(
                    time=bucket["time"].strftime("%H:%M"),
                    packets=packets,
                    alerts=alerts,
                    load=load,
                )
            )
    else:
        for index in range(bucket_count):
            points.append(
                schemas.MetricsPoint(time=f"00:{index * 4:02d}", packets=0, alerts=0, load=0)
            )

    open_incidents = [incident for incident in incidents if incident.status != "resolved"]
    critical_incidents = [
        incident for incident in open_incidents if incident.severity == "critical"
    ]
    risk_score = min(
        100,
        round(sum(incident.severity_score for incident in open_incidents) / 2) if open_incidents else 0,
    )

    return schemas.DashboardMetrics(
        risk_score=risk_score,
        active_alarms=len(open_incidents),
        critical_incidents=len(critical_incidents),
        ai_agent_status="Analyzing" if any(
            incident.status in {"pending", "analyzing"} for incident in open_incidents
        ) else "Monitoring",
        points=points,
    )


@app.get("/api/security/posture", response_model=schemas.SecurityPosture)
def get_security_posture():
    return schemas.SecurityPosture(
        encryption="AES-GCM for stored log payloads",
        integrity="SHA-512 hash per ingested log",
        authenticity="HMAC-SHA512 supported on ingestion requests",
        tls=tls_configuration(),
    )


@app.post("/api/seed", response_model=schemas.IngestResponse)
def seed_demo_data(scenario: str = "mixed", db: Session = Depends(database.get_db)):
    # Each seed run is randomized and preserved so operators can compare history.
    logs, normalized_scenario = build_demo_logs(scenario)
    correlation_result = ingest_log_batch(
        db,
        logs,
        signature=f"seeded-local-demo-{normalized_scenario}",
        source_verified=True,
    )

    created = correlation_result["created"]
    updated = correlation_result["updated"]
    return schemas.IngestResponse(
        message=(
            f"Seeded {normalized_scenario.replace('_', ' ')} demo with {len(logs)} logs. "
            f"Created {created} incidents and updated {updated} incidents while preserving prior history."
        ),
        ingested=len(logs),
        incidents_created=created,
        incidents_updated=updated,
        source_verified=True,
    )

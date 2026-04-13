import json
import datetime

import models
from schemas import LogItem
from services.correlation_service import process_logs_heuristic
from services.queue_service import rca_queue
from utils.crypto_utils import encrypt_log_data, sha512_hash


def _infer_defaults(item: LogItem) -> tuple[str | None, str | None, int | None]:
    if item.target or item.service or item.port:
        return item.target, item.service, item.port

    event_type = item.event_type.lower()
    if event_type in {"config_change", "auth_failure", "rule_update", "traffic_blocked"}:
        return "VPN Gateway", "vpn", 443
    if event_type in {"syn_flood", "latency_spike", "service_failure"}:
        return "Payment Gateway", "payments", 443
    return None, None, None


def ingest_logs(db, logs: list[LogItem], signature: str | None, source_verified: bool):
    for item in logs:
        target, service, port = _infer_defaults(item)
        db_log = models.LogEvent(
            timestamp=item.timestamp or datetime.datetime.utcnow(),
            source=item.source,
            event_type=item.event_type,
            raw_message=encrypt_log_data(item.raw_message),
            raw_message_hash=sha512_hash(item.raw_message),
            severity=item.severity,
            target=item.target or target,
            service=item.service or service,
            port=item.port or port,
            context_json=json.dumps(item.context),
            hmac_signature=signature,
            source_verified=source_verified,
        )
        db.add(db_log)

    db.commit()
    result = process_logs_heuristic(db)
    for incident_id in result["queued_incident_ids"]:
        rca_queue.enqueue(incident_id)
    return result

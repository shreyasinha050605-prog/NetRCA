import datetime
import json
from typing import Any

import models


def append_audit_entry(
    db,
    incident: models.Incident,
    action: str,
    details: dict[str, Any] | None = None,
    actor: str = "system",
) -> models.IncidentAudit:
    incident.updated_at = datetime.datetime.utcnow()
    audit_entry = models.IncidentAudit(
        incident_id=incident.id,
        action=action,
        actor=actor,
        details_json=json.dumps(details or {}),
    )
    db.add(audit_entry)
    return audit_entry

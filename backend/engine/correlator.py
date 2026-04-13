from sqlalchemy.orm import Session
import models
import json
import uuid

def process_logs_heuristic(db: Session):
    """
    Very simple heuristic correlation:
    Checks if there are recent logs that form a pattern.
    If a pattern is found, groups them into an Incident.
    """
    # Grab recent unprocessed logs (simplification for prototype: grab all)
    logs = db.query(models.LogEvent).order_by(models.LogEvent.timestamp.desc()).limit(50).all()
    
    # Check for misconfiguration pattern (Config change followed by failures)
    config_changes = [l for l in logs if l.event_type == 'config_change']
    auth_failures = [l for l in logs if l.event_type == 'auth_failure']
    
    if len(config_changes) >= 1 and len(auth_failures) >= 3:
        # Create an incident if one doesn't exist
        existing = db.query(models.Incident).filter(models.Incident.classification == "Misconfiguration Pattern").first()
        if not existing:
            inc = models.Incident(
                incident_ref=f"INC-{str(uuid.uuid4())[:6]}",
                classification="Misconfiguration Pattern",
                target="VPN Gateway",
                severity="high",
                correlated_logs_json=json.dumps([l.id for l in config_changes + auth_failures])
            )
            db.add(inc)

    # Check for DDoS pattern
    syn_floods = [l for l in logs if l.event_type == 'syn_flood']
    if len(syn_floods) >= 5:
        existing = db.query(models.Incident).filter(models.Incident.classification == "Volumetric Attack").first()
        if not existing:
            inc = models.Incident(
                incident_ref=f"INC-{str(uuid.uuid4())[:6]}",
                classification="Volumetric Attack",
                target="Payment Gateway",
                severity="critical",
                correlated_logs_json=json.dumps([l.id for l in syn_floods])
            )
            db.add(inc)

    db.commit()

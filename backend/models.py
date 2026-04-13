import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text

from database import Base


class LogEvent(Base):
    __tablename__ = "log_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    source = Column(String, index=True, nullable=False)
    event_type = Column(String, index=True, nullable=False)
    raw_message = Column(Text, nullable=False)
    raw_message_hash = Column(String, index=True, nullable=True)
    severity = Column(String, index=True, nullable=False)
    target = Column(String, index=True, nullable=True)
    service = Column(String, index=True, nullable=True)
    port = Column(Integer, nullable=True)
    context_json = Column(Text, nullable=True)
    hmac_signature = Column(Text, nullable=True)
    source_verified = Column(Boolean, default=False, nullable=False)


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    incident_ref = Column(String, unique=True, index=True, nullable=False)
    detected_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)
    updated_at = Column(
        DateTime,
        default=datetime.datetime.utcnow,
        nullable=False,
        index=True,
    )
    classification = Column(String, index=True, nullable=False)
    target = Column(String, index=True, nullable=False)
    service = Column(String, index=True, nullable=True)
    port = Column(Integer, nullable=True)
    severity = Column(String, index=True, nullable=False)
    severity_score = Column(Float, default=0, nullable=False)
    status = Column(String, default="open", index=True, nullable=False)
    correlated_logs_json = Column(Text, nullable=False)
    causal_chain_json = Column(Text, nullable=True)
    graph_json = Column(Text, nullable=True)
    root_cause_nodes_json = Column(Text, nullable=True)
    impact_nodes_json = Column(Text, nullable=True)
    failure_nodes_json = Column(Text, nullable=True)
    path_traces_json = Column(Text, nullable=True)
    timeline_json = Column(Text, nullable=True)
    ai_root_cause = Column(String, nullable=True)
    ai_explanation = Column(Text, nullable=True)
    ai_fix = Column(Text, nullable=True)
    ai_report_json = Column(Text, nullable=True)
    last_analyzed_at = Column(DateTime, nullable=True)


class IncidentAudit(Base):
    __tablename__ = "incident_audits"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(
        Integer,
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    action = Column(String, nullable=False)
    actor = Column(String, default="system", nullable=False)
    details_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

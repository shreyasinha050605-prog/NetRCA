import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class LogItem(BaseModel):
    timestamp: datetime.datetime | None = None
    source: str
    event_type: str
    raw_message: str
    severity: str
    target: str | None = None
    service: str | None = None
    port: int | None = None
    context: dict[str, Any] = Field(default_factory=dict)


class CorrelatedLogOut(BaseModel):
    id: int
    timestamp: datetime.datetime
    source: str
    event_type: str
    severity: str
    target: str | None = None
    service: str | None = None
    port: int | None = None
    raw_message: str
    integrity_hash: str | None = None
    source_verified: bool = False
    context: dict[str, Any] = Field(default_factory=dict)


class TimelineStep(BaseModel):
    timestamp: datetime.datetime
    event_type: str
    source: str
    observation: str


class GraphNode(BaseModel):
    id: str
    label: str
    event_type: str
    source: str
    timestamp: datetime.datetime
    severity: str
    target: str | None = None
    service: str | None = None
    port: int | None = None
    is_root_cause: bool = False
    is_failure: bool = False
    impact_score: int = 0


class GraphEdge(BaseModel):
    source: str
    target: str
    relationship: str
    weight: float = 1.0


class CausalGraph(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    root_cause_nodes: list[str] = Field(default_factory=list)
    impact_nodes: list[str] = Field(default_factory=list)
    failure_nodes: list[str] = Field(default_factory=list)
    path_traces: list[list[str]] = Field(default_factory=list)
    is_dag: bool = True


class ReasoningStep(BaseModel):
    phase: str
    detail: str


class AIReport(BaseModel):
    root_cause: str
    executive_summary: str
    what_changed: str
    why_it_happened: str
    attack_or_misconfig: str
    security_risk_level: str
    timeline: list[TimelineStep] = Field(default_factory=list)
    affected_components: list[str] = Field(default_factory=list)
    security_impact: list[str] = Field(default_factory=list)
    remediation: str
    remediation_steps: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    reasoning: str
    reasoning_steps: list[ReasoningStep] = Field(default_factory=list)


class IncidentAuditOut(BaseModel):
    action: str
    actor: str
    created_at: datetime.datetime
    details: dict[str, Any] = Field(default_factory=dict)


class IncidentOut(BaseModel):
    incident_ref: str
    detected_at: datetime.datetime
    updated_at: datetime.datetime
    classification: str
    target: str
    service: str | None = None
    port: int | None = None
    severity: str
    severity_score: float
    status: str
    correlated_logs: list[CorrelatedLogOut] = Field(default_factory=list)
    causal_chain: list[str] = Field(default_factory=list)
    graph: CausalGraph | None = None
    timeline: list[TimelineStep] = Field(default_factory=list)
    ai_root_cause: str | None = None
    ai_explanation: str | None = None
    ai_fix: str | None = None
    ai_report: AIReport | None = None
    audit_trail: list[IncidentAuditOut] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


class MetricsPoint(BaseModel):
    time: str
    packets: int
    alerts: int
    load: int


class DashboardMetrics(BaseModel):
    risk_score: int
    active_alarms: int
    critical_incidents: int
    ai_agent_status: str
    points: list[MetricsPoint]


class IngestResponse(BaseModel):
    message: str
    ingested: int
    incidents_created: int
    incidents_updated: int
    source_verified: bool


class ActionResponse(BaseModel):
    message: str
    incident: str
    status: str
    queued: bool = True


class SecurityPosture(BaseModel):
    encryption: str
    integrity: str
    authenticity: str
    tls: dict[str, Any]

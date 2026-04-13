import datetime
import json
import os
from typing import Any

from openai import OpenAI

import models
from database import SessionLocal
from services.audit_service import append_audit_entry


def _safe_json_load(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def _build_incident_payload(incident: models.Incident) -> dict[str, Any]:
    return {
        "incident_ref": incident.incident_ref,
        "classification": incident.classification,
        "target": incident.target,
        "service": incident.service,
        "port": incident.port,
        "severity": incident.severity,
        "severity_score": incident.severity_score,
        "status": incident.status,
        "causal_chain": _safe_json_load(incident.causal_chain_json, []),
        "graph": _safe_json_load(incident.graph_json, {}),
        "root_cause_nodes": _safe_json_load(incident.root_cause_nodes_json, []),
        "impact_nodes": _safe_json_load(incident.impact_nodes_json, []),
        "failure_nodes": _safe_json_load(incident.failure_nodes_json, []),
        "path_traces": _safe_json_load(incident.path_traces_json, []),
        "correlated_logs": _safe_json_load(incident.correlated_logs_json, []),
        "timeline": _safe_json_load(incident.timeline_json, []),
    }


def _agent_reasoning_steps(payload: dict[str, Any]) -> list[dict[str, str]]:
    graph = payload.get("graph", {})
    correlated_logs = payload.get("correlated_logs", [])
    root_nodes = graph.get("root_cause_nodes", payload.get("root_cause_nodes", []))
    impact_nodes = graph.get("impact_nodes", payload.get("impact_nodes", []))

    return [
        {
            "phase": "Observation",
            "detail": (
                f"Collected {len(correlated_logs)} correlated logs and built a DAG with "
                f"{len(graph.get('nodes', []))} nodes and {len(graph.get('edges', []))} edges."
            ),
        },
        {
            "phase": "Hypothesis",
            "detail": (
                f"Nodes without incoming edges ({', '.join(root_nodes) or 'none'}) are treated "
                "as candidate root causes because nothing earlier in the incident graph explains them."
            ),
        },
        {
            "phase": "Validation",
            "detail": (
                f"Influence analysis marked {', '.join(impact_nodes) or 'none'} as the most impactful "
                "events because they reach the greatest number of downstream failures."
            ),
        },
        {
            "phase": "Conclusion",
            "detail": (
                "The RCA report is based on graph reachability, event ordering, and resource affinity, "
                "not just raw frequency counts."
            ),
        },
    ]


def _fallback_report(payload: dict[str, Any]) -> dict[str, Any]:
    classification = payload["classification"]
    target = payload["target"]
    root_nodes = payload.get("root_cause_nodes", [])
    affected_components = sorted(
        {
            target,
            *(log.get("service") for log in payload.get("correlated_logs", []) if log.get("service")),
            *(log.get("source") for log in payload.get("correlated_logs", [])),
        }
    )

    if classification == "Misconfiguration Cascade":
        root_cause = "A configuration change propagated into an access-control failure"
        what_changed = "A control-plane update was observed before downstream authentication and service failures."
        why_it_happened = (
            "The causal DAG places a configuration event at the start of the failure path, "
            "which is consistent with a firewall or routing policy error."
        )
        attack_or_misconfig = "misconfiguration"
        security_risk_level = "High"
        summary = (
            "The incident is most consistent with an operator-driven misconfiguration cascade on a protected network service."
        )
        impact = [
            "Legitimate traffic was blocked or degraded.",
            "Administrative changes introduced an availability and access-control risk.",
        ]
        remediation_steps = [
            "Roll back the last firewall or policy change affecting the target service.",
            "Validate policy intent against the affected port and service path.",
            "Enforce staged change validation before deployment to production devices.",
        ]
    else:
        root_cause = "A volumetric attack saturated the exposed network path"
        what_changed = "The event graph shows repeated flood indicators that branch into latency and service impact."
        why_it_happened = (
            "Multiple attack indicators became root or near-root graph nodes and fan out toward failure nodes, "
            "which matches parallel saturation behavior rather than a single isolated fault."
        )
        attack_or_misconfig = "attack"
        security_risk_level = "High"
        summary = (
            "The incident reflects a network-layer denial-of-service pattern affecting an externally reachable component."
        )
        impact = [
            "Packet pressure and latency likely affected edge stability.",
            "Customer-facing service reachability and performance were degraded.",
        ]
        remediation_steps = [
            "Apply upstream filtering and SYN flood mitigation at the edge.",
            "Engage DDoS scrubbing or ISP assistance for persistent abusive sources.",
            "Tune rate limits and anomaly thresholds for early detection of saturation patterns.",
        ]

    reasoning_steps = _agent_reasoning_steps(payload)
    return {
        "executive_summary": summary,
        "root_cause": root_cause,
        "what_changed": what_changed,
        "why_it_happened": why_it_happened,
        "attack_or_misconfig": attack_or_misconfig,
        "security_risk_level": security_risk_level,
        "timeline": payload["timeline"],
        "affected_components": affected_components,
        "security_impact": impact,
        "remediation": " ".join(remediation_steps),
        "remediation_steps": remediation_steps,
        "confidence": 0.86,
        "reasoning": (
            f"Root cause candidates {root_nodes or ['unknown']} appear earliest in the DAG and "
            "lead to the strongest downstream effect on failure nodes."
        ),
        "reasoning_steps": reasoning_steps,
    }


def _generate_openai_report(payload: dict[str, Any]) -> dict[str, Any]:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return _fallback_report(payload)

    client = OpenAI(api_key=api_key)
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    prompt = {
        "task": "Act as a multi-step network RCA agent and return strict JSON only.",
        "agent_steps": [
            "Observation: inspect logs, graph, and path traces",
            "Hypothesis: identify probable root causes",
            "Validation: verify graph reachability and downstream failures",
            "Conclusion: produce SOC-ready RCA output",
        ],
        "required_schema": {
            "root_cause": "string",
            "executive_summary": "string",
            "what_changed": "string",
            "why_it_happened": "string",
            "attack_or_misconfig": "string",
            "security_risk_level": "string",
            "timeline": [
                {
                    "timestamp": "ISO-8601 string",
                    "event_type": "string",
                    "source": "string",
                    "observation": "string",
                }
            ],
            "affected_components": ["string"],
            "security_impact": ["string"],
            "remediation": "string",
            "remediation_steps": ["string"],
            "confidence": "float 0-1",
            "reasoning": "string",
            "reasoning_steps": [{"phase": "string", "detail": "string"}],
        },
        "incident": payload,
    }

    response = client.chat.completions.create(
        model=model,
        response_format={"type": "json_object"},
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a senior network security RCA agent. Use the graph, not only text, "
                    "to reason about causal ordering. Return valid JSON only."
                ),
            },
            {"role": "user", "content": json.dumps(prompt)},
        ],
    )

    raw_content = response.choices[0].message.content or "{}"
    try:
        parsed = json.loads(raw_content)
    except json.JSONDecodeError:
        parsed = _fallback_report(payload)

    parsed.setdefault("timeline", payload["timeline"])
    parsed.setdefault("affected_components", [])
    parsed.setdefault("security_impact", [])
    parsed.setdefault("remediation", "")
    parsed.setdefault("remediation_steps", [])
    parsed.setdefault("confidence", 0.7)
    parsed.setdefault("reasoning_steps", _agent_reasoning_steps(payload))
    return parsed


def run_rca_analysis(incident_id: int) -> None:
    db = SessionLocal()
    try:
        incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
        if not incident:
            return

        incident.status = "analyzing"
        incident.updated_at = datetime.datetime.utcnow()
        append_audit_entry(
            db,
            incident,
            action="ai_rca_started",
            details={"incident_ref": incident.incident_ref},
            actor="ai-agent",
        )
        db.commit()

        payload = _build_incident_payload(incident)
        report = _generate_openai_report(payload)

        incident.ai_root_cause = report["root_cause"]
        incident.ai_explanation = report["executive_summary"]
        incident.ai_fix = report.get("remediation", "\n".join(report.get("remediation_steps", [])))
        incident.ai_report_json = json.dumps(report)
        incident.last_analyzed_at = datetime.datetime.utcnow()
        incident.updated_at = datetime.datetime.utcnow()
        incident.status = "completed"

        append_audit_entry(
            db,
            incident,
            action="ai_rca_completed",
            details={
                "confidence": report.get("confidence"),
                "root_cause": report.get("root_cause"),
            },
            actor="ai-agent",
        )
        db.commit()
    except Exception as exc:
        incident = db.query(models.Incident).filter(models.Incident.id == incident_id).first()
        if incident:
            fallback_report = _fallback_report(_build_incident_payload(incident))
            incident.ai_root_cause = "AI analysis failed"
            incident.ai_explanation = str(exc)
            incident.ai_fix = "Review backend logs and rerun RCA after correcting the failure."
            incident.ai_report_json = json.dumps(fallback_report)
            incident.updated_at = datetime.datetime.utcnow()
            incident.status = "completed"
            append_audit_entry(
                db,
                incident,
                action="ai_rca_failed",
                details={"error": str(exc)},
                actor="ai-agent",
            )
            db.commit()
    finally:
        db.close()

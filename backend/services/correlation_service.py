import datetime
import json
import uuid
from collections import defaultdict
from typing import Any

import networkx as nx

import models
from services.audit_service import append_audit_entry
from utils.crypto_utils import decrypt_log_data

WINDOW_MINUTES = 5

SEVERITY_WEIGHTS = {
    "info": 1,
    "warning": 2,
    "error": 3,
    "high": 4,
    "critical": 5,
}

EVENT_RELATIONSHIPS = {
    "config_change": {"rule_update", "traffic_blocked", "auth_failure", "service_failure"},
    "rule_update": {"traffic_blocked", "service_failure"},
    "traffic_blocked": {"service_failure", "auth_failure"},
    "syn_flood": {"latency_spike", "traffic_saturation", "service_failure"},
    "traffic_saturation": {"latency_spike", "service_failure"},
    "latency_spike": {"service_failure"},
    "auth_failure": {"service_failure"},
}

FAILURE_EVENT_TYPES = {"service_failure", "auth_failure", "traffic_blocked", "latency_spike"}


def _safe_json_load(value: str | None, default: Any) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def _infer_resource(log: models.LogEvent) -> tuple[str, str | None, int | None]:
    if log.target:
        return log.target, log.service, log.port

    event_type = log.event_type.lower()
    if event_type in {"config_change", "auth_failure", "rule_update", "traffic_blocked"}:
        return "VPN Gateway", log.service or "vpn", log.port or 443
    if event_type in {"syn_flood", "service_failure", "latency_spike", "traffic_saturation"}:
        return "Payment Gateway", log.service or "payments", log.port or 443
    return log.source, log.service, log.port


def _serialize_log(log: models.LogEvent) -> dict[str, Any]:
    target, service, port = _infer_resource(log)
    return {
        "id": log.id,
        "timestamp": log.timestamp.isoformat(),
        "source": log.source,
        "event_type": log.event_type,
        "severity": log.severity,
        "target": target,
        "service": service,
        "port": port,
        "raw_message": decrypt_log_data(log.raw_message),
        "integrity_hash": log.raw_message_hash,
        "source_verified": bool(log.source_verified),
        "context": _safe_json_load(log.context_json, {}),
    }


def _split_by_time_window(logs: list[models.LogEvent]) -> list[list[models.LogEvent]]:
    if not logs:
        return []

    groups: list[list[models.LogEvent]] = []
    current_group = [logs[0]]

    for previous, current in zip(logs, logs[1:]):
        gap = current.timestamp - previous.timestamp
        if gap <= datetime.timedelta(minutes=WINDOW_MINUTES):
            current_group.append(current)
        else:
            groups.append(current_group)
            current_group = [current]

    groups.append(current_group)
    return groups


def _build_groups(logs: list[models.LogEvent]) -> list[list[models.LogEvent]]:
    grouped: dict[tuple[str, str | None, int | None], list[models.LogEvent]] = defaultdict(list)
    for log in logs:
        grouped[_infer_resource(log)].append(log)

    windows: list[list[models.LogEvent]] = []
    for resource_logs in grouped.values():
        ordered_logs = sorted(resource_logs, key=lambda item: item.timestamp)
        windows.extend(_split_by_time_window(ordered_logs))
    return windows


def _severity_score(group: list[models.LogEvent], classification: str) -> tuple[str, float]:
    base = sum(SEVERITY_WEIGHTS.get(log.severity.lower(), 1) for log in group)
    if classification == "Volumetric Attack":
        base += 6
    if any(log.event_type in FAILURE_EVENT_TYPES for log in group):
        base += 3
    score = min(100.0, round(base * 4.5, 1))

    if score >= 80:
        severity = "critical"
    elif score >= 55:
        severity = "high"
    elif score >= 30:
        severity = "warning"
    else:
        severity = "info"

    return severity, score


def _timeline_entry(log: models.LogEvent) -> dict[str, Any]:
    return {
        "timestamp": log.timestamp.isoformat(),
        "event_type": log.event_type,
        "source": log.source,
        "observation": decrypt_log_data(log.raw_message),
    }


def _relationship_between(first: models.LogEvent, second: models.LogEvent) -> tuple[str, float] | None:
    allowed_targets = EVENT_RELATIONSHIPS.get(first.event_type, set())
    if second.event_type in allowed_targets:
        return "event_pattern", 1.0
    if first.source == second.source:
        return "same_device", 0.7
    if _infer_resource(first) == _infer_resource(second):
        return "shared_resource", 0.6
    return None


def _build_causal_graph(group: list[models.LogEvent]) -> dict[str, Any]:
    graph = nx.DiGraph()
    ordered_logs = sorted(group, key=lambda item: item.timestamp)

    for log in ordered_logs:
        node_id = f"log-{log.id}"
        target, service, port = _infer_resource(log)
        graph.add_node(
            node_id,
            id=node_id,
            label=f"{log.event_type} @ {log.source}",
            event_type=log.event_type,
            source=log.source,
            timestamp=log.timestamp.isoformat(),
            severity=log.severity,
            target=target,
            service=service,
            port=port,
        )

    for index, current in enumerate(ordered_logs):
        current_id = f"log-{current.id}"
        best_candidates: dict[str, tuple[models.LogEvent, str, float]] = {}

        for candidate in ordered_logs[index + 1:]:
            if candidate.timestamp - current.timestamp > datetime.timedelta(minutes=WINDOW_MINUTES):
                break

            relation = _relationship_between(current, candidate)
            if not relation:
                continue

            relationship, weight = relation
            existing = best_candidates.get(relationship)
            if existing is None or candidate.timestamp < existing[0].timestamp:
                best_candidates[relationship] = (candidate, relationship, weight)

        for candidate, relationship, weight in sorted(
            best_candidates.values(),
            key=lambda item: item[0].timestamp,
        )[:2]:
            candidate_id = f"log-{candidate.id}"
            graph.add_edge(
                current_id,
                candidate_id,
                relationship=relationship,
                weight=weight,
            )

    if not nx.is_directed_acyclic_graph(graph):
        # Edges always point forward in time, so cycles are unlikely.
        # This fallback removes any accidental back edges if malformed data appears.
        while not nx.is_directed_acyclic_graph(graph):
            edge_to_remove = next(iter(nx.find_cycle(graph)))
            graph.remove_edge(edge_to_remove[0], edge_to_remove[1])

    root_cause_nodes = [node for node in graph.nodes if graph.in_degree(node) == 0]
    failure_nodes = [
        node
        for node, attrs in graph.nodes(data=True)
        if attrs["event_type"] in FAILURE_EVENT_TYPES or graph.out_degree(node) == 0
    ]
    impact_nodes = sorted(
        graph.nodes,
        key=lambda node: len(nx.descendants(graph, node)),
        reverse=True,
    )[: max(1, min(3, len(graph.nodes)))]

    path_traces: list[list[str]] = []
    for root_node in root_cause_nodes:
        for failure_node in failure_nodes:
            if root_node == failure_node:
                continue
            for path in nx.all_simple_paths(graph, root_node, failure_node):
                path_traces.append(path)

    nodes_payload = []
    for node_id, attrs in graph.nodes(data=True):
        nodes_payload.append(
            {
                **attrs,
                "is_root_cause": node_id in root_cause_nodes,
                "is_failure": node_id in failure_nodes,
                "impact_score": len(nx.descendants(graph, node_id)),
            }
        )

    edges_payload = []
    for source, target, attrs in graph.edges(data=True):
        edges_payload.append(
            {
                "source": source,
                "target": target,
                "relationship": attrs["relationship"],
                "weight": attrs["weight"],
            }
        )

    return {
        "nodes": nodes_payload,
        "edges": edges_payload,
        "root_cause_nodes": root_cause_nodes,
        "impact_nodes": impact_nodes,
        "failure_nodes": failure_nodes,
        "path_traces": path_traces,
        "is_dag": nx.is_directed_acyclic_graph(graph),
    }


def _detect_incident(group: list[models.LogEvent]) -> dict[str, Any] | None:
    event_types = [log.event_type for log in group]
    target, service, port = _infer_resource(group[0])

    if "config_change" in event_types and event_types.count("auth_failure") >= 2:
        classification = "Misconfiguration Cascade"
        causal_chain = [
            "config_change",
            "rule_update",
            "traffic_blocked",
            "service_failure",
        ]
    elif event_types.count("syn_flood") >= 3:
        classification = "Volumetric Attack"
        causal_chain = [
            "syn_flood",
            "traffic_saturation",
            "latency_spike",
            "service_failure",
        ]
    elif "traffic_blocked" in event_types and "service_failure" in event_types:
        classification = "Network Path Disruption"
        causal_chain = [
            "traffic_blocked",
            "service_failure",
        ]
    else:
        return None

    severity, severity_score = _severity_score(group, classification)
    correlated_logs = [_serialize_log(log) for log in group]
    timeline = [_timeline_entry(log) for log in sorted(group, key=lambda item: item.timestamp)]
    graph = _build_causal_graph(group)

    return {
        "classification": classification,
        "target": target,
        "service": service,
        "port": port,
        "severity": severity,
        "severity_score": severity_score,
        "correlated_logs": correlated_logs,
        "timeline": timeline,
        "causal_chain": causal_chain,
        "graph": graph,
    }


def _merge_unique_logs(
    existing: list[dict[str, Any]],
    incoming: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    merged = {entry["id"]: entry for entry in existing}
    for entry in incoming:
        merged[entry["id"]] = entry
    return sorted(merged.values(), key=lambda item: item["timestamp"])


def _extract_demo_run_id_from_logs(logs: list[dict[str, Any]]) -> str | None:
    for entry in logs:
        context = entry.get("context") or {}
        demo_run_id = context.get("demo_run_id")
        if demo_run_id:
            return str(demo_run_id)
    return None


def _group_demo_run_id(group: list[models.LogEvent]) -> str | None:
    for log in group:
        context = _safe_json_load(log.context_json, {})
        demo_run_id = context.get("demo_run_id")
        if demo_run_id:
            return str(demo_run_id)
    return None


def _get_open_incident(
    db,
    classification: str,
    target: str,
    service: str | None,
    demo_run_id: str | None,
):
    candidates = (
        db.query(models.Incident)
        .filter(models.Incident.classification == classification)
        .filter(models.Incident.target == target)
        .filter(models.Incident.service == service)
        .filter(models.Incident.status != "resolved")
        .order_by(models.Incident.updated_at.desc())
        .all()
    )

    if demo_run_id:
        for incident in candidates:
            existing_logs = _safe_json_load(incident.correlated_logs_json, [])
            if _extract_demo_run_id_from_logs(existing_logs) == demo_run_id:
                return incident
        return None

    return candidates[0] if candidates else None


def _build_incident_ref(prefix: str = "INC") -> str:
    return f"{prefix}-{str(uuid.uuid4())[:8].upper()}"


def process_logs_heuristic(db) -> dict[str, Any]:
    """
    Build resource-aware correlation windows, then convert them into a directed
    causal graph where nodes are events and edges are hypothesized cause/effect links.
    """
    recent_logs = (
        db.query(models.LogEvent)
        .order_by(models.LogEvent.timestamp.desc())
        .limit(200)
        .all()
    )
    recent_logs = list(reversed(recent_logs))

    created_count = 0
    updated_count = 0
    queued_incident_ids: list[int] = []

    for group in _build_groups(recent_logs):
        incident_candidate = _detect_incident(group)
        if not incident_candidate:
            continue
        demo_run_id = _group_demo_run_id(group)

        incident = _get_open_incident(
            db,
            incident_candidate["classification"],
            incident_candidate["target"],
            incident_candidate["service"],
            demo_run_id,
        )

        graph_json = json.dumps(incident_candidate["graph"])
        if incident:
            existing_logs = _safe_json_load(incident.correlated_logs_json, [])
            merged_logs = _merge_unique_logs(existing_logs, incident_candidate["correlated_logs"])
            incident.correlated_logs_json = json.dumps(merged_logs)
            incident.timeline_json = json.dumps(incident_candidate["timeline"])
            incident.causal_chain_json = json.dumps(incident_candidate["causal_chain"])
            incident.graph_json = graph_json
            incident.root_cause_nodes_json = json.dumps(incident_candidate["graph"]["root_cause_nodes"])
            incident.impact_nodes_json = json.dumps(incident_candidate["graph"]["impact_nodes"])
            incident.failure_nodes_json = json.dumps(incident_candidate["graph"]["failure_nodes"])
            incident.path_traces_json = json.dumps(incident_candidate["graph"]["path_traces"])
            incident.severity = incident_candidate["severity"]
            incident.severity_score = incident_candidate["severity_score"]
            incident.updated_at = datetime.datetime.utcnow()
            append_audit_entry(
                db,
                incident,
                action="correlation_updated",
                details={
                    "new_log_count": len(incident_candidate["correlated_logs"]),
                    "root_cause_nodes": incident_candidate["graph"]["root_cause_nodes"],
                    "impact_nodes": incident_candidate["graph"]["impact_nodes"],
                },
            )
            updated_count += 1
        else:
            incident = models.Incident(
                incident_ref=_build_incident_ref("DEMO" if demo_run_id else "INC"),
                classification=incident_candidate["classification"],
                target=incident_candidate["target"],
                service=incident_candidate["service"],
                port=incident_candidate["port"],
                severity=incident_candidate["severity"],
                severity_score=incident_candidate["severity_score"],
                status="pending",
                correlated_logs_json=json.dumps(incident_candidate["correlated_logs"]),
                causal_chain_json=json.dumps(incident_candidate["causal_chain"]),
                graph_json=graph_json,
                root_cause_nodes_json=json.dumps(incident_candidate["graph"]["root_cause_nodes"]),
                impact_nodes_json=json.dumps(incident_candidate["graph"]["impact_nodes"]),
                failure_nodes_json=json.dumps(incident_candidate["graph"]["failure_nodes"]),
                path_traces_json=json.dumps(incident_candidate["graph"]["path_traces"]),
                timeline_json=json.dumps(incident_candidate["timeline"]),
            )
            db.add(incident)
            db.flush()
            append_audit_entry(
                db,
                incident,
                action="incident_created",
                details={
                    "classification": incident.classification,
                    "severity_score": incident.severity_score,
                    "target": incident.target,
                    "graph_root_causes": incident_candidate["graph"]["root_cause_nodes"],
                },
            )
            queued_incident_ids.append(incident.id)
            created_count += 1

    db.commit()
    return {"created": created_count, "updated": updated_count, "queued_incident_ids": queued_incident_ids}

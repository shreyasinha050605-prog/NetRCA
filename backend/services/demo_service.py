import datetime
import random
import uuid

from schemas import LogItem

USERS = ["alice", "bob", "charlie", "diana", "eva", "mario", "nina"]
VPN_DEVICES = ["VPN-GW", "VPN-EDGE-2", "FW-RTR-01"]
EDGE_DEVICES = ["IDS-CORE", "EDGE-FW-01", "RTR-PEERING-2"]
PAYMENT_TARGETS = ["Payment Gateway", "Checkout API", "Edge LB"]
ROUTING_TARGETS = ["Core Router", "Transit Edge", "MPLS Gateway"]
VPN_TARGETS = ["VPN Gateway", "Remote Access Hub", "Zero Trust Gateway"]
ROUTING_DEVICES = ["RTR-CORE-1", "RTR-CORE-2", "TRANSIT-SW-1", "PEER-RTR-7"]
SERVICE_FAILURE_PHRASES = [
    "breached latency threshold after policy rollout",
    "started rejecting healthy sessions after a control change",
    "degraded sharply while recovery automation attempted reroutes",
]


def _recent_timestamp(offset_seconds: int) -> datetime.datetime:
    return datetime.datetime.utcnow() - datetime.timedelta(seconds=offset_seconds)


def _with_demo_context(logs: list[LogItem], scenario: str, variant: str, run_id: str) -> list[LogItem]:
    enriched_logs: list[LogItem] = []
    for index, log in enumerate(logs, start=1):
        enriched_logs.append(
            log.model_copy(
                update={
                    "context": {
                        **log.context,
                        "demo_run_id": run_id,
                        "demo_scenario": scenario,
                        "demo_variant": variant,
                        "sequence": index,
                    }
                }
            )
        )
    return enriched_logs


def _misconfig_scenario() -> tuple[list[LogItem], str]:
    username = random.choice(USERS)
    rule_id = random.randint(12, 88)
    port = random.choice([443, 8443, 1194])
    device = random.choice(VPN_DEVICES)
    target = random.choice(VPN_TARGETS)
    service = random.choice(["vpn", "remote-access", "ztna"])
    variant = random.choice(["policy_drift", "staged_rollout", "expired_exception"])
    auth_users = random.sample(USERS, k=2)
    failure_phrase = random.choice(SERVICE_FAILURE_PHRASES)

    return [
        LogItem(
            timestamp=_recent_timestamp(180),
            source="ADMIN-UI",
            event_type="config_change",
            raw_message=f"User {username} modified fw-rule-{rule_id} for port {port} during {variant}",
            severity="info",
            target=target,
            service=service,
            port=port,
            context={
                "change_ticket": f"CHG-{random.randint(3000, 9999)}",
                "change_window": random.choice(["nightly", "emergency", "regional"]),
            },
        ),
        LogItem(
            timestamp=_recent_timestamp(130),
            source=device,
            event_type="traffic_blocked",
            raw_message=f"Firewall policy denied new inbound sessions on port {port} after {variant}",
            severity="high",
            target=target,
            service=service,
            port=port,
        ),
        LogItem(
            timestamp=_recent_timestamp(95),
            source=device,
            event_type="auth_failure",
            raw_message=f"Connection timeout for user {auth_users[0]}",
            severity="error",
            target=target,
            service=service,
            port=port,
        ),
        LogItem(
            timestamp=_recent_timestamp(60),
            source=device,
            event_type="auth_failure",
            raw_message=f"TLS negotiation failed for user {auth_users[1]}",
            severity="error",
            target=target,
            service=service,
            port=port,
        ),
        LogItem(
            timestamp=_recent_timestamp(25),
            source="SYS-MON",
            event_type="service_failure",
            raw_message=f"{target} login service {failure_phrase}",
            severity="high",
            target=target,
            service=service,
            port=port,
        ),
    ], variant


def _ddos_scenario() -> tuple[list[LogItem], str]:
    target = random.choice(PAYMENT_TARGETS)
    service = random.choice(["payments", "checkout", "public-api"])
    port = random.choice([443, 8443, 9443])
    source_device = random.choice(EDGE_DEVICES)
    variant = random.choice(["botnet_surge", "spoofed_syn", "regional_burst"])
    syn_count = random.randint(4, 7)

    logs = []
    for offset in sorted(random.sample(range(70, 240), k=syn_count), reverse=True):
        logs.append(
            LogItem(
                timestamp=_recent_timestamp(offset),
                source=source_device,
                event_type="syn_flood",
                raw_message=f"SYN surge detected from ASN{random.randint(1200, 9800)} towards {target} during {variant}",
                severity="critical",
                target=target,
                service=service,
                port=port,
                context={"pps_estimate": random.randint(120000, 900000)},
            )
        )

    logs.extend(
        [
            LogItem(
                timestamp=_recent_timestamp(55),
                source="EDGE-LB",
                event_type="latency_spike",
                raw_message=f"Response latency exceeded {random.randint(2500, 6000)} ms on {service}",
                severity="high",
                target=target,
                service=service,
                port=port,
            ),
            LogItem(
                timestamp=_recent_timestamp(20),
                source="APP-MON",
                event_type="service_failure",
                raw_message=f"{target} returned sustained 503 errors during {variant}",
                severity="critical",
                target=target,
                service=service,
                port=port,
            ),
        ]
    )
    return logs, variant


def _routing_failure_scenario() -> tuple[list[LogItem], str]:
    target = random.choice(ROUTING_TARGETS)
    port = random.choice([179, 443, 22])
    device = random.choice(ROUTING_DEVICES)
    variant = random.choice(["bgp_policy_drift", "peer_flap", "transit_filter_mismatch"])
    tertiary_source = random.choice(["NETFLOW", "NOC-ALERT", "PATH-MON"])

    logs = [
        LogItem(
            timestamp=_recent_timestamp(160),
            source=device,
            event_type="config_change",
            raw_message=f"Routing policy updated for peer group on port {port} during {variant}",
            severity="info",
            target=target,
            service="routing",
            port=port,
        ),
        LogItem(
            timestamp=_recent_timestamp(120),
            source=device,
            event_type="traffic_blocked",
            raw_message=f"BGP adjacency traffic dropped after {variant}",
            severity="high",
            target=target,
            service="routing",
            port=port,
        ),
        LogItem(
            timestamp=_recent_timestamp(85),
            source=tertiary_source,
            event_type="service_failure",
            raw_message="Upstream route convergence failed; packet loss rising on transit path",
            severity="high",
            target=target,
            service="routing",
            port=port,
        ),
    ]

    if random.random() > 0.45:
        logs.insert(
            2,
            LogItem(
                timestamp=_recent_timestamp(102),
                source=random.choice(["PEER-MON", "BGP-MON", device]),
                event_type="traffic_blocked",
                raw_message="Policy filter rejected a subset of routed prefixes during convergence",
                severity="error",
                target=target,
                service="routing",
                port=port,
            ),
        )

    return logs, variant


def build_demo_logs(scenario: str) -> tuple[list[LogItem], str]:
    normalized = (scenario or "mixed").strip().lower()
    scenario_builders = {
        "mixed": lambda: random.sample(
            [_misconfig_scenario, _ddos_scenario, _routing_failure_scenario],
            k=random.randint(2, 3),
        ),
        "firewall_misconfig": _misconfig_scenario,
        "ddos_attack": _ddos_scenario,
        "routing_failure": _routing_failure_scenario,
    }

    if normalized not in scenario_builders:
        normalized = "mixed"

    run_id = f"DEMO-{uuid.uuid4().hex[:10].upper()}"

    if normalized == "mixed":
        builders = scenario_builders[normalized]()
        logs: list[LogItem] = []
        variants: list[str] = []
        for builder in builders:
            scenario_logs, variant = builder()
            logs.extend(scenario_logs)
            variants.append(variant)
        random.shuffle(logs)
        return _with_demo_context(logs, normalized, "+".join(variants), run_id), normalized

    logs, variant = scenario_builders[normalized]()
    return _with_demo_context(logs, normalized, variant, run_id), normalized

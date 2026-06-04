from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import List

from engine.correlator import CorrelationEngine
from engine.exporter import build_cluster_snapshot, build_correlation_result
from engine.fsm import validate_rule_assets
from engine.models import Event, parse_time
from parsers import load_falco_events, load_hubble_events, load_hubble_observe_events, materialize_events


def sample_events() -> List[Event]:
    return [
        Event(
            event_id="falco-evt-001",
            event_source="falco",
            observed_at=parse_time("2026-04-11T10:00:01Z"),
            subject_pod="pod-a",
            namespace="attack-lab-01",
            node_name="worker-1",
            workload_name="attacker",
            event_type="shell_exec",
            description="Terminal shell in container",
            role="trigger",
            rule_name="Terminal shell in container",
        ),
        Event(
            event_id="falco-evt-002",
            event_source="falco",
            observed_at=parse_time("2026-04-11T10:00:20Z"),
            subject_pod="pod-a",
            namespace="attack-lab-01",
            node_name="worker-1",
            workload_name="attacker",
            event_type="k8s_api_access",
            description="Kubernetes API access from pod-a",
            role="trigger",
            rule_name="Pod-ing K8s API Access from Container",
        ),
        Event(
            event_id="hubble-evt-001",
            event_source="hubble",
            observed_at=parse_time("2026-04-11T10:00:42Z"),
            subject_pod="pod-a",
            namespace="attack-lab-01",
            node_name="worker-1",
            workload_name="attacker",
            event_type="new_pod_connection",
            description="New pod-to-pod connection from pod-a to pod-b on TCP/8080",
            role="propagation",
            flow_pattern="new_pod_to_pod_connection",
            peer_pod="pod-b",
            peer_namespace="attack-lab-01",
            peer_node_name="worker-2",
            peer_workload_name="unknown",
        ),
        Event(
            event_id="falco-evt-003",
            event_source="falco",
            observed_at=parse_time("2026-04-11T10:01:10Z"),
            subject_pod="pod-a",
            namespace="attack-lab-01",
            node_name="worker-1",
            workload_name="attacker",
            event_type="shell_exec",
            description="Terminal shell in container on follow-on pod",
            role="trigger",
            rule_name="Terminal shell in container",
        ),
    ]


def parser_events_or_fallback() -> tuple[List[Event], str]:
    actual_falco_candidates = [
        Path("data/falco-live.json"),
        Path("data/falco.json"),
        Path("reference/falco_real_samples.json"),
    ]
    actual_hubble_json_candidates = [
        Path("data/hubble-live.json"),
        Path("data/hubble-sample.json"),
        Path("reference/hubble_real_samples.json"),
    ]
    actual_hubble_observe_candidates = [
        Path("data/hubble-observe.log"),
        Path("data/hubble_observe.log"),
    ]

    falco_path = next((path for path in actual_falco_candidates if path.exists()), None)
    hubble_json_path = next((path for path in actual_hubble_json_candidates if path.exists()), None)
    hubble_observe_path = next((path for path in actual_hubble_observe_candidates if path.exists()), None)

    if falco_path and hubble_observe_path:
        events = materialize_events(load_falco_events(falco_path) + load_hubble_observe_events(hubble_observe_path))
        return events, f"parser input: falco={falco_path}, hubble_observe={hubble_observe_path}"

    if falco_path and hubble_json_path:
        events = materialize_events(load_falco_events(falco_path) + load_hubble_events(hubble_json_path))
        return events, f"parser input: falco={falco_path}, hubble_json={hubble_json_path}"

    return sample_events(), "fallback input: built-in sample_events()"


def resolve_scope_pod(events: List[Event]) -> str:
    preferred_scope = "attack-lab-01/pod-a"
    available_keys = {event.primary_entity_key for event in events}
    if preferred_scope in available_keys:
        return preferred_scope
    if not events:
        raise ValueError("No events available to determine scope pod.")
    return events[0].primary_entity_key


def main() -> None:
    events, source_message = parser_events_or_fallback()
    print(source_message, file=sys.stderr)
    asset_summary = validate_rule_assets()
    print(
        (
            "validated rule assets: "
            f"event_type_mappings={asset_summary['event_type_mapping_count']}, "
            f"symbols={asset_summary['symbol_count']}, "
            f"scenario_rules={asset_summary['scenario_rule_count']}"
        ),
        file=sys.stderr,
    )
    engine = CorrelationEngine(cluster_name="poding-lab")
    engine.ingest(events)
    scope_pod_key = resolve_scope_pod(events)

    snapshot = build_cluster_snapshot(
        cluster_name=engine.cluster_name,
        pod_fsms=engine.fsms,
        graph_manager=engine.graph,
    )
    snapshot["preferred_scope_result"] = build_correlation_result(
        cluster_name=engine.cluster_name,
        pod_key=scope_pod_key,
        pod_fsm=engine.fsms[scope_pod_key],
        graph_manager=engine.graph,
    )
    print(json.dumps(snapshot, indent=2, ensure_ascii=True))


if __name__ == "__main__":
    main()

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from engine.hubble_conditions import is_public_destination
from engine.models import Event
from parsers.raw_event import RawEvent


@lru_cache(maxsize=1)
def load_event_type_mapping() -> Dict[str, Any]:
    mapping_path = Path(__file__).resolve().parents[1] / "rules" / "event_type_mapping.yaml"
    with mapping_path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def materialize_event(raw_event: RawEvent) -> Optional[Event]:
    event_type = resolve_event_type(raw_event)
    if event_type is None:
        return None

    return Event(
        event_id=raw_event.event_id,
        event_source=raw_event.event_source,
        observed_at=raw_event.observed_at,
        subject_pod=raw_event.subject_pod,
        namespace=raw_event.namespace,
        node_name=raw_event.node_name,
        workload_name=raw_event.workload_name,
        event_type=event_type,
        description=raw_event.description,
        role=raw_event.role,
        rule_name=raw_event.rule_name,
        flow_pattern=raw_event.flow_pattern,
        peer_pod=raw_event.peer_pod,
        peer_namespace=raw_event.peer_namespace,
        peer_node_name=raw_event.peer_node_name,
        peer_workload_name=raw_event.peer_workload_name,
        official_fields=dict(raw_event.official_fields),
    )


def materialize_events(raw_events: List[RawEvent]) -> List[Event]:
    events: List[Event] = []
    for raw_event in raw_events:
        materialized = materialize_event(raw_event)
        if materialized is not None:
            events.append(materialized)
    return events


def resolve_event_type(raw_event: RawEvent) -> Optional[str]:
    mapping = load_event_type_mapping()

    if raw_event.event_source == "falco":
        falco_rules = mapping.get("falco", {}).get("rules", {})
        rule_mapping = falco_rules.get(raw_event.rule_name or "")
        if isinstance(rule_mapping, dict):
            event_type = rule_mapping.get("event_type")
            return str(event_type) if event_type else None
        return None

    if raw_event.event_source == "hubble":
        for condition in mapping.get("hubble", {}).get("conditions", []):
            if _matches_hubble_condition(raw_event, condition.get("require", {})):
                event_type = condition.get("event_type")
                return str(event_type) if event_type else None

    return None


def _matches_hubble_condition(raw_event: RawEvent, require: Dict[str, Any]) -> bool:
    direction = str(raw_event.official_fields.get("direction", "unknown")).lower()
    destination_ip = raw_event.official_fields.get("destination_ip")
    destination_port = str(raw_event.official_fields.get("destination_port", "")).lower()
    protocol = str(raw_event.official_fields.get("protocol", "")).lower()
    source_ip = raw_event.official_fields.get("source_ip")
    peer_count = raw_event.official_fields.get("peer_count")
    peer_namespace = str(raw_event.peer_namespace or "")
    peer_pod = str(raw_event.peer_pod or "")
    declared_event_type = str(raw_event.official_fields.get("declared_event_type", "")).strip()
    same_namespace = bool(raw_event.peer_namespace) and raw_event.peer_namespace == raw_event.namespace

    declared_event_types = set(str(value) for value in require.get("declared_event_types", []))
    if declared_event_types and declared_event_type not in declared_event_types:
        return False
    if require.get("peer_pod_present") and not raw_event.peer_pod:
        return False
    if require.get("peer_pod_absent") and raw_event.peer_pod:
        return False
    if require.get("external_destination") and (raw_event.peer_pod or not destination_ip):
        return False
    if require.get("public_destination") and not is_public_destination(destination_ip):
        return False
    if require.get("external_source") and not source_ip:
        return False

    peer_namespaces = set(str(value) for value in require.get("peer_namespace_any_of", []))
    if peer_namespaces and peer_namespace not in peer_namespaces:
        return False

    excluded_peer_namespaces = set(str(value) for value in require.get("peer_namespace_not_in", []))
    if excluded_peer_namespaces and peer_namespace in excluded_peer_namespaces:
        return False

    peer_pod_prefixes = tuple(str(value) for value in require.get("peer_pod_prefix_any_of", []))
    if peer_pod_prefixes and not peer_pod.startswith(peer_pod_prefixes):
        return False

    protocols = [str(value).lower() for value in require.get("protocol_any_of", [])]
    if protocols and protocol not in protocols:
        return False

    destination_ports = [str(value).lower() for value in require.get("destination_port_any_of", [])]
    if destination_ports and destination_port not in destination_ports:
        return False

    same_namespace_requirement = require.get("same_namespace")
    if same_namespace_requirement is True and not same_namespace:
        return False
    if same_namespace_requirement is False and (
        not raw_event.peer_namespace or raw_event.peer_namespace == raw_event.namespace
    ):
        return False

    directions = [str(value).lower() for value in require.get("direction_any_of", [])]
    if directions and direction not in directions:
        return False

    peer_count_min = require.get("peer_count_min")
    if peer_count_min is not None:
        try:
            current_peer_count = int(peer_count)
        except (TypeError, ValueError):
            return False
        if current_peer_count < int(peer_count_min):
            return False

    return True

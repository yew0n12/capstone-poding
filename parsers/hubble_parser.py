from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from engine.models import parse_time
from parsers.raw_event import RawEvent


def _first_non_empty(*values: Any) -> Any:
    for value in values:
        if value not in (None, "", []):
            return value
    return None


def _safe_node_name(item: Dict[str, Any], prefix: str) -> str:
    return _first_non_empty(item.get(f"{prefix}_node_name"), item.get(f"{prefix}_node")) or "unknown"


def _safe_workload_name(item: Dict[str, Any], prefix: str) -> str:
    return (
        _first_non_empty(
            item.get(f"{prefix}_workload_name"),
            item.get(f"{prefix}_workload"),
            item.get(f"{prefix}_pod"),
        )
        or "unknown"
    )


def parse_hubble_event(raw_item: Dict[str, Any]) -> Optional[RawEvent]:
    timestamp = raw_item.get("timestamp")
    event_id = raw_item.get("event_id") or raw_item.get("flow_id")
    source_pod = raw_item.get("source_pod")
    source_namespace = raw_item.get("source_namespace")
    destination_pod = raw_item.get("destination_pod")
    destination_namespace = raw_item.get("destination_namespace")
    destination_ip = raw_item.get("destination_ip")
    protocol = raw_item.get("protocol", "UNKNOWN")
    port = raw_item.get("port", "unknown")
    direction = raw_item.get("direction", "unknown")

    if not all([timestamp, event_id, source_pod, source_namespace]):
        raise ValueError(
            "Hubble event is missing one of required fields: timestamp, event_id/flow_id, source_pod, source_namespace."
        )

    destination_label = destination_pod or destination_ip or "unknown"
    description = raw_item.get("description") or (
        f"Hubble flow {source_namespace}/{source_pod} -> {destination_label} on {protocol}/{port} ({direction})"
    )

    return RawEvent(
        event_id=str(event_id),
        event_source="hubble",
        observed_at=parse_time(str(timestamp)),
        subject_pod=str(source_pod),
        namespace=str(source_namespace),
        node_name=_safe_node_name(raw_item, "source"),
        workload_name=_safe_workload_name(raw_item, "source"),
        description=str(description),
        role="propagation",
        flow_pattern=str(raw_item.get("verdict", "")).lower() or None,
        peer_pod=destination_pod,
        peer_namespace=destination_namespace,
        peer_node_name=_safe_node_name(raw_item, "destination"),
        peer_workload_name=_safe_workload_name(raw_item, "destination"),
        official_fields={
            "direction": str(direction),
            "protocol": str(protocol),
            "destination_ip": str(destination_ip or ""),
            "destination_port": port,
            "verdict": str(raw_item.get("verdict", "")),
            "peer_count": raw_item.get("peer_count") or raw_item.get("spread_count"),
            "source_ip": str(raw_item.get("source_ip", "")),
            "declared_event_type": str(raw_item.get("event_type", "")),
        },
    )


def parse_hubble_events(raw_items: List[Dict[str, Any]]) -> List[RawEvent]:
    events: List[RawEvent] = []
    for item in raw_items:
        try:
            parsed = parse_hubble_event(item)
        except ValueError:
            continue
        if parsed is not None:
            events.append(parsed)
    return events


def load_hubble_events(path: str | Path) -> List[RawEvent]:
    raw = json.loads(Path(path).read_text())
    if not isinstance(raw, list):
        raise ValueError("Hubble sample file must contain a JSON array.")
    return parse_hubble_events(raw)

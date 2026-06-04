from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
from typing import Any, Dict, Optional


STATE_ORDER = ["IDLE", "RECON", "CRED", "LATERAL", "ALERT"]
STATE_RANK = {state: index for index, state in enumerate(STATE_ORDER)}
DEFAULT_CORRELATION_DIMENSIONS = ["time", "entity", "sequence", "propagation"]


def parse_time(value: str) -> datetime:
    normalized = re.sub(
        r"(\.\d{6})\d+(Z|[+-]\d{2}:?\d{2})$",
        r"\1\2",
        value,
    )
    parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def utc_now() -> str:
    return format_timestamp(datetime.now(timezone.utc))


def unique_append(items: list[str], value: Optional[str]) -> None:
    if value and value not in items:
        items.append(value)


def build_pod_key(namespace: str, pod_name: str) -> str:
    return f"{namespace}/{pod_name}"


def parse_int(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


@dataclass(order=True)
class Event:
    observed_at: datetime
    event_id: str = field(compare=False)
    event_source: str = field(compare=False)
    subject_pod: str = field(compare=False)
    namespace: str = field(compare=False)
    node_name: str = field(compare=False)
    workload_name: str = field(compare=False)
    event_type: str = field(compare=False)
    description: str = field(compare=False)
    role: str = field(compare=False)
    rule_name: Optional[str] = field(default=None, compare=False)
    flow_pattern: Optional[str] = field(default=None, compare=False)
    peer_pod: Optional[str] = field(default=None, compare=False)
    peer_namespace: Optional[str] = field(default=None, compare=False)
    peer_node_name: Optional[str] = field(default=None, compare=False)
    peer_workload_name: Optional[str] = field(default=None, compare=False)
    official_fields: Dict[str, Any] = field(default_factory=dict, compare=False)

    @property
    def primary_entity_key(self) -> str:
        return build_pod_key(self.namespace, self.subject_pod)

    @property
    def namespace_key(self) -> str:
        return self.namespace

    @property
    def node_key(self) -> str:
        return self.node_name

    @property
    def workload_key(self) -> str:
        return f"{self.namespace}/{self.workload_name}"

    @property
    def peer_entity_key(self) -> Optional[str]:
        if self.peer_pod and self.peer_namespace:
            return build_pod_key(self.peer_namespace, self.peer_pod)
        return None

    @property
    def receive_order(self) -> int | None:
        return parse_int(self.official_fields.get("receive_order"))

    @property
    def ingested_at(self) -> str:
        ingested_at = self.official_fields.get("ingested_at")
        return str(ingested_at).strip() if isinstance(ingested_at, str) else ""

    def to_source_event(self) -> Dict[str, Any]:
        source_event = {
            "event_id": self.event_id,
            "event_source": self.event_source,
            "observed_at": format_timestamp(self.observed_at),
            "role": self.role,
            "event_type": self.event_type,
            "rule_name": self.rule_name or "",
            "peer_entity_key": self.peer_entity_key or "",
        }
        if self.ingested_at:
            source_event["ingested_at"] = self.ingested_at
        if self.receive_order is not None:
            source_event["receive_order"] = self.receive_order
        return source_event

    def correlation_key_values(self) -> Dict[str, str]:
        values = {
            "primary_entity_key": self.primary_entity_key,
            "namespace_key": self.namespace_key,
            "node_key": self.node_key,
            "workload_key": self.workload_key,
        }
        if self.peer_entity_key:
            values["peer_entity_key"] = self.peer_entity_key
        return values


@dataclass
class SymbolObservation:
    symbol: str
    source: str
    matched_by: str
    event_id: str
    state_hint: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

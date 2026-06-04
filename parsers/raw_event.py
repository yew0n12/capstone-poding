from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass(order=True)
class RawEvent:
    observed_at: datetime
    event_id: str = field(compare=False)
    event_source: str = field(compare=False)
    subject_pod: str = field(compare=False)
    namespace: str = field(compare=False)
    node_name: str = field(compare=False)
    workload_name: str = field(compare=False)
    description: str = field(compare=False)
    role: str = field(compare=False)
    rule_name: Optional[str] = field(default=None, compare=False)
    flow_pattern: Optional[str] = field(default=None, compare=False)
    peer_pod: Optional[str] = field(default=None, compare=False)
    peer_namespace: Optional[str] = field(default=None, compare=False)
    peer_node_name: Optional[str] = field(default=None, compare=False)
    peer_workload_name: Optional[str] = field(default=None, compare=False)
    official_fields: Dict[str, Any] = field(default_factory=dict, compare=False)

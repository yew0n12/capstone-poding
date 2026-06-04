from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from engine.models import Event, parse_time


RULE_EVENT_MAPPINGS = {
    "Terminal shell in container": "shell_exec",
    "Shell Exec in Container": "shell_exec",
    "Read sensitive file untrusted": "service_account_token_access",
    "Read Sensitive File via hostPath": "secret_file_access",
    "Read Kubeconfig via hostPath": "secret_file_access",
    "Service Account Token Access": "service_account_token_access",
    "Contact K8S API Server From Container": "k8s_api_access",
    "Pod-ing K8s API Access from Container": "k8s_api_access",
    "Pod-ing SA Token Read": "service_account_token_access",
    "Netcat Remote Code Execution in Container": "network_tool_exec",
    "Pod-ing Netcat Execution in Container": "network_tool_exec",
    "Pod-ing External Download in Container": "network_tool_exec",
    "Redirect STDOUT/STDIN to Network Connection in Container": "network_tool_exec",
    "Drop and execute new binary in container": "process_exec",
    "Namespace Escape via nsenter": "container_escape",
    "Propagation Received From Suspect": "propagation_received",
    "THEIA Host Network Tool": "network_tool_exec",
    "THEIA Host Credential Read": "secret_file_access",
    "THEIA Host Lateral Inbound": "propagation_received",
}

TEXT_FIELD_PATTERNS = {
    "namespace": [
        re.compile(r"k8s\.ns\.name=(?P<value>[^\s)]+)"),
        re.compile(r"namespace=(?P<value>[^\s)]+)"),
        re.compile(r"ns=(?P<value>[^\s)]+)"),
    ],
    "pod_name": [
        re.compile(r"k8s\.pod\.name=(?P<value>[^\s)]+)"),
        re.compile(r"pod(?:_name)?=(?P<value>[^\s)]+)"),
    ],
    "rule": [
        re.compile(r'rule="?([^"]+)"?'),
    ],
}


def _get_nested(mapping: Dict[str, Any], *path: str) -> Any:
    current: Any = mapping
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def _first_non_empty(*values: Any) -> Any:
    for value in values:
        if value not in (None, "", []):
            return value
    return None


def _output_fields(item: Dict[str, Any]) -> Dict[str, Any]:
    fields = item.get("output_fields")
    return fields if isinstance(fields, dict) else {}


def _safe_workload_name(item: Dict[str, Any], output_fields: Dict[str, Any]) -> str:
    return (
        _first_non_empty(
            item.get("workload_name"),
            output_fields.get("k8s.deployment.name"),
            output_fields.get("k8s.rs.name"),
            output_fields.get("container.name"),
            item.get("container_name"),
            item.get("pod_name"),
        )
        or "unknown"
    )


def _safe_node_name(item: Dict[str, Any], output_fields: Dict[str, Any]) -> str:
    return _first_non_empty(
        item.get("node_name"),
        item.get("host"),
        output_fields.get("k8s.node.name"),
        output_fields.get("evt.hostname"),
    ) or "unknown"


def _extract_from_text(text: str, field_name: str) -> Optional[str]:
    for pattern in TEXT_FIELD_PATTERNS.get(field_name, []):
        match = pattern.search(text)
        if match:
            return match.group("value") if "value" in match.groupdict() else match.group(1)
    return None


def extract_falco_json(line: str) -> Optional[Dict[str, Any]]:
    stripped = line.strip()
    if not stripped:
        return None

    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        start = stripped.find("{")
        end = stripped.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return None
        candidate = stripped[start : end + 1]
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            return None

    return parsed if isinstance(parsed, dict) else None


def _map_rule_to_event_type(rule_name: str, raw_item: Dict[str, Any]) -> Optional[str]:
    mapped = RULE_EVENT_MAPPINGS.get(rule_name)
    if mapped:
        return mapped

    output = str(raw_item.get("output", ""))
    raw_data = str(raw_item.get("raw_data", ""))
    if "/var/run/secrets/kubernetes.io/serviceaccount/token" in output or "/var/run/secrets/kubernetes.io/serviceaccount/token" in raw_data:
        return "service_account_token_access"

    return None


def parse_falco_event(raw_item: Dict[str, Any]) -> Optional[Event]:
    output_fields = _output_fields(raw_item)
    output_text = str(raw_item.get("output", ""))
    raw_data = str(raw_item.get("raw_data", ""))

    rule_name = _first_non_empty(
        raw_item.get("rule"),
        _get_nested(raw_item, "rule"),
        _extract_from_text(output_text, "rule"),
        _extract_from_text(raw_data, "rule"),
    )
    if not rule_name:
        raise ValueError("Falco event is missing required field `rule`.")

    event_type = _map_rule_to_event_type(str(rule_name), raw_item)
    if event_type is None:
        return None

    timestamp = _first_non_empty(
        raw_item.get("timestamp"),
        raw_item.get("time"),
        raw_item.get("output_time"),
        output_fields.get("evt.time"),
        _get_nested(raw_item, "output_fields", "evt.time"),
    )
    pod_name = _first_non_empty(
        raw_item.get("pod_name"),
        output_fields.get("k8s.pod.name"),
        _extract_from_text(output_text, "pod_name"),
        _extract_from_text(raw_data, "pod_name"),
    )
    namespace = _first_non_empty(
        raw_item.get("namespace"),
        output_fields.get("k8s.ns.name"),
        _extract_from_text(output_text, "namespace"),
        _extract_from_text(raw_data, "namespace"),
    )
    event_id = _first_non_empty(raw_item.get("event_id"), raw_item.get("id"))
    if not event_id and timestamp and rule_name and pod_name and namespace:
        event_id = f"falco-{timestamp}-{namespace}-{pod_name}-{rule_name}"

    if not all([timestamp, event_id, pod_name, namespace]):
        raise ValueError(
            "Falco event is missing one of required fields: timestamp/time, event_id/id, pod_name, namespace."
        )

    proc_name = _first_non_empty(raw_item.get("process"), output_fields.get("proc.name"))
    proc_cmdline = _first_non_empty(raw_item.get("proc_cmdline"), output_fields.get("proc.cmdline"))
    description = str(
        _first_non_empty(raw_item.get("output"), rule_name, proc_name, raw_item.get("command"))
    )

    return Event(
        event_id=str(event_id),
        event_source="falco",
        observed_at=parse_time(str(timestamp)),
        subject_pod=str(pod_name),
        namespace=str(namespace),
        node_name=_safe_node_name(raw_item, output_fields),
        workload_name=_safe_workload_name(raw_item, output_fields),
        event_type=event_type,
        description=description,
        role="trigger",
        rule_name=str(rule_name),
        official_fields={
            "rule_name": str(rule_name),
            "process_name": str(proc_name or ""),
            "process_cmdline": str(proc_cmdline or ""),
            "fd_name": str(output_fields.get("fd.name") or ""),
            "fd_sip": str(output_fields.get("fd.sip") or ""),
            "fd_sport": str(output_fields.get("fd.sport") or ""),
            "output": output_text,
            "raw_data": raw_data,
            "evt_type": str(output_fields.get("evt.type") or ""),
        },
    )


def parse_falco_line(line: str) -> Optional[Event]:
    raw_item = extract_falco_json(line)
    if raw_item is None:
        return None
    return parse_falco_event(raw_item)


def parse_falco_events(raw_items: List[Dict[str, Any]]) -> List[Event]:
    events: List[Event] = []
    for item in raw_items:
        try:
            parsed = parse_falco_event(item)
        except ValueError:
            continue
        if parsed is not None:
            events.append(parsed)
    return events


def load_falco_events(path: str | Path) -> List[Event]:
    raw = json.loads(Path(path).read_text())
    if not isinstance(raw, list):
        raise ValueError("Falco sample file must contain a JSON array.")
    return parse_falco_events(raw)

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from engine.models import parse_time
from parsers.raw_event import RawEvent


ISO_LINE_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+"
    r"(?P<source_ns>[^/\s]+)/(?P<source_pod>[^\s]+)\s+->\s+"
    r"(?P<target>[^\s]+)"
    r"(?:\s+(?P<protocol>TCP|UDP))?"
    r"(?:/(?P<port>\d+))?"
    r"(?:\s+(?P<direction>ingress|egress))?",
    re.IGNORECASE,
)

OBSERVE_LINE_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+"
    r"(?P<day>\d{1,2})\s+"
    r"(?P<clock>\d{2}:\d{2}:\d{2}\.\d{3}):\s+"
    r"(?P<source>[^\s]+)\s+\((?P<source_identity>[^)]+)\)\s+"
    r"(?P<direction><>|->|<-)\s+"
    r"(?P<target>[^\s]+)\s+\((?P<target_identity>[^)]+)\)\s+"
    r"(?P<traffic_type>\S+)\s+"
    r"(?P<verdict>[A-Z]+)"
    r"(?:\s+\((?P<details>.+)\))?$",
    re.IGNORECASE,
)


def _normalize_timestamp(month: str, day: str, clock: str) -> str:
    year = datetime.now(timezone.utc).year
    parsed = datetime.strptime(f"{year} {month} {day} {clock}", "%Y %b %d %H:%M:%S.%f")
    parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.isoformat().replace("+00:00", "Z")


def _split_target(target: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
    if target.startswith("kube-apiserver"):
        return None, None, "kube-apiserver"

    if "/" in target:
        namespace, remainder = target.split("/", 1)
        if ":" in remainder:
            pod_name, _port = remainder.split(":", 1)
            return namespace, pod_name, None
        return namespace, remainder, None

    if ":" in target:
        service_name, _port = target.split(":", 1)
        return "kube-system", service_name, None

    return None, None, target


def _split_endpoint(endpoint: str) -> tuple[str, Optional[str], Optional[str], Optional[str]]:
    host = endpoint
    port = None
    if endpoint.count(":") == 1:
        maybe_host, maybe_port = endpoint.rsplit(":", 1)
        if maybe_port.isdigit():
            host = maybe_host
            port = maybe_port

    if "/" in host:
        namespace, pod_name = host.split("/", 1)
        return host, namespace, pod_name, port

    return host, None, None, port


def _extract_protocol(details: Optional[str]) -> str:
    if not details:
        return "UNKNOWN"
    return details.split()[0].rstrip(",)").upper()


def parse_hubble_observe_line(line: str, line_number: int = 0) -> Optional[RawEvent]:
    stripped = line.strip()
    if not stripped:
        return None

    iso_match = ISO_LINE_PATTERN.search(stripped)
    if iso_match:
        timestamp = iso_match.group("timestamp")
        source_ns = iso_match.group("source_ns")
        source_pod = iso_match.group("source_pod")
        target = iso_match.group("target")
        protocol = iso_match.group("protocol") or "UNKNOWN"
        port = iso_match.group("port") or "unknown"
        direction = (iso_match.group("direction") or "egress").lower()
        target_namespace, target_pod, _ = _split_target(target)

        description = (
            f"Hubble observe {source_ns}/{source_pod} -> {target} on {protocol}/{port} ({direction})"
        )

        return RawEvent(
            event_id=f"hubble-observe-{line_number}",
            event_source="hubble",
            observed_at=parse_time(timestamp),
            subject_pod=source_pod,
            namespace=source_ns,
            node_name="unknown",
            workload_name=source_pod,
            description=description,
            role="propagation",
            flow_pattern=None,
            peer_pod=target_pod,
            peer_namespace=target_namespace,
            peer_node_name="unknown",
            peer_workload_name=target_pod or "unknown",
            official_fields={
                "direction": direction,
                "protocol": protocol,
                "destination_ip": "" if target_pod else target,
                "destination_port": port,
                "source_ip": "",
                "declared_event_type": "",
            },
        )

    observe_match = OBSERVE_LINE_PATTERN.search(stripped)
    if not observe_match:
        return None

    timestamp = _normalize_timestamp(
        observe_match.group("month"),
        observe_match.group("day"),
        observe_match.group("clock"),
    )
    source = observe_match.group("source")
    source_identity = observe_match.group("source_identity")
    target = observe_match.group("target")
    direction = observe_match.group("direction")
    verdict = observe_match.group("verdict").upper()
    details = observe_match.group("details")
    protocol = _extract_protocol(details)

    _source_raw, source_ns, source_pod, source_port = _split_endpoint(source)
    target_raw, target_namespace, target_pod, target_port = _split_endpoint(target)
    normalized_direction = "egress" if direction == "->" else "ingress" if direction == "<-" else "unknown"
    inbound_source_ip = ""
    destination_ip = "" if target_pod else target
    destination_port = target_port or "unknown"
    if normalized_direction == "ingress" and source_pod and not target_pod:
        inbound_source_ip = target_raw
        destination_ip = ""
        destination_port = source_port or "unknown"

    subject_pod = source_pod or source_identity or "unknown"
    namespace = source_ns or "unknown"
    workload_name = source_pod or source_identity or "unknown"
    description = (
        f"Hubble observe {source} ({source_identity}) {direction} {target} "
        f"verdict={verdict} protocol={protocol}"
    )

    return RawEvent(
        event_id=f"hubble-observe-{line_number}",
        event_source="hubble",
        observed_at=parse_time(timestamp),
        subject_pod=subject_pod,
        namespace=namespace,
        node_name="unknown",
        workload_name=workload_name,
        description=description,
        role="propagation",
        flow_pattern=verdict.lower(),
        peer_pod=target_pod,
        peer_namespace=target_namespace,
        peer_node_name="unknown",
        peer_workload_name=target_pod or observe_match.group("target_identity") or "unknown",
        official_fields={
            "direction": normalized_direction,
            "protocol": protocol,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "source_ip": inbound_source_ip or (source if source_ns is None else ""),
            "verdict": verdict,
            "declared_event_type": "",
        },
    )


def parse_hubble_observe_lines(lines: List[str]) -> List[RawEvent]:
    events: List[RawEvent] = []
    for index, line in enumerate(lines, start=1):
        parsed = parse_hubble_observe_line(line, line_number=index)
        if parsed is not None:
            events.append(parsed)
    return events


def load_hubble_observe_events(path: str | Path) -> List[RawEvent]:
    lines = Path(path).read_text().splitlines()
    return parse_hubble_observe_lines(lines)

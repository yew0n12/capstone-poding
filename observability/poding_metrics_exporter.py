#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

STATE_ORDER = ["IDLE", "RECON", "CRED", "LATERAL", "ALERT"]
STATE_SCORE = {state: index for index, state in enumerate(STATE_ORDER)}
PROGRESS_LEVEL = STATE_SCORE
STATE_SEVERITY = {
    "IDLE": "Normal",
    "RECON": "Suspicious",
    "CRED": "Suspicious",
    "LATERAL": "Critical",
    "ALERT": "Critical",
}
PRIORITY_SEVERITY = {
    "none": "Normal",
    "supporting": "Suspicious",
    "primary": "Critical",
}
SEVERITY_SCORE = {
    "Normal": 0,
    "Suspicious": 1,
    "Critical": 2,
}
SEVERITY_COLOR = {
    "Normal": "#73BF69",
    "Suspicious": "#FF9830",
    "Critical": "#F2495C",
}
DISPLAY_STATE_COLOR = {
    "IDLE": "#5794F2",
    "RECON": "#F2CC0C",
    "CRED": "#FF9830",
    "LATERAL": "#FA6400",
    "ALERT": "#F2495C",
}


@dataclass
class NodeEntry:
    id: str
    title: str
    subtitle: str
    mainstat: str
    secondarystat: str
    color: str
    scenario: str
    severity: str
    state: str
    namespace: str
    pod: str
    progress: float
    progress_level: int
    display_state: str
    display_score: float
    threat_score: float
    role: str
    symbols: tuple[str, ...]
    ui_state: str
    ui_severity: str
    highlighted: bool


@dataclass
class EdgeEntry:
    id: str
    source: str
    target: str
    mainstat: str
    secondarystat: str
    color: str
    scenario: str
    severity: str
    response_status: str
    edge_type: str
    relation: str
    highlighted: bool


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export Pod-ing JSON results as Prometheus metrics.")
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, default=9108)
    parser.add_argument("--results-dir", default="results")
    parser.add_argument("--correlation-file")
    parser.add_argument("--detection-summary-file")
    parser.add_argument("--debug-summary-file")
    parser.add_argument("--staleness-seconds", type=int, default=300)
    parser.add_argument("--once", action="store_true")
    return parser.parse_args()


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def iso_to_timestamp(raw: str | None) -> float:
    if not raw:
        return 0.0
    text = raw.strip()
    if not text:
        return 0.0
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text).timestamp()
    except ValueError:
        return 0.0


def split_pod_key(pod_key: str) -> tuple[str, str]:
    if "/" not in pod_key:
        return "", pod_key
    namespace, pod = pod_key.split("/", 1)
    return namespace, pod


def progress_ratio(state: str) -> float:
    max_index = max(len(STATE_ORDER) - 1, 1)
    return STATE_SCORE.get(state, 0) / max_index


def severity_for_state(state: str) -> str:
    return STATE_SEVERITY.get(state, "Normal")


def max_severity(left: str, right: str) -> str:
    return left if SEVERITY_SCORE.get(left, 0) >= SEVERITY_SCORE.get(right, 0) else right


def severity_for_detection(priority: str, final_state: str) -> str:
    return max_severity(PRIORITY_SEVERITY.get(priority.lower(), "Normal"), severity_for_state(final_state))


def threat_score(progress: float, severity: str, is_primary: bool) -> float:
    base = progress * 80.0
    sev_bonus = {"Normal": 0.0, "Suspicious": 20.0, "Critical": 35.0}.get(severity, 0.0)
    suspect_bonus = 10.0 if is_primary else 0.0
    return min(100.0, base + sev_bonus + suspect_bonus)


def prom_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")


class MetricWriter:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self.seen_headers: set[str] = set()

    def header(self, name: str, metric_type: str, help_text: str) -> None:
        if name in self.seen_headers:
            return
        self.seen_headers.add(name)
        self.lines.append(f"# HELP {name} {help_text}")
        self.lines.append(f"# TYPE {name} {metric_type}")

    def sample(self, name: str, value: float | int, labels: dict[str, Any] | None = None) -> None:
        if labels:
            rendered = ",".join(
                f'{key}="{prom_escape(str(labels[key]))}"'
                for key in sorted(labels)
                if labels[key] is not None
            )
            self.lines.append(f"{name}{{{rendered}}} {float(value):.6f}")
            return
        self.lines.append(f"{name} {float(value):.6f}")

    def render(self) -> str:
        return "\n".join(self.lines) + "\n"


def pick_primary_scenario(scenarios: set[str], fallback: str) -> str:
    if not scenarios:
        return fallback
    return sorted(scenarios)[0]


def ensure_pod_context(
    pod_ctx: dict[str, dict[str, Any]],
    pod_scenarios: dict[str, set[str]],
    pod_key: str,
    summary_label: str,
    related_pods: set[str],
    primary_suspect: str,
) -> None:
    if pod_key in pod_ctx:
        return
    namespace, pod = split_pod_key(pod_key)
    scenario = summary_label if pod_key in related_pods else "state_tracking"
    pod_ctx[pod_key] = {
        "namespace": namespace,
        "pod": pod,
        "state": "IDLE",
        "progress": 0.0,
        "severity": "Normal",
        "is_primary": pod_key == primary_suspect,
    }
    pod_scenarios[pod_key].add(scenario)


def is_excluded_system_pod(pod_key: str) -> bool:
    namespace, pod = split_pod_key(pod_key)
    if namespace in {"kube-system", "monitoring"}:
        return True
    if pod == "kubernetes":
        return True
    return pod.startswith(("coredns", "kube-dns", "falco", "prometheus", "grafana", "hubble-relay", "poding-detector"))


def is_non_system_pod(pod_key: str) -> bool:
    return not is_excluded_system_pod(pod_key)


def evidence_score(
    *,
    state: str,
    symbols: set[str],
    symbol_trace_len: int,
    matched_flow_count: int,
    detection_count: int,
    is_primary: bool,
    is_secondary: bool,
) -> float:
    score = progress_ratio(state) * 0.4
    if "O" in symbols:
        score += 0.15
    if "E" in symbols:
        score += 0.45
    score += min(0.15, symbol_trace_len * 0.01)
    score += min(0.15, matched_flow_count * 0.08)
    score += min(0.2, detection_count * 0.15)
    if is_primary:
        score += 0.1
    if is_secondary:
        score += 0.08
    return min(1.0, score)


def severity_for_evidence(state: str, score: float, symbols: set[str], detection_count: int) -> str:
    state_severity = severity_for_state(state)
    if detection_count > 0 or state_severity == "Critical" or ("E" in symbols and score >= 0.75):
        return "Critical"
    if state_severity == "Suspicious" or score > 0.0:
        return "Suspicious"
    return "Normal"


def node_role(
    *,
    pod_key: str,
    primary_suspect: str,
    secondary_suspects: set[str],
    symbols: set[str],
) -> str:
    if pod_key == primary_suspect:
        return "source"
    if pod_key in secondary_suspects:
        return "target"
    if "E" in symbols:
        return "target"
    if "O" in symbols:
        return "observed"
    return "support"


def edge_relation_label(edge_type: str, source_symbols: set[str], target_symbols: set[str], summary_symbols: set[str]) -> str:
    if "E" in source_symbols or "E" in target_symbols or "E" in summary_symbols:
        return "E / lateral movement"
    if edge_type == "network_flow":
        return "Observed flow"
    return edge_type.replace("_", " ")


def edge_score(source_ctx: dict[str, Any], target_ctx: dict[str, Any]) -> float:
    return max(
        float(source_ctx.get("display_score") or 0.0),
        float(target_ctx.get("display_score") or 0.0),
        float(source_ctx.get("progress") or 0.0),
        float(target_ctx.get("progress") or 0.0),
    )


def ordered_symbols(evidence: dict[str, Any]) -> tuple[str, ...]:
    ordered: list[str] = []
    for step in evidence.get("symbol_trace", []) or []:
        symbol = str(step.get("symbol") or "").strip()
        if symbol and symbol not in ordered:
            ordered.append(symbol)
    for symbol in evidence.get("observed_symbols", []) or []:
        text = str(symbol).strip()
        if text and text not in ordered:
            ordered.append(text)
    return tuple(ordered)


def format_symbols(symbols: tuple[str, ...]) -> str:
    return f"symbols: {','.join(symbols)}" if symbols else "symbols: -"


def ui_state_for_node(ctx: dict[str, Any]) -> str:
    # Visual-only display state. It follows the detector FSM state and must not
    # promote a pod to LATERAL/ALERT just because it is primary or has E traffic.
    state = str(ctx.get("display_state") or ctx.get("state") or "IDLE").upper()
    return state if state in PROGRESS_LEVEL else "IDLE"


def ui_severity_for_state(ui_state: str) -> str:
    if ui_state in {"LATERAL", "ALERT"}:
        return "Critical"
    if ui_state in {"RECON", "CRED"}:
        return "Suspicious"
    return "Normal"


def make_arc_values(ui_state: str) -> dict[str, float]:
    return {
        "arc__alert": 1.0 if ui_state == "ALERT" else 0.0,
        "arc__lateral": 1.0 if ui_state == "LATERAL" else 0.0,
        "arc__cred": 1.0 if ui_state == "CRED" else 0.0,
        "arc__recon": 1.0 if ui_state == "RECON" else 0.0,
        "arc__idle": 1.0 if ui_state == "IDLE" else 0.0,
        "arc__follow": 0.0,
        "arc__tracking": 1.0 if ui_state in {"RECON", "CRED"} else 0.0,
    }


def edge_chain_text(source_ctx: dict[str, Any], target_ctx: dict[str, Any]) -> str:
    source_symbols = tuple(source_ctx.get("symbols_ordered") or ())
    target_symbols = tuple(target_ctx.get("symbols_ordered") or ())
    if source_symbols and target_symbols:
        return f"{','.join(source_symbols)} → {','.join(target_symbols)}"
    if source_symbols:
        return f"{','.join(source_symbols)} → follow"
    if target_symbols:
        return f"source → {','.join(target_symbols)}"
    return "source → target"


def has_attack_evidence(ctx: dict[str, Any]) -> bool:
    return bool(
        ctx.get("detection_count")
        or ctx.get("symbol_trace_len")
        or ctx.get("matched_flow_count")
        or ctx.get("observed_symbols")
        or str(ctx.get("state") or "IDLE") != "IDLE"
    )


def collect_pod_refs(value: Any) -> set[str]:
    refs: set[str] = set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key in {
                "primary_suspect_pod",
                "secondary_suspect_pod",
                "related_pod",
                "source_pod",
                "target_pod",
                "peer",
                "peer_entity_key",
                "pod",
                "entity_id",
            } and isinstance(item, str) and "/" in item:
                refs.add(item.strip())
            refs.update(collect_pod_refs(item))
    elif isinstance(value, list):
        for item in value:
            refs.update(collect_pod_refs(item))
    return {ref for ref in refs if ref}


def build_graph_payload(
    *,
    correlation: dict[str, Any],
    detection_summary: dict[str, Any],
    debug_summary: dict[str, Any],
    staleness_seconds: int,
) -> dict[str, Any]:
    latest_generated = iso_to_timestamp(str(correlation.get("generated_at") or detection_summary.get("generated_at") or ""))
    fresh_cutoff = datetime.now(timezone.utc) - timedelta(seconds=staleness_seconds)
    detector_up = 1.0 if latest_generated and latest_generated >= fresh_cutoff.timestamp() else 0.0

    primary_suspect = str(detection_summary.get("primary_suspect_pod") or "").strip()
    secondary_suspects = {
        str(item).strip()
        for item in detection_summary.get("secondary_suspect_pods", []) or []
        if str(item).strip()
    }
    summary_label = str(detection_summary.get("label") or "state_tracking").strip() or "state_tracking"
    summary_symbols = {
        str(item).strip()
        for item in detection_summary.get("observed_symbols", []) or []
        if str(item).strip()
    }
    related_pods = {
        str(item).strip()
        for item in detection_summary.get("related_pods", []) or []
        if str(item).strip()
    }
    explicit_candidate_pods = {
        pod
        for pod in (
            {primary_suspect}
            | secondary_suspects
            | related_pods
            | collect_pod_refs(detection_summary)
        )
        if pod
    }
    hard_anchor_pods = {pod for pod in {primary_suspect} | collect_pod_refs(detection_summary) if pod}

    pod_ctx: dict[str, dict[str, Any]] = {}
    pod_scenarios: dict[str, set[str]] = defaultdict(set)
    alerts: dict[tuple[str, str, str], float] = {}
    critical_alerts: dict[tuple[str, str], float] = {}
    correlated_totals: dict[tuple[str, str], float] = defaultdict(float)
    last_detection: dict[tuple[str, str], float] = defaultdict(float)

    pods = correlation.get("pods", {})
    if isinstance(pods, dict):
        for pod_key, result in pods.items():
            state = str(((result.get("fsm") or {}).get("current_state")) or "IDLE")
            namespace, pod = split_pod_key(str(pod_key))
            evidence = result.get("evidence") or {}
            observed_symbols = {
                str(item).strip()
                for item in evidence.get("observed_symbols", []) or []
                if str(item).strip()
            }
            symbols_ordered = ordered_symbols(evidence)
            detections = evidence.get("detections") or []
            symbol_trace = evidence.get("symbol_trace") or []
            matched_flow_patterns = evidence.get("matched_flow_patterns") or []
            peer_pods = (
                collect_pod_refs(evidence.get("source_events", []))
                | collect_pod_refs(evidence.get("primary_detection", {}))
                | collect_pod_refs(evidence.get("state_trace", []))
            ) - {str(pod_key)}
            is_secondary = str(pod_key) in secondary_suspects
            graph_score = evidence_score(
                state=state,
                symbols=observed_symbols,
                symbol_trace_len=len(symbol_trace),
                matched_flow_count=len(matched_flow_patterns),
                detection_count=len(detections),
                is_primary=str(pod_key) == primary_suspect,
                is_secondary=is_secondary,
            )
            graph_severity = severity_for_evidence(state, graph_score, observed_symbols, len(detections))
            pod_ctx[str(pod_key)] = {
                "namespace": namespace,
                "pod": pod,
                "state": state,
                "progress": progress_ratio(state),
                "progress_level": PROGRESS_LEVEL.get(state, 0),
                "display_state": state if state in PROGRESS_LEVEL else "IDLE",
                "severity": graph_severity,
                "is_primary": str(pod_key) == primary_suspect,
                "is_secondary": is_secondary,
                "observed_symbols": observed_symbols,
                "symbols_ordered": symbols_ordered,
                "symbol_trace_len": len(symbol_trace),
                "matched_flow_count": len(matched_flow_patterns),
                "detection_count": len(detections),
                "display_score": graph_score,
                "role": node_role(
                    pod_key=str(pod_key),
                    primary_suspect=primary_suspect,
                    secondary_suspects=secondary_suspects,
                    symbols=observed_symbols,
                ),
                "peer_pods": peer_pods,
            }
            for detection in detections:
                detection_refs = collect_pod_refs(detection)
                explicit_candidate_pods.update(detection_refs)
                hard_anchor_pods.update(detection_refs)

        for pod_key, result in pods.items():
            detections = (((result.get("evidence") or {}).get("detections")) or [])
            for detection in detections:
                scenario = str(detection.get("rule_id") or detection.get("rule_name") or summary_label).strip() or summary_label
                final_state = str(detection.get("final_state") or pod_ctx.get(str(pod_key), {}).get("state") or "IDLE")
                severity = severity_for_detection(str(detection.get("priority") or "none"), final_state)
                suspect = primary_suspect or f"{detection.get('namespace', '')}/{detection.get('pod', '')}".strip("/")
                detected_at = iso_to_timestamp(str(detection.get("detected_at") or correlation.get("generated_at") or ""))
                pod_scenarios[str(pod_key)].add(scenario)
                correlated_totals[(scenario, severity)] += 1.0
                alerts[(scenario, severity, suspect)] = 1.0
                last_detection[(scenario, suspect)] = max(last_detection[(scenario, suspect)], detected_at)
                if severity == "Critical":
                    critical_alerts[(scenario, suspect)] = 1.0

    for trace_entry in detection_summary.get("state_trace", []) or []:
        pod_key = str(trace_entry.get("pod") or "").strip()
        trace = trace_entry.get("trace") or []
        if not pod_key or not trace:
            continue
        explicit_candidate_pods.add(pod_key)
        hard_anchor_pods.add(pod_key)
        final_state = str(trace[-1].get("to_state") or pod_ctx.get(pod_key, {}).get("state") or "IDLE")
        severity = severity_for_state(final_state)
        detected_at = max(iso_to_timestamp(str(step.get("observed_at") or "")) for step in trace)
        suspect = primary_suspect or pod_key
        pod_scenarios[pod_key].add(summary_label)
        alerts[(summary_label, severity, suspect)] = 1.0
        last_detection[(summary_label, suspect)] = max(last_detection[(summary_label, suspect)], detected_at)
        if progress_ratio(final_state) >= 1.0:
            critical_alerts[(summary_label, suspect)] = 1.0
        if pod_key not in pod_ctx:
            namespace, pod = split_pod_key(pod_key)
            pod_ctx[pod_key] = {
                "namespace": namespace,
                "pod": pod,
                "state": final_state,
                "progress": progress_ratio(final_state),
                "progress_level": PROGRESS_LEVEL.get(final_state, 0),
                "display_state": final_state if final_state in PROGRESS_LEVEL else "IDLE",
                "severity": severity,
                "is_primary": pod_key == primary_suspect,
                "is_secondary": pod_key in secondary_suspects,
                "observed_symbols": set(),
                "symbols_ordered": tuple(),
                "symbol_trace_len": 0,
                "matched_flow_count": 0,
                "detection_count": 0,
                "display_score": progress_ratio(final_state),
                "role": node_role(
                    pod_key=pod_key,
                    primary_suspect=primary_suspect,
                    secondary_suspects=secondary_suspects,
                    symbols=set(),
                ),
                "peer_pods": set(),
            }

    for pod_key in list(pod_ctx):
        if not pod_scenarios[pod_key]:
            pod_scenarios[pod_key].add(summary_label if pod_key in related_pods else "state_tracking")

    unique_edges: dict[tuple[str, str], dict[str, Any]] = {}
    for edge in ((correlation.get("graph") or {}).get("edges") or []):
        source = str(edge.get("source") or "").strip()
        target = str(edge.get("target") or "").strip()
        if not source or not target:
            continue
        ensure_pod_context(pod_ctx, pod_scenarios, source, summary_label, related_pods, primary_suspect)
        ensure_pod_context(pod_ctx, pod_scenarios, target, summary_label, related_pods, primary_suspect)
        key = (source, target)
        ts = iso_to_timestamp(str(edge.get("observed_at") or edge.get("ingested_at") or ""))
        if key not in unique_edges or ts >= unique_edges[key]["ts"]:
            unique_edges[key] = {
                "source": source,
                "target": target,
                "edge_type": str(edge.get("edge_type") or "network_flow"),
                "active": bool(edge.get("is_active_path", False)),
                "ts": ts,
            }

    candidate_pods = {pod_key for pod_key in explicit_candidate_pods if pod_key in pod_ctx}
    if not candidate_pods:
        candidate_pods.update(
            pod_key
            for pod_key, ctx in pod_ctx.items()
            if has_attack_evidence(ctx) and not is_excluded_system_pod(pod_key)
        )
    if not candidate_pods:
        candidate_pods.update(
            pod_key
            for pod_key, ctx in pod_ctx.items()
            if has_attack_evidence(ctx) and (pod_key == primary_suspect or pod_key in secondary_suspects)
        )

    preferred_edges: list[dict[str, Any]] = []
    secondary_edges: list[dict[str, Any]] = []
    for edge in sorted(unique_edges.values(), key=lambda item: (item["source"], item["target"])):
        source = str(edge["source"])
        target = str(edge["target"])
        if source not in candidate_pods or target not in candidate_pods:
            continue
        source_ctx = pod_ctx.get(source, {})
        target_ctx = pod_ctx.get(target, {})
        source_non_system = is_non_system_pod(source)
        target_non_system = is_non_system_pod(target)
        connects_primary_to_non_system = (
            (source == primary_suspect and target_non_system)
            or (target == primary_suspect and source_non_system)
        )
        both_non_system = source_non_system and target_non_system
        if both_non_system or connects_primary_to_non_system:
            preferred_edges.append(edge)
            continue
        if source in hard_anchor_pods and target in hard_anchor_pods and both_non_system:
            preferred_edges.append(edge)
            continue
        if (source in hard_anchor_pods or target in hard_anchor_pods) and not (is_excluded_system_pod(source) or is_excluded_system_pod(target)):
            secondary_edges.append(edge)

    filtered_edges = preferred_edges or secondary_edges
    if not filtered_edges and candidate_pods:
        filtered_edges = [
            edge
            for edge in sorted(unique_edges.values(), key=lambda item: item["ts"], reverse=True)
            if edge["source"] in candidate_pods
            and edge["target"] in candidate_pods
            and is_non_system_pod(edge["source"])
            and is_non_system_pod(edge["target"])
            and (has_attack_evidence(pod_ctx.get(edge["source"], {})) or has_attack_evidence(pod_ctx.get(edge["target"], {})))
        ][:5]

    final_pod_keys = {
        pod_key
        for pod_key in candidate_pods
        if (
            is_non_system_pod(pod_key)
            or pod_key == primary_suspect
            or any(edge["source"] == pod_key or edge["target"] == pod_key for edge in filtered_edges)
        )
    }
    if filtered_edges:
        final_pod_keys.update({edge["source"] for edge in filtered_edges})
        final_pod_keys.update({edge["target"] for edge in filtered_edges})
    elif primary_suspect and primary_suspect in pod_ctx:
        final_pod_keys = {primary_suspect}

    node_entries: list[NodeEntry] = []
    for pod_key in sorted(pod_key for pod_key in final_pod_keys if pod_key in pod_ctx):
        ctx = pod_ctx[pod_key]
        scenario = pick_primary_scenario(pod_scenarios[pod_key], summary_label)
        symbols_ordered = tuple(ctx.get("symbols_ordered") or ())
        ui_state = ui_state_for_node(ctx)
        ui_severity = ui_severity_for_state(ui_state)
        progress = float(ctx["progress"])
        progress_level = int(ctx.get("progress_level", PROGRESS_LEVEL.get(ui_state, 0)))
        display_score = float(ctx.get("display_score") or progress)
        node_entries.append(
            NodeEntry(
                id=pod_key,
                title=str(ctx["pod"]),
                subtitle=str(ctx["namespace"]),
                mainstat=f"DISPLAY: {ui_state}",
                secondarystat=f"fsm: {ctx['state']} progress={progress_level} {format_symbols(symbols_ordered)}",
                color=DISPLAY_STATE_COLOR[ui_state],
                scenario=scenario,
                severity=ui_severity,
                state=str(ctx["state"]),
                namespace=str(ctx["namespace"]),
                pod=str(ctx["pod"]),
                progress=progress,
                progress_level=progress_level,
                display_state=ui_state,
                display_score=display_score,
                threat_score=round(display_score * 100.0, 2),
                role=str(ctx.get("role") or "support"),
                symbols=symbols_ordered,
                ui_state=ui_state,
                ui_severity=ui_severity,
                highlighted=ui_state != "IDLE" or bool(ctx["is_primary"]),
            )
        )
        if progress >= 1.0:
            critical_alerts[(scenario, primary_suspect or pod_key)] = 1.0

    edge_entries: list[EdgeEntry] = []
    for edge in filtered_edges:
        source_ctx = pod_ctx.get(edge["source"], {})
        target_ctx = pod_ctx.get(edge["target"], {})
        source_ui_state = ui_state_for_node(source_ctx)
        target_ui_state = ui_state_for_node(target_ctx)
        severity = max_severity(ui_severity_for_state(source_ui_state), ui_severity_for_state(target_ui_state))
        score = edge_score(source_ctx, target_ctx)
        if edge["source"] == primary_suspect or edge["target"] == primary_suspect:
            severity = max_severity(severity, "Suspicious")
        if float(source_ctx.get("progress") or 0.0) >= 1.0 or float(target_ctx.get("progress") or 0.0) >= 1.0:
            severity = "Critical"
        scenario_set = set()
        scenario_set.update(pod_scenarios.get(edge["source"], set()))
        scenario_set.update(pod_scenarios.get(edge["target"], set()))
        if not scenario_set:
            scenario_set.add(summary_label if edge["source"] in related_pods or edge["target"] in related_pods else edge["edge_type"])
        relation = edge_relation_label(
            str(edge["edge_type"]),
            set(source_ctx.get("observed_symbols") or set()),
            set(target_ctx.get("observed_symbols") or set()),
            summary_symbols,
        )
        chain_text = edge_chain_text(source_ctx, target_ctx)
        for scenario in sorted(scenario_set):
            source_key = str(edge["source"])
            target_key = str(edge["target"])
            edge_entries.append(
                EdgeEntry(
                    id=f"{source_key}->{target_key}::{scenario}",
                    source=source_key,
                    target=target_key,
                    mainstat=relation,
                    secondarystat=chain_text if chain_text != "source → target" else f"{severity.lower()}: source → target",
                    color=SEVERITY_COLOR[severity],
                    scenario=scenario,
                    severity=severity,
                    response_status="active" if edge["active"] else "observed",
                    edge_type=str(edge["edge_type"]),
                    relation=relation,
                    highlighted=severity != "Normal",
                )
            )
            if severity == "Critical":
                critical_alerts[(scenario, primary_suspect or source_key)] = 1.0

    if not alerts and detection_summary:
        fallback_severity = PRIORITY_SEVERITY.get(str(detection_summary.get("highest_priority") or "none").lower(), "Normal")
        fallback_suspect = primary_suspect or "unknown"
        alerts[(summary_label, fallback_severity, fallback_suspect)] = 1.0
        last_detection[(summary_label, fallback_suspect)] = iso_to_timestamp(str(detection_summary.get("generated_at") or ""))

    if debug_summary:
        last_written = iso_to_timestamp(str(debug_summary.get("last_result_written_at") or ""))
        if last_written > 0:
            last_detection[("cluster-wide", primary_suspect or "unknown")] = last_written

    return {
        "generated_at": correlation.get("generated_at") or detection_summary.get("generated_at") or "",
        "detector_up": detector_up,
        "primary_suspect_pod": primary_suspect,
        "summary_label": summary_label,
        "nodes": node_entries,
        "edges": edge_entries,
        "alerts": alerts,
        "critical_alerts": critical_alerts,
        "correlated_totals": correlated_totals,
        "last_detection": last_detection,
    }


def graph_payload_to_json(graph: dict[str, Any]) -> dict[str, Any]:
    return {
        "generated_at": graph["generated_at"],
        "primary_suspect_pod": graph["primary_suspect_pod"],
        "summary_label": graph["summary_label"],
        "nodes": [
            {
                **{
                    "id": node.id,
                    "title": node.title,
                    "subtitle": node.subtitle,
                    "mainstat": node.mainstat,
                    "secondarystat": node.secondarystat,
                    "color": node.color,
                    "highlighted": node.highlighted,
                    "detail__state": node.state,
                    "detail__severity": node.severity,
                    "detail__scenario": node.scenario,
                    "detail__namespace": node.namespace,
                    "detail__pod": node.pod,
                    "detail__role": node.role,
                    "detail__symbols": ",".join(node.symbols),
                    "detail__score": round(node.display_score, 2),
                    "detail__progress_ratio": round(node.progress, 2),
                    "detail__progress_level": node.progress_level,
                    "detail__display_state": node.display_state,
                    "detail__ui_severity": node.ui_severity,
                    "detail__ui_state": node.ui_state,
                    "detail__threat_score": round(node.threat_score, 2),
                    "detail__color": node.color,
                },
                **make_arc_values(node.ui_state),
            }
            for node in graph["nodes"]
        ],
        "edges": [
            {
                "id": edge.id,
                "source": edge.source,
                "target": edge.target,
                "mainstat": edge.mainstat,
                "secondarystat": edge.secondarystat,
                "color": edge.color,
                "highlighted": edge.highlighted,
                "detail__scenario": edge.scenario,
                "detail__severity": edge.severity,
                "detail__response_status": edge.response_status,
                "detail__edge_type": edge.edge_type,
                "detail__relation": edge.relation,
            }
            for edge in graph["edges"]
        ],
    }


def graph_payload_to_nodegraph_api_data(graph: dict[str, Any]) -> dict[str, Any]:
    return {
        "nodes": [
            {
                **{
                    "id": node.id,
                    "title": node.title,
                    "subTitle": node.subtitle,
                    "mainStat": node.mainstat,
                    "secondaryStat": node.secondarystat,
                    "color": node.color,
                    "detail__state": node.state,
                    "detail__severity": node.severity,
                    "detail__scenario": node.scenario,
                    "detail__namespace": node.namespace,
                    "detail__pod": node.pod,
                    "detail__role": node.role,
                    "detail__symbols": ",".join(node.symbols),
                    "detail__score": round(node.display_score, 2),
                    "detail__progress_ratio": round(node.progress, 2),
                    "detail__progress_level": node.progress_level,
                    "detail__display_state": node.display_state,
                    "detail__ui_severity": node.ui_severity,
                    "detail__ui_state": node.ui_state,
                    "detail__threat_score": round(node.threat_score, 2),
                    "detail__color": node.color,
                },
                **make_arc_values(node.ui_state),
            }
            for node in graph["nodes"]
        ],
        "edges": [
            {
                "id": edge.id,
                "source": edge.source,
                "target": edge.target,
                "mainStat": edge.mainstat,
                "secondaryStat": edge.secondarystat,
                "detail__scenario": edge.scenario,
                "detail__severity": edge.severity,
                "detail__response_status": edge.response_status,
                "detail__edge_type": edge.edge_type,
                "detail__relation": edge.relation,
                "detail__color": edge.color,
            }
            for edge in graph["edges"]
        ],
    }


def graph_fields_for_nodegraph_api() -> dict[str, Any]:
    node_fields = [
        {"field_name": "id", "type": "string"},
        {"field_name": "title", "type": "string"},
        {"field_name": "subTitle", "type": "string"},
        {"field_name": "mainStat", "type": "string"},
        {"field_name": "secondaryStat", "type": "string"},
        {"field_name": "color", "type": "string"},
        {"field_name": "detail__state", "type": "string"},
        {"field_name": "detail__severity", "type": "string"},
        {"field_name": "detail__scenario", "type": "string"},
        {"field_name": "detail__namespace", "type": "string"},
        {"field_name": "detail__pod", "type": "string"},
        {"field_name": "detail__role", "type": "string"},
        {"field_name": "detail__symbols", "type": "string"},
        {"field_name": "detail__score", "type": "number"},
        {"field_name": "detail__progress_ratio", "type": "number"},
        {"field_name": "detail__progress_level", "type": "number"},
        {"field_name": "detail__display_state", "type": "string"},
        {"field_name": "detail__ui_severity", "type": "string"},
        {"field_name": "detail__ui_state", "type": "string"},
        {"field_name": "detail__threat_score", "type": "number"},
        {"field_name": "detail__color", "type": "string"},
        {"field_name": "arc__alert", "type": "number"},
        {"field_name": "arc__lateral", "type": "number"},
        {"field_name": "arc__cred", "type": "number"},
        {"field_name": "arc__recon", "type": "number"},
        {"field_name": "arc__idle", "type": "number"},
        {"field_name": "arc__follow", "type": "number"},
        {"field_name": "arc__tracking", "type": "number"},
    ]
    edge_fields = [
        {"field_name": "id", "type": "string"},
        {"field_name": "source", "type": "string"},
        {"field_name": "target", "type": "string"},
        {"field_name": "mainStat", "type": "string"},
        {"field_name": "secondaryStat", "type": "string"},
        {"field_name": "detail__scenario", "type": "string"},
        {"field_name": "detail__severity", "type": "string"},
        {"field_name": "detail__response_status", "type": "string"},
        {"field_name": "detail__edge_type", "type": "string"},
        {"field_name": "detail__relation", "type": "string"},
        {"field_name": "detail__color", "type": "string"},
    ]
    return {
        "nodes_fields": node_fields,
        "edges_fields": edge_fields,
        "node_fields": node_fields,
        "edge_fields": edge_fields,
    }


def build_metrics(
    *,
    correlation: dict[str, Any],
    detection_summary: dict[str, Any],
    debug_summary: dict[str, Any],
    staleness_seconds: int,
) -> str:
    graph = build_graph_payload(
        correlation=correlation,
        detection_summary=detection_summary,
        debug_summary=debug_summary,
        staleness_seconds=staleness_seconds,
    )

    writer = MetricWriter()
    writer.header("poding_detector_up", "gauge", "Whether the latest Pod-ing JSON output is fresh.")
    writer.header("poding_alert_active", "gauge", "Active Pod-ing alerts by scenario, severity, and primary suspect pod.")
    writer.header("poding_critical_alert_active", "gauge", "Critical Pod-ing alerts by scenario and primary suspect pod.")
    writer.header("poding_fsm_progress_ratio", "gauge", "FSM progress ratio derived from Pod-ing current state.")
    writer.header("poding_fsm_progress_level", "gauge", "FSM progress level used by Grafana display_state coloring.")
    writer.header("poding_threat_score", "gauge", "Derived Pod-ing threat score from current state and suspect role.")
    writer.header("poding_attack_node_state", "gauge", "Current attack graph node state score for each pod.")
    writer.header("poding_attack_edge_active", "gauge", "Current attack graph edges derived from correlation graph.")
    writer.header("poding_correlated_alerts_total", "gauge", "Current correlated alert count grouped by scenario and severity.")
    writer.header("poding_last_detection_timestamp_seconds", "gauge", "Latest detection timestamp per scenario and primary suspect pod.")

    writer.sample("poding_detector_up", graph["detector_up"], {"namespace": "poding-system"})

    for node in graph["nodes"]:
        writer.sample(
            "poding_fsm_progress_ratio",
            node.progress,
            {
                "namespace": node.namespace,
                "pod": node.pod,
                "scenario": node.scenario,
                "state": node.state,
            },
        )
        writer.sample(
            "poding_fsm_progress_level",
            node.progress_level,
            {
                "namespace": node.namespace,
                "pod": node.pod,
                "scenario": node.scenario,
                "state": node.state,
                "display_state": node.display_state,
            },
        )
        writer.sample(
            "poding_threat_score",
            node.threat_score,
            {
                "namespace": node.namespace,
                "pod": node.pod,
                "scenario": node.scenario,
            },
        )
        writer.sample(
            "poding_attack_node_state",
            node.progress_level,
            {
                "namespace": node.namespace,
                "pod": node.pod,
                "scenario": node.scenario,
                "state": node.state,
                "display_state": node.display_state,
                "severity": node.severity,
                "id": node.id,
                "title": node.title,
                "subtitle": node.subtitle,
                "mainstat": node.mainstat,
                "secondarystat": node.secondarystat,
                "color": node.color,
                "detail__state": node.state,
                "detail__severity": node.severity,
                "detail__scenario": node.scenario,
                "detail__namespace": node.namespace,
                "detail__pod": node.pod,
                "detail__role": node.role,
                "detail__symbols": ",".join(node.symbols),
                "detail__score": round(node.display_score, 2),
                "detail__progress_ratio": round(node.progress, 2),
                "detail__progress_level": node.progress_level,
                "detail__display_state": node.display_state,
                "detail__ui_severity": node.ui_severity,
                "detail__ui_state": node.ui_state,
            },
        )

    for edge in graph["edges"]:
        source_ns, source_pod = split_pod_key(edge.source)
        target_ns, target_pod = split_pod_key(edge.target)
        writer.sample(
            "poding_attack_edge_active",
            1.0,
            {
                "source_namespace": source_ns,
                "source_pod": source_pod,
                "target_namespace": target_ns,
                "target_pod": target_pod,
                "scenario": edge.scenario,
                "severity": edge.severity,
                "response_status": edge.response_status,
                "id": edge.id,
                "source": edge.source,
                "target": edge.target,
                "mainstat": edge.mainstat,
                "secondarystat": edge.secondarystat,
                "color": edge.color,
                "detail__scenario": edge.scenario,
                "detail__severity": edge.severity,
                "detail__response_status": edge.response_status,
                "detail__edge_type": edge.edge_type,
                "detail__relation": edge.relation,
            },
        )

    for (scenario, severity, suspect), value in sorted(graph["alerts"].items()):
        writer.sample(
            "poding_alert_active",
            value,
            {
                "scenario": scenario,
                "severity": severity,
                "primary_suspect_pod": suspect,
            },
        )

    for (scenario, suspect), value in sorted(graph["critical_alerts"].items()):
        writer.sample(
            "poding_critical_alert_active",
            value,
            {
                "scenario": scenario,
                "primary_suspect_pod": suspect,
            },
        )

    for (scenario, severity), value in sorted(graph["correlated_totals"].items()):
        writer.sample(
            "poding_correlated_alerts_total",
            value,
            {
                "scenario": scenario,
                "severity": severity,
            },
        )

    for (scenario, suspect), timestamp in sorted(graph["last_detection"].items()):
        if timestamp > 0:
            writer.sample(
                "poding_last_detection_timestamp_seconds",
                timestamp,
                {
                    "scenario": scenario,
                    "primary_suspect_pod": suspect,
                },
            )

    return writer.render()


class Exporter:
    def __init__(self, correlation_file: Path, detection_file: Path, debug_file: Path, staleness_seconds: int) -> None:
        self.correlation_file = correlation_file
        self.detection_file = detection_file
        self.debug_file = debug_file
        self.staleness_seconds = staleness_seconds

    def load_sources(self) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        return (
            load_json(self.correlation_file),
            load_json(self.detection_file),
            load_json(self.debug_file),
        )

    def collect(self) -> str:
        correlation, detection_summary, debug_summary = self.load_sources()
        return build_metrics(
            correlation=correlation,
            detection_summary=detection_summary,
            debug_summary=debug_summary,
            staleness_seconds=self.staleness_seconds,
        )

    def graph_json(self) -> dict[str, Any]:
        correlation, detection_summary, debug_summary = self.load_sources()
        graph = build_graph_payload(
            correlation=correlation,
            detection_summary=detection_summary,
            debug_summary=debug_summary,
            staleness_seconds=self.staleness_seconds,
        )
        return graph_payload_to_json(graph)

    def nodegraph_api_data(self) -> dict[str, Any]:
        correlation, detection_summary, debug_summary = self.load_sources()
        graph = build_graph_payload(
            correlation=correlation,
            detection_summary=detection_summary,
            debug_summary=debug_summary,
            staleness_seconds=self.staleness_seconds,
        )
        return graph_payload_to_nodegraph_api_data(graph)


class Handler(BaseHTTPRequestHandler):
    exporter: Exporter

    def do_GET(self) -> None:  # noqa: N802
        request_path = urlsplit(self.path).path
        if request_path in {"/", "/health", "/api/health", "/nodegraphds/api/health"}:
            self._write(HTTPStatus.OK, b'{"status":"ok"}', "application/json")
            return
        if request_path == "/healthz":
            self._write(HTTPStatus.OK, b'{"status":"ok"}', "application/json")
            return
        if request_path == "/metrics":
            body = self.exporter.collect().encode("utf-8")
            self._write(HTTPStatus.OK, body, "text/plain; version=0.0.4; charset=utf-8")
            return
        if request_path in {"/api/graph/fields", "/nodegraphds/api/graph/fields"}:
            body = json.dumps(graph_fields_for_nodegraph_api(), ensure_ascii=True).encode("utf-8")
            self._write(HTTPStatus.OK, body, "application/json")
            return
        if request_path in {"/api/graph/data", "/nodegraphds/api/graph/data"}:
            body = json.dumps(self.exporter.nodegraph_api_data(), ensure_ascii=True).encode("utf-8")
            self._write(HTTPStatus.OK, body, "application/json")
            return
        if request_path in {"/api/graph", "/graph"}:
            body = json.dumps(self.exporter.graph_json(), ensure_ascii=True).encode("utf-8")
            self._write(HTTPStatus.OK, body, "application/json")
            return
        if request_path == "/graph/nodes":
            body = json.dumps(self.exporter.graph_json()["nodes"], ensure_ascii=True).encode("utf-8")
            self._write(HTTPStatus.OK, body, "application/json")
            return
        if request_path == "/graph/edges":
            body = json.dumps(self.exporter.graph_json()["edges"], ensure_ascii=True).encode("utf-8")
            self._write(HTTPStatus.OK, body, "application/json")
            return
        self._write(HTTPStatus.NOT_FOUND, b'{"error":"not found"}', "application/json")

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _write(self, status: HTTPStatus, body: bytes, content_type: str) -> None:
        self.send_response(status.value)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    args = parse_args()
    results_dir = Path(args.results_dir)
    exporter = Exporter(
        correlation_file=Path(args.correlation_file) if args.correlation_file else results_dir / "latest_correlation.json",
        detection_file=Path(args.detection_summary_file) if args.detection_summary_file else results_dir / "latest_detection_summary.json",
        debug_file=Path(args.debug_summary_file) if args.debug_summary_file else results_dir / "latest_debug_summary.json",
        staleness_seconds=args.staleness_seconds,
    )
    if args.once:
        print(exporter.collect(), end="")
        return
    Handler.exporter = exporter
    server = ThreadingHTTPServer((args.listen_host, args.listen_port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

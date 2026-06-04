from __future__ import annotations

from typing import Any, Dict, List

from engine.fsm import PodFSM, load_symbol_mapping
from engine.graph import GraphManager
from engine.models import STATE_ORDER, utc_now


def build_correlation_result(
    *,
    cluster_name: str,
    pod_key: str,
    pod_fsm: PodFSM,
    graph_manager: GraphManager,
) -> Dict[str, Any]:
    primary_detection = pod_fsm.primary_detection() or {}
    detections = list(pod_fsm.completed_detections)
    explanation = (
        "This result was produced by YAML rule-based Falco and Hubble evidence mapped into FSM symbols and "
        "executed with an NFA model. Multiple partial matches can remain active for the same pod, unrelated "
        "noise events do not invalidate a path, and detections are emitted only when an explicit rule chain completes."
    )

    return {
        "schema_version": "0.3.0",
        "result_id": f"corr-{pod_key.replace('/', '-')}",
        "generated_at": utc_now(),
        "detection_scope": {
            "cluster_name": cluster_name,
            "entity_type": "pod",
            "entity_id": pod_key,
            "namespace": pod_fsm.metadata.get("namespace", ""),
            "workload_name": pod_fsm.metadata.get("workload_name", ""),
        },
        "fsm": {
            "execution_model": pod_fsm.execution_model,
            "current_state": pod_fsm.current_state,
            "previous_state": pod_fsm.previous_state,
            "active_states": pod_fsm.active_states,
            "candidate_next_states": pod_fsm.candidate_next_states,
            "active_partial_match_count": len(pod_fsm.active_partial_matches()),
            "completed_detection_count": len(detections),
            "ongoing_detection": pod_fsm.is_ongoing_detection,
            "transition_trigger": pod_fsm.transition_trigger,
            "last_transition_at": pod_fsm.last_transition_at,
        },
        "evidence": {
            "time_window": pod_fsm.time_window(),
            "source_events": pod_fsm.source_events,
            "observed_symbols": pod_fsm.observed_symbols,
            "symbol_trace": pod_fsm.symbol_trace,
            "state_evidence_summary": pod_fsm.state_evidence_summary,
            "latest_evidence_note": pod_fsm.latest_evidence_note,
            "matched_rules": pod_fsm.matched_rules,
            "matched_flow_patterns": pod_fsm.matched_flow_patterns,
            "correlation_dimensions": pod_fsm.correlation_dimensions,
            "correlation_keys": pod_fsm.formatted_correlation_keys(),
            "key_match_summary": pod_fsm.key_match_summary(),
            "state_trace": pod_fsm.state_trace,
            "active_partial_matches": pod_fsm.active_partial_matches(),
            "detections": detections,
            "primary_detection": primary_detection,
            "explanation": explanation,
        },
        "graph": graph_manager.build_graph(),
        "alert": {
            "priority": _highest_priority(detections, fallback_state=pod_fsm.current_state),
            "message": _alert_message(pod_key=pod_key, pod_fsm=pod_fsm, primary_detection=primary_detection),
            "recommended_action": "Inspect the scoped pod, matched event chain, and connected peer pods from the graph evidence.",
        },
    }


def build_cluster_snapshot(
    *,
    cluster_name: str,
    pod_fsms: dict[str, PodFSM],
    graph_manager: GraphManager,
) -> Dict[str, Any]:
    pod_results = {
        pod_key: build_correlation_result(
            cluster_name=cluster_name,
            pod_key=pod_key,
            pod_fsm=pod_fsm,
            graph_manager=graph_manager,
        )
        for pod_key, pod_fsm in sorted(pod_fsms.items())
    }

    state_counts: Dict[str, int] = {}
    ongoing_detection_count = 0
    for pod_fsm in pod_fsms.values():
        state_counts[pod_fsm.current_state] = state_counts.get(pod_fsm.current_state, 0) + 1
        if pod_fsm.is_ongoing_detection:
            ongoing_detection_count += 1

    return {
        "schema_version": "0.3.0",
        "snapshot_id": "cluster-wide-state-tracking",
        "generated_at": utc_now(),
        "cluster": {
            "cluster_name": cluster_name,
            "tracked_pod_count": len(pod_fsms),
            "ongoing_detection_count": ongoing_detection_count,
            "state_counts": state_counts,
        },
        "pods": pod_results,
        "graph": graph_manager.build_graph(),
    }


def build_detection_summary(
    *,
    snapshot: Dict[str, Any],
    label: str,
) -> Dict[str, Any]:
    detection_scope = snapshot.get("detection_scope", {}) or {}
    if isinstance(snapshot.get("pods"), dict):
        pods = snapshot.get("pods", {}) or {}
    else:
        pod_key = str(detection_scope.get("entity_id", "")).strip()
        pods = {pod_key: snapshot} if pod_key else {}
    ranked_pods = _rank_pod_candidates(pods=pods)
    relevant_pods = _select_relevant_pods(snapshot=snapshot, pods=pods, ranked_pods=ranked_pods)
    related_pods = sorted(relevant_pods.keys())
    primary_suspect_pod = ranked_pods[0] if ranked_pods else ""
    secondary_suspect_pods = [pod_key for pod_key in ranked_pods[1:] if pod_key in relevant_pods]
    falco_rules: List[str] = []
    hubble_flow_summary: List[str] = []
    symbols = _ordered_symbol_sequence(relevant_pods, preferred_pod=primary_suspect_pod)
    detected_rules: List[str] = []
    fsm_state_trace: List[Dict[str, Any]] = []
    priorities: List[str] = []

    for pod_key, pod_result in relevant_pods.items():
        evidence = pod_result.get("evidence", {}) or {}

        for rule_name in evidence.get("matched_rules", []) or []:
            if rule_name and rule_name not in falco_rules:
                falco_rules.append(rule_name)

        for detection in evidence.get("detections", []) or []:
            rule_id = str(detection.get("rule_id", "")).strip()
            if rule_id and rule_id not in detected_rules:
                detected_rules.append(rule_id)
            priority = str(detection.get("priority", "")).strip().lower()
            if priority:
                priorities.append(priority)

        trace = evidence.get("state_trace", []) or []
        if trace:
            fsm_state_trace.append({"pod": pod_key, "trace": trace})

    related_pod_set = set(relevant_pods.keys())
    for edge in (snapshot.get("graph", {}) or {}).get("edges", []) or []:
        source = edge.get("source")
        target = edge.get("target")
        edge_type = edge.get("edge_type", "flow")
        observed_at = edge.get("observed_at", "")
        if not source or not target:
            continue
        if source not in related_pod_set and target not in related_pod_set:
            continue
        flow_text = f"{source} -> {target} ({edge_type})"
        if observed_at:
            flow_text = f"{flow_text} @ {observed_at}"
        if flow_text not in hubble_flow_summary:
            hubble_flow_summary.append(flow_text)

    highest_priority = "none"
    if priorities:
        highest_priority = max(priorities, key=lambda value: {"none": 0, "supporting": 1, "primary": 2}.get(value, 0))

    notes: List[str] = []
    if symbols and not fsm_state_trace:
        notes.append("Symbol evidence는 기록됐지만 아직 완성된 rule chain은 없을 수 있다.")
    if hubble_flow_summary and "E" not in symbols:
        notes.append("Hubble flow는 있었지만 stage mapping 결과가 lateral state와 연결되지 않았을 수 있다.")
    if not falco_rules and not hubble_flow_summary:
        notes.append("의미 있는 Falco/Hubble 이벤트가 아직 요약되지 않았다.")

    if highest_priority == "primary":
        final_judgement = "강한 탐지"
    elif fsm_state_trace:
        final_judgement = "부분 탐지"
    elif symbols or falco_rules or hubble_flow_summary:
        final_judgement = "행위 기록만 존재"
    else:
        final_judgement = "탐지 없음"

    return {
        "generated_at": snapshot.get("generated_at", utc_now()),
        "label": label,
        "primary_suspect_pod": primary_suspect_pod,
        "secondary_suspect_pods": secondary_suspect_pods,
        "related_pods": related_pods,
        "falco_rules": falco_rules,
        "hubble_flow_summary": hubble_flow_summary,
        "observed_symbols": symbols,
        "detected_rules": detected_rules,
        "state_trace": fsm_state_trace,
        "highest_priority": highest_priority,
        "final_judgement": final_judgement,
        "notes": notes,
        "pod_states": {
            pod_key: {
                "current_state": pod_result.get("fsm", {}).get("current_state", "IDLE"),
                "priority": pod_result.get("alert", {}).get("priority", "none"),
            }
            for pod_key, pod_result in relevant_pods.items()
        },
        "state_order": STATE_ORDER,
    }


def _select_relevant_pods(
    *,
    snapshot: Dict[str, Any],
    pods: Dict[str, Any],
    ranked_pods: List[str] | None = None,
) -> Dict[str, Any]:
    if not pods:
        return {}

    adjacency: Dict[str, set[str]] = {}
    for edge in (snapshot.get("graph", {}) or {}).get("edges", []) or []:
        source = str(edge.get("source", "")).strip()
        target = str(edge.get("target", "")).strip()
        if not source or not target:
            continue
        adjacency.setdefault(source, set()).add(target)
        adjacency.setdefault(target, set()).add(source)

    ranked = ranked_pods or _rank_pod_candidates(pods=pods)
    if ranked:
        primary_suspect = ranked[0]
        expanded_candidates = {primary_suspect}
        expanded_candidates.update(adjacency.get(primary_suspect, set()))
        for pod_key in ranked[1:]:
            if _has_falco_priority_evidence(pods.get(pod_key, {})):
                expanded_candidates.add(pod_key)
        return {pod_key: pods[pod_key] for pod_key in sorted(expanded_candidates) if pod_key in pods}

    secondary_candidates = {
        pod_key
        for pod_key, pod_result in pods.items()
        if bool((pod_result.get("evidence", {}) or {}).get("matched_rules", [])) or pod_key in adjacency
    }
    if secondary_candidates:
        return {pod_key: pods[pod_key] for pod_key in sorted(secondary_candidates) if pod_key in pods}

    tertiary_candidates = {
        pod_key
        for pod_key, pod_result in pods.items()
        if bool((pod_result.get("evidence", {}) or {}).get("observed_symbols", []))
    }
    if tertiary_candidates:
        return {pod_key: pods[pod_key] for pod_key in sorted(tertiary_candidates) if pod_key in pods}

    return pods


def _rank_pod_candidates(
    *,
    pods: Dict[str, Any],
) -> List[str]:
    scored: List[tuple[tuple[int, int, int, int, int, int, int], str]] = []
    for pod_key, pod_result in pods.items():
        score = _pod_candidate_score(pod_result)
        if any(score):
            scored.append((score, pod_key))
    scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return [pod_key for _, pod_key in scored]


def _pod_candidate_score(pod_result: Dict[str, Any]) -> tuple[int, int, int, int, int, int, int]:
    evidence = pod_result.get("evidence", {}) or {}
    fsm = pod_result.get("fsm", {}) or {}
    falco_symbols, hubble_symbols = _mapped_symbol_sources()
    observed_symbols = [str(symbol) for symbol in evidence.get("observed_symbols", []) or [] if symbol]
    falco_symbol_count = sum(1 for symbol in observed_symbols if symbol in falco_symbols)
    hubble_symbol_count = sum(1 for symbol in observed_symbols if symbol in hubble_symbols)
    matched_rules = evidence.get("matched_rules", []) or []
    detections = evidence.get("detections", []) or []
    active_partial_matches = evidence.get("active_partial_matches", []) or []
    current_state = str(fsm.get("current_state", "IDLE"))
    state_rank = STATE_ORDER.index(current_state) if current_state in STATE_ORDER else -1
    return (
        1 if matched_rules or falco_symbol_count > 0 else 0,
        len(matched_rules),
        falco_symbol_count,
        len(active_partial_matches),
        len(detections),
        1 if current_state != "IDLE" else 0,
        hubble_symbol_count + max(state_rank, 0),
    )


def _has_falco_priority_evidence(pod_result: Dict[str, Any]) -> bool:
    evidence = pod_result.get("evidence", {}) or {}
    falco_symbols, _ = _mapped_symbol_sources()
    observed_symbols = evidence.get("observed_symbols", []) or []
    if evidence.get("matched_rules", []) or evidence.get("active_partial_matches", []):
        return True
    return any(symbol in falco_symbols for symbol in observed_symbols)


def _mapped_symbol_sources() -> tuple[set[str], set[str]]:
    mapping = load_symbol_mapping()
    falco_symbols: set[str] = set()
    hubble_symbols: set[str] = set()

    falco_mapping = mapping.get("falco", {}) if isinstance(mapping, dict) else {}
    for section_name in ("rules", "normalized_types"):
        section = falco_mapping.get(section_name, {}) if isinstance(falco_mapping, dict) else {}
        for item in section.values() if isinstance(section, dict) else []:
            for symbol in item.get("symbols", []) if isinstance(item, dict) else []:
                text = str(symbol).strip()
                if text:
                    falco_symbols.add(text)

    hubble_mapping = mapping.get("hubble", {}) if isinstance(mapping, dict) else {}
    for item in hubble_mapping.get("conditions", []) if isinstance(hubble_mapping, dict) else []:
        for symbol in item.get("symbols", []) if isinstance(item, dict) else []:
            text = str(symbol).strip()
            if text:
                hubble_symbols.add(text)

    return falco_symbols, hubble_symbols


def _ordered_symbol_sequence(
    pods: Dict[str, Any],
    *,
    preferred_pod: str = "",
) -> List[str]:
    # observed_at-first ordering keeps the symbol sequence aligned with the
    # FSM's chain semantics (PDF p.17 "사후 시간 보정"): two sensors with
    # different ingestion delays should not flip the symbol order in the
    # summary just because one stream arrived at the detector first.
    symbol_entries: List[tuple[str, int, int, str]] = []

    def _collect(pod_result: Dict[str, Any]) -> None:
        evidence = pod_result.get("evidence", {}) or {}
        for index, item in enumerate(evidence.get("symbol_trace", []) or []):
            symbol = str(item.get("symbol", "")).strip()
            if not symbol:
                continue
            observed_at = str(item.get("observed_at", "")).strip()
            receive_order = item.get("receive_order")
            try:
                normalized_receive_order = (
                    int(receive_order) if receive_order is not None else 1 << 30
                )
            except (TypeError, ValueError):
                normalized_receive_order = 1 << 30
            symbol_entries.append((observed_at, normalized_receive_order, index, symbol))

    if preferred_pod and preferred_pod in pods:
        _collect(pods[preferred_pod])
    else:
        for pod_result in pods.values():
            _collect(pod_result)

    ordered_symbols: List[str] = []
    for _, _, _, symbol in sorted(symbol_entries):
        if symbol not in ordered_symbols:
            ordered_symbols.append(symbol)
    return ordered_symbols


def _highest_priority(detections: List[Dict[str, Any]], fallback_state: str) -> str:
    if detections:
        return max(
            (str(detection.get("priority", "supporting")).lower() for detection in detections),
            key=lambda value: {"none": 0, "supporting": 1, "primary": 2}.get(value, 0),
        )
    if fallback_state in {"LATERAL", "ALERT"}:
        return "supporting"
    return "none"


def _alert_message(
    *,
    pod_key: str,
    pod_fsm: PodFSM,
    primary_detection: Dict[str, Any],
) -> str:
    if primary_detection.get("rule_id"):
        return (
            f"{pod_key} matched `{primary_detection['rule_id']}` with state `{pod_fsm.current_state}` "
            f"at {primary_detection.get('detected_at', pod_fsm.last_transition_at)}."
        )
    if pod_fsm.active_partial_matches():
        return f"{pod_key} has active partial NFA matches up to state {pod_fsm.current_state}."
    return f"{pod_key} has no completed rule match yet."

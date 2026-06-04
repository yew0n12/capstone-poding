"""propagation-exporter

Serves a causal propagation graph derived from poding-detector's
latest_correlation.json + latest_detection_summary.json + latest_debug_summary.json.

Reads only. Original detector code is not modified.

Endpoints:
  GET  /healthz
  GET  /api/graph                Cytoscape elements from latest_*.json
  GET  /api/raw-hubble-graph     Troubleshooting graph from direct Hubble flows
  GET  /api/evidence/<edge_id>   Evidence for a single edge
  GET  /api/baseline             Current baseline status
  POST /api/baseline/reset       Restart the baseline window
  GET  /nodegraphds/api/graph/fields   Grafana NodeGraphAPI compat
  GET  /nodegraphds/api/graph/data     Grafana NodeGraphAPI compat from latest_*.json
  GET  /rawnodegraphds/api/graph/data  Raw Hubble troubleshooting NodeGraph data
  GET  /                         Static UI (Cytoscape SPA)

Edge grading:
  correlation : detector correlation / propagation relation
  related     : detector-related or partially suspicious relation
  observed    : correlation graph relation without an active threat state

Direct Hubble subscription is retained only as a troubleshooting endpoint and
is not mixed into the default Grafana graph.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from hubble_subscriber import attach_to_state as _attach_hubble_subscriber

RESULTS_DIR = Path(os.environ.get("PROPAGATION_RESULTS_DIR", "/home/yw/poding/results"))
UI_DIR = Path(os.environ.get("PROPAGATION_UI_DIR", str(Path(__file__).parent / "ui")))
LISTEN_HOST = os.environ.get("PROPAGATION_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("PROPAGATION_PORT", "9109"))
POLL_INTERVAL = float(os.environ.get("PROPAGATION_POLL_INTERVAL", "5"))
BASELINE_SECONDS = float(os.environ.get("PROPAGATION_BASELINE_SECONDS", "300"))
FREQ_SPIKE_RATIO = float(os.environ.get("PROPAGATION_FREQ_SPIKE", "3.0"))
ADVISORY_FILE = os.environ.get("PROPAGATION_ADVISORY_FILE", "")  # e.g. /var/lib/propagation/advisory.jsonl
ADVISORY_HOST = os.environ.get("PROPAGATION_ADVISORY_HOST", "propagation-advisory-shim")
ADVISORY_RULE = "Propagation Received From Suspect"


_state_lock = threading.Lock()
_state = {
    "baseline_started_at": time.time(),
    "baseline_active": True,
    "baseline_peers": defaultdict(set),
    "baseline_edge_counts": defaultdict(int),
    "live_edge_counts": defaultdict(int),
    "last_correlation_mtime": 0.0,
    "last_summary_mtime": 0.0,
    "graph": {"nodes": [], "edges": []},
    "debug_summary": {},
    "evidence_index": {},
    "last_built_at": None,
    "matched_pods": {},
    "matched_first_seen": {},  # pod_id -> ISO timestamp of first match observation
    "errors": [],
    "demo_overlay": False,
    "advised_targets": set(),  # frozen (src,dst) tuples we've already advised on
    "advisory_count": 0,
    "display_state_cache": {},  # pod_id -> visual-only display_state hold metadata
}


FSM_STATES = ["IDLE", "RECON", "CRED", "LATERAL", "ALERT"]
PROGRESS_LEVEL = {state: index for index, state in enumerate(FSM_STATES)}
DISPLAY_STATE_HOLD_SECONDS = float(os.environ.get("DISPLAY_STATE_HOLD_SECONDS", "3"))
DISPLAY_STATE_COLOR = {
    "IDLE": "#63B3ED",
    "RECON": "#F6E05E",
    "CRED": "#F6AD55",
    "LATERAL": "#DD6B20",
    "ALERT": "#E53E3E",
    "EXTERNAL": "#E53E3E",
    "UNTRACKED": "#A0AEC0",
}


def _demo_fsm_payload(pod_id: str) -> dict:
    """Synthesize FSM state for demo overlay pods."""
    name = pod_id[5:] if pod_id.startswith("demo:") else pod_id
    fixtures = {
        "external-203.0.113.5": {
            "current_state": "EXTERNAL",
            "active_states": [],
            "observed_symbols": ["X"],
            "transition_trigger": "External ingress observed (X).",
            "source_events": [
                {"rule_name": "external_origin", "event_type": "external_inbound",
                 "symbols": ["X"], "observed_at": "demo"},
            ],
        },
        "attack-lab-01/pod-a": {
            "current_state": "LATERAL",
            "active_states": ["LATERAL"],
            "candidate_next_states": ["ALERT"],
            "observed_symbols": ["E", "n", "k"],
            "transition_trigger": "lateral_movement_via_api: foothold_shell (s) -> api_access (k) -> east_west_propagation (E)",
            "source_events": [
                {"rule_name": "Terminal shell in container", "event_type": "shell_exec", "symbols": ["s"]},
                {"rule_name": "Contact K8S API Server From Container", "event_type": "k8s_api_access", "symbols": ["k"]},
                {"rule_name": "east_west_new_pod_connection", "event_type": "new_pod_connection", "symbols": ["E"]},
            ],
        },
        "attack-lab-01/pod-b": {
            "current_state": "LATERAL",
            "active_states": ["LATERAL"],
            "candidate_next_states": ["ALERT"],
            "observed_symbols": ["R", "n"],
            "transition_trigger": "cross_layer_propagation_target: propagation_received (R) -> target_runtime_activity needs s/n/b/k",
            "source_events": [
                {"rule_name": "Propagation Received From Suspect", "event_type": "propagation_received",
                 "symbols": ["R"], "from_source": "attack-lab-01/pod-a"},
                {"rule_name": "Pod-ing Netcat Execution in Container", "event_type": "network_tool_exec", "symbols": ["n"]},
            ],
        },
        "attack-lab-01/pod-c": {
            "current_state": "ALERT",
            "active_states": ["ALERT"],
            "candidate_next_states": [],
            "observed_symbols": ["R", "s", "n"],
            "transition_trigger": "cross_layer_propagation_target: R + (s,n) reached ALERT",
            "source_events": [
                {"rule_name": "Propagation Received From Suspect", "event_type": "propagation_received", "symbols": ["R"]},
                {"rule_name": "Terminal shell in container", "event_type": "shell_exec", "symbols": ["s"]},
                {"rule_name": "Pod-ing Netcat Execution in Container", "event_type": "network_tool_exec", "symbols": ["n"]},
            ],
        },
        "attack-lab-01/pod-d": {
            "current_state": "LATERAL",
            "active_states": ["LATERAL"],
            "candidate_next_states": ["ALERT"],
            "observed_symbols": ["R"],
            "transition_trigger": "cross_layer_propagation_target: R alone advances LATERAL; ALERT pending",
            "source_events": [
                {"rule_name": "Propagation Received From Suspect", "event_type": "propagation_received",
                 "symbols": ["R"], "from_source": "attack-lab-01/pod-c"},
            ],
        },
        "attack-lab-01/pod-e": {
            "current_state": "IDLE",
            "active_states": ["IDLE"],
            "observed_symbols": [],
            "transition_trigger": "received traffic from matched source but no own behavior change (adjacent edge, not propagation)",
            "source_events": [],
        },
        "attack-lab-01/pod-f": {
            "current_state": "IDLE",
            "active_states": ["IDLE"],
            "observed_symbols": [],
            "transition_trigger": "baseline traffic only",
            "source_events": [],
        },
    }
    base = fixtures.get(name)
    if not base:
        return {"pod_id": pod_id, "error": "no demo fixture", "current_state": "IDLE"}
    return {
        "pod_id": pod_id,
        "demo": True,
        "current_state": base["current_state"],
        "active_states": base.get("active_states", []),
        "candidate_next_states": base.get("candidate_next_states", []),
        "previous_state": base.get("previous_state"),
        "observed_symbols": base.get("observed_symbols", []),
        "transition_trigger": base.get("transition_trigger"),
        "source_events": base.get("source_events", []),
    }


def _real_fsm_payload(pod_id: str) -> dict:
    """Read per-pod FSM state from the detector's latest_correlation.json."""
    cor = _read_json(RESULTS_DIR / "latest_correlation.json") or {}
    pods = cor.get("pods") or {}
    pod = pods.get(pod_id)
    if not pod:
        return {"pod_id": pod_id, "error": "pod not tracked by detector",
                "current_state": "UNTRACKED",
                "hint": "detector adds pods to its FSM only when their events are observed; "
                        "attack-lab pods may need explicit Falco-rule-firing activity."}
    fsm = pod.get("fsm") or {}
    evidence = pod.get("evidence") or {}
    raw_events = evidence.get("source_events") or []
    symbol_trace = evidence.get("symbol_trace") or []
    # build event_id -> [symbols] from symbol_trace so we can attach to events
    sym_by_event: dict[str, list[str]] = {}
    for st in symbol_trace:
        eid = st.get("event_id")
        sym = st.get("symbol")
        if eid and sym:
            sym_by_event.setdefault(eid, []).append(sym)
    source_events = []
    for ev in raw_events[-20:]:
        eid = ev.get("event_id")
        source_events.append({
            "event_id": eid,
            "rule_name": ev.get("rule_name"),
            "event_type": ev.get("event_type"),
            "observed_at": ev.get("observed_at"),
            "symbols": sym_by_event.get(eid, []),
        })
    observed_symbols = list(evidence.get("observed_symbols") or [])
    state_trace = evidence.get("state_trace") or []
    return {
        "pod_id": pod_id,
        "demo": False,
        "current_state": fsm.get("current_state", "IDLE"),
        "previous_state": fsm.get("previous_state"),
        "active_states": fsm.get("active_states") or [],
        "candidate_next_states": fsm.get("candidate_next_states") or [],
        "ongoing_detection": fsm.get("ongoing_detection", False),
        "transition_trigger": fsm.get("transition_trigger"),
        "last_transition_at": fsm.get("last_transition_at"),
        "observed_symbols": observed_symbols,
        "source_events": source_events,
        "state_trace": [
            {"from": s.get("from_state"), "to": s.get("to_state"),
             "at": s.get("observed_at")}
            for s in state_trace[-10:]
        ],
        "matched_rules": list(evidence.get("matched_rules") or []),
    }


def _pod_fsm_payload(pod_id: str) -> dict:
    if pod_id.startswith("demo:"):
        return _demo_fsm_payload(pod_id)
    return _real_fsm_payload(pod_id)


def _emit_advisory(src: str, dst: str, edge_id: str, evidence: dict) -> None:
    """Append a Falco-shaped JSON line so the advisory shim pod's tail stream
    surfaces it through detector's existing kubectl-logs follower."""
    if not ADVISORY_FILE:
        return
    # Strip demo: prefix so synthetic edges still produce well-formed pod ids.
    src = src[5:] if src.startswith("demo:") else src
    dst = dst[5:] if dst.startswith("demo:") else dst
    key = (src, dst)
    if key in _state["advised_targets"]:
        return
    if not _is_pod_id(dst):
        return
    ns, _, name = dst.partition("/")
    # Microsecond precision so the detector's follower doesn't skip multiple
    # advisories emitted within the same second as "replayed".
    now_t = time.time()
    frac_ns = int((now_t - int(now_t)) * 1e9)
    now = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now_t)) + f".{frac_ns:09d}Z"
    payload = {
        "hostname": ADVISORY_HOST,
        "output": (f"{time.strftime('%H:%M:%S')} Notice "
                   f"propagation edge from {src} -> {dst} "
                   f"(deviation={','.join(evidence.get('baseline_deviation') or []) or 'none'}, "
                   f"target_activated={evidence.get('target_activated')})"),
        "rule": ADVISORY_RULE,
        "priority": "Notice",
        "source": "syscall",
        "tags": ["propagation", "cross_layer", "causal"],
        "time": now,
        "output_fields": {
            "k8s.ns.name": ns,
            "k8s.pod.name": name,
            "k8smeta.ns.name": ns,
            "k8smeta.pod.name": name,
            "container.name": "advisory-shim",
            "container.image.repository": "poding/propagation-advisory-shim",
            "container.image.tag": "v0.1",
            "evt.type": "propagation_received",
            "evt.time": int(time.time() * 1e9),
            "propagation.source_pod": src,
            "propagation.edge_id": edge_id,
            "propagation.baseline_deviation": ",".join(evidence.get("baseline_deviation") or []),
            "propagation.target_activated": str(evidence.get("target_activated", False)).lower(),
            "user.name": "advisory",
            "user.uid": 0,
            "user.loginuid": -1,
            "proc.name": "propagation-advisor",
            "proc.cmdline": f"advisory: {src} -> {dst}",
        },
    }
    line = json.dumps(payload, separators=(",", ":")) + "\n"
    try:
        path = Path(ADVISORY_FILE)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(line)
        _state["advised_targets"].add(key)
        _state["advisory_count"] += 1
    except OSError as exc:
        _state["errors"].append(f"{_now_iso()} advisory_emit: {exc}")
        del _state["errors"][:-20]


def _demo_overlay_payload() -> dict:
    """Synthetic 4-color propagation chain for visual demonstration.

    External attacker -> pod-a (compromised) -> pod-b (lateral, propagated)
                                             -> pod-c (lateral, propagated)
                                                  pod-c -> pod-d (chain propagation)
                                             -> pod-e (talked to, but not activated -> adjacent)
                                             -> pod-f (normal baseline contact)
    Marked classes prefixed with "demo" so they coexist with live data.
    """
    nodes = [
        {"data": {"id": "demo:external-203.0.113.5", "label": "203.0.113.5",
                  "namespace": "external", "type": "external",
                  "color": NODE_COLOR["external"], "fsm_state": "EXTERNAL",
                  "label_state": "EXTERNAL", "matched": {"role": "ingress"}}},
        {"data": {"id": "demo:attack-lab-01/pod-a", "label": "pod-a (matched)",
                  "namespace": "attack-lab-01", "type": "matched",
                  "color": NODE_COLOR["matched"], "fsm_state": "MATCHED",
                  "label_state": "MATCHED",
                  "matched": {"role": "primary", "matched_at": "2026-05-04T15:00:00Z",
                              "observed_symbols": ["E", "n", "k"],
                              "scenario": "demo-chain"}}},
        {"data": {"id": "demo:attack-lab-01/pod-b", "label": "pod-b (propagated)",
                  "namespace": "attack-lab-01", "type": "propagated",
                  "color": NODE_COLOR["propagated"], "fsm_state": "PROPAGATED",
                  "label_state": "PROPAGATED",
                  "matched": {"role": "target", "observed_symbols": ["n", "s"]}}},
        {"data": {"id": "demo:attack-lab-01/pod-c", "label": "pod-c (propagated)",
                  "namespace": "attack-lab-01", "type": "propagated",
                  "color": NODE_COLOR["propagated"], "fsm_state": "PROPAGATED",
                  "label_state": "PROPAGATED",
                  "matched": {"role": "target", "observed_symbols": ["n", "x"]}}},
        {"data": {"id": "demo:attack-lab-01/pod-d", "label": "pod-d (chain propagated)",
                  "namespace": "attack-lab-01", "type": "propagated",
                  "color": NODE_COLOR["propagated"], "fsm_state": "PROPAGATED",
                  "label_state": "PROPAGATED",
                  "matched": {"role": "chain", "observed_symbols": ["n"]}}},
        {"data": {"id": "demo:attack-lab-01/pod-e", "label": "pod-e (adjacent)",
                  "namespace": "attack-lab-01", "type": "adjacent",
                  "color": NODE_COLOR["adjacent"], "fsm_state": "IDLE",
                  "label_state": "ADJACENT",
                  "matched": {"role": "investigated", "note": "received traffic but no behavior change"}}},
        {"data": {"id": "demo:attack-lab-01/pod-f", "label": "pod-f (normal)",
                  "namespace": "attack-lab-01", "type": "normal",
                  "color": NODE_COLOR["normal"], "fsm_state": "IDLE",
                  "label_state": "NORMAL", "matched": {}}},
    ]

    def edge(eid, src, dst, grade, evidence):
        style = GRADE_STYLE[grade]
        return {"data": {"id": "demo:" + eid, "source": src, "target": dst,
                         "grade": grade, "color": style["color"], "width": style["width"],
                         "flow_count": 1, "edge_type": "network_flow",
                         "observed_at": "2026-05-04T15:00:30Z",
                         "evidence": evidence},
                "classes": grade}

    edges = [
        edge("ext-a", "demo:external-203.0.113.5", "demo:attack-lab-01/pod-a",
             "propagation", {"after_match": True, "baseline_deviation": ["external_origin"],
                             "target_activated": True, "src_matched": False, "dst_matched": True}),
        edge("a-b", "demo:attack-lab-01/pod-a", "demo:attack-lab-01/pod-b",
             "propagation", {"after_match": True, "baseline_deviation": ["new_peer"],
                             "target_activated": True, "src_matched": True, "dst_matched": True}),
        edge("a-c", "demo:attack-lab-01/pod-a", "demo:attack-lab-01/pod-c",
             "propagation", {"after_match": True, "baseline_deviation": ["new_peer", "freq_spike_5x"],
                             "target_activated": True, "src_matched": True, "dst_matched": True}),
        edge("c-d", "demo:attack-lab-01/pod-c", "demo:attack-lab-01/pod-d",
             "propagation", {"after_match": True, "baseline_deviation": ["new_peer"],
                             "target_activated": True, "src_matched": True, "dst_matched": True}),
        edge("a-e", "demo:attack-lab-01/pod-a", "demo:attack-lab-01/pod-e",
             "adjacent", {"after_match": True, "baseline_deviation": ["new_peer"],
                          "target_activated": False, "src_matched": True, "dst_matched": False}),
        edge("a-f", "demo:attack-lab-01/pod-a", "demo:attack-lab-01/pod-f",
             "baseline", {"after_match": True, "baseline_deviation": [],
                          "target_activated": False, "src_matched": True, "dst_matched": False}),
    ]
    # merge raw Hubble nodes + edges
    try:
        raw = _build_raw_hubble_graph()
        all_node_ids = {n["id"] for n in nodes}
        for rn in raw.get("nodes", []):
            rid = rn.get("id","")
            ns = rid.split("/")[0] if "/" in rid else ""
            if rid.startswith("<NA>") or rid.startswith("external"):
                continue
            if rid not in all_node_ids:
                nodes.append({"id": rid, "title": rid.split("/")[-1],
                    "subTitle": ns, "mainStat": "DISPLAY: IDLE",
                    "secondaryStat": "fsm: IDLE type: normal progress=0",
                    "color": "#63B3ED",
                    "detail__type": "normal", "detail__fsm_state": "IDLE",
                    "detail__display_state": "IDLE", "detail__progress_level": 0,
                    "detail__priority": "none", "detail__namespace": ns})
                all_node_ids.add(rid)
        for e in raw.get("edges", []):
            src, tgt = e.get("source",""), e.get("target","")
            if src in all_node_ids and tgt in all_node_ids:
                eid = f"raw-{src}-{tgt}"
                if not any(ex["id"] == eid for ex in edges):
                    edges.append({"id": eid, "source": src, "target": tgt,
                        "mainStat": "grade: observed", "secondaryStat": "hubble flow",
                        "color": "#4A5568",
                        "detail__grade": "observed", "detail__relation_type": "network_flow",
                        "detail__symbols": "-", "detail__src_state": "-",
                        "detail__dst_state": "-", "detail__after_match": "",
                        "detail__deviation": "-", "detail__target_activated": ""})
    except Exception:
        pass
    return {"nodes": nodes, "edges": edges}


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _read_json(path: Path) -> dict | None:
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        with _state_lock:
            errs = _state["errors"]
            errs.append(f"{_now_iso()} {path.name}: {exc}")
            del errs[:-20]
        return None


def _is_pod_id(node_id: str) -> bool:
    return isinstance(node_id, str) and "/" in node_id and not node_id.startswith("external")


def _matched_pods_from_summary(summary: dict | None) -> dict[str, dict]:
    if not summary:
        return {}
    out: dict[str, dict] = {}
    matched_at = summary.get("generated_at") or _now_iso()
    primary = summary.get("primary_suspect_pod")
    if primary and _is_pod_id(primary):
        out[primary] = {
            "matched_at": matched_at,
            "role": "primary",
            "observed_symbols": summary.get("observed_symbols") or [],
            "scenario": summary.get("label"),
            "severity": summary.get("highest_priority") or "Unknown",
        }
    for sec in summary.get("secondary_suspect_pods") or []:
        if not _is_pod_id(sec) or sec in out:
            continue
        out[sec] = {
            "matched_at": matched_at,
            "role": "secondary",
            "observed_symbols": summary.get("observed_symbols") or [],
            "scenario": summary.get("label"),
            "severity": summary.get("highest_priority") or "Unknown",
        }
    return out


def _matched_pods_from_correlation(correlation: dict | None,
                                   matched: dict[str, dict]) -> None:
    if not correlation:
        return
    pods = correlation.get("pods") or {}
    if not isinstance(pods, dict):
        return
    for pod_id, body in pods.items():
        if not _is_pod_id(pod_id):
            continue
        fsm = (body or {}).get("fsm") or {}
        # detector schema uses "current_state"; older code uses "state".
        state = fsm.get("current_state") or fsm.get("state") or "IDLE"
        observed = ((body or {}).get("evidence") or {}).get("observed_symbols") \
            or fsm.get("observed_symbols") or []
        if state != "IDLE" or observed:
            entry = matched.setdefault(pod_id, {
                "matched_at": fsm.get("entered_state_at") or fsm.get("last_transition_at") or _now_iso(),
                "role": "matched",
                "observed_symbols": observed,
                "scenario": (body.get("alert") or {}).get("scenario"),
                "severity": (body.get("alert") or {}).get("severity") or "Unknown",
            })
            if observed and not entry.get("observed_symbols"):
                entry["observed_symbols"] = observed
            # Strong = FSM advanced past IDLE; weak = symbols present, state still IDLE.
            entry["match_strength"] = "strong" if state != "IDLE" else "weak"
            entry["fsm_state"] = state


def _classify_edge(edge: dict, matched: dict[str, dict],
                   baseline_peers: dict[str, set],
                   baseline_active: bool) -> tuple[str, dict]:
    src = edge.get("source")
    dst = edge.get("target")
    observed_at = edge.get("observed_at") or ""
    src_match = matched.get(src)
    dst_match = matched.get(dst)

    deviation: list[str] = []
    if src and dst and dst not in baseline_peers.get(src, set()):
        deviation.append("new_peer")
    if not _is_pod_id(src or ""):
        deviation.append("external_origin")

    src_count = _state["live_edge_counts"].get(src, 0)
    base_count = _state["baseline_edge_counts"].get(src, 0)
    if base_count > 0 and src_count > base_count * FREQ_SPIKE_RATIO:
        deviation.append(f"freq_spike_{src_count // max(base_count,1)}x")

    after_match = False
    if src_match and observed_at and observed_at >= src_match["matched_at"]:
        after_match = True

    # Three levels of target activation:
    #   strong = dst FSM advanced past IDLE (state transitioned)
    #   weak   = dst has observed_symbols but FSM still IDLE
    #   contacted = dst is reached but no symbols (just TCP)
    dst_strength = (dst_match or {}).get("match_strength") if dst_match else None
    target_activated = dst_strength == "strong"
    target_partial = dst_strength == "weak"
    target_contacted = bool(dst_match) or bool(edge.get("is_new_connection"))

    evidence = {
        "after_match": after_match,
        "baseline_deviation": deviation,
        "target_activated": target_activated,
        "target_partial": target_partial,
        "target_contacted": target_contacted,
        "dst_match_strength": dst_strength,
        "src_matched": bool(src_match),
        "dst_matched": bool(dst_match),
        "observed_at": observed_at,
        "is_new_connection": bool(edge.get("is_new_connection")),
        "is_active_path": bool(edge.get("is_active_path")),
    }

    if baseline_active:
        return "baseline", evidence

    # External entry rule. Same three-tier dst gate.
    if "external_origin" in deviation:
        if target_activated:
            return "propagation", evidence
        if target_partial:
            return "partial", evidence
        if target_contacted:
            return "adjacent", evidence
        return "baseline", evidence

    # Pod -> Pod rule:
    #   propagation = after_match ∧ deviation ∧ FSM-state-transitioned
    #   partial     = after_match ∧ deviation ∧ symbols-only (FSM still IDLE)
    #   adjacent    = contact / weaker partial signal
    if after_match and deviation and target_activated:
        return "propagation", evidence
    if after_match and deviation and target_partial:
        return "partial", evidence
    if after_match and (deviation or target_contacted):
        return "adjacent", evidence

    return "baseline", evidence


GRADE_STYLE = {
    "correlation": {"color": "#E53E3E", "width": 4, "style": "solid"},
    "related": {"color": "#DD6B20", "width": 3, "style": "solid"},
    "observed": {"color": "#A0AEC0", "width": 1, "style": "solid"},
    "propagation": {"color": "#E53E3E", "width": 4, "style": "solid"},
    "partial":     {"color": "#DD6B20", "width": 3, "style": "solid"},
    "adjacent":    {"color": "#63B3ED", "width": 2, "style": "dashed"},
    "baseline": {"color": "#A0AEC0", "width": 1, "style": "solid"},
}

FSM_COLOR = {
    "IDLE": "#63B3ED",
    "NORMAL": "#63B3ED",
    "RECON": DISPLAY_STATE_COLOR["RECON"],
    "SUSPECT": DISPLAY_STATE_COLOR["RECON"],
    "CRED": DISPLAY_STATE_COLOR["CRED"],
    "RISK": DISPLAY_STATE_COLOR["CRED"],
    "LATERAL": DISPLAY_STATE_COLOR["LATERAL"],
    "PROPAGATION": DISPLAY_STATE_COLOR["LATERAL"],
    "ALERT": DISPLAY_STATE_COLOR["ALERT"],
    "MATCHED": DISPLAY_STATE_COLOR["ALERT"],
    "EXTERNAL": "#E53E3E",
    "UNTRACKED": "#A0AEC0",
}

NODE_COLOR = {
    "external": "#E53E3E",
    "matched": "#E53E3E",
    "propagated": "#DD6B20",
    "partial":   "#F6AD55",
    "adjacent":  "#63B3ED",
    "normal":    "#48BB78",
    "isolated":  "#A0AEC0",
}


def _summary_pod_states(summary: dict | None) -> dict[str, dict]:
    states = ((summary or {}).get("pod_states") or {})
    return states if isinstance(states, dict) else {}


# Genuine attacker-behaviour symbols. A pod that the attacker is operating
# produces one of these. k (K8s API access) and the network symbols
# (E/O/X/D) are deliberately excluded -- monitoring / operator / controller
# pods generate those constantly under normal load, so they are ambient and
# must not, on their own, mark a pod or its edges as suspicious.
_BEHAVIORAL_SYMBOLS = {"s", "b", "c", "n", "R", "h"}


def _behavioral_suspects(correlation: dict | None) -> set[str]:
    """Pod ids that show at least one genuine attacker-behaviour symbol.

    Stage-agnostic: a pod qualifies the moment it shows such a symbol, so the
    FSM progression (RECON -> CRED -> LATERAL -> ALERT) stays fully visible
    and capturable -- this is NOT a "completed attack" gate. It only filters
    pods whose non-IDLE state comes purely from ambient symbols (k/E/O/X/D).
    """
    out: set[str] = set()
    pods = (correlation or {}).get("pods") or {}
    if not isinstance(pods, dict):
        return out
    for pid, body in pods.items():
        if not _is_pod_id(pid):
            continue
        ev = (body or {}).get("evidence") or {}
        fsm = (body or {}).get("fsm") or {}
        syms = set(ev.get("observed_symbols") or fsm.get("observed_symbols") or [])
        base = {str(s).split("_")[0] for s in syms}  # c_sa_token -> c, s_shell -> s
        if base & _BEHAVIORAL_SYMBOLS:
            out.add(pid)
    return out


def _summary_pod_sets(summary: dict | None,
                      gated: set[str] | None = None) -> tuple[str, set[str], set[str]]:
    data = summary or {}
    primary = data.get("primary_suspect_pod") or ""
    secondary = set(data.get("secondary_suspect_pods") or [])
    related = set(data.get("related_pods") or [])
    if gated is not None:
        # The detector ranks suspects partly on ambient symbols, so its
        # secondary/related lists pull in monitoring infrastructure. Keep
        # only pods with genuine attacker behaviour. primary is left as-is
        # (the detector's top pick, the furthest-advanced real attack).
        secondary &= gated
        related &= gated
    if primary:
        related.add(primary)
    related.update(secondary)
    return primary, secondary, related


def _pod_state_from_results(pod_id: str, raw: dict, summary: dict | None,
                            correlation: dict | None) -> tuple[str, str]:
    pod_states = _summary_pod_states(summary)
    state_info = pod_states.get(pod_id) or {}
    state = state_info.get("current_state") or raw.get("state")
    priority = state_info.get("priority") or raw.get("priority")

    corr_pod = ((correlation or {}).get("pods") or {}).get(pod_id) or {}
    fsm = corr_pod.get("fsm") or {}
    state = state or fsm.get("current_state")
    priority = priority or corr_pod.get("priority")

    state = str(state or "IDLE").upper()
    priority = str(priority or "none")
    return state, priority


def _progress_level(state: str) -> int:
    return PROGRESS_LEVEL.get(str(state or "IDLE").upper(), 0)


def _state_sequence_from_trace(pod_id: str, fsm_state: str, correlation: dict | None) -> list[str]:
    """Return the detector transition sequence, keeping only FSM display states."""
    corr_pod = ((correlation or {}).get("pods") or {}).get(pod_id) or {}
    evidence = corr_pod.get("evidence") or {}
    sequence: list[str] = []
    for step in evidence.get("state_trace") or []:
        state = str(step.get("to_state") or "").upper()
        if state in PROGRESS_LEVEL and (not sequence or sequence[-1] != state):
            sequence.append(state)

    final_state = str(fsm_state or "IDLE").upper()
    if final_state in PROGRESS_LEVEL and (not sequence or sequence[-1] != final_state):
        sequence.append(final_state)
    if not sequence:
        sequence.append("IDLE")
    return sequence


def _display_state_for_pod(pod_id: str, fsm_state: str, correlation: dict | None) -> str:
    """Visual-only state used for graph coloring.

    This may briefly replay state_trace transitions so humans can see RECON/CRED/
    LATERAL on refresh-based UIs. It never changes detector state, alert status,
    correlation decisions, or exported fsm_state.
    """
    actual = str(fsm_state or "IDLE").upper()
    if actual not in PROGRESS_LEVEL:
        return actual
    sequence = _state_sequence_from_trace(pod_id, actual, correlation)
    if DISPLAY_STATE_HOLD_SECONDS <= 0 or len(sequence) <= 1:
        _state["display_state_cache"].pop(pod_id, None)
        return actual

    signature = "|".join(sequence)
    now = time.time()
    cache = _state["display_state_cache"].get(pod_id)
    if not cache or cache.get("signature") != signature:
        cache = {"signature": signature, "started_at": now}
        _state["display_state_cache"][pod_id] = cache

    index = min(int((now - float(cache["started_at"])) // DISPLAY_STATE_HOLD_SECONDS), len(sequence) - 1)
    return sequence[index]


def _node_role(pod_id: str, state: str, summary: dict | None,
               gated: set[str] | None = None) -> str:
    primary, secondary, related = _summary_pod_sets(summary, gated)
    if not _is_pod_id(pod_id):
        return "external"
    if pod_id == primary:
        return "primary"
    if pod_id in secondary:
        return "secondary"
    if pod_id in related:
        return "related"
    if state not in ("IDLE", "NORMAL"):
        return "stateful"
    return "normal"


def _node_color_for_state(state: str, role: str, display_state: str | None = None) -> str:
    if role == "external":
        return FSM_COLOR["EXTERNAL"]
    visual_state = str(display_state or state or "IDLE").upper()
    return DISPLAY_STATE_COLOR.get(visual_state, FSM_COLOR.get(visual_state, FSM_COLOR["UNTRACKED"]))


def _detector_edge_grade(raw: dict, summary: dict | None,
                         src_state: str, dst_state: str,
                         gated: set[str] | None = None) -> str:
    # Honor the detector's in-process cross-layer decision: if the correlation
    # engine already flagged this edge as propagation (R injected to target),
    # render it as such instead of re-grading with the local heuristic.
    if raw.get("propagation"):
        return "propagation"
    source = raw.get("source")
    target = raw.get("target")
    primary, secondary, related = _summary_pod_sets(summary, gated)
    endpoint_set = {source, target}
    edge_type = str(raw.get("edge_type") or raw.get("type") or "").lower()
    # An endpoint counts as "active" only if it is a genuine behavioural
    # suspect -- NOT merely non-IDLE. Infra pods reach non-IDLE on ambient
    # symbols; grading their normal traffic as correlation/propagation is
    # exactly the "normal behaviour drawn on the graph" false positive.
    gset = gated or set()
    active_endpoint = bool(endpoint_set & gset)

    if primary and primary in endpoint_set:
        return "correlation"
    if endpoint_set & secondary:
        return "correlation" if active_endpoint else "related"
    if active_endpoint and ("propagation" in edge_type or "correlation" in edge_type):
        return "correlation"
    if endpoint_set & related:
        return "related"
    return "observed"


def _normalise_detector_graph(correlation: dict | None,
                              summary: dict | None) -> tuple[list[dict], list[dict]]:
    raw_nodes = list(((correlation or {}).get("graph") or {}).get("nodes") or [])
    raw_edges = list(((correlation or {}).get("graph") or {}).get("edges") or [])
    node_ids = {n.get("id") for n in raw_nodes if n.get("id")}

    for pod_id in _summary_pod_states(summary).keys():
        if pod_id not in node_ids:
            raw_nodes.append({
                "id": pod_id,
                "label": pod_id.split("/")[-1],
                "type": "pod",
                "state": "IDLE",
            })
            node_ids.add(pod_id)

    for pod_id in _summary_pod_sets(summary)[2]:
        if pod_id and pod_id not in node_ids:
            raw_nodes.append({
                "id": pod_id,
                "label": pod_id.split("/")[-1],
                "type": "pod",
                "state": "IDLE",
            })
            node_ids.add(pod_id)

    for pod_id, pod_info in (((correlation or {}).get("pods") or {}).items()):
        if pod_id not in node_ids:
            fsm = pod_info.get("fsm") or {}
            raw_nodes.append({
                "id": pod_id,
                "label": pod_id.split("/")[-1],
                "type": "pod",
                "state": fsm.get("current_state") or "IDLE",
            })
            node_ids.add(pod_id)

    for edge in raw_edges:
        for pod_id in (edge.get("source"), edge.get("target")):
            if pod_id and pod_id not in node_ids:
                raw_nodes.append({
                    "id": pod_id,
                    "label": pod_id if not _is_pod_id(pod_id) else pod_id.split("/")[-1],
                    "type": "pod" if _is_pod_id(pod_id) else "external",
                    "state": "IDLE" if _is_pod_id(pod_id) else "EXTERNAL",
                })
                node_ids.add(pod_id)

    return raw_nodes, raw_edges


def _build_graph(correlation: dict | None, summary: dict | None,
                 debug_summary: dict | None = None) -> dict:
    matched: dict[str, dict] = {}
    matched.update(_matched_pods_from_summary(summary))
    _matched_pods_from_correlation(correlation, matched)

    # Freeze matched_at to first observation per pod. The detector regenerates
    # detection_summary every poll, so summary.generated_at is always "now",
    # which would make every edge fail after_match.
    with _state_lock:
        first_seen = _state["matched_first_seen"]
        for pod_id, info in matched.items():
            if pod_id not in first_seen:
                first_seen[pod_id] = info["matched_at"]
            info["matched_at"] = first_seen[pod_id]
            info["first_seen_at"] = first_seen[pod_id]

    raw_nodes, raw_edges = _normalise_detector_graph(correlation, summary)

    # Behavioural-suspect gate: pods that show a genuine attacker symbol.
    # Both node role and edge grade are filtered through it, so infra pods
    # (incl. the detector itself) and their normal traffic leave the graph.
    gated = _behavioral_suspects(correlation)

    grade_rank = {"propagation": 4, "correlation": 3, "related": 2, "observed": 1}
    deduped: dict[tuple[str, str], dict] = {}
    evidence_index = {}
    node_lookup = {n.get("id"): n for n in raw_nodes if n.get("id")}

    for raw in raw_edges:
        s, d = raw.get("source"), raw.get("target")
        if not s or not d:
            continue
        src_state, _src_priority = _pod_state_from_results(s, node_lookup.get(s, {}), summary, correlation)
        dst_state, _dst_priority = _pod_state_from_results(d, node_lookup.get(d, {}), summary, correlation)
        grade = _detector_edge_grade(raw, summary, src_state, dst_state, gated)
        evidence = {
            "source_of_truth": "latest_correlation.json",
            "relation_type": raw.get("edge_type") or raw.get("type") or "correlation",
            "symbols": raw.get("symbols") or raw.get("observed_symbols") or (summary or {}).get("observed_symbols") or [],
            "src_state": src_state,
            "dst_state": dst_state,
            "observed_at": raw.get("observed_at") or (summary or {}).get("generated_at"),
            "receive_order": raw.get("receive_order"),
            "raw": raw,
        }
        key = (s, d)
        existing = deduped.get(key)
        if existing and grade_rank[existing["grade"]] >= grade_rank[grade]:
            existing["flow_count"] = existing.get("flow_count", 1) + 1
            continue
        edge_id = f"{s}__{d}"
        style = GRADE_STYLE[grade]
        deduped[key] = {
            "id": edge_id,
            "source": s,
            "target": d,
            "grade": grade,
            "color": style["color"],
            "width": style["width"],
            "style": style["style"],
            "edge_type": evidence["relation_type"],
            "observed_at": raw.get("observed_at"),
            "evidence": evidence,
            "flow_count": (existing.get("flow_count", 0) + 1) if existing else 1,
        }
        evidence_index[edge_id] = evidence

    classified_edges = list(deduped.values())

    nodes_out = []
    seen_ids: set[str] = set()
    for raw in raw_nodes:
        nid = raw.get("id")
        if not nid:
            continue
        seen_ids.add(nid)
        fsm_state, priority = _pod_state_from_results(nid, raw, summary, correlation)
        role = _node_role(nid, fsm_state, summary, gated)
        display_state = _display_state_for_pod(nid, fsm_state, correlation)
        progress_level = _progress_level(display_state)
        color = _node_color_for_state(fsm_state, role, display_state)
        label_state = fsm_state if role == "normal" else f"{role.upper()}:{fsm_state}"
        out = {
            "id": nid,
            "label": raw.get("label") or nid.split("/")[-1],
            "namespace": nid.split("/")[0] if "/" in nid else "",
            "type": role,
            "color": color,
            "fsm_state": fsm_state,
            "display_state": display_state,
            "progress_level": progress_level,
            "priority": priority,
            "is_entrypoint": bool(raw.get("is_entrypoint")),
            "matched": matched.get(nid),
            "label_state": label_state,
        }
        nodes_out.append(out)

    for nid, info in matched.items():
        if nid in seen_ids:
            continue
        fallback_state = str(info.get("fsm_state") or "IDLE").upper()
        display_state = _display_state_for_pod(nid, fallback_state, correlation)
        progress_level = _progress_level(display_state)
        nodes_out.append({
            "id": nid,
            "label": nid.split("/")[-1],
            "namespace": nid.split("/")[0] if "/" in nid else "",
            "type": info.get("role") or "matched",
            "color": _node_color_for_state(fallback_state, info.get("role") or "matched", display_state),
            "fsm_state": fallback_state,
            "display_state": display_state,
            "progress_level": progress_level,
            "priority": info.get("priority") or "none",
            "is_entrypoint": False,
            "matched": info,
            "label_state": f"{str(info.get('role') or 'matched').upper()}:{fallback_state}",
        })

    return {
        "nodes": nodes_out,
        "edges": classified_edges,
        "matched_pods": matched,
        "evidence_index": evidence_index,
        "baseline_active": False,
        "source_of_truth": [
            "results/latest_correlation.json",
            "results/latest_detection_summary.json",
            "results/latest_debug_summary.json",
        ],
        "summary": {
            "node_count": len(nodes_out),
            "edge_count": len(classified_edges),
            "correlation_edges": sum(1 for e in classified_edges if e["grade"] == "correlation"),
            "related_edges": sum(1 for e in classified_edges if e["grade"] == "related"),
            "observed_edges": sum(1 for e in classified_edges if e["grade"] == "observed"),
            "matched_pods": len(matched),
            "primary_suspect_pod": (summary or {}).get("primary_suspect_pod"),
            "highest_priority": (summary or {}).get("highest_priority"),
            "final_judgement": (summary or {}).get("final_judgement"),
            "valid_falco_events_parsed": (debug_summary or {}).get("valid_falco_events_parsed"),
            "valid_hubble_events_parsed": (debug_summary or {}).get("valid_hubble_events_parsed"),
        },
    }


def _node_classify(nid: str, raw: dict, matched: dict[str, dict],
                   prop_targets: set[str], partial_targets: set[str],
                   adj_targets: set[str]) -> tuple[str, str, str]:
    if not _is_pod_id(nid):
        return "external", NODE_COLOR["external"], "EXTERNAL"
    info = matched.get(nid)
    if info:
        # strong = FSM advanced past IDLE -> red matched
        # weak   = symbols observed but state still IDLE -> orange partial
        if info.get("match_strength") == "strong":
            return "matched", NODE_COLOR["matched"], "MATCHED"
        return "partial", NODE_COLOR["partial"], "PARTIAL"
    if nid in prop_targets:
        return "propagated", NODE_COLOR["propagated"], "PROPAGATED"
    if nid in partial_targets:
        return "partial", NODE_COLOR["partial"], "PARTIAL"
    if nid in adj_targets:
        return "adjacent", NODE_COLOR["adjacent"], "ADJACENT"
    state = raw.get("state") or "IDLE"
    if state != "IDLE":
        return "matched", NODE_COLOR["matched"], state
    return "normal", NODE_COLOR["normal"], "NORMAL"


def _build_raw_hubble_graph() -> dict:
    with _state_lock:
        live_edges = list(_state.get("live_edges", {}).values())
        stats = dict(_state.get("hubble_subscriber_stats", {}))

    nodes: dict[str, dict] = {}
    edges = []
    for raw in live_edges:
        source = raw.get("source")
        target = raw.get("target")
        if not source or not target:
            continue
        for pod_id in (source, target):
            if pod_id not in nodes:
                is_pod = _is_pod_id(pod_id)
                nodes[pod_id] = {
                    "id": pod_id,
                    "label": pod_id.split("/")[-1] if is_pod else pod_id,
                    "namespace": pod_id.split("/")[0] if is_pod else "",
                    "type": "raw_pod" if is_pod else "external",
                    "color": FSM_COLOR["IDLE"] if is_pod else FSM_COLOR["EXTERNAL"],
                    "fsm_state": "UNTRACKED" if is_pod else "EXTERNAL",
                    "display_state": "IDLE" if is_pod else "EXTERNAL",
                    "progress_level": 0,
                    "priority": "troubleshooting",
                    "is_entrypoint": not is_pod,
                    "matched": {},
                    "label_state": "RAW_HUBBLE",
                }
        edge_id = f"raw::{source}__{target}"
        style = GRADE_STYLE["observed"]
        edges.append({
            "id": edge_id,
            "source": source,
            "target": target,
            "grade": "observed",
            "color": style["color"],
            "width": style["width"],
            "style": style["style"],
            "edge_type": raw.get("edge_type") or "raw_hubble_flow",
            "observed_at": raw.get("observed_at"),
            "flow_count": raw.get("flow_count", 1),
            "evidence": {
                "source_of_truth": "direct_hubble_subscriber",
                "relation_type": raw.get("edge_type") or "raw_hubble_flow",
                "symbols": raw.get("symbols") or [],
                "src_state": "UNTRACKED",
                "dst_state": "UNTRACKED",
                "observed_at": raw.get("observed_at"),
                "raw": raw,
            },
        })

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "baseline_active": False,
        "source_of_truth": ["direct_hubble_subscriber"],
        "summary": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "raw_hubble": True,
            "subscriber_stats": stats,
        },
    }


def _watcher_loop() -> None:
    correlation_path = RESULTS_DIR / "latest_correlation.json"
    summary_path = RESULTS_DIR / "latest_detection_summary.json"
    debug_path = RESULTS_DIR / "latest_debug_summary.json"
    while True:
        try:
            cor = _read_json(correlation_path)
            sumry = _read_json(summary_path)
            debug = _read_json(debug_path)

            with _state_lock:
                if _state["baseline_active"]:
                    elapsed = time.time() - _state["baseline_started_at"]
                    if elapsed >= BASELINE_SECONDS:
                        _state["baseline_active"] = False

            graph = _build_graph(cor, sumry, debug)
            with _state_lock:
                _state["graph"] = graph
                _state["evidence_index"] = graph.pop("evidence_index", {})
                _state["matched_pods"] = graph.pop("matched_pods", {})
                _state["debug_summary"] = debug or {}
                _state["last_built_at"] = _now_iso()
        except Exception as exc:
            with _state_lock:
                _state["errors"].append(f"{_now_iso()} watcher: {exc}")
                del _state["errors"][:-20]
        time.sleep(POLL_INTERVAL)


def _cytoscape_payload(grades: set[str] | None = None,
                       drop_isolated: bool = True,
                       demo: bool | None = None,
                       graph_override: dict | None = None) -> dict:
    with _state_lock:
        graph = graph_override or _state["graph"]
        nodes = list(graph.get("nodes", []))
        edges = list(graph.get("edges", []))
        demo_on = _state["demo_overlay"] if demo is None else demo

    if demo_on and graph_override is None:
        ov = _demo_overlay_payload()
        demo_node_dicts = [n["data"] for n in ov["nodes"]]
        demo_edge_dicts = [e["data"] for e in ov["edges"]]
        nodes = nodes + demo_node_dicts
        edges = edges + demo_edge_dicts
        # Demo edges also drive the cross-layer advisory channel so that
        # the bidirectional R-symbol path can be exercised end-to-end without
        # waiting for an organic detector classification.
        with _state_lock:
            for e in demo_edge_dicts:
                if e.get("grade") == "propagation":
                    _emit_advisory(e["source"], e["target"], e["id"], e["evidence"])

    if grades:
        edges = [e for e in edges if e["grade"] in grades]

    if drop_isolated:
        connected = set()
        for e in edges:
            connected.add(e["source"])
            connected.add(e["target"])
        # Always keep matched/propagated/partial/adjacent (graph anchors)
        # and external entry nodes. Normal pods stay too — they provide
        # the "rest of the cluster is fine" context, otherwise filtering
        # baseline edges would also evict every healthy green pod.
        nodes = [n for n in nodes
                 if n["id"] in connected
                 or n["type"] in ("matched", "propagated", "partial",
                                  "adjacent", "external", "normal",
                                  "primary", "secondary", "related",
                                  "stateful", "raw_pod")]

    elements = []
    for n in nodes:
        elements.append({
            "data": {
                "id": n["id"],
                "label": n["label"],
                "namespace": n["namespace"],
                "type": n["type"],
                "color": n["color"],
                "fsm_state": n["fsm_state"],
                "display_state": n.get("display_state", n["fsm_state"]),
                "progress_level": n.get("progress_level", _progress_level(n.get("display_state") or n["fsm_state"])),
                "detail__display_state": n.get("display_state", n["fsm_state"]),
                "detail__progress_level": n.get("progress_level", _progress_level(n.get("display_state") or n["fsm_state"])),
                "label_state": n["label_state"],
                "matched": n.get("matched") or {},
            }
        })
    for e in edges:
        elements.append({
            "data": {
                "id": e["id"],
                "source": e["source"],
                "target": e["target"],
                "grade": e["grade"],
                "color": e["color"],
                "width": e["width"],
                "flow_count": e.get("flow_count", 1),
                "edge_type": e["edge_type"],
                "observed_at": e["observed_at"],
                "evidence": e["evidence"],
            },
            "classes": e["grade"],
        })
    return {
        "elements": elements,
        "summary": graph.get("summary", {}),
        "baseline_active": graph.get("baseline_active", False),
        "source_of_truth": graph.get("source_of_truth", []),
        "last_built_at": _state["last_built_at"],
        "rendered": {"node_count": len(nodes), "edge_count": len(edges),
                     "grades": sorted(grades) if grades else "all"},
    }


def _grafana_fields() -> dict:
    return {
        "nodes_fields": [
            {"field_name": "id", "type": "string"},
            {"field_name": "title", "type": "string"},
            {"field_name": "subTitle", "type": "string"},
            {"field_name": "mainStat", "type": "string"},
            {"field_name": "secondaryStat", "type": "string"},
            {"field_name": "color", "type": "string"},
            {"field_name": "detail__type", "type": "string"},
            {"field_name": "detail__fsm_state", "type": "string"},
            {"field_name": "detail__display_state", "type": "string"},
            {"field_name": "detail__progress_level", "type": "number"},
            {"field_name": "detail__priority", "type": "string"},
            {"field_name": "detail__namespace", "type": "string"},
        ],
        "edges_fields": [
            {"field_name": "id", "type": "string"},
            {"field_name": "source", "type": "string"},
            {"field_name": "target", "type": "string"},
            {"field_name": "mainStat", "type": "string"},
            {"field_name": "secondaryStat", "type": "string"},
            {"field_name": "color", "type": "string"},
            {"field_name": "detail__grade", "type": "string"},
            {"field_name": "detail__relation_type", "type": "string"},
            {"field_name": "detail__symbols", "type": "string"},
            {"field_name": "detail__src_state", "type": "string"},
            {"field_name": "detail__dst_state", "type": "string"},
            {"field_name": "detail__after_match", "type": "string"},
            {"field_name": "detail__deviation", "type": "string"},
            {"field_name": "detail__target_activated", "type": "string"},
        ],
    }


def _grafana_data(graph_override: dict | None = None) -> dict:
    with _state_lock:
        graph = graph_override or _state["graph"]
    nodes = []
    for n in graph.get("nodes", []):
        if n.get("id", "").startswith("<NA>"):
            continue
        nodes.append({
            "id": n["id"],
            "title": n["label"],
            "subTitle": n["namespace"],
            "mainStat": f"DISPLAY: {n.get('display_state', n['fsm_state'])}",
            "secondaryStat": f"fsm: {n['fsm_state']} type: {n['type']} progress={n.get('progress_level', 0)}",
            "color": n["color"],
            "detail__type": n["type"],
            "detail__fsm_state": n["fsm_state"],
            "detail__display_state": n.get("display_state", n["fsm_state"]),
            "detail__progress_level": n.get("progress_level", 0),
            "detail__priority": n.get("priority", "none"),
            "detail__namespace": n["namespace"],
        })
    edges = []
    for e in graph.get("edges", []):
        ev = e["evidence"]
        symbols = ev.get("symbols") or []
        if isinstance(symbols, list):
            symbols_text = ",".join(str(s) for s in symbols) or "-"
        else:
            symbols_text = str(symbols)
        relation = ev.get("relation_type") or e.get("edge_type") or "relation"
        src_state = ev.get("src_state") or "-"
        dst_state = ev.get("dst_state") or "-"
        edges.append({
            "id": e["id"],
            "source": e["source"],
            "target": e["target"],
            "mainStat": f"grade: {e['grade']}",
            "secondaryStat": f"{relation} symbols={symbols_text} {src_state}->{dst_state}",
            "color": e["color"],
            "detail__grade": e["grade"],
            "detail__relation_type": relation,
            "detail__symbols": symbols_text,
            "detail__src_state": src_state,
            "detail__dst_state": dst_state,
            "detail__after_match": str(ev.get("after_match", "")),
            "detail__deviation": ",".join(ev.get("baseline_deviation", [])) or "-",
            "detail__target_activated": str(ev.get("target_activated", "")),
        })
    try:
        raw = _build_raw_hubble_graph()
        all_node_ids = {n["id"] for n in nodes}
        for rn in raw.get("nodes", []):
            rid = rn.get("id", "")
            ns = rid.split("/")[0] if "/" in rid else ""
            if rid.startswith("<NA>") or rid.startswith("external"):
                continue
            if rid not in all_node_ids:
                nodes.append({"id": rid, "title": rid.split("/")[-1],
                    "subTitle": ns, "mainStat": "DISPLAY: IDLE",
                    "secondaryStat": "fsm: IDLE type: normal progress=0",
                    "color": "#63B3ED",
                    "detail__type": "normal", "detail__fsm_state": "IDLE",
                    "detail__display_state": "IDLE", "detail__progress_level": 0,
                    "detail__priority": "none", "detail__namespace": ns})
                all_node_ids.add(rid)
        for e in raw.get("edges", []):
            src, tgt = e.get("source", ""), e.get("target", "")
            if src in all_node_ids and tgt in all_node_ids:
                eid = f"raw-{src}-{tgt}"
                if not any(ex["id"] == eid for ex in edges):
                    edges.append({"id": eid, "source": src, "target": tgt,
                        "mainStat": "grade: observed", "secondaryStat": "hubble flow",
                        "color": "#4A5568",
                        "detail__grade": "observed", "detail__relation_type": "network_flow",
                        "detail__symbols": "-", "detail__src_state": "-",
                        "detail__dst_state": "-", "detail__after_match": "",
                        "detail__deviation": "-", "detail__target_activated": ""})
    except Exception:
        pass
    return {"nodes": nodes, "edges": edges}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # type: ignore[override]
        return  # quiet

    def _json(self, payload, status=200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _static(self, rel: str):
        path = (UI_DIR / rel).resolve()
        try:
            ui_root = UI_DIR.resolve()
            if not str(path).startswith(str(ui_root)):
                self.send_response(403); self.end_headers(); return
            data = path.read_bytes()
        except FileNotFoundError:
            self.send_response(404); self.end_headers(); return
        ctype = "text/plain"
        if rel.endswith(".html"): ctype = "text/html"
        elif rel.endswith(".js"): ctype = "application/javascript"
        elif rel.endswith(".css"): ctype = "text/css"
        elif rel.endswith(".json"): ctype = "application/json"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):  # noqa: N802
        url = urlparse(self.path)
        p = url.path
        if p == "/healthz":
            self._json({"status": "ok", "last_built_at": _state["last_built_at"]})
            return
        if p == "/api/graph":
            qs = parse_qs(url.query)
            raw_grades = qs.get("grades", ["propagation,correlation,related,observed"])[0]
            grades = {g.strip() for g in raw_grades.split(",") if g.strip()}
            if "all" in grades or "*" in grades:
                grades = None
            drop_isolated = qs.get("drop_isolated", ["1"])[0] not in ("0", "false")
            demo_q = qs.get("demo", [None])[0]
            demo = None if demo_q is None else demo_q in ("1", "true")
            self._json(_cytoscape_payload(grades=grades, drop_isolated=drop_isolated, demo=demo)); return
        if p == "/api/raw-hubble-graph":
            qs = parse_qs(url.query)
            raw_grades = qs.get("grades", ["observed"])[0]
            grades = {g.strip() for g in raw_grades.split(",") if g.strip()}
            if "all" in grades or "*" in grades:
                grades = None
            drop_isolated = qs.get("drop_isolated", ["1"])[0] not in ("0", "false")
            self._json(_cytoscape_payload(
                grades=grades,
                drop_isolated=drop_isolated,
                demo=False,
                graph_override=_build_raw_hubble_graph(),
            )); return
        if p.startswith("/api/evidence/"):
            edge_id = p[len("/api/evidence/"):]
            with _state_lock:
                ev = _state["evidence_index"].get(edge_id)
            self._json(ev or {"error": "not_found"}, 200 if ev else 404); return
        if p.startswith("/api/pod_fsm/"):
            from urllib.parse import unquote
            pod_id = unquote(p[len("/api/pod_fsm/"):])
            self._json(_pod_fsm_payload(pod_id)); return
        if p == "/api/fsm/states":
            self._json({"states": FSM_STATES}); return
        if p == "/api/baseline":
            with _state_lock:
                self._json({
                    "baseline_active": _state["baseline_active"],
                    "started_at": _state["baseline_started_at"],
                    "elapsed_seconds": time.time() - _state["baseline_started_at"],
                    "window_seconds": BASELINE_SECONDS,
                    "tracked_sources": len(_state["baseline_peers"]),
                })
            return
        if p == "/api/state":
            with _state_lock:
                self._json({
                    "last_built_at": _state["last_built_at"],
                    "matched_pod_count": len(_state["matched_pods"]),
                    "summary": _state["graph"].get("summary", {}),
                    "errors": list(_state["errors"][-5:]),
                    "advisory_file": ADVISORY_FILE or "",
                    "advisory_count": _state["advisory_count"],
                    "advised_targets": [f"{s}->{d}" for s, d in list(_state["advised_targets"])[-20:]],
                    "default_graph_source": "latest_results",
                    "raw_hubble_graph": "/api/raw-hubble-graph",
                    "hubble_subscriber": _state.get("hubble_subscriber_stats", {}),
                    "live_edge_count": len(_state.get("live_edges", {})),
                    "live_pods_seen": len(_state.get("live_pod_first_seen", {})),
                })
            return
        if p in ("/nodegraphds/api/graph/fields", "/api/graph/fields"):
            self._json(_grafana_fields()); return
        if p in ("/nodegraphds/api/graph/data", "/api/graph/data"):
            self._json(_grafana_data()); return
        if p in ("/rawnodegraphds/api/graph/fields", "/api/raw-hubble-graph/fields"):
            self._json(_grafana_fields()); return
        if p in ("/rawnodegraphds/api/graph/data", "/api/raw-hubble-graph/data"):
            self._json(_grafana_data(graph_override=_build_raw_hubble_graph())); return
        if p in ("/nodegraphds/api/health", "/api/health"):
            self._json({"status": "ok"}); return
        if p in ("/", ""):
            self._static("index.html"); return
        if p.startswith("/ui/"):
            self._static(p[len("/ui/"):]); return
        # try static
        if p.startswith("/") and "." in p.rsplit("/", 1)[-1]:
            self._static(p.lstrip("/")); return
        self.send_response(404); self.end_headers()

    def do_POST(self):  # noqa: N802
        url = urlparse(self.path)
        if url.path == "/api/demo/toggle":
            qs = parse_qs(url.query)
            mode = qs.get("on", ["1"])[0]
            with _state_lock:
                _state["demo_overlay"] = mode in ("1", "true", "yes")
            self._json({"demo_overlay": _state["demo_overlay"]}); return
        if url.path == "/api/baseline/reset":
            with _state_lock:
                _state["baseline_started_at"] = time.time()
                _state["baseline_active"] = True
                _state["baseline_peers"].clear()
                _state["baseline_edge_counts"].clear()
                _state["live_edge_counts"].clear()
                _state["matched_first_seen"].clear()
                _state["advised_targets"].clear()
                _state["advisory_count"] = 0
            self._json({"status": "reset", "baseline_active": True}); return
        self.send_response(404); self.end_headers()


def main():
    print(f"[propagation] results_dir={RESULTS_DIR}", flush=True)
    print(f"[propagation] ui_dir={UI_DIR}", flush=True)
    print(f"[propagation] listen={LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    print(f"[propagation] poll_interval={POLL_INTERVAL}s baseline_window={BASELINE_SECONDS}s", flush=True)

    def _hubble_err(msg: str) -> None:
        with _state_lock:
            errs = _state["errors"]
            errs.append(f"{_now_iso()} hubble: {msg}")
            del errs[:-20]
        print(f"[propagation] hubble: {msg}", flush=True)

    try:
        _attach_hubble_subscriber(_state, _state_lock, _hubble_err)
        print("[propagation] hubble subscriber attached", flush=True)
    except Exception as exc:
        _hubble_err(f"failed to attach subscriber: {exc}")

    t = threading.Thread(target=_watcher_loop, daemon=True)
    t.start()
    httpd = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

"""Direct Hubble subscriber.

Avoids relying on the detector's hubble follower stream, which empirically
omits some intra-namespace and cross-node socket-LB flows under sustained
high-rate self-noise. We subscribe to hubble-relay independently and keep
our own (source, target) edge state. Reuses the repo's hubble parser so
the line format handling stays consistent with detector.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from collections import defaultdict
from typing import Callable

# parsers/* lives at /home/yw/poding/parsers when the deployment hostPath
# is mounted; that path is on PYTHONPATH because the exporter command
# starts from /home/yw/poding/propagation/exporter/server.py and Python
# adds that directory + the cwd.
_repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

try:
    from parsers.hubble_observe_parser import parse_hubble_observe_line  # type: ignore
    from parsers.event_mapper import resolve_event_type  # type: ignore
except Exception as exc:  # pragma: no cover
    parse_hubble_observe_line = None  # type: ignore
    resolve_event_type = None  # type: ignore
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None


HUBBLE_BINARY = os.environ.get("PROPAGATION_HUBBLE_BIN", "hubble")
HUBBLE_RELAY = os.environ.get(
    "PROPAGATION_HUBBLE_RELAY",
    "hubble-relay.kube-system.svc.cluster.local:80",
)
RESTART_BACKOFF_SECONDS = 5.0


class HubbleSubscriber:
    """Long-running thread that ingests Hubble flows into a shared edge dict."""

    def __init__(self, on_edge: Callable[[dict], None],
                 on_error: Callable[[str], None] | None = None) -> None:
        self._on_edge = on_edge
        self._on_error = on_error or (lambda msg: None)
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.lines_received = 0
        self.events_parsed = 0
        self.edges_emitted = 0
        self.last_line_at: float | None = None

    def start(self) -> None:
        if _IMPORT_ERROR is not None:
            self._on_error(f"hubble parser import failed: {_IMPORT_ERROR}")
            return
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="hubble-subscriber")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._stream_once()
            except Exception as exc:
                self._on_error(f"hubble stream crash: {exc}")
            if self._stop.is_set():
                return
            time.sleep(RESTART_BACKOFF_SECONDS)

    def _stream_once(self) -> None:
        cmd = [HUBBLE_BINARY, "observe", "--server", HUBBLE_RELAY, "--follow"]
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                bufsize=1,
                text=True,
            )
        except FileNotFoundError as exc:
            self._on_error(f"hubble binary not found: {exc}")
            return

        line_no = 0
        try:
            assert proc.stdout is not None
            for line in proc.stdout:
                if self._stop.is_set():
                    break
                line_no += 1
                self.lines_received += 1
                self.last_line_at = time.time()
                edge = self._line_to_edge(line, line_no)
                if edge:
                    self.edges_emitted += 1
                    self._on_edge(edge)
        finally:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                pass
            stderr = ""
            try:
                if proc.stderr:
                    stderr = proc.stderr.read() or ""
            except Exception:
                pass
            if stderr:
                self._on_error(f"hubble stream stderr: {stderr.strip()[:200]}")

    def _line_to_edge(self, line: str, line_no: int) -> dict | None:
        if parse_hubble_observe_line is None:
            return None
        raw = parse_hubble_observe_line(line, line_number=line_no)
        if raw is None:
            return None
        self.events_parsed += 1
        direction = (raw.official_fields.get("direction") or "egress").lower()

        src_is_pod = bool(raw.subject_pod and raw.namespace
                          and raw.namespace != "unknown"
                          and raw.subject_pod not in ("unknown", "host", "world"))
        dst_is_pod = bool(raw.peer_pod and raw.peer_namespace
                          and raw.peer_namespace != "unknown"
                          and raw.peer_pod not in ("unknown", "host", "world"))

        edge_type = "network_flow"
        if src_is_pod and dst_is_pod:
            # Pod -> Pod. Use egress flows only to dedup the bidirectional
            # observation (Cilium logs both -> and <- for the same TCP flow).
            if direction != "egress":
                return None
            src = f"{raw.namespace}/{raw.subject_pod}"
            dst = f"{raw.peer_namespace}/{raw.peer_pod}"
        elif not src_is_pod and dst_is_pod:
            # External -> Pod. This is the "contamination origin" / 오염 시작점:
            # external IP entering a cluster pod. Synthesise node id
            # `external-<ip>` so the grader fires `external_origin` deviation
            # and surfaces it as the chain root.
            source_ip = ""
            raw_src_ip = raw.official_fields.get("source_ip") or ""
            if isinstance(raw_src_ip, str) and raw_src_ip:
                source_ip = raw_src_ip.split(":")[0]
            if not source_ip:
                source_ip = (raw.subject_pod or "unknown")
            src = f"external-{source_ip}"
            dst = f"{raw.peer_namespace}/{raw.peer_pod}"
            edge_type = "external_inbound"
        else:
            # Pod -> external or external -> external: skip for now.
            return None

        if src == dst:
            return None
        observed_iso = raw.observed_at.isoformat() if raw.observed_at else ""
        if observed_iso.endswith("+00:00"):
            observed_iso = observed_iso.replace("+00:00", "Z")
        event_type = resolve_event_type(raw) if resolve_event_type else None
        return {
            "source": src,
            "target": dst,
            "observed_at": observed_iso,
            "event_type": event_type or "live_hubble_flow",
            "is_new_connection": True,
            "is_active_path": True,
            "edge_type": edge_type,
        }


def attach_to_state(state: dict, lock: threading.Lock,
                    on_error: Callable[[str], None]) -> HubbleSubscriber:
    """Wire a subscriber into the propagation-exporter state dict.

    Maintains:
      state["live_edges"]: dict[(src,dst)] -> {observed_at, count, ...}
      state["live_edge_first_seen"]: dict[(src,dst)] -> first iso timestamp
      state["live_pod_first_seen"]: dict[pod_id] -> first iso timestamp seen
                                    as either src or dst
    """

    state.setdefault("live_edges", {})
    state.setdefault("live_edge_first_seen", {})
    state.setdefault("live_pod_first_seen", {})
    state.setdefault("hubble_subscriber_stats", {
        "lines_received": 0,
        "events_parsed": 0,
        "edges_emitted": 0,
        "last_line_at": None,
    })

    def on_edge(edge: dict) -> None:
        key = (edge["source"], edge["target"])
        with lock:
            ts = edge.get("observed_at") or ""
            existing = state["live_edges"].get(key)
            if existing:
                existing["count"] = existing.get("count", 1) + 1
                if ts and ts > (existing.get("observed_at") or ""):
                    existing["observed_at"] = ts
            else:
                state["live_edges"][key] = {
                    "id": f"live-edge-{edge['source']}__{edge['target']}",
                    "source": edge["source"],
                    "target": edge["target"],
                    "observed_at": ts,
                    "first_observed_at": ts,
                    "count": 1,
                    "edge_type": edge.get("edge_type", "network_flow"),
                    "event_type": edge.get("event_type"),
                    "is_new_connection": True,
                    "is_active_path": True,
                }
                state["live_edge_first_seen"].setdefault(key, ts)
            for pod in (edge["source"], edge["target"]):
                state["live_pod_first_seen"].setdefault(pod, ts)
            state["hubble_subscriber_stats"]["edges_emitted"] += 1

    sub = HubbleSubscriber(on_edge=on_edge, on_error=on_error)

    def stats_pump() -> None:
        while True:
            time.sleep(5)
            with lock:
                state["hubble_subscriber_stats"].update({
                    "lines_received": sub.lines_received,
                    "events_parsed": sub.events_parsed,
                    "edges_emitted": sub.edges_emitted,
                    "last_line_at": sub.last_line_at,
                })

    threading.Thread(target=stats_pump, daemon=True, name="hubble-subscriber-stats").start()
    sub.start()
    return sub

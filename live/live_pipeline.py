from __future__ import annotations

import argparse
import json
import os
import re
import signal
import sys
import threading
from datetime import datetime, timezone
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from queue import Empty, Queue
from typing import Any, Optional
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from engine.correlator import CorrelationEngine
from engine.exporter import build_cluster_snapshot, build_correlation_result, build_detection_summary
from engine.fsm import validate_rule_assets
from engine.models import Event, parse_time
from parsers import materialize_event, parse_falco_line, parse_hubble_observe_line
from utils.config import build_cli_override_map, resolve_config
from live.adaptive_delay import DelayEstimator
from live.result_writer import ResultWriter, build_result_paths

from live.stream_collectors import (
    build_falco_command,
    build_hubble_command,
    ensure_hubble_connectivity,
    stop_managed_process,
    stream_falco_logs,
    stream_hubble_observe,
)


DEFAULT_FALCO_MAX_OBSERVED_AT_SKEW_SECONDS = 600


@dataclass
class StreamMessage:
    source: str
    line: Optional[str] = None
    line_number: int = 0
    stream_closed: bool = False


@dataclass
class DebugStats:
    tracking_mode: str
    raw_falco_lines_received: int = 0
    valid_falco_events_parsed: int = 0
    raw_hubble_lines_received: int = 0
    valid_hubble_events_parsed: int = 0
    scope_matched_events: int = 0
    correlation_candidates: int = 0
    correlation_results_emitted: int = 0
    tracked_pod_count: int = 0
    last_event_received_at: str | None = None
    last_result_written_at: str | None = None
    discarded_reasons: dict[str, int] = field(default_factory=dict)
    discarded_examples: list[dict[str, str | int]] = field(default_factory=list)
    delay_estimator: DelayEstimator = field(default_factory=DelayEstimator)

    def record_event_delay(self, event: Event) -> None:
        self.delay_estimator.add_event(event)

    def record_discard(
        self,
        *,
        source: str,
        reason: str,
        line_number: int,
        detail: str,
    ) -> None:
        self.discarded_reasons[reason] = self.discarded_reasons.get(reason, 0) + 1
        if len(self.discarded_examples) < 20:
            self.discarded_examples.append(
                {
                    "source": source,
                    "reason": reason,
                    "line_number": line_number,
                    "detail": detail,
                }
            )

    def to_dict(self, *, scope: str | None) -> dict[str, Any]:
        return {
            "scope": scope or "cluster-wide",
            "tracking_mode": self.tracking_mode,
            "tracked_pod_count": self.tracked_pod_count,
            "raw_falco_lines_received": self.raw_falco_lines_received,
            "valid_falco_events_parsed": self.valid_falco_events_parsed,
            "raw_hubble_lines_received": self.raw_hubble_lines_received,
            "valid_hubble_events_parsed": self.valid_hubble_events_parsed,
            "scope_matched_events": self.scope_matched_events,
            "correlation_candidates": self.correlation_candidates,
            "correlation_results_emitted": self.correlation_results_emitted,
            "last_event_received_at": self.last_event_received_at,
            "last_result_written_at": self.last_result_written_at,
            "discarded_reasons": self.discarded_reasons,
            "discarded_examples": self.discarded_examples,
            "adaptive_delay": self.delay_estimator.model(),
        }


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _default_falco_max_observed_at_skew_seconds() -> int:
    raw_value = os.getenv("PODING_FALCO_MAX_OBSERVED_AT_SKEW_SECONDS", "").strip()
    if not raw_value:
        return DEFAULT_FALCO_MAX_OBSERVED_AT_SKEW_SECONDS
    try:
        return max(0, int(raw_value))
    except ValueError:
        return DEFAULT_FALCO_MAX_OBSERVED_AT_SKEW_SECONDS


def _falco_timestamp_guard(
    event: Event,
    *,
    max_observed_at_skew_seconds: int,
) -> tuple[str, str] | None:
    if event.event_source != "falco" or max_observed_at_skew_seconds <= 0:
        return None
    if not event.ingested_at:
        return None

    ingested_at = parse_time(event.ingested_at)
    skew_seconds = (ingested_at - event.observed_at).total_seconds()
    if skew_seconds > max_observed_at_skew_seconds:
        return (
            "stale_falco_observed_at",
            (
                f"observed_at={event.observed_at.isoformat()} "
                f"ingested_at={event.ingested_at} "
                f"skew_seconds={skew_seconds:.3f} "
                f"max_seconds={max_observed_at_skew_seconds}"
            ),
        )
    if skew_seconds < -max_observed_at_skew_seconds:
        return (
            "future_falco_observed_at",
            (
                f"observed_at={event.observed_at.isoformat()} "
                f"ingested_at={event.ingested_at} "
                f"skew_seconds={skew_seconds:.3f} "
                f"max_seconds={max_observed_at_skew_seconds}"
            ),
        )
    return None


def _sanitize_label(raw_value: str | None) -> str:
    text = (raw_value or "").strip().lower()
    if not text:
        return ""
    text = re.sub(r"[^a-z0-9._-]+", "-", text)
    text = re.sub(r"-{2,}", "-", text).strip("-._")
    return text[:64]


def _default_run_label(config: dict[str, Any], *, scope: str | None) -> str:
    if scope:
        return scope.replace("/", "_")

    scenario_config = config.get("scenario", {})
    namespace = str(scenario_config.get("namespace", "")).strip()
    attack_pod = str(scenario_config.get("attack_pod", "")).strip()
    if namespace and attack_pod:
        return f"{namespace}_{attack_pod}"
    if namespace:
        return namespace
    return "cluster-wide"


def _resolve_run_label(
    config: dict[str, Any],
    *,
    scope: str | None,
    cli_run_label: str | None,
) -> str:
    pipeline_config = config.get("pipeline", {})
    scenario_config = config.get("scenario", {})
    candidates = [
        cli_run_label,
        pipeline_config.get("run_label"),
        scenario_config.get("label"),
        _default_run_label(config, scope=scope),
    ]
    for candidate in candidates:
        sanitized = _sanitize_label(str(candidate or ""))
        if sanitized:
            return sanitized
    return "cluster-wide"


def _is_truthy(value: Any) -> bool:
    return str(value).strip().lower() not in {"", "0", "false", "no", "off"}


class ApiState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._snapshot: dict[str, Any] | None = None
        self._debug_summary: dict[str, Any] | None = None

    def update(self, *, snapshot: dict[str, Any] | None = None, debug_summary: dict[str, Any] | None = None) -> None:
        with self._lock:
            if snapshot is not None:
                self._snapshot = snapshot
            if debug_summary is not None:
                self._debug_summary = debug_summary

    def read_snapshot(self) -> dict[str, Any] | None:
        with self._lock:
            return self._snapshot

    def read_debug_summary(self) -> dict[str, Any] | None:
        with self._lock:
            return self._debug_summary


def _log(message: str) -> None:
    print(message, file=sys.stderr)


def _load_latest_falco_observed_at(path: Path) -> str | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None

    pods = payload.get("pods", {}) if isinstance(payload, dict) else {}
    latest: str | None = None
    for pod_result in pods.values() if isinstance(pods, dict) else []:
        evidence = pod_result.get("evidence", {}) if isinstance(pod_result, dict) else {}
        for event in evidence.get("source_events", []) if isinstance(evidence, dict) else []:
            if not isinstance(event, dict):
                continue
            if str(event.get("event_source", "")).strip() != "falco":
                continue
            observed_at = str(event.get("observed_at", "")).strip()
            if not observed_at:
                continue
            if latest is None or observed_at > latest:
                latest = observed_at
    return latest


def _collector_worker(
    *,
    source: str,
    collector,
    output_queue: Queue[StreamMessage],
    stop_event: threading.Event,
    restart_on_close: bool = True,
    restart_delay_seconds: int = 3,
) -> None:
    line_number = 0
    try:
        while not stop_event.is_set():
            try:
                for line in collector():
                    if stop_event.is_set():
                        break
                    line_number += 1
                    output_queue.put(
                        StreamMessage(
                            source=source,
                            line=line,
                            line_number=line_number,
                        )
                    )
            except Exception as exc:
                _log(f"[{source}] collector stopped with error: {exc}")

            if stop_event.is_set() or not restart_on_close:
                break

            _log(f"[{source}] collector disconnected; restarting in {restart_delay_seconds}s")
            stop_event.wait(restart_delay_seconds)
    finally:
        output_queue.put(StreamMessage(source=source, stream_closed=True))


def _next_stream_message(
    *,
    falco_queue: Queue[StreamMessage],
    hubble_queue: Queue[StreamMessage],
    timeout_seconds: float = 1.0,
) -> StreamMessage | None:
    try:
        return falco_queue.get_nowait()
    except Empty:
        pass

    try:
        return hubble_queue.get(timeout=timeout_seconds)
    except Empty:
        pass

    try:
        return falco_queue.get_nowait()
    except Empty:
        return None


def _log_debug_stats(stats: DebugStats) -> None:
    _log(
        "[debug] "
        f"tracking mode={stats.tracking_mode}, "
        f"tracked pods={stats.tracked_pod_count}, "
        f"raw falco lines received={stats.raw_falco_lines_received}, "
        f"valid falco events parsed={stats.valid_falco_events_parsed}, "
        f"raw hubble lines received={stats.raw_hubble_lines_received}, "
        f"valid hubble events parsed={stats.valid_hubble_events_parsed}, "
        f"scope-matched events={stats.scope_matched_events}, "
        f"correlation candidates={stats.correlation_candidates}, "
        f"correlation results emitted={stats.correlation_results_emitted}"
    )


def _iter_detections(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    pods = snapshot.get("pods")
    if isinstance(pods, dict):
        items = []
        for pod_key, pod_result in pods.items():
            evidence = pod_result.get("evidence", {}) or {}
            for detection in evidence.get("detections", []) or []:
                materialized = dict(detection)
                materialized.setdefault("pod", pod_key)
                items.append(materialized)
        return items

    evidence = snapshot.get("evidence", {}) or {}
    return [dict(detection) for detection in evidence.get("detections", []) or []]


def _log_new_detections(snapshot: dict[str, Any], seen_signatures: set[tuple[str, str, str]]) -> None:
    for detection in _iter_detections(snapshot):
        rule_id = str(detection.get("rule_id", "")).strip()
        pod = str(detection.get("pod", "")).strip()
        detected_at = str(detection.get("detected_at", "")).strip()
        signature = (pod, rule_id, detected_at)
        if not rule_id or not pod or signature in seen_signatures:
            continue
        seen_signatures.add(signature)
        sequence = " -> ".join(step.get("to_state", "") for step in detection.get("state_trace", []) or [])
        event_chain = " -> ".join(item.get("event_id", "") for item in detection.get("event_chain", []) or [])
        _log("[DETECTION]")
        _log(f"rule: {rule_id}")
        _log(f"pod: {pod}")
        _log(f"sequence: {sequence}")
        _log(f"time: {detected_at}")
        _log(f"details: {event_chain}")


def _classify_falco_discard(message: StreamMessage, exc: Exception | None = None) -> tuple[str, str]:
    line = (message.line or "").strip()
    if exc is not None:
        text = str(exc)
        if "missing required field" in text:
            return "missing fields", text
        return "unsupported schema", text
    if "{" not in line:
        return "non-json", line[:160]
    return "unsupported schema", line[:160]


def _classify_hubble_discard(message: StreamMessage) -> tuple[str, str]:
    line = (message.line or "").strip()
    if not line:
        return "unsupported schema", "empty line"
    return "unsupported schema", line[:160]


def _is_cluster_trackable_event(event: Event) -> bool:
    if not event.namespace or event.namespace == "unknown":
        return False
    if not event.subject_pod:
        return False
    lowered = event.subject_pod.lower()
    if lowered in {"unknown", "host", "remote-node"}:
        return False
    if event.subject_pod.startswith("ID:"):
        return False
    return True


def _tracking_mismatch_reason(
    event: Event,
    *,
    scope_namespace: str | None,
    scope_pod: str | None,
) -> Optional[str]:
    if not _is_cluster_trackable_event(event):
        return "non-pod entity"

    if scope_namespace is None or scope_pod is None:
        return None

    if event.namespace != scope_namespace:
        return "namespace mismatch"
    if event.subject_pod == scope_pod:
        return None
    return "pod mismatch"


def _build_scope_result(
    *,
    engine: CorrelationEngine,
    scope_pod_key: str,
) -> Optional[dict[str, Any]]:
    pod_fsm = engine.fsms.get(scope_pod_key)
    if pod_fsm is None:
        return None

    return build_correlation_result(
        cluster_name=engine.cluster_name,
        pod_key=scope_pod_key,
        pod_fsm=pod_fsm,
        graph_manager=engine.graph,
    )


def _build_cluster_result(engine: CorrelationEngine) -> dict[str, Any]:
    return build_cluster_snapshot(
        cluster_name=engine.cluster_name,
        pod_fsms=engine.fsms,
        graph_manager=engine.graph,
    )


def _write_api_payload(handler: BaseHTTPRequestHandler, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
    body = json.dumps(payload, indent=2, ensure_ascii=True).encode("utf-8")
    handler.send_response(status.value)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _start_api_server(api_state: ApiState, *, bind_host: str, bind_port: int) -> ThreadingHTTPServer:
    class StateApiHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            path = urlparse(self.path).path

            if path == "/healthz":
                _write_api_payload(self, {"status": "ok"})
                return

            if path == "/debug":
                debug_summary = api_state.read_debug_summary()
                if debug_summary is None:
                    _write_api_payload(self, {"error": "debug summary not ready"}, HTTPStatus.NOT_FOUND)
                    return
                _write_api_payload(self, debug_summary)
                return

            if path == "/snapshot":
                snapshot = api_state.read_snapshot()
                if snapshot is None:
                    _write_api_payload(self, {"error": "snapshot not ready"}, HTTPStatus.NOT_FOUND)
                    return
                _write_api_payload(self, snapshot)
                return

            if path == "/pods":
                snapshot = api_state.read_snapshot()
                if snapshot is None:
                    _write_api_payload(self, {"error": "snapshot not ready"}, HTTPStatus.NOT_FOUND)
                    return

                pods = snapshot.get("pods")
                if isinstance(pods, dict):
                    _write_api_payload(self, {"tracked_pods": sorted(pods.keys())})
                    return

                detection_scope = snapshot.get("detection_scope", {})
                pod_key = detection_scope.get("entity_id", "")
                _write_api_payload(self, {"tracked_pods": [pod_key] if pod_key else []})
                return

            if path.startswith("/pods/"):
                snapshot = api_state.read_snapshot()
                if snapshot is None:
                    _write_api_payload(self, {"error": "snapshot not ready"}, HTTPStatus.NOT_FOUND)
                    return

                _, _, namespace, pod_name = path.split("/", 3)
                pod_key = f"{namespace}/{pod_name}"
                pods = snapshot.get("pods")
                if isinstance(pods, dict):
                    pod_result = pods.get(pod_key)
                    if pod_result is None:
                        _write_api_payload(self, {"error": f"pod not tracked: {pod_key}"}, HTTPStatus.NOT_FOUND)
                        return
                    _write_api_payload(self, pod_result)
                    return

                detection_scope = snapshot.get("detection_scope", {})
                if detection_scope.get("entity_id") != pod_key:
                    _write_api_payload(self, {"error": f"pod not tracked: {pod_key}"}, HTTPStatus.NOT_FOUND)
                    return
                _write_api_payload(self, snapshot)
                return

            _write_api_payload(self, {"error": "not found"}, HTTPStatus.NOT_FOUND)

        def log_message(self, format: str, *args: Any) -> None:
            _log(f"[api] {format % args}")

    server = ThreadingHTTPServer((bind_host, bind_port), StateApiHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    return server


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ingest live Falco and Hubble streams into the CorrelationEngine."
    )
    parser.add_argument(
        "--config",
        help="Path to YAML config file. Default: config/default.yaml or PODING_CONFIG",
    )
    parser.add_argument(
        "--scope",
        help="Optional pod scope key in the form namespace/pod-name. Omit for cluster-wide tracking.",
    )
    parser.add_argument(
        "--falco-namespace",
        help="Override Falco namespace in resolved config",
    )
    parser.add_argument(
        "--falco-target",
        help="Override Falco target in resolved config",
    )
    parser.add_argument(
        "--falco-command-template",
        help="Override Falco command template in resolved config",
    )
    parser.add_argument(
        "--falco-cmd",
        help="Override Falco stream command after config resolution",
    )
    parser.add_argument(
        "--hubble-server",
        help="Override Hubble server in resolved config",
    )
    parser.add_argument(
        "--hubble-command-template",
        help="Override Hubble command template in resolved config",
    )
    parser.add_argument(
        "--hubble-cmd",
        help="Override Hubble stream command after config resolution",
    )
    parser.add_argument(
        "--results-path",
        help="Override correlation result path in resolved config",
    )
    parser.add_argument(
        "--run-label",
        help="Optional run label used for timestamped result file naming",
    )
    parser.add_argument(
        "--keep-latest",
        help="Whether to keep writing latest_* files. true/false",
    )
    parser.add_argument(
        "--cluster-name",
        help="Override cluster name in resolved config",
    )
    parser.add_argument(
        "--api-host",
        help="Bind host for the read-only HTTP endpoint",
    )
    parser.add_argument(
        "--api-port",
        help="Bind port for the read-only HTTP endpoint. Set 0 to disable.",
    )
    parser.add_argument(
        "--falco-max-observed-at-skew-seconds",
        type=int,
        default=_default_falco_max_observed_at_skew_seconds(),
        help=(
            "Drop Falco events whose observed_at differs from detector receive "
            "time by more than this many seconds. Set 0 to disable."
        ),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    asset_summary = validate_rule_assets()
    cli_overrides = build_cli_override_map(
        [
            ("falco.namespace", args.falco_namespace),
            ("falco.target", args.falco_target),
            ("falco.command_template", args.falco_command_template),
            ("hubble.server", args.hubble_server),
            ("hubble.command_template", args.hubble_command_template),
            ("pipeline.results_path", args.results_path),
            ("pipeline.run_label", args.run_label),
            ("pipeline.keep_latest", args.keep_latest),
            ("pipeline.cluster_name", args.cluster_name),
            ("pipeline.api_host", args.api_host),
            ("pipeline.api_port", args.api_port),
        ]
    )
    config = resolve_config(
        config_path=args.config or os.getenv("PODING_CONFIG"),
        cli_overrides=cli_overrides,
    )

    falco_command = build_falco_command(config, override_command=args.falco_cmd)
    resolved_hubble_server, hubble_port_forward_process, hubble_connection_method = (
        ensure_hubble_connectivity(
            config,
            override_server=args.hubble_server,
            override_command=args.hubble_cmd,
        )
    )
    hubble_command = build_hubble_command(
        config,
        override_server=resolved_hubble_server,
        override_command=args.hubble_cmd,
    )
    run_label = _resolve_run_label(config, scope=args.scope, cli_run_label=args.run_label)
    keep_latest = _is_truthy(config["pipeline"].get("keep_latest", "true"))
    result_paths = build_result_paths(
        config=config,
        run_label=run_label,
        results_path_override=args.results_path,
    )
    cluster_name = str(config["pipeline"]["cluster_name"])
    api_host = str(config["pipeline"].get("api_host", "0.0.0.0"))
    api_port = int(str(config["pipeline"].get("api_port", "8080")))

    scope_namespace: str | None = None
    scope_pod: str | None = None
    if args.scope:
        scope_namespace, scope_pod = args.scope.split("/", 1)

    tracking_mode = "single-pod" if args.scope else "cluster-wide"
    stats = DebugStats(tracking_mode=tracking_mode)
    stop_requested = False
    collector_stop_event = threading.Event()
    emitted_detection_signatures: set[tuple[str, str, str]] = set()
    receive_order_counter = 0

    def _handle_signal(_signum, _frame) -> None:
        nonlocal stop_requested
        stop_requested = True
        collector_stop_event.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    _log(f"[live] tracking mode={tracking_mode}")
    _log(f"[live] scope={args.scope or 'cluster-wide'}")
    _log(f"[live] config={args.config or os.getenv('PODING_CONFIG') or 'config/default.yaml'}")
    _log(
        "[live] validated rule assets="
        f"event_type_mappings:{asset_summary['event_type_mapping_count']}, "
        f"symbols:{asset_summary['symbol_count']}, "
        f"scenario_rules:{asset_summary['scenario_rule_count']}"
    )
    _log(f"[live] falco command={' '.join(falco_command)}")
    _log(f"[live] hubble connection method={hubble_connection_method}")
    _log(f"[live] hubble command={' '.join(hubble_command)}")
    _log(
        "[live] falco observed_at skew guard="
        f"{args.falco_max_observed_at_skew_seconds}s"
    )
    _log(f"[live] keep latest files={keep_latest}")
    result_writer = ResultWriter(paths=result_paths, keep_latest=keep_latest, logger=_log)
    result_writer.log_configured_paths()
    # Demo-safe mode:
    # Do not seed Falco follower from persisted latest_correlation.json.
    # Persisted results can contain old replayed Falco events and make the
    # follower start from an outdated time boundary.
    # Instead, start from current detector time so this run only observes
    # events generated after the detector starts.
    initial_falco_since_time = None
    _log(f"[live] seeded falco follower last_seen_time={initial_falco_since_time} (current detector time)")

    api_state = ApiState()
    api_server: ThreadingHTTPServer | None = None
    if api_port > 0:
        api_server = _start_api_server(api_state, bind_host=api_host, bind_port=api_port)
        _log(f"[live] api endpoint=http://{api_host}:{api_port}")

    cross_layer_feedback = _is_truthy(os.getenv("PODING_CROSS_LAYER_FEEDBACK", "true"))
    _log(f"[live] cross-layer feedback (R injection)={cross_layer_feedback}")
    engine = CorrelationEngine(
        cluster_name=cluster_name,
        delay_estimator=stats.delay_estimator,
        cross_layer_feedback=cross_layer_feedback,
    )
    falco_output_queue: Queue[StreamMessage] = Queue()
    hubble_output_queue: Queue[StreamMessage] = Queue()

    falco_thread = threading.Thread(
        target=_collector_worker,
        kwargs={
            "source": "falco",
            "collector": lambda: stream_falco_logs(
                falco_command,
                continuous=args.falco_cmd is None,
                initial_since_time=initial_falco_since_time,
            ),
            "output_queue": falco_output_queue,
            "stop_event": collector_stop_event,
            "restart_on_close": args.falco_cmd is None,
        },
        daemon=True,
    )
    hubble_thread = threading.Thread(
        target=_collector_worker,
        kwargs={
            "source": "hubble",
            "collector": lambda: stream_hubble_observe(hubble_command),
            "output_queue": hubble_output_queue,
            "stop_event": collector_stop_event,
            "restart_on_close": args.hubble_cmd is None,
        },
        daemon=True,
    )

    falco_thread.start()
    hubble_thread.start()

    closed_streams = 0

    try:
        while True:
            if stop_requested:
                _log("[live] stop requested")
                break

            message = _next_stream_message(
                falco_queue=falco_output_queue,
                hubble_queue=hubble_output_queue,
            )
            if message is None:
                continue

            if message.stream_closed:
                closed_streams += 1
                _log(f"[{message.source}] stream closed")
                if closed_streams == 2:
                    break
                continue

            if message.source == "falco":
                stats.raw_falco_lines_received += 1
                _log(
                    f"[falco] queue received raw line #{message.line_number}: "
                    f"{(message.line or '')[:240]}"
                )
            elif message.source == "hubble":
                stats.raw_hubble_lines_received += 1
            stats.last_event_received_at = _utc_now()

            event: Optional[Event] = None
            if message.source == "falco":
                try:
                    raw_event = parse_falco_line(message.line or "")
                except ValueError as exc:
                    reason, detail = _classify_falco_discard(message, exc)
                    stats.record_discard(
                        source="falco",
                        reason=reason,
                        line_number=message.line_number,
                        detail=detail,
                    )
                    _log(f"[falco] discard #{message.line_number}: {reason} ({detail})")
                else:
                    event = materialize_event(raw_event) if raw_event is not None else None
                    if event is None:
                        reason, detail = _classify_falco_discard(message)
                        stats.record_discard(
                            source="falco",
                            reason=reason,
                            line_number=message.line_number,
                            detail=detail,
                        )
                        _log(f"[falco] discard #{message.line_number}: {reason}")
                    else:
                        stats.valid_falco_events_parsed += 1
                        _log(
                            f"[falco] parsed event #{message.line_number}: "
                            f"{event.event_type} for {event.primary_entity_key}"
                        )
            elif message.source == "hubble":
                raw_event = parse_hubble_observe_line(message.line or "", line_number=message.line_number)
                event = materialize_event(raw_event) if raw_event is not None else None
                if event is None:
                    reason, detail = _classify_hubble_discard(message)
                    stats.record_discard(
                        source="hubble",
                        reason=reason,
                        line_number=message.line_number,
                        detail=detail,
                    )
                    _log(f"[hubble] discard #{message.line_number}: {reason}")
                else:
                    stats.valid_hubble_events_parsed += 1
                    _log(
                        f"[hubble] parsed event #{message.line_number}: "
                        f"{event.event_type} for {event.primary_entity_key}"
                    )

            if event is None:
                debug_summary = stats.to_dict(scope=args.scope)
                result_writer.write_debug_summary(debug_summary)
                api_state.update(debug_summary=debug_summary)
                continue

            receive_order_counter += 1
            event.official_fields["ingested_at"] = stats.last_event_received_at or _utc_now()
            event.official_fields["receive_order"] = receive_order_counter

            falco_guard_rejection = _falco_timestamp_guard(
                event,
                max_observed_at_skew_seconds=args.falco_max_observed_at_skew_seconds,
            )
            if falco_guard_rejection is not None:
                reason, detail = falco_guard_rejection
                stats.record_discard(
                    source="falco",
                    reason=reason,
                    line_number=message.line_number,
                    detail=detail,
                )
                _log(f"[falco] discard #{message.line_number}: {reason} ({detail})")
                debug_summary = stats.to_dict(scope=args.scope)
                result_writer.write_debug_summary(debug_summary)
                api_state.update(debug_summary=debug_summary)
                continue

            stats.record_event_delay(event)

            mismatch_reason = _tracking_mismatch_reason(
                event,
                scope_namespace=scope_namespace,
                scope_pod=scope_pod,
            )
            if mismatch_reason is not None:
                stats.record_discard(
                    source=event.event_source,
                    reason=mismatch_reason,
                    line_number=message.line_number,
                    detail=event.primary_entity_key,
                )
                _log(
                    f"[{event.event_source}] discard #{message.line_number}: "
                    f"{mismatch_reason} ({event.primary_entity_key})"
                )
                debug_summary = stats.to_dict(scope=args.scope)
                result_writer.write_debug_summary(debug_summary)
                api_state.update(debug_summary=debug_summary)
                continue

            stats.scope_matched_events += 1
            stats.correlation_candidates += 1

            engine.ingest([event])
            stats.tracked_pod_count = len(engine.tracked_pod_keys())
            _log(
                f"[{event.event_source}] ingested {event.event_type} for {event.primary_entity_key}"
            )

            if args.scope:
                result = _build_scope_result(engine=engine, scope_pod_key=args.scope)
            else:
                result = _build_cluster_result(engine)

            if result is None:
                _log_debug_stats(stats)
                debug_summary = stats.to_dict(scope=args.scope)
                result_writer.write_debug_summary(debug_summary)
                api_state.update(debug_summary=debug_summary)
                continue

            detection_summary = build_detection_summary(snapshot=result, label=run_label)
            _log_new_detections(result, emitted_detection_signatures)
            stats.correlation_results_emitted += 1
            stats.last_result_written_at = _utc_now()
            _log_debug_stats(stats)
            debug_summary = stats.to_dict(scope=args.scope)
            result_writer.write_detection_outputs(
                snapshot=result,
                detection_summary=detection_summary,
                debug_summary=debug_summary,
            )
            api_state.update(snapshot=result, debug_summary=debug_summary)
            result_writer.log_detection_output_updates()
    finally:
        _log_debug_stats(stats)
        debug_summary = stats.to_dict(scope=args.scope)
        result_writer.write_debug_summary(debug_summary)
        api_state.update(debug_summary=debug_summary)
        result_writer.log_final_debug_summary()
        if hubble_port_forward_process is not None:
            stop_managed_process(hubble_port_forward_process)
        if api_server is not None:
            api_server.shutdown()
            api_server.server_close()


if __name__ == "__main__":
    main()

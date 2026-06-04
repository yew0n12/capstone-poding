from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

import yaml

from engine.hubble_conditions import is_public_destination
from engine.models import (
    DEFAULT_CORRELATION_DIMENSIONS,
    STATE_ORDER,
    STATE_RANK,
    Event,
    SymbolObservation,
    format_timestamp,
    parse_time,
    unique_append,
)

if TYPE_CHECKING:
    from live.adaptive_delay import DelayEstimator

# Fallback inversion tolerance used when no DelayEstimator is wired in. Mirrors
# live.adaptive_delay.SMALL_BACK_TOLERANCE_SECONDS so the constant stays in
# sync with the estimator's floor.
SMALL_BACK_TOLERANCE_SECONDS = 2.0


@dataclass(frozen=True)
class ScenarioStep:
    step_id: str
    state: str
    symbols: tuple[str, ...]
    event_sources: tuple[str, ...] = ()
    event_types: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScenarioRule:
    rule_id: str
    name: str
    description: str
    priority: str
    time_window_seconds: int
    steps: tuple[ScenarioStep, ...]
    tags: tuple[str, ...] = ()

    @property
    def final_state(self) -> str:
        return self.steps[-1].state if self.steps else "IDLE"


@dataclass
class ActivePath:
    path_id: str
    rule_id: str
    rule_name: str
    priority: str
    time_window_seconds: int
    matched_step_index: int
    started_at: str
    last_seen_at: str
    started_ingested_at: str = ""
    last_seen_ingested_at: str = ""
    started_receive_order: int | None = None
    last_seen_receive_order: int | None = None
    state_trace: List[Dict[str, Any]] = field(default_factory=list)
    event_chain: List[Dict[str, Any]] = field(default_factory=list)
    matched_symbols: List[str] = field(default_factory=list)
    explanation: str = ""

    @property
    def current_state(self) -> str:
        if not self.state_trace:
            return "IDLE"
        return self.state_trace[-1]["to_state"]

    @property
    def next_step_index(self) -> int:
        return self.matched_step_index + 1

    def snapshot(self, rule: ScenarioRule) -> Dict[str, Any]:
        next_state = None
        if self.next_step_index < len(rule.steps):
            next_state = rule.steps[self.next_step_index].state
        return {
            "path_id": self.path_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "priority": self.priority,
            "current_state": self.current_state,
            "next_expected_state": next_state,
            "started_at": self.started_at,
            "last_seen_at": self.last_seen_at,
            "started_ingested_at": self.started_ingested_at,
            "last_seen_ingested_at": self.last_seen_ingested_at,
            "started_receive_order": self.started_receive_order,
            "last_seen_receive_order": self.last_seen_receive_order,
            "matched_step_count": self.matched_step_index + 1,
            "time_window_seconds": self.time_window_seconds,
            "matched_symbols": list(self.matched_symbols),
            "event_chain": list(self.event_chain),
            "state_trace": list(self.state_trace),
            "explanation": self.explanation,
        }


@lru_cache(maxsize=1)
def load_event_type_mapping() -> Dict[str, Any]:
    mapping_path = Path(__file__).resolve().parents[1] / "rules" / "event_type_mapping.yaml"
    with mapping_path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}
    if not isinstance(raw, dict):
        raise ValueError("rules/event_type_mapping.yaml must contain a YAML mapping.")
    return raw


@lru_cache(maxsize=1)
def load_symbol_mapping() -> Dict[str, Any]:
    mapping_path = Path(__file__).resolve().parents[1] / "rules" / "stage_mapping.yaml"
    with mapping_path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


@lru_cache(maxsize=1)
def load_scenario_rules() -> List[ScenarioRule]:
    rules_path = Path(__file__).resolve().parents[1] / "rules" / "scenario_rules.yaml"
    with rules_path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}

    defaults = raw.get("defaults", {}) if isinstance(raw, dict) else {}
    default_window = int(defaults.get("time_window_seconds", 120))
    materialized: List[ScenarioRule] = []

    for item in raw.get("rules", []) if isinstance(raw, dict) else []:
        steps = tuple(
            ScenarioStep(
                step_id=str(step.get("id", f"step-{index + 1}")),
                state=str(step["state"]),
                symbols=tuple(str(symbol) for symbol in step.get("symbols", [])),
                event_sources=tuple(str(source) for source in step.get("event_sources", [])),
                event_types=tuple(str(event_type) for event_type in step.get("event_types", [])),
            )
            for index, step in enumerate(item.get("steps", []))
        )
        if not steps:
            continue
        materialized.append(
            ScenarioRule(
                rule_id=str(item["id"]),
                name=str(item.get("name", item["id"])),
                description=str(item.get("description", "")),
                priority=str(item.get("priority", "supporting")),
                time_window_seconds=int(item.get("time_window_seconds", default_window)),
                steps=steps,
                tags=tuple(str(tag) for tag in item.get("tags", [])),
            )
        )

    return materialized


def validate_rule_assets() -> Dict[str, int]:
    event_type_mapping = load_event_type_mapping()
    symbol_mapping = load_symbol_mapping()
    scenario_rules = load_scenario_rules()
    falco_event_types = event_type_mapping.get("falco", {}).get("rules", {})
    hubble_event_types = event_type_mapping.get("hubble", {}).get("conditions", [])
    return {
        "event_type_mapping_count": len(falco_event_types) + len(hubble_event_types),
        "symbol_count": len(symbol_mapping.get("symbols", {})),
        "scenario_rule_count": len(scenario_rules),
    }


def _text_blob(event: Event) -> str:
    parts = [
        event.description or "",
        str(event.rule_name or ""),
        str(event.event_type or ""),
    ]
    for value in event.official_fields.values():
        if value is None:
            continue
        parts.append(str(value))
    return " ".join(parts)


def _contains_snippet(text: str, snippet: str, *, case_sensitive: bool) -> bool:
    if case_sensitive:
        return snippet in text
    return snippet.lower() in text.lower()


def _matches_text_requirements(text: str, config: Dict[str, Any]) -> bool:
    case_sensitive = bool(config.get("case_sensitive", False))
    contains_any = [str(value) for value in config.get("output_contains_any", [])]
    contains_all = [str(value) for value in config.get("output_contains_all", [])]
    excludes = [str(value) for value in config.get("output_not_contains_any", [])]

    if contains_any and not any(
        _contains_snippet(text, snippet, case_sensitive=case_sensitive) for snippet in contains_any
    ):
        return False
    if contains_all and not all(
        _contains_snippet(text, snippet, case_sensitive=case_sensitive) for snippet in contains_all
    ):
        return False
    if excludes and any(_contains_snippet(text, snippet, case_sensitive=case_sensitive) for snippet in excludes):
        return False
    return True


def map_event_to_symbols(event: Event) -> List[SymbolObservation]:
    mapping = load_symbol_mapping()
    observations: List[SymbolObservation] = []

    if event.event_source == "falco":
        falco_rules = mapping.get("falco", {}).get("rules", {})
        falco_types = mapping.get("falco", {}).get("normalized_types", {})
        text_blob = _text_blob(event)

        rule_config = falco_rules.get(event.rule_name or "")
        if isinstance(rule_config, dict):
            required_snippets = rule_config.get("output_contains", [])
            if not required_snippets or any(snippet in text_blob for snippet in required_snippets):
                for symbol in rule_config.get("symbols", []):
                    observations.append(
                        SymbolObservation(
                            symbol=symbol,
                            source=event.event_source,
                            matched_by=f"falco.rule:{event.rule_name}",
                            event_id=event.event_id,
                            state_hint=(rule_config.get("state_hints") or [None])[0],
                            details={"rule_name": event.rule_name or "", "event_type": event.event_type},
                        )
                    )

            for conditional in rule_config.get("conditional_symbols", []):
                symbol = str(conditional.get("symbol", ""))
                if not symbol or any(obs.symbol == symbol for obs in observations):
                    continue
                if not _matches_text_requirements(text_blob, conditional):
                    continue
                observations.append(
                    SymbolObservation(
                        symbol=symbol,
                        source=event.event_source,
                        matched_by=f"falco.rule:{event.rule_name}.conditional:{symbol}",
                        event_id=event.event_id,
                        state_hint=conditional.get("state_hint") or (rule_config.get("state_hints") or [None])[0],
                        details={"rule_name": event.rule_name or "", "event_type": event.event_type},
                    )
                )

        type_config = falco_types.get(event.event_type or "")
        if isinstance(type_config, dict):
            for symbol in type_config.get("symbols", []):
                if any(obs.symbol == symbol for obs in observations):
                    continue
                observations.append(
                    SymbolObservation(
                        symbol=symbol,
                        source=event.event_source,
                        matched_by=f"falco.normalized_type:{event.event_type}",
                        event_id=event.event_id,
                        state_hint=(type_config.get("state_hints") or [None])[0],
                        details={"rule_name": event.rule_name or "", "event_type": event.event_type},
                    )
                )

    elif event.event_source == "hubble":
        conditions = mapping.get("hubble", {}).get("conditions", [])
        direction = str(event.official_fields.get("direction", "unknown")).lower()
        destination_ip = event.official_fields.get("destination_ip")
        source_ip = event.official_fields.get("source_ip")

        for condition in conditions:
            require = condition.get("require", {})
            event_types = set(require.get("event_types", []))
            if event_types and event.event_type not in event_types:
                continue
            if require.get("peer_pod_present") and not event.peer_pod:
                continue
            if require.get("external_destination") and (event.peer_pod or not destination_ip):
                continue
            if require.get("public_destination") and not is_public_destination(destination_ip):
                continue
            if require.get("external_source") and not source_ip:
                continue
            directions = require.get("direction_any_of", [])
            if directions and direction not in directions:
                continue

            for symbol in condition.get("symbols", []):
                observations.append(
                    SymbolObservation(
                        symbol=symbol,
                        source=event.event_source,
                        matched_by=f"hubble.condition:{condition.get('name', 'unknown')}",
                        event_id=event.event_id,
                        state_hint=(condition.get("state_hints") or [None])[0],
                        details={"event_type": event.event_type, "direction": direction},
                    )
                )

    return observations


class PodFSM:
    def __init__(
        self,
        pod_key: str,
        *,
        delay_estimator: Optional["DelayEstimator"] = None,
    ) -> None:
        self.pod_key = pod_key
        self.delay_estimator = delay_estimator
        self.execution_model = "nfa"
        self.current_state = "IDLE"
        self.previous_state = "IDLE"
        self.transition_trigger = "No NFA path has been advanced yet."
        self.last_transition_at: Optional[str] = None
        self.source_events: List[Dict[str, Any]] = []
        self.state_trace: List[Dict[str, Any]] = []
        self.matched_rules: List[str] = []
        self.matched_flow_patterns: List[str] = []
        self.correlation_dimensions = list(DEFAULT_CORRELATION_DIMENSIONS)
        self.correlation_keys: Dict[str, str] = {}
        self.key_match_types: List[str] = []
        self.graph_edges: List[Dict[str, Any]] = []
        self.graph_peers: List[str] = []
        self.metadata: Dict[str, str] = {}
        self.symbol_trace: List[Dict[str, Any]] = []
        self.observed_symbols: List[str] = []
        self.state_evidence_summary: Dict[str, int] = {
            "RECON": 0,
            "CRED": 0,
            "LATERAL": 0,
            "ALERT": 0,
        }
        self.latest_evidence_note = "No symbol evidence recorded yet."
        self.active_paths: Dict[str, List[ActivePath]] = {rule.rule_id: [] for rule in load_scenario_rules()}
        self.completed_detections: List[Dict[str, Any]] = []
        self._path_counter = 0
        self._detection_signatures: set[tuple[str, str, str]] = set()

    @property
    def candidate_next_states(self) -> List[str]:
        states: List[str] = []
        for rule in load_scenario_rules():
            for path in self.active_paths.get(rule.rule_id, []):
                if path.next_step_index >= len(rule.steps):
                    continue
                next_state = rule.steps[path.next_step_index].state
                if next_state not in states:
                    states.append(next_state)
        return states

    @property
    def active_states(self) -> List[str]:
        states: List[str] = []
        for paths in self.active_paths.values():
            for path in paths:
                if path.current_state != "IDLE" and path.current_state not in states:
                    states.append(path.current_state)
        return sorted(states, key=lambda state: STATE_RANK.get(state, -1))

    @property
    def is_ongoing_detection(self) -> bool:
        return self.current_state in {"LATERAL", "ALERT"}

    def update_metadata(
        self,
        *,
        namespace: str,
        pod_name: str,
        node_name: str,
        workload_name: str,
    ) -> None:
        self.metadata = {
            "namespace": namespace,
            "pod_name": pod_name,
            "node_name": node_name,
            "workload_name": workload_name,
        }

    def hydrate_from_subject_event(self, event: Event) -> None:
        self.update_metadata(
            namespace=event.namespace,
            pod_name=event.subject_pod,
            node_name=event.node_name,
            workload_name=event.workload_name,
        )

    def hydrate_as_peer(self, event: Event) -> None:
        if not event.peer_entity_key or self.metadata:
            return

        self.update_metadata(
            namespace=event.peer_namespace or "",
            pod_name=event.peer_pod or event.peer_entity_key.split("/")[-1],
            node_name=event.peer_node_name or "",
            workload_name=event.peer_workload_name or "unknown",
        )

    def apply_event(self, event: Event) -> None:
        self.hydrate_from_subject_event(event)
        self._record_event(event)
        observations = map_event_to_symbols(event)
        self._record_symbol_observations(event, observations)
        self._prune_expired_paths(event)

        if event.event_source == "hubble" and event.peer_entity_key and any(obs.symbol == "E" for obs in observations):
            self._record_graph_edge(event)

        observed_symbols = {observation.symbol for observation in observations}
        if observed_symbols:
            self._advance_nfa(event, observed_symbols)
        else:
            self._refresh_state_summary()

    def time_window(self) -> Dict[str, Any]:
        if not self.source_events:
            return {"start": None, "end": None, "window_seconds": 0}

        ordered_events = sorted(
            self.source_events,
            key=lambda item: (
                str(item.get("observed_at", "")),
                self._source_event_receive_order(item) is None,
                self._source_event_receive_order(item) or 0,
                str(item.get("event_id", "")),
            ),
        )
        start = ordered_events[0]["observed_at"]
        end = ordered_events[-1]["observed_at"]
        return {
            "start": start,
            "end": end,
            "window_seconds": max(0, int(parse_time(end).timestamp() - parse_time(start).timestamp())),
        }

    def key_match_summary(self) -> Dict[str, Any]:
        return {
            "primary_entity_key": self.correlation_keys.get("primary_entity_key", self.pod_key),
            "namespace_key": self.correlation_keys.get("namespace_key", self.metadata.get("namespace", "")),
            "node_key": self.correlation_keys.get("node_key", self.metadata.get("node_name", "")),
            "workload_key": self.correlation_keys.get(
                "workload_key",
                f"{self.metadata.get('namespace', '')}/{self.metadata.get('workload_name', '')}",
            ),
            "peer_entity_key": self.correlation_keys.get("peer_entity_key", ""),
            "matched_key_types": self.key_match_types,
        }

    def formatted_correlation_keys(self) -> List[str]:
        ordered_keys: List[str] = []
        for key_name in ["primary_entity_key", "namespace_key", "node_key", "workload_key", "peer_entity_key"]:
            key_value = self.correlation_keys.get(key_name)
            if key_value:
                ordered_keys.append(f"{key_name}:{key_value}")
        return ordered_keys

    def active_partial_matches(self) -> List[Dict[str, Any]]:
        snapshots: List[Dict[str, Any]] = []
        rules_by_id = {rule.rule_id: rule for rule in load_scenario_rules()}
        for rule_id, paths in self.active_paths.items():
            rule = rules_by_id[rule_id]
            for path in paths:
                snapshots.append(path.snapshot(rule))
        return sorted(
            snapshots,
            key=lambda item: (
                STATE_RANK.get(item["current_state"], -1),
                self._snapshot_receive_order(item),
                item["started_at"],
            ),
        )

    def primary_detection(self) -> Optional[Dict[str, Any]]:
        if self.completed_detections:
            return max(
                self.completed_detections,
                key=lambda detection: (
                    STATE_RANK.get(detection.get("final_state", "IDLE"), -1),
                    self._snapshot_receive_order(detection),
                    detection.get("detected_at", ""),
                ),
            )

        active = self.active_partial_matches()
        if not active:
            return None
        return max(
            active,
            key=lambda path: (
                STATE_RANK.get(path.get("current_state", "IDLE"), -1),
                self._snapshot_receive_order(path),
                path.get("last_seen_at", ""),
            ),
        )

    def _record_event(self, event: Event) -> None:
        self.source_events.append(event.to_source_event())
        self._merge_correlation_keys(event)
        self._record_match_types(event)
        self._record_matched_artifacts(event)

    def _merge_correlation_keys(self, event: Event) -> None:
        for key_name, key_value in event.correlation_key_values().items():
            self.correlation_keys[key_name] = key_value

    def _record_match_types(self, event: Event) -> None:
        unique_append(self.key_match_types, "same_pod")
        unique_append(self.key_match_types, "same_namespace")
        unique_append(self.key_match_types, "same_node")

        if event.workload_key:
            unique_append(self.key_match_types, "same_workload")
        if event.peer_entity_key:
            unique_append(self.key_match_types, "new_peer_pod")

    def _record_matched_artifacts(self, event: Event) -> None:
        unique_append(self.matched_rules, event.rule_name)
        unique_append(self.matched_flow_patterns, event.flow_pattern)
        unique_append(self.graph_peers, event.peer_entity_key)

    def _record_symbol_observations(self, event: Event, observations: List[SymbolObservation]) -> None:
        if not observations:
            self.latest_evidence_note = (
                f"No symbol mapping matched event `{event.description}`. "
                "The event was recorded as evidence but did not start or advance any NFA path."
            )
            return

        counted_state_hints: set[str] = set()
        for observation in observations:
            unique_append(self.observed_symbols, observation.symbol)
            if observation.state_hint in self.state_evidence_summary and observation.state_hint not in counted_state_hints:
                self.state_evidence_summary[observation.state_hint] += 1
                counted_state_hints.add(observation.state_hint)
            self.symbol_trace.append(
                {
                    "step": len(self.symbol_trace) + 1,
                    "observed_at": format_timestamp(event.observed_at),
                    "ingested_at": event.ingested_at,
                    "receive_order": event.receive_order,
                    "event_id": event.event_id,
                    "symbol": observation.symbol,
                    "state_hint": observation.state_hint,
                    "matched_by": observation.matched_by,
                    "source": observation.source,
                }
            )

        symbols = ", ".join(observation.symbol for observation in observations)
        self.latest_evidence_note = (
            f"Recorded symbol evidence [{symbols}] from `{event.description}`. "
            "The NFA engine keeps partial matches alive even when unrelated noise events appear between steps."
        )

    def _prune_expired_paths(self, event: Event) -> None:
        current_time = self._event_timeout_reference(event)
        for rule in load_scenario_rules():
            retained: List[ActivePath] = []
            for path in self.active_paths.get(rule.rule_id, []):
                started_at = self._path_timeout_reference(path)
                age_seconds = int((current_time - started_at).total_seconds())
                if age_seconds <= rule.time_window_seconds:
                    retained.append(path)
            self.active_paths[rule.rule_id] = retained

    def _advance_nfa(self, event: Event, observed_symbols: set[str]) -> None:
        for rule in load_scenario_rules():
            existing_paths = list(self.active_paths.get(rule.rule_id, []))
            advanced_paths: List[ActivePath] = []

            for path in existing_paths:
                next_step_index = path.next_step_index
                if next_step_index >= len(rule.steps):
                    advanced_paths.append(path)
                    continue

                next_step = rule.steps[next_step_index]
                if self._can_advance_path(path, event) and self._matches_step(event, observed_symbols, next_step):
                    advanced_paths.append(self._advance_path(rule, path, next_step, next_step_index, event, observed_symbols))
                else:
                    advanced_paths.append(path)

            if self._matches_step(event, observed_symbols, rule.steps[0]):
                advanced_paths.append(self._start_path(rule, event, observed_symbols))

            deduped: List[ActivePath] = []
            seen_signatures: set[tuple[int, tuple[str, ...]]] = set()
            for path in advanced_paths:
                event_ids = tuple(item["event_id"] for item in path.event_chain)
                signature = (path.matched_step_index, event_ids)
                if signature in seen_signatures:
                    continue
                seen_signatures.add(signature)
                if path.matched_step_index >= len(rule.steps) - 1:
                    self._finalize_detection(rule, path)
                    continue
                deduped.append(path)

            self.active_paths[rule.rule_id] = deduped[-32:]

        self._refresh_state_summary()

    def _matches_step(self, event: Event, observed_symbols: set[str], step: ScenarioStep) -> bool:
        if not observed_symbols.intersection(step.symbols):
            return False
        if step.event_sources and event.event_source not in step.event_sources:
            return False
        if step.event_types and event.event_type not in step.event_types:
            return False
        return True

    def _start_path(self, rule: ScenarioRule, event: Event, observed_symbols: set[str]) -> ActivePath:
        self._path_counter += 1
        first_step = rule.steps[0]
        return ActivePath(
            path_id=f"{rule.rule_id}-path-{self._path_counter}",
            rule_id=rule.rule_id,
            rule_name=rule.name,
            priority=rule.priority,
            time_window_seconds=rule.time_window_seconds,
            matched_step_index=0,
            started_at=format_timestamp(event.observed_at),
            last_seen_at=format_timestamp(event.observed_at),
            started_ingested_at=event.ingested_at,
            last_seen_ingested_at=event.ingested_at,
            started_receive_order=event.receive_order,
            last_seen_receive_order=event.receive_order,
            state_trace=[
                {
                    "step": 1,
                    "from_state": "IDLE",
                    "to_state": first_step.state,
                    "observed_at": format_timestamp(event.observed_at),
                    "ingested_at": event.ingested_at,
                    "receive_order": event.receive_order,
                    "event_id": event.event_id,
                    "event_source": event.event_source,
                    "reason": self._build_step_reason(rule, first_step, event, observed_symbols, started=True),
                }
            ],
            event_chain=[self._event_chain_entry(event, first_step.state, observed_symbols)],
            matched_symbols=sorted(observed_symbols.intersection(first_step.symbols)),
            explanation=self._build_step_reason(rule, first_step, event, observed_symbols, started=True),
        )

    def _advance_path(
        self,
        rule: ScenarioRule,
        path: ActivePath,
        step: ScenarioStep,
        step_index: int,
        event: Event,
        observed_symbols: set[str],
    ) -> ActivePath:
        matched_symbols = sorted(observed_symbols.intersection(step.symbols))
        state_trace = list(path.state_trace)
        state_trace.append(
            {
                "step": len(state_trace) + 1,
                "from_state": path.current_state,
                "to_state": step.state,
                "observed_at": format_timestamp(event.observed_at),
                "ingested_at": event.ingested_at,
                "receive_order": event.receive_order,
                "event_id": event.event_id,
                "event_source": event.event_source,
                "reason": self._build_step_reason(rule, step, event, observed_symbols, started=False),
            }
        )
        event_chain = list(path.event_chain)
        event_chain.append(self._event_chain_entry(event, step.state, observed_symbols))
        return ActivePath(
            path_id=path.path_id,
            rule_id=path.rule_id,
            rule_name=path.rule_name,
            priority=path.priority,
            time_window_seconds=path.time_window_seconds,
            matched_step_index=step_index,
            started_at=path.started_at,
            last_seen_at=format_timestamp(event.observed_at),
            started_ingested_at=path.started_ingested_at,
            last_seen_ingested_at=event.ingested_at,
            started_receive_order=path.started_receive_order,
            last_seen_receive_order=event.receive_order,
            state_trace=state_trace,
            event_chain=event_chain,
            matched_symbols=list(path.matched_symbols) + matched_symbols,
            explanation=self._build_step_reason(rule, step, event, observed_symbols, started=False),
        )

    def _finalize_detection(self, rule: ScenarioRule, path: ActivePath) -> None:
        final_event_id = ""
        if path.event_chain:
            final_event_id = str(path.event_chain[-1].get("event_id", ""))
        signature = (rule.rule_id, path.current_state, final_event_id)
        if signature in self._detection_signatures:
            return
        self._detection_signatures.add(signature)
        self.completed_detections.append(
            {
                "rule_id": rule.rule_id,
                "rule_name": rule.name,
                "priority": rule.priority,
                "description": rule.description,
                "pod": self.pod_key,
                "namespace": self.metadata.get("namespace", self.pod_key.split("/")[0]),
                "detected_at": path.last_seen_at,
                "detected_ingested_at": path.last_seen_ingested_at,
                "detected_receive_order": path.last_seen_receive_order,
                "time_window_seconds": rule.time_window_seconds,
                "final_state": path.current_state,
                "matched_steps": len(path.state_trace),
                "state_trace": list(path.state_trace),
                "event_chain": list(path.event_chain),
                "explanation": self._build_detection_explanation(rule, path),
                "tags": list(rule.tags),
            }
        )

    def _refresh_state_summary(self) -> None:
        previous_state = self.current_state
        primary = self.primary_detection()
        if primary is None:
            self.previous_state = previous_state
            self.current_state = "IDLE"
            self.state_trace = []
            self.transition_trigger = "No active or completed NFA match for this pod."
            self.last_transition_at = None
            return

        primary_state = primary.get("final_state") or primary.get("current_state") or "IDLE"
        primary_trace = primary.get("state_trace", [])
        self.previous_state = previous_state
        self.current_state = primary_state
        self.state_trace = list(primary_trace)
        self.last_transition_at = primary.get("detected_at") or primary.get("last_seen_at")
        self.transition_trigger = primary.get("explanation") or primary.get("rule_name") or self.transition_trigger

    def _record_graph_edge(self, event: Event) -> None:
        target = event.peer_entity_key
        if not target:
            return

        self.graph_edges.append(
            {
                "id": self._build_edge_id(target),
                "source": self.pod_key,
                "target": target,
                "edge_type": "network_flow",
                "observed_at": format_timestamp(event.observed_at),
                "ingested_at": event.ingested_at,
                "receive_order": event.receive_order,
                "is_new_connection": True,
                "is_active_path": self.current_state in {"LATERAL", "ALERT"} or "E" in self.observed_symbols,
            }
        )

    def _build_edge_id(self, target: str) -> str:
        edge_index = len(self.graph_edges) + 1
        return f"edge-{self.pod_key.replace('/', '-')}-{target.replace('/', '-')}-{edge_index}"

    def _event_chain_entry(self, event: Event, state: str, observed_symbols: set[str]) -> Dict[str, Any]:
        return {
            "event_id": event.event_id,
            "observed_at": format_timestamp(event.observed_at),
            "ingested_at": event.ingested_at,
            "receive_order": event.receive_order,
            "event_source": event.event_source,
            "event_type": event.event_type,
            "rule_name": event.rule_name or "",
            "state": state,
            "symbols": sorted(observed_symbols),
            "description": event.description,
            "peer_entity_key": event.peer_entity_key or "",
        }

    def _build_step_reason(
        self,
        rule: ScenarioRule,
        step: ScenarioStep,
        event: Event,
        observed_symbols: set[str],
        *,
        started: bool,
    ) -> str:
        matched_symbols = ", ".join(sorted(observed_symbols.intersection(step.symbols)))
        action = "started" if started else "advanced"
        return (
            f"Rule `{rule.rule_id}` {action} on state `{step.state}` because event `{event.event_id}` "
            f"from {event.event_source} produced symbol evidence [{matched_symbols}] at receive_order "
            f"{event.receive_order if event.receive_order is not None else 'unknown'} within the active time window."
        )

    def _build_detection_explanation(self, rule: ScenarioRule, path: ActivePath) -> str:
        states = " -> ".join(step["to_state"] for step in path.state_trace)
        event_ids = " -> ".join(item["event_id"] for item in path.event_chain)
        return (
            f"Rule `{rule.rule_id}` completed for pod `{self.pod_key}` via NFA state chain {states}. "
            f"The matched event chain was {event_ids}. Noise events were tolerated as long as the path stayed within "
            f"{rule.time_window_seconds} seconds."
        )

    def _can_advance_path(self, path: ActivePath, event: Event) -> bool:
        if not path.last_seen_at:
            return True
        try:
            last_observed = parse_time(path.last_seen_at)
        except Exception:
            return True
        delta_seconds = (event.observed_at - last_observed).total_seconds()
        if self.delay_estimator is not None:
            tolerance = self.delay_estimator.small_back_tolerance()
        else:
            tolerance = SMALL_BACK_TOLERANCE_SECONDS
        return delta_seconds >= -tolerance

    def _event_timeout_reference(self, event: Event):
        if event.ingested_at:
            return parse_time(event.ingested_at)
        return event.observed_at

    def _path_timeout_reference(self, path: ActivePath):
        if path.started_ingested_at:
            return parse_time(path.started_ingested_at)
        return parse_time(path.started_at)

    def _source_event_receive_order(self, item: Dict[str, Any]) -> int | None:
        try:
            value = item.get("receive_order")
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    def _snapshot_receive_order(self, item: Dict[str, Any]) -> int:
        receive_order = self._source_event_receive_order(item)
        if receive_order is None:
            receive_order = self._source_event_receive_order({"receive_order": item.get("last_seen_receive_order")})
        if receive_order is None:
            receive_order = self._source_event_receive_order({"receive_order": item.get("detected_receive_order")})
        return receive_order if receive_order is not None else -1

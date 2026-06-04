from __future__ import annotations

from typing import TYPE_CHECKING, Dict, Iterable, Optional

from engine.fsm import PodFSM, map_event_to_symbols
from engine.graph import GraphManager
from engine.models import Event, format_timestamp

if TYPE_CHECKING:
    from live.adaptive_delay import DelayEstimator

# Minimal in-process cross-layer feedback (prototype "B").
# Falco rule name the FSM symbol-mapping turns into the `R`
# (propagation_received) symbol. Kept in sync with rules/stage_mapping.yaml.
PROPAGATION_RULE_NAME = "Propagation Received From Suspect"
PROPAGATION_EVENT_TYPE = "propagation_received"


def _event_sort_key(event: Event) -> tuple[str, int, str]:
    receive_order = event.receive_order if event.receive_order is not None else 1 << 30
    return (format_timestamp(event.observed_at), receive_order, event.event_id)


class CorrelationEngine:
    def __init__(
        self,
        cluster_name: str,
        *,
        delay_estimator: Optional["DelayEstimator"] = None,
        cross_layer_feedback: bool = True,
    ) -> None:
        self.cluster_name = cluster_name
        self.delay_estimator = delay_estimator
        # Ablation toggle: when False, no synthetic R (propagation_received) is
        # injected, so cross_layer_propagation_target can only fire from
        # externally seeded events. Lets the same captured stream be replayed
        # with feedback ON vs OFF for a clean ablation.
        self.cross_layer_feedback = cross_layer_feedback
        self.fsms: Dict[str, PodFSM] = {}
        self.graph = GraphManager()
        self._event_history: list[Event] = []

    def get_or_create_fsm(self, pod_key: str) -> PodFSM:
        if pod_key not in self.fsms:
            self.fsms[pod_key] = PodFSM(pod_key, delay_estimator=self.delay_estimator)
        return self.fsms[pod_key]

    def ingest(self, events: Iterable[Event]) -> None:
        materialized_events = list(events)
        if not materialized_events:
            return

        self._event_history.extend(materialized_events)
        self.fsms = {}
        self.graph = GraphManager()

        # Per-source baseline of normal east-west peers, learned in-process from
        # the replayed history (peers contacted while the source is still IDLE,
        # i.e. before it is matched). Rebuilt each ingest to stay deterministic.
        peer_baseline: Dict[str, set[str]] = {}

        for event in sorted(self._event_history, key=_event_sort_key):
            subject_fsm = self.get_or_create_fsm(event.primary_entity_key)
            subject_fsm.apply_event(event)
            self.graph.sync_pod_node(event.primary_entity_key, subject_fsm)

            if event.peer_entity_key:
                peer_fsm = self._initialize_peer_fsm(event)
                self._maybe_propagate_to_peer(event, subject_fsm, peer_fsm, peer_baseline)
                self.graph.sync_pod_node(event.peer_entity_key, peer_fsm)

            self.graph.collect_edges(subject_fsm.graph_edges)

    def _initialize_peer_fsm(self, event: Event) -> PodFSM:
        peer_key = event.peer_entity_key
        if not peer_key:
            raise ValueError("Peer FSM initialization requires peer entity information.")

        peer_fsm = self.get_or_create_fsm(peer_key)
        peer_fsm.hydrate_as_peer(event)
        return peer_fsm

    def _maybe_propagate_to_peer(
        self,
        event: Event,
        subject_fsm: PodFSM,
        peer_fsm: PodFSM,
        peer_baseline: Dict[str, set[str]],
    ) -> None:
        """In-process cross-layer causal feedback (prototype "A").

        For an east-west flow (E symbol) A -> B, inject a synthetic
        `propagation_received` (R) event into B's FSM only when the edge passes
        an in-process causal gate built from signals *external to B*:

          - after_match       : source A is already matched (past IDLE).
          - baseline_deviation : B is a new peer for A, i.e. A never contacted
                                 B while still IDLE (its learned normal set).
          - target_activated   : enforced downstream by the
                                 `cross_layer_propagation_target` rule, whose
                                 second step requires B's own runtime symbol.

        Because the injection decision uses only A's match state and the
        network edge/baseline, B's runtime activity is consumed exactly once
        (by the rule), so the attribution is not circular. Normal east-west to
        a long-known peer never deviates, so it never emits R (FP suppression).
        """
        if not self.cross_layer_feedback:
            return
        src_key = event.primary_entity_key
        dst_key = event.peer_entity_key
        if not dst_key or dst_key == src_key:
            return
        # Only east-west pod-to-pod edges carry the E symbol.
        if not any(observation.symbol == "E" for observation in map_event_to_symbols(event)):
            return

        if subject_fsm.current_state == "IDLE":
            # Pre-match traffic: learn B as a normal peer of A; do not propagate.
            peer_baseline.setdefault(src_key, set()).add(dst_key)
            return

        # after_match holds. Propagate only on baseline deviation (new peer).
        if dst_key in peer_baseline.get(src_key, set()):
            return
        peer_fsm.apply_event(self._build_propagation_event(event))
        self._mark_propagation_edge(subject_fsm, dst_key, src_key)

    def _mark_propagation_edge(self, subject_fsm: PodFSM, dst_key: str, src_key: str) -> None:
        """Flag the A->B graph edge that triggered feedback so the propagation
        UI / exporter renders the detector's in-process decision directly
        instead of re-grading the edge with its own (separate) grader."""
        for edge in reversed(subject_fsm.graph_edges):
            if edge.get("target") == dst_key:
                edge["propagation"] = True
                edge["propagation_source"] = src_key
                break

    def _build_propagation_event(self, event: Event) -> Event:
        return Event(
            observed_at=event.observed_at,
            event_id=f"propagation-{event.event_id}",
            event_source="falco",
            subject_pod=event.peer_pod or "",
            namespace=event.peer_namespace or "",
            node_name=event.peer_node_name or "",
            workload_name=event.peer_workload_name or "unknown",
            event_type=PROPAGATION_EVENT_TYPE,
            description=f"Propagation received from already-matched suspect {event.primary_entity_key}",
            role="trigger",
            rule_name=PROPAGATION_RULE_NAME,
            official_fields={
                "rule_name": PROPAGATION_RULE_NAME,
                "propagation_source_pod": event.primary_entity_key,
            },
        )

    def tracked_pod_keys(self) -> list[str]:
        return sorted(self.fsms.keys())

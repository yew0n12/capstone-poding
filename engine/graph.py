from __future__ import annotations

from typing import Any, Dict, Iterable, List

from engine.fsm import PodFSM


class GraphManager:
    def __init__(self) -> None:
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []
        self._edge_ids: set[str] = set()

    def sync_pod_node(self, pod_key: str, fsm: PodFSM) -> None:
        metadata = fsm.metadata
        self.nodes[pod_key] = {
            "id": pod_key,
            "label": metadata.get("pod_name", pod_key.split("/")[-1]),
            "type": "pod",
            "state": fsm.current_state,
            "active_states": fsm.active_states,
            "is_entrypoint": False,
            "is_active_spread_node": fsm.is_ongoing_detection,
        }

    def collect_edges(self, edges: Iterable[Dict[str, Any]]) -> None:
        for edge in edges:
            if edge["id"] in self._edge_ids:
                continue
            self._edge_ids.add(edge["id"])
            self.edges.append(edge)

    def build_graph(self) -> Dict[str, Any]:
        return {
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
        }

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from utils.config import PROJECT_ROOT, resolve_project_path


Logger = Callable[[str], None]


def _utc_timestamp_for_path() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _write_json_payload(payload: dict[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = output_path.with_name(f"{output_path.name}.{os.getpid()}.tmp")
    temp_path.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n")
    temp_path.replace(output_path)


def _display_project_relative_path(path: Path) -> str:
    try:
        relative = path.resolve().relative_to(PROJECT_ROOT.resolve())
    except ValueError:
        return str(path)
    return f"./{relative.as_posix()}"


def resolve_results_dir(config: dict[str, Any]) -> Path:
    pipeline_config = config.get("pipeline", {})
    configured_results_dir = str(pipeline_config.get("results_dir", "")).strip()
    if configured_results_dir:
        return resolve_project_path(configured_results_dir)

    legacy_results_path = str(pipeline_config.get("results_path", "")).strip()
    if legacy_results_path:
        return resolve_project_path(legacy_results_path).parent

    return resolve_project_path("./results")


@dataclass(frozen=True)
class ResultPaths:
    latest_correlation: Path
    latest_detection_summary: Path
    latest_debug_summary: Path
    timestamped_correlation: Path
    timestamped_detection_summary: Path
    timestamped_debug_summary: Path


def build_result_paths(
    *,
    config: dict[str, Any],
    run_label: str,
    results_path_override: str | None = None,
    run_timestamp: str | None = None,
) -> ResultPaths:
    if results_path_override:
        latest_correlation = resolve_project_path(results_path_override)
    else:
        latest_correlation = resolve_results_dir(config) / "latest_correlation.json"

    latest_detection_summary = latest_correlation.with_name("latest_detection_summary.json")
    latest_debug_summary = latest_correlation.with_name("latest_debug_summary.json")

    results_dir = latest_correlation.parent
    label_suffix = f"_{run_label}" if run_label else ""
    timestamp = run_timestamp or _utc_timestamp_for_path()

    return ResultPaths(
        latest_correlation=latest_correlation,
        latest_detection_summary=latest_detection_summary,
        latest_debug_summary=latest_debug_summary,
        timestamped_correlation=results_dir / f"correlation_{timestamp}{label_suffix}.json",
        timestamped_detection_summary=results_dir / f"detection_summary_{timestamp}{label_suffix}.json",
        timestamped_debug_summary=results_dir / f"debug_{timestamp}{label_suffix}.json",
    )


class ResultWriter:
    def __init__(
        self,
        *,
        paths: ResultPaths,
        keep_latest: bool,
        logger: Logger,
    ) -> None:
        self.paths = paths
        self.keep_latest = keep_latest
        self._log = logger

    def log_configured_paths(self) -> None:
        self._log(f"[live] results path={self.paths.latest_correlation}")
        self._log(f"[live] debug summary path={self.paths.latest_debug_summary}")
        self._log(f"[live] timestamped correlation path={self.paths.timestamped_correlation}")
        self._log(f"[live] timestamped debug path={self.paths.timestamped_debug_summary}")
        self._log(f"[live] detection summary path={self.paths.latest_detection_summary}")
        self._log(f"[live] timestamped detection summary path={self.paths.timestamped_detection_summary}")
        self._log_result_write_banner()

    def write_debug_summary(self, debug_summary: dict[str, Any]) -> None:
        if self.keep_latest:
            _write_json_payload(debug_summary, self.paths.latest_debug_summary)
        _write_json_payload(debug_summary, self.paths.timestamped_debug_summary)

    def write_detection_outputs(
        self,
        *,
        snapshot: dict[str, Any],
        detection_summary: dict[str, Any],
        debug_summary: dict[str, Any],
    ) -> None:
        if self.keep_latest:
            _write_json_payload(snapshot, self.paths.latest_correlation)
        _write_json_payload(snapshot, self.paths.timestamped_correlation)

        if self.keep_latest:
            _write_json_payload(detection_summary, self.paths.latest_detection_summary)
        _write_json_payload(detection_summary, self.paths.timestamped_detection_summary)

        self.write_debug_summary(debug_summary)
        self._log_result_write_banner()

    def log_detection_output_updates(self) -> None:
        if self.keep_latest:
            self._log(f"[live] updated {self.paths.latest_correlation}")
        self._log(f"[live] updated {self.paths.timestamped_correlation}")
        if self.keep_latest:
            self._log(f"[live] updated {self.paths.latest_detection_summary}")
        self._log(f"[live] updated {self.paths.timestamped_detection_summary}")

    def log_final_debug_summary(self) -> None:
        if self.keep_latest:
            self._log(f"[live] wrote debug summary to {self.paths.latest_debug_summary}")
        self._log(f"[live] wrote debug summary to {self.paths.timestamped_debug_summary}")

    def _log_result_write_banner(self) -> None:
        self._log("[RESULT WRITE]")
        self._log(f"correlation -> {_display_project_relative_path(self.paths.latest_correlation)}")
        self._log(f"summary     -> {_display_project_relative_path(self.paths.latest_detection_summary)}")
        self._log(f"debug       -> {_display_project_relative_path(self.paths.latest_debug_summary)}")

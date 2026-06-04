from __future__ import annotations

import argparse
import os
import shlex
from copy import deepcopy
from pathlib import Path
from typing import Any, Iterable

import yaml


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "default.yaml"

INTERNAL_FALLBACK_CONFIG: dict[str, Any] = {
    "falco": {
        "namespace": "poding-system",
        "target": "app.kubernetes.io/name=falco",
        "command_template": "kubectl logs -f -n {namespace} -l {target} -c falco --tail=20 --since=30s --prefix --max-log-requests=10",
    },
    "hubble": {
        "server": "hubble-relay.kube-system.svc.cluster.local:80",
        "command_template": "hubble observe --server {server} --follow --since 30s",
        "relay_namespace": "kube-system",
        "relay_service": "svc/hubble-relay",
        "relay_local_port": "4245",
        "relay_remote_port": "80",
        "port_forward_command": "cilium hubble port-forward",
        "fallback_port_forward_command": (
            "kubectl port-forward -n {relay_namespace} {relay_service} "
            "{relay_local_port}:{relay_remote_port}"
        ),
    },
    "pipeline": {
        "cluster_name": "poding-lab",
        "results_dir": "./results",
        "run_label": "",
        "keep_latest": "true",
        "logs_dir": "logs",
        "startup_sleep": "3",
        "api_host": "0.0.0.0",
        "api_port": "8080",
    },
    "scenario": {
        "label": "",
        "namespace": "attack-lab-01",
        "attack_pod": "pod-a",
        "attack_container": "",
        "ready_timeout": "180s",
        "step_sleep": "3",
    },
}

ENV_TO_PATH = {
    "PODING_RESULTS_DIR": ("pipeline", "results_dir"),
    "PODING_FALCO_NAMESPACE": ("falco", "namespace"),
    "PODING_FALCO_TARGET": ("falco", "target"),
    "PODING_FALCO_COMMAND_TEMPLATE": ("falco", "command_template"),
    "PODING_HUBBLE_SERVER": ("hubble", "server"),
    "PODING_HUBBLE_COMMAND_TEMPLATE": ("hubble", "command_template"),
    "PODING_HUBBLE_RELAY_NAMESPACE": ("hubble", "relay_namespace"),
    "PODING_HUBBLE_RELAY_SERVICE": ("hubble", "relay_service"),
    "PODING_HUBBLE_RELAY_LOCAL_PORT": ("hubble", "relay_local_port"),
    "PODING_HUBBLE_RELAY_REMOTE_PORT": ("hubble", "relay_remote_port"),
    "PODING_HUBBLE_PORT_FORWARD_COMMAND": ("hubble", "port_forward_command"),
    "PODING_HUBBLE_PORT_FORWARD_FALLBACK_COMMAND": (
        "hubble",
        "fallback_port_forward_command",
    ),
    "PODING_PIPELINE_CLUSTER_NAME": ("pipeline", "cluster_name"),
    "PODING_PIPELINE_RESULTS_DIR": ("pipeline", "results_dir"),
    "PODING_PIPELINE_RESULTS_PATH": ("pipeline", "results_path"),
    "PODING_PIPELINE_RUN_LABEL": ("pipeline", "run_label"),
    "PODING_PIPELINE_KEEP_LATEST": ("pipeline", "keep_latest"),
    "PODING_PIPELINE_LOGS_DIR": ("pipeline", "logs_dir"),
    "PODING_PIPELINE_STARTUP_SLEEP": ("pipeline", "startup_sleep"),
    "PODING_PIPELINE_API_HOST": ("pipeline", "api_host"),
    "PODING_PIPELINE_API_PORT": ("pipeline", "api_port"),
    "PODING_SCENARIO_LABEL": ("scenario", "label"),
    "PODING_SCENARIO_NAMESPACE": ("scenario", "namespace"),
    "PODING_SCENARIO_ATTACK_POD": ("scenario", "attack_pod"),
    "PODING_SCENARIO_ATTACK_CONTAINER": ("scenario", "attack_container"),
    "PODING_SCENARIO_READY_TIMEOUT": ("scenario", "ready_timeout"),
    "PODING_SCENARIO_STEP_SLEEP": ("scenario", "step_sleep"),
}

SHELL_EXPORT_PATHS = {
    "PODING_RESOLVED_FALCO_NAMESPACE": ("falco", "namespace"),
    "PODING_RESOLVED_FALCO_TARGET": ("falco", "target"),
    "PODING_RESOLVED_FALCO_COMMAND_TEMPLATE": ("falco", "command_template"),
    "PODING_RESOLVED_HUBBLE_SERVER": ("hubble", "server"),
    "PODING_RESOLVED_HUBBLE_COMMAND_TEMPLATE": ("hubble", "command_template"),
    "PODING_RESOLVED_HUBBLE_RELAY_NAMESPACE": ("hubble", "relay_namespace"),
    "PODING_RESOLVED_HUBBLE_RELAY_SERVICE": ("hubble", "relay_service"),
    "PODING_RESOLVED_HUBBLE_RELAY_LOCAL_PORT": ("hubble", "relay_local_port"),
    "PODING_RESOLVED_HUBBLE_RELAY_REMOTE_PORT": ("hubble", "relay_remote_port"),
    "PODING_RESOLVED_HUBBLE_PORT_FORWARD_COMMAND": (
        "hubble",
        "port_forward_command",
    ),
    "PODING_RESOLVED_HUBBLE_PORT_FORWARD_FALLBACK_COMMAND": (
        "hubble",
        "fallback_port_forward_command",
    ),
    "PODING_RESOLVED_PIPELINE_CLUSTER_NAME": ("pipeline", "cluster_name"),
    "PODING_RESOLVED_PIPELINE_RESULTS_DIR": ("pipeline", "results_dir"),
    "PODING_RESOLVED_PIPELINE_RESULTS_PATH": ("pipeline", "results_path"),
    "PODING_RESOLVED_PIPELINE_RUN_LABEL": ("pipeline", "run_label"),
    "PODING_RESOLVED_PIPELINE_KEEP_LATEST": ("pipeline", "keep_latest"),
    "PODING_RESOLVED_PIPELINE_LOGS_DIR": ("pipeline", "logs_dir"),
    "PODING_RESOLVED_PIPELINE_STARTUP_SLEEP": ("pipeline", "startup_sleep"),
    "PODING_RESOLVED_PIPELINE_API_HOST": ("pipeline", "api_host"),
    "PODING_RESOLVED_PIPELINE_API_PORT": ("pipeline", "api_port"),
    "PODING_RESOLVED_SCENARIO_LABEL": ("scenario", "label"),
    "PODING_RESOLVED_SCENARIO_NAMESPACE": ("scenario", "namespace"),
    "PODING_RESOLVED_SCENARIO_ATTACK_POD": ("scenario", "attack_pod"),
    "PODING_RESOLVED_SCENARIO_ATTACK_CONTAINER": ("scenario", "attack_container"),
    "PODING_RESOLVED_SCENARIO_READY_TIMEOUT": ("scenario", "ready_timeout"),
    "PODING_RESOLVED_SCENARIO_STEP_SLEEP": ("scenario", "step_sleep"),
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _set_nested(config: dict[str, Any], path: Iterable[str], value: Any) -> None:
    current = config
    path_items = list(path)
    for key in path_items[:-1]:
        next_value = current.get(key)
        if not isinstance(next_value, dict):
            next_value = {}
            current[key] = next_value
        current = next_value
    current[path_items[-1]] = value


def _get_nested(config: dict[str, Any], path: Iterable[str]) -> Any:
    current: Any = config
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def resolve_config_path(config_path: str | os.PathLike[str] | None = None) -> Path:
    if config_path is None:
        return DEFAULT_CONFIG_PATH

    candidate = Path(config_path).expanduser()
    if candidate.is_absolute():
        return candidate
    return PROJECT_ROOT / candidate


def load_yaml_config(config_path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    path = resolve_config_path(config_path)
    if not path.exists():
        return {}

    loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    return loaded if isinstance(loaded, dict) else {}


def resolve_project_path(path_value: str | os.PathLike[str]) -> Path:
    path = Path(path_value).expanduser()
    if path.is_absolute():
        return path
    return PROJECT_ROOT / path


def resolve_config(
    *,
    config_path: str | os.PathLike[str] | None = None,
    cli_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    config = deepcopy(INTERNAL_FALLBACK_CONFIG)
    config = _deep_merge(config, load_yaml_config(config_path))

    for env_name, path in ENV_TO_PATH.items():
        env_value = os.getenv(env_name)
        if env_value not in (None, ""):
            _set_nested(config, path, env_value)

    if cli_overrides:
        for path_key, value in cli_overrides.items():
            if value not in (None, ""):
                _set_nested(config, path_key.split("."), value)

    return config


def export_shell(config: dict[str, Any]) -> str:
    lines = []
    for env_name, path in SHELL_EXPORT_PATHS.items():
        value = _get_nested(config, path)
        if value is None:
            value = ""
        lines.append(f"{env_name}={shlex.quote(str(value))}")
    return "\n".join(lines)


def build_cli_override_map(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    overrides: dict[str, Any] = {}
    for key, value in pairs:
        if value not in (None, ""):
            overrides[key] = value
    return overrides


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Resolve project configuration.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    shell_parser = subparsers.add_parser(
        "shell",
        help="Render resolved configuration as shell assignments.",
    )
    shell_parser.add_argument(
        "--config",
        help="Path to YAML config file. Default: config/default.yaml or PODING_CONFIG",
    )

    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    config_path = args.config or os.getenv("PODING_CONFIG")
    config = resolve_config(config_path=config_path)

    if args.command == "shell":
        print(export_shell(config))


if __name__ == "__main__":
    main()

from __future__ import annotations

import atexit
import json
import os
import queue
import selectors
import shlex
import subprocess
import sys
import threading
import time
import traceback
from collections import deque
from collections.abc import Generator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from engine.models import parse_time

from utils.config import resolve_project_path


FALLBACK_FALCO_SETTINGS = {
    "namespace": "poding-system",
    "target": "app.kubernetes.io/name=falco",
    "command_template": "kubectl logs -f -n {namespace} -l {target} -c falco --tail=0 --prefix --max-log-requests=10",
}

FALLBACK_HUBBLE_SETTINGS = {
    "server": "hubble-relay.kube-system.svc.cluster.local:80",
    "command_template": "hubble observe --server {server} --namespace attack-lab-01 --follow --since 30s",
    "relay_namespace": "kube-system",
    "relay_service": "svc/hubble-relay",
    "relay_local_port": "4245",
    "relay_remote_port": "80",
    "port_forward_command": "cilium hubble port-forward",
    "fallback_port_forward_command": "kubectl port-forward -n {relay_namespace} {relay_service} {relay_local_port}:{relay_remote_port}",
}


_PORT_FORWARD_PROCESSES: list[subprocess.Popen[str]] = []
DEFAULT_STREAM_IDLE_TIMEOUT_SECONDS = 120


def _is_local_hubble_endpoint(server: str) -> bool:
    normalized = server.strip().lower()
    return normalized.startswith("localhost:") or normalized.startswith("127.0.0.1:")


def _stream_stderr(stderr, stream_name: str) -> None:
    if stderr is None:
        return

    for raw_line in iter(stderr.readline, ""):
        line = raw_line.rstrip()
        if line:
            print(f"[{stream_name} stderr] {line}", file=sys.stderr)


def _resolve_command(
    *,
    template: str,
    values: dict[str, Any],
    override_command: str | None = None,
) -> list[str]:
    if override_command:
        return shlex.split(override_command)
    return shlex.split(template.format(**values))


def build_falco_command(
    config: dict[str, Any] | None = None,
    *,
    override_command: str | None = None,
) -> list[str]:
    falco_config = config.get("falco", {}) if config else {}
    namespace = str(
        falco_config.get("namespace", FALLBACK_FALCO_SETTINGS["namespace"])
    )
    target = str(falco_config.get("target", FALLBACK_FALCO_SETTINGS["target"]))
    template = str(
        falco_config.get(
            "command_template",
            FALLBACK_FALCO_SETTINGS["command_template"],
        )
    )
    return _resolve_command(
        template=template,
        values={
            "namespace": namespace,
            "target": target,
        },
        override_command=override_command,
    )


def build_hubble_command(
    config: dict[str, Any] | None = None,
    *,
    override_server: str | None = None,
    override_command: str | None = None,
) -> list[str]:
    hubble_config = config.get("hubble", {}) if config else {}
    server = override_server or str(
        hubble_config.get("server", FALLBACK_HUBBLE_SETTINGS["server"])
    )
    template = str(
        hubble_config.get(
            "command_template",
            FALLBACK_HUBBLE_SETTINGS["command_template"],
        )
    )
    return _resolve_command(
        template=template,
        values={"server": server},
        override_command=override_command,
    )


DEFAULT_FALCO_COMMAND = build_falco_command()
DEFAULT_HUBBLE_COMMAND = build_hubble_command()
DEFAULT_FALCO_POLL_INTERVAL_SECONDS = 3
DEFAULT_FALCO_RECENT_LINE_LIMIT = 256
DEFAULT_FALCO_POD_DISCOVERY_INTERVAL_SECONDS = 10


@dataclass
class _FalcoFollowerState:
    pod_name: str
    last_seen_time: str | None = None
    thread: threading.Thread | None = None
    stop_event: threading.Event = field(default_factory=threading.Event)


def _cleanup_port_forward_processes() -> None:
    while _PORT_FORWARD_PROCESSES:
        process = _PORT_FORWARD_PROCESSES.pop()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


atexit.register(_cleanup_port_forward_processes)


def _render_command_template(template: str, values: dict[str, Any]) -> str:
    rendered = template
    for key, value in values.items():
        rendered = rendered.replace(f"{{{key}}}", str(value))
    return rendered


def _command_option_value(command: Sequence[str], *option_names: str) -> str | None:
    for index, token in enumerate(command):
        for option_name in option_names:
            if token == option_name and index + 1 < len(command):
                return command[index + 1]
            if token.startswith(f"{option_name}="):
                return token.split("=", 1)[1]
    return None


def _falco_command_details(command: Sequence[str]) -> tuple[str, str | None]:
    namespace = _command_option_value(command, "-n", "--namespace") or FALLBACK_FALCO_SETTINGS["namespace"]
    selector = _command_option_value(command, "-l", "--selector")
    return namespace, selector


def _is_selector_falco_command(command: Sequence[str]) -> bool:
    return _command_option_value(command, "-l", "--selector") is not None


def _list_falco_pods(namespace: str, selector: str) -> list[str]:
    result = subprocess.run(
        [
            "kubectl",
            "get",
            "pods",
            "-n",
            namespace,
            "-l",
            selector,
            "-o",
            "name",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"failed to list Falco pods in {namespace}")

    pods: list[str] = []
    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        pods.append(line.split("/", 1)[1] if "/" in line else line)
    unique_pods = sorted(dict.fromkeys(pods))
    print(
        f"[falco] discovered {len(unique_pods)} Falco pod(s) in namespace={namespace} selector={selector}: {', '.join(unique_pods)}",
        file=sys.stderr,
    )
    return unique_pods


def _extract_falco_event_time(line: str) -> str | None:
    payload = _extract_falco_payload(line)
    if payload is None:
        return None

    for key in ("time", "timestamp", "output_time"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _extract_falco_payload(line: str) -> dict[str, Any] | None:
    start = line.find("{")
    end = line.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None

    try:
        payload = json.loads(line[start : end + 1])
    except json.JSONDecodeError:
        return None

    if not isinstance(payload, dict):
        return None

    return payload


def _first_text_value(*values: Any) -> str:
    for value in values:
        if value not in (None, "", []):
            return str(value).strip()
    return ""


def _falco_dedupe_key(pod_name: str, line: str) -> str:
    payload = _extract_falco_payload(line)
    if payload is None:
        return f"{pod_name}:raw:{line}"

    output_fields = payload.get("output_fields")
    if not isinstance(output_fields, dict):
        output_fields = {}

    event_time = _first_text_value(
        payload.get("time"),
        payload.get("timestamp"),
        payload.get("output_time"),
        output_fields.get("evt.time"),
    )
    rule = _first_text_value(payload.get("rule"))
    namespace = _first_text_value(payload.get("namespace"), output_fields.get("k8s.ns.name"))
    event_pod = _first_text_value(payload.get("pod_name"), output_fields.get("k8s.pod.name"), pod_name)
    container_id = _first_text_value(
        payload.get("container_id"),
        output_fields.get("container.id"),
        output_fields.get("container.name"),
    )
    proc_cmdline = _first_text_value(
        payload.get("proc_cmdline"),
        output_fields.get("proc.cmdline"),
        payload.get("command"),
    )

    return "|".join(
        [
            "falco",
            event_time,
            rule,
            namespace,
            event_pod,
            container_id,
            proc_cmdline,
        ]
    )


def _build_falco_pod_command(
    *,
    namespace: str,
    pod_name: str,
    base_command: Sequence[str],
    since_time: str | None = None,
) -> list[str]:
    command = ["kubectl", "logs", "-f", "-n", namespace, pod_name, "-c", "falco"]

    if since_time:
        command.extend(["--since-time", since_time])
    else:
        command.append("--tail=0")

    if "--prefix" in base_command:
        command.append("--prefix")
    return command


def _is_newer_falco_event_time(event_time: str, last_seen_time: str | None) -> bool:
    if not event_time:
        return True
    if not last_seen_time:
        return True
    try:
        return parse_time(event_time) > parse_time(last_seen_time)
    except Exception:
        return event_time > last_seen_time


def _falco_pod_follower(
    *,
    namespace: str,
    pod_name: str,
    base_command: Sequence[str],
    output_queue: "queue.Queue[tuple[str, str]]",
    follower_state: _FalcoFollowerState,
) -> None:
    while not follower_state.stop_event.is_set():
        previous_last_seen_time = follower_state.last_seen_time
        command = _build_falco_pod_command(
            namespace=namespace,
            pod_name=pod_name,
            base_command=base_command,
            since_time=previous_last_seen_time,
        )
        stream_name = f"falco:{pod_name}"
        print(
            f"[{stream_name}] starting follower with command: {' '.join(command)}",
            file=sys.stderr,
        )
        try:
            for line in stream_command_lines(
                command,
                stream_name=stream_name,
                idle_timeout_seconds=0,
            ):
                if follower_state.stop_event.is_set():
                    break
                event_time = _extract_falco_event_time(line)
                if event_time and not _is_newer_falco_event_time(event_time, previous_last_seen_time):
                    print(
                        f"[{stream_name}] skipped replayed line at {event_time} (last_seen_time={previous_last_seen_time})",
                        file=sys.stderr,
                    )
                    continue
                if event_time:
                    follower_state.last_seen_time = event_time
                preview = line[:240]
                print(
                    f"[{stream_name}] received line preview: {preview}",
                    file=sys.stderr,
                )
                output_queue.put((pod_name, line))
                print(
                    f"[{stream_name}] queued line for pipeline",
                    file=sys.stderr,
                )
        except Exception as exc:
            print(f"[{stream_name}] collector error: {exc}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)

        if follower_state.stop_event.is_set():
            break
        time.sleep(DEFAULT_FALCO_POLL_INTERVAL_SECONDS)


def _hubble_can_connect(server: str) -> bool:
    try:
        result = subprocess.run(
            ["hubble", "status", "--server", server],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _wait_for_hubble_server(server: str, attempts: int = 12) -> bool:
    for _ in range(attempts):
        if _hubble_can_connect(server):
            return True
        time.sleep(1)
    return False


def _start_port_forward(command_string: str, *, log_path: str) -> subprocess.Popen[str]:
    log_file = open(log_path, "a", encoding="utf-8")
    try:
        process = subprocess.Popen(
            shlex.split(command_string),
            stdout=log_file,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except Exception:
        log_file.close()
        raise
    setattr(process, "_poding_log_file", log_file)
    return process


def stop_managed_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    log_file = getattr(process, "_poding_log_file", None)
    if log_file is not None:
        log_file.close()


def _try_port_forward(
    command_string: str,
    *,
    server: str,
    log_path: str,
) -> subprocess.Popen[str] | None:
    process = _start_port_forward(command_string, log_path=log_path)
    if _wait_for_hubble_server(server):
        _PORT_FORWARD_PROCESSES.append(process)
        return process
    stop_managed_process(process)
    return None


def ensure_hubble_connectivity(
    config: dict[str, Any] | None = None,
    *,
    override_server: str | None = None,
    override_command: str | None = None,
) -> tuple[str, subprocess.Popen[str] | None, str]:
    if override_command:
        server = override_server or str(
            (config or {}).get("hubble", {}).get(
                "server",
                FALLBACK_HUBBLE_SETTINGS["server"],
            )
        )
        return server, None, "custom-command"

    hubble_config = config.get("hubble", {}) if config else {}
    pipeline_config = config.get("pipeline", {}) if config else {}
    server = override_server or str(
        hubble_config.get("server", FALLBACK_HUBBLE_SETTINGS["server"])
    )

    if _hubble_can_connect(server):
        return server, None, "direct"

    # In-cluster deployments should target the Hubble relay service directly
    # instead of trying local port-forward helpers inside the detector pod.
    if not _is_local_hubble_endpoint(server):
        return server, None, "service-dns"

    relay_namespace = str(
        hubble_config.get(
            "relay_namespace",
            FALLBACK_HUBBLE_SETTINGS["relay_namespace"],
        )
    )
    relay_service = str(
        hubble_config.get(
            "relay_service",
            FALLBACK_HUBBLE_SETTINGS["relay_service"],
        )
    )
    relay_local_port = str(
        hubble_config.get(
            "relay_local_port",
            FALLBACK_HUBBLE_SETTINGS["relay_local_port"],
        )
    )
    relay_remote_port = str(
        hubble_config.get(
            "relay_remote_port",
            FALLBACK_HUBBLE_SETTINGS["relay_remote_port"],
        )
    )
    port_forward_command = str(
        hubble_config.get(
            "port_forward_command",
            FALLBACK_HUBBLE_SETTINGS["port_forward_command"],
        )
    )
    fallback_port_forward_command = str(
        hubble_config.get(
            "fallback_port_forward_command",
            FALLBACK_HUBBLE_SETTINGS["fallback_port_forward_command"],
        )
    )
    logs_dir = resolve_project_path(str(pipeline_config.get("logs_dir", "logs")))
    os.makedirs(logs_dir, exist_ok=True)
    log_path = str(Path(logs_dir) / "hubble-port-forward.log")
    local_server = f"localhost:{relay_local_port}"
    render_values = {
        "relay_namespace": relay_namespace,
        "relay_service": relay_service,
        "relay_local_port": relay_local_port,
        "relay_remote_port": relay_remote_port,
    }

    if port_forward_command:
        try:
            process = _try_port_forward(
                port_forward_command,
                server=local_server,
                log_path=log_path,
            )
        except OSError:
            process = None
        if process is not None:
            return local_server, process, "cilium-port-forward"

    rendered_fallback = _render_command_template(
        fallback_port_forward_command,
        render_values,
    )
    if rendered_fallback:
        try:
            process = _try_port_forward(
                rendered_fallback,
                server=local_server,
                log_path=log_path,
            )
        except OSError:
            process = None
        if process is not None:
            return local_server, process, "kubectl-port-forward"

    return server, None, "unavailable"


def stream_command_lines(
    command: Sequence[str],
    *,
    stream_name: str,
    idle_timeout_seconds: int = DEFAULT_STREAM_IDLE_TIMEOUT_SECONDS,
    force_tty: bool = False,
) -> Generator[str, None, None]:
    rendered_command = list(command)
    if force_tty:
        rendered_command = [
            "script",
            "-qec",
            shlex.join(rendered_command),
            "/dev/null",
        ]

    process = subprocess.Popen(
        rendered_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    stderr_thread = threading.Thread(
        target=_stream_stderr,
        args=(process.stderr, stream_name),
        daemon=True,
    )
    stderr_thread.start()

    stdout_queue: "queue.Queue[str | None]" = queue.Queue()

    def _stream_stdout(stdout, sink: "queue.Queue[str | None]") -> None:
        if stdout is None:
            sink.put(None)
            return
        try:
            for raw_line in iter(stdout.readline, ""):
                sink.put(raw_line)
        finally:
            sink.put(None)

    stdout_thread = threading.Thread(
        target=_stream_stdout,
        args=(process.stdout, stdout_queue),
        daemon=True,
    )
    stdout_thread.start()

    try:
        last_activity_at = time.monotonic()
        stdout_closed = False

        while True:
            try:
                raw_line = stdout_queue.get(timeout=1)
            except queue.Empty:
                if process.poll() is not None and stdout_closed:
                    break
                if idle_timeout_seconds > 0 and time.monotonic() - last_activity_at >= idle_timeout_seconds:
                    print(
                        f"[{stream_name}] idle timeout after {idle_timeout_seconds}s without new output; restarting collector",
                        file=sys.stderr,
                    )
                    break
                continue

            if raw_line is None:
                stdout_closed = True
                if process.poll() is not None:
                    break
                continue

            line = raw_line.rstrip("\n")
            if line:
                last_activity_at = time.monotonic()
                yield line
            continue

        return_code = process.wait()
        if return_code != 0:
            print(
                f"[{stream_name}] process exited with code {return_code}",
                file=sys.stderr,
            )
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def stream_falco_logs(
    command: Sequence[str] | None = None,
    *,
    continuous: bool = True,
    initial_since_time: str | None = None,
) -> Generator[str, None, None]:
    base_command = list(command or DEFAULT_FALCO_COMMAND)
    recent_lines: deque[str] = deque()
    recent_line_set: set[str] = set()
    if not _is_selector_falco_command(base_command):
        while True:
            for line in stream_command_lines(
                base_command,
                stream_name="falco",
                idle_timeout_seconds=15,
            ):
                if "{" not in line or "}" not in line:
                    continue
                if line in recent_line_set:
                    continue

                recent_lines.append(line)
                recent_line_set.add(line)
                if len(recent_lines) > DEFAULT_FALCO_RECENT_LINE_LIMIT:
                    expired = recent_lines.popleft()
                    recent_line_set.discard(expired)
                yield line

            if not continuous:
                break
            time.sleep(DEFAULT_FALCO_POLL_INTERVAL_SECONDS)
        return

    namespace, selector = _falco_command_details(base_command)
    if not selector:
        return

    output_queue: "queue.Queue[tuple[str, str]]" = queue.Queue()
    follower_states: dict[str, _FalcoFollowerState] = {}
    manager_stop_event = threading.Event()

    def ensure_followers() -> None:
        try:
            pod_names = _list_falco_pods(namespace, selector)
        except Exception as exc:
            print(f"[falco] failed to discover Falco pods: {exc}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            return

        active_pods = set(pod_names)
        for pod_name in pod_names:
            state = follower_states.get(pod_name)
            if state is None:
                state = _FalcoFollowerState(
                    pod_name=pod_name,
                    last_seen_time=initial_since_time,
                )
                follower_states[pod_name] = state
            if state.thread is not None and state.thread.is_alive():
                continue
            state.stop_event.clear()
            state.thread = threading.Thread(
                target=_falco_pod_follower,
                kwargs={
                    "namespace": namespace,
                    "pod_name": pod_name,
                    "base_command": base_command,
                    "output_queue": output_queue,
                    "follower_state": state,
                },
                daemon=True,
            )
            state.thread.start()
            print(
                f"[falco] started follower thread for pod={pod_name}",
                file=sys.stderr,
            )

        for pod_name, state in list(follower_states.items()):
            if pod_name in active_pods:
                continue
            state.stop_event.set()
            print(
                f"[falco] stopping follower thread for removed pod={pod_name}",
                file=sys.stderr,
            )
            follower_states.pop(pod_name, None)

    manager_thread = threading.Thread(
        target=lambda: _run_falco_follower_manager(ensure_followers, manager_stop_event),
        daemon=True,
    )
    manager_thread.start()

    try:
        while True:
            try:
                pod_name, line = output_queue.get(timeout=1)
            except queue.Empty:
                if not continuous and not any(
                    state.thread is not None and state.thread.is_alive() for state in follower_states.values()
                ):
                    break
                continue

            if "{" not in line or "}" not in line:
                continue

            dedupe_key = _falco_dedupe_key(pod_name, line)
            if dedupe_key in recent_line_set:
                continue

            recent_lines.append(dedupe_key)
            recent_line_set.add(dedupe_key)
            if len(recent_lines) > DEFAULT_FALCO_RECENT_LINE_LIMIT:
                expired = recent_lines.popleft()
                recent_line_set.discard(expired)
            yield line
    finally:
        manager_stop_event.set()
        for state in follower_states.values():
            state.stop_event.set()


def _run_falco_follower_manager(ensure_followers, stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        ensure_followers()
        stop_event.wait(DEFAULT_FALCO_POD_DISCOVERY_INTERVAL_SECONDS)


def stream_hubble_observe(
    command: Sequence[str] | None = None,
) -> Generator[str, None, None]:
    yield from stream_command_lines(
        command or DEFAULT_HUBBLE_COMMAND,
        stream_name="hubble",
    )

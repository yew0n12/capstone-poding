"""DARPA TC CDM Avro replay adapter.

This module translates DARPA Transparent Computing CDM v20 records into the
same replay inputs used by the rest of Pod-ing:

* Falco-like dictionaries consumed by ``parsers.falco_parser.parse_falco_event``.
* Hubble-like ``RawEvent`` objects consumed by ``parsers.event_mapper``.

The implementation intentionally keeps the Kubernetes claim scoped. TC THEIA is
host provenance data, not Kubernetes telemetry, so host identities are mapped to
synthetic namespaces/pods only to exercise Pod-ing's lateral-movement FSM.

The project environment used for the PoC does not currently ship ``fastavro``.
To keep the workflow reproducible, this file includes a small Avro Object
Container File reader that supports the Avro primitives used by CDM20.
"""

from __future__ import annotations

import gzip
import io
import json
import logging
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Dict, Iterable, Iterator, List, Optional, Tuple, Union

from parsers.raw_event import RawEvent


LOGGER = logging.getLogger(__name__)

PrimitiveSchema = Union[str, Dict[str, Any], List[Any]]
ReplayInput = Union[Dict[str, Any], RawEvent]

_AVRO_MAGIC = b"Obj\x01"
_PRIMITIVES = {"null", "boolean", "int", "long", "float", "double", "bytes", "string"}
_COMPLEX_TYPES = {"record", "enum", "fixed", "array", "map"}
_TCP_PROTOCOL = 6


# ---------------------------------------------------------------------------
# Minimal Avro OCF reader
# ---------------------------------------------------------------------------


class AvroDecodeError(ValueError):
    """Raised when an Avro container cannot be decoded by the local reader."""


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    data = stream.read(size)
    if len(data) != size:
        raise EOFError("unexpected EOF while reading Avro data")
    return data


def _read_long(stream: BinaryIO) -> int:
    shift = 0
    raw = 0
    while True:
        byte = stream.read(1)
        if not byte:
            raise EOFError("unexpected EOF while reading Avro long")
        value = byte[0]
        raw |= (value & 0x7F) << shift
        if not value & 0x80:
            break
        shift += 7
    return (raw >> 1) ^ -(raw & 1)


def _read_bool(stream: BinaryIO) -> bool:
    return _read_exact(stream, 1) != b"\x00"


def _read_bytes(stream: BinaryIO) -> bytes:
    size = _read_long(stream)
    if size < 0:
        raise AvroDecodeError(f"negative byte-string size: {size}")
    return _read_exact(stream, size)


def _read_string(stream: BinaryIO) -> str:
    return _read_bytes(stream).decode("utf-8", errors="replace")


def _read_header_map(stream: BinaryIO) -> Dict[str, bytes]:
    values: Dict[str, bytes] = {}
    while True:
        count = _read_long(stream)
        if count == 0:
            return values
        if count < 0:
            count = -count
            _block_size = _read_long(stream)
        for _ in range(count):
            key = _read_string(stream)
            values[key] = _read_bytes(stream)


def _fullname(name: str, namespace: Optional[str]) -> str:
    if "." in name or not namespace:
        return name
    return f"{namespace}.{name}"


def _schema_name(schema: PrimitiveSchema, namespace: Optional[str] = None) -> str:
    if isinstance(schema, str):
        return schema
    if isinstance(schema, list):
        return "union"
    schema_type = schema.get("type")
    if isinstance(schema_type, str) and schema_type in {"record", "enum", "fixed"}:
        return _fullname(str(schema["name"]), schema.get("namespace") or namespace)
    if isinstance(schema_type, str):
        return schema_type
    return "unknown"


class _AvroSchemaRegistry:
    def __init__(self, schema: Dict[str, Any]):
        self.root = schema
        self.names: Dict[str, Dict[str, Any]] = {}
        self._register(schema, schema.get("namespace"))

    def resolve(self, schema: PrimitiveSchema, namespace: Optional[str] = None) -> PrimitiveSchema:
        if not isinstance(schema, str) or schema in _PRIMITIVES:
            return schema
        return self.names[_fullname(schema, namespace)]

    def _register(self, schema: PrimitiveSchema, namespace: Optional[str]) -> None:
        if isinstance(schema, str):
            return
        if isinstance(schema, list):
            for branch in schema:
                self._register(branch, namespace)
            return

        schema_type = schema.get("type")
        current_namespace = schema.get("namespace") or namespace
        if schema_type in {"record", "enum", "fixed"}:
            full = _fullname(str(schema["name"]), current_namespace)
            schema.setdefault("__fullname", full)
            self.names[full] = schema

        if schema_type == "record":
            for field in schema.get("fields", []):
                self._register(field["type"], current_namespace)
        elif schema_type == "array":
            self._register(schema["items"], current_namespace)
        elif schema_type == "map":
            self._register(schema["values"], current_namespace)
        elif isinstance(schema_type, (dict, list)):
            self._register(schema_type, current_namespace)


class AvroObjectContainerReader:
    """Small Avro Object Container File reader for CDM replay files."""

    def __init__(self, stream: BinaryIO):
        self.stream = stream
        self.metadata: Dict[str, bytes] = {}
        self.schema: Dict[str, Any] = {}
        self.codec = "null"
        self.sync_marker = b""
        self.registry: Optional[_AvroSchemaRegistry] = None
        self._read_header()

    def __iter__(self) -> Iterator[Dict[str, Any]]:
        while True:
            try:
                block_count = _read_long(self.stream)
            except EOFError:
                return
            block_size = _read_long(self.stream)
            block_data = _read_exact(self.stream, block_size)
            sync = _read_exact(self.stream, 16)
            if sync != self.sync_marker:
                raise AvroDecodeError("Avro sync marker mismatch")

            decoded = self._decode_block(block_data)
            for _ in range(block_count):
                yield self._decode(self.schema, decoded, self.schema.get("namespace"))

    def _read_header(self) -> None:
        magic = _read_exact(self.stream, 4)
        if magic != _AVRO_MAGIC:
            raise AvroDecodeError(f"unsupported Avro container magic: {magic!r}")

        self.metadata = _read_header_map(self.stream)
        raw_schema = self.metadata.get("avro.schema")
        if not raw_schema:
            raise AvroDecodeError("Avro container is missing avro.schema metadata")
        self.schema = json.loads(raw_schema.decode("utf-8"))
        self.codec = self.metadata.get("avro.codec", b"null").decode("utf-8")
        self.sync_marker = _read_exact(self.stream, 16)
        self.registry = _AvroSchemaRegistry(self.schema)

    def _decode_block(self, block_data: bytes) -> io.BytesIO:
        if self.codec == "null":
            return io.BytesIO(block_data)
        if self.codec == "deflate":
            return io.BytesIO(zlib.decompress(block_data, -15))
        raise AvroDecodeError(f"unsupported Avro codec: {self.codec}")

    def _decode(
        self,
        schema: PrimitiveSchema,
        stream: BinaryIO,
        namespace: Optional[str],
    ) -> Any:
        assert self.registry is not None
        schema = self.registry.resolve(schema, namespace)

        if isinstance(schema, str):
            if schema == "null":
                return None
            if schema == "boolean":
                return _read_bool(stream)
            if schema in {"int", "long"}:
                return _read_long(stream)
            if schema == "bytes":
                return _read_bytes(stream)
            if schema == "string":
                return _read_string(stream)
            if schema == "float":
                import struct

                return struct.unpack("<f", _read_exact(stream, 4))[0]
            if schema == "double":
                import struct

                return struct.unpack("<d", _read_exact(stream, 8))[0]
            raise AvroDecodeError(f"unsupported primitive schema: {schema}")

        if isinstance(schema, list):
            branch_index = _read_long(stream)
            try:
                branch = schema[branch_index]
            except IndexError as exc:
                raise AvroDecodeError(f"invalid union branch index: {branch_index}") from exc
            value = self._decode(branch, stream, namespace)
            return value

        schema_type = schema.get("type")
        if isinstance(schema_type, (dict, list)):
            return self._decode(schema_type, stream, namespace)
        if isinstance(schema_type, str) and schema_type not in _PRIMITIVES | _COMPLEX_TYPES:
            resolved = self.registry.resolve(schema_type, namespace)
            if resolved is not schema:
                return self._decode(resolved, stream, namespace)

        if schema_type == "record":
            current_namespace = schema.get("namespace") or namespace
            record = {"__cdm_type": schema.get("name", "record")}
            for field in schema.get("fields", []):
                record[field["name"]] = self._decode(field["type"], stream, current_namespace)
            return record
        if schema_type == "enum":
            index = _read_long(stream)
            return schema["symbols"][index]
        if schema_type == "fixed":
            return _read_exact(stream, int(schema["size"]))
        if schema_type == "array":
            items: List[Any] = []
            while True:
                count = _read_long(stream)
                if count == 0:
                    return items
                if count < 0:
                    count = -count
                    _block_size = _read_long(stream)
                for _ in range(count):
                    items.append(self._decode(schema["items"], stream, namespace))
        if schema_type == "map":
            values: Dict[str, Any] = {}
            while True:
                count = _read_long(stream)
                if count == 0:
                    return values
                if count < 0:
                    count = -count
                    _block_size = _read_long(stream)
                for _ in range(count):
                    values[_read_string(stream)] = self._decode(schema["values"], stream, namespace)

        return self._decode(str(schema_type), stream, namespace)


def iter_avro_ocf_gzip(path: Path) -> Iterator[Dict[str, Any]]:
    """Yield decoded Avro records from one ``.gz`` wrapped OCF file."""
    with gzip.open(path, "rb") as stream:
        yield from AvroObjectContainerReader(stream)


# ---------------------------------------------------------------------------
# CDM -> Pod-ing mapping
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SyntheticPod:
    namespace: str
    pod_name: str
    node_name: str


@dataclass(frozen=True)
class CdmHost:
    uuid: str
    host_name: str
    ip_addresses: Tuple[str, ...]
    pod: SyntheticPod


@dataclass(frozen=True)
class CdmSubject:
    uuid: str
    host_uuid: str
    cid: int
    cmd_line: str
    parent_subject: str = ""


@dataclass(frozen=True)
class CdmNetFlowObject:
    uuid: str
    host_uuid: str
    local_address: str
    local_port: Optional[int]
    remote_address: str
    remote_port: Optional[int]
    protocol: Optional[int]


@dataclass
class CdmAdapterConfig:
    namespace_prefix: str = "darpa-tc"
    node_name: str = "darpa-tc-theia"
    target_host_ips: Tuple[str, ...] = ("128.55.12.110",)
    target_host_names: Tuple[str, ...] = ("ta1-theia-target-1",)
    host_namespace_overrides: Dict[str, str] = field(
        default_factory=lambda: {
            "ta1-theia-target-1": "darpa-tc-theia",
            "ta51-pivot-1": "darpa-tc-pivot",
            "ta1-cadets-1": "darpa-tc-cadets",
            "ta1-trace-2": "darpa-tc-trace",
        }
    )
    host_pod_overrides: Dict[str, str] = field(
        default_factory=lambda: {
            "128.55.12.110": "ta1-theia-target-1",
            "10.0.6.60": "ta1-theia-target-1",
            "128.55.12.149": "ta51-pivot-1",
            "128.55.12.51": "ta1-cadets-1",
            "128.55.12.118": "ta1-trace-2",
        }
    )
    shell_process_names: Tuple[str, ...] = ("sh", "bash", "dash", "zsh", "ksh")
    network_tool_names: Tuple[str, ...] = ("ssh", "sshd", "scp", "sftp", "nmap")
    ssh_tool_names: Tuple[str, ...] = ("ssh", "sshd", "sftp")
    scp_tool_names: Tuple[str, ...] = ("scp",)
    scan_tool_names: Tuple[str, ...] = ("nmap",)
    ssh_ports: Tuple[int, ...] = (22,)
    emit_raw_network_events: bool = True
    emit_propagation_seed: bool = True


class CdmAdapter:
    """Stateful CDM record translator for THEIA replay windows."""

    def __init__(self, config: Optional[CdmAdapterConfig] = None):
        self.config = config or CdmAdapterConfig()
        self.hosts: Dict[str, CdmHost] = {}
        self.hosts_by_ip: Dict[str, CdmHost] = {}
        self.subjects: Dict[str, CdmSubject] = {}
        self.netflows: Dict[str, CdmNetFlowObject] = {}
        self.file_objects: Dict[str, str] = {}
        self._emitted_propagation: set[Tuple[str, str, str]] = set()

    def iter_poding_inputs(
        self,
        paths: Iterable[Path],
        *,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        limit_records: Optional[int] = None,
    ) -> Iterator[ReplayInput]:
        """Stream decoded CDM records as Pod-ing replay inputs."""
        seen = 0
        for path in sorted((Path(p) for p in paths), key=lambda item: _chunk_sort_key(item.name)):
            LOGGER.info("reading CDM Avro file %s", path)
            for record in iter_avro_ocf_gzip(path):
                seen += 1
                if limit_records is not None and seen > limit_records:
                    return
                yield from self.ingest_record(record, start=start, end=end)

    def ingest_metadata_only(self, record: Dict[str, Any]) -> None:
        """Pass-1 helper for parallel replay: update HOST/SUBJECT/NETFLOW/FILE_OBJECT state and skip events."""
        record_type = str(record.get("type") or "")
        if record_type not in {
            "RECORD_HOST",
            "RECORD_SUBJECT",
            "RECORD_NET_FLOW_OBJECT",
            "RECORD_FILE_OBJECT",
        }:
            return
        datum = record.get("datum") or {}
        host_id = _uuid_str(record.get("hostId"))
        if record_type == "RECORD_HOST":
            self._remember_host(host_id, datum)
        elif record_type == "RECORD_SUBJECT":
            self._remember_subject(host_id, datum)
        elif record_type == "RECORD_NET_FLOW_OBJECT":
            self._remember_netflow(host_id, datum)
        else:
            self._remember_file_object(datum)

    def ingest_record(
        self,
        record: Dict[str, Any],
        *,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
    ) -> Iterator[ReplayInput]:
        record_type = str(record.get("type") or "")
        datum = record.get("datum") or {}
        host_id = _uuid_str(record.get("hostId"))

        if record_type == "RECORD_HOST":
            self._remember_host(host_id, datum)
            return
        if record_type == "RECORD_SUBJECT":
            self._remember_subject(host_id, datum)
            return
        if record_type == "RECORD_NET_FLOW_OBJECT":
            self._remember_netflow(host_id, datum)
            return
        if record_type == "RECORD_FILE_OBJECT":
            self._remember_file_object(datum)
            return
        if record_type != "RECORD_EVENT":
            return

        observed_at = _datetime_from_nanos(datum.get("timestampNanos"))
        if observed_at is None or not _within_window(observed_at, start, end):
            return

        for event in self._event_to_replay_inputs(record, datum, host_id, observed_at):
            yield event

    def _remember_host(self, host_id: str, datum: Dict[str, Any]) -> None:
        uuid = _uuid_str(datum.get("uuid")) or host_id
        host_name = str(datum.get("hostName") or "")
        ips: List[str] = []
        for interface in datum.get("interfaces") or []:
            for ip in interface.get("ipAddresses") or []:
                if ip:
                    ips.append(str(ip))

        pod = self._synthetic_pod(host_name=host_name, ip_addresses=tuple(ips))
        host = CdmHost(uuid=uuid, host_name=host_name, ip_addresses=tuple(ips), pod=pod)
        self.hosts[uuid] = host
        if host_id and host_id != uuid:
            self.hosts[host_id] = host
        for ip in ips:
            self.hosts_by_ip[ip] = host

    def _remember_subject(self, host_id: str, datum: Dict[str, Any]) -> None:
        uuid = _uuid_str(datum.get("uuid"))
        if not uuid:
            return
        self.subjects[uuid] = CdmSubject(
            uuid=uuid,
            host_uuid=host_id,
            cid=int(datum.get("cid") or 0),
            cmd_line=str(datum.get("cmdLine") or ""),
            parent_subject=_uuid_str(datum.get("parentSubject")),
        )

    def _remember_file_object(self, datum: Dict[str, Any]) -> None:
        """THEIA stores filenames inside FileObject.baseObject.properties as
        an inverted dict where the actual path is the key and the literal
        string ``"filename"`` is the value.
        """
        uuid = _uuid_str(datum.get("uuid"))
        if not uuid:
            return
        base = datum.get("baseObject") or {}
        props = base.get("properties") or {}
        if not isinstance(props, dict):
            return
        for key, value in props.items():
            if value == "filename" and key:
                self.file_objects[uuid] = str(key)
                return

    def _remember_netflow(self, host_id: str, datum: Dict[str, Any]) -> None:
        uuid = _uuid_str(datum.get("uuid"))
        if not uuid:
            return
        self.netflows[uuid] = CdmNetFlowObject(
            uuid=uuid,
            host_uuid=host_id,
            local_address=str(datum.get("localAddress") or ""),
            local_port=_optional_int(datum.get("localPort")),
            remote_address=str(datum.get("remoteAddress") or ""),
            remote_port=_optional_int(datum.get("remotePort")),
            protocol=_optional_int(datum.get("ipProtocol")),
        )

    def _event_to_replay_inputs(
        self,
        record: Dict[str, Any],
        datum: Dict[str, Any],
        host_id: str,
        observed_at: datetime,
    ) -> Iterator[ReplayInput]:
        event_type = str(datum.get("type") or "")
        event_uuid = _uuid_str(datum.get("uuid")) or f"cdm-{datum.get('sequence')}"
        subject = self.subjects.get(_uuid_str(datum.get("subject")))
        subject_host = self.hosts.get(subject.host_uuid if subject else host_id)
        predicate_uuid = _uuid_str(datum.get("predicateObject"))
        inline_path = str(datum.get("predicateObjectPath") or "")
        resolved_path = inline_path or self.file_objects.get(predicate_uuid, "")

        if event_type == "EVENT_EXECUTE" and subject_host:
            falco_dict = self._process_event_to_falco(
                event_uuid=event_uuid,
                observed_at=observed_at,
                event_type=event_type,
                subject=subject,
                host=subject_host,
                path=resolved_path,
            )
            if falco_dict is not None:
                yield falco_dict

        if event_type in {"EVENT_OPEN", "EVENT_READ"} and subject_host:
            falco_dict = self._file_event_to_falco(
                event_uuid=event_uuid,
                observed_at=observed_at,
                event_type=event_type,
                subject=subject,
                host=subject_host,
                path=resolved_path,
            )
            if falco_dict is not None:
                yield falco_dict

        netflow = self.netflows.get(predicate_uuid)
        if netflow is None:
            return

        raw = self._netflow_event_to_raw(
            event_uuid=event_uuid,
            observed_at=observed_at,
            event_type=event_type,
            subject=subject,
            netflow=netflow,
        )
        if raw is None:
            return

        if self.config.emit_propagation_seed:
            seed = self._netflow_event_to_propagation_seed(
                event_uuid=event_uuid,
                observed_at=observed_at,
                event_type=event_type,
                raw=raw,
            )
            if seed is not None:
                yield seed

        if self.config.emit_raw_network_events:
            yield raw

    def _process_event_to_falco(
        self,
        *,
        event_uuid: str,
        observed_at: datetime,
        event_type: str,
        subject: Optional[CdmSubject],
        host: CdmHost,
        path: str,
    ) -> Optional[Dict[str, Any]]:
        cmdline = (subject.cmd_line if subject else "") or path
        proc_name = _process_name(cmdline or path)
        lowered = proc_name.lower()

        tool_kind = ""
        if lowered in self.config.shell_process_names:
            rule_name = "Shell Exec in Container"
        elif lowered in self.config.network_tool_names:
            rule_name = "THEIA Host Network Tool"
            tool_kind = self._classify_tool_kind(lowered)
        else:
            return None

        tool_suffix = f" tool_kind={tool_kind}" if tool_kind else ""
        return _falco_dict(
            rule_name=rule_name,
            event_id=f"cdm-{event_uuid}",
            observed_at=observed_at,
            host=host,
            output=(
                f"{rule_name} from CDM {event_type} "
                f"(host={host.host_name} proc={proc_name}{tool_suffix} cmdline={cmdline})"
            ),
            output_fields={
                "proc.name": proc_name,
                "proc.cmdline": cmdline,
                "evt.type": event_type,
                "container.name": host.pod.pod_name,
                "theia.tool_kind": tool_kind,
            },
        )

    def _classify_tool_kind(self, proc_name: str) -> str:
        name = proc_name.lower()
        if name in self.config.scan_tool_names:
            return "nmap"
        if name in self.config.ssh_tool_names:
            return "ssh"
        if name in self.config.scp_tool_names:
            return "scp"
        return ""

    def _file_event_to_falco(
        self,
        *,
        event_uuid: str,
        observed_at: datetime,
        event_type: str,
        subject: Optional[CdmSubject],
        host: CdmHost,
        path: str,
    ) -> Optional[Dict[str, Any]]:
        if not _is_sensitive_path(path):
            return None

        cmdline = subject.cmd_line if subject else ""
        proc_name = _process_name(cmdline)
        return _falco_dict(
            rule_name="THEIA Host Credential Read",
            event_id=f"cdm-{event_uuid}",
            observed_at=observed_at,
            host=host,
            output=(
                "THEIA Host Credential Read from CDM "
                f"{event_type} (host={host.host_name} file={path} proc={proc_name})"
            ),
            output_fields={
                "proc.name": proc_name,
                "proc.cmdline": cmdline,
                "fd.name": path,
                "evt.type": event_type,
                "container.name": host.pod.pod_name,
            },
        )

    def _netflow_event_to_raw(
        self,
        *,
        event_uuid: str,
        observed_at: datetime,
        event_type: str,
        subject: Optional[CdmSubject],
        netflow: CdmNetFlowObject,
    ) -> Optional[RawEvent]:
        local_host = self.hosts.get(netflow.host_uuid) or self.hosts_by_ip.get(netflow.local_address)
        if local_host is None:
            return None

        remote_host, remote_is_synthetic = self._resolve_remote_endpoint(netflow.remote_address)
        direction = _direction_for_network_event(event_type, netflow)
        # THEIA host audit: never expose a remote host as a Kubernetes peer pod.
        # K8s pod-to-pod symbols (E_same_ns, E_cross_ns) must not be derived from
        # host-audit netflows. Synthetic remotes are surfaced via the
        # `remote_host_endpoint` official field only.
        peer_pod = None
        peer_namespace = None
        peer_node = None
        remote_endpoint_name = remote_host.host_name if remote_host else ""

        protocol = {6: "TCP", 17: "UDP"}.get(netflow.protocol or 0, str(netflow.protocol or ""))
        if direction == "ingress":
            source_ip = netflow.remote_address
            source_port = netflow.remote_port
            destination_ip = netflow.local_address
            destination_port = netflow.local_port
        else:
            source_ip = netflow.local_address
            source_port = netflow.local_port
            destination_ip = netflow.remote_address
            destination_port = netflow.remote_port

        description = (
            f"CDM {event_type} {source_ip}:{source_port or 0} "
            f"-> {destination_ip}:{destination_port or 0}"
        )
        if subject and subject.cmd_line:
            description += f" proc={_process_name(subject.cmd_line)}"

        return RawEvent(
            observed_at=observed_at,
            event_id=f"cdm-{event_uuid}",
            event_source="hubble",
            subject_pod=local_host.pod.pod_name,
            namespace=local_host.pod.namespace,
            node_name=local_host.pod.node_name,
            workload_name=local_host.pod.pod_name,
            description=description,
            role="trigger",
            flow_pattern=direction,
            peer_pod=peer_pod,
            peer_namespace=peer_namespace,
            peer_node_name=peer_node,
            peer_workload_name=peer_pod,
            official_fields={
                "direction": direction,
                "source_ip": source_ip,
                "source_port": source_port,
                "destination_ip": destination_ip,
                "destination_port": destination_port,
                "protocol": protocol,
                "cdm_event_type": event_type,
                "cdm_netflow_uuid": netflow.uuid,
                "cdm_subject_uuid": subject.uuid if subject else "",
                "cdm_subject_cmdline": subject.cmd_line if subject else "",
                "remote_host_endpoint": remote_endpoint_name,
                "remote_host_endpoint_is_synthetic": remote_is_synthetic,
            },
        )

    def _resolve_remote_endpoint(
        self, remote_address: str
    ) -> Tuple[Optional[CdmHost], bool]:
        """Resolve a netflow remote IP to either a real CdmHost or a synthetic
        remote-host endpoint derived from ``host_pod_overrides``.

        The synthetic host is NOT a Kubernetes pod — callers must keep
        ``peer_pod``/``peer_namespace`` unset so the K8s lateral-movement
        symbols (E_same_ns, E_cross_ns, new_pod_connection) cannot be inferred
        from THEIA host-audit telemetry.
        """
        if not remote_address:
            return None, False
        host = self.hosts_by_ip.get(remote_address)
        if host is not None:
            return host, False
        override_name = self.config.host_pod_overrides.get(remote_address)
        if not override_name:
            return None, False
        pod = self._synthetic_pod(host_name=override_name, ip_addresses=(remote_address,))
        synthetic = CdmHost(
            uuid="",
            host_name=override_name,
            ip_addresses=(remote_address,),
            pod=pod,
        )
        return synthetic, True

    def _netflow_event_to_propagation_seed(
        self,
        *,
        event_uuid: str,
        observed_at: datetime,
        event_type: str,
        raw: RawEvent,
    ) -> Optional[Dict[str, Any]]:
        if raw.flow_pattern != "ingress":
            return None
        if raw.official_fields.get("destination_port") not in self.config.ssh_ports:
            return None
        remote_endpoint = str(raw.official_fields.get("remote_host_endpoint") or "")
        if not remote_endpoint:
            return None
        if not self._is_target_pod(raw.namespace, raw.subject_pod):
            return None

        source_ip = str(raw.official_fields.get("source_ip") or "")
        key = (raw.namespace, raw.subject_pod, remote_endpoint, source_ip)
        if key in self._emitted_propagation:
            return None
        self._emitted_propagation.add(key)

        host = CdmHost(
            uuid="",
            host_name=raw.subject_pod,
            ip_addresses=(source_ip,),
            pod=SyntheticPod(raw.namespace, raw.subject_pod, raw.node_name),
        )
        return _falco_dict(
            rule_name="THEIA Host Lateral Inbound",
            event_id=f"cdm-host-lateral-{event_uuid}",
            observed_at=observed_at,
            host=host,
            output=(
                "THEIA Host Lateral Inbound from CDM "
                f"{event_type} remote_host_endpoint={remote_endpoint} "
                f"source_ip={source_ip}"
            ),
            output_fields={
                "proc.name": "sshd",
                "proc.cmdline": raw.description,
                "evt.type": event_type,
                "fd.sip": source_ip,
                "fd.sport": str(raw.official_fields.get("source_port") or ""),
                "container.name": raw.subject_pod,
                "theia.remote_host_endpoint": remote_endpoint,
            },
        )

    def _is_target_pod(self, namespace: str, pod_name: str) -> bool:
        del namespace
        target_names = {name.lower() for name in self.config.target_host_names}
        return pod_name.lower() in target_names

    def _synthetic_pod(self, *, host_name: str, ip_addresses: Tuple[str, ...]) -> SyntheticPod:
        pod_name = ""
        for key in (host_name, *ip_addresses):
            if key in self.config.host_pod_overrides:
                pod_name = self.config.host_pod_overrides[key]
                break
        if not pod_name:
            pod_name = _sanitize_name(host_name or (ip_addresses[0] if ip_addresses else "unknown-host"))

        namespace = self.config.host_namespace_overrides.get(pod_name)
        if namespace is None:
            if pod_name.startswith("ta1-theia"):
                namespace = "darpa-tc-theia"
            else:
                namespace = f"{self.config.namespace_prefix}-external-hosts"

        return SyntheticPod(namespace=namespace, pod_name=pod_name, node_name=self.config.node_name)


# ---------------------------------------------------------------------------
# Parallel replay (multiprocessing)
# ---------------------------------------------------------------------------
#
# CdmAdapter accumulates state from RECORD_HOST/SUBJECT/NET_FLOW_OBJECT records
# that earlier files may define for events later files reference. To parallelize
# safely we use two passes:
#
#   Pass 1: each worker decodes one file and returns only the metadata state
#           it observed. The main process merges into a single adapter view.
#   Pass 2: each worker is forked from the main process and inherits the merged
#           state via copy-on-write, then decodes its file again and yields
#           events filtered by the time window.
#
# Workers each have a private CdmAdapter, so cross-file dedup of "Propagation
# Received From Suspect" seeds is broken. The main process dedupes by
# (namespace, subject_pod, fd.sip) after Pass 2.


_WORKER_HOSTS: Optional[Dict[str, "CdmHost"]] = None
_WORKER_SUBJECTS: Optional[Dict[str, "CdmSubject"]] = None
_WORKER_NETFLOWS: Optional[Dict[str, "CdmNetFlowObject"]] = None
_WORKER_HOSTS_BY_IP: Optional[Dict[str, "CdmHost"]] = None
_WORKER_FILE_OBJECTS: Optional[Dict[str, str]] = None


def _worker_extract_metadata(
    file_path: str,
) -> Tuple[
    Dict[str, "CdmHost"],
    Dict[str, "CdmSubject"],
    Dict[str, "CdmNetFlowObject"],
    Dict[str, str],
]:
    adapter = CdmAdapter()
    for record in iter_avro_ocf_gzip(Path(file_path)):
        adapter.ingest_metadata_only(record)
    LOGGER.info(
        "pass1 done %s: hosts=%d subjects=%d netflows=%d file_objects=%d",
        file_path,
        len(adapter.hosts),
        len(adapter.subjects),
        len(adapter.netflows),
        len(adapter.file_objects),
    )
    return adapter.hosts, adapter.subjects, adapter.netflows, adapter.file_objects


def _worker_extract_events(
    args: Tuple[str, Optional[datetime], Optional[datetime]],
) -> List[ReplayInput]:
    file_path, start, end = args
    adapter = CdmAdapter()
    if _WORKER_HOSTS is not None:
        adapter.hosts = _WORKER_HOSTS
        adapter.hosts_by_ip = _WORKER_HOSTS_BY_IP or {}
        adapter.subjects = _WORKER_SUBJECTS or {}
        adapter.netflows = _WORKER_NETFLOWS or {}
        adapter.file_objects = _WORKER_FILE_OBJECTS or {}
    items: List[ReplayInput] = []
    for record in iter_avro_ocf_gzip(Path(file_path)):
        for item in adapter.ingest_record(record, start=start, end=end):
            items.append(item)
    LOGGER.info("pass2 done %s: yielded=%d", file_path, len(items))
    return items


def replay_parallel(
    paths: Iterable[Path],
    *,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    n_workers: int = 4,
) -> List[ReplayInput]:
    """Parallel two-pass replay across CDM ``.gz`` files.

    Returns a sorted (by observed_at) list of replay inputs equivalent to what a
    single-process ``CdmAdapter.iter_poding_inputs`` would yield, modulo the
    propagation-seed dedup that's enforced post-merge.
    """
    import gc
    import multiprocessing as mp

    paths_sorted = sorted(
        (Path(p) for p in paths), key=lambda item: _chunk_sort_key(item.name)
    )
    if not paths_sorted:
        return []

    n_workers = max(1, min(n_workers, len(paths_sorted)))

    LOGGER.info(
        "replay_parallel pass1: extracting metadata from %d files (%d workers)",
        len(paths_sorted),
        n_workers,
    )
    ctx = mp.get_context("fork")
    with ctx.Pool(n_workers) as pool:
        pass1_results = pool.map(_worker_extract_metadata, [str(p) for p in paths_sorted])

    merged_hosts: Dict[str, CdmHost] = {}
    merged_subjects: Dict[str, CdmSubject] = {}
    merged_netflows: Dict[str, CdmNetFlowObject] = {}
    merged_file_objects: Dict[str, str] = {}
    for hosts, subjects, netflows, file_objects in pass1_results:
        merged_hosts.update(hosts)
        merged_subjects.update(subjects)
        merged_netflows.update(netflows)
        merged_file_objects.update(file_objects)
    del pass1_results
    gc.collect()

    merged_hosts_by_ip: Dict[str, CdmHost] = {}
    for host in merged_hosts.values():
        for ip in host.ip_addresses:
            merged_hosts_by_ip[ip] = host

    LOGGER.info(
        "replay_parallel pass1 merged: hosts=%d subjects=%d netflows=%d "
        "hosts_by_ip=%d file_objects=%d",
        len(merged_hosts),
        len(merged_subjects),
        len(merged_netflows),
        len(merged_hosts_by_ip),
        len(merged_file_objects),
    )

    global _WORKER_HOSTS, _WORKER_SUBJECTS, _WORKER_NETFLOWS, _WORKER_HOSTS_BY_IP
    global _WORKER_FILE_OBJECTS
    _WORKER_HOSTS = merged_hosts
    _WORKER_SUBJECTS = merged_subjects
    _WORKER_NETFLOWS = merged_netflows
    _WORKER_HOSTS_BY_IP = merged_hosts_by_ip
    _WORKER_FILE_OBJECTS = merged_file_objects

    try:
        LOGGER.info(
            "replay_parallel pass2: extracting events (%d workers)", n_workers
        )
        args_list = [(str(p), start, end) for p in paths_sorted]
        with ctx.Pool(n_workers) as pool:
            pass2_results = pool.map(_worker_extract_events, args_list)
    finally:
        _WORKER_HOSTS = None
        _WORKER_SUBJECTS = None
        _WORKER_NETFLOWS = None
        _WORKER_HOSTS_BY_IP = None
        _WORKER_FILE_OBJECTS = None

    items: List[ReplayInput] = []
    for batch in pass2_results:
        items.extend(batch)
    del pass2_results
    gc.collect()

    seen_propagation: set = set()
    deduped: List[ReplayInput] = []
    propagation_rule_names = {
        "Propagation Received From Suspect",
        "THEIA Host Lateral Inbound",
    }
    for item in items:
        if isinstance(item, dict) and item.get("rule") in propagation_rule_names:
            fields = item.get("output_fields") or {}
            key = (
                item.get("rule"),
                item.get("namespace"),
                item.get("pod_name"),
                fields.get("fd.sip"),
                fields.get("theia.remote_host_endpoint", ""),
            )
            if key in seen_propagation:
                continue
            seen_propagation.add(key)
        deduped.append(item)

    LOGGER.info(
        "replay_parallel pass2 done: raw=%d deduped=%d", len(items), len(deduped)
    )
    return deduped


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def discover_cdm_gz_files(root: Path) -> List[Path]:
    """Return CDM ``.bin*.gz`` files under a directory in deterministic order."""
    return sorted(Path(root).glob("*.bin*.gz"), key=lambda path: _chunk_sort_key(path.name))


def theia_e5_lateral_window() -> Tuple[datetime, datetime]:
    """Ground-truth window for 2019-05-10 THEIA Nmap/SSH/SCP segment."""
    return (
        datetime(2019, 5, 10, 17, 45, 0, tzinfo=timezone.utc),
        datetime(2019, 5, 10, 18, 23, 0, tzinfo=timezone.utc),
    )


def theia_e5_inject_window() -> Tuple[datetime, datetime]:
    """Fallback ground-truth window for 2019-05-15 THEIA Drakon/elevate/inject."""
    return (
        datetime(2019, 5, 15, 18, 48, 0, tzinfo=timezone.utc),
        datetime(2019, 5, 15, 19, 8, 0, tzinfo=timezone.utc),
    )


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------


def _uuid_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.hex()
    return str(value)


def _datetime_from_nanos(value: Any) -> Optional[datetime]:
    try:
        nanos = int(value)
    except (TypeError, ValueError):
        return None
    return datetime.fromtimestamp(nanos / 1_000_000_000, tz=timezone.utc)


def _within_window(
    observed_at: datetime,
    start: Optional[datetime],
    end: Optional[datetime],
) -> bool:
    if start is not None and observed_at < start:
        return False
    if end is not None and observed_at > end:
        return False
    return True


def _optional_int(value: Any) -> Optional[int]:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _process_name(cmdline: str) -> str:
    if not cmdline:
        return ""
    first = cmdline.strip().split()[0] if cmdline.strip() else ""
    if not first:
        return ""
    base = Path(first).name
    return base.lstrip("-").rstrip(":")


def _is_sensitive_path(path: str) -> bool:
    lowered = path.lower()
    return any(
        marker in lowered
        for marker in (
            "/var/run/secrets/",
            "/run/secrets/",
            "/etc/secrets/",
            ".kube/config",
            "kubeconfig",
            "/etc/kubernetes",
            "/etc/shadow",
            "/etc/gshadow",
            "/etc/sudoers",
            "/etc/pam.conf",
            "/etc/pam.d/",
            "/.ssh/id_rsa",
            "/.ssh/id_dsa",
            "/.ssh/id_ecdsa",
            "/.ssh/id_ed25519",
            "/.ssh/authorized_keys",
        )
    )


def _direction_for_network_event(
    event_type: str,
    netflow: Optional[CdmNetFlowObject] = None,
) -> str:
    if netflow is not None:
        if netflow.local_port == 22 and netflow.remote_port != 22:
            return "ingress"
        if netflow.remote_port == 22 and netflow.local_port != 22:
            return "egress"
    if event_type in {"EVENT_ACCEPT", "EVENT_RECVFROM", "EVENT_RECVMSG", "EVENT_READ"}:
        return "ingress"
    if event_type in {"EVENT_CONNECT", "EVENT_SENDTO", "EVENT_SENDMSG", "EVENT_WRITE"}:
        return "egress"
    return "unknown"


def _falco_dict(
    *,
    rule_name: str,
    event_id: str,
    observed_at: datetime,
    host: CdmHost,
    output: str,
    output_fields: Dict[str, Any],
) -> Dict[str, Any]:
    timestamp = observed_at.isoformat()
    fields = {
        "k8s.ns.name": host.pod.namespace,
        "k8s.pod.name": host.pod.pod_name,
        "k8s.node.name": host.pod.node_name,
        "evt.time": timestamp,
    }
    fields.update(output_fields)
    return {
        "rule": rule_name,
        "priority": "WARNING",
        "time": timestamp,
        "timestamp": timestamp,
        "event_id": event_id,
        "namespace": host.pod.namespace,
        "pod_name": host.pod.pod_name,
        "node_name": host.pod.node_name,
        "workload_name": host.pod.pod_name,
        "output": output,
        "output_fields": fields,
    }


def _sanitize_name(value: str) -> str:
    sanitized = []
    for ch in value.lower():
        if ch.isalnum() or ch == "-":
            sanitized.append(ch)
        elif ch in {"_", ".", ":"}:
            sanitized.append("-")
    result = "".join(sanitized).strip("-")
    return result or "unknown-host"


def _chunk_sort_key(name: str) -> Tuple[str, int]:
    # Keep base .bin.gz before .bin.1.gz/.bin.2.gz, then numeric chunks.
    stem = name[:-3] if name.endswith(".gz") else name
    if stem.endswith(".bin"):
        return (stem[:-4], 0)
    marker = ".bin."
    if marker in stem:
        prefix, suffix = stem.rsplit(marker, 1)
        try:
            return (prefix, int(suffix))
        except ValueError:
            pass
    return (stem, 0)


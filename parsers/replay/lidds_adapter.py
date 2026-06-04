"""LID-DS 2021 → Pod-ing event adapter (skeleton).

LID-DS 2021 한 recording은 zip 파일 1개로, 안에 같은 base name을 공유하는
4개 파일(.sc / .pcap / .res / .json)이 들어 있다. 이 모듈은 그 데이터를
Pod-ing의 내부 이벤트 포맷으로 번역해서, 엔진 코드를 건드리지 않고도
공개 데이터셋으로 외부 평가를 돌릴 수 있게 한다.

매핑 방향
- .json `container[]` → 합성된 K8s 컨텍스트 (namespace, pod_name, node).
  LID-DS는 Docker 시나리오라 K8s 정보가 없으므로 일관된 명명 규칙으로 합성.
- .sc syscall line → Falco JSON 형태 dict. parsers.falco_parser.parse_falco_event
  가 그대로 받아 처리할 수 있게 키를 맞춘다. 어떤 syscall 패턴이 어떤
  Falco rule_name 으로 매핑되는지는 rules/lidds_event_mapping.yaml 에 정의.
- .pcap packet → parsers.raw_event.RawEvent (event_source='hubble').
  peer_pod 은 container[].ip 룩업으로 해석. 외부 IP면 peer_pod=None →
  event_mapper 에서 external_inbound/external_outbound 로 분류됨.
- .json `time.exploit[].absolute` → ground truth attack window (metrics 용).

알려진 한계 (CVE-2017-7529, 2026-05-18 실측)
- .sc trace 는 victim sysdig probe 한 컨테이너 분만 캡처. 컨테이너 간
  syscall 은 보이지 않는다. CVE-2017-7529 자체가 integer overflow → OOB read
  취약점이라 nginx worker 내부에서 처리되어 execve / fork / clone 이 0개.
  → 이 시나리오에서는 s_shell / n_tool / b_drop_exec 같은 process-spawn
  기반 심볼은 자극이 불가능하다. 네트워크 측 신호(attacker→victim:80)만
  유효 시그널.
- .pcap linktype 은 113 (LINUX_SLL) 로 표준 14B Ethernet 헤더가 아니라
  16B "cooked" 헤더다. 이 모듈은 LINUX_SLL 만 처리한다 (다른 linktype 만나면
  경고 후 skip).
"""

from __future__ import annotations

import json
import logging
import struct
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO, Dict, Iterator, List, Optional, Set, Tuple, Union

import yaml

from parsers.raw_event import RawEvent


LOGGER = logging.getLogger(__name__)

# --- .sc syscall line layout (LID-DS-repo/dataloader/syscall_2021.py) -------
_SC_TIMESTAMP = 0
_SC_USER_ID = 1
_SC_PROCESS_ID = 2
_SC_PROCESS_NAME = 3
_SC_THREAD_ID = 4
_SC_SYSCALL_NAME = 5
_SC_DIRECTION = 6
_SC_PARAMS_BEGIN = 7

# --- LINUX_SLL (pcap linktype 113) cooked header is 16 bytes ----------------
_SLL_HEADER_LEN = 16
_LINKTYPE_LINUX_SLL = 113
_ETHERTYPE_IPV4 = 0x0800


@dataclass(frozen=True)
class LiddsContainer:
    ip: str
    name: str
    role: str  # 'normal' | 'attacker' | 'victim'


@dataclass(frozen=True)
class LiddsMetadata:
    recording_id: str
    scenario: str
    containers: Tuple[LiddsContainer, ...]
    exploit: bool
    exploit_name: str
    image: str
    recording_time_sec: int
    container_ready_unix: float
    warmup_end_unix: float
    exploit_start_unix: Optional[float]


def _read_metadata(z: zipfile.ZipFile, recording_id: str, scenario: str) -> LiddsMetadata:
    raw = z.read(f"{recording_id}.json").decode("utf-8")
    try:
        meta = json.loads(raw)
    except json.JSONDecodeError:
        # LID-DS reference loader does the same fallback (recording_2021.py:166)
        meta = json.loads(raw.replace("'", '"'))

    containers = tuple(
        LiddsContainer(ip=c["ip"], name=c["name"], role=c["role"])
        for c in meta.get("container", [])
    )
    time_meta = meta.get("time", {})
    exploit_arr = time_meta.get("exploit", []) or []
    exploit_start = (
        float(exploit_arr[0].get("absolute"))
        if exploit_arr and exploit_arr[0].get("absolute") is not None
        else None
    )
    return LiddsMetadata(
        recording_id=recording_id,
        scenario=scenario,
        containers=containers,
        exploit=bool(meta.get("exploit", False)),
        exploit_name=str(meta.get("exploit_name", "")),
        image=str(meta.get("image", "")),
        recording_time_sec=int(meta.get("recording_time", 0)),
        container_ready_unix=float(time_meta.get("container_ready", {}).get("absolute", 0.0)),
        warmup_end_unix=float(time_meta.get("warmup_end", {}).get("absolute", 0.0)),
        exploit_start_unix=exploit_start,
    )


def _parse_syscall_line(line: str) -> Optional[Dict[str, Any]]:
    """.sc 한 줄을 dict 로 분해. 형식 깨진 줄은 None."""
    parts = line.split(" ")
    if len(parts) < 7:
        return None
    try:
        ts_ns = int(parts[_SC_TIMESTAMP])
    except ValueError:
        return None
    params: Dict[str, str] = {}
    if len(parts) > _SC_PARAMS_BEGIN:
        for kv in parts[_SC_PARAMS_BEGIN:]:
            if "=" in kv:
                k, v = kv.split("=", 1)
                params[k] = v
    return {
        "ts_ns": ts_ns,
        "user_id": parts[_SC_USER_ID],
        "pid": parts[_SC_PROCESS_ID],
        "proc_name": parts[_SC_PROCESS_NAME],
        "tid": parts[_SC_THREAD_ID],
        "syscall": parts[_SC_SYSCALL_NAME],
        "direction": parts[_SC_DIRECTION],
        "params": params,
        "raw_line": line,
    }


def _iter_pcap_packets(stream: BinaryIO) -> Iterator[Dict[str, Any]]:
    """classic pcap + LINUX_SLL (linktype 113) 최소 reader.

    IPv4 + TCP/UDP 패킷만 yield. pcapng / 다른 linktype 은 skip.
    외부 라이브러리(scapy/dpkt) 의존을 피하기 위해 struct 만 사용.
    더 풍부한 분석이 필요하면 scapy 로 교체할 수 있다.
    """
    header = stream.read(24)
    if len(header) < 24:
        return
    magic = struct.unpack("<I", header[:4])[0]
    if magic == 0xA1B2C3D4:
        endian, ts_scale = "<", 1e-6
    elif magic == 0xA1B23C4D:
        endian, ts_scale = "<", 1e-9
    elif magic == 0xD4C3B2A1:
        endian, ts_scale = ">", 1e-6
    else:
        LOGGER.warning("Unsupported pcap magic 0x%x", magic)
        return
    _snaplen, linktype = struct.unpack(f"{endian}II", header[16:24])
    if linktype != _LINKTYPE_LINUX_SLL:
        LOGGER.warning("Expected LINUX_SLL (113), got linktype=%d", linktype)
        # 모르는 linktype 이라도 IP 위치만 추정해서 계속 시도하지 않고 종료
        return

    rec_struct = struct.Struct(f"{endian}IIII")
    while True:
        rec = stream.read(16)
        if len(rec) < 16:
            return
        ts_sec, ts_frac, caplen, _origlen = rec_struct.unpack(rec)
        pkt = stream.read(caplen)
        if len(pkt) < caplen:
            return
        if caplen < _SLL_HEADER_LEN + 20:
            continue
        ethertype = struct.unpack(">H", pkt[14:16])[0]
        if ethertype != _ETHERTYPE_IPV4:
            continue
        ip_start = _SLL_HEADER_LEN
        version_ihl = pkt[ip_start]
        ihl_bytes = (version_ihl & 0x0F) * 4
        if ihl_bytes < 20 or caplen < ip_start + ihl_bytes:
            continue
        proto = pkt[ip_start + 9]
        src_ip = ".".join(str(b) for b in pkt[ip_start + 12 : ip_start + 16])
        dst_ip = ".".join(str(b) for b in pkt[ip_start + 16 : ip_start + 20])
        l4_start = ip_start + ihl_bytes
        src_port = dst_port = 0
        if proto in (6, 17) and caplen >= l4_start + 4:
            src_port, dst_port = struct.unpack(">HH", pkt[l4_start : l4_start + 4])
        yield {
            "ts_unix": ts_sec + ts_frac * ts_scale,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "proto": {6: "TCP", 17: "UDP"}.get(proto, str(proto)),
            "caplen": caplen,
        }


class LiddsRecording:
    """LID-DS 2021 recording 한 개를 표현."""

    def __init__(self, zip_path: Path, scenario: str):
        self.zip_path = Path(zip_path)
        self.scenario = scenario
        self._recording_id = self.zip_path.stem
        with zipfile.ZipFile(self.zip_path) as z:
            self._metadata = _read_metadata(z, self._recording_id, scenario)

    @property
    def metadata(self) -> LiddsMetadata:
        return self._metadata

    @property
    def recording_id(self) -> str:
        return self._recording_id

    def iter_syscalls(self) -> Iterator[Dict[str, Any]]:
        with zipfile.ZipFile(self.zip_path) as z:
            with z.open(f"{self._recording_id}.sc") as f:
                for raw in f:
                    decoded = raw.decode("utf-8", errors="ignore").rstrip()
                    parsed = _parse_syscall_line(decoded)
                    if parsed is not None:
                        yield parsed

    def iter_packets(self) -> Iterator[Dict[str, Any]]:
        with zipfile.ZipFile(self.zip_path) as z:
            with z.open(f"{self._recording_id}.pcap") as f:
                yield from _iter_pcap_packets(f)


# ---------------------------------------------------------------------------
# Adapter (recording → Pod-ing 입력 포맷)
# ---------------------------------------------------------------------------


@dataclass
class LiddsPacketAggregateRule:
    name: str
    event_type: str
    rule_name: str
    protocol: str = "TCP"
    destination_ports: Tuple[int, ...] = (443,)
    threshold_per_source_second: int = 100


@dataclass
class LiddsAdapterConfig:
    namespace_template: str = "lidds-{scenario}"
    node_name: str = "lidds-host"
    # syscall name → Falco rule name. event_type_mapping.yaml 에 이미 정의된
    # rule_name 을 그대로 써야 엔진이 처리한다. 비어 있으면 syscall 측 신호 없음.
    #
    # 값은 두 가지 형태를 허용한다 (rules/lidds_event_mapping.yaml 의 스키마 v0.2):
    #   - str  : 단순 매핑 (모든 entry-direction syscall 매치)
    #   - list : [{"when": {...}, "rule": "..."}] 조건부 매핑, 첫 번째 매치 사용.
    syscall_rule_map: Dict[str, Union[str, List[Dict[str, Any]]]] = field(default_factory=dict)
    packet_aggregate_rules: Tuple[LiddsPacketAggregateRule, ...] = ()


def _parse_packet_aggregate_rules(raw: Any) -> Tuple[LiddsPacketAggregateRule, ...]:
    """YAML packet aggregate rule 설정을 dataclass 로 변환."""
    if not isinstance(raw, dict):
        return ()

    rules: List[LiddsPacketAggregateRule] = []
    for name, cfg in raw.items():
        if not isinstance(cfg, dict) or cfg.get("enabled") is False:
            continue
        destination_ports = tuple(int(port) for port in cfg.get("destination_ports", [443]))
        threshold = int(cfg.get("threshold_per_source_second", 100))
        if threshold <= 0:
            continue
        rules.append(
            LiddsPacketAggregateRule(
                name=str(name),
                event_type=str(cfg.get("event_type", name)),
                rule_name=str(cfg.get("rule_name", name)),
                protocol=str(cfg.get("protocol", "TCP")).upper(),
                destination_ports=destination_ports,
                threshold_per_source_second=threshold,
            )
        )
    return tuple(rules)


class LiddsAdapter:
    """LID-DS recording → (Falco-like dict 스트림, RawEvent 스트림)."""

    def __init__(self, config: LiddsAdapterConfig):
        self.config = config

    @classmethod
    def from_yaml(cls, yaml_path: Path) -> "LiddsAdapter":
        with Path(yaml_path).open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
        cfg = LiddsAdapterConfig(
            namespace_template=data.get("namespace_template", "lidds-{scenario}"),
            node_name=data.get("node_name", "lidds-host"),
            syscall_rule_map=dict(data.get("syscall_rule_map") or {}),
            packet_aggregate_rules=_parse_packet_aggregate_rules(
                data.get("packet_aggregate_rules") or {}
            ),
        )
        return cls(cfg)

    # -- helpers -----------------------------------------------------------

    def _namespace(self, recording: LiddsRecording) -> str:
        return self.config.namespace_template.format(scenario=recording.scenario.lower())

    def _pod_for_ip(
        self, recording: LiddsRecording, ip: str
    ) -> Optional[Tuple[str, str]]:
        """ip → (pod_name, role) 또는 외부면 None."""
        for c in recording.metadata.containers:
            if c.ip == ip:
                return (f"lidds-{c.role}-{c.name[:8]}", c.role)
        return None

    def _victim_pod(self, recording: LiddsRecording) -> str:
        for c in recording.metadata.containers:
            if c.role == "victim":
                return f"lidds-victim-{c.name[:8]}"
        return f"lidds-victim-{recording.recording_id}"

    # -- syscall → Falco JSON dict -----------------------------------------

    def syscall_falco_events(
        self, recording: LiddsRecording
    ) -> Iterator[Dict[str, Any]]:
        """.sc syscall 중 syscall_rule_map 에 매칭되는 항목만 Falco dict 로 산출.

        반환 dict 는 parsers.falco_parser.parse_falco_event 가 요구하는 키
        (rule, timestamp/time, event_id, namespace, pod_name, output, output_fields)
        를 모두 채운다.

        Nginx CVE-2017-7529 처럼 syscall_rule_map 가 비어 있는(또는 매칭 0건인)
        시나리오에서는 이 제너레이터는 아무 것도 yield 하지 않는다 — 의도된 동작.
        """
        namespace = self._namespace(recording)
        victim_pod = self._victim_pod(recording)
        for entry in recording.iter_syscalls():
            rule_name = self._match_syscall_rule(entry)
            if rule_name is None:
                continue
            ts_iso = datetime.fromtimestamp(
                entry["ts_ns"] / 1e9, tz=timezone.utc
            ).isoformat()
            event_id = f"lidds-{recording.recording_id}-{entry['ts_ns']}"
            yield {
                "rule": rule_name,
                "priority": "WARNING",
                "time": ts_iso,
                "timestamp": ts_iso,
                "event_id": event_id,
                "namespace": namespace,
                "pod_name": victim_pod,
                "output": (
                    f"{rule_name} (lidds replay: syscall={entry['syscall']} "
                    f"proc={entry['proc_name']})"
                ),
                "output_fields": {
                    "k8s.ns.name": namespace,
                    "k8s.pod.name": victim_pod,
                    "k8s.node.name": self.config.node_name,
                    "proc.name": entry["proc_name"],
                    "proc.cmdline": entry["params"].get("cmdline", entry["syscall"]),
                    "fd.name": entry["params"].get("name", ""),
                    "evt.type": entry["syscall"],
                    "evt.time": ts_iso,
                },
            }

    def _match_syscall_rule(self, entry: Dict[str, Any]) -> Optional[str]:
        """syscall line 을 mapping YAML 에 따라 Falco rule_name 으로 변환.

        sysdig .sc 포맷에서 syscall 의 인자는 syscall 종류마다 entry/exit 어느
        쪽에 붙는지가 다르다. execve 는 proc.name 이 line 의 고정 필드에 있어
        entry 만 봐도 충분하지만, open/openat/unlink/rename 의 path 인자는
        exit('<') 라인에서만 채워진다. 그래서 clause 마다 어떤 direction 의
        라인을 매칭할지를 명시할 수 있게 했다 (기본은 entry '>').

        조건부 매칭 (list-of-dict) 의 when 절은 모든 조건이 AND 로 결합되며,
        지원 키는 proc_name_any_of, filename_prefix_any_of 둘 뿐이다. when 이
        없으면 항상 매치 (fallback).
        """
        spec = self.config.syscall_rule_map.get(entry["syscall"])
        if spec is None:
            return None
        if isinstance(spec, str):
            if entry["direction"] != ">":
                return None
            return spec
        if not isinstance(spec, list):
            LOGGER.warning(
                "Unsupported syscall_rule_map entry for %s: %r", entry["syscall"], spec
            )
            return None

        for clause in spec:
            if not isinstance(clause, dict) or "rule" not in clause:
                continue
            required_direction = str(clause.get("direction", ">"))
            if entry["direction"] != required_direction:
                continue
            when = clause.get("when") or {}
            if self._when_matches(when, entry):
                return str(clause["rule"])
        return None

    @staticmethod
    def _when_matches(when: Dict[str, Any], entry: Dict[str, Any]) -> bool:
        proc_names = when.get("proc_name_any_of")
        if proc_names is not None and entry.get("proc_name") not in proc_names:
            return False

        filename_prefixes = when.get("filename_prefix_any_of")
        if filename_prefixes is not None:
            params = entry.get("params") or {}
            target = params.get("filename") or params.get("name") or ""
            if not any(target.startswith(prefix) for prefix in filename_prefixes):
                return False

        return True

    # -- packet → RawEvent (Hubble path) -----------------------------------

    def packet_raw_events(
        self,
        recording: LiddsRecording,
        *,
        emit_raw: bool = True,
    ) -> Iterator[RawEvent]:
        """pcap 패킷을 RawEvent 로 변환. event_mapper 가 hubble 규칙으로 해석.

        emit_raw=False 면 per-packet RawEvent 는 yield 하지 않고 aggregate
        event 만 흘려보낸다. CouchDB CVE 처럼 한 recording 당 packet 수가 수만
        이상이라 engine.ingest 가 비선형 비용으로 못 끝나는 시나리오용.
        """
        namespace = self._namespace(recording)
        aggregate_counts: Dict[Tuple[str, str, str, int], int] = {}
        aggregate_emitted: Set[Tuple[str, str, str]] = set()
        for pkt in recording.iter_packets():
            src_resolved = self._pod_for_ip(recording, pkt["src_ip"])
            dst_resolved = self._pod_for_ip(recording, pkt["dst_ip"])

            # 양쪽 다 외부 IP 면 의미 없음. 한쪽이라도 컨테이너면 그쪽을 subject 로.
            if dst_resolved and not src_resolved:
                subject_pod = dst_resolved[0]
                peer = src_resolved  # None → external_inbound
                direction = "ingress"
            elif src_resolved and not dst_resolved:
                subject_pod = src_resolved[0]
                peer = dst_resolved  # None → external_outbound
                direction = "egress"
            elif src_resolved and dst_resolved:
                # 두 컨테이너 사이 트래픽. victim 을 subject 로 잡아 일관성 유지.
                if dst_resolved[1] == "victim" or src_resolved[1] == "attacker":
                    subject_pod, _ = dst_resolved
                    peer = src_resolved
                    direction = "ingress"
                else:
                    subject_pod, _ = src_resolved
                    peer = dst_resolved
                    direction = "egress"
            else:
                continue

            peer_pod = peer[0] if peer else None
            peer_namespace = namespace if peer else None
            if emit_raw:
                event_id = (
                    f"lidds-{recording.recording_id}-"
                    f"{int(pkt['ts_unix'] * 1e6)}-{pkt['src_port']}-{pkt['dst_port']}"
                )
                yield RawEvent(
                    observed_at=datetime.fromtimestamp(pkt["ts_unix"], tz=timezone.utc),
                    event_id=event_id,
                    event_source="hubble",
                    subject_pod=subject_pod,
                    namespace=namespace,
                    node_name=self.config.node_name,
                    workload_name=subject_pod,
                    description=(
                        f"{pkt['proto']} {pkt['src_ip']}:{pkt['src_port']} → "
                        f"{pkt['dst_ip']}:{pkt['dst_port']}"
                    ),
                    role="trigger",
                    flow_pattern=direction,
                    peer_pod=peer_pod,
                    peer_namespace=peer_namespace,
                    official_fields={
                        "direction": direction,
                        "source_ip": pkt["src_ip"],
                        "destination_ip": pkt["dst_ip"],
                        "destination_port": pkt["dst_port"],
                        "protocol": pkt["proto"],
                    },
                )
            yield from self._packet_aggregate_events(
                pkt,
                namespace=namespace,
                subject_pod=subject_pod,
                peer_pod=peer_pod,
                peer_namespace=peer_namespace,
                direction=direction,
                aggregate_counts=aggregate_counts,
                aggregate_emitted=aggregate_emitted,
            )

    def _packet_aggregate_events(
        self,
        pkt: Dict[str, Any],
        *,
        namespace: str,
        subject_pod: str,
        peer_pod: Optional[str],
        peer_namespace: Optional[str],
        direction: str,
        aggregate_counts: Dict[Tuple[str, str, str, int], int],
        aggregate_emitted: Set[Tuple[str, str, str]],
    ) -> Iterator[RawEvent]:
        """Packet burst 를 LID-DS 전용 synthetic Hubble event 로 축약."""
        if direction != "ingress" or not self.config.packet_aggregate_rules:
            return

        bucket_second = int(pkt["ts_unix"])
        for rule in self.config.packet_aggregate_rules:
            if str(pkt["proto"]).upper() != rule.protocol:
                continue
            # destination_ports 빈 tuple = "any port". yaml 에서 destination_ports
            # 키 자체를 생략하면 default 443 이 들어가므로, 빈 list 를 명시해야 한다.
            if rule.destination_ports and int(pkt["dst_port"]) not in rule.destination_ports:
                continue

            key = (rule.name, subject_pod, str(pkt["src_ip"]), bucket_second)
            emitted_key = (rule.name, subject_pod, str(pkt["src_ip"]))
            current = aggregate_counts.get(key, 0) + 1
            aggregate_counts[key] = current
            if current < rule.threshold_per_source_second or emitted_key in aggregate_emitted:
                continue
            aggregate_emitted.add(emitted_key)
            event_id = (
                f"lidds-aggregate-{rule.name}-{subject_pod}-"
                f"{pkt['src_ip']}-{bucket_second}"
            ).replace("/", "-")
            yield RawEvent(
                observed_at=datetime.fromtimestamp(pkt["ts_unix"], tz=timezone.utc),
                event_id=event_id,
                event_source="hubble",
                subject_pod=subject_pod,
                namespace=namespace,
                node_name=self.config.node_name,
                workload_name=subject_pod,
                description=(
                    f"{rule.rule_name}: {current} {rule.protocol} packets from "
                    f"{pkt['src_ip']} to {pkt['dst_ip']}:{pkt['dst_port']} "
                    f"within second {bucket_second}"
                ),
                role="trigger",
                rule_name=rule.rule_name,
                flow_pattern=direction,
                peer_pod=peer_pod,
                peer_namespace=peer_namespace,
                official_fields={
                    "declared_event_type": rule.event_type,
                    "direction": direction,
                    "source_ip": pkt["src_ip"],
                    "destination_ip": pkt["dst_ip"],
                    "destination_port": pkt["dst_port"],
                    "protocol": pkt["proto"],
                    "packet_count": current,
                    "threshold_per_source_second": rule.threshold_per_source_second,
                    "bucket_second": bucket_second,
                },
            )

    # -- ground truth ------------------------------------------------------

    def ground_truth(self, recording: LiddsRecording) -> Dict[str, Any]:
        """metrics 단계에서 쓸 정답 라벨."""
        m = recording.metadata
        return {
            "recording_id": m.recording_id,
            "scenario": m.scenario,
            "is_attack": m.exploit,
            "attack_start_unix": m.exploit_start_unix,
            "warmup_end_unix": m.warmup_end_unix,
            "container_ready_unix": m.container_ready_unix,
            "recording_time_sec": m.recording_time_sec,
        }

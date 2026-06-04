# Pod-ing

Kubernetes 환경에서 Falco 런타임 이벤트와 Hubble 네트워크 이벤트를 결합해, Pod 단위 공격 상태를 추적하는 rule-based FSM 상관분석 시스템입니다.

## 핵심 방향

현재 엔진은 FSM 개념을 유지하되 실행 모델을 **DFA 스타일 단일 경로 전이**에서 **NFA 스타일 다중 partial match 추적**으로 확장했습니다.

- rule-based 구조 유지
- YAML 기반 symbol/rule 정의 유지
- 상태 기반 FSM 유지
- 한 Pod에 대해 여러 partial match 동시 유지
- noise event 허용
- score / anomaly / baseline 제거

## 시스템 구조

```text
Falco + Hubble -> normalization -> symbol mapping -> YAML scenario rules -> NFA FSM -> JSON
```

- `rules/event_type_mapping.yaml`
  - Falco 기본 룰과 Hubble flow를 normalized event type으로 매핑
- `rules/stage_mapping.yaml`
  - Falco rule / normalized event / Hubble condition을 symbol로 매핑
- `rules/scenario_rules.yaml`
  - lateral movement 중심 NFA 시나리오 정의
- `engine/fsm.py`
  - Pod별 active partial path와 completed detection 관리
- `live/result_writer.py`
  - `results/` 아래 correlation, detection summary, debug summary 파일 기록
- `engine/exporter.py`
  - explainable detection output 생성
- `live/live_pipeline.py`
  - 실시간 Falco/Hubble 수집, YAML mapping, NFA 탐지 orchestrator

## 탐지 모델

상태는 다음 순서를 중심으로 사용합니다.

- `IDLE`
- `RECON`
- `CRED`
- `LATERAL`
- `ALERT`

중요한 점은 이제 이 상태들이 하나의 직선 경로로만 움직이지 않는다는 것입니다. 같은 Pod에서 여러 rule chain이 동시에 살아 있을 수 있고, 각 chain은 자신만의 time window 안에서 독립적으로 전진합니다.

우선순위는 다음과 같습니다.

- Primary: `lateral movement`
- Supporting: `credential theft`, `data exfiltration`, `remote I/O external egress`, `privilege escalation`, `dropped binary external egress`

## 출력

결과는 점수 없이 다음 정보를 제공합니다.

- 어떤 rule이 매칭됐는지
- 어떤 event chain이 rule을 완성했는지
- 어떤 pod / namespace인지
- 언제 탐지됐는지
- 현재 active partial match가 무엇인지

## 실행

```bash
python3 live/live_pipeline.py --hubble-server localhost:4245
```

또는 cluster-wide 모드:

```bash
python3 live/live_pipeline.py
```

실시간 프로토타입 엔진:

```bash
python3 engine.py
```

## 발표용 데모

긴 통합 실험은 [scripts/run_end_to_end.sh](/home/yw/poding/scripts/run_end_to_end.sh:1) 를 유지하고, 발표용 짧은 경로는 [scripts/demo_lateral_movement.sh](/home/yw/poding/scripts/demo_lateral_movement.sh:1) 로 분리했습니다.

전제:

- `attack-lab-01` namespace와 `pod-a`, `pod-b` 같은 리소스가 이미 떠 있어야 합니다.
- `poding-detector`, Falco, Hubble도 이미 실행 중이어야 합니다.
- 발표 중에는 리소스 생성/삭제 없이 짧은 행위만 발생시킵니다.

모니터링 명령만 먼저 확인:

```bash
bash scripts/demo_lateral_movement.sh --print-watch-commands
```

기본 실행:

```bash
bash scripts/demo_lateral_movement.sh
```

이 스크립트는 `kubectl exec`로 짧은 공격 행위만 발생시키는 trigger다. 결과 JSON 생성, correlation 결과 작성, detection summary 작성은 하지 않는다. `live/live_pipeline.py`는 실시간 수집과 탐지를 orchestration하고, 실제 파일 쓰기는 `live/result_writer.py`가 `results/` 아래에 수행한다.

주요 인자:

- `--namespace`
- `--attack-pod`
- `--attack-container`
- `--target-url`
- `--results-path`
- `--step-sleep`
- `--final-wait`

발표 중 실행 순서:

- Terminal A: `python3 live/live_pipeline.py`
- Terminal B: `watch -n 1 'cat ./results/latest_correlation.json'`
- Terminal C: `watch -n 1 'cat ./results/latest_detection_summary.json'`
- Terminal D: `bash scripts/demo_lateral_movement.sh`

발표 중 확인할 것:

- Detector 로그:
```bash
kubectl logs -n poding-system deploy/poding-detector -f
```

- 최신 correlation 결과:
```bash
watch -n 1 'cat ./results/latest_correlation.json'
```

- 최신 detection summary:
```bash
watch -n 1 'cat ./results/latest_detection_summary.json'
```

- 최신 debug summary:
```bash
watch -n 1 'cat ./results/latest_debug_summary.json'
```

스크립트는 다음 순서로 발표 친화적인 문구와 함께 짧은 행위를 발생시킵니다.

- shell-like command
- service account token access
- Kubernetes API access
- pod-to-pod communication

정상 동작 시 detector 로그에 다음 형식의 출력이 보입니다.

```text
[DETECTION]
rule: lateral_movement_via_api
pod: attack-lab-01/pod-a
sequence: RECON -> CRED -> LATERAL
time: ...
details: falco-shell-1 -> falco-api-1 -> hubble-observe-1
```

## 검증

현재 리팩토링 후 핵심 테스트는 아래 명령으로 확인했습니다.

```bash
python3 -m unittest tests.test_fsm tests.test_correlator tests.test_integration_lateral tests.test_live_pipeline tests.test_clusterwide_live_pipeline
```

## 문서

- 로컬 실행 가이드(팀원용): [docs/local-run-guide.md](docs/local-run-guide.md) — `./scripts/local/local-up.sh` 한 줄로 kind에 전체 스택 + 관제 UI 재현
- Helm 차트: [charts/poding/README.md](charts/poding/README.md)
- NFA 전환 메모: [docs/nfa-migration-notes.md](/home/yw/poding/docs/nfa-migration-notes.md:1)
- Grafana setup: [docs/grafana-setup.md](/home/yw/poding/docs/grafana-setup.md:1)

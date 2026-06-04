# Pod-ing Helm Chart

Pod-ing은 Falco·Hubble 신호를 NFA로 상관분석해 컨테이너/파드 간 공격
전파를 탐지하는 **Kubernetes 보안 상관분석 시스템**이다. 이 차트로 클러스터에
배포할 수 있다.

> 🚀 **로컬에서 바로 해보기:** [`QUICKSTART-local.md`](QUICKSTART-local.md) —
> `./scripts/local/local-up.sh` 한 줄이면 kind에 전체 스택(Cilium/Hubble·Falco·
> Grafana) + Pod-ing 이 뜨고 세 UI를 바로 볼 수 있다.

## 구성 컴포넌트

| 컴포넌트 | 역할 | 포트 | 토글 |
|---|---|---|---|
| `poding-detector` | NFA 상관분석 파이프라인 (핵심) | 8080 | `detector.enabled` |
| `poding-metrics-exporter` | Prometheus 메트릭(`/metrics`) | 9108 | `metricsExporter.enabled` |
| `propagation-exporter` | cross-layer 전파 관제 UI | 9109 | `propagationExporter.enabled` |
| `propagation-advisory-shim` | Falco advisory 피드백 shim | — | `propagationExporter.advisoryShim.enabled` |
| `poding-image-loader` | kind/lab 이미지 적재 헬퍼 | — | `imageLoader.enabled` (기본 off) |
| `ServiceMonitor` | prometheus-operator 스크랩 | — | `serviceMonitor.enabled` (기본 off) |
| Grafana 대시보드 | detector 상태 UI (sidecar ConfigMap) | — | `grafana.dashboards.enabled` (기본 off) |
| Grafana 데이터소스 | flow UI (NodeGraph) | — | `grafana.datasources.enabled` (기본 off) |

## 전제 조건

- 이미지 `poding:prototype` 가 대상 노드(`nodePlacement.hostname`, 기본 `k8s-cp`)의
  컨테이너 런타임에 **미리 적재**되어 있어야 한다 (레지스트리 pull 안 함).
- detector/exporter 는 hostPath `hostPath.repoRoot`(기본 `/home/yw/poding`)에 있는
  poding 레포를 마운트한다 → 해당 노드에 레포가 존재해야 한다.
- detector·exporter·shim 은 노드-로컬 파일을 공유하므로 **모두 같은 노드**에 핀된다.

## 설치

```bash
# 기본값으로 설치 (poding-system 네임스페이스 생성 포함)
helm install poding charts/poding

# 렌더 결과만 확인
helm template poding charts/poding

# 노드/경로가 다른 환경
helm install poding charts/poding \
  --set nodePlacement.hostname=my-node \
  --set hostPath.repoRoot=/opt/poding \
  --set hostPath.resultsDir=/opt/poding/results \
  --set hostPath.advisoryDir=/opt/poding/propagation-advisory

# detector 만 (exporter 류 끄기)
helm install poding charts/poding \
  --set metricsExporter.enabled=false \
  --set propagationExporter.enabled=false

# prometheus-operator 환경: ServiceMonitor 켜기
helm install poding charts/poding --set serviceMonitor.enabled=true
```

## 관제(Observability) — flow & detector 상태 UI

관제자는 **detector 상태**와 **flow** 를 UI 로 확인할 수 있다.

| 보고 싶은 것 | UI | 활성화 방법 |
|---|---|---|
| detector 상태 (alert/FSM/threat) | Grafana 대시보드 (Overview·Attack-Graph) | `grafana.dashboards.enabled=true` |
| 공격 전파 flow (cross-layer) | propagation-exporter UI (:9109) + Grafana NodeGraph | `propagationExporter.enabled` / `grafana.datasources.enabled=true` |
| 네트워크 east-west flow | Cilium Hubble UI | Cilium 측 `cilium hubble enable --ui` |

### Grafana 대시보드 (detector 상태)

kube-prometheus-stack 의 grafana sidecar 가 `grafana_dashboard: "1"` 라벨이 붙은
ConfigMap 을 자동 로드한다. 차트가 대시보드 2종(Overview·Attack-Graph)과
flow 데이터소스(NodeGraphAPI·Propagation)를 sidecar ConfigMap 으로 배포한다:

```bash
helm install poding charts/poding \
  --set grafana.dashboards.enabled=true \
  --set grafana.datasources.enabled=true
# Grafana 가 monitoring 네임스페이스고 sidecar 가 그 NS 만 본다면:
#   --set grafana.namespace=monitoring
```

> NodeGraph 데이터소스는 Grafana 에 `hamedkarbasi93-nodegraphapi-datasource`
> 플러그인이 설치돼 있어야 동작한다.

### 포트포워드로 직접 접속

```bash
# cross-layer 전파 UI
kubectl port-forward -n poding-system svc/propagation-exporter 9109:9109   # → localhost:9109
# detector API
kubectl port-forward -n poding-system svc/poding-detector 8080:8080
```

### 네트워크 flow (Hubble UI)

east-west 네트워크 flow 는 Cilium Hubble 소관이라 이 차트가 배포하지 않는다.
Cilium 측에서 켠다:

```bash
cilium hubble enable --ui
cilium hubble ui            # 브라우저로 flow 그래프 열기
```

## 제거

```bash
helm uninstall poding
```

## 기존 raw 매니페스트와의 관계

이 차트는 `deploy/k8s`, `deploy/metrics`, `deploy/propagation` 의 매니페스트를
그대로 재현하며, 환경별로 달라지는 값(이미지·노드·hostPath·포트)과 컴포넌트
on/off 만 `values.yaml` 로 노출한 것이다. 렌더 결과는 원본 매니페스트와 동일하다.

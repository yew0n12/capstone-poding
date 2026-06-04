# Pod-ing 로컬 빠른 시작 (kind 전체 스택)

pull 받은 누구나 **로컬 PC에서** Pod-ing 을 Helm 으로 배포하고
**Grafana(detector 상태) · propagation(전파 flow) · Hubble UI(네트워크 flow)** 까지
바로 띄워볼 수 있다.

## 0. 사전 설치 (한 번만)

| 도구 | 설치 |
|---|---|
| Docker | Docker Desktop |
| kind | `brew install kind` |
| kubectl | `brew install kubectl` |
| helm | `brew install helm` |

> Docker Desktop 은 **메모리 6GB 이상** 권장 (Cilium+Hubble+Falco+Grafana 동시 구동).
> Settings → Resources 에서 늘릴 수 있다.

## 1. 전체 스택 올리기 (한 줄)

```bash
./scripts/local/local-up.sh
```

이 스크립트가 순서대로 실행한다:
1. kind 단일 노드 클러스터 생성 (레포를 노드 `/poding` 으로 마운트)
2. **Cilium + Hubble (+UI)** 설치
3. **Falco** 설치 (detector 가 따라가는 Falco 로그 소스)
4. **kube-prometheus-stack** 설치 (Grafana + Prometheus, NodeGraph 플러그인 포함)
5. `poding:prototype` 이미지 빌드 + kind 로드
6. `helm install poding charts/poding -f values-local.yaml`
7. 접속 방법 출력

완료까지 보통 5~10분 (이미지 pull 포함).

## 2. 관제 UI 접속

스크립트가 끝나면 아래 명령이 출력된다(각각 다른 터미널에서):

```bash
# detector 상태 — Grafana (폴더 "Pod-ing")
kubectl port-forward -n monitoring svc/kube-prometheus-stack-grafana 3000:80
#   → http://localhost:3000  (admin / 비번은 스크립트 출력 참고)

# 공격 전파 flow — propagation UI
kubectl port-forward -n poding-system svc/propagation-exporter 9109:9109
#   → http://localhost:9109

# 네트워크 east-west flow — Hubble UI
kubectl port-forward -n kube-system svc/hubble-ui 12000:80
#   → http://localhost:12000
```

## 3. 정리

```bash
./scripts/local/local-down.sh     # kind 클러스터 통째로 삭제
```

## 동작 원리 (요약)

- **로컬 전용 값**은 [`values-local.yaml`](values-local.yaml) 에 모여 있다
  (노드 핀 off · 이미지 `Never` · hostPath `/poding` · Grafana/Hubble 토글 on).
- lab 기본값([`values.yaml`](values.yaml))은 그대로 두므로, **연구실/클라우드 배포에는 영향 없다**.
- 레포가 kind 노드 `/poding` 으로 마운트되어, detector/exporter 가 결과 파일을 공유한다.

## 자주 막히는 곳

| 증상 | 원인 / 해결 |
|---|---|
| `ImagePullBackOff` | 이미지 미로드 → `kind load docker-image poding:prototype --name poding` 재실행 |
| Falco 파드 `CrashLoopBackOff` | 호스트 커널이 modern eBPF 미지원. detector 의 Falco 경로만 영향(전체 데모는 계속 가능) |
| Grafana 에 대시보드 안 보임 | sidecar 가 ConfigMap 로드 전 — 1~2분 대기. 폴더 "Pod-ing" 확인 |
| NodeGraph 패널 비어있음 | `hamedkarbasi93-nodegraphapi-datasource` 플러그인 로드 확인(스크립트가 설치) |
| Cilium 파드 안 뜸 | Docker 재시작 후 kind 노드 IP 가 바뀌면 깨질 수 있음 → `local-down.sh` 후 다시 `local-up.sh` |

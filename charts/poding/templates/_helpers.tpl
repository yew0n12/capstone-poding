{{/*
공통 이름. fullnameOverride > nameOverride > "poding".
*/}}
{{- define "poding.name" -}}
{{- default "poding" .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "poding.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- include "poding.name" . -}}
{{- end -}}
{{- end -}}

{{/*
배포 대상 네임스페이스.
*/}}
{{- define "poding.namespace" -}}
{{- .Values.namespace.name -}}
{{- end -}}

{{/*
컨테이너 이미지 (repository:tag).
*/}}
{{- define "poding.image" -}}
{{- printf "%s:%s" .Values.image.repository .Values.image.tag -}}
{{- end -}}

{{/*
모든 리소스에 붙는 공통 라벨.
*/}}
{{- define "poding.labels" -}}
app.kubernetes.io/name: {{ include "poding.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
{{- end -}}

{{/*
노드-로컬 파일을 읽는 컴포넌트의 노드 핀(nodeSelector + control-plane toleration).
detector / propagation-exporter / advisory-shim 가 공유.
nodePlacement.enabled=false 면 아무것도 emit 하지 않아 단일 노드에 스케줄된다.
*/}}
{{- define "poding.nodePlacement" -}}
{{- if .Values.nodePlacement.enabled }}
nodeSelector:
  kubernetes.io/hostname: {{ .Values.nodePlacement.hostname }}
{{- if .Values.nodePlacement.controlPlaneToleration }}
tolerations:
  - key: node-role.kubernetes.io/control-plane
    operator: Exists
    effect: NoSchedule
{{- end }}
{{- end }}
{{- end -}}

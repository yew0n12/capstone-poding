# Propagation Causal Graph

Optional companion to `poding-detector`.

Runs alongside the detector, reads `results/latest_correlation.json`,
`results/latest_detection_summary.json`, and `results/latest_debug_summary.json`,
and produces a causal propagation graph from the detector's analysis result.
The original detector pipeline (`engine/`, `live/`, `parsers/`, `observability/`)
is **not modified**.

## Why

`poding-detector` already correlates Falco events and Hubble flows into a
per-pod FSM, suspect summary, and graph. The default Grafana NodeGraph view uses
that detector output as its source of truth. It is intentionally not a raw
Hubble flow graph.

Nodes represent Pods and are colored by FSM/threat state:

- `IDLE` / normal: blue
- `RECON` / suspect: yellow
- `CRED` / risk: orange
- `LATERAL` / propagation: red
- `ALERT`: dark red

Edges represent detector correlation/propagation relations:

- `correlation`: confirmed relation around the primary suspect or active state
- `related`: related or partial propagation relation
- `observed`: edge present in the detector correlation graph without an active
  threat state

The direct Hubble subscriber is retained only as a troubleshooting data source
at `/api/raw-hubble-graph` and `/rawnodegraphds/api/graph/fields|data`.

## Endpoints

- `GET  /healthz`
- `GET  /api/graph` — Cytoscape elements + summary from latest result JSON
- `GET  /api/raw-hubble-graph` — direct Hubble troubleshooting graph
- `GET  /api/evidence/<edge_id>` — per-edge classification evidence
- `GET  /api/baseline` — baseline window status
- `POST /api/baseline/reset` — restart baseline window
- `GET  /nodegraphds/api/graph/fields|data` — Grafana NodeGraphAPI compat for
  the detector result graph
- `GET  /rawnodegraphds/api/graph/fields|data` — Grafana NodeGraphAPI compat
  for the raw Hubble troubleshooting graph
- `GET  /` — Cytoscape SPA

## Configuration (env vars)

- `PROPAGATION_RESULTS_DIR` (default `/home/yw/poding/results`)
- `PROPAGATION_PORT` (default `9109`)
- `PROPAGATION_POLL_INTERVAL` seconds (default `5`)
- `PROPAGATION_BASELINE_SECONDS` window length (default `300`)
- `PROPAGATION_FREQ_SPIKE` ratio threshold for freq spike detection (default `3.0`)

## Deployment

```
kubectl apply -f deploy/propagation/propagation-exporter-deployment.yaml
kubectl apply -f deploy/propagation/propagation-exporter-service.yaml
kubectl apply -f monitoring/grafana-propagation-datasource.yaml
kubectl apply -f monitoring/grafana-propagation-dashboard.yaml
kubectl rollout restart deployment -n monitoring poding-prometheus-grafana
```

The exporter reuses the `poding:prototype` image (Python 3 only, no extra
dependencies — uses stdlib `http.server`). HostPath `/home/yw/poding` is
mounted read-only so the exporter can read both `results/` and the source
files at `propagation/exporter/`.

## Layout

```
propagation/
├── README.md
└── exporter/
    ├── server.py           # HTTP + watcher
    └── ui/
        ├── index.html      # Cytoscape SPA
        ├── app.js
        └── style.css
```

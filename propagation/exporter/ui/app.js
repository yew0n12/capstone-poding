/* Propagation Causal Graph — Cytoscape SPA */
(function () {
  const cy = cytoscape({
    container: document.getElementById('cy'),
    style: [
      {
        selector: 'node',
        style: {
          'background-color': 'data(color)',
          'label': 'data(label)',
          'color': '#e6e8eb',
          'text-valign': 'bottom',
          'text-halign': 'center',
          'font-size': 10,
          'text-outline-color': '#0f1115',
          'text-outline-width': 2,
          'border-width': 1,
          'border-color': '#0f1115',
          'width': 26,
          'height': 26,
        },
      },
      {
        selector: 'node[type = "external"]',
        style: { 'shape': 'diamond', 'border-style': 'dashed', 'border-color': '#fff' },
      },
      {
        selector: 'edge',
        style: {
          'curve-style': 'bezier',
          'target-arrow-shape': 'triangle',
          'line-color': 'data(color)',
          'target-arrow-color': 'data(color)',
          'width': 'data(width)',
          'opacity': 0.85,
          'label': 'data(grade)',
          'font-size': 8,
          'color': '#cbd5e0',
          'text-rotation': 'autorotate',
          'text-background-color': '#0f1115',
          'text-background-opacity': 0.6,
          'text-background-padding': 2,
        },
      },
      { selector: 'edge.partial',  style: { 'line-style': 'solid',  'opacity': 0.9 } },
      { selector: 'edge.adjacent', style: { 'line-style': 'dashed', 'opacity': 0.75 } },
      { selector: 'edge.baseline', style: { 'opacity': 0.4 } },
      {
        selector: ':selected',
        style: { 'border-width': 3, 'border-color': '#63b3ed' },
      },
    ],
    layout: { name: 'dagre', rankDir: 'LR', nodeSep: 30, edgeSep: 10, rankSep: 80 },
    wheelSensitivity: 0.2,
  });

  const params = new URLSearchParams(window.location.search);
  const refreshMs = Math.max(500, Number(params.get('refresh_ms') || window.PROPAGATION_REFRESH_MS || 2000));

  const evidenceBody = document.getElementById('evidence-body');
  function showEvidence(obj) {
    evidenceBody.textContent = JSON.stringify(obj, null, 2);
  }

  const FSM_LAYOUT = {
    IDLE:    { x:  40, y:  60 },
    RECON:   { x: 110, y:  60 },
    CRED:    { x: 180, y:  60 },
    LATERAL: { x: 250, y:  60 },
    ALERT:   { x: 250, y: 140 },
    EXTERNAL:{ x:  40, y: 140 },
  };
  const FSM_EDGES = [
    ["IDLE",    "RECON",   "s,n,b,X"],
    ["RECON",   "CRED",    "c,k"],
    ["CRED",    "LATERAL", "E"],
    ["IDLE",    "LATERAL", "R"],
    ["LATERAL", "ALERT",   "s,n,b,k,O"],
    ["RECON",   "ALERT",   "s,n,b,O"],
    ["EXTERNAL","RECON",   "X→s/n/b"],
  ];

  function renderFsm(data) {
    const svg = document.getElementById('fsm-svg');
    document.getElementById('fsm-pod').textContent = data.pod_id || '';
    while (svg.firstChild) svg.removeChild(svg.firstChild);

    const ns = 'http://www.w3.org/2000/svg';
    // arrow marker
    const defs = document.createElementNS(ns, 'defs');
    defs.innerHTML = `<marker id="fsm-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#4a5568"/></marker>`;
    svg.appendChild(defs);

    const active = new Set(data.active_states || []);
    if (data.current_state) active.add(data.current_state);
    const candidates = new Set(data.candidate_next_states || []);
    const firedSyms = new Set();
    for (const ev of (data.source_events || [])) {
      for (const s of (ev.symbols || [])) firedSyms.add(s);
    }

    // edges first (so nodes overlay)
    for (const [from, to, label] of FSM_EDGES) {
      const a = FSM_LAYOUT[from], b = FSM_LAYOUT[to];
      if (!a || !b) continue;
      const fired = label.split(',').some(s => firedSyms.has(s.trim()));
      const path = document.createElementNS(ns, 'path');
      const dx = b.x - a.x, dy = b.y - a.y;
      const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
      const ctrl = `M ${a.x + 18},${a.y} Q ${mx},${my - 18} ${b.x - 18},${b.y}`;
      path.setAttribute('d', ctrl);
      path.setAttribute('class', 'edge-line' + (fired ? ' fired' : ''));
      svg.appendChild(path);
      const txt = document.createElementNS(ns, 'text');
      txt.setAttribute('x', mx);
      txt.setAttribute('y', my - 8);
      txt.setAttribute('text-anchor', 'middle');
      txt.setAttribute('class', 'edge-symbol');
      txt.textContent = label;
      svg.appendChild(txt);
    }

    // nodes
    for (const state of Object.keys(FSM_LAYOUT)) {
      const pos = FSM_LAYOUT[state];
      let cls = 'state';
      if (active.has(state)) cls += ' active';
      else if (candidates.has(state)) cls += ' candidate';
      if (state === 'ALERT') cls += ' alert';
      const c = document.createElementNS(ns, 'circle');
      c.setAttribute('cx', pos.x); c.setAttribute('cy', pos.y);
      c.setAttribute('r', 16); c.setAttribute('class', cls);
      svg.appendChild(c);
      const t = document.createElementNS(ns, 'text');
      t.setAttribute('x', pos.x); t.setAttribute('y', pos.y + 4);
      t.setAttribute('text-anchor', 'middle'); t.setAttribute('class', 'state-label');
      t.textContent = state;
      svg.appendChild(t);
    }

    // meta
    const meta = document.getElementById('fsm-meta');
    let html = '';
    html += `<div><b>state:</b> ${data.current_state || '?'} `;
    if (data.candidate_next_states && data.candidate_next_states.length)
      html += `<span style="color:#fbd38d">→ ${data.candidate_next_states.join(', ')}</span>`;
    html += `</div>`;
    if (data.observed_symbols && data.observed_symbols.length) {
      html += `<div><b>symbols:</b> ` + data.observed_symbols.map(s =>
        `<span class="obs-symbol${s==='R'?' r-symbol':''}">${s}</span>`).join('') + `</div>`;
    } else {
      html += `<div><b>symbols:</b> <i>none</i></div>`;
    }
    if (data.transition_trigger) html += `<div style="margin-top:4px"><i>${escapeHtml(data.transition_trigger).slice(0, 220)}</i></div>`;
    if (data.error) html += `<div style="color:#f56565">${data.error}${data.hint?': '+escapeHtml(data.hint):''}</div>`;
    meta.innerHTML = html;

    // events
    const ol = document.getElementById('fsm-events');
    ol.innerHTML = '';
    for (const ev of (data.source_events || []).slice(-10).reverse()) {
      const li = document.createElement('li');
      const syms = (ev.symbols || []).join(',') || '-';
      li.innerHTML = `<span class="rule">${escapeHtml(ev.rule_name||'?')}</span> · <span class="syms">[${syms}]</span>` + (ev.observed_at ? ` · <small>${ev.observed_at.slice(11,19)}</small>` : '');
      ol.appendChild(li);
    }
  }
  function escapeHtml(s) { return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

  async function loadFsmFor(podId) {
    try {
      const r = await fetch('/api/pod_fsm/' + encodeURIComponent(podId));
      const data = await r.json();
      renderFsm(data);
    } catch (e) { console.error(e); }
  }

  cy.on('tap', 'node', (ev) => {
    const d = ev.target.data();
    showEvidence({
      id: d.id,
      type: d.type,
      label_state: d.label_state,
      fsm_state: d.fsm_state,
      display_state: d.display_state,
      progress_level: d.progress_level,
      namespace: d.namespace,
      matched: d.matched,
    });
    loadFsmFor(d.id);
  });
  cy.on('tap', 'edge', (ev) => {
    const d = ev.target.data();
    showEvidence({
      id: d.id,
      grade: d.grade,
      source: d.source,
      target: d.target,
      observed_at: d.observed_at,
      edge_type: d.edge_type,
      evidence: d.evidence,
    });
  });

  function buildGraphUrl() {
    const showBaseline = document.getElementById('show-baseline').checked;
    const showIsolated = document.getElementById('show-isolated').checked;
    const grades = showBaseline ? 'all' : 'correlation,related';
    return `/api/graph?grades=${grades}&drop_isolated=${showIsolated ? 0 : 1}`;
  }

  async function loadGraph() {
    try {
      const res = await fetch(buildGraphUrl());
      const data = await res.json();
      cy.elements().remove();
      cy.add(data.elements || []);
      const r = data.rendered || {};
      const s = data.summary || {};
      const layoutName = (r.edge_count || 0) > 300 ? 'cose' : 'dagre';
      cy.layout({
        name: layoutName,
        rankDir: 'LR', nodeSep: 30, edgeSep: 10, rankSep: 80,
        animate: false, idealEdgeLength: 80, nodeRepulsion: 4000,
      }).run();
      document.getElementById('counts').textContent =
        `rendered: ${r.node_count || 0}n / ${r.edge_count || 0}e ` +
        `(of total ${s.node_count || 0}n / ${s.edge_count || 0}e — prop=${s.propagation_edges || 0} adj=${s.adjacent_edges || 0})`;
      document.getElementById('baseline-badge').textContent =
        `baseline: ${data.baseline_active ? 'collecting' : 'fixed'}`;
    } catch (e) {
      console.error(e);
      document.getElementById('counts').textContent = `error: ${e.message || e}`;
    }
  }

  document.getElementById('refresh').onclick = loadGraph;
  document.getElementById('show-baseline').onchange = loadGraph;
  document.getElementById('show-isolated').onchange = loadGraph;
  document.getElementById('reset-baseline').onclick = async () => {
    await fetch('/api/baseline/reset', { method: 'POST' });
    loadGraph();
  };

  let timer = null;
  function startAuto() {
    if (timer) return;
    timer = setInterval(loadGraph, refreshMs);
  }
  function stopAuto() {
    if (!timer) return;
    clearInterval(timer); timer = null;
  }
  document.getElementById('auto').addEventListener('change', (ev) => {
    if (ev.target.checked) startAuto(); else stopAuto();
  });

  loadGraph();
  startAuto();
})();

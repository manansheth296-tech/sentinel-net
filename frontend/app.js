/* SentinelNet frontend — vanilla JS, no build step.
 * Talks to backend/api.py (FastAPI). All data shown is exactly what the
 * API returns; this file does not invent placeholder values. Where the
 * backend marks something unavailable, the UI shows "Not available" /
 * the backend's stated reason instead of fabricating a number.
 */

const API_BASE = window.SENTINELNET_API_BASE;

const state = {
  page: "dashboard",
  health: null,
  modelInfo: null,
  mitreInfo: null,
  analysis: null,      // last successful /api/analyze response
  analyzing: false,
  analyzeError: null,
  sourceFileName: null,
  selectedFeature: null,
};

const PAGE_TITLES = {
  dashboard: "Dashboard",
  traffic: "Traffic Analysis",
  forecast: "Forecast",
  mitre: "MITRE ATT&CK",
  flows: "Network Flows",
  shap: "SHAP Explainability",
  performance: "Model Performance",
  technical: "Technical Details",
  report: "Report",
};

// ---------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------
async function apiGet(path) {
  const res = await fetch(`${API_BASE}${path}`);
  if (!res.ok) throw new Error(`${path} returned HTTP ${res.status}`);
  return res.json();
}

async function apiAnalyze(file) {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${API_BASE}/api/analyze`, { method: "POST", body: form });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(body.message || body.detail || `Analysis failed (HTTP ${res.status})`);
    err.detail = body;
    throw err;
  }
  return body;
}

// ---------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------
async function refreshHealth() {
  const dot = document.getElementById("status-dot");
  const text = document.getElementById("status-text");
  try {
    const health = await apiGet("/api/health");
    state.health = health;
    dot.className = "status-dot ok";
    text.textContent = `Backend online — ${health.model_version}`;
  } catch (e) {
    state.health = null;
    dot.className = "status-dot bad";
    text.textContent = `Backend unreachable at ${API_BASE}`;
  }
}

async function loadStaticInfo() {
  try { state.modelInfo = await apiGet("/api/model"); } catch (e) { /* shown as unavailable in Technical page */ }
  try { state.mitreInfo = await apiGet("/api/mitre"); } catch (e) { /* shown as unavailable in MITRE page */ }
}

function init() {
  document.querySelectorAll(".nav-link").forEach((btn) => {
    btn.addEventListener("click", () => navigate(btn.dataset.page));
  });
  refreshHealth();
  loadStaticInfo().then(renderCurrentPage);
  renderCurrentPage();
}

function navigate(page) {
  state.page = page;
  document.querySelectorAll(".nav-link").forEach((b) => b.classList.toggle("active", b.dataset.page === page));
  document.getElementById("breadcrumb").textContent = PAGE_TITLES[page];
  document.getElementById("main-content").focus();
  renderCurrentPage();
}

function renderCurrentPage() {
  const root = document.getElementById("page-root");
  root.innerHTML = "";
  const renderers = {
    dashboard: renderDashboard,
    traffic: renderTraffic,
    forecast: renderForecast,
    mitre: renderMitre,
    flows: renderFlows,
    shap: renderShap,
    performance: renderPerformance,
    technical: renderTechnical,
    report: renderReport,
  };
  (renderers[state.page] || renderDashboard)(root);
}

// ---------------------------------------------------------------------
// Small DOM helpers
// ---------------------------------------------------------------------
function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  Object.entries(attrs).forEach(([k, v]) => {
    if (k === "class") node.className = v;
    else if (k === "html") node.innerHTML = v;
    else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  });
  (Array.isArray(children) ? children : [children]).forEach((c) => {
    if (c === null || c === undefined) return;
    node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  });
  return node;
}

function emptyState(root, message) {
  root.appendChild(el("div", { class: "panel empty-state" }, [
    el("h2", {}, "No analysis available"),
    el("p", {}, message || "Upload a supported network flow dataset on the Traffic Analysis page to begin."),
    el("button", { class: "btn", onclick: () => navigate("traffic") }, "Go to Traffic Analysis"),
  ]));
}

function riskBadge(prob) {
  if (prob === null || prob === undefined) return el("span", { class: "badge badge-grey" }, "Unavailable");
  let cls = "badge-green", label = "Low";
  if (prob >= 0.7) { cls = "badge-red"; label = "High"; }
  else if (prob >= 0.3) { cls = "badge-amber"; label = "Medium"; }
  return el("span", { class: `badge ${cls}` }, `${label} — ${(prob * 100).toFixed(0)}%`);
}

function fmtPct(v) { return (v === null || v === undefined || Number.isNaN(v)) ? "—" : `${(v * 100).toFixed(1)}%`; }
function fmtNum(v, d = 4) { return (v === null || v === undefined || Number.isNaN(v)) ? "—" : Number(v).toFixed(d); }

// ---------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------
function renderDashboard(root) {
  root.appendChild(el("h1", {}, "Executive Dashboard"));
  root.appendChild(el("p", { class: "page-lede" }, "Aggregate attack-risk overview for the most recently analyzed traffic capture."));

  const a = state.analysis;
  if (!a) { emptyState(root); return; }

  const prob = a.prediction?.attack_risk_probability ?? null;
  const forecastPeak = (a.forecast || []).reduce((m, s) => Math.max(m, s.infiltration_prob ?? 0), prob ?? 0);
  const riskClass = prob === null ? "" : prob >= 0.7 ? "risk-high" : prob >= 0.3 ? "risk-medium" : "risk-low";

  const strip = el("div", { class: "stat-strip" }, [
    el("div", { class: `stat-cell ${riskClass}` }, [
      el("div", { class: "stat-label" }, "Current attack risk"),
      el("div", { class: "stat-value" }, prob !== null ? `${(prob * 100).toFixed(1)}%` : "—"),
      el("div", { class: "stat-sub" }, [riskBadge(prob)]),
    ]),
    el("div", { class: "stat-cell" }, [
      el("div", { class: "stat-label" }, "Predicted stage (rule-based)"),
      el("div", { class: "stat-value", style: "font-size:16px;" }, a.current_context?.rule_based_mitre_stage ?? "Unknown"),
    ]),
    el("div", { class: "stat-cell" }, [
      el("div", { class: "stat-label" }, "Peak forecast risk"),
      el("div", { class: "stat-value" }, `${(forecastPeak * 100).toFixed(1)}%`),
      el("div", { class: "stat-sub" }, "next 5 rollout steps"),
    ]),
    el("div", { class: "stat-cell" }, [
      el("div", { class: "stat-label" }, "Windows analyzed"),
      el("div", { class: "stat-value" }, String(a.metadata?.windows_in_session ?? "—")),
    ]),
    el("div", { class: "stat-cell" }, [
      el("div", { class: "stat-label" }, "Sequence shape"),
      el("div", { class: "stat-value", style: "font-size:16px;" }, (a.metadata?.sequence_shape || []).join(" × ")),
    ]),
    el("div", { class: "stat-cell" }, [
      el("div", { class: "stat-label" }, "Model status"),
      el("div", { class: "stat-value", style: "font-size:14px;" }, a.status ?? "—"),
    ]),
  ]);
  root.appendChild(strip);

  root.appendChild(el("div", { class: "panel" }, [
    el("h2", {}, "Risk Timeline (observed → forecast)"),
    buildTimelineSvg(a),
  ]));

  root.appendChild(el("div", { class: "two-col" }, [
    el("div", { class: "panel" }, [
      el("h2", {}, "Top Risk Drivers (SHAP)"),
      buildFeatureBars(a.top_features || []),
      el("p", { class: "metric-sub" }, `Method: ${a.shap?.method || "unknown"}`),
    ]),
    el("div", { class: "panel" }, [
      el("h2", {}, "Recent Network Activity"),
      buildRecentActivitySummary(a),
    ]),
  ]));
}

function metricCard(label, value, sub) {
  const card = el("div", { class: "metric-card" }, [
    el("div", { class: "metric-label" }, label),
    el("div", { class: "metric-value" }, String(value)),
  ]);
  if (sub) {
    if (typeof sub === "string") card.appendChild(el("div", { class: "metric-sub" }, sub));
    else card.appendChild(el("div", { class: "metric-sub" }, [sub]));
  }
  return card;
}

function buildRecentActivitySummary(a) {
  const flows = a.flows;
  if (!flows || !flows.available) {
    return el("p", { class: "metric-sub" }, flows?.reason || "Flow preview unavailable for this file.");
  }
  return el("p", { class: "metric-sub" },
    `${flows.total_rows_in_file.toLocaleString()} flow rows found (showing ${flows.rows_shown}). Columns: ${flows.columns_found.join(", ")}.`);
}

// ---------------------------------------------------------------------
// Traffic Analysis
// ---------------------------------------------------------------------
function renderTraffic(root) {
  root.appendChild(el("h1", {}, "Traffic Analysis"));
  root.appendChild(el("p", { class: "page-lede" },
    "Upload a network flow-record file (CSV or Parquet — e.g. CICFlowMeter output). PCAP capture files are not supported by this pipeline."));

  const fileInput = el("input", { type: "file", id: "file-input", accept: ".csv,.parquet" });
  const uploadZone = el("div", { class: "upload-zone" }, [
    el("p", {}, "Drag a file here or choose one to analyze."),
    fileInput,
    el("div", { style: "margin-top:14px;" }, [
      el("button", {
        class: "btn", id: "analyze-btn",
        onclick: () => handleAnalyze(fileInput.files[0]),
      }, "Run Analysis"),
    ]),
  ]);
  root.appendChild(el("div", { class: "panel" }, uploadZone));

  if (state.analyzing) {
    root.appendChild(buildLoadingPanel());
    return;
  }

  if (state.analyzeError) {
    root.appendChild(el("div", { class: "alert alert-error" }, [
      el("strong", {}, "Analysis failed. "),
      state.analyzeError,
    ]));
  }

  const a = state.analysis;
  if (!a) {
    root.appendChild(el("div", { class: "panel empty-state" }, [
      el("p", {}, "No analysis available. Upload a file above to begin."),
    ]));
    return;
  }

  root.appendChild(el("div", { class: "panel" }, [
    el("h2", {}, "Processing Summary"),
    el("table", {}, [
      el("tbody", {}, [
        tr("File", state.sourceFileName || "—"),
        tr("Rows processed", (a.flows?.total_rows_in_file ?? "—").toLocaleString?.() ?? a.flows?.total_rows_in_file ?? "—"),
        tr("Windows built", a.metadata?.windows_in_session ?? "—"),
        tr("Sequence used for prediction", (a.metadata?.sequence_shape || []).join(" × ")),
        tr("Attack risk probability", fmtPct(a.prediction?.attack_risk_probability)),
        tr("Classification (≥0.5 threshold)", a.prediction?.predicted_attack ? "Predicted attack" : "Predicted benign"),
        tr("Rule-based MITRE stage", a.current_context?.rule_based_mitre_stage ?? "—"),
      ]),
    ]),
  ]));
}

function tr(label, value) {
  return el("tr", {}, [el("th", {}, label), el("td", {}, String(value))]);
}

function buildLoadingPanel() {
  const steps = [
    "Loading dataset…",
    "Validating features…",
    "Building sequence…",
    "Running model…",
    "Generating forecast…",
    "Calculating SHAP explanation…",
    "Preparing results…",
  ];
  return el("div", { class: "panel loading-state" }, steps.map((s) =>
    el("div", { class: "loading-line" }, [el("span", { class: "spinner" }), s])
  ));
}

async function handleAnalyze(file) {
  if (!file) {
    state.analyzeError = "Choose a file first.";
    renderCurrentPage();
    return;
  }
  state.analyzing = true;
  state.analyzeError = null;
  state.sourceFileName = file.name;
  renderCurrentPage();
  try {
    const result = await apiAnalyze(file);
    state.analysis = result;
    state.analyzeError = null;
  } catch (e) {
    state.analysis = null;
    state.analyzeError = e.message;
  } finally {
    state.analyzing = false;
    renderCurrentPage();
  }
}

// ---------------------------------------------------------------------
// Forecast
// ---------------------------------------------------------------------
function renderForecast(root) {
  root.appendChild(el("h1", {}, "Forecast"));
  root.appendChild(el("p", { class: "page-lede" }, "Autoregressive rollout of the world model, 5 steps beyond the current window."));

  const a = state.analysis;
  if (!a) { emptyState(root); return; }

  root.appendChild(el("div", { class: "alert alert-info" }, a.forecast_note ||
    "Forecast steps follow the model's internal pseudo-window contract, not a real-world clock."));

  root.appendChild(el("div", { class: "panel" }, [
    el("h2", {}, "Observed vs. Predicted Risk"),
    buildTimelineSvg(a),
  ]));

  root.appendChild(el("div", { class: "panel" }, [
    el("h2", {}, "Step-by-Step Forecast"),
    el("div", { class: "table-scroll" }, [
      el("table", {}, [
        el("thead", {}, el("tr", {}, [el("th", {}, "Step"), el("th", {}, "Attack Risk"), el("th", {}, "Nearest-Centroid Stage")])),
        el("tbody", {}, [
          el("tr", {}, [el("td", {}, "Current (observed)"), el("td", {}, fmtPct(a.prediction?.attack_risk_probability)), el("td", {}, a.current_context?.rule_based_mitre_stage ?? "—")]),
          ...(a.forecast || []).map((s) => el("tr", {}, [
            el("td", {}, `+${s.step_ahead}`),
            el("td", {}, fmtPct(s.infiltration_prob)),
            el("td", {}, s.predicted_stage ?? "Unknown"),
          ])),
        ]),
      ]),
    ]),
  ]));
}

function buildTimelineSvg(a) {
  const current = a.prediction?.attack_risk_probability ?? 0;
  const points = [{ x: 0, y: current, kind: "observed" }, ...(a.forecast || []).map((s) => ({ x: s.step_ahead, y: s.infiltration_prob ?? 0, kind: "predicted" }))];
  const w = 640, h = 220, pad = 34;
  const maxX = Math.max(...points.map((p) => p.x), 1);
  const xScale = (x) => pad + (x / maxX) * (w - pad * 2);
  const yScale = (y) => h - pad - y * (h - pad * 2);

  const svgNS = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(svgNS, "svg");
  svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", "Line chart of observed and forecast attack risk probability over rollout steps");
  svg.style.width = "100%";
  svg.style.maxWidth = `${w}px`;
  svg.style.height = "auto";

  // gridlines
  [0, 0.25, 0.5, 0.75, 1].forEach((g) => {
    const y = yScale(g);
    const line = document.createElementNS(svgNS, "line");
    line.setAttribute("x1", pad); line.setAttribute("x2", w - pad);
    line.setAttribute("y1", y); line.setAttribute("y2", y);
    line.setAttribute("stroke", "#e2e8f0");
    svg.appendChild(line);
    const label = document.createElementNS(svgNS, "text");
    label.setAttribute("x", 4); label.setAttribute("y", y + 4);
    label.setAttribute("font-size", "10"); label.setAttribute("fill", "#5b6779");
    label.textContent = `${Math.round(g * 100)}%`;
    svg.appendChild(label);
  });

  // threshold line at 0.5
  const thresholdY = yScale(0.5);
  const thresholdLine = document.createElementNS(svgNS, "line");
  thresholdLine.setAttribute("x1", pad); thresholdLine.setAttribute("x2", w - pad);
  thresholdLine.setAttribute("y1", thresholdY); thresholdLine.setAttribute("y2", thresholdY);
  thresholdLine.setAttribute("stroke", "#b3261e"); thresholdLine.setAttribute("stroke-dasharray", "4 3");
  svg.appendChild(thresholdLine);

  const path = document.createElementNS(svgNS, "polyline");
  path.setAttribute("points", points.map((p) => `${xScale(p.x)},${yScale(p.y)}`).join(" "));
  path.setAttribute("fill", "none");
  path.setAttribute("stroke", "#0f8a8a");
  path.setAttribute("stroke-width", "2.5");
  svg.appendChild(path);

  points.forEach((p) => {
    const c = document.createElementNS(svgNS, "circle");
    c.setAttribute("cx", xScale(p.x)); c.setAttribute("cy", yScale(p.y));
    c.setAttribute("r", 4);
    c.setAttribute("fill", p.kind === "observed" ? "#0f8a8a" : "#2f6fed");
    svg.appendChild(c);
    const t = document.createElementNS(svgNS, "text");
    t.setAttribute("x", xScale(p.x)); t.setAttribute("y", h - 10);
    t.setAttribute("font-size", "10"); t.setAttribute("fill", "#5b6779"); t.setAttribute("text-anchor", "middle");
    t.textContent = p.x === 0 ? "now" : `+${p.x}`;
    svg.appendChild(t);
  });

  return el("div", { class: "timeline-svg-wrap" }, svg);
}

// ---------------------------------------------------------------------
// MITRE
// ---------------------------------------------------------------------
function renderMitre(root) {
  root.appendChild(el("h1", {}, "MITRE ATT&CK Mapping"));
  root.appendChild(el("div", { class: "alert alert-warn" },
    "This mapping is a rule-based lookup table (backend/mitre_mapping.py), not a learned MITRE classifier. It matches known dataset labels/filenames to a stage name."));

  const a = state.analysis;
  if (a) {
    root.appendChild(el("div", { class: "panel" }, [
      el("h2", {}, "Current Session"),
      el("table", {}, [el("tbody", {}, [
        tr("Rule-based stage", a.current_context?.rule_based_mitre_stage ?? "Unknown Stage"),
        tr("Recent-window majority vote", a.current_context?.recent_stage?.stage ?? "—"),
        tr("Windows considered for vote", a.current_context?.recent_stage?.n_windows_considered ?? "—"),
      ])]),
    ]));
  }

  const map = state.mitreInfo?.mapping;
  root.appendChild(el("div", { class: "panel" }, [
    el("h2", {}, "Lookup Table"),
    map
      ? el("table", {}, [
          el("thead", {}, el("tr", {}, [el("th", {}, "Dataset label"), el("th", {}, "MITRE stage")])),
          el("tbody", {}, Object.entries(map).map(([k, v]) => el("tr", {}, [el("td", {}, k), el("td", {}, v)]))),
        ])
      : el("p", { class: "metric-sub" }, "Mapping table not available — is the backend running?"),
  ]));
}

// ---------------------------------------------------------------------
// Network Flows
// ---------------------------------------------------------------------
function renderFlows(root) {
  root.appendChild(el("h1", {}, "Network Flows"));
  const a = state.analysis;
  if (!a) { emptyState(root); return; }

  const flows = a.flows;
  if (!flows || !flows.available) {
    root.appendChild(el("div", { class: "alert alert-warn" }, flows?.reason || "Flow-level detection unavailable for this file."));
    return;
  }

  root.appendChild(el("div", { class: "alert alert-info" }, flows.note));

  const cols = flows.columns_found;
  root.appendChild(el("div", { class: "panel" }, [
    el("h2", {}, `Flows (${flows.rows_shown} of ${flows.total_rows_in_file.toLocaleString()})`),
    el("div", { class: "table-scroll" }, [
      el("table", {}, [
        el("thead", {}, el("tr", {}, [...cols.map((c) => el("th", {}, c)), el("th", {}, "Window")])),
        el("tbody", {}, flows.rows.slice(0, 200).map((row) => el("tr", {}, [
          ...cols.map((c) => el("td", {}, row[c] === null || row[c] === undefined ? "—" : String(row[c]))),
          el("td", {}, String(row.window_id)),
        ]))),
      ]),
    ]),
    flows.rows.length > 200 ? el("p", { class: "metric-sub" }, `Showing first 200 of ${flows.rows.length} previewed rows.`) : null,
  ]));
}

// ---------------------------------------------------------------------
// SHAP Explainability
// ---------------------------------------------------------------------
function renderShap(root) {
  root.appendChild(el("h1", {}, "SHAP Explainability"));
  const a = state.analysis;
  if (!a) { emptyState(root); return; }

  const shap = a.shap || {};
  root.appendChild(el("div", { class: "alert alert-info" }, [el("strong", {}, "Explanation method: "), shap.method || "unknown"]));

  root.appendChild(el("div", { class: "panel" }, [
    el("h2", {}, "Why was this traffic scored this way?"),
    buildWhyList(shap.local_explanation || []),
  ]));

  root.appendChild(el("div", { class: "two-col" }, [
    el("div", { class: "panel" }, [
      el("h2", {}, "Top Contributors (local)"),
      buildShapTable(shap.local_explanation || []),
    ]),
    el("div", { class: "panel" }, [
      el("h2", {}, "Feature Detail"),
      buildFeatureDetail(shap.local_explanation || []),
    ]),
  ]));

  root.appendChild(el("div", { class: "panel" }, [
    el("h2", {}, "Temporal Contribution (across the 20-step sequence)"),
    shap.temporal_explanation?.available
      ? buildTemporalChart(shap.temporal_explanation)
      : el("p", { class: "metric-sub" }, shap.temporal_explanation?.reason || "Temporal breakdown unavailable."),
  ]));

  root.appendChild(el("div", { class: "panel" }, [
    el("h2", {}, "Global Explanation (whole session)"),
    shap.global_explanation?.available
      ? buildGlobalTable(shap.global_explanation)
      : el("p", { class: "metric-sub" }, shap.global_explanation?.reason || "Global explanation unavailable."),
  ]));
}

function buildWhyList(rows) {
  if (!rows.length) return el("p", { class: "metric-sub" }, "No explanation rows returned.");
  return el("ol", {}, rows.slice(0, 5).map((r) =>
    el("li", {}, `${r.feature} ${r.direction} (SHAP ${r.shap_value >= 0 ? "+" : ""}${fmtNum(r.shap_value, 4)})`)
  ));
}

function buildShapTable(rows) {
  if (!rows.length) return el("p", { class: "metric-sub" }, "No SHAP rows returned.");
  return el("table", {}, [
    el("thead", {}, el("tr", {}, ["Feature", "SHAP value", "|SHAP|", "Direction"].map((h) => el("th", {}, h)))),
    el("tbody", {}, rows.map((r) => el("tr", {
      onclick: () => { state.selectedFeature = r.feature; renderCurrentPage(); },
      style: "cursor:pointer;",
    }, [
      el("td", {}, r.feature),
      el("td", {}, fmtNum(r.shap_value, 4)),
      el("td", {}, fmtNum(r.absolute_shap_value, 4)),
      el("td", {}, r.direction),
    ]))),
  ]);
}

function buildFeatureDetail(rows) {
  const sel = state.selectedFeature && rows.find((r) => r.feature === state.selectedFeature);
  const row = sel || rows[0];
  if (!row) return el("p", { class: "metric-sub" }, "Select a feature from the table to see its detail.");
  const dl = el("dl", { class: "feature-detail" }, [
    el("dt", {}, "Feature"), el("dd", {}, row.feature),
    el("dt", {}, "SHAP value (signed)"), el("dd", {}, fmtNum(row.shap_value, 6)),
    el("dt", {}, "Absolute SHAP value"), el("dd", {}, fmtNum(row.absolute_shap_value, 6)),
    el("dt", {}, "Mean-statistic contribution"), el("dd", {}, fmtNum(row.mean_contribution, 6)),
    el("dt", {}, "Std-statistic (variability) contribution"), el("dd", {}, fmtNum(row.std_contribution, 6)),
    el("dt", {}, "Direction"), el("dd", {}, row.direction),
  ]);
  return dl;
}

function buildTemporalChart(temporal) {
  const steps = temporal.steps || [];
  const maxImp = Math.max(...steps.map((s) => s.importance), 0.0001);
  return el("div", {}, [
    ...steps.map((s) => el("div", { class: "bar-row" }, [
      el("span", { class: "bar-label" }, `t = ${s.timestep}`),
      el("span", { class: "bar-track" }, [el("span", { class: "bar-fill", style: `width:${(s.importance / maxImp) * 100}%` })]),
      el("span", { class: "bar-value" }, fmtNum(s.importance, 4)),
    ])),
    el("p", { class: "metric-sub" }, `Most influential timestep: t = ${temporal.most_influential_timestep} (0 = most recent observed window).`),
  ]);
}

function buildGlobalTable(global) {
  return el("div", {}, [
    el("p", { class: "metric-sub" }, `Computed across ${global.n_windows_analyzed} windows in this session.`),
    el("table", {}, [
      el("thead", {}, el("tr", {}, [el("th", {}, "Feature"), el("th", {}, "Mean |SHAP|")])),
      el("tbody", {}, (global.top_features || []).map((r) => el("tr", {}, [el("td", {}, r.feature), el("td", {}, fmtNum(r.mean_absolute_shap, 6))]))),
    ]),
  ]);
}

function buildFeatureBars(rows) {
  if (!rows.length) return el("p", { class: "metric-sub" }, "No feature attribution available.");
  const maxImp = Math.max(...rows.map((r) => r.importance), 0.0001);
  return el("div", {}, rows.map((r) => el("div", { class: "bar-row" }, [
    el("span", { class: "bar-label" }, r.feature),
    el("span", { class: "bar-track" }, [el("span", { class: "bar-fill", style: `width:${(r.importance / maxImp) * 100}%` })]),
    el("span", { class: "bar-value" }, fmtPct(r.importance)),
  ])));
}

// ---------------------------------------------------------------------
// Model Performance
// ---------------------------------------------------------------------
function renderPerformance(root) {
  root.appendChild(el("h1", {}, "Model Performance"));

  const bench = state.analysis?.benchmark || null;
  const info = state.modelInfo;

  root.appendChild(el("div", { class: "panel" }, [
    el("h2", {}, "World Model — Recorded Benchmark"),
    el("p", { class: "metric-sub" }, `Source: ${bench?.world_model_source || info?.benchmark?.source || "model2/export_bundle_v4.json"}`),
    buildBenchmarkTable(bench?.world_model || info?.benchmark?.world_model),
  ]));

  root.appendChild(el("div", { class: "panel" }, [
    el("h2", {}, "Logistic Regression Baseline"),
    bench?.logistic_baseline?.available
      ? buildBenchmarkTable(bench.logistic_baseline)
      : el("p", { class: "metric-sub" }, bench?.logistic_baseline?.reason || "Run an analysis, or execute backend/train_baseline.py, to populate this section."),
  ]));
}

function buildBenchmarkTable(m) {
  if (!m) return el("p", { class: "metric-sub" }, "Not available.");
  return el("table", {}, [
    el("thead", {}, el("tr", {}, ["Metric", "Value"].map((h) => el("th", {}, h)))),
    el("tbody", {}, [
      tr("F1 Score", fmtNum(m.f1)),
      tr("Precision", fmtNum(m.precision)),
      tr("Recall", fmtNum(m.recall)),
      tr("False Positive Rate", fmtNum(m.fpr)),
    ]),
  ]);
}

// ---------------------------------------------------------------------
// Technical Details
// ---------------------------------------------------------------------
function renderTechnical(root) {
  root.appendChild(el("h1", {}, "Technical Details"));
  const info = state.modelInfo;
  if (!info) {
    root.appendChild(el("div", { class: "alert alert-warn" }, "Could not reach /api/model. Is the backend running?"));
    return;
  }

  root.appendChild(el("div", { class: "panel" }, [
    el("h2", {}, "Model"),
    el("table", {}, [el("tbody", {}, [
      tr("Model version", info.model_version),
      tr("Canonical source", info.canonical_source),
      tr("Status", info.status),
    ])]),
  ]));

  root.appendChild(el("div", { class: "panel" }, [
    el("h2", {}, "Architecture"),
    el("table", {}, [el("tbody", {}, [
      tr("Type", info.architecture.type),
      tr("Hidden size", info.architecture.hidden_size),
      tr("Layers", info.architecture.num_layers),
      tr("Dropout", info.architecture.dropout),
      tr("LayerNorm", info.architecture.layer_norm ? "Yes" : "No"),
      tr("Heads", info.architecture.heads.join(" · ")),
    ])]),
  ]));

  root.appendChild(el("div", { class: "panel" }, [
    el("h2", {}, "Input Contract"),
    el("table", {}, [el("tbody", {}, [
      tr("Raw features", info.input_contract.raw_features),
      tr("State dimensions", info.input_contract.state_dim),
      tr("Sequence length", info.input_contract.sequence_length),
      tr("Window size (rows)", info.input_contract.window_rows),
    ])]),
  ]));

  root.appendChild(el("div", { class: "panel" }, [
    el("h2", {}, "Explainability"),
    el("p", {}, state.analysis?.shap?.method
      ? `Last analysis used: ${state.analysis.shap.method}`
      : "Run an analysis to see which explainer actually ran (shap.GradientExplainer, or the permutation-importance fallback if SHAP could not run for that session)."),
  ]));

  root.appendChild(el("div", { class: "panel" }, [
    el("h2", {}, "Model Limitations"),
    el("ul", { class: "limitations-list" }, (info.limitations || []).map((l) => el("li", {}, l))),
  ]));
}

// ---------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------
function renderReport(root) {
  root.appendChild(el("h1", {}, "Report"));
  const a = state.analysis;
  if (!a) { emptyState(root); return; }

  root.appendChild(el("div", { class: "panel" }, [
    el("h2", {}, "Analysis Summary"),
    el("table", {}, [el("tbody", {}, [
      tr("Source file", state.sourceFileName || "—"),
      tr("Attack risk probability", fmtPct(a.prediction?.attack_risk_probability)),
      tr("Predicted stage (rule-based)", a.current_context?.rule_based_mitre_stage ?? "—"),
      tr("Peak forecast risk", fmtPct(Math.max(...(a.forecast || []).map((s) => s.infiltration_prob ?? 0), a.prediction?.attack_risk_probability ?? 0))),
      tr("Windows analyzed", a.metadata?.windows_in_session ?? "—"),
      tr("SHAP method used", a.shap?.method ?? "—"),
    ])]),
  ]));

  root.appendChild(el("div", { class: "panel" }, [
    el("h2", {}, "Top SHAP Drivers"),
    buildFeatureBars(a.top_features || []),
  ]));

  root.appendChild(el("div", { class: "panel" }, [
    el("h2", {}, "Limitations"),
    el("ul", { class: "limitations-list" }, (a.limitations || []).map((l) => el("li", {}, l))),
  ]));

  root.appendChild(el("div", { class: "panel report-actions" }, [
    el("button", { class: "btn", onclick: downloadReport }, "Download Report (.json)"),
  ]));
}

function downloadReport() {
  const blob = new Blob([JSON.stringify(state.analysis, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `sentinelnet-report-${Date.now()}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------------
init();

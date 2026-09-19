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
  findings: "Key Findings",
  traffic: "Traffic Analysis",
  forecast: "Forecast",
  mitre: "MITRE ATT&CK",
  flows: "Network Flows",
  shap: "SHAP Explainability",
  performance: "Model Performance",
  technical: "Technical Details",
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
    findings: renderFindings,
    traffic: renderTraffic,
    forecast: renderForecast,
    mitre: renderMitre,
    flows: renderFlows,
    shap: renderShap,
    performance: renderPerformance,
    technical: renderTechnical,
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
    // Show high-risk popup if attack_risk_probability >= 0.70
    const prob = result?.prediction?.attack_risk_probability ?? null;
    if (prob !== null && prob >= 0.70) {
      showHighRiskAlert(result);
    }
  } catch (e) {
    state.analysis = null;
    state.analyzeError = e.message;
  } finally {
    state.analyzing = false;
    renderCurrentPage();
  }
}

// ---------------------------------------------------------------------
// High-Risk Alert Popup
// ---------------------------------------------------------------------
function showHighRiskAlert(result) {
  // Remove any existing popup first
  dismissHighRiskAlert(true);

  const prob      = result?.prediction?.attack_risk_probability ?? 0;
  const pctText   = `${(prob * 100).toFixed(1)}%`;
  const stage     = result?.current_context?.rule_based_mitre_stage ?? "Unknown Stage";
  const predicted = result?.prediction?.predicted_attack;
  const filename  = state.sourceFileName || "uploaded file";

  const overlay = document.createElement("div");
  overlay.id = "risk-alert-overlay";
  overlay.setAttribute("role", "alertdialog");
  overlay.setAttribute("aria-modal", "true");
  overlay.setAttribute("aria-labelledby", "risk-alert-title");

  const popup = document.createElement("div");
  popup.id = "risk-alert-popup";

  // Header
  const header = document.createElement("div");
  header.id = "risk-alert-header";
  const icon = document.createElement("span");
  icon.className = "risk-alert-icon";
  icon.setAttribute("aria-hidden", "true");
  const title = document.createElement("h2");
  title.id = "risk-alert-title";
  title.textContent = "⚠ High-Risk Threat Detected";
  header.appendChild(icon);
  header.appendChild(title);

  // Body
  const body = document.createElement("div");
  body.id = "risk-alert-body";

  const pctEl = document.createElement("div");
  pctEl.className = "risk-pct";
  pctEl.textContent = pctText;

  const pctSub = document.createElement("div");
  pctSub.className = "risk-pct-sub";
  pctSub.textContent = `Attack risk probability · ${filename}`;

  const detailRow = document.createElement("div");
  detailRow.className = "risk-detail-row";

  function detailItem(label, value) {
    const item = document.createElement("div");
    item.className = "risk-detail-item";
    const lbl = document.createElement("div");
    lbl.className = "risk-detail-label";
    lbl.textContent = label;
    const val = document.createElement("div");
    val.className = "risk-detail-value";
    val.textContent = value;
    item.appendChild(lbl);
    item.appendChild(val);
    return item;
  }
  detailRow.appendChild(detailItem("MITRE Stage", stage));
  detailRow.appendChild(detailItem("Classification", predicted ? "Attack predicted" : "Predicted benign"));

  const msg = document.createElement("p");
  msg.className = "risk-msg";
  msg.textContent = "The model assigns a risk score above 70%. Review Key Findings for a plain-language summary and recommended actions.";

  body.appendChild(pctEl);
  body.appendChild(pctSub);
  body.appendChild(detailRow);
  body.appendChild(msg);

  // Actions
  const actions = document.createElement("div");
  actions.id = "risk-alert-actions";

  const btnDismiss = document.createElement("button");
  btnDismiss.className = "btn-dismiss";
  btnDismiss.id = "risk-alert-dismiss-btn";
  btnDismiss.textContent = "Dismiss";
  btnDismiss.addEventListener("click", () => dismissHighRiskAlert());

  const btnView = document.createElement("button");
  btnView.className = "btn-view";
  btnView.id = "risk-alert-findings-btn";
  btnView.textContent = "View Key Findings →";
  btnView.addEventListener("click", () => { dismissHighRiskAlert(); navigate("findings"); });

  actions.appendChild(btnDismiss);
  actions.appendChild(btnView);

  popup.appendChild(header);
  popup.appendChild(body);
  popup.appendChild(actions);
  overlay.appendChild(popup);
  document.body.appendChild(overlay);

  // Close on backdrop click (but not popup click)
  overlay.addEventListener("click", (e) => { if (e.target === overlay) dismissHighRiskAlert(); });

  // Close on Escape
  function onKey(e) {
    if (e.key === "Escape") { dismissHighRiskAlert(); document.removeEventListener("keydown", onKey); }
  }
  document.addEventListener("keydown", onKey);

  // Focus the dismiss button for keyboard users
  setTimeout(() => btnDismiss.focus(), 50);
}

function dismissHighRiskAlert(immediate) {
  const overlay = document.getElementById("risk-alert-overlay");
  if (!overlay) return;
  if (immediate) { overlay.remove(); return; }
  overlay.classList.add("closing");
  overlay.addEventListener("animationend", () => overlay.remove(), { once: true });
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
// Shared export helpers
// ---------------------------------------------------------------------
function downloadAnalysisJson() {
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

function printFindings() {
  window.print();
}

// ---------------------------------------------------------------------
// Key Findings  — plain-language summary for a non-technical reader
// ---------------------------------------------------------------------

/*
 * MITRE_PLAIN — a frontend-only lookup keyed by the five stages defined in
 * backend/mitre_mapping.py, plus Normal Traffic and a default fallback.
 * Each entry has:
 *   description  — one sentence explaining what that stage means in an attack
 *   steps        — 3-5 concrete, manager-friendly defensive actions
 */
const MITRE_PLAIN = {
  "Reconnaissance": {
    description: "Someone appears to be probing your network — scanning for open doors, weak spots, or services they can exploit later.",
    steps: [
      "Block or rate-limit the source IP(s) showing scanning behaviour at your firewall.",
      "Review which services and ports are publicly reachable and close anything that doesn't need to be open.",
      "Check server and firewall logs for the same IP appearing in earlier sessions.",
      "Alert your IT or security team so they can watch for a follow-up intrusion attempt.",
    ],
  },
  "Initial Access": {
    description: "This traffic looks like an attempt to break into your systems — for example, by repeatedly guessing passwords or exploiting a web application weakness.",
    steps: [
      "Reset passwords for any accounts or services that were targeted (e.g. FTP, SSH, web login).",
      "Enable or verify multi-factor authentication (MFA) on those accounts.",
      "Block the source IP at the firewall immediately.",
      "Review recent login logs for other suspicious attempts from the same source or time window.",
      "Notify your security or IT team to investigate whether any attempt succeeded.",
    ],
  },
  "Lateral Movement": {
    description: "An attacker may already be inside your network and moving between systems, trying to reach more valuable data or take control of more machines.",
    steps: [
      "Isolate any machines that show unusual internal connection patterns.",
      "Change credentials (passwords, service accounts) for systems involved in the suspicious traffic.",
      "Check for new or unexpected user accounts or software installed on affected systems.",
      "Contact your IT or security team immediately — lateral movement often means an attacker already has a foothold.",
      "Review network-segmentation rules to limit which systems can talk to each other.",
    ],
  },
  "Command & Control": {
    description: "A machine on your network may be receiving remote instructions from an attacker — often a sign that malware (like a bot) is installed and being controlled from outside.",
    steps: [
      "Disconnect the suspected machine from the network to stop the communication channel.",
      "Run a malware scan on the machine immediately.",
      "Block the external IP addresses or domains involved at the firewall and DNS level.",
      "Change credentials for any accounts used on that machine.",
      "Engage your IT or security team — this usually requires a full incident-response process.",
    ],
  },
  "Impact": {
    description: "Your systems are under a disruptive attack — most likely a denial-of-service (DoS/DDoS) intended to make your services unavailable.",
    steps: [
      "Enable DDoS protection or rate-limiting at your firewall or hosting provider.",
      "Contact your ISP or cloud provider to activate traffic scrubbing or upstream filtering.",
      "Block the attacking IP ranges at the network edge if your firewall can handle the volume.",
      "Activate any business-continuity or failover plan to maintain service for legitimate users.",
      "Document the timeline and notify management — a service disruption may require customer or regulatory communication.",
    ],
  },
  "Normal Traffic": null,   // signals "no action needed" branch
  "Unknown Stage": null,    // signals fallback / unavailable branch
};

/*
 * humaniseFeature — maps raw SHAP/model feature names to plain-English phrases
 * a non-technical reader can understand. Falls back to the raw name if not found.
 */
function humaniseFeature(name) {
  const map = {
    // Connection counts / rate
    "Flow Duration":           "how long the connection stayed open",
    "Flow Packets/s":          "how many data packets were sent per second",
    "Flow Bytes/s":            "how much data was transferred per second",
    "Total Fwd Packets":       "total packets sent toward the server",
    "Total Backward Packets":  "total reply packets from the server",
    // Flag-based features
    "SYN Flag Count":          "number of connection-start requests (SYN flags)",
    "FIN Flag Count":          "number of connection-close signals",
    "RST Flag Count":          "number of abrupt connection resets",
    "ACK Flag Count":          "number of acknowledgement signals",
    "PSH Flag Count":          "number of data-push signals",
    "URG Flag Count":          "number of urgent-data signals",
    // Packet size / IAT
    "Fwd Packet Length Max":   "size of the largest packet sent to the server",
    "Fwd Packet Length Min":   "size of the smallest packet sent to the server",
    "Fwd Packet Length Mean":  "average packet size sent to the server",
    "Bwd Packet Length Max":   "size of the largest reply packet from the server",
    "Bwd Packet Length Mean":  "average reply packet size",
    "Packet Length Mean":      "average packet size overall",
    "Packet Length Std":       "how much packet sizes varied",
    "Packet Length Variance":  "variability in packet sizes",
    "Fwd IAT Mean":            "average gap between packets sent to the server",
    "Fwd IAT Std":             "how much the sending gap varied",
    "Bwd IAT Mean":            "average gap between reply packets",
    "Flow IAT Mean":           "average gap between all packets in the flow",
    "Flow IAT Std":            "how much the gap between packets varied",
    "Flow IAT Max":            "the longest pause between packets in this flow",
    // Subflow / bulk
    "Subflow Fwd Packets":     "packets sent in sub-flows toward the server",
    "Subflow Fwd Bytes":       "bytes sent in sub-flows toward the server",
    "Subflow Bwd Packets":     "packets received in sub-flows from the server",
    "Subflow Bwd Bytes":       "bytes received in sub-flows from the server",
    // Misc
    "Active Mean":             "average time the connection was actively transferring data",
    "Idle Mean":               "average time the connection was idle",
    "Init_Win_bytes_forward":  "initial window size offered by the sender",
    "Init_Win_bytes_backward": "initial window size offered by the receiver",
    "act_data_pkt_fwd":        "packets that actually carried data (forward)",
    "min_seg_size_forward":    "smallest segment size sent toward the server",
  };
  return map[name] || name;
}

/*
 * buildFeatureReason — turns the top 2-3 SHAP features into a plain sentence.
 * e.g. "an unusually high SYN flag count and large variation in packet sizes"
 */
function buildFeatureReason(topFeatures) {
  const top = (topFeatures || []).slice(0, 3);
  if (!top.length) return null;
  const phrases = top.map((f) => humaniseFeature(f.feature));
  if (phrases.length === 1) return phrases[0];
  if (phrases.length === 2) return `${phrases[0]} and ${phrases[1]}`;
  return `${phrases[0]}, ${phrases[1]}, and ${phrases[2]}`;
}

function renderFindings(root) {
  root.appendChild(el("h1", {}, "Key Findings"));
  root.appendChild(el("p", { class: "page-lede" },
    "A plain-language summary of the latest analysis — written for a manager or non-technical reader. For full technical detail, see the other pages."));

  const a = state.analysis;
  if (!a) { emptyState(root); return; }

  // ── Data extraction (same fields used by renderDashboard / renderReport) ──
  const prob  = a.prediction?.attack_risk_probability ?? null;
  const stage = a.current_context?.rule_based_mitre_stage ?? "Unknown Stage";
  const forecastPeak = (a.forecast || []).reduce(
    (m, s) => Math.max(m, s.infiltration_prob ?? 0), prob ?? 0
  );

  // Risk label — same thresholds as riskBadge()
  let riskLabel, riskAlertClass;
  if (prob === null)    { riskLabel = "unknown";  riskAlertClass = "alert-info"; }
  else if (prob >= 0.7) { riskLabel = "High";     riskAlertClass = "alert-error"; }
  else if (prob >= 0.3) { riskLabel = "Medium";   riskAlertClass = "alert-warn"; }
  else                  { riskLabel = "Low";       riskAlertClass = "alert-info"; }

  // Plain-language stage translation
  const stageDescriptions = {
    "Reconnaissance":   "probing and scanning for weaknesses (what security teams call 'Reconnaissance')",
    "Initial Access":   "attempting to break in from the outside (what security teams call 'Initial Access')",
    "Lateral Movement": "moving between systems inside the network (what security teams call 'Lateral Movement')",
    "Command & Control": "remotely controlling a machine on your network (what security teams call 'Command & Control')",
    "Impact":           "trying to disrupt or disable your services (what security teams call 'Impact')",
    "Normal Traffic":   "normal activity with no detected attack pattern",
    "Unknown Stage":    null,
  };
  const stagePhrase = stageDescriptions[stage] ?? null;

  // ── Plain-language summary panel ──────────────────────────────────────────
  const featureReason = buildFeatureReason(a.top_features);

  let summaryText;
  if (stage === "Normal Traffic") {
    summaryText = prob !== null
      ? `The analyzed traffic looks like normal, benign activity — currently rated ${riskLabel} risk (${(prob * 100).toFixed(0)}%). No attack pattern was detected.`
      : "The analyzed traffic looks like normal, benign activity. No attack pattern was detected.";
  } else if (stagePhrase && prob !== null) {
    summaryText = `This traffic shows signs of ${stagePhrase}, currently rated ${riskLabel} risk (${(prob * 100).toFixed(0)}%).`;
  } else if (stagePhrase) {
    summaryText = `This traffic shows signs of ${stagePhrase}.`;
  } else {
    summaryText = prob !== null
      ? `The model assigned a ${riskLabel} attack-risk score (${(prob * 100).toFixed(0)}%) to this traffic, but the specific attack stage could not be determined with the available data.`
      : "The attack stage and risk level could not be determined from the available data.";
  }

  let reasonText = null;
  if (featureReason && stage !== "Normal Traffic") {
    reasonText = `The model flagged this traffic mainly because of ${featureReason}.`;
  }

  const summaryChildren = [
    el("h2", {}, "At a glance"),
    el("p", {}, summaryText),
  ];
  if (reasonText) summaryChildren.push(el("p", {}, reasonText));

  // Everything inside printArea will appear in the @media print layout;
  // the action buttons (below) are appended to root directly and are hidden when printing.
  const printArea = el("div", { id: "findings-print-area" });
  root.appendChild(printArea);

  printArea.appendChild(el("div", { class: "panel" }, summaryChildren));

  // Quick-stat strip (reuses existing CSS classes)
  printArea.appendChild(el("div", { class: "stat-strip" }, [
    el("div", { class: `stat-cell ${prob === null ? "" : prob >= 0.7 ? "risk-high" : prob >= 0.3 ? "risk-medium" : "risk-low"}` }, [
      el("div", { class: "stat-label" }, "Current risk level"),
      el("div", { class: "stat-value" }, prob !== null ? `${(prob * 100).toFixed(0)}%` : "—"),
      el("div", { class: "stat-sub" }, [riskBadge(prob)]),
    ]),
    el("div", { class: "stat-cell" }, [
      el("div", { class: "stat-label" }, "Attack stage detected"),
      el("div", { class: "stat-value", style: "font-size:14px;" }, stage),
    ]),
    el("div", { class: "stat-cell" }, [
      el("div", { class: "stat-label" }, "Peak forecast risk"),
      el("div", { class: "stat-value" }, `${(forecastPeak * 100).toFixed(0)}%`),
      el("div", { class: "stat-sub" }, "next 5 rollout steps"),
    ]),
  ]));

  // ── "What this means" + defense checklist ────────────────────────────────
  const stageInfo = Object.prototype.hasOwnProperty.call(MITRE_PLAIN, stage)
    ? MITRE_PLAIN[stage]
    : undefined;  // key genuinely absent → Unknown Stage fallback

  if (stage === "Normal Traffic") {
    // Reassuring note — no checklist needed
    printArea.appendChild(el("div", { class: "panel" }, [
      el("h2", {}, "What this means"),
      el("div", { class: "alert alert-info" },
        "No attack pattern was detected in this capture — no immediate action is needed beyond your normal monitoring practices."),
    ]));
  } else if (stageInfo && stageInfo.steps) {
    // Known stage — full description + ordered checklist
    printArea.appendChild(el("div", { class: "panel" }, [
      el("h2", {}, "What this means"),
      el("p", {}, stageInfo.description),
      el("h2", {}, "Recommended next steps"),
      el("ol", { class: "findings-checklist" },
        stageInfo.steps.map((s) => el("li", {}, s))
      ),
    ]));
  } else {
    // Unknown / missing stage — same "unavailable" pattern used elsewhere
    printArea.appendChild(el("div", { class: "panel" }, [
      el("h2", {}, "What this means"),
      el("p", { class: "metric-sub" },
        "The attack stage could not be determined from this capture. " +
        "No stage-specific guidance is available — if you are concerned, " +
        "share the full report with your IT or security team."),
    ]));
  }

  // Model limitations inherited from the analysis result
  if (a.limitations && a.limitations.length) {
    printArea.appendChild(el("div", { class: "panel" }, [
      el("h2", {}, "Model limitations relevant to this result"),
      el("ul", { class: "limitations-list" },
        a.limitations.map((l) => el("li", {}, l))
      ),
    ]));
  }

  // ── Disclaimer ───────────────────────────────────────────────────────────
  printArea.appendChild(el("p", { class: "metric-sub" },
    "This page simplifies technical findings for a general audience. " +
    "It is a rule-based summary of the model output, not certified security guidance — " +
    "for a confirmed incident, follow your organization\u2019s incident response process."
  ));

  // ── Action buttons (outside print area — hidden when printing) ────────────
  const actionsRow = el("div", { class: "panel report-actions findings-actions" }, [
    el("button", {
      class: "btn",
      id: "findings-btn-json",
      onclick: downloadAnalysisJson,
    }, "Download as JSON"),
    el("button", {
      class: "btn btn-secondary",
      id: "findings-btn-pdf",
      title: "Opens the print dialog — choose \u2018Save as PDF\u2019 as the destination",
      onclick: printFindings,
    }, "Download as PDF\u2026"),
  ]);
  root.appendChild(actionsRow);
}


// ---------------------------------------------------------------------
init();


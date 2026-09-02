import os
import sys
import tempfile

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

# Find the parent folder that actually holds the 'backend' folder
PROJECT_ROOT = CURRENT_DIR
while PROJECT_ROOT and not os.path.exists(os.path.join(PROJECT_ROOT, "backend")):
    PARENT = os.path.dirname(PROJECT_ROOT)
    if PARENT == PROJECT_ROOT: # Reached file system root without finding it
        break
    PROJECT_ROOT = PARENT

# Add it safely to Python's search list
if os.path.exists(os.path.join(PROJECT_ROOT, "backend")):
    if PROJECT_ROOT not in sys.path:
        sys.path.insert(0, PROJECT_ROOT)
else:
    raise RuntimeError(f"Could not find 'backend' directory relative to {CURRENT_DIR}")


# Allow `from backend...` imports when launched as `streamlit run app/streamlit_app.py`
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.engine import run_inference  # noqa: E402

# --------------------------------------------------------------------------
# Theme / tokens — kept consistent with the team's other prototype surfaces
# --------------------------------------------------------------------------
BG = "#0B0F1A"
PANEL = "#121729"
BORDER = "#232B45"
TEXT = "#E9ECF6"
TEXT_DIM = "#8A93B3"
GRID = "#1E2540"
TEAL = "#34D6C4"
AMBER = "#F2B84B"
ORANGE = "#F08A3C"
CORAL = "#F2495C"

STAGE_COLOR = {
    "Normal Traffic": TEAL,
    "Reconnaissance": "#7FE0D2",
    "Initial Access": AMBER,
    "Lateral Movement": ORANGE,
    "Command & Control": "#F26B4C",
    "Impact": CORAL,
    "Unknown Stage": TEXT_DIM,
}

st.set_page_config(page_title="SentinelNet", layout="wide", page_icon=None)

st.markdown(
    f"""
    <style>
    .stApp {{ background-color: {BG}; color: {TEXT}; }}
    [data-testid="stSidebar"] {{ background-color: {PANEL}; border-right: 1px solid {BORDER}; }}
    .block-container {{ padding-top: 3.5rem; max-width: 1200px; }}
    h1, h2, h3, h4 {{ color: {TEXT} !important; font-weight: 600; }}
    .snet-panel {{
        background: {PANEL}; border: 1px solid {BORDER}; border-radius: 10px;
        padding: 16px 18px; margin-bottom: 14px;
    }}
    .snet-label {{ color: {TEXT_DIM}; font-size: 11px; letter-spacing: 0.02em; margin-bottom: 6px; }}
    .snet-big {{ font-family: 'JetBrains Mono','IBM Plex Mono',ui-monospace,monospace; font-size: 34px; }}
    .snet-stage-badge {{
        display: inline-block; padding: 6px 14px; border-radius: 6px;
        font-size: 13px; font-weight: 600; font-family: 'JetBrains Mono',monospace;
    }}
    .snet-flow-row {{ font-size: 12.5px; padding: 6px 0; border-bottom: 1px solid {GRID}; }}
    .snet-flow-ip {{ font-family: 'JetBrains Mono',monospace; color: {TEXT}; }}
    div[data-testid="stFileUploader"] {{ background: {PANEL}; border: 1px dashed {BORDER}; border-radius: 10px; padding: 6px; }}
    .stButton > button {{
        background: {TEAL}; color: #04211D; border: none; font-weight: 600;
    }}
    .stButton > button:hover {{ background: #4FE3D3; color: #04211D; }}
    hr {{ border-color: {BORDER}; }}
    footer, #MainMenu {{ visibility: hidden; }}
    </style>
    """,
    unsafe_allow_html=True,
)

PLOTLY_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color=TEXT_DIM, size=12),
    margin=dict(l=10, r=10, t=10, b=10),
)

# --------------------------------------------------------------------------
# Header
# --------------------------------------------------------------------------
st.markdown(
    f"<div style='font-size:20px;font-weight:700;'>SentinelNet</div>"
    f"<div style='color:{TEXT_DIM};font-size:12.5px;margin-top:-4px;'>"
    f"World-model network attack forecasting — SIH26153</div>",
    unsafe_allow_html=True,
)
st.markdown(f"<hr style='margin:14px 0;border-color:{BORDER};'>", unsafe_allow_html=True)

# --------------------------------------------------------------------------
# Input: upload or load a bundled demo session
# --------------------------------------------------------------------------
left, right = st.columns([2, 1])
with left:
    uploaded = st.file_uploader("Upload traffic capture", type=["pcap", "csv"], label_visibility="collapsed")
with right:
    use_demo = st.button("Load sample attack session", use_container_width=True)

result = None
source_label = None

if uploaded is not None:
    suffix = os.path.splitext(uploaded.name)[1] or ".csv"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(uploaded.getvalue())
        tmp_path = tmp.name
    with st.spinner("Running world-model inference..."):
        result = run_inference(tmp_path)
    source_label = uploaded.name
elif use_demo:
    with st.spinner("Running world-model inference..."):
        result = run_inference("demo_session_24.pcap")
    source_label = "demo_session_24.pcap (bundled sample)"

if result is None:
    st.markdown(
        f"""
        <div class="snet-panel" style="text-align:center;padding:48px 20px;">
            <div style="color:{TEXT_DIM};font-size:13.5px;">
            Upload a PCAP or flow-record CSV, or load the bundled sample, to run
            infiltration forecasting — offline, no external calls.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.stop()

st.markdown(f"<div style='color:{TEXT_DIM};font-size:11.5px;margin-bottom:10px;'>Source: {source_label}</div>", unsafe_allow_html=True)

# --------------------------------------------------------------------------
# Top row: predicted stage, peak probability, flagged-flow count
# --------------------------------------------------------------------------
timeline = result.get("infiltration_timeline", [])
predicted_stage = result.get("predicted_stage", "Unknown Stage")
stage_probs = result.get("stage_probs", {})
top_features = result.get("top_features", [])
flagged_flows = result.get("flagged_flows", [])
benchmark = result.get("benchmark", {})

peak_prob = max((w.get("probability", 0) for w in timeline), default=0)
stage_color = STAGE_COLOR.get(predicted_stage, TEXT_DIM)

m1, m2, m3 = st.columns(3)
with m1:
    st.markdown(
        f"""<div class="snet-panel">
            <div class="snet-label">PREDICTED ATT&CK STAGE</div>
            <div class="snet-stage-badge" style="background:{stage_color}22;color:{stage_color};border:1px solid {stage_color};">
                {predicted_stage}
            </div>
        </div>""",
        unsafe_allow_html=True,
    )
with m2:
    st.markdown(
        f"""<div class="snet-panel">
            <div class="snet-label">PEAK INFILTRATION PROBABILITY</div>
            <div class="snet-big" style="color:{stage_color};">{peak_prob*100:.0f}%</div>
        </div>""",
        unsafe_allow_html=True,
    )
with m3:
    st.markdown(
        f"""<div class="snet-panel">
            <div class="snet-label">FLAGGED FLOWS</div>
            <div class="snet-big" style="color:{TEXT};">{len(flagged_flows)}</div>
        </div>""",
        unsafe_allow_html=True,
    )

# --------------------------------------------------------------------------
# Timeline — forward simulation
# --------------------------------------------------------------------------
st.markdown("<div class='snet-label' style='margin:6px 0 4px;'>INFILTRATION PROBABILITY — FORWARD SIMULATION</div>", unsafe_allow_html=True)
if timeline:
    tl_df = pd.DataFrame(timeline)
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=tl_df["window_start"], y=tl_df["probability"],
        mode="lines+markers", line=dict(color=TEAL, width=2.5), marker=dict(size=6, color=TEAL),
        fill="tozeroy", fillcolor="rgba(52,214,196,0.08)",
    ))
    fig.add_hline(y=0.5, line_dash="dot", line_color=TEXT_DIM)
    fig.update_layout(**PLOTLY_LAYOUT, height=260, yaxis=dict(range=[0, 1], gridcolor=GRID),
                       xaxis=dict(gridcolor=GRID))
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
else:
    st.info("No timeline data returned.")

# --------------------------------------------------------------------------
# Stage probabilities + driving features
# --------------------------------------------------------------------------
c1, c2 = st.columns(2)
with c1:
    st.markdown("<div class='snet-label'>STAGE PROBABILITY BREAKDOWN</div>", unsafe_allow_html=True)
    if stage_probs:
        stages = list(stage_probs.keys())
        vals = list(stage_probs.values())
        colors = [STAGE_COLOR.get(s, TEXT_DIM) for s in stages]
        fig2 = go.Figure(go.Bar(x=vals, y=stages, orientation="h", marker_color=colors))
        fig2.update_layout(**PLOTLY_LAYOUT, height=220, xaxis=dict(range=[0, 1], gridcolor=GRID),
                            yaxis=dict(gridcolor=GRID))
        st.plotly_chart(fig2, use_container_width=True, config={"displayModeBar": False})
    else:
        st.caption("No stage probabilities returned.")

with c2:
    st.markdown("<div class='snet-label'>DRIVING FEATURES</div>", unsafe_allow_html=True)
    if top_features:
        feat_df = pd.DataFrame(top_features).sort_values("importance")
        fig3 = go.Figure(go.Bar(x=feat_df["importance"], y=feat_df["feature"], orientation="h",
                                 marker_color=TEAL))
        fig3.update_layout(**PLOTLY_LAYOUT, height=220, xaxis=dict(gridcolor=GRID), yaxis=dict(gridcolor=GRID))
        st.plotly_chart(fig3, use_container_width=True, config={"displayModeBar": False})
    else:
        st.caption("No feature attribution returned.")

# --------------------------------------------------------------------------
# Flagged flows
# --------------------------------------------------------------------------
st.markdown("<div class='snet-label' style='margin-top:6px;'>FLAGGED FLOWS</div>", unsafe_allow_html=True)
if flagged_flows:
    rows = ""
    for f in flagged_flows:
        risk = f.get("risk_score", 0)
        risk_color = CORAL if risk >= 0.7 else (AMBER if risk >= 0.4 else TEAL)
        rows += (
            f"<div class='snet-flow-row'>"
            f"<span class='snet-flow-ip'>{f.get('src_ip','?')} → {f.get('dst_ip','?')}</span>"
            f"&nbsp;&nbsp;<span style='color:{risk_color};font-weight:600;'>risk {risk:.2f}</span>"
            f"</div>"
        )
    st.markdown(f"<div class='snet-panel'>{rows}</div>", unsafe_allow_html=True)
else:
    st.caption("No flows flagged.")

# --------------------------------------------------------------------------
# Benchmark: world model vs. baseline
# --------------------------------------------------------------------------
st.markdown("<div class='snet-label' style='margin-top:6px;'>WORLD MODEL vs. LOGISTIC-REGRESSION BASELINE</div>", unsafe_allow_html=True)
if benchmark:
    wm = benchmark.get("world_model", {})
    bl = benchmark.get("logistic_baseline", {})
    metrics = [m for m in ["f1", "precision", "recall", "fpr"] if m in wm or m in bl]
    fig4 = go.Figure()
    fig4.add_trace(go.Bar(name="Baseline (logistic)", x=metrics, y=[bl.get(m, 0) for m in metrics], marker_color=TEXT_DIM))
    fig4.add_trace(go.Bar(name="World model", x=metrics, y=[wm.get(m, 0) for m in metrics], marker_color=TEAL))
    fig4.update_layout(**PLOTLY_LAYOUT, height=240, barmode="group",
                        legend=dict(orientation="h", y=1.15),
                        yaxis=dict(gridcolor=GRID))
    st.plotly_chart(fig4, use_container_width=True, config={"displayModeBar": False})
    st.caption(
        "Note: on this mock payload the baseline numbers are placeholders and don't yet reflect "
        "a real head-to-head — swap in backend/train_baseline.py's actual output once it's wired "
        "into engine.run_inference()."
    )
else:
    st.caption("No benchmark data returned.")

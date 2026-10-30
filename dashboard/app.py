"""
dashboard/app.py
Layer 6: real-time SOC threat monitoring dashboard (Streamlit), Grafana-style.

- Light and dark theme with a switch in the top bar (remembered in the URL: ?theme=dark).
- Gauge panels for current / rolling / peak throughput and an anomaly ring, stat panels,
  a live time-series panel with Isolation Forest anomaly markers, attack-type and
  target-port breakdowns, and a live incident feed.
- The live part is a fragment that re-queries the SQLite serving layer every 2 seconds.
- Options menu: Print, Clear cache and About (client.toolbarMode = "developer"); Deploy, Rerun,
  Record a screencast and Streamlit's own theme switcher are hidden with CSS.
"""
import base64
import math
import os
import sys
from datetime import datetime
from string import Template

import altair as alt
import pandas as pd
import streamlit as st

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.config import DASHBOARD_REFRESH_SECONDS, DATABASE_PATH, PORT_LABELS, MODEL_PATH, SLIDING_WINDOW_SIZE
from src.database import get_latest_metrics, get_recent_readings, get_attack_breakdown, reset_db


@st.cache_resource
def ensure_database():
    """Create the serving-layer tables if they do not exist yet (dashboard opened before any run)."""
    from src.database import init_db
    init_db()
    return True


ensure_database()

st.set_page_config(
    page_title="SOC Threat Watch | Real-Time Streaming Analytics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
    menu_items={
        "Get help": None,
        "Report a bug": None,
        "About": "**SOC Threat Watch** - real-time network threat detection.\n\n"
                 "Kafka → sliding-window processor → Isolation Forest → SQLite (WAL) → Streamlit.\n\n"
                 "Data Streaming and Analysis mini-project · ADITYA K · 23BTRCL127 · CSE AIML 'A'",
    },
)

# ── Themes ──────────────────────────────────────────────────────────────────
THEMES = {
    "dark": dict(
        bg="#111217", panel="#181b1f", panel2="#1f2228", border="#2c3036", border_strong="#3a3f47",
        text="#d8d9da", muted="#8e8e9a", title="#e6e7e8",
        blue="#5794f2", green="#73bf69", amber="#ff9830", red="#f2495c", purple="#b877d9",
        track="#2a2d33", grid="rgba(204,204,220,0.08)", shadow="none",
        chip="#22252b", hover="#22262c", code="#22252b",
    ),
    "light": dict(
        bg="#f4f5f5", panel="#ffffff", panel2="#f7f8fa", border="#dcdee1", border_strong="#c7cad0",
        text="#24292e", muted="#6e6e7a", title="#1f2328",
        blue="#3871dc", green="#1a7f4b", amber="#c46b00", red="#d4183d", purple="#8a4fbd",
        track="#e6e8eb", grid="rgba(36,41,46,0.08)", shadow="0 1px 2px rgba(24,26,27,0.06)",
        chip="#eef0f2", hover="#f2f4f6", code="#eef0f2",
    ),
}

ATTACK_COLORS_KEY = {"DDoS_Volumetric": "red", "SYN_Flood": "amber", "Port_Scan": "purple",
                     "Unclassified Anomaly": "muted"}
ATTACK_NAMES = {"DDoS_Volumetric": "DDoS Surge", "SYN_Flood": "SYN Flood", "Port_Scan": "Port Scan",
                "Unclassified Anomaly": "Anomaly"}
ATTACK_BANNER_NAMES = {"DDoS_Volumetric": "VOLUMETRIC DDoS SURGE", "SYN_Flood": "SYN FLOOD",
                       "Port_Scan": "PORT SCAN SWEEP"}
GAUGE_MAX_KBPS = 4000.0
THRESHOLDS_KBPS = (100.0, 500.0)      # green below 100 KB/s, amber below 500, red above

# ── Theme switch (remembered in the URL so a browser refresh keeps it) ─────────
if "dark_mode" not in st.session_state:
    st.session_state.dark_mode = st.query_params.get("theme", "light") == "dark"
with st.container(key="theme_toggle"):
    st.toggle(":material/dark_mode: Dark", key="dark_mode")
st.query_params["theme"] = "dark" if st.session_state.dark_mode else "light"
MODE = "dark" if st.session_state.dark_mode else "light"
T = THEMES[MODE]

CSS = Template("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

html, body, [data-testid="stApp"], [data-testid="stAppViewContainer"], [data-testid="stMain"],
[data-testid="stMainBlockContainer"], .main, .block-container {
    background: $bg !important; color: $text !important;
    font-family: 'Inter', system-ui, sans-serif !important;
    color-scheme: $mode !important;
}
[data-testid="stMainBlockContainer"], .block-container { padding-top: 4.2rem !important; padding-bottom: 2rem !important; max-width: 100% !important; }
p, span, label, li, div { color: inherit; }

/* header bar + title */
header[data-testid="stHeader"], .stAppHeader { background: $panel !important; border-bottom: 1px solid $border !important; }
header[data-testid="stHeader"]::before {
    content: "🛡️  SOC Threat Watch  ·  Real-Time Network Threat Detection";
    position: absolute; left: 1.4rem; top: 50%; transform: translateY(-50%);
    font-size: 1.02rem; font-weight: 700; letter-spacing: -0.01em; color: $title;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: calc(100% - 18rem);
    pointer-events: none;
}
header[data-testid="stHeader"] button, [data-testid="stToolbar"] button { background: transparent !important; color: $text !important; }
header[data-testid="stHeader"] svg, [data-testid="stToolbar"] svg { fill: $text !important; color: $text !important; }
[data-testid="stAppDeployButton"], div[data-testid="stDecoration"],
[data-testid="stMainMenuItem-recordScreencast"], [data-testid="stThemeSwitcher"],
[data-testid="stMainMenuItem-rerun"], [data-testid="stMainMenuItem-autoRerun"],
[data-testid="stMainMenuDivider"], [data-testid="stStatusWidget"] { display: none !important; }

/* options menu */
div[data-baseweb="popover"] > div, [data-testid="stMainMenuPopover"], [data-testid="stMainMenuList"] {
    background: $panel !important; border: 1px solid $border !important; border-radius: 6px !important;
}
[data-testid^="stMainMenuItem"] { color: $text !important; }
[data-testid^="stMainMenuItem"]:hover { background: $hover !important; }

/* theme switch sits in the header bar */
.st-key-theme_toggle { position: fixed !important; top: 0.62rem; right: 4.4rem; z-index: 1000100; width: auto !important; }
.st-key-theme_toggle label, .st-key-theme_toggle p, .st-key-theme_toggle span { color: $text !important; font-weight: 600 !important; }

/* native widgets */
[data-testid="stExpander"], [data-testid="stExpander"] details, [data-testid="stExpander"] summary,
[data-testid="stExpanderDetails"] { background: $panel !important; }
[data-testid="stExpander"] details { border: 1px solid $border !important; border-radius: 6px !important; overflow: hidden; }
[data-testid="stExpander"] summary { border-radius: 6px !important; }
[data-testid="stExpander"] summary, [data-testid="stExpander"] summary * { color: $title !important; }
[data-testid="stExpander"] summary p { font-family: 'Inter', system-ui, sans-serif !important; font-weight: 600 !important; }
[data-testid="stExpander"] summary:hover, [data-testid="stExpander"] summary:focus,
[data-testid="stExpander"] summary:focus-visible { background: $panel !important; outline: none !important; }
[data-testid="stExpander"] summary:hover * { color: $blue !important; }
.stButton button { background: $panel2 !important; color: $text !important; border: 1px solid $border_strong !important; border-radius: 4px !important; }
.stButton button:hover { border-color: $blue !important; color: $blue !important; }
[data-testid="stCaptionContainer"], [data-testid="stCaptionContainer"] * { color: $muted !important; }
[data-testid="stElementToolbar"] button[aria-label*="Show data" i] { display: none !important; }
code { background: $code !important; color: $text !important; }

/* panels */
.panel, .st-key-panel_ts, .st-key-panel_types, .st-key-panel_ports {
    background: $panel; border: 1px solid $border; border-radius: 6px; box-shadow: $shadow;
}
.st-key-panel_ts, .st-key-panel_types, .st-key-panel_ports { padding: 10px 14px 6px 14px !important; gap: 0.2rem !important; }
.panel { padding: 10px 14px; height: 100%; }
.ptitle { font-size: 0.86rem; font-weight: 600; color: $title; display: flex; align-items: center; justify-content: space-between; gap: 10px; margin-bottom: 4px; }
.psub { font-size: 0.74rem; color: $muted; font-weight: 500; }
.gauge-panel { height: 236px; display: flex; flex-direction: column; }
.gauge-panel img { flex: 1; min-height: 0; width: 100%; object-fit: contain; }
.stat-panel { height: 118px; display: flex; flex-direction: column; justify-content: space-between; }
.stat-value { font-size: 2.05rem; font-weight: 600; letter-spacing: -0.02em; line-height: 1.1; color: $title; }
.stat-value small { font-size: 0.95rem; color: $muted; font-weight: 500; margin-left: 4px; }

/* top strip */
.topbar { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px;
          padding: 8px 12px; background: $panel; border: 1px solid $border; border-radius: 6px; }
.crumb { font-size: 0.9rem; color: $muted; }
.crumb b { color: $title; font-weight: 600; }
.chips { display: flex; flex-wrap: wrap; gap: 6px; }
.chip { font-family: 'JetBrains Mono', monospace; font-size: 0.74rem; padding: 4px 9px; border-radius: 4px;
        background: $chip; border: 1px solid $border; color: $text; white-space: nowrap; }
.chip .dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; margin-right: 6px; vertical-align: 1px; }

/* alert banner */
.alert { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 12px 16px;
         border-radius: 6px; border: 1px solid; }
.alert .h { font-size: 1rem; font-weight: 700; letter-spacing: 0.01em; }
.alert .s { font-size: 0.8rem; color: $muted; margin-top: 2px; }
.badge { font-size: 0.7rem; font-weight: 700; letter-spacing: 0.06em; padding: 3px 9px; border-radius: 3px;
         border: 1px solid; white-space: nowrap; font-family: 'JetBrains Mono', monospace; }

/* incident table */
.inc { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
.inc th { text-align: left; font-weight: 600; color: $muted; font-size: 0.72rem; text-transform: uppercase;
          letter-spacing: 0.05em; padding: 7px 10px; border-bottom: 1px solid $border; }
.inc td { padding: 7px 10px; border-bottom: 1px solid $border; color: $text; }
.inc tr:hover td { background: $hover; }
.mono { font-family: 'JetBrains Mono', monospace; }
.empty { padding: 28px; text-align: center; color: $muted; font-size: 0.85rem; }

/* architecture cards */
.arch { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 8px; }
.arch div { background: $panel2; border: 1px solid $border; border-top: 3px solid $blue; border-radius: 5px; padding: 8px 10px; }
.arch b { display: block; font-size: 0.7rem; color: $muted; letter-spacing: 0.06em; }
.arch span { font-size: 0.84rem; color: $title; font-weight: 600; }
.arch i { display: block; font-style: normal; font-size: 0.72rem; color: $muted; margin-top: 2px; }
@media (max-width: 900px) { .arch { grid-template-columns: repeat(2, minmax(0, 1fr)); } }

/* print / save as PDF */
@media print {
    @page { size: A4 landscape; margin: 10mm; }
    * { -webkit-print-color-adjust: exact !important; print-color-adjust: exact !important; }
    html, body, [data-testid="stApp"], [data-testid="stAppViewContainer"], [data-testid="stMain"],
    [data-testid="stMainBlockContainer"], .main, .block-container {
        height: auto !important; min-height: 0 !important; overflow: visible !important; position: static !important; }
    [data-testid="stMainBlockContainer"], .block-container { padding: 0 !important; }
    header[data-testid="stHeader"] { position: static !important; height: 2.4rem !important; }
    header[data-testid="stHeader"]::before { left: 0; }
    [data-testid="stToolbar"], [data-testid="stExpander"], [data-testid="stElementToolbar"],
    [data-testid="stStatusWidget"], .st-key-theme_toggle { display: none !important; }
    .panel, .alert, .topbar, .st-key-panel_ts, .st-key-panel_types, .st-key-panel_ports,
    [data-testid="stHorizontalBlock"] { break-inside: avoid !important; page-break-inside: avoid !important; }
}
</style>
""")
st.html(CSS.substitute(mode=MODE, **T))


# ── Helpers ─────────────────────────────────────────────────────────────────
@st.cache_resource
def load_model_metrics():
    """Offline metrics stored in the model artifact (read once, not hardcoded)."""
    try:
        import joblib
        return joblib.load(MODEL_PATH).get("metrics", {})
    except Exception:
        return {}


def level_color(value, thresholds=THRESHOLDS_KBPS):
    if value < thresholds[0]:
        return T["green"]
    if value < thresholds[1]:
        return T["amber"]
    return T["red"]


def polar(cx, cy, r, deg):
    a = math.radians(deg)
    return cx + r * math.cos(a), cy + r * math.sin(a)


def arc(cx, cy, r, a0, a1):
    x0, y0 = polar(cx, cy, r, a0)
    x1, y1 = polar(cx, cy, r, a1)
    large = 1 if (a1 - a0) > 180 else 0
    return f"M {x0:.2f} {y0:.2f} A {r} {r} 0 {large} 1 {x1:.2f} {y1:.2f}"


def log_fraction(value, vmax=GAUGE_MAX_KBPS):
    return max(0.0, min(1.0, math.log10(1 + max(value, 0)) / math.log10(1 + vmax)))


def fmt_kbps(v):
    return f"{v:,.0f}" if v >= 100 else f"{v:,.1f}"


def gauge_panel(title, value, unit, sub):
    """Grafana-style 240° arc gauge (log scale so 5 KB/s and 3,000 KB/s both read clearly)."""
    cx, cy, r, a0, span = 110, 92, 70, 150, 240
    frac = log_fraction(value)
    color = level_color(value)
    value_arc = f'<path d="{arc(cx, cy, r, a0, a0 + span * frac)}" stroke="{color}" stroke-width="14" fill="none" stroke-linecap="round"/>' if frac > 0.004 else ""
    lx, ly = polar(cx, cy, r, a0)
    rx, ry = polar(cx, cy, r, a0 + span)
    svg = f"""
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 220 165" preserveAspectRatio="xMidYMid meet">
      <path d="{arc(cx, cy, r, a0, a0 + span)}" stroke="{T['track']}" stroke-width="14" fill="none" stroke-linecap="round"/>
      {value_arc}
      <text x="{cx}" y="{cy + 6}" text-anchor="middle" font-size="31" font-weight="600" fill="{T['title']}" font-family="Inter, sans-serif">{fmt_kbps(value)}</text>
      <text x="{cx}" y="{cy + 26}" text-anchor="middle" font-size="11" fill="{T['muted']}" font-family="Inter, sans-serif">{unit}</text>
      <text x="{lx:.0f}" y="{ly + 20:.0f}" text-anchor="middle" font-size="9.5" fill="{T['muted']}" font-family="JetBrains Mono, monospace">0</text>
      <text x="{rx:.0f}" y="{ry + 20:.0f}" text-anchor="middle" font-size="9.5" fill="{T['muted']}" font-family="JetBrains Mono, monospace">4k</text>
    </svg>"""
    return f'<div class="panel gauge-panel"><div class="ptitle">{title}<span class="psub">{sub}</span></div>{svg_img(svg)}</div>'


def segment_gauge_panel(title, value, unit, sub, segments=34):
    """Bar-segment gauge, like the 'Peak Power' panel in Grafana."""
    cx, cy, r, a0, span = 110, 96, 68, 150, 240
    filled = round(log_fraction(value) * segments)
    color = level_color(value)
    step = span / segments
    parts = []
    for i in range(segments):
        s0 = a0 + i * step + 1.1
        s1 = a0 + (i + 1) * step - 1.1
        parts.append(f'<path d="{arc(cx, cy, r, s0, s1)}" stroke="{color if i < filled else T["track"]}" stroke-width="20" fill="none"/>')
    svg = f"""
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 220 165" preserveAspectRatio="xMidYMid meet">
      {''.join(parts)}
      <text x="{cx}" y="{cy + 8}" text-anchor="middle" font-size="31" font-weight="600" fill="{T['title']}" font-family="Inter, sans-serif">{fmt_kbps(value)}</text>
      <text x="{cx}" y="{cy + 28}" text-anchor="middle" font-size="11" fill="{T['muted']}" font-family="Inter, sans-serif">{unit}</text>
    </svg>"""
    return f'<div class="panel gauge-panel"><div class="ptitle">{title}<span class="psub">{sub}</span></div>{svg_img(svg)}</div>'


def ring_panel(title, total, in_window, window):
    """Anomaly ring: the arc shows how much of the sliding window is anomalous."""
    cx, cy, r = 110, 80, 58
    frac = max(0.0, min(1.0, in_window / max(window, 1)))
    circ = 2 * math.pi * r
    color = T["red"] if in_window >= 5 else (T["amber"] if in_window >= 2 else T["green"])
    ring_arc = (f'<circle cx="{cx}" cy="{cy}" r="{r}" stroke="{color}" stroke-width="11" fill="none" '
                f'stroke-linecap="round" stroke-dasharray="{frac * circ:.1f} {circ:.1f}" transform="rotate(-90 {cx} {cy})"/>'
                if frac > 0 else "")
    svg = f"""
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 220 165" preserveAspectRatio="xMidYMid meet">
      <defs>
        <radialGradient id="ringGlow" cx="50%" cy="50%" r="50%">
          <stop offset="0%" stop-color="{color}" stop-opacity="{0.28 if in_window else 0.06}"/>
          <stop offset="100%" stop-color="{color}" stop-opacity="0"/>
        </radialGradient>
      </defs>
      <circle cx="{cx}" cy="{cy}" r="{r - 9}" fill="url(#ringGlow)"/>
      <circle cx="{cx}" cy="{cy}" r="{r}" stroke="{T['track']}" stroke-width="11" fill="none"/>
      {ring_arc}
      <text x="{cx}" y="{cy + 11}" text-anchor="middle" font-size="32" font-weight="600" fill="{T['title']}" font-family="Inter, sans-serif">{total:,}</text>
      <text x="{cx}" y="{cy + r + 24}" text-anchor="middle" font-size="10.5" fill="{T['muted']}" font-family="Inter, sans-serif">{in_window} of the last {window} flows</text>
    </svg>"""
    return f'<div class="panel gauge-panel"><div class="ptitle">{title}<span class="psub">sliding window</span></div>{svg_img(svg)}</div>'


def svg_img(svg):
    """st.html strips inline <svg>, so gauges are embedded as SVG images."""
    data = base64.b64encode(svg.strip().encode("utf-8")).decode("ascii")
    return f'<img alt="" src="data:image/svg+xml;base64,{data}"/>'


def stat_panel(title, value, sub, accent=None, tint=None):
    style = f' style="background:{tint};border-color:{accent}55;"' if tint else ""
    color = f' style="color:{accent};"' if accent else ""
    return (f'<div class="panel stat-panel"{style}><div class="ptitle">{title}</div>'
            f'<div class="stat-value"{color}>{value}</div><div class="psub">{sub}</div></div>')


def badge(text, color):
    return f'<span class="badge" style="color:{color};border-color:{color}66;background:{color}1a;">{text}</span>'


def chart_config(chart):
    return (chart.configure(background="transparent", padding={"left": 22, "right": 8, "top": 6, "bottom": 4})
            .configure_view(stroke=None)
            .configure_axis(gridColor=T["grid"], domainColor=T["border"], tickColor=T["border"],
                            labelColor=T["muted"], titleColor=T["muted"], labelFont="Segoe UI, Arial, sans-serif", labelLimit=220,
                            titleFont="Segoe UI, Arial, sans-serif", labelFontSize=10.5, titleFontSize=11, titleFontWeight=500)
            .configure_legend(disable=True))


# ── Static part: pipeline drawer with reset ──────────────────────────────────
with st.expander("Pipeline architecture & controls", icon=":material/account_tree:", expanded=False):
    st.html("""
    <div class="arch">
      <div><b>LAYER 1</b><span>Data source</span><i>CSV replay, 5 events/s</i></div>
      <div><b>LAYER 2</b><span>Apache Kafka</span><i>topic network-traffic</i></div>
      <div><b>LAYER 3</b><span>Stream processor</span><i>30-event sliding window</i></div>
      <div><b>LAYER 4</b><span>Isolation Forest</span><i>log-scaled, batch scoring</i></div>
      <div><b>LAYER 5</b><span>SQLite (WAL)</span><i>serving layer</i></div>
      <div><b>LAYER 6</b><span>Streamlit</span><i>auto-refresh every 2 s</i></div>
    </div>""")
    c_btn, c_txt = st.columns([1, 4], vertical_alignment="center")
    with c_btn:
        if st.button("Reset stream & database", icon=":material/restart_alt:", width="stretch"):
            reset_db()
            st.rerun()
    with c_txt:
        mm = load_model_metrics()
        full = mm.get("full", {})
        if "vec_latency_us" in mm:
            st.caption(f"Model: ~{mm['vec_latency_us']:.1f} µs per flow (batch scoring) · recall {full.get('recall', 0):.2f} · "
                       f"false alarms {full.get('false_alarm_rate', 0) * 100:.1f}% on the 8,000-flow dataset · "
                       f"serving layer `{os.path.basename(DATABASE_PATH)}` (WAL) · refresh {DASHBOARD_REFRESH_SECONDS}s")


# ── Live part: re-queried every 2 seconds ────────────────────────────────────
@st.fragment(run_every=f"{DASHBOARD_REFRESH_SECONDS}s")
def live_dashboard():
    mx = get_latest_metrics()
    df = get_recent_readings(limit=120)

    n_ev = int(mx.get("total_events", 0) or 0)
    n_anom = int(mx.get("total_anomalies", 0) or 0)
    kbps = float(mx.get("current_kbps", 0.0) or 0.0)
    rolling = float(mx.get("rolling_avg_kbps", 0.0) or 0.0)
    peak = float(mx.get("peak_kbps", 0.0) or 0.0)
    rate = float(mx.get("recent_anomaly_rate", 0.0) or 0.0)
    threat = mx.get("threat_level", "NORMAL") or "NORMAL"
    ts = mx.get("last_updated") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    tmode = str(mx.get("transport_mode", "local") or "local")
    in_window = round(rate * SLIDING_WINDOW_SIZE / 100.0) if n_ev else 0

    # top strip
    live = n_ev > 0
    status = (f'<span class="chip"><span class="dot" style="background:{T["green"]};"></span>LIVE</span>' if live
              else f'<span class="chip"><span class="dot" style="background:{T["muted"]};"></span>STANDBY</span>')
    transport = ('<span class="chip">Apache Kafka · network-traffic</span>' if tmode == "kafka"
                 else '<span class="chip">Local fallback channel</span>')
    st.html(f"""
    <div class="topbar">
      <div class="crumb">Dashboards › <b>SOC Threat Watch</b></div>
      <div class="chips">{status}{transport}<span class="chip">last scored {ts}</span>
        <span class="chip">⟳ {DASHBOARD_REFRESH_SECONDS}s</span></div>
    </div>""")

    # alert banner
    flagged = df[df["is_anomaly"] == 1] if not df.empty else df
    recent_types = flagged.tail(30)["attack_type"] if not df.empty else pd.Series(dtype=str)
    top_type = recent_types.mode().iloc[0] if not recent_types.empty else ""
    if threat == "CRITICAL ATTACK":
        c, head = T["red"], f"CRITICAL ATTACK — {ATTACK_BANNER_NAMES.get(top_type, 'ANOMALOUS TRAFFIC')} ACTIVE"
        tag = "CRITICAL"
    elif threat == "SUSPICIOUS":
        c, head, tag = T["amber"], "ELEVATED ANOMALOUS ACTIVITY", "ELEVATED"
    else:
        c, head, tag = T["green"], "ALL TRAFFIC WITHIN NORMAL BASELINE", "HEALTHY"
    st.html(f"""
    <div class="alert" style="border-color:{c}66;background:{c}14;">
      <div><div class="h" style="color:{c};">{head}</div>
        <div class="s">Isolation Forest scoring every flow · {in_window} of the last {SLIDING_WINDOW_SIZE} flows anomalous ({rate:.0f}%)</div></div>
      {badge(tag, c)}
    </div>""")

    # gauges
    g1, g2, g3, g4 = st.columns(4)
    g1.html(gauge_panel("Current ingress", kbps, "KB/s", f"{kbps - rolling:+,.1f} vs avg"))
    g2.html(gauge_panel("30-event rolling average", rolling, "KB/s", "sliding window"))
    g3.html(segment_gauge_panel("Peak throughput", peak, "KB/s", "this session"))
    g4.html(ring_panel("Anomaly count", n_anom, in_window, SLIDING_WINDOW_SIZE))

    # stat panels
    s1, s2, s3, s4 = st.columns(4)
    ratio = (n_anom / n_ev * 100) if n_ev else 0.0
    s1.html(stat_panel("Events processed", f"{n_ev:,}", "flows scored since reset"))
    s2.html(stat_panel("Detection ratio", f"{ratio:.2f}<small>%</small>", "anomalies / events"))
    s3.html(stat_panel("Threat level", threat.title(), "from the 30-flow window", accent=c, tint=f"{c}12"))
    s4.html(stat_panel("Transport", "Kafka" if tmode == "kafka" else "Fallback",
                       "topic network-traffic" if tmode == "kafka" else "start Docker for Kafka",
                       accent=T["blue"] if tmode == "kafka" else T["amber"]))

    # time series
    with st.container(key="panel_ts"):
        legend = (f'<span class="psub"><span style="color:{T["blue"]};">━</span> throughput &nbsp; '
                  f'<span style="color:{T["amber"]};">┅</span> 30-event average &nbsp; '
                  f'<span style="color:{T["red"]};">●</span> anomaly</span>')
        st.html(f'<div class="ptitle">Live ingress throughput &amp; ML anomalies {legend}</div>')
        if df.empty:
            st.html('<div class="empty">Waiting for the stream - start it with run.bat (option 1).</div>')
        else:
            pf = df.copy()
            pf["seq"] = range(1, len(pf) + 1)
            pf["time"] = pf["timestamp"].astype(str).str.split(" ").str[-1]
            pf["Service"] = pf["dst_port"].map(lambda p: PORT_LABELS.get(p, f"Port {p}"))
            tips = [alt.Tooltip("time:N", title="Time"), alt.Tooltip("src_ip:N", title="Source"),
                    alt.Tooltip("Service:N"), alt.Tooltip("throughput_kbps:Q", title="KB/s", format=",.1f"),
                    alt.Tooltip("attack_type:N", title="Class"), alt.Tooltip("anomaly_score:Q", title="Score", format=".3f")]
            base = alt.Chart(pf).encode(x=alt.X("seq:Q", title=None, axis=alt.Axis(labels=False, ticks=False)))
            area = base.mark_area(color=T["blue"], opacity=0.12, interpolate="monotone").encode(y="throughput_kbps:Q")
            line = base.mark_line(color=T["blue"], strokeWidth=1.8, interpolate="monotone").encode(
                y=alt.Y("throughput_kbps:Q", title="KB/s"), tooltip=tips)
            avg = base.mark_line(color=T["amber"], strokeWidth=1.8, strokeDash=[5, 4]).encode(y="rolling_avg_kbps:Q")
            dots = alt.Chart(pf[pf["is_anomaly"] == 1]).mark_circle(size=58, color=T["red"], opacity=0.95,
                                                                   stroke=T["panel"], strokeWidth=1).encode(
                x="seq:Q", y="throughput_kbps:Q", tooltip=tips)
            st.altair_chart(chart_config((area + line + avg + dots).properties(height=270)),
                            width="stretch", theme=None)

    # breakdowns
    b1, b2 = st.columns(2)
    with b1, st.container(key="panel_types"):
        st.html('<div class="ptitle">Anomalies by attack type<span class="psub">since reset</span></div>')
        br = get_attack_breakdown()
        if br.empty:
            st.html('<div class="empty">No anomalies yet.</div>')
        else:
            br["Class"] = br["attack_type"].map(lambda a: ATTACK_NAMES.get(a, a))
            dom = [ATTACK_NAMES[k] for k in ATTACK_NAMES]
            rng = [T[ATTACK_COLORS_KEY[k]] for k in ATTACK_NAMES]
            bar = alt.Chart(br).mark_bar(cornerRadiusEnd=3, height=22).encode(
                x=alt.X("count:Q", title="flows", axis=alt.Axis(format="d", tickMinStep=1)),
                y=alt.Y("Class:N", sort="-x", title=None),
                color=alt.Color("Class:N", scale=alt.Scale(domain=dom, range=rng)),
                tooltip=["Class:N", alt.Tooltip("count:Q", title="Flows")])
            st.altair_chart(chart_config(bar.properties(height=190)), width="stretch", theme=None)
    with b2, st.container(key="panel_ports"):
        st.html('<div class="ptitle">Target port exposure<span class="psub">last 120 flows</span></div>')
        if df.empty:
            st.html('<div class="empty">No traffic yet.</div>')
        else:
            pc = df["dst_port"].map(lambda p: PORT_LABELS.get(p, "Other ports")).value_counts().reset_index()
            pc.columns = ["Service", "Flows"]
            bar = alt.Chart(pc).mark_bar(color=T["blue"], cornerRadiusEnd=3, height=22).encode(
                x=alt.X("Flows:Q", title="flows", axis=alt.Axis(format="d", tickMinStep=1)),
                y=alt.Y("Service:N", sort="-x", title=None), tooltip=["Service:N", "Flows:Q"])
            st.altair_chart(chart_config(bar.properties(height=190)), width="stretch", theme=None)

    # incident feed
    rows = ""
    for _, r in flagged.tail(8).iloc[::-1].iterrows() if not df.empty else []:
        at = str(r.get("attack_type", "Unclassified Anomaly"))
        col = T[ATTACK_COLORS_KEY.get(at, "muted")]
        svc = PORT_LABELS.get(int(r["dst_port"]), f"Port {int(r['dst_port'])}")
        rows += (f'<tr><td class="mono">{str(r["timestamp"]).split(" ")[-1]}</td><td class="mono">{r["src_ip"]}</td>'
                 f'<td>{svc}</td><td class="mono">{float(r["throughput_kbps"]):,.1f} KB/s</td>'
                 f'<td>{badge(ATTACK_NAMES.get(at, at), col)}</td><td class="mono">{float(r["anomaly_score"]):.3f}</td></tr>')
    table = (f'<table class="inc"><thead><tr><th>Time</th><th>Source IP</th><th>Service</th><th>Rate</th>'
             f'<th>Classification</th><th>Score</th></tr></thead><tbody>{rows}</tbody></table>' if rows
             else '<div class="empty">No incidents in the recent stream.</div>')
    st.html(f'<div class="panel"><div class="ptitle">Live security incident feed<span class="psub">latest 8 flagged flows</span></div>{table}</div>')


live_dashboard()

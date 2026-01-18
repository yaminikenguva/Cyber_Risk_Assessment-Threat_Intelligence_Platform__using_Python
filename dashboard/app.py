# Streamlit main
import sys
from pathlib import Path
from datetime import datetime
import ipaddress
import requests
import pandas as pd
import streamlit as st


# ================================
# Session State Initialization
# ================================
if "scan_filter" not in st.session_state:
    st.session_state.scan_filter = "All"

if "scan_results" not in st.session_state:
    st.session_state.scan_results = []

if "selected_host" not in st.session_state:
    st.session_state.selected_host = None

if "theme_mode" not in st.session_state:
    st.session_state.theme_mode = "Dark"


# =================================================
# PROJECT PATH SETUP
# =================================================
project_root = Path(__file__).resolve().parents[1]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

# =================================================
# INTERNAL IMPORTS
# =================================================
from dashboard.data_loader import load_scan_metadata
from dashboard._pages import (
    overview,
    nmap,
    vulnerability,
    threat_summary,
    threat_intel,
    risk_analysis,
    ai_analyst,
    reports,
    alerts,
)

API = "http://127.0.0.1:8000"

# =================================================
# PAGE CONFIG
# =================================================
st.set_page_config(
    page_title="Cyber Risk Assessment Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# =================================================
# SESSION STATE
# =================================================
# st.session_state.setdefault("theme_mode", "Dark")
# st.session_state.setdefault("scan_filter", "All")

# =================================================
# BACKEND HEALTH CHECK
# =================================================
@st.cache_data(ttl=30)
def backend_health():
    try:
        return requests.get(f"{API}/scan/metadata", timeout=3).ok
    except Exception:
        return False

if not backend_health():
    st.sidebar.error("🚫 Backend API not reachable")

# =================================================
# THEME
# =================================================
with st.sidebar:
    st.markdown("## 🌗 Theme")
    theme_mode = st.radio(
        "Mode",
        ["🌙 Dark", "☀️ Light"],
        index=0
    )

# st.session_state.theme_mode = theme_mode
# is_dark = "Dark" in theme_mode

# st.session_state.plotly_template = (
#     "plotly_dark" if is_dark else "plotly_white"
# )

st.session_state.theme_mode = theme_mode
is_dark = "Dark" in theme_mode

if is_dark:
    bg_color = "#000000"
    panel_bg = "#0f0f0f"
    card_bg = "#121212"
    text_color = "#e0e0e0"
    accent_color = "#00f2ff"
    chart_theme = "plotly_dark"
    secondary_text = "#a0a0a0"
else:
    bg_color = "#f0f2f6"
    panel_bg = "#fafafa"
    card_bg = "#ffffff"
    text_color = "#1f1f1f"
    accent_color = "#0068c9"
    chart_theme = "plotly_white"
    secondary_text = "#555555"

st.session_state.plotly_template = chart_theme

st.markdown(f"""
<style>
.stApp {{
    background-color: {bg_color};
    color: {text_color};
}}
section[data-testid="stSidebar"] {{
    background-color: {panel_bg};
    border-right: 1px solid {'#333' if 'Dark' in theme_mode else '#ddd'};
}}
div.stContainer {{
    background-color: {card_bg};
    border-radius: 12px;
    padding: 18px;
    border: 1px solid {'#333' if 'Dark' in theme_mode else '#ddd'};
}}
h1, h2, h3 {{
    color: {accent_color} !important;
}}
p, span, label {{
    color: {text_color};
}}



div[data-testid="stMetricValue"] {{
    color: {accent_color} !important;
    font-size: 32px !important;
    font-weight: 700 !important;
}}
div[data-testid="stMetricLabel"] {{
    color: {secondary_text} !important;
}}
button[data-baseweb="tab"] div p {{
    color: {secondary_text} !important;
    font-size: 14px;
    font-weight: 600;
}}
button[data-baseweb="tab"][aria-selected="true"] div p {{
    color: {accent_color} !important;
}}
button[data-baseweb="tab"][aria-selected="true"] {{
    border-bottom: 3px solid {accent_color} !important;
}}
div.stButton > button {{
    background-color: {card_bg};
    color: {accent_color};
    border: 1px solid {accent_color};
    border-radius: 8px;
    font-weight: bold;
}}
div.stButton > button:hover {{
    background-color: {accent_color};
    color: {'#000' if 'Dark' in theme_mode else '#fff'};
}}
</style>
""", unsafe_allow_html=True)



# =================================================
# SIDEBAR — SCAN INPUTS
# =================================================
st.sidebar.markdown("## 🧪 Scan Inputs")

target_input = st.sidebar.text_area(
    "Targets (IP / Host / CIDR)",
    placeholder="192.168.1.1\nexample.com\n10.0.0.0/24"
)

ports_input = st.sidebar.text_input(
    "Ports (optional)",
    placeholder="22,80,443 or 1-1000"
)

uploaded_file = st.sidebar.file_uploader(
    "Upload target file (.txt)",
    type=["txt"]
)

scan_profile = st.sidebar.selectbox(
    "Scan Profile",
    ["Quick", "Normal", "High"],
    index=1
)

# ---------------- Build Target List ----------------
targets = []

if target_input:
    targets.extend([t.strip() for t in target_input.splitlines() if t.strip()])

if uploaded_file:
    file_targets = uploaded_file.read().decode("utf-8").splitlines()
    targets.extend([t.strip() for t in file_targets if t.strip()])

# =================================================
# RUN SCAN
# =================================================
if st.sidebar.button("🚀 Run Scan"):
    if not targets and not ports_input:
        st.sidebar.error("Provide at least a target or ports")
    else:
        payload = {
            "targets": targets,
            "ports": ports_input or None,
            "scan_profile": scan_profile,
        }

        try:
            r = requests.post(
                f"{API}/scan/start",
                json=payload,
                timeout=120
            )

            if r.ok:
                st.sidebar.success("✅ Scan started")
                st.session_state.scan_refresh_key =st.session_state.get("scan_refresh_key",0)+1
                st.rerun()

            else:
                st.sidebar.error(f"❌ Scan failed ({r.status_code})")

        except Exception as e:
            st.sidebar.error(f"Backend error: {e}")

# Add this to the bottom of your Sidebar section in app.py
# if st.sidebar.button("🔄 Reset All Tabs"):
#     # Clear all keys in session state
#     for key in list(st.session_state.keys()):
#         del st.session_state[key]
    
#     # Force a rerun to re-initialize defaults
#     st.rerun()

# In app.py sidebar
if st.sidebar.button("🔄 Reset All Tabs"):
    # Clear all session state to reset all tabs, inputs, and values
    st.session_state.clear()
    
    st.sidebar.success("Dashboard Reset!")
    st.rerun()

# =================================================
# HEADER
# =================================================
meta = load_scan_metadata()

st.markdown("## 🛡 Cyber Risk Assessment Dashboard")
st.markdown(
    f"**Scan Profile:** `{meta.get('scan_type', 'Nmap')}` "
    f"&nbsp;&nbsp; 🕒 {datetime.now().strftime('%H:%M:%S')}"
)

# =================================================
# TABS
# =================================================
tabs = st.tabs([
    "🏠 Overview",
    "🛰️ Nmap",
    "🐞 Vulnerability Insights",
    "⚠️ Threat Summary",
    "🌍 Threat Intel",
    "📊 Risk Analysis",
    "🚨 Alerts",
    "🧠 AI Analyst",
    "📜 Reports",
])

with tabs[0]:
    overview.run()

with tabs[1]:
    nmap.run()

with tabs[2]:
    vulnerability.run()

with tabs[3]:
    threat_summary.run()

with tabs[4]:
    threat_intel.run()

with tabs[5]:
    risk_analysis.run()

with tabs[6]:
    alerts.run()

with tabs[7]:
    ai_analyst.run()

with tabs[8]:
    reports.run()

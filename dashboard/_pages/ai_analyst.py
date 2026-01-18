import streamlit as st
import pandas as pd
import requests
import json
from dashboard.data_loader import load

API_BASE = "http://127.0.0.1:8000"


def run(filters=None):
    """
    AI Analyst Tab
    - Explains scan results
    - Interprets risk & vulnerabilities
    - Uses backend Layer-3 AI output when available
    """
    # filters = filters or {}

    st.markdown(
        "<div class='section-title'>🧠 AI Analyst</div>",
        unsafe_allow_html=True
    )

    # ---------------- Load Data ----------------
    nmap_df = load("/nmap/results")
    risk = load("/risk/summary")
    threat_intel = load("/threat/intel")

    if threat_intel is None:
        threat_intel = pd.DataFrame()

    if nmap_df is None or getattr(nmap_df, "empty", True):
        st.info("Run a scan to enable AI analysis.")
        return

    # ---------------- Normalize ----------------
    nmap_df = nmap_df.copy()
    nmap_df.columns = [c.lower() for c in nmap_df.columns]

    # ---------------- Prompt Input ----------------
    user_prompt = st.text_area(
        "Ask the AI Analyst",
        value="Summarize key risks and recommend next actions.",
        height=80,
    )

    # ---------------- Quick KPIs ----------------
    c1, c2, c3 = st.columns(3)

    total_hosts = nmap_df["host"].nunique() if "host" in nmap_df.columns else 0
    open_ports = (
        (nmap_df["state"] == "open").sum()
        if "state" in nmap_df.columns
        else len(nmap_df)
    )

    avg_risk = risk.get("avg_risk", 0) if isinstance(risk, dict) else 0

    c1.metric("Hosts", total_hosts)
    c2.metric("Open Ports", open_ports)
    c3.metric("Avg Risk", avg_risk)

    st.markdown("---")

    # ---------------- Heuristic AI Reasoning ----------------
    insights = []

    insights.append(
        f"Scanned **{total_hosts} host(s)** with **{open_ports} exposed service(s)**."
    )

    if "service" in nmap_df.columns:
        top_services = (
            nmap_df["service"]
            .value_counts()
            .head(5)
            .to_dict()
        )
        if top_services:
            svc_line = ", ".join(
                [f"{k} ({v})" for k, v in top_services.items()]
            )
            insights.append(f"Most exposed services: {svc_line}.")

    if isinstance(risk, dict):
        critical = risk.get("critical", 0)
        high = risk.get("high", 0)
        if critical or high:
            insights.append(
                f"Detected **{critical} critical** and **{high} high-risk** assets."
            )

    if not threat_intel.empty:
        insights.append(
            "Threat intelligence sources indicate active exploitation patterns."
        )

    insights.append(
        "Recommended actions: restrict unnecessary ports, "
        "prioritize patching critical services, "
        "and continuously monitor high-risk hosts."
    )

    with st.expander("🧠 AI-Generated Summary", expanded=True):
        st.write("\n".join(insights))

    # ---------------- Optional LLM Reasoning ----------------
    st.markdown("### 🤖 Advanced AI Reasoning")

    if st.button("Run AI Reasoning"):
        try:
            payload = {
                "prompt": user_prompt,
                "context": {
                    "nmap": nmap_df.head(50).to_dict(),
                    "risk": risk,
                    "threat_intel": threat_intel[:20] if isinstance(threat_intel, list) else [],
                },
            }

            r = requests.post(
                f"{API_BASE}/ai/reason",
                json=payload,
                timeout=30,
            )

            if r.ok:
                st.success("AI analysis complete")
                st.write(r.json().get("analysis", ""))
            else:
                st.warning("AI service unavailable")

        except Exception as e:
            st.error(f"AI error: {e}")

    st.markdown("---")

    # ---------------- Raw Data ----------------
    st.markdown("### 📄 Raw Scan Data")
    st.dataframe(nmap_df, width="stretch")

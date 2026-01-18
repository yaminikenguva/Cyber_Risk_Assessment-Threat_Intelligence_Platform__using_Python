import streamlit as st
import plotly.express as px
import pandas as pd
from textwrap import dedent
from datetime import datetime

from dashboard.data_loader import load


# =================================================
# FALLBACK DATA (UI CONTINUITY)
# =================================================
def _sample_data():
    nmap = pd.DataFrame({
        "host": [f"192.168.1.{i}" for i in range(1, 21)],
        "vulnerabilities": [i % 4 for i in range(1, 21)],
    })

    risk = {
        "critical": 3,
        "high": 6,
        "medium": 8,
        "low": 3,
        "total_assets": 20,
        "overall_score": 65
    }

    hosts = pd.DataFrame([
        {"Host": "192.168.1.1", "Total Vulns": 12, "Risk Score": 91, "Risk Level": "Critical", "Threat Score": 88, "Services": "HTTP, SSH"},
        {"Host": "192.168.1.2", "Total Vulns": 7, "Risk Score": 63, "Risk Level": "High", "Threat Score": 70, "Services": "HTTPS"},
        {"Host": "192.168.1.3", "Total Vulns": 4, "Risk Score": 48, "Risk Level": "Medium", "Threat Score": 55, "Services": "SMB"},
        {"Host": "192.168.1.4", "Total Vulns": 1, "Risk Score": 22, "Risk Level": "Low", "Threat Score": 30, "Services": "RDP"},
    ])

    return nmap, risk, hosts


# =================================================
# PAGE ENTRYPOINT
# =================================================
def run(filters=None):
    filters = filters or {}

    st.markdown(
        "<div class='section-title'>⚠️ Threat Summary</div>",
        unsafe_allow_html=True
    )

    st.caption(
        "Aggregated threat posture derived from Nmap scan results "
        "and Layer-3 risk scoring."
    )

    # =================================================
    # LOAD & NORMALIZE DATA
    # =================================================
    nmap_raw = load("/nmap/results")
    risk_raw = load("/risk/summary")

    # 1. Normalize Nmap DataFrame
    if isinstance(nmap_raw, pd.DataFrame):
        nmap_df = nmap_raw.copy()
    elif isinstance(nmap_raw, list):
        nmap_df = pd.DataFrame(nmap_raw)
    else:
        nmap_df = pd.DataFrame()

    # 2. Normalize Risk Dictionary
    if isinstance(risk_raw, dict) and risk_raw:
        risk_data = risk_raw.copy()
    else:
        risk_data = {}

    # =================================================
    # 3. Determine if Fallback is needed (RESET AWARE)
    # =================================================
    refresh_key = st.session_state.get("scan_refresh_key", 0)

    # 3. Determine if Fallback is needed
    if nmap_df.empty or not risk_data:
        # nmap_df, risk_data, hosts_table = _sample_data()
        # st.info("Showing sample threat summary data (Backend database table 'scans' may be empty).")
        if refresh_key == 0:
            # RESET STATE: Force all metrics to zero and empty the UI
            nmap_df = pd.DataFrame(columns=["host", "vulnerabilities"])
            risk_data = {"critical": 0, "high": 0, "medium": 0, "low": 0, "overall_score": 0}
            hosts_table = pd.DataFrame()
            st.info("Dashboard Reset. Run a new scan to see results.")
        else:
            # STANDBY STATE: Show sample data if backend is simply empty but not reset
            nmap_df, risk_data, hosts_table = _sample_data()
            st.info("Showing sample threat summary data (Backend database table 'scans' may be empty).")
    else:
        # Generate hosts_table from real backend data
        if "host" in nmap_df.columns and "vulnerabilities" in nmap_df.columns:
            top_hosts = nmap_df.groupby("host")["vulnerabilities"].sum()
            top_hosts = top_hosts.sort_values(ascending=False).head(10)

            hosts_table = pd.DataFrame({
                "Host": top_hosts.index,
                "Total Vulns": top_hosts.values,
            })

            # Heuristic scoring
            hosts_table["Risk Score"] = (hosts_table["Total Vulns"] * 8).clip(0, 100)
            
            def score_to_level_simple(score):
                if score >= 80: return "Critical"
                if score >= 60: return "High"
                if score >= 40: return "Medium"
                return "Low"

            hosts_table["Risk Level"] = hosts_table["Risk Score"].apply(score_to_level_simple)
            hosts_table["Threat Score"] = (hosts_table["Risk Score"] * 0.9).astype(int)
            hosts_table["Services"] = "Multiple Detected"
        else:
            hosts_table = pd.DataFrame()

    # =================================================
    # METRICS
    # =================================================
    total_hosts_count = int(nmap_df["host"].nunique()) if "host" in nmap_df.columns else 0
    total_vulns_count = int(nmap_df["vulnerabilities"].sum()) if "vulnerabilities" in nmap_df.columns else 0
    
    # Priority KPI: Critical + High findings
    high_critical_count = int(risk_data.get("high", 0) + risk_data.get("critical", 0))
    
    # Weighted Threat Score Calculation
    calc_score = int(
        risk_data.get("critical", 0) * 4 +
        risk_data.get("high", 0) * 3 +
        risk_data.get("medium", 0) * 2 +
        risk_data.get("low", 0)
    )
    final_threat_score = risk_data.get("overall_score", calc_score)

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("TOTAL HOSTS", total_hosts_count)
    m2.metric("TOTAL VULNERABILITIES", total_vulns_count)
    m3.metric("HIGH / CRITICAL", high_critical_count)
    m4.metric("THREAT SCORE", final_threat_score)

    # Risk Badge Styling
    def get_badge_info(score):
        if score >= 80: return "Critical", "#e74c3c"
        if score >= 60: return "High", "#f39c12"
        if score >= 40: return "Medium", "#f1c40f"
        return "Low", "#2ecc71"

    level, color = get_badge_info(final_threat_score)
    st.markdown(
        f"**Overall Risk:** <span style='color:{color}; font-weight:700'>{level}</span>",
        unsafe_allow_html=True
    )

    st.markdown("---")

    # =================================================
    # CHARTS
    # =================================================
    c1, c2 = st.columns(2)

    sev_counts = pd.Series({
        "Critical": risk_data.get("critical", 0),
        "High": risk_data.get("high", 0),
        "Medium": risk_data.get("medium", 0),
        "Low": risk_data.get("low", 0),
    })

    fig_donut = px.pie(
        values=sev_counts.values,
        names=sev_counts.index,
        hole=0.5,
        title="Vulnerability Severity Distribution",
        color=sev_counts.index,
        color_discrete_map={"Critical": "#e74c3c", "High": "#f39c12", "Medium": "#f1c40f", "Low": "#2ecc71"},
        template=st.session_state.get("plotly_template", "plotly_dark"),
    )
    c1.plotly_chart(fig_donut, width='stretch')

    if not hosts_table.empty:
        fig_bar = px.bar(
            hosts_table,
            x="Host",
            y="Threat Score",
            color="Risk Level",
            title="Host Threat Score Comparison",
            color_discrete_map={"Critical": "#e74c3c", "High": "#f39c12", "Medium": "#f1c40f", "Low": "#2ecc71"},
            template=st.session_state.get("plotly_template", "plotly_dark"),
        )
        c2.plotly_chart(fig_bar, width='stretch')
    else:
        c2.info("No host distribution data available.")

    st.markdown("---")

    # =================================================
    # HOST TABLE (HTML STYLED)
    # =================================================
    st.markdown(
        "<h3 style='text-align:center'>Detailed Host Risk Overview</h3>",
        unsafe_allow_html=True
    )

    if not hosts_table.empty:
        table_rows = ""
        for _, r in hosts_table.iterrows():
            lvl_color = "#e74c3c" if r['Risk Level'] == "Critical" else "#f39c12" if r['Risk Level'] == "High" else "#a0a0a0"
            table_rows += dedent(f"""
                <tr style="border-bottom: 1px solid #333">
                  <td style="padding: 10px">{r['Host']}</td>
                  <td style="padding: 10px" align="center">{r['Total Vulns']}</td>
                  <td style="padding: 10px" align="center">{r['Risk Score']}</td>
                  <td style="padding: 10px" align="center"><b style="color:{lvl_color}">{r['Risk Level']}</b></td>
                  <td style="padding: 10px" align="center">{r['Threat Score']}</td>
                  <td style="padding: 10px">{r['Services']}</td>
                </tr>
            """)

        st.markdown(f"""
        <div style="background:#121212; padding:16px; border-radius:12px; border: 1px solid #333">
        <table style="width:100%; border-collapse: collapse; color: #e0e0e0">
          <tr style="background: #1a1a1a; color: #00f2ff">
            <th style="padding: 12px">Host</th>
            <th style="padding: 12px">Total Vulns</th>
            <th style="padding: 12px">Risk Score</th>
            <th style="padding: 12px">Risk Level</th>
            <th style="padding: 12px">Threat Score</th>
            <th style="padding: 12px">Services</th>
          </tr>
          {table_rows}
        </table>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.info("No host data available for table display.")
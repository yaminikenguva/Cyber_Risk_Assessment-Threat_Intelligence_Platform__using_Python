import streamlit as st
import plotly.express as px
import pandas as pd
import tempfile
import os
import io
from datetime import datetime

from dashboard.data_loader import load_scan_metadata, load
from dashboard.utils.pdf_export import generate_executive_pdf

def run(filters=None):
    filters = filters or {}

    st.markdown(
        "<div class='section-title'>🏠 Overview</div>",
        unsafe_allow_html=True
    )

    # ==================================
    # FORCE REFRESH LOGIC
    # ============================
    refresh_key = st.session_state.get("scan_refresh_key", 0)

    # =================================================
    # LOAD DATA
    # =================================================
    meta = load_scan_metadata(refresh_key=refresh_key) or {}
    nmap = load("/nmap/results", refresh_key=refresh_key)
    risk = load("/risk/summary", refresh_key=refresh_key)

    # Safe Normalization
    nmap_df = nmap if isinstance(nmap, pd.DataFrame) else pd.DataFrame()
    risk_data = risk if isinstance(risk, dict) else {}

    # Metrics Defaults
    total_hosts = 0
    total_findings = 0
    threat_score = 0
    risk_level = "Unknown"

    # =================================================
    # COMPUTE METRICS
    # =================================================
    if not nmap_df.empty:
        total_hosts = nmap_df["host"].nunique() if "host" in nmap_df.columns else len(nmap_df)
        total_findings = len(nmap_df) # Total findings based on discovery

    if risk_data:
        # Prioritize overall_score from API; fallback to calculation if missing
        if "overall_score" in risk_data:
            threat_score = risk_data.get("overall_score", 0)
        else:
            threat_score = (
                risk_data.get("critical", 0) * 3
                + risk_data.get("high", 0) * 2
                + risk_data.get("medium", 0)
            )

        critical_count = risk_data.get("critical", 0)
        high_count = risk_data.get("high", 0)
        
        if threat_score >= 80 or critical_count > 0:
            risk_level = "Critical"
        elif threat_score >= 60 or high_count > 0:
            risk_level = "High"
        elif threat_score >= 40:
            risk_level = "Medium"
        else:
            risk_level = "Low"

    # =================================================
    # HEADER & FRESHNESS ALERT
    # =================================================
    scan_time_str = meta.get('created_at', '—')
    st.caption(f"**Scan Type:** {meta.get('scan_type', 'Nmap')}  |  **Scan Time:** {scan_time_str}")

    # Security Principle: Check if scan is older than 4-day signature update window
    if scan_time_str != '—':
        try:
            scan_dt = datetime.strptime(scan_time_str, "%Y-%m-%d %H:%M:%S")
            if (datetime.now() - scan_dt).days >= 4:
                st.warning("⚠️ **Vulnerability definitions may be stale.** (Last scan was > 4 days ago)")
        except:
            pass

    # =================================================
    # KPI CARDS
    # =================================================
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Hosts", total_hosts)
    c2.metric("Total Findings", total_findings)
    c3.metric("Threat Score", threat_score)
    c4.metric("Risk Level", risk_level)

    st.markdown("---")

    # =================================================
    # SEVERITY DISTRIBUTION
    # =================================================
    if not nmap_df.empty and "port" in nmap_df.columns:
        def derive_severity(port):
            # Flagging high-risk ports that often expose PII/IP
            if port in (22, 3389, 445, 1433): 
                return "High"
            elif port in (80, 443):
                return "Medium"
            return "Low"

        sev_series = (
            nmap_df["port"]
            .apply(derive_severity)
            .value_counts()
            .reindex(["Critical", "High", "Medium", "Low"])
            .fillna(0)
        )

        fig = px.pie(
            values=sev_series.values,
            names=sev_series.index,
            hole=0.4,
            title="Findings Severity Distribution",
            color=sev_series.index,
            color_discrete_map={"Critical": "#e74c3c", "High": "#f39c12", "Medium": "#f1c40f", "Low": "#2ecc71"},
            template=st.session_state.get("plotly_template", "plotly_dark"),
        )
        st.plotly_chart(fig, width='stretch')
    else:
        st.info("Run a scan to see severity distribution.")

    st.markdown("---")

    # =================================================
    # EXECUTIVE PDF EXPORT (WINDOWS FIX)
    # =================================================
    st.markdown("### 📄 Executive Report")

    if st.button("Generate Executive PDF"):
        tmp_path = None
        try:
            # 1. Create file and close handle immediately
            with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
                tmp_path = tmp.name
            
            # 2. Generate PDF to the path
            generate_executive_pdf(
                summary={
                    "scan_type": meta.get("scan_type", "Nmap"),
                    "scan_time": meta.get("created_at"),
                    "hosts": total_hosts,
                    "findings": total_findings,
                    "risk_level": risk_level,
                    "threat_score": threat_score,
                },
                path=tmp_path,
            )

            # 3. Read into memory while disk file is closed
            with open(tmp_path, "rb") as f:
                pdf_bytes = f.read()

            # 4. Provide download
            st.download_button(
                label="Download PDF",
                data=pdf_bytes,
                file_name=f"cyber_risk_report_{datetime.now().strftime('%Y%m%d')}.pdf",
                mime="application/pdf",
            )
            st.success("Report ready for download.")

        except Exception as e:
            st.error(f"PDF Error: {e}")
        
        finally:
            # 5. Safe cleanup after all handles are released
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except:
                    pass

    st.caption("Overview combines Layer-1 discovery and Layer-3 risk analysis.")
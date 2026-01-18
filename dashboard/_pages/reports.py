import io
import streamlit as st
import pandas as pd
from datetime import datetime

from dashboard.data_loader import load
from dashboard.utils.pdf_export import generate_executive_pdf


# =================================================
# PAGE ENTRYPOINT
# =================================================
def run(filters=None):
    """
    Reports & Compliance Page

    - Aggregates Layer 1 (Nmap)
    - Layer 2 (Threat Intel)
    - Layer 3 (Risk Scoring)
    - Supports CSV / PDF / Excel exports
    """
    filters = filters or {}

    st.markdown(
        "<div class='section-title'>📜 Reports & Compliance</div>",
        unsafe_allow_html=True,
    )

    st.caption(
        "Audit-ready security reports generated from automated scans "
        "and threat intelligence."
    )

    # =================================================
    # LOAD DATA FROM BACKEND
    # =================================================
    meta = load("/scan/metadata") or {}
    nmap = load("/nmap/results")
    risk = load("/risk/summary")
    threat = load("/threat/intel")

    # Normalize Nmap
    if isinstance(nmap, pd.DataFrame):
        nmap_df = nmap.copy()
    else:
        nmap_df = pd.DataFrame()

    # Normalize Threat Intel
    if isinstance(threat, pd.DataFrame):
        threat_df = threat.copy()
    else:
        threat_df = pd.DataFrame()

    # Normalize Risk
    if isinstance(risk, dict):
        risk_data = risk
    else:
        risk_data = {}

    # =================================================
    # SCAN SUMMARY
    # =================================================
    st.markdown("### 🧾 Scan Summary")

    scan_time = meta.get("created_at") or meta.get("timestamp")
    scan_time = scan_time or datetime.utcnow().isoformat()

    summary_cols = st.columns(4)

    summary_cols[0].metric("Scan Type", meta.get("scan_type", "Nmap"))
    summary_cols[1].metric("Scan Time", scan_time.split("T")[0])
    summary_cols[2].metric(
        "Hosts Scanned",
        nmap_df["host"].nunique() if "host" in nmap_df.columns else 0,
    )
    summary_cols[3].metric(
        "Total Findings",
        len(nmap_df) if not nmap_df.empty else 0,
    )

    st.markdown("---")

    # =================================================
    # RISK OVERVIEW
    # =================================================
    st.markdown("### ⚠️ Risk Overview")

    if risk_data:
        r1, r2, r3, r4 = st.columns(4)
        r1.metric("Critical", risk_data.get("critical", 0))
        r2.metric("High", risk_data.get("high", 0))
        r3.metric("Medium", risk_data.get("medium", 0))
        r4.metric("Low", risk_data.get("low", 0))
    else:
        st.info("Risk summary not available yet.")

    st.markdown("---")

    # =================================================
    # DATA PREVIEW
    # =================================================
    st.markdown("### 📊 Data Preview")

    with st.expander("Nmap Scan Results"):
        if not nmap_df.empty:
            st.dataframe(nmap_df, width='stretch')
        else:
            st.info("No Nmap scan data available.")

    with st.expander("Threat Intelligence"):
        if not threat_df.empty:
            st.dataframe(threat_df, width='stretch')
        else:
            st.info("No threat intelligence data available.")

    # =================================================
    # EXPORT SECTION
    # =================================================
    st.markdown("---")
    st.markdown("### ⬇ Download Reports")

    # ---------- CSV ----------
    csv_buf = io.StringIO()
    if not nmap_df.empty:
        nmap_df.to_csv(csv_buf, index=False)

    st.download_button(
        "Download Nmap Findings (CSV)",
        csv_buf.getvalue(),
        file_name="nmap_findings.csv",
        mime="text/csv",
    )

    # ---------- EXCEL ----------
    excel_buf = io.BytesIO()
    with pd.ExcelWriter(excel_buf, engine="xlsxwriter") as writer:
        if not nmap_df.empty:
            nmap_df.to_excel(writer, sheet_name="Nmap Results", index=False)
        if risk_data:
            pd.DataFrame([risk_data]).to_excel(
                writer, sheet_name="Risk Summary", index=False
            )
        if not threat_df.empty:
            threat_df.to_excel(
                writer, sheet_name="Threat Intel", index=False
            )

    st.download_button(
        "Download Full Report (Excel)",
        excel_buf.getvalue(),
        file_name="cyber_risk_report.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )

    # ---------- PDF ----------
    st.markdown("### 📄 Executive PDF")

    if st.button("Generate Executive PDF",key="reports_exec_pdf"):
        generate_executive_pdf(
            summary={
                "scan_type": meta.get("scan_type", "Nmap"),
                "scan_time": scan_time,
                "hosts": nmap_df["host"].nunique()
                if "host" in nmap_df.columns
                else 0,
                "findings": len(nmap_df),
                "risk": risk_data,
            }
        )

        st.success("Executive PDF generated successfully.")

    # =================================================
    # COMPLIANCE NOTE
    # =================================================
    st.caption(
        "Reports are generated from automated scans and threat intelligence "
        "sources. Intended for audit, compliance, and management review."
    )

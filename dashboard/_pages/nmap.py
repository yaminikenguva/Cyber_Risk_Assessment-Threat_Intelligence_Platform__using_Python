import streamlit as st
import pandas as pd

from dashboard.data_loader import load


# =================================================
# NMAP PAGE
# =================================================
def run(filters=None):
    filters = filters or {}

    st.markdown(
        "<div class='section-title'>🛰️ Nmap Scan Results</div>",
        unsafe_allow_html=True
    )

    st.caption(
        "Layer-1 automated vulnerability scanning using Nmap "
        "(open ports, services, versions, and basic vulnerabilities)."
    )

    # =================================================
    # CHECK SCAN STATUS FIRST
    # =================================================
    status = load("/scan/status")

    if isinstance(status, dict):
        scan_state = status.get("state", "idle")
    else:
        scan_state = status or "idle"

    if scan_state != "completed":
        st.info(f"Scan status: **{scan_state.upper()}**")
        st.caption("Run a scan from the sidebar to generate results.")
        return

    # =================================================
    # LOAD NMAP RESULTS
    # =================================================
    data = load("/nmap/results")

    if data is None:
        st.warning("Backend returned no Nmap data.")
        return

    if isinstance(data, dict):
        st.warning("Scan completed, but no service data available.")
        return

    if not isinstance(data, pd.DataFrame) or data.empty:
        st.info("No Nmap scan results available.")
        return

    df = data.copy()
    df.columns = [c.lower() for c in df.columns]

    # =================================================
    # FILTERS
    # =================================================
    f1, f2, f3 = st.columns(3)

    if "host" in df.columns:
        hosts = sorted(df["host"].dropna().unique())
        selected_hosts = f1.multiselect("Host", hosts)
        if selected_hosts:
            df = df[df["host"].isin(selected_hosts)]

    if "service" in df.columns:
        services = sorted(df["service"].dropna().unique())
        selected_services = f2.multiselect("Service", services)
        if selected_services:
            df = df[df["service"].isin(selected_services)]

    if "state" in df.columns:
        states = sorted(df["state"].dropna().unique())
        selected_state = f3.selectbox("Port State", ["All"] + states)
        if selected_state != "All":
            df = df[df["state"] == selected_state]

    # =================================================
    # KPIs
    # =================================================
    k1, k2, k3 = st.columns(3)

    total_hosts = df["host"].nunique() if "host" in df.columns else 0
    open_ports = (
        (df["state"].astype(str).str.lower() == "open").sum()
        if "state" in df.columns else 0
    )
    services_count = df["service"].nunique() if "service" in df.columns else 0

    k1.metric("Total Hosts", total_hosts)
    k2.metric("Open Ports", open_ports)
    k3.metric("Services Detected", services_count)

    st.markdown("---")

    # =================================================
    # RESULTS TABLE
    # =================================================
    # st.dataframe(
    #     df.sort_values(
    #         by=["host", "port"],
    #         errors="ignore"
    #     ),
    #     width="stretch",
    #     hide_index=True
    # )

    # =================================================
    # RESULTS TABLE
    # =================================================
    
    # Identify which columns are available for sorting to avoid TypeErrors
    available_cols = df.columns.tolist()
    preferred_sort = [c for c in ["host", "port"] if c in available_cols]

    if preferred_sort:
        # If 'port' exists, ensure it is numeric for proper 22 -> 80 -> 443 sorting
        if "port" in df.columns:
            df["port"] = pd.to_numeric(df["port"], errors="coerce")
            
        df = df.sort_values(by=preferred_sort)

    st.dataframe(
        df,
        use_container_width=True, # Modern replacement for width='stretch'
        hide_index=True
    )

    # =================================================
    # EXPORT
    # =================================================
    st.markdown("### ⬇ Export")

    st.download_button(
        label="Download CSV",
        data=df.to_csv(index=False),
        file_name="nmap_results.csv",
        mime="text/csv"
    )

    st.caption(
        "Source: Layer-1 Nmap Scanner → Backend API → `/nmap/results`"
    )

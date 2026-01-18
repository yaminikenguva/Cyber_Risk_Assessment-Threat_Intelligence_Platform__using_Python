import streamlit as st
import pandas as pd
from datetime import datetime
import requests

from dashboard.data_loader import load

API = "http://127.0.0.1:8000"


# =================================================
# ALERTS PAGE
# =================================================
def run(filters=None):
    """
    Security Alerts Dashboard
    
    Displays:
    - Active alerts requiring attention
    - Alert statistics and metrics
    - Historical alerts
    - Severity-based filtering
    """
    filters = filters or {}

    st.markdown(
        "<div class='section-title'>🚨 Security Alerts</div>",
        unsafe_allow_html=True,
    )

    st.caption(
        "Automated alerts generated from vulnerability scans and threat intelligence. "
        "Critical and high-severity alerts require immediate attention."
    )

    # =================================================
    # LOAD ALERTS DATA
    # =================================================
    alerts_data = load("/alerts")
    stats_data = load("/alerts/stats")
    
    # Normalize data
    if isinstance(alerts_data, list):
        alerts_df = pd.DataFrame(alerts_data)
    else:
        alerts_df = pd.DataFrame()
    
    if not isinstance(stats_data, dict):
        stats_data = {}

    # =================================================
    # ALERT STATISTICS
    # =================================================
    st.markdown("### 📊 Alert Overview")
    
    c1, c2, c3, c4, c5 = st.columns(5)
    
    with c1:
        st.metric(
            "Total Alerts",
            stats_data.get("total", 0),
            delta=None,
        )
    
    with c2:
        active_count = stats_data.get("active", 0)
        st.metric(
            "🔴 Active",
            active_count,
            delta=None,
        )
    
    with c3:
        critical_count = stats_data.get("critical", 0)
        st.metric(
            "🔥 Critical",
            critical_count,
            delta=None,
        )
    
    with c4:
        high_count = stats_data.get("high", 0)
        st.metric(
            "⚠️ High",
            high_count,
            delta=None,
        )
    
    with c5:
        ack_count = stats_data.get("acknowledged", 0)
        st.metric(
            "✅ Acknowledged",
            ack_count,
            delta=None,
        )
    
    st.markdown("---")

    # =================================================
    # NO ALERTS MESSAGE
    # =================================================
    if alerts_df.empty:
        st.info("✅ No alerts generated. Run a scan to monitor for security issues.")
        return

    # =================================================
    # FILTERS
    # =================================================
    st.markdown("### 🔍 Filters")
    
    f1, f2, f3 = st.columns(3)
    
    with f1:
        severity_filter = st.multiselect(
            "Severity",
            options=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            default=["CRITICAL", "HIGH"],
        )
    
    with f2:
        status_filter = st.radio(
            "Status",
            options=["All", "Active Only", "Acknowledged Only"],
            index=1,
        )
    
    with f3:
        alert_types = alerts_df["alert_type"].unique().tolist() if "alert_type" in alerts_df.columns else []
        type_filter = st.multiselect(
            "Alert Type",
            options=alert_types,
            default=alert_types,
        )

    # =================================================
    # APPLY FILTERS
    # =================================================
    view = alerts_df.copy()
    
    # Severity filter
    if severity_filter and "severity" in view.columns:
        view = view[view["severity"].isin(severity_filter)]
    
    # Status filter
    if status_filter == "Active Only" and "acknowledged" in view.columns:
        view = view[view["acknowledged"] == 0]
    elif status_filter == "Acknowledged Only" and "acknowledged" in view.columns:
        view = view[view["acknowledged"] == 1]
    
    # Type filter
    if type_filter and "alert_type" in view.columns:
        view = view[view["alert_type"].isin(type_filter)]
    
    st.markdown("---")

    # =================================================
    # ALERT CARDS
    # =================================================
    st.markdown(f"### 🚨 Alerts ({len(view)})")
    
    if view.empty:
        st.info("No alerts match the selected filters.")
        return
    
    # Sort by severity and date
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    if "severity" in view.columns:
        view["severity_rank"] = view["severity"].map(severity_order)
        view = view.sort_values(["severity_rank", "created_at"], ascending=[True, False])
    
    # Display alerts
    for idx, alert in view.iterrows():
        severity = alert.get("severity", "UNKNOWN")
        title = alert.get("title", "Untitled Alert")
        description = alert.get("description", "No description available")
        alert_type = alert.get("alert_type", "UNKNOWN")
        targets = alert.get("targets", "N/A")
        created_at = alert.get("created_at", "Unknown")
        is_acknowledged = alert.get("acknowledged", 0)
        
        # Severity color mapping
        if severity == "CRITICAL":
            severity_color = "🔴"
            border_color = "#ff4444"
        elif severity == "HIGH":
            severity_color = "🟠"
            border_color = "#ff9944"
        elif severity == "MEDIUM":
            severity_color = "🟡"
            border_color = "#ffdd44"
        else:
            severity_color = "🟢"
            border_color = "#44ff44"
        
        # Alert card
        with st.container():
            st.markdown(
                f"""
                <div style="border-left: 4px solid {border_color}; padding: 15px; margin-bottom: 15px; background-color: rgba(255,255,255,0.05); border-radius: 5px;">
                    <h4>{severity_color} {title}</h4>
                    <p><strong>Severity:</strong> {severity} | <strong>Type:</strong> {alert_type}</p>
                    <p><strong>Targets:</strong> {targets}</p>
                    <p>{description}</p>
                    <p style="color: #888; font-size: 0.9em;">Created: {created_at}</p>
                </div>
                """,
                unsafe_allow_html=True,
            )
            
            # Acknowledge button (if not already acknowledged)
            if not is_acknowledged:
                if st.button(f"✅ Acknowledge", key=f"ack_{idx}"):
                    st.info("Alert acknowledgment feature will be implemented in the next update.")

    st.markdown("---")

    # =================================================
    # SEVERITY DISTRIBUTION CHART
    # =================================================
    st.markdown("### 📊 Alert Distribution by Severity")
    
    if "severity" in view.columns and not view.empty:
        import plotly.express as px
        
        severity_counts = view["severity"].value_counts()
        
        fig = px.pie(
            values=severity_counts.values,
            names=severity_counts.index,
            color=severity_counts.index,
            color_discrete_map={
                "CRITICAL": "#ff4444",
                "HIGH": "#ff9944",
                "MEDIUM": "#ffdd44",
                "LOW": "#44ff44",
            },
            template=st.session_state.get("plotly_template", "plotly_dark"),
        )
        
        fig.update_traces(textposition='inside', textinfo='percent+label')
        
        st.plotly_chart(fig, width='stretch')
    
    st.markdown("---")

    # =================================================
    # ALERT TIMELINE
    # =================================================
    st.markdown("### 📅 Alert Timeline")
    
    if "created_at" in view.columns and not view.empty:
        import plotly.express as px
        
        timeline_df = view.copy()
        timeline_df["date"] = pd.to_datetime(timeline_df["created_at"]).dt.date
        timeline_counts = timeline_df.groupby(["date", "severity"]).size().reset_index(name="count")
        
        fig = px.bar(
            timeline_counts,
            x="date",
            y="count",
            color="severity",
            color_discrete_map={
                "CRITICAL": "#ff4444",
                "HIGH": "#ff9944",
                "MEDIUM": "#ffdd44",
                "LOW": "#44ff44",
            },
            template=st.session_state.get("plotly_template", "plotly_dark"),
            title="Alerts Over Time",
        )
        
        st.plotly_chart(fig, width='stretch')
    
    st.markdown("---")

    # =================================================
    # EXPORT OPTIONS
    # =================================================
    st.markdown("### ⬇️ Export Alerts")
    
    try:
        csv_data = view.to_csv(index=False)
        
        st.download_button(
            label="📥 Download Alerts as CSV",
            data=csv_data,
            file_name=f"security_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
        )
    except Exception as e:
        st.warning(f"Unable to generate CSV: {e}")

import streamlit as st
import plotly.express as px
import pandas as pd
from dashboard.data_loader import load


def run(filters=None):
    filters = filters or {}

    st.markdown("### 🌍 Global Threat Intelligence")

    # ---------------- Map ----------------
    st.components.v1.iframe(
        "https://threat-intel-map.netlify.app/",
        height=500,
        scrolling=True
    )

    st.markdown("---")

    # ---------------- Load Data ----------------
    df = load("/threat/intel")

    if df is None or getattr(df, "empty", True):
        st.info("No threat intelligence data available")
        return

    # Normalize columns
    df = df.copy()
    df.columns = [c.lower() for c in df.columns]

    # ---------------- Apply Filters ----------------
    host_filter = filters.get("host")
    if host_filter and "host" in df.columns:
        df = df[df["host"].astype(str).str.contains(host_filter)]

    # ---------------- Identify Indicator Column ----------------
    indicator_col = None
    for c in ["indicator", "ioc", "value", "pattern", "ip"]:
        if c in df.columns:
            indicator_col = c
            break

    # ---------------- Top Indicators ----------------
    if indicator_col:
        top = (
            df[indicator_col]
            .astype(str)
            .value_counts()
            .head(10)
            .reset_index()
        )

        # ✅ CRITICAL FIX: Rename columns explicitly
        top.columns = ["indicator", "count"]

        fig = px.bar(
            top,
            x="indicator",
            y="count",
            title="Top Threat Indicators",
            template=st.session_state.get("plotly_template", "plotly_dark"),
        )

        st.plotly_chart(fig, width='stretch')

    else:
        st.info("No indicator field found in threat intel data")

    st.markdown("---")

    # ---------------- Timeline ----------------
    time_col = None
    for c in ["timestamp", "time", "created_at", "date"]:
        if c in df.columns:
            time_col = c
            break

    if time_col:
        try:
            df[time_col] = pd.to_datetime(df[time_col], errors="coerce")

            timeline = (
                df.groupby(pd.Grouper(key=time_col, freq="D"))
                .size()
                .reset_index(name="count")
            )

            fig_t = px.line(
                timeline,
                x=time_col,
                y="count",
                title="Threat Events Over Time",
                template=st.session_state.get("plotly_template", "plotly_dark"),
            )

            st.plotly_chart(fig_t, width='stretch')

        except Exception:
            pass

    st.markdown("---")

    # ---------------- Raw Table ----------------
    st.markdown("### 📋 Threat Intelligence Records")
    st.dataframe(df, width='stretch')

import io
import streamlit as st
import plotly.express as px
import pandas as pd

from dashboard.data_loader import load
from dashboard.utils.pdf_export import generate_executive_pdf


# =================================================
# FALLBACK SAMPLE DATA
# =================================================
def _sample_data() -> pd.DataFrame:
    dates = pd.date_range(end=pd.Timestamp.today(), periods=7, freq="D")
    hosts = ["192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4"]

    rows = []
    for d in dates:
        for i, h in enumerate(hosts):
            rows.append({
                "date": d,
                "host": h,
                "risk_score": max(20, 90 - i * 8 - dates.get_loc(d) * 3),
                "risk_level": ["Critical", "High", "Medium", "Low"][i % 4],
            })

    return pd.DataFrame(rows)


# =================================================
# PAGE ENTRYPOINT
# =================================================
def run(filters=None):
    filters = filters or {}

    st.markdown(
        "<div class='section-title'>📊 Risk Analysis</div>",
        unsafe_allow_html=True
    )

    st.caption(
        "Layer-3 risk scoring & normalization based on scan exposure, "
        "service risk, and vulnerability context."
    )

    # =================================================
    # LOAD BACKEND DATA
    # =================================================
    raw = load("/risk/summary")

    # Normalize backend response
    if isinstance(raw, dict) and "overall_score" in raw:
        # Summary format - create single row
        df = pd.DataFrame([{
            "host": "Overall",
            "risk_score": raw.get("overall_score", 0),
            "risk_level": (
                "Critical" if raw.get("critical", 0) > 0
                else "High" if raw.get("high", 0) > 0
                else "Medium" if raw.get("medium", 0) > 0
                else "Low"
            ),
            "date": pd.Timestamp.utcnow(),
            "critical": raw.get("critical", 0),
            "high": raw.get("high", 0),
            "medium": raw.get("medium", 0),
            "low": raw.get("low", 0),
        }])
    elif isinstance(raw, list):
        df = pd.DataFrame(raw)
    elif isinstance(raw, pd.DataFrame):
        df = raw.copy()
    else:
        df = pd.DataFrame()

    if df.empty:
        df = _sample_data()

    # =================================================
    # NORMALIZATION
    # =================================================
    df.columns = [c.lower() for c in df.columns]

    if "date" not in df.columns:
        df["date"] = pd.Timestamp.utcnow()

    df["date"] = pd.to_datetime(df["date"], errors="coerce", utc=True)
    df["date"] = df["date"].dt.tz_localize(None)

    if "risk_score" not in df.columns:
        df["risk_score"] = 0

    if "risk_level" not in df.columns:
        def _level(score):
            if score >= 80: return "Critical"
            if score >= 60: return "High"
            if score >= 40: return "Medium"
            return "Low"

        df["risk_level"] = df["risk_score"].apply(_level)

    df["risk_level"] = df["risk_level"].astype(str).str.title()

    # =================================================
    # FILTERS
    # =================================================
    f1, f2, f3 = st.columns([1, 1, 2])

    host_opts = sorted(df["host"].unique())
    selected_hosts = f1.multiselect("Host", host_opts)

    selected_levels = f2.multiselect(
        "Risk Level",
        ["Critical", "High", "Medium", "Low"]
    )

    date_range = f3.date_input(
        "Date Range",
        value=(df["date"].min(), df["date"].max())
    )

    view = df.copy()

    if selected_hosts:
        view = view[view["host"].isin(selected_hosts)]

    if selected_levels:
        view = view[view["risk_level"].isin(selected_levels)]

    if isinstance(date_range, tuple) and len(date_range) == 2:
        start = pd.to_datetime(date_range[0])
        end = pd.to_datetime(date_range[1])

        # Normalize to timezone-navie
        start = start.tz_localize(None) if start.tzinfo else start
        end = end.tz_localize(None) if end.tzinfo else end
        

        view = view[(view["date"] >= start) & (view["date"] <= end)]

    # =================================================
    # KPIs
    # =================================================
    k1, k2, k3 = st.columns(3)

    k1.metric("Unique Hosts", view["host"].nunique())

    avg_risk = float(view["risk_score"].mean()) if not view.empty else 0
    k2.metric("Average Risk", f"{avg_risk:.1f}")

    high_critical = int(view["risk_level"].isin(["Critical", "High"]).sum())
    k3.metric("High / Critical", high_critical)

    st.markdown("---")

    # =================================================
    # RISK MODELING CONTROLS
    # =================================================
    st.markdown("### ⚙️ Risk Modeling Controls")

    w1, w2 = st.columns(2)
    exposure_weight = w1.slider("Exposure Weight", 0.0, 2.0, 1.0, 0.1)
    vuln_weight = w2.slider("Vulnerability Weight", 0.0, 2.0, 0.5, 0.1)

    view = view.copy()

    rng = (view["risk_score"].max() - view["risk_score"].min()) or 1
    view["exposure"] = (
        (view["risk_score"] - view["risk_score"].min()) / rng
    ) * 100

    view["adjusted_risk"] = (
        view["risk_score"]
        * (1 + exposure_weight * (view["exposure"] / 100))
        * (1 + vuln_weight)
    ).clip(0, 100)

    # =================================================
    # AUTOMATED INSIGHTS
    # =================================================
    st.markdown("### 🧠 Automated Insights")

    if not view.empty:
        top = (
            view.groupby("host")["adjusted_risk"]
            .mean()
            .sort_values(ascending=False)
        )

        top_host = top.index[0]
        top_score = top.iloc[0]

        st.info(
            f"Host **{top_host}** shows the highest adjusted risk "
            f"(**{top_score:.1f}**). Prioritize remediation."
        )
    else:
        st.info("No risk insights available.")

    st.markdown("---")

    # =================================================
    # CHARTS
    # =================================================
    tplt = st.session_state.get("plotly_template", "plotly_dark")

    c1, c2 = st.columns([2, 1])

    host_avg = (
        view.groupby("host")["risk_score"]
        .mean()
        .sort_values(ascending=False)
        .reset_index()
    )

    fig_bar = px.bar(
        host_avg.head(10),
        x="host",
        y="risk_score",
        title="Top Hosts by Average Risk",
        template=tplt,
    )
    c1.plotly_chart(fig_bar, width='stretch')

    sev_counts = (
        view["risk_level"]
        .value_counts()
        .reindex(["Critical", "High", "Medium", "Low"])
        .fillna(0)
    )

    fig_pie = px.pie(
        values=sev_counts.values,
        names=sev_counts.index,
        hole=0.4,
        title="Risk Level Distribution",
        template=tplt,
    )
    c2.plotly_chart(fig_pie, width='stretch')

    ts = (
        view.groupby("date")["risk_score"]
        .mean()
        .reset_index()
    )

    fig_ts = px.line(
        ts,
        x="date",
        y="risk_score",
        title="Average Risk Over Time",
        template=tplt,
    )
    st.plotly_chart(fig_ts, width='stretch')

    st.markdown("---")

    # =================================================
    # TABLE + EXPORT
    # =================================================
    st.markdown("### 🚨 High-Risk Hosts")

    table = (
        view.groupby("host")["adjusted_risk"]
        .mean()
        .sort_values(ascending=False)
        .reset_index()
    )

    st.dataframe(table, width='stretch')

    st.markdown("### ⬇ Export")

    csv_buf = io.StringIO()
    view.to_csv(csv_buf, index=False)

    st.download_button(
        "Download Risk CSV",
        csv_buf.getvalue(),
        file_name="risk_analysis.csv",
        mime="text/csv",
    )

    if st.button("📄 Export Risk Summary PDF"):
        generate_executive_pdf(
            summary={
                "module": "Risk Analysis",
                "hosts": int(view["host"].nunique()),
                "average_risk": round(avg_risk, 2),
                "high_risk_hosts": int(high_critical),
            }
        )

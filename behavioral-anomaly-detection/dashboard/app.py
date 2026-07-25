"""
dashboard/app.py — Deliverable 6: analyst-facing dashboard.

Run with: streamlit run dashboard/app.py

Planned layout:
    - Sidebar: alert-budget slider (top N% of events), date range, entity_type filter
    - Main: ranked alert queue table
        columns: risk_score, entity_id, entity_type, timestamp, predicted anomaly_type,
                 top explanation reasons (from explainability.explain_batch)
    - Row click -> entity history view:
        - timeline of that entity's sessions (normal vs flagged)
        - geo map of source locations (flag impossible-travel pairs visually)
        - resource-access heatmap: typical resources vs this session's resource
        - device fingerprint history (flag mismatches)
    - Top bar: summary stats (alerts today, precision@budget on labeled
      backtest data, entities currently cold-start / low-confidence)

This file currently renders a static placeholder against
data/labeled/access_logs_labeled.csv so the UI shell can be reviewed before
src/pipeline/infer.py produces real scored_alerts.csv output.
"""

import pandas as pd
import streamlit as st

st.set_page_config(page_title="Behavioural Anomaly Detection — Analyst Console", layout="wide")
st.title("🛡️ Behavioural Anomaly Detection — Analyst Console")
st.caption("Placeholder UI — wire up to data/scored_alerts.csv once src/pipeline/infer.py is implemented.")

DATA_PATH = "data/labeled/access_logs_labeled.csv"

try:
    df = pd.read_csv(DATA_PATH, parse_dates=["timestamp"])
except FileNotFoundError:
    st.error(f"Could not find {DATA_PATH}. Run `python -m src.data_generation.generate_dataset` first.")
    st.stop()

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total sessions", f"{len(df):,}")
col2.metric("Flagged (ground truth, demo only)", f"{(df['label'] != 'normal').sum():,}")
col3.metric("Entities", f"{df['entity_id'].nunique():,}")
col4.metric("Anomaly types", f"{df.loc[df['label'].str.startswith('anomaly'), 'label'].nunique()}")

st.subheader("Alert queue (showing ground-truth anomalies — replace with model risk_score)")
alert_view = df[df["label"] != "normal"].sort_values("timestamp", ascending=False)
st.dataframe(
    alert_view[["timestamp", "entity_id", "entity_type", "label", "resource_accessed",
                "geo_city", "device_fingerprint", "attack_group_id"]].head(200),
    use_container_width=True,
)

st.subheader("Entity history")
entity_id = st.selectbox("Select entity_id", sorted(df["entity_id"].unique()))
entity_df = df[df["entity_id"] == entity_id].sort_values("timestamp")
st.line_chart(entity_df.set_index("timestamp")["session_duration_sec"])
st.dataframe(entity_df.tail(50), use_container_width=True)

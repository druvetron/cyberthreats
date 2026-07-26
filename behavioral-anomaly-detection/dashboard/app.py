"""
dashboard/app.py
CyberThreats Analyst Dashboard
A strictly grayscale, high-contrast UI for real-time security telemetry triage.
"""
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import os

# --- Page Config & Branding ---
st.set_page_config(
    page_title="CyberThreats UEBA Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Strict Grayscale Custom CSS ---
st.markdown("""
    <style>
    /* Global Background and Text */
    .stApp {
        background-color: #1a1a1a;
        color: #d3d3d3;
    }
    
    /* Headers */
    .main-header { 
        font-size: 32px; 
        font-weight: 800; 
        color: #ffffff; 
        margin-bottom: 25px; 
        letter-spacing: 1.5px; 
        border-bottom: 1px solid #404040; 
        padding-bottom: 10px;
    }
    .sub-header { 
        font-size: 20px; 
        font-weight: 600; 
        color: #b0b0b0; 
        margin-top: 25px; 
        margin-bottom: 15px;
    }
    
    /* Metric Override */
    div[data-testid="stMetricValue"] {
        color: #ffffff;
        font-size: 36px;
    }
    div[data-testid="stMetricLabel"] {
        color: #8c8c8c;
        font-size: 14px;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    
    /* Hide top padding for a cleaner look */
    .block-container {
        padding-top: 2rem;
    }
    </style>
""", unsafe_allow_html=True)


# --- Data Acquisition Helper ---
@st.cache_data
def fetch_scored_alerts(file_path: str):
    if os.path.exists(file_path):
        df = pd.read_csv(file_path)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        return df.sort_values(by='risk_score', ascending=False).reset_index(drop=True)
    else:
        # Fallback generation for safe demo rendering
        np.random.seed(42)
        times = pd.date_range(end=pd.Timestamp.now(), periods=100, freq='5min')
        entities = [f"USR_{np.random.randint(1001, 1020)}" for _ in range(100)]
        types = ['Normal'] * 85 + ['Brute Force', 'Impossible Travel', 'Lateral Movement', 'Device Spoofing', 'Low-and-slow exfiltration'] * 3
        np.random.shuffle(types)
        scores = [np.random.uniform(0.5, 4.2) if t == 'Normal' else np.random.uniform(7.1, 9.8) for t in types]
        exps = ["Behavior exhibits baseline characteristics." if t == 'Normal' else f"Flagged due to anomalous behavior matching {t} parameters." for t in types]
        
        return pd.DataFrame({
            'timestamp': times, 'entity_id': entities, 'entity_type': np.random.choice(['user', 'edge_device'], 100),
            'resource_accessed': np.random.choice(['PLC_Gateway_04', 'Cloud_ERP_API', 'Core_Auth_Server'], 100),
            'risk_score': scores, 'predicted_anomaly': types, 'explanation': exps, 'session_duration': np.random.exponential(120, 100)
        }).sort_values(by='risk_score', ascending=False).reset_index(drop=True)

SCORED_FILE_PATH = "data/scored_alerts.csv"
df_alerts = fetch_scored_alerts(SCORED_FILE_PATH)


# --- Sidebar Controls ---
st.sidebar.markdown("## 🛡️ CyberThreats")
st.sidebar.markdown("---")
risk_threshold = st.sidebar.slider("Minimum Risk Filtering Threshold", 0.0, 10.0, 6.5, step=0.1)
entity_filter = st.sidebar.text_input("Filter Queue by Entity ID (Exact match)")

filtered_df = df_alerts[df_alerts['risk_score'] >= risk_threshold]
if entity_filter:
    filtered_df = filtered_df[filtered_df['entity_id'] == entity_filter]


# --- Top Dashboard Executive Metrics ---
st.markdown('<div class="main-header">CyberThreats Behavioral Anomaly Detection</div>', unsafe_allow_html=True)

m_col1, m_col2, m_col3, m_col4 = st.columns(4)

# delta_color="off" forces the delta indicator to be neutral/grey instead of red/green
with m_col1:
    st.metric("Telemetry Logs Ingested", f"{len(df_alerts):,}", delta="Live Stream Active", delta_color="off")
with m_col2:
    critical_alerts_count = len(df_alerts[df_alerts['risk_score'] >= 8.0])
    st.metric("Critical Alerts (Risk ≥ 8.0)", critical_alerts_count, delta=f"{critical_alerts_count} Unresolved", delta_color="off")
with m_col3:
    budget_idx = max(1, int(len(df_alerts) * 0.01))
    avg_budget_score = df_alerts['risk_score'].iloc[:budget_idx].mean() if len(df_alerts) > 0 else 0.0
    st.metric("Top 1% Alert Budget Avg Risk", f"{avg_budget_score:.2f} / 10.0", delta="Budget Enforced", delta_color="off")
with m_col4:
    unique_entities = df_alerts['entity_id'].nunique()
    st.metric("Active Monitored Entities", unique_entities, delta="Entities", delta_color="off")

st.markdown("---")


# --- Layout Division: Prioritized Queue vs Taxonomy Charts ---
left_pane, right_pane = st.columns([3, 2], gap="large")

with left_pane:
    st.markdown('<div class="sub-header">Prioritized Analyst Threat Triage Queue</div>', unsafe_allow_html=True)
    st.markdown("<span style='color:#8c8c8c; font-size:14px;'>*Showing active alerts matching safety constraints ordered by urgency indices.*</span>", unsafe_allow_html=True)
    
    display_queue = filtered_df[filtered_df['predicted_anomaly'] != 'Normal'].copy()
    
    if len(display_queue) == 0:
        st.info("Zero anomalous behavior paths identified matching active filtering constraints.")
    else:
        # Grayscale conditional formatting for the dataframe
        def style_risk_indices(val):
            if val >= 8.5: return 'background-color: #d9d9d9; color: #000000; font-weight: bold;'
            if val >= 7.0: return 'background-color: #595959; color: #ffffff; font-weight: bold;'
            return 'color: #8c8c8c;'

        st.dataframe(
            display_queue[['timestamp', 'entity_id', 'entity_type', 'predicted_anomaly', 'risk_score', 'explanation']]
            .style.map(style_risk_indices, subset=['risk_score']),
            use_container_width=True,
            hide_index=True
        )

with right_pane:
    st.markdown('<div class="sub-header">Ingested Threat Taxonomy Split</div>', unsafe_allow_html=True)
    anomaly_counts = df_alerts[df_alerts['predicted_anomaly'] != 'Normal']['predicted_anomaly'].value_counts().reset_index()
    
    if len(anomaly_counts) == 0:
        st.info("No threat distributions to visualize.")
    else:
        # Strict grayscale color sequence for Plotly
        fig = px.pie(
            anomaly_counts, names='predicted_anomaly', values='count',
            color_discrete_sequence=px.colors.sequential.Greys_r,
            hole=0.4
        )
        # Make chart background transparent to blend with CSS
        fig.update_layout(
            margin=dict(t=10, b=10, l=10, r=10), 
            height=320,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#b0b0b0')
        )
        st.plotly_chart(fig, use_container_width=True)

st.markdown("---")


# --- Entity Deep Dive Investigation Layer ---
st.markdown('<div class="sub-header">Contextual Deep-Dive Profile Investigation</div>', unsafe_allow_html=True)
target_entity = st.selectbox("Select Target Entity ID for Timeline Forensics:", df_alerts['entity_id'].unique())

if target_entity:
    entity_history = df_alerts[df_alerts['entity_id'] == target_entity].sort_values(by='timestamp', ascending=True)
    
    hist_col1, hist_col2 = st.columns([2, 1], gap="large")
    
    with hist_col1:
        # Grayscale line chart
        fig_timeline = px.line(
            entity_history, x='timestamp', y='risk_score', markers=True,
            labels={'risk_score': 'Risk Score Index', 'timestamp': 'Event Timestamp'},
            color_discrete_sequence=['#ffffff']
        )
        fig_timeline.update_layout(
            height=350,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color='#b0b0b0'),
            title=dict(text=f"Risk Score Progression Profile Over Time for {target_entity}", font=dict(color='#ffffff'))
        )
        # Mute grid lines to match theme
        fig_timeline.update_xaxes(showgrid=True, gridwidth=1, gridcolor='#333333')
        fig_timeline.update_yaxes(showgrid=True, gridwidth=1, gridcolor='#333333')
        st.plotly_chart(fig_timeline, use_container_width=True)
        
    with hist_col2:
        st.markdown(f"<div style='margin-bottom:15px; font-weight:bold; color:#ffffff;'>Entity Metadata Overview: {target_entity}</div>", unsafe_allow_html=True)
        st.markdown(f"- **Primary Component Type:** `{entity_history['entity_type'].iloc[0]}`")
        st.markdown(f"- **Total Tracked Sessions:** `{len(entity_history)}` entries")
        st.markdown(f"- **Max Logged Risk Index:** `{entity_history['risk_score'].max():.2f}`")
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        last_anomaly = entity_history[entity_history['predicted_anomaly'] != 'Normal']
        if len(last_anomaly) > 0:
            st.markdown(f"""
            <div style="background-color:#333333; padding:15px; border-radius:5px; border-left:4px solid #ffffff; margin-bottom:10px;">
                <strong style="color:#ffffff;">Recent Classification:</strong><br>
                <span style="color:#d3d3d3;">{last_anomaly['predicted_anomaly'].iloc[-1]}</span>
            </div>
            <div style="background-color:#1a1a1a; padding:15px; border-radius:5px; border:1px solid #404040;">
                <strong style="color:#8c8c8c;">Explanation:</strong><br>
                <span style="color:#b0b0b0;">{last_anomaly['explanation'].iloc[-1]}</span>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div style="background-color:#262626; padding:15px; border-radius:5px; border-left:4px solid #8c8c8c;">
                <span style="color:#b0b0b0;">Behavior remains bound within historical baseline limits.</span>
            </div>
            """, unsafe_allow_html=True)
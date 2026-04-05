import streamlit as st
import pandas as pd
import joblib
import time
import os

# -------------------------------------------------
# Page Config
# -------------------------------------------------
st.set_page_config(page_title="IoT IDS Dashboard", layout="wide")
st.title("🔐Intrusion Detection System")

THRESHOLD = 0.6

# -------------------------------------------------
# Load Model
# -------------------------------------------------
model = joblib.load("rf_model.joblib")
TRAIN_FEATURES = list(model.feature_names_in_)

# -------------------------------------------------
# Sidebar
# -------------------------------------------------
st.sidebar.header("Select Mode")
mode = st.sidebar.radio(
    "Input Method",
    ["Upload CSV File", "Live MQTT Monitoring"]
)

# =================================================
# LIVE MONITORING MODE
# =================================================
if mode == "Live MQTT Monitoring":

    st.subheader("📡 Real-Time IoT Network Monitoring")

    if not os.path.exists("live_data.csv"):
        st.info("Waiting for live data stream...")
        st.stop()

    data = pd.read_csv("live_data.csv")

    total_packets = len(data)
    attack_count = (data["prediction"] == 1).sum()
    latest_score = data["anomaly_score"].iloc[-1]

    col1, col2, col3 = st.columns(3)
    col1.metric("Total Packets", total_packets)
    col2.metric("Attacks Detected", attack_count)
    col3.metric("Latest Anomaly Score", round(latest_score, 3))

    # ----------- Professional Area Chart -----------
    st.subheader("📊 Intrusion Probability Monitor")
    recent = data.tail(100)

    st.area_chart(recent["anomaly_score"])

    # ----------- Threshold Indicator -----------
    recent_scores = data["anomaly_score"].tail(5)
    recent_attacks = (data["prediction"].tail(5) == 1).sum()

    if recent_attacks > 0:
        st.error("⚠️ LIVE INTRUSION DETECTED")
    elif latest_score >= THRESHOLD:
        st.error("⚠️ LIVE INTRUSION DETECTED")
    else:
        st.success("✅ Network Operating Normally")
    # ----------- Recent Table -----------
    st.subheader("📋 Recent Traffic Events")
    st.dataframe(
        recent[["anomaly_score", "prediction"]].tail(20),
        width="stretch"
    )

    time.sleep(2)
    st.rerun()

# =================================================
# CSV ANALYSIS MODE (UNCHANGED CORE LOGIC)
# =================================================
else:

    uploaded_file = st.sidebar.file_uploader("Upload CSV File", type=["csv"])

    if uploaded_file:

        data = pd.read_csv(uploaded_file)
        X = data.copy()

        for col in TRAIN_FEATURES:
            if col not in X.columns:
                X[col] = 0

        X = X[TRAIN_FEATURES]

        probs = model.predict_proba(X)[:, 1]
        data["anomaly_score"] = probs
        data["prediction"] = (probs >= THRESHOLD).astype(int)

        st.subheader("📊 Batch Analysis Results")

        col1, col2 = st.columns(2)
        col1.metric("Total Flows", len(data))
        col2.metric("High Risk Intrusions", data["prediction"].sum())

        st.area_chart(data["anomaly_score"].tail(300))

        st.dataframe(
            data[["anomaly_score", "prediction"]].head(50),
            width="stretch"
        )

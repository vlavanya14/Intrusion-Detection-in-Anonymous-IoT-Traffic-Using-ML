# feature_extractor.py

import json
import ssl
import os
import pandas as pd
import paho.mqtt.client as mqtt
import joblib

# -----------------------------
# HiveMQ Credentials
# -----------------------------
BROKER = "3698a45a8d964ea5a18398d6fee3ad2d.s1.eu.hivemq.cloud"
PORT = 8883
USERNAME = "Capstone_project"
PASSWORD = "Project12345"
TOPIC = "agriot/sensor/data"

OUTPUT_FILE = "live_data.csv"

# -----------------------------
# Load Model
# -----------------------------
model = joblib.load("rf_model.joblib")
THRESHOLD = 0.6

MODEL_COLUMNS = list(model.feature_names_in_)

# -----------------------------
# Preprocess
# -----------------------------
def preprocess(df):
    for col in MODEL_COLUMNS:
        if col not in df.columns:
            df[col] = 0
    return df[MODEL_COLUMNS]

# -----------------------------
# MQTT Callbacks
# -----------------------------
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("✅ Extractor Connected")
        client.subscribe(TOPIC)

def on_message(client, userdata, msg):
    payload = json.loads(msg.payload.decode())
    print("📩 Received:", payload)

    df = pd.DataFrame([payload])
    df = preprocess(df)

    prob = model.predict_proba(df)[0][1]
    prediction = 1 if prob >= THRESHOLD else 0

    print("🚨 Prediction:", prediction, "Score:", round(prob, 3))

    row = payload.copy()
    row["prediction"] = prediction
    row["anomaly_score"] = prob

    df_out = pd.DataFrame([row])

    if not os.path.exists(OUTPUT_FILE):
        df_out.to_csv(OUTPUT_FILE, index=False)
    else:
        df_out.to_csv(OUTPUT_FILE, mode="a", header=False, index=False)

# -----------------------------
# MQTT Setup
# -----------------------------
client = mqtt.Client()
client.username_pw_set(USERNAME, PASSWORD)
client.tls_set()
client.tls_insecure_set(True)

client.on_connect = on_connect
client.on_message = on_message

client.connect(BROKER, PORT)
client.loop_forever()

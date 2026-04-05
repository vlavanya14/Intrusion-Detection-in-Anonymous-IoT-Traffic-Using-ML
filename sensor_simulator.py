# sensor_simulator.py

import pandas as pd
import json
import time
import random
import ssl
import paho.mqtt.client as mqtt

# -----------------------------
# HiveMQ Credentials
# -----------------------------
BROKER = "3698a45a8d964ea5a18398d6fee3ad2d.s1.eu.hivemq.cloud"
PORT = 8883
USERNAME = "Capstone_project"
PASSWORD = "Project12345"
TOPIC = "agriot/sensor/data"

# -----------------------------
# Load Real Dataset
# -----------------------------
data = pd.read_csv("archive/data_1.csv")

# Keep only model features
model_columns = [
    "stime","ltime","dur","mean","stddev",
    "dmac","sum","min","max","rate","srate","drate","attack"
]

data = data[model_columns]

normal_data = data[data["attack"] == 0]
attack_data = data[data["attack"] == 1]

# -----------------------------
# MQTT Setup
# -----------------------------
client = mqtt.Client()
client.username_pw_set(USERNAME, PASSWORD)
client.tls_set()
client.tls_insecure_set(True)

client.connect(BROKER, PORT)
client.loop_start()

print("✅ Real Dataset Simulator Running")

# -----------------------------
# Publish Loop
# -----------------------------
while True:

    # 20% attack
    if random.randint(1,10) <= 2:
        row = attack_data.sample(1).iloc[0]
    else:
        row = normal_data.sample(1).iloc[0]

    payload = row.drop("attack").to_dict()

    client.publish(TOPIC, json.dumps(payload))
    print("📡 Sent:", payload)

    time.sleep(2)

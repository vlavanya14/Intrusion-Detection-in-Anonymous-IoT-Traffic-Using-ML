
import json
import logging
import pandas as pd
import joblib
import os
import paho.mqtt.client as mqtt

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

# ── Broker Config ─────────────────────────────
BROKER_URL  = "broker.hivemq.com"
BROKER_PORT = 1883
TOPIC       = "agiot/ids/traffic"

# ── Paths ─────────────────────────────────────
MODEL_PATH = "rf_model.joblib"
OUTPUT_CSV = "live_data.csv"
THRESHOLD  = 0.5

# ── Load Model ────────────────────────────────
log.info("Loading RF model...")
try:
    model = joblib.load(MODEL_PATH)
    TRAIN_FEATURES = list(model.feature_names_in_)
    log.info(f"✅ Model loaded — {len(TRAIN_FEATURES)} features")
    log.info(f"📋 Features: {TRAIN_FEATURES}")
except Exception as e:
    log.error(f"❌ Model load failed: {e}")
    exit(1)

# ── Packet Counter ────────────────────────────
packet_counter = 0

# ── Init CSV ──────────────────────────────────
def init_csv():
    if os.path.exists(OUTPUT_CSV):
        os.remove(OUTPUT_CSV)
        log.info("🗑 Old live_data.csv removed")

    df = pd.DataFrame(
        columns=["packet_no", "stime", "ltime", "dur",
                 "mean", "stddev", "dmac", "sum",
                 "min", "max", "rate", "srate", "drate",
                 "anomaly_score", "prediction"]
    )
    df.to_csv(OUTPUT_CSV, index=False)
    log.info(f"✅ Created fresh {OUTPUT_CSV}")

# ── Build Feature Vector (for RF model) ───────
def build_feature_vector(raw: dict):
    try:
        row = {}
        for feature in TRAIN_FEATURES:
            if feature == "dmac":
                row["dmac"] = 0.0
            elif feature in raw:
                try:
                    row[feature] = float(raw[feature])
                except:
                    row[feature] = 0.0
            else:
                row[feature] = 0.0
        return pd.DataFrame([row])
    except Exception as e:
        log.error(f"Feature build error: {e}")
        return None

# ── Rule Based Detection (for attacks) ────────
def detect(raw: dict) -> tuple:
    try:
        rate   = float(raw.get("rate",   0))
        pkts   = float(raw.get("pkts",   0))
        bytes_ = float(raw.get("bytes",  0))
        dur    = float(raw.get("dur",    1))
        dport  = int(float(raw.get("dport", 0)))
        proto  = str(raw.get("proto",   "")).lower()
        srate  = float(raw.get("srate",  0))
        stddev = float(raw.get("stddev", 0))

        score   = 0.0
        reasons = []

        # DoS/DDoS
        if rate > 50000:
            score += 0.60
            reasons.append(f"DoS rate={rate:.0f}")
        elif rate > 10000:
            score += 0.40
            reasons.append(f"High rate={rate:.0f}")
        elif rate > 1000:
            score += 0.20
            reasons.append(f"Med rate={rate:.0f}")

        # Packet Flood
        if pkts > 1000:
            score += 0.40
            reasons.append(f"Flood pkts={pkts:.0f}")
        elif pkts > 500:
            score += 0.25
            reasons.append(f"High pkts={pkts:.0f}")
        elif pkts > 100:
            score += 0.10
            reasons.append(f"Med pkts={pkts:.0f}")

        # Data Exfiltration
        if bytes_ > 200000:
            score += 0.30
            reasons.append(f"Exfil bytes={bytes_:.0f}")
        elif bytes_ > 50000:
            score += 0.15
            reasons.append(f"High bytes={bytes_:.0f}")

        # Suspicious Ports
        if dport in [23, 21, 3389, 445, 1433, 3306]:
            score += 0.40
            reasons.append(f"Malicious port={dport}")
        elif dport in [22, 8080, 8443]:
            score += 0.20
            reasons.append(f"Suspicious port={dport}")
        elif 0 < dport < 1024 and dport not in [80, 443, 53, 25]:
            score += 0.15
            reasons.append(f"Low port={dport}")

        # Protocol Anomaly
        if proto == "icmp" and pkts > 50:
            score += 0.35
            reasons.append("ICMP flood")
        elif proto == "arp" and pkts > 100:
            score += 0.35
            reasons.append("ARP flood")

        # Burst Attack
        if dur < 0.01 and pkts > 200:
            score += 0.35
            reasons.append("Burst attack")
        elif dur < 0.1 and pkts > 100:
            score += 0.20
            reasons.append("Short burst")

        # High Source Rate
        if srate > 50000:
            score += 0.25
            reasons.append(f"srate={srate:.0f}")

        # Stddev Anomaly
        if stddev > 400:
            score += 0.20
            reasons.append(f"stddev={stddev:.0f}")

        score      = min(round(score, 4), 1.0)
        prediction = 1 if score >= THRESHOLD else 0

        return prediction, score, reasons

    except Exception as e:
        log.error(f"Detection error: {e}")
        return 0, 0.0, []

# ── Predict and Save ──────────────────────────
def predict_and_save(raw: dict):
    global packet_counter
    packet_counter += 1

    try:
        # ── Rule based detection ──────────────────
        rule_pred, rule_score, reasons = detect(raw)

        # ── RF Model score ────────────────────────
        X = build_feature_vector(raw)
        if X is not None:
            model_score = float(model.predict_proba(X)[:, 1][0])
        else:
            model_score = 0.0

        # ── Final Decision ────────────────────────
        # Attack → use rule score
        # Normal → use RF model score
        if rule_pred == 1:
            final_score = rule_score
            prediction  = 1
        else:
            final_score = model_score
            prediction  = 0

        # --- Simple Reward-Based Threshold Update ---
        global THRESHOLD

        # Assume: rule_pred is closer to ground truth (or use prediction logic)
        if prediction == rule_pred:
            THRESHOLD = min(THRESHOLD + 0.01, 1.0)   # reward → increase threshold
        else:
            THRESHOLD = max(THRESHOLD - 0.01, 0.0)   # penalty → decrease threshold

        log.info(f"Updated Threshold: {THRESHOLD:.2f}")

        # ── Save to CSV ───────────────────────────
        row = {
            "packet_no"    : packet_counter,
            "stime"        : float(raw.get("stime",  0)),
            "ltime"        : float(raw.get("ltime",  0)),
            "dur"          : float(raw.get("dur",    0)),
            "mean"         : float(raw.get("mean",   0)),
            "stddev"       : float(raw.get("stddev", 0)),
            "dmac"         : final_score * 1000000,
            "sum"          : float(raw.get("sum",    0)),
            "min"          : float(raw.get("min",    0)),
            "max"          : float(raw.get("max",    0)),
            "rate"         : float(raw.get("rate",   0)),
            "srate"        : float(raw.get("srate",  0)),
            "drate"        : float(raw.get("drate",  0)),
            "anomaly_score": round(final_score, 4),
            "prediction"   : prediction
        }

        result_df    = pd.DataFrame([row])
        write_header = not os.path.exists(OUTPUT_CSV) or \
                       os.path.getsize(OUTPUT_CSV) == 0

        result_df.to_csv(
            OUTPUT_CSV,
            mode="a",
            header=write_header,
            index=False
        )

        status = "⚠  ATTACK" if prediction == 1 else "✓  Normal"
        log.info(
            f"Packet #{packet_counter} | "
            f"{status} | "
            f"Score: {final_score:.4f}"
        )
        if reasons:
            log.info(f"Reasons : {', '.join(reasons)}")

    except Exception as e:
        log.error(f"Prediction error: {e}")

# ── Trim CSV ──────────────────────────────────
def trim_csv(max_rows=500):
    try:
        if os.path.exists(OUTPUT_CSV):
            df = pd.read_csv(OUTPUT_CSV)
            if len(df) > max_rows:
                df.tail(max_rows).to_csv(
                    OUTPUT_CSV, index=False
                )
    except Exception as e:
        log.error(f"CSV trim error: {e}")

# ── MQTT Callbacks ────────────────────────────
def on_connect(client, userdata, flags, rc):
    if rc == 0:
        log.info("✅ Connected to broker.hivemq.com!")
        client.subscribe(TOPIC, qos=0)
        log.info(f"✅ Subscribed to: {TOPIC}")
    else:
        log.error(f"❌ Failed rc={rc}")

def on_message(client, userdata, msg):
    try:
        raw = json.loads(msg.payload.decode("utf-8"))
        log.info(f"📦 Packet #{raw.get('pkSeqID','?')}")
        predict_and_save(raw)
        trim_csv()
    except json.JSONDecodeError:
        log.error("Bad JSON")
    except Exception as e:
        log.error(f"Error: {e}")

def on_disconnect(client, userdata, rc):
    log.warning(f"⚠ Disconnected rc={rc}")

# ── Main ──────────────────────────────────────
def main():
    log.info("=" * 45)
    log.info("  AgIoT IDS — Feature Extractor     ")
    log.info("  Hybrid: Rules + RF Model           ")
    log.info("=" * 45)

    init_csv()

    client = mqtt.Client(
        client_id="agiot-extractor",
        clean_session=True,
        protocol=mqtt.MQTTv311
    )

    client.on_connect    = on_connect
    client.on_message    = on_message
    client.on_disconnect = on_disconnect

    client.reconnect_delay_set(min_delay=1, max_delay=5)

    try:
        log.info(f"Connecting to {BROKER_URL}:{BROKER_PORT}...")
        client.connect(BROKER_URL, BROKER_PORT, keepalive=60)
        log.info("✅ Connection initiated!")
        log.info("Listening... (Ctrl+C to stop)")
        client.loop_forever()
    except Exception as e:
        log.error(f"Connection error: {e}")
        exit(1)

if __name__ == "__main__":
    main()

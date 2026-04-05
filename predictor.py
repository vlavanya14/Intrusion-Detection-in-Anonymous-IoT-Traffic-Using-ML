# predictor.py

import joblib
import os

MODEL_PATH = "rf_model.joblib"

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"Model file not found at {MODEL_PATH}")

model = joblib.load(MODEL_PATH)

print("✅ Random Forest model loaded successfully")

def predict_attack(df):
    prediction = model.predict(df)
    return int(prediction[0])

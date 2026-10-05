"""
TrustGuard - Dynamic Zero Trust Access Control for Land Records Management
ML Service: Scikit-learn Isolation Forest via FastAPI
Trained on sample activity dataset across 6 core behavioral indicators:
  1. login_hour (Normal range: 7 to 19)
  2. records_viewed (Normal range: 1 to 20)
  3. downloads_count (Normal range: 0 to 5)
  4. requests_per_minute (Normal range: 1.8 to 14.2)
  5. failed_operations (Normal range: 0 to 3)
  6. session_duration_minutes (Normal range: 5 to 118)
"""

import os
import json
from typing import List, Optional
import numpy as np
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sklearn.ensemble import IsolationForest
import joblib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.join(BASE_DIR, "models")
MODEL_PATH = os.path.join(MODELS_DIR, "isolation_forest.joblib")
THRESHOLDS_PATH = os.path.join(MODELS_DIR, "thresholds.json")

app = FastAPI(
    title="TrustGuard ML Anomaly Detector",
    description="Isolation Forest behavioral anomaly engine for Zero Trust continuous session evaluation",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class BehavioralFeatures(BaseModel):
    login_hour: int = Field(..., ge=0, le=23, description="Hour of login/request (0-23)")
    records_viewed: int = Field(0, ge=0, description="Cumulative count of land records inspected in session")
    downloads_count: int = Field(0, ge=0, description="Count of document downloads initiated in session")
    requests_per_minute: float = Field(0.0, ge=0.0, description="Current rolling requests per minute")
    failed_operations: int = Field(0, ge=0, description="Count of failed actions or unauthorized attempts")
    session_duration_minutes: float = Field(0.0, ge=0.0, description="Elapsed session duration in minutes")
    ip_mismatch: Optional[int] = Field(0, ge=0, le=1)
    device_mismatch: Optional[int] = Field(0, ge=0, le=1)

class PredictionResponse(BaseModel):
    isolation_forest_score: float
    is_anomaly: bool
    normalized_anomaly_score: float
    ml_risk: float
    anomaly_reasons: List[str]
    details: str

model = None
s5 = None
s95 = None

def load_or_train_model():
    global model, s5, s95
    if os.path.exists(MODEL_PATH) and os.path.exists(THRESHOLDS_PATH):
        try:
            model = joblib.load(MODEL_PATH)
            with open(THRESHOLDS_PATH, "r") as f:
                data = json.load(f)
                s5 = float(data["s5"])
                s95 = float(data["s95"])
            return
        except Exception as e:
            print(f"[ML Service] Loading error: {e}. Retraining...")

    csv_path = os.path.join(BASE_DIR, "data", "activity_dataset.csv")
    if os.path.exists(csv_path):
        import pandas as pd
        df = pd.read_csv(csv_path)
        feature_names = ["login_hour", "records_viewed", "downloads_count", "requests_per_minute", "failed_operations", "session_duration_minutes"]
        X = df[feature_names].values
        model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
        model.fit(X)
        scores = model.decision_function(X)
        s5 = float(np.percentile(scores, 5))
        s95 = float(np.percentile(scores, 95))
        os.makedirs(MODELS_DIR, exist_ok=True)
        joblib.dump(model, MODEL_PATH)
        with open(THRESHOLDS_PATH, "w") as f:
            json.dump({"features": feature_names, "s5": s5, "s95": s95}, f, indent=2)

@app.on_event("startup")
def startup_event():
    load_or_train_model()

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "TrustGuard Isolation Forest ML Engine",
        "model": "Scikit-Learn IsolationForest",
        "n_estimators": 100
    }

@app.post("/predict", response_model=PredictionResponse)
def predict_anomaly(features: BehavioralFeatures):
    global model, s5, s95
    if model is None or s5 is None or s95 is None:
        load_or_train_model()
        if model is None:
            raise HTTPException(status_code=503, detail="Model unavailable")

    try:
        sample = np.array([[
            features.login_hour,
            features.records_viewed,
            features.downloads_count,
            features.requests_per_minute,
            features.failed_operations,
            features.session_duration_minutes
        ]], dtype=float)

        ifs = float(model.decision_function(sample)[0])
        prediction = int(model.predict(sample)[0])

        if s95 != s5:
            nas = float(np.clip((s95 - ifs) / (s95 - s5), 0.0, 1.0))
        else:
            nas = 0.0

        is_anomaly = bool(prediction == -1 or nas >= 0.50)
        ml_risk = float(round(25.0 * nas, 2)) if is_anomaly else 0.0

        reasons = []
        if features.requests_per_minute > 14.2:
            reasons.append(f"Excessive document access rate ({features.requests_per_minute:.1f} req/min vs max baseline 14.2)")
        if features.records_viewed > 20:
            reasons.append(f"Abnormal record inspection volume ({features.records_viewed} records vs baseline max 20)")
        if features.downloads_count > 5:
            reasons.append(f"Unusual document download activity ({features.downloads_count} downloads vs baseline max 5)")
        if features.failed_operations > 3:
            reasons.append(f"Repeated authorization failures ({features.failed_operations} failed attempts vs baseline max 3)")
        if features.login_hour < 7 or features.login_hour > 19:
            reasons.append(f"Off-hours access anomaly (hour {features.login_hour}:00 outside baseline 07:00-19:00)")

        if not reasons:
            if is_anomaly:
                reasons.append(f"Isolation Forest identified behavioral divergence (NAS: {nas:.2f})")
            else:
                reasons.append("Behavioral profile is within normal baseline parameters")

        return PredictionResponse(
            isolation_forest_score=round(ifs, 4),
            is_anomaly=is_anomaly,
            normalized_anomaly_score=round(nas, 4),
            ml_risk=ml_risk,
            anomaly_reasons=reasons,
            details="; ".join(reasons)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("ml_service:app", host="127.0.0.1", port=8000, reload=False)

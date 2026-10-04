"""
TrustGuard - Dynamic Zero Trust Access Control for Land Records Management
ML Service: Scikit-learn Isolation Forest via FastAPI
"""

import numpy as np
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sklearn.ensemble import IsolationForest

app = FastAPI(
    title="TrustGuard ML Anomaly Detector",
    description="Isolation Forest behavioral anomaly engine for Zero Trust continuous session evaluation",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class SessionFeatures(BaseModel):
    ipMismatch: int = Field(0, description="1 if IP differs from baseline, else 0")
    deviceMismatch: int = Field(0, description="1 if device fingerprint mismatch, else 0")
    nightAccess: int = Field(0, description="1 if accessed outside normal office hours, else 0")
    outsideJurisdiction: int = Field(0, description="1 if accessing outside assigned taluk/village, else 0")
    spamTriggered: int = Field(0, description="1 if rapid API spikes detected, else 0")
    idleTriggered: int = Field(0, description="1 if burst action after long idle, else 0")
    failedActionCount: int = Field(0, ge=0, description="Count of recent failed actions/authorizations")
    requestHour: int = Field(12, ge=0, le=23, description="Hour of request (0-23)")
    trustScoreBaseline: float = Field(75.0, description="Current rule-based trust score")


class PredictionResponse(BaseModel):
    anomalyScore: float
    isAnomaly: bool
    riskPenalty: int
    source: str
    details: str


# Initialize and train Isolation Forest on synthetic baseline of normal and anomalous activity
np.random.seed(42)

# Normal behaviors: mostly zeros, daytime hours (9-18), 0-1 failed actions, high baseline score
normal_data = np.column_stack([
    np.random.choice([0, 1], size=1000, p=[0.96, 0.04]),  # ipMismatch
    np.random.choice([0, 1], size=1000, p=[0.97, 0.03]),  # deviceMismatch
    np.random.choice([0, 1], size=1000, p=[0.95, 0.05]),  # nightAccess
    np.random.choice([0, 1], size=1000, p=[0.98, 0.02]),  # outsideJurisdiction
    np.random.choice([0, 1], size=1000, p=[0.98, 0.02]),  # spamTriggered
    np.random.choice([0, 1], size=1000, p=[0.96, 0.04]),  # idleTriggered
    np.random.poisson(0.2, size=1000),                    # failedActionCount
    np.random.normal(13, 3, size=1000).clip(8, 18),       # requestHour
    np.random.normal(85, 8, size=1000).clip(60, 100),     # trustScoreBaseline
])

# Synthetic anomalous behavior samples
threat_data = np.column_stack([
    np.random.choice([0, 1], size=100, p=[0.2, 0.8]),     # ipMismatch
    np.random.choice([0, 1], size=100, p=[0.1, 0.9]),     # deviceMismatch
    np.random.choice([0, 1], size=100, p=[0.3, 0.7]),     # nightAccess
    np.random.choice([0, 1], size=100, p=[0.2, 0.8]),     # outsideJurisdiction
    np.random.choice([0, 1], size=100, p=[0.4, 0.6]),     # spamTriggered
    np.random.choice([0, 1], size=100, p=[0.5, 0.5]),     # idleTriggered
    np.random.poisson(3.5, size=100),                     # failedActionCount
    np.random.choice([1, 2, 3, 22, 23], size=100),       # requestHour (night)
    np.random.normal(35, 12, size=100).clip(0, 60),       # trustScoreBaseline
])

training_matrix = np.vstack([normal_data, threat_data])

model = IsolationForest(
    n_estimators=100,
    contamination=0.1,
    random_state=42
)
model.fit(training_matrix)


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "TrustGuard Isolation Forest ML Engine",
        "model": "Scikit-Learn IsolationForest",
        "n_estimators": 100
    }


@app.post("/predict", response_model=PredictionResponse)
def predict_anomaly(features: SessionFeatures):
    try:
        sample = np.array([[
            features.ipMismatch,
            features.deviceMismatch,
            features.nightAccess,
            features.outsideJurisdiction,
            features.spamTriggered,
            features.idleTriggered,
            features.failedActionCount,
            features.requestHour,
            features.trustScoreBaseline
        ]])

        # decision_function yields negative values for anomalies, positive for inliers
        raw_score = model.decision_function(sample)[0]
        # prediction: 1 for inlier, -1 for anomaly
        prediction = model.predict(sample)[0]

        # Normalize score into [0.0, 1.0] where 1.0 is extremely anomalous
        # decision_function typically ranges from -0.35 to +0.25
        normalized_score = float(np.clip(1.0 - (raw_score + 0.35) / 0.60, 0.0, 1.0))
        is_anomaly = bool(prediction == -1 or normalized_score >= 0.50)

        # Calculate risk penalty points (0 - 25 points)
        risk_penalty = int(round(normalized_score * 25)) if is_anomaly else 0

        reasons = []
        if features.deviceMismatch:
            reasons.append("Unrecognized device fingerprint")
        if features.ipMismatch:
            reasons.append("Network IP route drift")
        if features.outsideJurisdiction:
            reasons.append("Cross-jurisdiction mutation access attempt")
        if features.nightAccess:
            reasons.append("Off-hours session access")
        if features.spamTriggered:
            reasons.append("Burst API request spike")
        if features.failedActionCount > 1:
            reasons.append(f"Repeated unauthorized attempts ({features.failedActionCount})")

        detail_text = "; ".join(reasons) if reasons else "Normal session profile"

        return PredictionResponse(
            anomalyScore=round(normalized_score, 3),
            isAnomaly=is_anomaly,
            riskPenalty=risk_penalty,
            source="fastapi_isolation_forest",
            details=detail_text
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("ml_service:app", host="127.0.0.1", port=8000, reload=True)

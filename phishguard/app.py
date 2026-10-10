"""API de prédiction avec métriques Prometheus."""
import json
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

import joblib
from fastapi import FastAPI, HTTPException, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from pydantic import BaseModel, Field

from .features import extract_features

KNOWN_PATHS = {"/predict", "/health", "/ready", "/model-info"}

REQUEST_LATENCY = Histogram("http_request_duration_seconds", "Latence HTTP",
                            ["method", "path"])
REQUESTS = Counter("http_requests_total", "Requêtes HTTP", ["method", "path", "status"])
PREDICTIONS = Counter("model_predictions_total", "Prédictions par label", ["label"])
SCORES = Histogram("model_phishing_score", "Distribution des scores de phishing",
                   buckets=[i / 10 for i in range(11)])
URL_LENGTH = Histogram("model_input_url_length", "Longueur des URLs reçues",
                       buckets=[20, 40, 60, 80, 100, 150, 200, 400, 2048])

state = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    model_dir = Path(os.getenv("MODEL_DIR", "models"))
    state["model"] = joblib.load(model_dir / "model.joblib")
    state["meta"] = json.loads((model_dir / "metadata.json").read_text())
    state["threshold"] = float(os.getenv("PHISHING_THRESHOLD", "0.5"))
    yield
    state.clear()


app = FastAPI(title="PhishGuard API", version="0.1.0", lifespan=lifespan)


@app.middleware("http")
async def instrument(request: Request, call_next):
    path = request.url.path if request.url.path in KNOWN_PATHS else "other"
    start = time.perf_counter()
    response = await call_next(request)
    REQUEST_LATENCY.labels(request.method, path).observe(time.perf_counter() - start)
    REQUESTS.labels(request.method, path, str(response.status_code)).inc()
    return response


class UrlRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)


class PredictResponse(BaseModel):
    label: str
    phishing_score: float


@app.get("/health")
def health():
    """Liveness : le processus tourne."""
    return {"status": "ok"}


@app.get("/ready")
def ready():
    """Readiness : le modèle est chargé."""
    if "model" not in state:
        raise HTTPException(status_code=503, detail="model not loaded")
    return {"status": "ready"}


@app.get("/model-info")
def model_info():
    if "meta" not in state:
        raise HTTPException(status_code=503, detail="model not loaded")
    return state["meta"]


@app.post("/predict", response_model=PredictResponse)
def predict(req: UrlRequest):
    if "model" not in state:
        raise HTTPException(status_code=503, detail="model not loaded")
    score = float(state["model"].predict_proba([extract_features(req.url)])[0][1])
    label = "phishing" if score >= state["threshold"] else "legitimate"
    PREDICTIONS.labels(label).inc()
    SCORES.observe(score)
    URL_LENGTH.observe(len(req.url))
    return PredictResponse(label=label, phishing_score=round(score, 4))


@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

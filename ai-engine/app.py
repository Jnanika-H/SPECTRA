"""
SPECTRA — Phase 2: Flask AI Service
=====================================
REST API wrapping the trained ML models.

Endpoints:
  POST /score     → threat score (0-100) for a single artifact
  POST /anomaly   → anomaly detection result
  POST /timeline  → build chronological timeline from artifact batch
  GET  /health    → service health check
  POST /retrain   → trigger model retraining from feedback (self-learning)

Run:
  export FLASK_ENV=development
  python app.py
  # or:
  gunicorn -w 4 -b 0.0.0.0:5001 app:app
"""

import os
import sys
import json
import logging
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from functools import wraps

from flask import Flask, request, jsonify, abort
from flask_cors import CORS

# Add parent dirs to path
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "ai-engine"))
sys.path.insert(0, str(Path(__file__).parent.parent / "ingestion"))

from train_models import (
    load_models, predict_threat_score, predict_anomaly,
    SYSTEM_FEATURES, generate_demo_data, train_threat_scorer,
    train_anomaly_detector, save_models
)
from timeline_engine import build_timeline, render_text_timeline
from evidence_collector import compute_final_score, classify_severity

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("spectra.flask")

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# ── Model state ───────────────────────────────────────────────────────────────
clf = None
iso = None
_models_loaded = False

API_KEY = os.getenv("SPECTRA_API_KEY", "spectra-dev-key-change-in-prod")


def load_or_init_models():
    """Load persisted models; fall back to training a demo model if missing."""
    global clf, iso, _models_loaded
    try:
        clf, iso = load_models()
        _models_loaded = True
        log.info("✔ Loaded persisted models")
    except FileNotFoundError:
        log.warning("No saved models found — training demo models …")
        X, y = generate_demo_data(n_samples=5000)
        clf = train_threat_scorer(X, y)
        iso = train_anomaly_detector(X)
        save_models(clf, iso)
        _models_loaded = True
        log.info("✔ Demo models trained and saved")


# ── Auth decorator ────────────────────────────────────────────────────────────

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key") or request.args.get("api_key")
        if key != API_KEY:
            abort(401, description="Invalid or missing API key")
        return f(*args, **kwargs)
    return decorated


# ── Helpers ───────────────────────────────────────────────────────────────────

def _validate_features(data: dict) -> tuple[dict, list[str]]:
    """Extract and coerce ML feature vector. Returns (features, errors)."""
    errors = []
    features = {}
    for f in SYSTEM_FEATURES:
        val = data.get(f)
        if val is None:
            features[f] = 0.0
        else:
            try:
                features[f] = float(val)
            except (TypeError, ValueError):
                errors.append(f"Invalid value for '{f}': {val}")
    return features, errors


def _success(data: dict, status: int = 200):
    return jsonify({"status": "success", "timestamp": datetime.now(tz=timezone.utc).isoformat(), **data}), status


def _error(msg: str, status: int = 400):
    return jsonify({"status": "error", "message": msg, "timestamp": datetime.now(tz=timezone.utc).isoformat()}), status


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    return _success({
        "service":      "SPECTRA AI Engine",
        "models_loaded": _models_loaded,
        "features":     SYSTEM_FEATURES,
    })


@app.route("/score", methods=["POST"])
@require_api_key
def score():
    """
    Compute a 0-100 threat score for one artifact.

    Request body (JSON):
    {
        "artifact_id": "abc123",          // optional
        "network_activity":  0.8,         // ML features (0.0–1.0)
        "session_time":      0.2,
        "data_transfer":     0.9,
        "connection_status": 2,
        "rule_score":        70            // optional rule-based score to blend
    }

    Response:
    {
        "artifact_id": "abc123",
        "ml_score":    78,
        "rule_score":  70,
        "final_score": 74,
        "severity":    "high",
        "features":    { ... }
    }
    """
    if not request.is_json:
        return _error("Content-Type must be application/json")

    data = request.get_json()
    features, errs = _validate_features(data)
    if errs:
        return _error(f"Feature validation errors: {errs}")

    try:
        ml_score   = predict_threat_score(clf, features)
        rule_score = min(int(data.get("rule_score", 0)), 100)
        final      = compute_final_score(ml_score, rule_score)
        severity   = classify_severity(final)

        log.info(f"Score: artifact={data.get('artifact_id','?')} ml={ml_score} rule={rule_score} final={final}")

        return _success({
            "artifact_id": data.get("artifact_id", ""),
            "ml_score":    ml_score,
            "rule_score":  rule_score,
            "final_score": final,
            "severity":    severity,
            "features":    features,
        })
    except Exception as e:
        log.exception("Score error")
        return _error(str(e), 500)


@app.route("/anomaly", methods=["POST"])
@require_api_key
def anomaly():
    """
    Detect whether an artifact is anomalous (IsolationForest).

    Request body: same feature schema as /score

    Response:
    {
        "artifact_id": "abc123",
        "is_anomaly":  true,
        "anomaly_score": -0.15,   // raw IsolationForest score (negative = anomaly)
        "confidence":  "high"
    }
    """
    if not request.is_json:
        return _error("Content-Type must be application/json")

    data = request.get_json()
    features, errs = _validate_features(data)
    if errs:
        return _error(f"Feature validation errors: {errs}")

    try:
        import pandas as pd
        row = pd.DataFrame([features])
        raw_score  = float(iso.decision_function(row)[0])
        is_anomaly = predict_anomaly(iso, features)

        # Confidence tier based on distance from decision boundary
        abs_score = abs(raw_score)
        confidence = "high" if abs_score > 0.15 else ("medium" if abs_score > 0.05 else "low")

        log.info(f"Anomaly: artifact={data.get('artifact_id','?')} is_anomaly={is_anomaly} raw={raw_score:.3f}")

        return _success({
            "artifact_id":   data.get("artifact_id", ""),
            "is_anomaly":    is_anomaly,
            "anomaly_score": round(raw_score, 4),
            "confidence":    confidence,
        })
    except Exception as e:
        log.exception("Anomaly error")
        return _error(str(e), 500)


@app.route("/timeline", methods=["POST"])
@require_api_key
def timeline():
    """
    Build a chronological crime timeline from a batch of artifacts.

    Request body:
    {
        "artifacts": [ { artifact_dict }, ... ],
        "format": "json"   // or "text"
    }

    Response:
    {
        "timeline": { events: [...], summary: {...}, groups: {...} },
        "text_report": "..." // if format=text
    }
    """
    if not request.is_json:
        return _error("Content-Type must be application/json")

    data = request.get_json()
    artifacts = data.get("artifacts", [])

    if not isinstance(artifacts, list):
        return _error("'artifacts' must be a list")

    if len(artifacts) > 10_000:
        return _error("Too many artifacts (max 10,000 per request)")

    try:
        tl = build_timeline(artifacts)
        result = {"timeline": tl}

        if data.get("format") == "text":
            result["text_report"] = render_text_timeline(tl)

        return _success(result)
    except Exception as e:
        log.exception("Timeline error")
        return _error(str(e), 500)


@app.route("/batch_score", methods=["POST"])
@require_api_key
def batch_score():
    """
    Score multiple artifacts in one call.

    Request body:
    { "artifacts": [ {artifact_id, feature fields...}, ... ] }
    """
    if not request.is_json:
        return _error("Content-Type must be application/json")

    data = request.get_json()
    artifacts = data.get("artifacts", [])
    if not isinstance(artifacts, list):
        return _error("'artifacts' must be a list")

    results = []
    for art in artifacts:
        features, _ = _validate_features(art)
        ml_score   = predict_threat_score(clf, features)
        is_anomaly = predict_anomaly(iso, features)
        rule_score = min(int(art.get("rule_score", 0)), 100)
        final      = compute_final_score(ml_score, rule_score)

        results.append({
            "artifact_id":  art.get("artifact_id", ""),
            "final_score":  final,
            "is_anomaly":   is_anomaly,
            "severity":     classify_severity(final),
        })

    return _success({"results": results, "count": len(results)})


@app.route("/retrain", methods=["POST"])
@require_api_key
def retrain():
    """
    Self-learning: retrain models using investigator feedback stored in the DB.
    Accepts a JSON list of labelled feedback samples.

    Request body:
    {
        "samples": [
            { "features": {...}, "label": 1 },   // 1=malicious, 0=benign
            ...
        ]
    }
    """
    if not request.is_json:
        return _error("Content-Type must be application/json")

    data = request.get_json()
    samples = data.get("samples", [])

    if len(samples) < 20:
        return _error("Need at least 20 labelled samples to retrain")

    try:
        import pandas as pd

        rows, labels = [], []
        for s in samples:
            feat, errs = _validate_features(s.get("features", {}))
            if not errs:
                rows.append(feat)
                labels.append(int(s.get("label", 0)))

        X = pd.DataFrame(rows)
        import numpy as np
        y = pd.Series(labels)

        global clf, iso
        clf = train_threat_scorer(X, y)
        iso = train_anomaly_detector(X)
        save_models(clf, iso)

        log.info(f"✔ Retrained on {len(rows)} samples")
        return _success({"message": f"Models retrained on {len(rows)} samples"})
    except Exception as e:
        log.exception("Retrain error")
        return _error(str(e), 500)


# ── Error handlers ────────────────────────────────────────────────────────────

@app.errorhandler(401)
def unauthorized(e):
    return _error(str(e.description), 401)

@app.errorhandler(404)
def not_found(e):
    return _error("Endpoint not found", 404)

@app.errorhandler(405)
def method_not_allowed(e):
    return _error("Method not allowed", 405)


# ── Startup ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    load_or_init_models()
    port = int(os.getenv("PORT", 5001))
    debug = os.getenv("FLASK_ENV") == "development"
    log.info(f"Starting SPECTRA Flask AI Service on port {port}")
    app.run(host="0.0.0.0", port=port, debug=debug)
else:
    # When run via gunicorn
    load_or_init_models()

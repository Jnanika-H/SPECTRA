"""
SPECTRA — Phase 1: Dataset Preprocessing & Model Training
==========================================================
Supports: CICIDS2017, UNSW-NB15, KDD Cup 99
Models: RandomForestClassifier (threat scoring), IsolationForest (anomaly detection)

Run:  python train_models.py --dataset cicids2017 --path ./data/cicids.csv
      python train_models.py --dataset unsw      --path ./data/unsw.csv
      python train_models.py --dataset kdd        --path ./data/kdd.csv
      python train_models.py --demo               # generates synthetic data for testing
"""

import os
import argparse
import pickle
import json
import logging
import numpy as np
import pandas as pd

from pathlib import Path
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix
)
from sklearn.utils import resample

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
log = logging.getLogger("spectra.train")

# ── System-wide feature vector used at RUNTIME ─────────────────────────────
SYSTEM_FEATURES = [
    "network_activity",   # packets/sec or connection count (normalised 0-1)
    "session_time",       # session duration in seconds (normalised 0-1)
    "data_transfer",      # bytes transferred (normalised 0-1)
    "connection_status",  # 0=normal, 1=suspicious, 2=malicious
]

MODELS_DIR = Path(__file__).parent / "models"
MODELS_DIR.mkdir(exist_ok=True)

# ── Dataset column mappings ─────────────────────────────────────────────────
COLUMN_MAPS = {
    "cicids2017": {
        "network_activity": " Flow Packets/s",
        "session_time":     " Flow Duration",
        "data_transfer":    " Total Fwd Packets",
        "label_col":        " Label",
        "benign_label":     "BENIGN",
    },
    "unsw": {
        "network_activity": "rate",
        "session_time":     "dur",
        "data_transfer":    "sbytes",
        "label_col":        "label",
        "benign_label":     0,
    },
    "kdd": {
        "network_activity": "src_bytes",
        "session_time":     "duration",
        "data_transfer":    "dst_bytes",
        "label_col":        "label",
        "benign_label":     "normal.",
    },
}


# ── 1. Preprocessing ─────────────────────────────────────────────────────────

def load_and_preprocess(dataset_name: str, path: str) -> tuple[pd.DataFrame, pd.Series]:
    """Load any of the three datasets and return (X, y) aligned to SYSTEM_FEATURES."""
    log.info(f"Loading {dataset_name} from {path}")
    df = pd.read_csv(path, low_memory=False)
    log.info(f"Rows: {len(df):,}  Columns: {len(df.columns)}")

    cfg = COLUMN_MAPS[dataset_name]

    # ── a. Handle missing / infinite values
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(subset=[cfg["network_activity"], cfg["session_time"], cfg["data_transfer"]], inplace=True)
    df.fillna(df.median(numeric_only=True), inplace=True)

    # ── b. Encode categorical label → binary (0=benign, 1=malicious)
    raw_label = df[cfg["label_col"]]
    if raw_label.dtype == object:
        y = (raw_label.str.strip() != str(cfg["benign_label"])).astype(int)
    else:
        y = (raw_label != cfg["benign_label"]).astype(int)

    # ── c. Extract + rename to SYSTEM_FEATURES
    feature_cols = [cfg["network_activity"], cfg["session_time"], cfg["data_transfer"]]
    X = df[feature_cols].copy()
    X.columns = ["network_activity", "session_time", "data_transfer"]

    # ── d. Derive connection_status from label (0-2 scale)
    X["connection_status"] = y.values  # will be refined by rule-based layer at runtime

    # ── e. Normalise numeric columns to [0, 1]
    for col in ["network_activity", "session_time", "data_transfer"]:
        col_min, col_max = X[col].min(), X[col].max()
        if col_max > col_min:
            X[col] = (X[col] - col_min) / (col_max - col_min)
        else:
            X[col] = 0.0

    # ── f. Balance classes (upsample minority to prevent skew)
    X["__y__"] = y.values
    majority = X[X["__y__"] == 0]
    minority = X[X["__y__"] == 1]
    if len(minority) > 0 and len(majority) / max(len(minority), 1) > 3:
        minority_up = resample(minority, replace=True, n_samples=len(majority), random_state=42)
        X = pd.concat([majority, minority_up])
    y_balanced = X.pop("__y__")

    log.info(f"Preprocessed shape: {X.shape}  Malicious ratio: {y_balanced.mean():.2%}")
    return X.reset_index(drop=True), y_balanced.reset_index(drop=True)


def generate_demo_data(n_samples: int = 5000) -> tuple[pd.DataFrame, pd.Series]:
    """Synthetic dataset for testing without real CSVs."""
    log.info(f"Generating synthetic demo dataset ({n_samples} samples)")
    rng = np.random.default_rng(42)

    # Benign traffic: low rates, normal hours, modest transfers
    n_benign = int(n_samples * 0.7)
    benign = pd.DataFrame({
        "network_activity": rng.beta(2, 5, n_benign),
        "session_time":     rng.beta(3, 2, n_benign),
        "data_transfer":    rng.beta(2, 5, n_benign),
        "connection_status": np.zeros(n_benign, dtype=int),
    })

    # Malicious: high rates, unusual hours, bulk transfers
    n_mal = n_samples - n_benign
    malicious = pd.DataFrame({
        "network_activity": rng.beta(5, 2, n_mal),
        "session_time":     rng.beta(2, 5, n_mal),
        "data_transfer":    rng.beta(5, 2, n_mal),
        "connection_status": np.ones(n_mal, dtype=int) * 2,
    })

    X = pd.concat([benign, malicious], ignore_index=True)
    y = pd.Series([0] * n_benign + [1] * n_mal)
    return X, y


# ── 2. Model Training ─────────────────────────────────────────────────────────

def train_threat_scorer(X_train, y_train) -> RandomForestClassifier:
    """Train RandomForestClassifier for threat scoring (0-100)."""
    log.info("Training RandomForestClassifier …")
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_leaf=5,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)
    log.info("RandomForest training complete")
    return clf


def train_anomaly_detector(X_train) -> IsolationForest:
    """Train IsolationForest for anomaly detection (unsupervised)."""
    log.info("Training IsolationForest …")
    iso = IsolationForest(
        n_estimators=150,
        contamination=0.1,     # expect ~10% anomalies
        max_features=1.0,
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(X_train)
    log.info("IsolationForest training complete")
    return iso


# ── 3. Evaluation ─────────────────────────────────────────────────────────────

def evaluate(clf, X_test, y_test, label="RandomForest") -> dict:
    """Full evaluation: accuracy, precision, recall, F1."""
    y_pred = clf.predict(X_test)
    metrics = {
        "model": label,
        "accuracy":  round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred, zero_division=0), 4),
        "recall":    round(recall_score(y_test, y_pred, zero_division=0), 4),
        "f1_score":  round(f1_score(y_test, y_pred, zero_division=0), 4),
    }
    log.info(f"\n{'='*50}\nModel: {label}")
    log.info(f"Accuracy:  {metrics['accuracy']}")
    log.info(f"Precision: {metrics['precision']}")
    log.info(f"Recall:    {metrics['recall']}")
    log.info(f"F1:        {metrics['f1_score']}")
    log.info(f"\n{classification_report(y_test, y_pred, zero_division=0)}")
    log.info(f"Confusion matrix:\n{confusion_matrix(y_test, y_pred)}")
    return metrics


def cross_validate(clf, X, y, cv=5) -> dict:
    """5-fold stratified CV for robust performance estimate."""
    log.info(f"Running {cv}-fold cross-validation …")
    skf = StratifiedKFold(n_splits=cv, shuffle=True, random_state=42)
    scores = cross_val_score(clf, X, y, cv=skf, scoring="f1", n_jobs=-1)
    result = {"cv_f1_mean": round(scores.mean(), 4), "cv_f1_std": round(scores.std(), 4)}
    log.info(f"CV F1: {result['cv_f1_mean']} ± {result['cv_f1_std']}")
    return result


# ── 4. Saving ─────────────────────────────────────────────────────────────────

def save_models(clf, iso, scaler=None):
    paths = {
        "classifier":  MODELS_DIR / "threat_scorer.pkl",
        "anomaly":     MODELS_DIR / "anomaly_detector.pkl",
        "scaler":      MODELS_DIR / "scaler.pkl",
        "features":    MODELS_DIR / "features.json",
    }
    with open(paths["classifier"], "wb") as f:
        pickle.dump(clf, f)
    with open(paths["anomaly"], "wb") as f:
        pickle.dump(iso, f)
    if scaler:
        with open(paths["scaler"], "wb") as f:
            pickle.dump(scaler, f)
    with open(paths["features"], "w") as f:
        json.dump(SYSTEM_FEATURES, f, indent=2)

    log.info("Models saved:")
    for k, p in paths.items():
        if p.exists():
            log.info(f"  {k}: {p}")
    return paths


# ── 5. Inference helper (used by Flask API) ───────────────────────────────────

def load_models():
    """Load persisted models. Called by the Flask service."""
    clf_path = MODELS_DIR / "threat_scorer.pkl"
    iso_path = MODELS_DIR / "anomaly_detector.pkl"
    if not clf_path.exists() or not iso_path.exists():
        raise FileNotFoundError(
            "Models not found. Run train_models.py --demo first."
        )
    with open(clf_path, "rb") as f:
        clf = pickle.load(f)
    with open(iso_path, "rb") as f:
        iso = pickle.load(f)
    return clf, iso


def predict_threat_score(clf, features: dict) -> int:
    """
    Convert a feature dict to a 0–100 threat score.
    Uses predict_proba from RandomForest scaled to 0-100.
    """
    row = pd.DataFrame([{k: features.get(k, 0.0) for k in SYSTEM_FEATURES}])
    prob_malicious = clf.predict_proba(row)[0][1]
    return int(round(prob_malicious * 100))


def predict_anomaly(iso, features: dict) -> bool:
    """Returns True if the sample is flagged as anomalous."""
    row = pd.DataFrame([{k: features.get(k, 0.0) for k in SYSTEM_FEATURES}])
    result = iso.predict(row)   # IsolationForest: -1=anomaly, 1=normal
    return bool(result[0] == -1)


# ── CLI Entry Point ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SPECTRA Model Trainer")
    parser.add_argument("--dataset", choices=["cicids2017", "unsw", "kdd"], help="Dataset name")
    parser.add_argument("--path", help="Path to CSV file")
    parser.add_argument("--demo", action="store_true", help="Use synthetic demo data")
    parser.add_argument("--no-cv", action="store_true", help="Skip cross-validation")
    args = parser.parse_args()

    if args.demo:
        X, y = generate_demo_data(n_samples=8000)
    elif args.dataset and args.path:
        X, y = load_and_preprocess(args.dataset, args.path)
    else:
        parser.error("Provide --demo OR both --dataset and --path")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    clf = train_threat_scorer(X_train, y_train)
    iso = train_anomaly_detector(X_train)

    rf_metrics = evaluate(clf, X_test, y_test, label="RandomForest Threat Scorer")
    if not args.no_cv:
        cv_result = cross_validate(clf, X, y)
        rf_metrics.update(cv_result)

    paths = save_models(clf, iso)

    # Save evaluation report
    report_path = MODELS_DIR / "evaluation_report.json"
    with open(report_path, "w") as f:
        json.dump(rf_metrics, f, indent=2)
    log.info(f"Evaluation report saved: {report_path}")
    log.info("\n✔ Phase 1 complete. Models ready for Flask API.")


if __name__ == "__main__":
    main()

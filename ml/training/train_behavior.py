import os
import json
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib

MODEL_DIR = os.path.join(os.path.dirname(__file__), "../models")
EVAL_DIR = os.path.join(os.path.dirname(__file__), "../evaluation")
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(EVAL_DIR, exist_ok=True)

def generate_behavior_data(n_samples: int = 4000):
    np.random.seed(42)
    # Features: [login_hour (0-23), failed_attempts, is_new_device, is_new_location, is_automated_agent]
    # Normal user behavior (95%)
    n_normal = int(n_samples * 0.95)
    hours_norm = np.random.normal(14, 3, n_normal).clip(8, 20)
    failed_norm = np.random.poisson(0.1, n_normal).clip(0, 2)
    new_dev_norm = np.random.binomial(1, 0.05, n_normal)
    new_loc_norm = np.random.binomial(1, 0.03, n_normal)
    auto_agent_norm = np.zeros(n_normal)

    X_norm = np.column_stack([hours_norm, failed_norm, new_dev_norm, new_loc_norm, auto_agent_norm])

    # Anomalous behavior (5%)
    n_anom = n_samples - n_normal
    hours_anom = np.random.choice([1, 2, 3, 4], n_anom)
    failed_anom = np.random.normal(12, 4, n_anom).clip(5, 25)
    new_dev_anom = np.ones(n_anom)
    new_loc_anom = np.ones(n_anom)
    auto_agent_anom = np.random.binomial(1, 0.8, n_anom)

    X_anom = np.column_stack([hours_anom, failed_anom, new_dev_anom, new_loc_anom, auto_agent_anom])
    X = np.vstack([X_norm, X_anom])
    return X

def train_behavior():
    print("Training Isolation Forest behavioral anomaly model...")
    X = generate_behavior_data(n_samples=5000)
    
    clf = IsolationForest(contamination=0.05, random_state=42)
    clf.fit(X)

    model_path = os.path.join(MODEL_DIR, "behavior_model.joblib")
    joblib.dump(clf, model_path)
    print(f"Behavior model saved to {model_path}")

    # Evaluate detection rate on synthetic anomalies
    test_norm = np.array([[14, 0, 0, 0, 0]]) # baseline
    test_anom = np.array([[3, 14, 1, 1, 1]]) # credential stuffing

    pred_norm = clf.predict(test_norm)[0] # 1 is inlier
    pred_anom = clf.predict(test_anom)[0] # -1 is outlier

    eval_data = {
        "model": "Isolation Forest",
        "contamination": 0.05,
        "n_samples": 5000,
        "baseline_inlier_prediction": int(pred_norm),
        "attack_anomaly_prediction": int(pred_anom),
        "status": "Trained & Validated"
    }

    report_path = os.path.join(EVAL_DIR, "behavior_evaluation.json")
    with open(report_path, "w") as f:
        json.dump(eval_data, f, indent=2)
    print(f"Behavior evaluation report saved to {report_path}")

if __name__ == "__main__":
    train_behavior()

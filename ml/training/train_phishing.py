import os
import json
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
import joblib

MODEL_DIR = os.path.join(os.path.dirname(__file__), "../models")
EVAL_DIR = os.path.join(os.path.dirname(__file__), "../evaluation")
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(EVAL_DIR, exist_ok=True)

def generate_training_data(n_samples: int = 5000):
    """
    Generates synthetic phishing vs benign URL feature distribution 
    modeled closely after UCI Phishing Websites & PhiUSIIL benchmarks.
    """
    np.random.seed(42)
    n_benign = n_samples // 2
    n_phish = n_samples - n_benign

    # Features:
    # 0: url_length, 1: domain_length, 2: has_ip, 3: has_https, 4: has_at_symbol,
    # 5: has_double_slash, 6: subdomain_count, 7: hyphen_count, 8: digit_count,
    # 9: special_character_count, 10: suspicious_keywords_count, 11: entropy

    # Benign data distribution
    b_url_len = np.random.normal(32, 10, n_benign).clip(12, 80)
    b_dom_len = np.random.normal(14, 5, n_benign).clip(6, 35)
    b_has_ip = np.zeros(n_benign)
    b_has_https = np.random.binomial(1, 0.95, n_benign)
    b_has_at = np.random.binomial(1, 0.005, n_benign)
    b_has_double_slash = np.zeros(n_benign)
    b_subdomains = np.random.poisson(0.4, n_benign).clip(0, 2)
    b_hyphens = np.random.poisson(0.3, n_benign).clip(0, 2)
    b_digits = np.random.poisson(1.2, n_benign).clip(0, 8)
    b_specials = np.random.poisson(1.5, n_benign).clip(0, 6)
    b_keywords = np.random.binomial(1, 0.05, n_benign)
    b_entropy = np.random.normal(2.8, 0.35, n_benign).clip(1.5, 4.0)

    X_benign = np.column_stack([
        b_url_len, b_dom_len, b_has_ip, b_has_https, b_has_at,
        b_has_double_slash, b_subdomains, b_hyphens, b_digits,
        b_specials, b_keywords, b_entropy
    ])
    y_benign = np.zeros(n_benign)

    # Phishing data distribution
    p_url_len = np.random.normal(78, 25, n_phish).clip(30, 190)
    p_dom_len = np.random.normal(28, 12, n_phish).clip(12, 65)
    p_has_ip = np.random.binomial(1, 0.18, n_phish)
    p_has_https = np.random.binomial(1, 0.35, n_phish)
    p_has_at = np.random.binomial(1, 0.12, n_phish)
    p_has_double_slash = np.random.binomial(1, 0.15, n_phish)
    p_subdomains = np.random.poisson(2.5, n_phish).clip(1, 6)
    p_hyphens = np.random.poisson(2.8, n_phish).clip(0, 7)
    p_digits = np.random.poisson(8.5, n_phish).clip(1, 30)
    p_specials = np.random.poisson(6.0, n_phish).clip(2, 20)
    p_keywords = np.random.poisson(1.8, n_phish).clip(1, 5)
    p_entropy = np.random.normal(4.1, 0.45, n_phish).clip(2.5, 5.5)

    X_phish = np.column_stack([
        p_url_len, p_dom_len, p_has_ip, p_has_https, p_has_at,
        p_has_double_slash, p_subdomains, p_hyphens, p_digits,
        p_specials, p_keywords, p_entropy
    ])
    y_phish = np.ones(n_phish)

    X = np.vstack([X_benign, X_phish])
    y = np.concatenate([y_benign, y_phish])
    return X, y

def train_and_evaluate():
    print("Generating UCI-style phishing benchmark dataset...")
    X, y = generate_training_data(n_samples=6000)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    print("Training Logistic Regression baseline...")
    lr = LogisticRegression(max_iter=1000)
    lr.fit(X_train, y_train)
    lr_preds = lr.predict(X_test)
    lr_prob = lr.predict_proba(X_test)[:, 1]

    print("Training Random Forest Classifier...")
    rf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42)
    rf.fit(X_train, y_train)
    rf_preds = rf.predict(X_test)
    rf_prob = rf.predict_proba(X_test)[:, 1]

    metrics_rf = {
        "model_name": "Random Forest Classifier",
        "accuracy": float(accuracy_score(y_test, rf_preds)),
        "precision": float(precision_score(y_test, rf_preds)),
        "recall": float(recall_score(y_test, rf_preds)),
        "f1_score": float(f1_score(y_test, rf_preds)),
        "roc_auc": float(roc_auc_score(y_test, rf_prob)),
        "confusion_matrix": confusion_matrix(y_test, rf_preds).tolist()
    }

    metrics_lr = {
        "model_name": "Logistic Regression",
        "accuracy": float(accuracy_score(y_test, lr_preds)),
        "precision": float(precision_score(y_test, lr_preds)),
        "recall": float(recall_score(y_test, lr_preds)),
        "f1_score": float(f1_score(y_test, lr_preds)),
        "roc_auc": float(roc_auc_score(y_test, lr_prob)),
        "confusion_matrix": confusion_matrix(y_test, lr_preds).tolist()
    }

    print("\n--- Model Evaluation Results ---")
    print(f"Random Forest  -> Accuracy: {metrics_rf['accuracy']:.4f}, F1: {metrics_rf['f1_score']:.4f}, ROC-AUC: {metrics_rf['roc_auc']:.4f}")
    print(f"Log Regression -> Accuracy: {metrics_lr['accuracy']:.4f}, F1: {metrics_lr['f1_score']:.4f}, ROC-AUC: {metrics_lr['roc_auc']:.4f}")

    # Select best model (Random Forest)
    best_model = rf
    model_save_path = os.path.join(MODEL_DIR, "phishing_model.joblib")
    joblib.dump(best_model, model_save_path)
    print(f"Best model saved to {model_save_path}")

    # Save evaluation report
    report = {
        "selected_model": "Random Forest Classifier",
        "random_forest": metrics_rf,
        "logistic_regression": metrics_lr,
        "features": [
            "url_length", "domain_length", "has_ip", "has_https", "has_at_symbol",
            "has_double_slash", "subdomain_count", "hyphen_count", "digit_count",
            "special_character_count", "suspicious_keywords_count", "entropy"
        ]
    }
    
    report_path = os.path.join(EVAL_DIR, "phishing_evaluation.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"Evaluation report saved to {report_path}")

if __name__ == "__main__":
    train_and_evaluate()

from typing import Any, Dict, List, Tuple
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from ...data.phishing_corpus import TRAINING_AND_TEST_SAMPLES

class PhishingMLClassifier:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            max_features=500,
            sublinear_tf=True,
            stop_words="english"
        )
        self.model = LogisticRegression(C=2.5, random_state=42)
        self.is_trained = False
        self._train_default_model()

    def _train_default_model(self):
        texts = []
        labels = []
        for sample in TRAINING_AND_TEST_SAMPLES:
            combined = f"{sample.get('subject', '')} {sample.get('text', '')} {' '.join(sample.get('urls', []))}"
            texts.append(combined)
            labels.append(sample["label"])
        
        X = self.vectorizer.fit_transform(texts)
        self.model.fit(X, labels)
        self.is_trained = True

    def predict_proba(self, text: str, subject: str = "", urls: List[str] = None) -> Tuple[float, List[Tuple[str, float]]]:
        """Returns the predicted phishing probability (0.0 to 1.0) and top contributing keywords."""
        if not self.is_trained:
            self._train_default_model()
        
        combined = f"{subject} {text} {' '.join(urls or [])}"
        X_vec = self.vectorizer.transform([combined])
        
        # Predicted probability for class 1 (phishing)
        proba = float(self.model.predict_proba(X_vec)[0][1])
        
        # Feature attribution: match active non-zero TF-IDF features with model coefficients
        feature_names = self.vectorizer.get_feature_names_out()
        coefs = self.model.coef_[0]
        
        active_indices = X_vec.nonzero()[1]
        feature_impacts = []
        for idx in active_indices:
            tfidf_val = X_vec[0, idx]
            weight = coefs[idx] * tfidf_val
            feature_impacts.append((feature_names[idx], float(weight)))
        
        # Sort by positive contribution to phishing class
        feature_impacts.sort(key=lambda x: x[1], reverse=True)
        top_features = [(word, round(w, 4)) for word, w in feature_impacts if w > 0][:5]
        
        return round(proba, 4), top_features

    def evaluate(self) -> Dict[str, Any]:
        """Evaluates model performance against the corpus benchmark."""
        texts = []
        labels = []
        for sample in TRAINING_AND_TEST_SAMPLES:
            combined = f"{sample.get('subject', '')} {sample.get('text', '')} {' '.join(sample.get('urls', []))}"
            texts.append(combined)
            labels.append(sample["label"])
        
        X = self.vectorizer.transform(texts)
        preds = self.model.predict(X)
        probs = self.model.predict_proba(X)[:, 1]
        
        acc = accuracy_score(labels, preds)
        prec = precision_score(labels, preds, zero_division=0)
        rec = recall_score(labels, preds, zero_division=0)
        f1 = f1_score(labels, preds, zero_division=0)
        cm = confusion_matrix(labels, preds).tolist()
        
        return {
            "total_samples": len(labels),
            "phishing_samples": sum(labels),
            "legitimate_samples": len(labels) - sum(labels),
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "confusion_matrix": {
                "true_negative": cm[0][0],
                "false_positive": cm[0][1],
                "false_negative": cm[1][0],
                "true_positive": cm[1][1]
            }
        }

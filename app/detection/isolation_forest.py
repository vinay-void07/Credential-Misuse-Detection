import os
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from typing import List, Optional
from app.core.config import settings

class IsolationForestDetector:
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or settings.MODEL_PATH
        self.model: Optional[IsolationForest] = None
        self._load_or_train_default()

    def _generate_synthetic_baseline(self, n_samples: int = 1000) -> np.ndarray:
        np.random.seed(42)
        # Normal request rate: 0.1 to 4.0
        req_rate = np.random.uniform(0.1, 4.0, size=(n_samples, 1))
        # Normal download rate: 0.0 to 1.0
        dl_rate = np.random.uniform(0.0, 1.0, size=(n_samples, 1))
        # Denied: 0
        denied = np.zeros((n_samples, 1))
        # Confidential: 0 to 1
        conf_acc = np.random.choice([0, 1], size=(n_samples, 1), p=[0.90, 0.10])
        # Internal: 1 to 4
        int_acc = np.random.randint(1, 5, size=(n_samples, 1))
        # Off-hours: 0
        off_hours = np.zeros((n_samples, 1))
        # New device: 0
        new_device = np.zeros((n_samples, 1))
        # Unique resources: 1 to 4
        uniq_res = np.random.randint(1, 5, size=(n_samples, 1))
        # Bulk downloads: 0
        bulk_dl = np.zeros((n_samples, 1))
        # Violations: 0
        violations = np.zeros((n_samples, 1))

        baseline = np.hstack([
            req_rate, dl_rate, denied, conf_acc, int_acc,
            off_hours, new_device, uniq_res, bulk_dl, violations
        ])
        return baseline

    def _load_or_train_default(self):
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                return
            except Exception:
                pass

        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        baseline_data = self._generate_synthetic_baseline(1200)
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.02,
            random_state=42
        )
        self.model.fit(baseline_data)
        joblib.dump(self.model, self.model_path)

    def train_and_save(self, data: np.ndarray):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.02,
            random_state=42
        )
        self.model.fit(data)
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(self.model, self.model_path)

    def score_anomaly(self, feature_vector: List[float]) -> dict:
        if self.model is None:
            self._load_or_train_default()

        X = np.array([feature_vector])
        decision_val = float(self.model.decision_function(X)[0])
        is_anomaly = bool(self.model.predict(X)[0] == -1)

        # In IsolationForest:
        # Normal data points yield positive score ~ +0.10 to +0.20
        # Outliers yield negative score ~ -0.10 to -0.30
        if decision_val >= 0.08:
            # Baseline normal behavior -> minimal ML risk (0 to 5 pts)
            normalized_anomaly = max(0.0, (0.18 - decision_val) / 0.18 * 0.10)
        else:
            # Deviates from normal -> scales up to 1.0
            normalized_anomaly = min(1.0, max(0.10, (0.08 - decision_val) / 0.25))

        ml_points = round(normalized_anomaly * settings.ML_WEIGHT, 2)

        return {
            "decision_value": round(decision_val, 4),
            "is_anomaly": is_anomaly,
            "normalized_anomaly_index": round(normalized_anomaly, 3),
            "ml_score": min(settings.ML_WEIGHT, max(0.0, ml_points))
        }

detector = IsolationForestDetector()
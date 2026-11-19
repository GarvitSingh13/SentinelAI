import os
import joblib
import numpy as np
from dataclasses import dataclass
from typing import Dict, Any, List, Optional
from app.ml.preprocessor import extract_features, extract_batch, CLASS_NAMES, FEATURE_NAMES

@dataclass
class PredictionResult:
    attack_class: str
    confidence: float
    is_attack: bool
    is_anomaly: bool
    anomaly_score: float
    probabilities: Dict[str, float]
    raw_features: np.ndarray

class IntrusionClassifier:
    _instance: Optional["IntrusionClassifier"] = None

    def __init__(self):
        artifacts_path = os.path.join(os.path.dirname(__file__), "artifacts", "sentinel_model.joblib")
        if not os.path.exists(artifacts_path):
            raise FileNotFoundError(f"Model artifact not found at {artifacts_path}. Run train_model.py first.")
        
        bundle = joblib.load(artifacts_path)
        self.model = bundle["classifier"]
        self.iso_forest = bundle["isolation_forest"]
        self.feature_names = bundle["feature_names"]
        self.class_names = bundle["class_names"]
        self.metrics = bundle.get("metrics", {})

    @classmethod
    def get_instance(cls) -> "IntrusionClassifier":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def predict_flow(self, flow: Dict[str, Any]) -> PredictionResult:
        features = extract_features(flow).reshape(1, -1)
        probs = self.model.predict_proba(features)[0]
        top_idx = int(np.argmax(probs))
        top_class = self.class_names[top_idx]
        confidence = float(probs[top_idx])
        is_attack = top_class != "BENIGN"

        # Unsupervised zero-day anomaly detection via Isolation Forest
        raw_anomaly_score = self.iso_forest.decision_function(features)[0]
        # Normalize score: lower decision function means higher anomaly
        anomaly_score = float(np.clip(1.0 - (raw_anomaly_score + 0.5), 0.0, 1.0))
        is_anomaly = anomaly_score > 0.65

        prob_dict = {self.class_names[i]: float(probs[i]) for i in range(len(self.class_names))}

        return PredictionResult(
            attack_class=top_class,
            confidence=confidence,
            is_attack=is_attack,
            is_anomaly=is_anomaly,
            anomaly_score=anomaly_score,
            probabilities=prob_dict,
            raw_features=features[0]
        )

    def predict_batch(self, flows: List[Dict[str, Any]]) -> List[PredictionResult]:
        return [self.predict_flow(f) for f in flows]

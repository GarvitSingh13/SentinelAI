import os
import joblib
import numpy as np
from typing import Dict, Any, List, Optional
from app.ml.preprocessor import FEATURE_NAMES, CLASS_NAMES

class FlowExplainer:
    _instance: Optional["FlowExplainer"] = None

    def __init__(self):
        artifacts_path = os.path.join(os.path.dirname(__file__), "artifacts", "sentinel_model.joblib")
        bundle = joblib.load(artifacts_path)
        self.explainer = bundle["explainer"]
        self.feature_names = bundle["feature_names"]
        self.class_names = bundle["class_names"]

    @classmethod
    def get_instance(cls) -> "FlowExplainer":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def explain(self, raw_features: np.ndarray, predicted_class: str, top_k: int = 6) -> Dict[str, Any]:
        """
        Computes exact TreeSHAP attribution values for a single network flow.
        """
        features_2d = raw_features.reshape(1, -1)
        shap_values = self.explainer.shap_values(features_2d)

        class_idx = self.class_names.index(predicted_class) if predicted_class in self.class_names else 0

        # Handle different SHAP output formats (list of arrays for multi-class vs 3D array)
        if isinstance(shap_values, list):
            class_shap = shap_values[class_idx][0]
        elif len(shap_values.shape) == 3:
            class_shap = shap_values[0, :, class_idx]
        else:
            class_shap = shap_values[0]

        contributions = []
        for i, feat_name in enumerate(self.feature_names):
            phi = float(class_shap[i])
            val = float(raw_features[i])
            contributions.append({
                "feature": feat_name,
                "value": val,
                "shap_value": round(phi, 4),
                "impact": "INCREASES_RISK" if phi > 0 else "DECREASES_RISK",
                "abs_impact": abs(phi)
            })

        # Sort by absolute Shapley importance
        contributions.sort(key=lambda x: x["abs_impact"], reverse=True)
        top_contributions = contributions[:top_k]

        # Natural language explanation summary
        top_risks = [c["feature"] for c in top_contributions if c["shap_value"] > 0][:3]
        if top_risks:
            summary = f"Flagged as {predicted_class} primarily due to anomalous {', '.join(top_risks)}."
        else:
            summary = f"Flow conforms to expected baseline behavior."

        return {
            "predicted_class": predicted_class,
            "summary": summary,
            "top_features": top_contributions,
            "all_features": {c["feature"]: c["shap_value"] for c in contributions}
        }

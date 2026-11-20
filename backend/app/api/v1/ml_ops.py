from fastapi import APIRouter, Depends
from sqlalchemy import select
from typing import Dict, Any
import numpy as np

from app.core.database import AsyncSessionLocal
from app.models.flow import NetworkFlow
from app.ml.drift_monitor import drift_monitor
from app.ml.classifier import IntrusionClassifier
from app.ml.preprocessor import extract_features

router = APIRouter()

@router.get("/drift", summary="Model Distribution Drift Analysis (PSI)")
async def get_model_drift() -> Dict[str, Any]:
    """Computes Population Stability Index (PSI) against reference baseline distribution."""
    async with AsyncSessionLocal() as session:
        # Fetch last 500 network flows
        stmt = select(NetworkFlow).order_by(NetworkFlow.created_at.desc()).limit(500)
        flows = (await session.execute(stmt)).scalars().all()

    if not flows:
        # Return clean baseline report if database has no recorded flows yet
        return drift_monitor.evaluate_dataset_drift(np.zeros((0, len(drift_monitor.feature_names))))

    # Reconstruct feature vectors for recent production traffic
    feature_rows = []
    for f in flows:
        flow_dict = {
            "flow_duration_ms": f.flow_duration_ms,
            "total_fwd_packets": f.total_fwd_packets,
            "total_bwd_packets": f.total_bwd_packets,
            "dst_port": f.dst_port,
            "protocol": f.protocol
        }
        feature_rows.append(extract_features(flow_dict))

    feature_matrix = np.vstack(feature_rows)
    report = drift_monitor.evaluate_dataset_drift(feature_matrix)
    report["sample_size"] = len(flows)
    return report

@router.get("/model-info", summary="Model Metadata & Training Evaluation Metrics")
async def get_model_info() -> Dict[str, Any]:
    clf = IntrusionClassifier.get_instance()
    return {
        "model_type": "XGBoost Multi-Class Classifier + Isolation Forest Anomaly Detector",
        "version": "1.0.0",
        "num_features": len(clf.feature_names),
        "features": clf.feature_names,
        "classes": clf.class_names,
        "metrics": clf.metrics,
        "explainability": "TreeSHAP Fast Tree Explainer (Exact Shapley Values)"
    }

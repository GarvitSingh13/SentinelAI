import pytest
import numpy as np
from httpx import AsyncClient
from app.ml.drift_monitor import drift_monitor

def test_drift_monitor_calculation():
    # 1. Baseline dataset compared with itself should yield near-zero PSI (<0.05)
    np.random.seed(42)
    sample_flows = np.random.randn(200, 18)
    report = drift_monitor.evaluate_dataset_drift(sample_flows)
    assert "overall_status" in report
    assert "mean_psi" in report
    assert "feature_psi" in report

def test_drift_monitor_single_feature():
    # Decile test
    vals = np.random.exponential(scale=150.0, size=500)
    psi = drift_monitor.calculate_feature_psi("flow_duration_ms", vals)
    assert isinstance(psi, float)
    assert psi >= 0.0

@pytest.mark.asyncio
async def test_ml_drift_endpoint(client: AsyncClient, admin_token_headers):
    res = await client.get("/api/v1/ml/drift")
    assert res.status_code == 200
    data = res.json()
    assert "overall_status" in data
    assert "mean_psi" in data
    assert "feature_psi" in data
    assert data["overall_status"] in ["STABLE", "MODERATE_DRIFT", "SIGNIFICANT_DRIFT"]

@pytest.mark.asyncio
async def test_ml_model_info_endpoint(client: AsyncClient, admin_token_headers):
    res = await client.get("/api/v1/ml/model-info")
    assert res.status_code == 200
    data = res.json()
    assert "XGBoost" in data["model_type"]
    assert "TreeSHAP" in data["explainability"]
    assert len(data["classes"]) == 6
    assert len(data["features"]) == 18

@pytest.mark.asyncio
async def test_prometheus_metrics_endpoint(client: AsyncClient):
    res = await client.get("/metrics")
    assert res.status_code == 200
    assert "text/plain" in res.headers["content-type"]
    text = res.text
    assert "sentinelai_flows_total" in text
    assert "sentinelai_incidents_active" in text
    assert "sentinelai_model_accuracy_ratio 1.000" in text

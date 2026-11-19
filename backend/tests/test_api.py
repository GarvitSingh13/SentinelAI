import pytest
from httpx import AsyncClient, ASGITransport
from app.main import app

@pytest.mark.asyncio
async def test_health_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "UP"
        assert "XGBoost" in data["ml_engine"]

@pytest.mark.asyncio
async def test_auth_login():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/v1/auth/login", json={
            "email": "admin@sentinelai.com",
            "password": "SentinelSecret2026!"
        })
        assert res.status_code == 200
        data = res.json()
        assert "access_token" in data
        assert data["role"] == "ADMIN"

@pytest.mark.asyncio
async def test_ingest_benign_flow():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Ingest normal web flow
        flow_data = {
            "src_ip": "192.168.1.45",
            "src_port": 54321,
            "dst_ip": "10.0.0.8",
            "dst_port": 443,
            "protocol": "TCP",
            "flow_duration_ms": 250.0,
            "total_fwd_packets": 8,
            "total_bwd_packets": 10,
            "fwd_packet_length_mean": 350.0,
            "bwd_packet_length_mean": 800.0,
            "flow_bytes_per_sec": 12000.0,
            "flow_packets_per_sec": 45.0,
            "flow_iat_mean": 25.0,
            "flow_iat_std": 12.0,
            "syn_flag_count": 1,
            "ack_flag_count": 17
        }
        res = await client.post("/api/v1/flows/ingest", json=flow_data)
        assert res.status_code == 202
        data = res.json()
        assert data["attack_class"] == "BENIGN"
        assert data["is_attack"] is False
        assert data["incident_id"] is None

@pytest.mark.asyncio
async def test_ingest_attack_flow_triggers_incident_and_shap():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Ingest high-velocity SYN flood
        attack_flow = {
            "src_ip": "45.33.32.156",
            "src_port": 41234,
            "dst_ip": "10.0.0.8",
            "dst_port": 80,
            "protocol": "TCP",
            "flow_duration_ms": 15.0,
            "total_fwd_packets": 350,
            "total_bwd_packets": 0,
            "fwd_packet_length_mean": 64.0,
            "bwd_packet_length_mean": 0.0,
            "flow_bytes_per_sec": 950000.0,
            "flow_packets_per_sec": 15000.0,
            "syn_flag_count": 350,
            "ack_flag_count": 0
        }
        res = await client.post("/api/v1/flows/ingest", json=attack_flow)
        assert res.status_code == 202
        data = res.json()
        assert data["attack_class"] == "DOS_DDOS"
        assert data["is_attack"] is True
        assert data["incident_id"] is not None
        assert data["shap_explanation"] is not None
        assert "summary" in data["shap_explanation"]
        assert len(data["shap_explanation"]["top_features"]) > 0

@pytest.mark.asyncio
async def test_stats_and_incidents():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Login
        login_res = await client.post("/api/v1/auth/login", json={
            "email": "admin@sentinelai.com",
            "password": "SentinelSecret2026!"
        })
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Check incidents list
        inc_res = await client.get("/api/v1/incidents", headers=headers)
        assert inc_res.status_code == 200
        incidents = inc_res.json()
        assert len(incidents) >= 1

        # Check stats
        stats_res = await client.get("/api/v1/stats")
        assert stats_res.status_code == 200
        stats = stats_res.json()
        assert stats["total_flows"] >= 2
        assert stats["total_threats"] >= 1

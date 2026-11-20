import pytest
import asyncio
from httpx import AsyncClient
from app.core.redis_client import ThreatStateStore
from app.services.websocket_manager import ws_manager
from app.services.traffic_generator import traffic_generator
from app.services.stream_producer import stream_producer

@pytest.mark.asyncio
async def test_redis_blacklist_lifecycle():
    test_ip = "203.0.113.45"
    assert await ThreatStateStore.is_blacklisted(test_ip) is False

    # Blacklist IP
    data = await ThreatStateStore.blacklist_ip(
        ip=test_ip,
        duration_seconds=30,
        reason="Test Brute Force Attack",
        attack_class="BRUTE_FORCE"
    )
    assert data["ip"] == test_ip
    assert await ThreatStateStore.is_blacklisted(test_ip) is True

    # Retrieve all
    all_blocked = await ThreatStateStore.get_all_blacklisted()
    blocked_ips = [b["ip"] for b in all_blocked]
    assert test_ip in blocked_ips

    # Unblacklist
    assert await ThreatStateStore.unblacklist_ip(test_ip) is True
    assert await ThreatStateStore.is_blacklisted(test_ip) is False

@pytest.mark.asyncio
async def test_redis_velocity_tracker():
    test_ip = "198.51.100.77"
    for _ in range(5):
        await ThreatStateStore.record_ip_velocity(test_ip, window_seconds=5)
    vel = await ThreatStateStore.record_ip_velocity(test_ip, window_seconds=5)
    assert vel == 6

@pytest.mark.asyncio
async def test_traffic_generator_lifecycle():
    status = traffic_generator.get_status()
    assert "is_running" in status
    assert "total_generated" in status

    # Start generator at 10 flows/sec
    await traffic_generator.start(rate_per_second=10)
    assert traffic_generator.is_running is True

    # Let it run briefly
    await asyncio.sleep(0.6)
    assert traffic_generator.total_generated > 0

    # Stop generator
    await traffic_generator.stop()
    assert traffic_generator.is_running is False

@pytest.mark.asyncio
async def test_websocket_broadcast():
    # Verify broadcast does not crash when no clients are connected
    await ws_manager.broadcast_threat({
        "attack_class": "DOS_DDOS",
        "confidence": 0.99,
        "src_ip": "1.2.3.4"
    })
    await ws_manager.broadcast_mitigation({
        "target_ip": "1.2.3.4",
        "action": "FIREWALL_BLOCK"
    })
    await ws_manager.broadcast_stats({
        "flows_per_sec": 45.0
    })

@pytest.mark.asyncio
async def test_blacklist_api_endpoints(client: AsyncClient, admin_token_headers):
    # 1. Add to blacklist via API
    res = await client.post("/api/v1/blacklist", json={
        "ip": "192.0.2.111",
        "duration_seconds": 60,
        "reason": "API Blacklist Test",
        "attack_class": "MANUAL_BLOCK"
    })
    assert res.status_code == 200
    assert res.json()["ip"] == "192.0.2.111"

    # 2. List blacklisted
    res = await client.get("/api/v1/blacklist")
    assert res.status_code == 200
    ips = [item["ip"] for item in res.json()]
    assert "192.0.2.111" in ips

    # 3. Delete from blacklist
    res = await client.delete("/api/v1/blacklist/192.0.2.111")
    assert res.status_code == 200
    assert res.json()["status"] == "SUCCESS"

@pytest.mark.asyncio
async def test_stream_api_endpoints(client: AsyncClient, admin_token_headers):
    # 1. Stream status
    res = await client.get("/api/v1/stream/status")
    assert res.status_code == 200
    assert "is_running" in res.json()

    # 2. Start stream
    res = await client.post("/api/v1/stream/start?rate=15")
    assert res.status_code == 200
    assert res.json()["status"] == "STARTED"

    # 3. Stop stream
    res = await client.post("/api/v1/stream/stop")
    assert res.status_code == 200
    assert res.json()["status"] == "STOPPED"

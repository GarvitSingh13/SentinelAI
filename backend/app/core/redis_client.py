import time
import json
from typing import Optional, List, Dict, Any
from redis import asyncio as aioredis
from app.core.config import settings

_redis_pool: Optional[aioredis.Redis] = None

def get_redis_client() -> aioredis.Redis:
    global _redis_pool
    if _redis_pool is None:
        _redis_pool = aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
            max_connections=20
        )
    return _redis_pool

async def close_redis_client():
    global _redis_pool
    if _redis_pool is not None:
        await _redis_pool.aclose()
        _redis_pool = None

class ThreatStateStore:
    """Manages real-time threat state, active IP blacklists, and sliding window rate telemetry."""

    @staticmethod
    async def is_blacklisted(ip: str) -> bool:
        redis = get_redis_client()
        exists = await redis.exists(f"blacklist:{ip}")
        return bool(exists)

    @staticmethod
    async def blacklist_ip(ip: str, duration_seconds: int = 3600, reason: str = "Automated AI Mitigation", attack_class: str = "UNKNOWN") -> Dict[str, Any]:
        redis = get_redis_client()
        key = f"blacklist:{ip}"
        data = {
            "ip": ip,
            "reason": reason,
            "attack_class": attack_class,
            "blocked_at": time.time(),
            "ttl": duration_seconds
        }
        await redis.set(key, json.dumps(data), ex=duration_seconds)
        await redis.sadd("blacklist:active_ips", ip)
        return data

    @staticmethod
    async def unblacklist_ip(ip: str) -> bool:
        redis = get_redis_client()
        key = f"blacklist:{ip}"
        await redis.delete(key)
        await redis.srem("blacklist:active_ips", ip)
        return True

    @staticmethod
    async def get_all_blacklisted() -> List[Dict[str, Any]]:
        redis = get_redis_client()
        ips = await redis.smembers("blacklist:active_ips")
        results = []
        for ip in ips:
            raw = await redis.get(f"blacklist:{ip}")
            if raw:
                try:
                    results.append(json.loads(raw))
                except Exception:
                    results.append({"ip": ip, "reason": "Active ACL Block", "attack_class": "UNKNOWN"})
            else:
                # Key expired, clean from set
                await redis.srem("blacklist:active_ips", ip)
        return sorted(results, key=lambda x: x.get("blocked_at", 0), reverse=True)

    @staticmethod
    async def record_ip_velocity(ip: str, window_seconds: int = 10) -> int:
        """Sliding window counter using sorted sets: returns number of flows from IP in past window."""
        redis = get_redis_client()
        now = time.time()
        key = f"velocity:{ip}"
        
        # Add current timestamp
        await redis.zadd(key, {str(now): now})
        # Evict timestamps older than now - window_seconds
        await redis.zremrangebyscore(key, 0, now - window_seconds)
        # Count remaining
        count = await redis.zcard(key)
        # Set expire on key so idle IPs get cleaned up
        await redis.expire(key, window_seconds * 2)
        return count

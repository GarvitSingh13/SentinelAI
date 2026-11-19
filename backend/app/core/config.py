from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True)

    PROJECT_NAME: str = "SentinelAI"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://sentinelai:sentinelai_secret@localhost:5434/sentinelai"
    SYNC_DATABASE_URL: str = "postgresql://sentinelai:sentinelai_secret@localhost:5434/sentinelai"

    # Redis
    REDIS_URL: str = "redis://localhost:6381/0"

    # Redpanda / Kafka
    KAFKA_BOOTSTRAP_SERVERS: str = "localhost:9093"
    KAFKA_FLOWS_TOPIC: str = "network-flows"
    KAFKA_ALERTS_TOPIC: str = "threat-alerts"

    # Security
    JWT_SECRET: str = "sentinelai-super-secret-jwt-key-change-in-production-2026"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    # ML Inference Thresholds
    ALERT_CONFIDENCE_THRESHOLD: float = 0.65
    ANOMALY_THRESHOLD: float = 0.60

settings = Settings()

import json
import logging
from typing import Dict, Any, List
from aiokafka import AIOKafkaProducer
from app.core.config import settings

logger = logging.getLogger("sentinel.producer")

class FlowStreamProducer:
    """Async Redpanda/Kafka producer for streaming network flow telemetry."""

    def __init__(self, bootstrap_servers: str = None):
        self.bootstrap_servers = bootstrap_servers or settings.KAFKA_BOOTSTRAP_SERVERS
        self.producer: AIOKafkaProducer = None

    async def start(self):
        if self.producer is None:
            self.producer = AIOKafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode("utf-8")
            )
            await self.producer.start()
            logger.info("✓ FlowStreamProducer connected to Redpanda on %s", self.bootstrap_servers)

    async def stop(self):
        if self.producer:
            await self.producer.stop()
            self.producer = None
            logger.info("FlowStreamProducer stopped.")

    async def send_flow(self, flow_dict: Dict[str, Any], topic: str = None):
        if self.producer is None:
            await self.start()
        target_topic = topic or settings.KAFKA_FLOWS_TOPIC
        key = str(flow_dict.get("src_ip", "default")).encode("utf-8")
        await self.producer.send_and_wait(target_topic, value=flow_dict, key=key)

    async def send_batch(self, flows: List[Dict[str, Any]], topic: str = None):
        if self.producer is None:
            await self.start()
        target_topic = topic or settings.KAFKA_FLOWS_TOPIC
        for flow in flows:
            key = str(flow.get("src_ip", "default")).encode("utf-8")
            await self.producer.send(target_topic, value=flow, key=key)
        await self.producer.flush()

# Global producer instance
stream_producer = FlowStreamProducer()

import asyncio
import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime
from aiokafka import AIOKafkaConsumer
from sqlalchemy import select, and_

from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.core.redis_client import ThreatStateStore
from app.ml.classifier import IntrusionClassifier
from app.ml.explainer import FlowExplainer
from app.ml.preprocessor import extract_features
from app.models.flow import NetworkFlow
from app.models.incident import Incident
from app.models.alert import Alert
from app.models.mitigation import MitigationAction
from app.services.websocket_manager import ws_manager
from app.services.stream_producer import stream_producer

logger = logging.getLogger("sentinel.consumer")

class FlowStreamConsumer:
    """Async Redpanda/Kafka consumer worker executing real-time ML detection and automated mitigation."""

    def __init__(self, bootstrap_servers: str = None, group_id: str = "sentinelai-workers"):
        self.bootstrap_servers = bootstrap_servers or settings.KAFKA_BOOTSTRAP_SERVERS
        self.group_id = group_id
        self.consumer: Optional[AIOKafkaConsumer] = None
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self.processed_count = 0
        self.threat_count = 0

    async def start(self):
        if self._running:
            return

        self.consumer = AIOKafkaConsumer(
            settings.KAFKA_FLOWS_TOPIC,
            bootstrap_servers=self.bootstrap_servers,
            group_id=self.group_id,
            auto_offset_reset="latest",
            value_deserializer=lambda m: json.loads(m.decode("utf-8")),
            enable_auto_commit=True
        )
        await self.consumer.start()
        self._running = True
        logger.info("✓ FlowStreamConsumer connected to Redpanda topic '%s'", settings.KAFKA_FLOWS_TOPIC)
        self._task = asyncio.create_task(self._consume_loop())

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

        if self.consumer:
            await self.consumer.stop()
            self.consumer = None
            logger.info("FlowStreamConsumer stopped.")

    async def _consume_loop(self):
        classifier = IntrusionClassifier.get_instance()
        explainer = FlowExplainer.get_instance()

        while self._running:
            try:
                msg = await self.consumer.getone()
                flow_data: Dict[str, Any] = msg.value
                self.processed_count += 1

                await self._process_single_flow(flow_data, classifier, explainer)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error in stream consume loop: %s", str(e), exc_info=True)
                await asyncio.sleep(0.5)

    async def _process_single_flow(self, flow_data: Dict[str, Any], classifier: IntrusionClassifier, explainer: FlowExplainer):
        src_ip = flow_data.get("src_ip", "0.0.0.0")
        dst_ip = flow_data.get("dst_ip", "0.0.0.0")
        src_port = int(flow_data.get("src_port", 0))
        dst_port = int(flow_data.get("dst_port", 0))
        protocol = str(flow_data.get("protocol", "TCP")).upper()

        # 1. Active Redis Blacklist Check
        is_already_blocked = await ThreatStateStore.is_blacklisted(src_ip)
        velocity = await ThreatStateStore.record_ip_velocity(src_ip)

        # 2. Feature Extraction & ML Inference
        features = extract_features(flow_data)
        ml_res = classifier.predict_flow(features)

        attack_class = ml_res["attack_class"]
        confidence = ml_res["confidence"]
        is_attack = ml_res["is_attack"] or is_already_blocked
        is_anomaly = ml_res["is_anomaly"]
        anomaly_score = ml_res["anomaly_score"]

        # Boost attack flag if IP has anomalous packet velocity (> 100 flows / 10s)
        if velocity > 100 and attack_class == "BENIGN":
            attack_class = "DOS_DDOS"
            is_attack = True
            confidence = max(confidence, 0.85)

        shap_explanation = None
        incident_id = None
        auto_mitigated = False

        if is_attack and confidence >= settings.ALERT_CONFIDENCE_THRESHOLD:
            self.threat_count += 1
            # 3. Compute TreeSHAP feature attributions
            shap_explanation = explainer.explain_flow(features, attack_class)

            # 4. Database Persistence: Incident & Alert
            async with AsyncSessionLocal() as session:
                # Severity determination
                if attack_class in ["DOS_DDOS", "BOTNET"] or confidence >= 0.95:
                    severity = "CRITICAL"
                elif attack_class in ["BRUTE_FORCE", "WEB_ATTACK"] or confidence >= 0.80:
                    severity = "HIGH"
                elif is_anomaly:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

                # Check for existing open incident for this src_ip & attack vector
                stmt = select(Incident).where(
                    and_(
                        Incident.src_ip == src_ip,
                        Incident.primary_attack_vector == attack_class,
                        Incident.status.in_(["DETECTED", "INVESTIGATING", "AUTO_MITIGATED"])
                    )
                )
                incident = (await session.execute(stmt)).scalars().first()

                if not incident:
                    incident = Incident(
                        title=f"Detected {attack_class} on {dst_ip}:{dst_port}",
                        severity=severity,
                        status="DETECTED",
                        primary_attack_vector=attack_class,
                        risk_score=float(confidence * 100.0),
                        src_ip=src_ip,
                        dst_ip=dst_ip
                    )
                    session.add(incident)
                    await session.flush()

                incident_id = str(incident.id)

                # Create Alert
                alert = Alert(
                    incident_id=incident.id,
                    attack_class=attack_class,
                    confidence=float(confidence),
                    is_anomaly=is_anomaly,
                    anomaly_score=float(anomaly_score),
                    shap_values=shap_explanation
                )
                session.add(alert)

                # 5. Automated Mitigation Engine
                # Automatically block IP if confidence >= 0.90 or severity is CRITICAL
                if (confidence >= 0.90 or severity == "CRITICAL") and not is_already_blocked:
                    await ThreatStateStore.blacklist_ip(
                        ip=src_ip,
                        duration_seconds=3600,
                        reason=f"Automated AI Blacklist: {attack_class} (Confidence: {confidence:.2f})",
                        attack_class=attack_class
                    )
                    mitigation = MitigationAction(
                        incident_id=incident.id,
                        action_type="FIREWALL_BLOCK",
                        target_value=src_ip,
                        executed_by="SentinelAI Automated Engine",
                        status="APPLIED"
                    )
                    session.add(mitigation)
                    incident.status = "AUTO_MITIGATED"
                    auto_mitigated = True

                await session.commit()

            # 6. Real-Time Broadcasts
            threat_payload = {
                "incident_id": incident_id,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "attack_class": attack_class,
                "confidence": round(confidence, 4),
                "severity": severity,
                "is_anomaly": is_anomaly,
                "auto_mitigated": auto_mitigated,
                "shap_explanation": shap_explanation,
                "timestamp": datetime.utcnow().isoformat()
            }

            # Broadcast to connected WebSocket clients
            await ws_manager.broadcast_threat(threat_payload)

            if auto_mitigated:
                await ws_manager.broadcast_mitigation({
                    "incident_id": incident_id,
                    "target_ip": src_ip,
                    "action": "FIREWALL_BLOCK",
                    "status": "APPLIED",
                    "reason": f"High-confidence {attack_class} threat"
                })

            # Publish to Redpanda threat-alerts topic
            try:
                await stream_producer.send_flow(threat_payload, topic="network-threats")
            except Exception as e:
                logger.warning("Failed to publish to network-threats: %s", str(e))

        # Save flow in database
        async with AsyncSessionLocal() as session:
            db_flow = NetworkFlow(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                flow_duration_ms=float(flow_data.get("flow_duration_ms", 0.0)),
                total_fwd_packets=int(flow_data.get("total_fwd_packets", 1)),
                total_bwd_packets=int(flow_data.get("total_bwd_packets", 0)),
                attack_class=attack_class,
                confidence=float(confidence),
                is_attack=is_attack,
                is_anomaly=is_anomaly,
                anomaly_score=float(anomaly_score)
            )
            session.add(db_flow)
            await session.commit()

# Global consumer instance
stream_consumer = FlowStreamConsumer()

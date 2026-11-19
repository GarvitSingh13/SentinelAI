from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import List
from datetime import datetime, timezone
import uuid

from app.core.database import get_db
from app.models.flow import NetworkFlow
from app.models.incident import Incident
from app.models.alert import Alert
from app.schemas.flow import FlowIngestRequest, FlowBatchIngestRequest, FlowIngestResult, BatchIngestResponse
from app.ml.classifier import IntrusionClassifier
from app.ml.explainer import FlowExplainer

router = APIRouter(prefix="/flows", tags=["Network Flow Ingestion & ML Detection"])

SEVERITY_MAP = {
    "DOS_DDOS": "CRITICAL",
    "BOTNET": "CRITICAL",
    "BRUTE_FORCE": "HIGH",
    "WEB_ATTACK": "HIGH",
    "PORTSCAN": "MEDIUM",
    "BENIGN": "LOW"
}

@router.post("/ingest", response_model=FlowIngestResult, status_code=status.HTTP_202_ACCEPTED)
async def ingest_single_flow(req: FlowIngestRequest, db: AsyncSession = Depends(get_db)):
    flow_data = req.model_dump()
    classifier = IntrusionClassifier.get_instance()
    explainer = FlowExplainer.get_instance()

    # 1. Run ML classification & anomaly scoring
    pred = classifier.predict_flow(flow_data)

    # 2. Persist raw flow
    flow_entity = NetworkFlow(**flow_data)
    db.add(flow_entity)
    await db.flush()

    incident_id = None
    shap_info = None

    # 3. If threat identified, generate SHAP explanation and trigger Incident
    if pred.is_attack and pred.confidence >= 0.50:
        shap_info = explainer.explain(pred.raw_features, pred.attack_class)
        severity = SEVERITY_MAP.get(pred.attack_class, "MEDIUM")

        incident = Incident(
            title=f"Detected {pred.attack_class} on {req.dst_ip}:{req.dst_port}",
            severity=severity,
            status="DETECTED",
            primary_attack_vector=pred.attack_class,
            risk_score=float(pred.confidence),
            src_ip=req.src_ip,
            dst_ip=req.dst_ip
        )
        db.add(incident)
        await db.flush()
        incident_id = incident.id

        alert = Alert(
            incident_id=incident.id,
            flow_id=flow_entity.id,
            attack_class=pred.attack_class,
            confidence=pred.confidence,
            shap_values=shap_info
        )
        db.add(alert)

    await db.commit()

    return FlowIngestResult(
        flow_id=flow_entity.id,
        src_ip=flow_entity.src_ip,
        dst_ip=flow_entity.dst_ip,
        dst_port=flow_entity.dst_port,
        attack_class=pred.attack_class,
        confidence=round(pred.confidence, 4),
        is_attack=pred.is_attack,
        is_anomaly=pred.is_anomaly,
        anomaly_score=round(pred.anomaly_score, 4),
        incident_id=incident_id,
        shap_explanation=shap_info
    )

@router.post("/ingest/batch", response_model=BatchIngestResponse, status_code=status.HTTP_202_ACCEPTED)
async def ingest_batch_flows(batch: FlowBatchIngestRequest, db: AsyncSession = Depends(get_db)):
    classifier = IntrusionClassifier.get_instance()
    explainer = FlowExplainer.get_instance()

    results = []
    threat_count = 0
    anomaly_count = 0

    for req in batch.flows:
        flow_data = req.model_dump()
        pred = classifier.predict_flow(flow_data)
        
        flow_entity = NetworkFlow(**flow_data)
        db.add(flow_entity)
        await db.flush()

        incident_id = None
        shap_info = None

        if pred.is_attack and pred.confidence >= 0.50:
            threat_count += 1
            shap_info = explainer.explain(pred.raw_features, pred.attack_class)
            severity = SEVERITY_MAP.get(pred.attack_class, "MEDIUM")

            incident = Incident(
                title=f"Detected {pred.attack_class} from {req.src_ip}",
                severity=severity,
                status="DETECTED",
                primary_attack_vector=pred.attack_class,
                risk_score=float(pred.confidence),
                src_ip=req.src_ip,
                dst_ip=req.dst_ip
            )
            db.add(incident)
            await db.flush()
            incident_id = incident.id

            alert = Alert(
                incident_id=incident.id,
                flow_id=flow_entity.id,
                attack_class=pred.attack_class,
                confidence=pred.confidence,
                shap_values=shap_info
            )
            db.add(alert)

        if pred.is_anomaly:
            anomaly_count += 1

        results.append(FlowIngestResult(
            flow_id=flow_entity.id,
            src_ip=flow_entity.src_ip,
            dst_ip=flow_entity.dst_ip,
            dst_port=flow_entity.dst_port,
            attack_class=pred.attack_class,
            confidence=round(pred.confidence, 4),
            is_attack=pred.is_attack,
            is_anomaly=pred.is_anomaly,
            anomaly_score=round(pred.anomaly_score, 4),
            incident_id=incident_id,
            shap_explanation=shap_info
        ))

    await db.commit()

    return BatchIngestResponse(
        total_processed=len(batch.flows),
        threats_detected=threat_count,
        anomalies_detected=anomaly_count,
        results=results
    )

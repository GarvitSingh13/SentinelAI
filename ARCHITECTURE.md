# 🛡️ SentinelAI — Real-Time AI-Powered Network Intrusion Detection & Response Platform
## Complete Architecture & Engineering Specification

---

## 1. Executive Summary & Vision

**SentinelAI** is an enterprise-grade Network Detection & Response (NDR) platform designed for modern Security Operations Centers (SOC). Modern enterprise networks process millions of network flows per minute across hybrid-cloud perimeters. Traditional rule-based Intrusion Detection Systems (such as basic Snort/Suricata signature matches) fail against zero-day exploits, distributed volumetric attacks, and polymorphic adversary techniques.

SentinelAI combines **real-time streaming flow ingestion (Redpanda/Kafka)**, **machine learning classification (XGBoost)**, **unsupervised zero-day anomaly detection (Isolation Forest)**, and **Explainable AI (TreeSHAP)** to detect, score, explain, and mitigate network threats within sub-second latencies.

Every detected threat is accompanied by transparent, audit-ready SHAP feature importance attributions, allowing security analysts to immediately understand *why* a connection was classified as an attack (e.g., abnormally high SYN-to-ACK ratio, anomalous packet length variance, or high flow packet velocity).

---

## 2. Core Architectural Pillars

| Component | Technology | Rationale & Tradeoffs | Role in SentinelAI |
|---|---|---|---|
| **API & Ingestion Gateway** | **Python 3.14 & FastAPI** | Asynchronous ASGI runtime with native `uvicorn`, automatic OpenAPI schema generation, and high-concurrency non-blocking I/O. | Ingests network flow telemetry, exposes incident triage REST APIs, and streams live threat alerts over WebSockets. |
| **Streaming Message Broker** | **Redpanda / Apache Kafka** | Distributed commit log capable of millions of events/sec with zero packet loss, partitioned ordering, and decoupled stream consumers. | Buffers continuous network flow streams from boundary agents, decoupling ingestion from ML inference. |
| **ML Inference Engine** | **XGBoost & Scikit-learn** | High-performance gradient boosted decision trees optimized for tabular network flow statistics; ultra-fast inference latency (< 5ms per flow). | Multi-class classification: `BENIGN`, `DOS_DDOS`, `PORTSCAN`, `BRUTE_FORCE`, `WEB_ATTACK`, `BOTNET`. |
| **Explainable AI (XAI)** | **SHAP (TreeSHAP)** | Game-theoretic Shapley Additive exPlanations providing mathematically sound local and global feature attribution. | Computes per-feature contributions ($\phi_i$) for every flagged threat, explaining root causes directly in the SOC console. |
| **State & Threat Cache** | **Redis 7** | In-memory key-value store with sub-millisecond lookups, TTL expirations, and Pub/Sub. | Tracks IP reputation, sliding-window traffic frequencies, active firewall blacklist rules, and session state. |
| **Relational Storage** | **PostgreSQL 16** | ACID-compliant storage with JSONB indexing and relational integrity. | Stores user RBAC, persistent incident audit trails, mitigation logs, and model drift telemetry. |
| **Frontend SOC Console** | **React 18 + TypeScript + Vite** | Component-driven dark UI with live WebSocket streaming, visual SHAP waterfall charts, and incident management controls. | Provides security analysts with real-time threat maps, incident triaging, XAI breakdowns, and manual/automated mitigations. |

---

## 3. Detailed Technology Pillar Breakdown

### Pillar 1: FastAPI Ingestion & Control Gateway
- **Definition:** An asynchronous web framework built on Starlette and Pydantic for building modern APIs with Python.
- **Why Using:** Python is the native lingua franca for machine learning (XGBoost, SHAP, PyTorch). FastAPI achieves near-Go/Node performance using `asyncio` and `uvloop`, allowing simultaneous low-latency ML inference and high-throughput ingestion without cross-language serialization bottlenecks.
- **Purpose in SentinelAI:** Serves as the central API gateway: accepts network flow bundles, validates schemas via Pydantic, broadcasts live threats via WebSockets, and manages incident status transitions.

### Pillar 2: Redpanda / Kafka Stream Broker
- **Definition:** A high-throughput, partitioned, fault-tolerant distributed streaming log.
- **Why Using:** Network packet collectors (such as NetFlow v9, IPFIX, or sFlow probes) generate bursts of thousands of flow events per second. Direct synchronous database writes or synchronous ML calls would drop packets under traffic spikes.
- **Purpose in SentinelAI:** Decouples flow ingestion from detection workers. Probes publish to `network-flows` topic; ML worker pools consume concurrently and push evaluated threats to `threat-alerts`.

### Pillar 3: XGBoost Multi-Class Classification & Anomaly Detection
- **Definition:** An optimized distributed gradient boosting library implementing machine learning algorithms under the Gradient Boosting framework.
- **Why Using:** Deep learning models (e.g. LSTMs or CNNs) are computationally heavy for line-rate packet flow metadata, whereas gradient boosted trees consistently dominate tabular benchmarks (like CIC-IDS2017 and UNSW-NB15) with microsecond inference times and compact memory footprints.
- **Purpose in SentinelAI:** Evaluates 20+ statistical network features per flow to compute multi-class probability distributions across attack vectors and normal baseline traffic.

### Pillar 4: Explainable AI with TreeSHAP
- **Definition:** A tree-specific optimization of the SHAP algorithm that computes exact Shapley values in polynomial time $\mathcal{O}(TLD^2)$ rather than exponential time.
- **Why Using:** "Black-box" AI is dangerous in cybersecurity. False positive alerts waste analyst time and can disrupt legitimate enterprise traffic. SHAP provides mathematically consistent, local explanation vectors proving exactly which network attributes triggered the alarm.
- **Purpose in SentinelAI:** Generates local feature attribution scores for every security alert, displayed in the dashboard as positive and negative risk contributors (e.g. `+0.42` for Destination Port 445 SMB anomaly, `+0.38` for SYN flag ratio).

---

## 4. Architectural Diagrams (Mermaid)

### 4.1 End-to-End System Architecture

```mermaid
flowchart TD
    subgraph NetworkPerimeter["Network Perimeter & Probes"]
        P1["Edge Gateway / Router"]
        P2["Cloud VPC Flow Logs"]
        P3["Internal Switch / NetFlow Probe"]
    end

    subgraph IngestionLayer["Ingestion & Streaming Layer"]
        IG["FastAPI Flow Collector (/api/v1/flows/ingest)"]
        RP["Redpanda / Kafka Cluster<br/>Topic: network-flows"]
    end

    subgraph InferenceEngine["SentinelAI Detection Engine"]
        CW["Stream Consumer Workers"]
        FE["Feature Normalizer & Scaler"]
        XGB["XGBoost Multi-Class Classifier"]
        IF["Isolation Forest Anomaly Detector"]
        SHAP["TreeSHAP Explainer Engine"]
    end

    subgraph DataStorage["Data & Threat Intelligence Layer"]
        PG[("PostgreSQL 16<br/>Incidents, Audit Logs, RBAC")]
        RD[("Redis 7<br/>IP Reputation, Blacklist Cache, Metrics")]
    end

    subgraph SOCConsole["Security Operations Center (SOC) Console"]
        UI["React 18 Dashboard (Vite + TypeScript)"]
        WS["WebSocket Real-Time Threat Stream"]
    end

    P1 & P2 & P3 -->|"JSON / NetFlow"| IG
    IG -->|"Batch Push"| RP
    RP -->|"Stream Fetch"| CW
    CW --> FE
    FE --> XGB & IF
    XGB & IF -->|"Alert Triggered (Score > Threshold)"| SHAP
    SHAP -->|"Persist Alert + SHAP Vector"| PG
    SHAP -->|"Update Blacklist & Counters"| RD
    SHAP -->|"Push Alert Event"| WS
    WS --> UI
    UI -->|"Incident Triage / Firewall Rule"| IG
```

---

### 4.2 Real-Time Detection & Explanation Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    actor Probe as Flow Sensor / VPC
    participant API as Ingestion API
    participant Queue as Kafka / Redpanda
    participant Worker as Detection Worker
    participant Model as XGBoost & SHAP
    participant DB as PostgreSQL & Redis
    participant SOC as React SOC Dashboard

    Probe->>API: POST /api/v1/flows/ingest (Batch of 50 flows)
    API->>Queue: Publish batch to topic 'network-flows'
    API-->>Probe: 202 Accepted { batch_id, received_count }

    Queue->>Worker: Consume flow events
    loop For Each Flow
        Worker->>Model: predict_proba(features)
        Model-->>Worker: Probabilities: { DOS: 0.94, BENIGN: 0.04, ... }
        alt Attack Probability > 0.70
            Worker->>Model: explain_flow(features) [TreeSHAP]
            Model-->>Worker: SHAP values { syn_ratio: +0.48, bytes_per_sec: +0.31 }
            Worker->>DB: Insert Incident (SEVERITY: HIGH, Features, SHAP JSON)
            Worker->>DB: Add Source IP to Redis Blacklist (TTL: 3600s)
            Worker->>SOC: Broadcast WS Alert (Incident ID, Attack Vector, SHAP)
        end
    end
    SOC->>SOC: Live alert card appears with SHAP waterfall & Mitigate button
```

---

### 4.3 Security Incident Lifecycle State Machine

```mermaid
stateDiagram-v2
    [*] --> DETECTED: ML Classifier / Anomaly Score > Threshold
    
    DETECTED --> AUTO_MITIGATED: Automated Rule Policy Matches (IP Blacklisted in Redis)
    DETECTED --> TRIAGING: Assigned to SOC Security Analyst
    
    AUTO_MITIGATED --> INVESTIGATING: Analyst Reviews Threat & Logs
    TRIAGING --> INVESTIGATING: Analyst Claims Incident
    
    INVESTIGATING --> MITIGATED: Firewall Rule Applied / Endpoint Isolated
    INVESTIGATING --> FALSE_POSITIVE: Analyst Flags Model Error (Drift Feedback)
    
    MITIGATED --> RESOLVED: Post-Incident Review Complete
    FALSE_POSITIVE --> RESOLVED: Model Retraining Sample Tagged
    
    RESOLVED --> [*]
```

---

### 4.4 Entity-Relationship Diagram (ERD)

```mermaid
erDiagram
    USERS ||--o{ INCIDENTS : triaged_by
    INCIDENTS ||--|{ ALERTS : contains
    ALERTS ||--|| NETWORK_FLOWS : triggered_by
    INCIDENTS ||--o{ MITIGATION_ACTIONS : triggers
    ML_MODELS ||--o{ ALERTS : classified_by
    ML_MODELS ||--o{ MODEL_DRIFT_METRICS : monitors

    USERS {
        uuid id PK
        string email
        string password_hash
        string full_name
        string role "ADMIN, ANALYST, AUDITOR"
        timestamptz created_at
    }

    NETWORK_FLOWS {
        uuid id PK
        string src_ip
        int src_port
        string dst_ip
        int dst_port
        string protocol "TCP, UDP, ICMP"
        float flow_duration_ms
        bigint total_fwd_packets
        bigint total_bwd_packets
        float flow_bytes_per_sec
        float flow_packets_per_sec
        float syn_flag_ratio
        float packet_length_mean
        float packet_length_std
        timestamptz captured_at
    }

    INCIDENTS {
        uuid id PK
        string title
        string severity "CRITICAL, HIGH, MEDIUM, LOW"
        string status "DETECTED, AUTO_MITIGATED, INVESTIGATING, RESOLVED, FALSE_POSITIVE"
        string primary_attack_vector "DOS, PORTSCAN, BRUTE_FORCE, WEB_ATTACK, BOTNET"
        float risk_score
        uuid assigned_to FK
        timestamptz created_at
        timestamptz updated_at
    }

    ALERTS {
        uuid id PK
        uuid incident_id FK
        uuid flow_id FK
        uuid model_id FK
        string attack_class
        float confidence
        jsonb shap_values "Feature attributions"
        timestamptz created_at
    }

    MITIGATION_ACTIONS {
        uuid id PK
        uuid incident_id FK
        string action_type "BLOCK_IP, RATE_LIMIT, ISOLATE_HOST"
        string target_value "e.g. IP Address"
        string executed_by "SYSTEM_AUTOMATION or USER"
        timestamptz executed_at
    }

    ML_MODELS {
        uuid id PK
        string model_name
        string version
        float accuracy
        float f1_score
        float false_positive_rate
        string artifacts_uri
        timestamptz trained_at
    }

    MODEL_DRIFT_METRICS {
        uuid id PK
        uuid model_id FK
        string feature_name
        float baseline_mean
        float current_window_mean
        float psi_score "Population Stability Index"
        boolean drift_detected
        timestamptz recorded_at
    }
```

---

## 5. Implementation Stages Roadmap

### Stage A: Essential Product
- Ingestion REST API (`POST /api/v1/flows/ingest`)
- Pre-trained XGBoost model with realistic CIC-IDS2017 feature engineering
- Real-time TreeSHAP local explanation generation
- PostgreSQL persistence for incidents and flows
- React SOC Dashboard: Threat Overview, Alerts Feed, and SHAP Explainability Drawer
- Dual authentication & RBAC (Admin & Analyst roles)

### Stage B: Engineering Depth
- Redpanda / Kafka streaming message queue integration
- Redis high-speed IP reputation cache and blacklist enforcement
- Automated mitigation engine (simulated firewall iptables rules & IP blocking)
- WebSocket real-time live threat streaming to frontend
- Incident lifecycle triaging (DETECTED $\to$ INVESTIGATING $\to$ MITIGATED $\to$ RESOLVED)

### Stage C: Production Scale & MLOps
- Model drift monitoring (PSI & Kolmogorov-Smirnov statistical tests)
- Prometheus security telemetry metrics & Grafana monitoring dashboards
- Synthetic network flow replay generator for high-volume stress testing
- Docker Compose multi-container deployment
- Complete end-to-end test suite

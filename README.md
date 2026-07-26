# Hackathon Technical Submission Report: AI-Powered Behavioral Anomaly Detection for Cybersecurity

## 1. Domain-Agnostic Behavioral Assumptions
This implementation acts on the operational thesis that any connection signature, whether originating from an enterprise cloud server, an IoT smart hub, or an industrial Operational Technology (OT) edge gateway running fieldbus/Modbus encapsulations, leaves an unalterable behavioral sequence footprint.

Our architecture transitions away from brittle signature-based approaches toward a **Two-Stage Unsupervised Detection + Supervised Classification Engine**:
* **Temporal Patterns:** Tracks multi-day cyclic trends to identify off-hours data extraction anomalies.
* **Velocity Metrics:** Computes geodesic speed across successive geolocation identifiers to systematically expose impossible-travel events.
* **Footprint Topology:** Identifies shifts in OS, MAC configurations, and communication sequences to flag active device spoofing maneuvers.

---

## 2. Advanced Constraint Architecture Solutions

### A. Severe Class Imbalance Mitigation
Real-world deployments isolate cyber threats within the top <1% of network logs. Relying on classic supervised classification causes severe majority-class bias. Our dual-stage pipeline isolates tracking:
1. **Stage 1 (Detection):** Employs an unsupervised **PyTorch GRU Autoencoder** trained strictly on baseline benign behaviors. It maps multi-dimensional normal boundaries across temporal sequences, generating high reconstruction losses on anomalous entries without requiring prior knowledge of attack structures.
2. **Stage 2 (Classification):** Leverages a lightweight, highly optimized **Multi-Class Random Forest** trained exclusively on the minority anomaly pool. This maps the deviations identified in Stage 1 directly to specific tactical classifications.

### B. The Cold-Start Mitigation Strategy
When a brand-new entity ID registers zero execution logs, it triggers false alarms due to the absence of historical reference nodes. 
* Our framework addresses this through a **Hierarchical Fallback Architecture**. 
* If a target `entity_id` is completely novel, inference calculations query the `entity_profiles.csv` to map the asset's structural class (`user`, `service_account`, `edge_device`). 
* The system evaluates behavior against a cluster-wide **Population-Level Prior Profile** (via an Isolation Forest fallback) until the entity hits a warm-start history threshold of 50 connection sessions.

### C. Concept Drift & Ambient Adaptive Tracking
Legitimate behaviors naturally change as environments evolve (e.g., scheduled firmware updates, new remote work locations). 
* To prevent baseline stagnation, stateful features utilize exponential time-decay moving averages for rolling behavioral baselines.
* This allows the normal threshold boundary to adapt dynamically to routine behavioral variance without hardcoded manual recalibration.

---

## 3. System Architecture & Project Structure

The pipeline is decoupled to ensure stateful streaming feature engineering can occur in near real-time before batched sequence evaluation.

### Architecture Flow
```text
[ Raw Log Ingestion ] 
        │
        ▼
[ Stateful Feature Engineering ] ── (Rolling Windows, Geo-Velocity, Exponential Decay)
        │
        ▼
[ Stage 1: Unsupervised PyTorch GRU Autoencoder ] ── (Learns Baseline / Flags Temporal Deviations)
        │
        ├──> (If Cold Start) ──> [ Isolation Forest / Population Prior Fallback ]
        │
        ▼
[ Stage 2: Supervised Random Forest ] ── (Classifies Deviation into specific Threat Taxonomy)
        │
        ▼
[ Explainability Layer (SHAP) ] ── (Extracts mathematical drivers & translates to plain English)
        │
        ▼
[ Streamlit SOC Dashboard ] ── (Real-time alert budgeting & triage queue)
```

###Key Repository Mapping

```text
cyberthreats/behavioral-anomaly-detection/
├── src/data_generation/      # Handles synthetic attacks and baseline assumptions
├── src/models/               # Contains GRU Detector, RF Classifier, & SHAP Explainability
├── dashboard/app.py          # The Streamlit SOC Analyst UI
└── config/                   # Hyperparameters for alert budgeting and drift decay
```
```text

```


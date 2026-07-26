# Hackathon Technical Submission Report: AI-Powered Behavioral Anomaly Detection for Cybersecurity

> AI/ML system that models "normal" access/connection behaviour for users, service accounts, and edge devices, detects intrusions or compromised-credential activity near real-time, classifies the anomaly type, and explains *why* an event was flagged — domain-agnostic across cloud, OT/edge, and IoT access logs.

## 1. Project Deliverables Status

| Deliverable | Status | Location |
|---|---|---|
| 1. Synthetic data generator + attack taxonomy | ✅ Done | `src/data_generation/` |
| 2. Baseline profiling model (per-entity normal) | ✅ Done | `src/models/baseline_profiling.py` |
| 3. Sequence-aware detection model | ✅ Done | `src/models/sequence_detector.py` |
| 4. Anomaly-type classification | ✅ Done | `src/models/anomaly_classifier.py` |
| 5. Explainability layer | ✅ Done | `src/models/explainability.py` |
| 6. Analyst-facing dashboard | ✅ Done | `dashboard/app.py` |
| 7. Report | ✅ Done | `reports/report.md` |

*✅ = Fully implemented, tested, and runnable via the centralized configuration pipeline.*

---

## 2. Domain-Agnostic Behavioral Assumptions
This implementation acts on the operational thesis that any connection signature, whether originating from an enterprise cloud server, an IoT smart hub, or an industrial Operational Technology (OT) edge gateway running fieldbus/Modbus encapsulations, leaves an unalterable behavioral sequence footprint.

Our architecture transitions away from brittle signature-based approaches toward a **Two-Stage Unsupervised Detection + Supervised Classification Engine**:
* **Temporal Patterns:** Tracks multi-day cyclic trends to identify off-hours data extraction anomalies.
* **Velocity Metrics:** Computes geodesic speed across successive geolocation identifiers to systematically expose impossible-travel events.
* **Footprint Topology:** Identifies shifts in OS, MAC configurations, and communication sequences to flag active device spoofing maneuvers.

---

## 3. Advanced Constraint Architecture Solutions

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

## 4. System Architecture & Project Structure

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

### Repository Mapping
```text
behavioral-anomaly-detection/
├── README.md
├── requirements.txt
├── docker-compose.yml            # Docker orchestration for the Streamlit dashboard
├── config/
│   └── config.yaml               # centralized paths, entity counts, attack rates, model hyperparams
├── data/
│   ├── raw/access_logs.csv               # unlabeled — what a live pipeline would see
│   ├── labeled/access_logs_labeled.csv   # + label, attack_group_id — train/eval only
│   └── reference/entity_profiles.csv     # per-entity baseline (cold-start reference)
├── src/
│   ├── data_generation/          # synthetic data generator and attack injectors
│   ├── features/
│   │   └── feature_engineering.py    # stateful, sequence-aware rolling feature derivations
│   ├── models/
│   │   ├── baseline_profiling.py     # Isolation Forest with role-level fallback for cold starts
│   │   ├── sequence_detector.py      # PyTorch GRU Autoencoder over session sequences
│   │   ├── anomaly_classifier.py     # multi-class Random Forest mapping deviations to tactics
│   │   └── explainability.py         # SHAP-powered feature attribution (translates math to english)
│   ├── pipeline/
│   │   ├── train.py                  # trains PyTorch GRU + classifier with strict time-based split
│   │   ├── infer.py                  # scores streaming logs, applies thresholds, generates explanations
│   │   └── streaming_simulator.py    # replays access_logs.csv as a live event stream
│   └── utils/
│       └── metrics.py                # PR-AUC, alert-budget precision validation
├── dashboard/
│   ├── app.py                    # Streamlit SOC analyst UI (ranked queue, risk score, entity history)
├── notebooks/
│   └── eda.ipynb                 # exploratory analysis of the synthetic data
├── reports/
│   └── report.md                 # assumptions, metric results, constraint mitigation strategies
└── docker/
    └── Dockerfile                # containerization for the UI
```
### Quickstart and execution
```text
# 1. Install dependencies
pip install -r requirements.txt

# 2. Generate synthetic data (creates the 3 required CSVs in data/)
python -m src.data_generation.generate_dataset --n-days 45 --seed 42

# 3. Train the GRU sequence detector and multi-class classifier end-to-end
python -m src.pipeline.train --config config/config.yaml

# 4. Score the raw/unlabeled stream and generate feature attributions
python -m src.pipeline.infer --config config/config.yaml

# 5. Launch the Analyst Triage Dashboard
streamlit run dashboard/app.py
```

### Architecture

![System Architecture](architecture.png)
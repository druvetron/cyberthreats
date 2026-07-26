# Behavioural Anomaly Detection for Cybersecurity

AI/ML system that models "normal" access/connection behaviour for users,
service accounts, and edge devices, detects intrusions or compromised-
credential activity near real-time, classifies the anomaly type, and
explains *why* an event was flagged — domain-agnostic across cloud, OT/edge,
and IoT access logs.

## Status

| Deliverable                                   | Status        | Location |
|------------------------------------------------|--------------|----------|
| 1. Synthetic data generator + attack taxonomy   | ✅ Done       | `src/data_generation/` |
| 2. Baseline profiling model (per-entity normal) | ✅ Done       | `src/models/baseline_profiling.py` |
| 3. Sequence-aware detection model               | ✅ Done       | `src/models/sequence_detector.py` |
| 4. Anomaly-type classification                  | ✅ Done       | `src/models/anomaly_classifier.py` |
| 5. Explainability layer                         | ✅ Done       | `src/models/explainability.py` |
| 6. Analyst-facing dashboard                     | ✅ Done       | `dashboard/app.py` |
| 7. Report                                       | ✅ Done       | `reports/report.md` |

✅ = Fully implemented, tested, and runnable via the centralized configuration pipeline.

## Project structure

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
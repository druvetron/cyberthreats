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
| 2. Baseline profiling model (per-entity normal) | 🚧 Scaffolded | `src/models/baseline_profiling.py` |
| 3. Sequence-aware detection model               | 🚧 Scaffolded | `src/models/sequence_detector.py` |
| 4. Anomaly-type classification                  | 🚧 Scaffolded | `src/models/anomaly_classifier.py` |
| 5. Explainability layer                         | 🚧 Scaffolded | `src/models/explainability.py` |
| 6. Analyst-facing dashboard                     | 🚧 Scaffolded | `dashboard/app.py` |
| 7. Report                                       | 🚧 Skeleton   | `reports/report.md` |

✅ = implemented and runnable now. 🚧 = folder/file + interface defined, logic is TODO.

## Project structure

```
behavioral-anomaly-detection/
├── README.md
├── requirements.txt
├── config/
│   └── config.yaml               # entity counts, date range, attack rates, model hyperparams
├── data/
│   ├── raw/access_logs.csv               # unlabeled — what a live pipeline would see
│   ├── labeled/access_logs_labeled.csv   # + label, attack_group_id — train/eval only
│   └── reference/entity_profiles.csv     # per-entity baseline (cold-start reference)
├── src/
│   ├── data_generation/          # ✅ synthetic data generator (this is what's implemented)
│   │   ├── entity_profiles.py    # per-entity "normal" baseline builder
│   │   ├── normal_traffic.py     # benign session sampler
│   │   ├── attack_injectors.py   # one function per attack pattern in the spec
│   │   ├── common.py             # shared row/geo/fingerprint helpers
│   │   └── generate_dataset.py   # CLI entry point, writes the 3 CSVs above
│   ├── features/
│   │   └── feature_engineering.py    # turns raw rows into model-ready features
│   ├── models/
│   │   ├── baseline_profiling.py     # per-entity statistical profile / autoencoder / one-class SVM
│   │   ├── sequence_detector.py      # LSTM/GRU/Transformer over session sequences
│   │   ├── anomaly_classifier.py     # multi-class: which attack type does this resemble
│   │   └── explainability.py         # SHAP-style feature attribution per alert
│   ├── pipeline/
│   │   ├── train.py                  # train baseline + detector + classifier end to end
│   │   ├── infer.py                  # score a batch/stream, apply cold-start fallback
│   │   └── streaming_simulator.py    # replays access_logs.csv as a live event stream
│   └── utils/
│       └── metrics.py                # PR-AUC, alert-budget precision, drift metrics
├── dashboard/
│   ├── app.py                    # Streamlit analyst dashboard (ranked queue, risk score, entity history)
│   └── components/
├── notebooks/
│   └── eda.ipynb                 # exploratory analysis of the synthetic data
├── reports/
│   └── report.md                 # assumptions, metrics, known limitations
├── presentation/
│   └── README.md                 # notes for filling in the required slide template
├── tests/
│   └── test_data_generation.py
└── docker/
    └── Dockerfile
```

## Quickstart

```bash
pip install -r requirements.txt

# 1. Generate synthetic data (already run once; re-run anytime to resample)
python -m src.data_generation.generate_dataset --n-days 45 --seed 42

# 2. (once implemented) train baseline + detector + classifier
python -m src.pipeline.train --config config/config.yaml

# 3. (once implemented) score the raw/unlabeled stream and launch the dashboard
python -m src.pipeline.infer --input data/raw/access_logs.csv --output data/scored_alerts.csv
streamlit run dashboard/app.py
```

## Design notes carried over from the problem statement

- **Sequential, not static**: rows are individual sessions/events; entity history
  across time is what makes impossible-travel, lateral-movement, and low-and-slow
  patterns detectable — a per-row classifier alone will underperform a sequence model.
- **Class imbalance**: synthetic anomaly rate is tuned to ~2% of rows, mirroring the
  0.5–3% range from the spec. Evaluate with PR-AUC and alert-budget precision
  (e.g. precision @ top 1% of scored events), not plain accuracy.
- **Concept drift**: `insider_drift_edge_case` rows are intentionally ambiguous —
  a legitimate entity's footprint widens slowly over weeks. They're labeled
  separately from hard anomalies (`is_edge_case=True`) specifically so they can be
  used to tune the false-positive rate rather than as a detection target.
- **Cold start**: `entity_profiles.csv` only reflects entities present during
  generation. `baseline_profiling.py` should define a fallback score (e.g.
  population/role-level prior) for entity_ids never seen before.
- **Explainability**: every alert should resolve to a short list of contributing
  features (e.g. "geo-velocity + new device fingerprint"), not just a score —
  `attack_group_id` in the labeled data can be used to validate that the
  explanation lines up with the actual injected mechanism during dev/testing.

## Schema note

The generator's CSV columns are a superset of the schema table in the problem
statement — `session_id`, `auth_result`, `attack_group_id`, and `is_edge_case`
were added because they're needed to simulate/evaluate failed-auth bursts
(brute force, credential stuffing) and to link multi-row campaigns for
sequence-aware evaluation. `attack_group_id` and `is_edge_case` are stripped
from `data/raw/access_logs.csv` along with `label`, since a real inference
pipeline wouldn't have them.

# Report — Behavioural Anomaly Detection for Cybersecurity

*Skeleton — fill in as each deliverable is implemented. Section headers match
the evaluation criteria so nothing gets missed.*

## 1. Problem framing & assumptions

- Domain-agnostic access-log model: same schema covers cloud/user auth,
  service-account API activity, and edge/IoT device connections.
- [ ] State any assumptions made about what counts as "normal" per entity_type.
- [ ] State assumptions behind the synthetic data (see `data/reference/entity_profiles.csv`
      and `src/data_generation/` docstrings for what's already encoded).

## 2. Synthetic data summary

- Rows: *(fill in from `generate_dataset.py` stdout, e.g. 48,457)*
- Entities: 150 users / 30 service accounts / 40 edge devices over 45 days
- Label distribution: *(paste `df['label'].value_counts()`)*
- Hard anomaly rate: *(target 0.5-3%, per spec)*
- Ambiguous edge-case rate (`insider_drift_edge_case`): *(kept separate — see README)*

## 3. Modelling approach

| Component | Method | Why |
|---|---|---|
| Baseline profiling | *(statistical / one-class SVM / autoencoder — pick one)* | |
| Sequence detector | *(LSTM / GRU / Transformer)* | |
| Anomaly classifier | *(e.g. gradient-boosted trees)* | |
| Explainability | SHAP | |

## 4. Detection accuracy on imbalanced labels

- [ ] PR-AUC (overall, and per anomaly_type)
- [ ] Precision/recall @ alert budget (top 1% of scored events — `config.evaluation.alert_budget_pct`)
- [ ] Confusion matrix across anomaly types

## 5. False positive rate at a realistic analyst alert budget

- [ ] Precision @ top 1% of events
- [ ] `insider_drift_edge_case` flag rate specifically (should be low — these
      are legitimate-but-unusual, not attacks; see `false_positive_rate_on_edge_cases`
      in `src/utils/metrics.py`)

## 6. Explainability / analyst usability

- [ ] Example alert with top-k SHAP reasons rendered as text
      (e.g. "flagged due to geo-velocity 2,140 km/h + new device fingerprint")
- [ ] Screenshot(s) of `dashboard/app.py`

## 7. Cold-start & concept drift handling

- [ ] How a brand-new entity_id is scored before it has history
      (`baseline_profiling.cold_start_fallback`)
- [ ] How the profile adapts as legitimate behaviour evolves without
      permanently flagging drifted-but-legitimate users
      (`config.drift.profile_decay_halflife_days`, retrain cadence)

## 8. System design & scalability

- [ ] Streaming feasibility numbers from `src/pipeline/streaming_simulator.py`
      (rows/sec throughput, p50/p95/p99 scoring latency)
- [ ] Architecture diagram: ingestion → feature store → baseline profiler →
      sequence detector → classifier → explainability → dashboard

## 9. Known limitations

- Synthetic data encodes the attack patterns the generator's authors thought
  of; real intrusions will include patterns not represented here.
- [ ] Add any limitations found during modelling (e.g. classes the model
      confuses, sequence length trade-offs, cold-start blind spots).

## 10. Reproducing this report

```bash
python -m src.data_generation.generate_dataset --seed 42
python -m src.pipeline.train --config config/config.yaml
python -m src.pipeline.infer --input data/raw/access_logs.csv --output data/scored_alerts.csv
```

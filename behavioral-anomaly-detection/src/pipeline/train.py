"""
train.py — end-to-end training entry point.

Planned flow:
    1. load_access_logs(data/labeled/access_logs_labeled.csv)
    2. build_features(...)  from src.features.feature_engineering
    3. fit baseline_profiling.EntityProfiler on normal rows only
    4. build sequence windows, train sequence_detector on normal windows
       (unsupervised: reconstruction / next-event likelihood)
    5. score all windows -> threshold at config.evaluation.alert_budget_pct
       to get the "flagged" set
    6. train anomaly_classifier on flagged + labeled rows (excluding
       insider_drift_edge_case from training labels, see anomaly_classifier.py)
    7. evaluate with src.utils.metrics against the held-out labeled split
    8. save all fitted models under models/ (create this dir; gitignored)

Usage (once implemented):
    python -m src.pipeline.train --config config/config.yaml
"""

import argparse
import yaml


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config/config.yaml")
    args = parser.parse_args()

    with open(args.config) as f:
        config = yaml.safe_load(f)

    raise NotImplementedError(
        "Wire up feature_engineering -> baseline_profiling -> "
        "sequence_detector -> anomaly_classifier -> metrics. "
        f"Config loaded OK: {list(config.keys())}"
    )


if __name__ == "__main__":
    main()

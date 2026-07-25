"""
infer.py — score new/unseen access-log rows (data/raw/access_logs.csv has
no label column, simulating what this would see in production).

Planned flow:
    1. load rows (batch file or, eventually, from streaming_simulator)
    2. build_features(...) using each entity's stored profile;
       entities with no stored profile -> baseline_profiling.cold_start_score
    3. sequence_detector.score(...) -> raw anomaly score
    4. threshold at config.evaluation.alert_budget_pct -> flagged subset
    5. anomaly_classifier.predict(...) on the flagged subset -> anomaly_type
    6. explainability.explain_batch(...) -> human-readable reasons
    7. write ranked alert queue (entity_id, timestamp, risk_score,
       predicted_type, reasons) for the dashboard to read

Usage (once implemented):
    python -m src.pipeline.infer --input data/raw/access_logs.csv --output data/scored_alerts.csv
"""

import argparse


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--config", default="config/config.yaml")
    args = parser.parse_args()

    raise NotImplementedError(
        "Load trained models from train.py's output, run the scoring "
        f"pipeline described in the module docstring on {args.input}, "
        f"write ranked alerts to {args.output}."
    )


if __name__ == "__main__":
    main()

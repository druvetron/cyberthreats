"""
generate_dataset.py — entry point for synthetic data generation.

Run:
    python -m src.data_generation.generate_dataset

Produces:
    data/labeled/access_logs_labeled.csv   (full ground truth — train/eval only)
    data/raw/access_logs.csv               (label + attack_group_id stripped —
                                             what an inference pipeline would see)
    data/reference/entity_profiles.csv     (per-entity baseline, for the
                                             cold-start / profiling module)
"""

import argparse
import datetime as dt
import random
import pandas as pd

from .entity_profiles import build_entities
from .normal_traffic import generate_normal_sessions
from . import attack_injectors as ai


_REFERENCE_ENTITY_DAYS = (150 + 30 + 40) * 45
_BASE_CAMPAIGN_COUNTS = {
    "brute_force": 8,
    "impossible_travel": 40,
    "credential_stuffing": 5,
    "lateral_movement": 15,
    "device_spoofing": 20,
    "low_and_slow": 10,
    "insider_drift": 8,
}


def generate(n_users=150, n_service_accounts=30, n_edge_devices=40,
             n_days=45, seed=42):
    rng = random.Random(seed)
    start_date = dt.date(2026, 6, 1)
    end_date = start_date + dt.timedelta(days=n_days)

    profiles = build_entities(n_users, n_service_accounts, n_edge_devices, seed=seed)

    # Attack campaign counts are calibrated for the reference dataset size
    # (150/30/40 entities, 45 days); scale proportionally for other sizes so
    # the anomaly rate stays in the spec's suggested 0.5-3% band instead of
    # being a fixed absolute count regardless of normal-traffic volume.
    entity_days = (n_users + n_service_accounts + n_edge_devices) * n_days
    scale = entity_days / _REFERENCE_ENTITY_DAYS
    counts = {k: max(1, round(v * scale)) for k, v in _BASE_CAMPAIGN_COUNTS.items()}

    rows = []
    rows += generate_normal_sessions(profiles, start_date, end_date, seed=seed)
    rows += ai.inject_brute_force(profiles, start_date, end_date, rng, n_campaigns=counts["brute_force"])
    rows += ai.inject_impossible_travel(profiles, start_date, end_date, rng, n_incidents=counts["impossible_travel"])
    rows += ai.inject_credential_stuffing(profiles, start_date, end_date, rng, n_campaigns=counts["credential_stuffing"])
    rows += ai.inject_lateral_movement(profiles, start_date, end_date, rng, n_campaigns=counts["lateral_movement"])
    rows += ai.inject_device_spoofing(profiles, start_date, end_date, rng, n_incidents=counts["device_spoofing"])
    rows += ai.inject_low_and_slow_exfiltration(profiles, start_date, end_date, rng, n_campaigns=counts["low_and_slow"])
    rows += ai.inject_insider_drift(profiles, start_date, end_date, rng, n_entities=min(counts["insider_drift"], n_users))

    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"], format="ISO8601")
    df = df.sort_values("timestamp").reset_index(drop=True)
    # re-issue session_id in chronological order so ids look natural in a stream
    df["session_id"] = [f"sess_{i:08d}" for i in range(1, len(df) + 1)]

    profiles_df = pd.DataFrame([
        {
            "entity_id": p["entity_id"],
            "entity_type": p["entity_type"],
            "home_city": p["home_city"],
            "home_country": p["home_country"],
            "typical_resources": ";".join(p["typical_resources"]),
            "usual_ips": ";".join(p["usual_ips"]),
            "active_hours": f'{p["active_hours"][0]}-{p["active_hours"][1]}',
            "avg_session_minutes": round(p["avg_session_minutes"], 2),
            "device_os": p["device_os"],
            "device_mac": p["device_mac"],
            "protocol": p["protocol"],
        }
        for p in profiles
    ])

    return df, profiles_df


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic access-log data")
    parser.add_argument("--n-users", type=int, default=150)
    parser.add_argument("--n-service-accounts", type=int, default=30)
    parser.add_argument("--n-edge-devices", type=int, default=40)
    parser.add_argument("--n-days", type=int, default=45)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--outdir", type=str, default="data")
    args = parser.parse_args()

    df, profiles_df = generate(args.n_users, args.n_service_accounts,
                                args.n_edge_devices, args.n_days, args.seed)

    labeled_path = f"{args.outdir}/labeled/access_logs_labeled.csv"
    raw_path = f"{args.outdir}/raw/access_logs.csv"
    profiles_path = f"{args.outdir}/reference/entity_profiles.csv"

    df.to_csv(labeled_path, index=False)

    unlabeled_cols = [c for c in df.columns if c not in ("label", "attack_group_id", "is_edge_case")]
    df[unlabeled_cols].to_csv(raw_path, index=False)

    profiles_df.to_csv(profiles_path, index=False)

    print(f"Total rows: {len(df)}")
    print(df["label"].value_counts())
    print(f"\nWrote:\n  {labeled_path}\n  {raw_path}\n  {profiles_path}")


if __name__ == "__main__":
    main()

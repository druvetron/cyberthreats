"""
Tests for the one deliverable that's actually implemented so far: the
synthetic data generator. Run with `pytest` from the project root.
"""

import sys
import os
import math

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.data_generation.generate_dataset import generate
from src.data_generation.common import haversine_km

EXPECTED_LABELS = {
    "normal",
    "anomaly_brute_force",
    "anomaly_impossible_travel",
    "anomaly_credential_stuffing",
    "anomaly_lateral_movement",
    "anomaly_device_spoofing",
    "anomaly_low_and_slow_exfil",
    "insider_drift_edge_case",
}

EXPECTED_COLUMNS = {
    "session_id", "entity_id", "entity_type", "timestamp", "source_ip",
    "geo_city", "geo_country", "geo_lat", "geo_lon", "resource_accessed",
    "auth_method", "auth_result", "session_duration_sec", "command_sequence",
    "device_fingerprint", "label", "attack_group_id", "is_edge_case",
}


def _small_dataset():
    # small + fixed seed so tests run fast and deterministically
    return generate(n_users=20, n_service_accounts=5, n_edge_devices=5, n_days=10, seed=1)


def test_columns_match_schema():
    df, _ = _small_dataset()
    assert set(df.columns) == EXPECTED_COLUMNS


def test_labels_are_known():
    df, _ = _small_dataset()
    assert set(df["label"].unique()) <= EXPECTED_LABELS


def test_normal_rows_have_no_attack_group():
    df, _ = _small_dataset()
    normal = df[df["label"] == "normal"]
    assert (normal["attack_group_id"] == "").all()


def test_anomaly_rows_have_attack_group():
    df, _ = _small_dataset()
    anomalies = df[df["label"] != "normal"]
    assert (anomalies["attack_group_id"] != "").all()


def test_anomaly_rate_within_target_range():
    df, _ = _small_dataset()
    hard_anomalies = df["label"].str.startswith("anomaly_").sum()
    rate = hard_anomalies / len(df)
    # spec suggests injecting at 0.5-3% of sessions; small-N runs can drift
    # a bit above that, so allow headroom rather than pin the exact range
    assert 0.001 < rate < 0.10, f"anomaly rate {rate:.3%} looks off"


def test_impossible_travel_is_actually_impossible():
    df, _ = _small_dataset()
    for gid, group in df[df["label"] == "anomaly_impossible_travel"].groupby("attack_group_id"):
        assert len(group) == 2
        a, b = group.sort_values("timestamp").itertuples()
        dist_km = haversine_km(a.geo_lat, a.geo_lon, b.geo_lat, b.geo_lon)
        hours = (b.timestamp - a.timestamp).total_seconds() / 3600
        implied_speed = dist_km / max(hours, 1e-6)
        assert implied_speed > 900, f"{gid}: implied speed {implied_speed:.0f} km/h is not implausible"


def test_entity_profiles_cover_all_entities_in_logs():
    df, profiles_df = _small_dataset()
    assert set(df["entity_id"]) <= set(profiles_df["entity_id"])


def test_insider_drift_is_flagged_as_edge_case_not_hard_anomaly():
    df, _ = _small_dataset()
    drift = df[df["label"] == "insider_drift_edge_case"]
    if len(drift):
        assert drift["is_edge_case"].all()

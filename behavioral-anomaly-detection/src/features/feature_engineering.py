"""
feature_engineering.py

Turns raw access-log rows into model-ready features. This is where the
"behavioural" part of behavioural anomaly detection actually lives — a
single row (one session) is not very informative on its own; what matters
is how it compares to that entity's own history and to its peers.

TODO — implement:
    - Rolling per-entity aggregates over config.features.windows
      (session count, distinct resources, distinct source_ips, failure rate)
    - geo_velocity_kmh: haversine(prev_geo, cur_geo) / time_delta_hours
      -> primary signal for impossible travel
    - novelty flags: resource_accessed not in entity's historical set,
      device_fingerprint changed, source_ip not in entity's historical set
    - off_hours flag relative to the entity's own typical active_hours
      (not a fixed global business-hours window — a night-shift worker's
      3am login is normal for them)
    - command_sequence features: n-gram / sensitive-action ratio
    - peer-group baseline: same entity_type's population statistics, used
      for cold-start entities with no individual history yet
"""

import pandas as pd


def load_access_logs(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, parse_dates=["timestamp"])
    return df.sort_values(["entity_id", "timestamp"]).reset_index(drop=True)


def build_features(df: pd.DataFrame, entity_profiles: pd.DataFrame) -> pd.DataFrame:
    """Return a feature matrix (one row per session) ready for the
    baseline profiler / sequence detector. Placeholder — raises until
    implemented so it fails loudly instead of silently returning raw data."""
    raise NotImplementedError(
        "Implement rolling aggregates, geo-velocity, and novelty flags per "
        "config/config.yaml -> features. See module docstring for the plan."
    )

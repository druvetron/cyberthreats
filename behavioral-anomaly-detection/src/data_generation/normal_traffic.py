"""
normal_traffic.py — samples benign sessions for every entity across the
simulation window, following that entity's baseline profile with realistic
noise (occasional off-hour login, rare non-typical resource, rare typo'd
failed auth). This is the "Normal baseline" row in the Behaviours-to-Simulate
table of the problem statement.
"""

import random
import datetime as dt

from .entity_profiles import _weighted_choice, _random_ip
from .common import make_row, sample_command_sequence


def _sample_hour(rng, active_hours):
    start, end = active_hours
    if start <= end:
        if rng.random() < 0.05:  # small chance of an off-hour session (noise, not anomaly)
            return rng.randint(0, 23)
        return rng.randint(start, end)
    else:  # wraps past midnight (night shift)
        if rng.random() < 0.05:
            return rng.randint(0, 23)
        return rng.choice(list(range(start, 24)) + list(range(0, end + 1)))


def generate_normal_sessions(profiles, start_date, end_date, seed=42):
    rng = random.Random(seed)
    rows = []
    n_days = (end_date - start_date).days

    for profile in profiles:
        lam = profile["sessions_per_day_lambda"]
        for day_offset in range(n_days):
            day = start_date + dt.timedelta(days=day_offset)
            n_sessions = max(0, int(rng.gauss(lam, lam * 0.25)))
            for _ in range(n_sessions):
                hour = _sample_hour(rng, profile["active_hours"])
                minute = rng.randint(0, 59)
                second = rng.randint(0, 59)
                timestamp = dt.datetime(day.year, day.month, day.day, hour % 24, minute, second)

                # resource: mostly from the entity's typical working set
                if rng.random() < 0.92:
                    resource = rng.choice(profile["typical_resources"])
                else:
                    resource = rng.choice(profile["typical_resources"])  # kept in-set; true novelty = anomaly signal

                source_ip = rng.choice(profile["usual_ips"])
                auth_method = _weighted_choice(profile["auth_method_weights"])
                auth_result = "success" if rng.random() > 0.02 else "failure"  # rare, non-clustered typo
                duration = max(1, rng.gauss(profile["avg_session_minutes"] * 60,
                                             profile["avg_session_minutes"] * 15))
                cmd_seq = sample_command_sequence(rng, sensitive_bias=0.04)

                rows.append(make_row(
                    entity_id=profile["entity_id"],
                    entity_type=profile["entity_type"],
                    timestamp=timestamp,
                    source_ip=source_ip,
                    geo_city=profile["home_city"],
                    geo_country=profile["home_country"],
                    geo_lat=profile["home_lat"] + rng.uniform(-0.02, 0.02),
                    geo_lon=profile["home_lon"] + rng.uniform(-0.02, 0.02),
                    resource=resource,
                    auth_method=auth_method,
                    auth_result=auth_result,
                    duration_sec=duration,
                    command_sequence=cmd_seq,
                    device_os=profile["device_os"],
                    device_mac=profile["device_mac"],
                    protocol=profile["protocol"],
                    label="normal",
                ))
    return rows

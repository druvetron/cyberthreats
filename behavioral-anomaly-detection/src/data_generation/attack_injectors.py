"""
attack_injectors.py

One function per row of the "Behaviours to Simulate" table in the problem
statement. Each function takes the pool of entity profiles plus a time
window and returns a list of rows (same shape as normal_traffic rows) that
deviate from the target entity's baseline in the specific way that attack
pattern implies. Every campaign gets a shared `attack_group_id` so a
sequence-aware model has a ground-truth grouping to learn from, and so the
report can measure "did we flag the whole campaign or just one row".
"""

import random
import uuid
import datetime as dt

from .entity_profiles import CITIES, DEVICE_OS_POOL, PROTOCOLS, RESOURCE_POOL, _random_ip, _random_mac
from .common import make_row, sample_command_sequence, haversine_km


def _gid(tag):
    return f"{tag}_{uuid.uuid4().hex[:8]}"


def _rand_ts(rng, start_date, end_date):
    span = (end_date - start_date).days
    day = start_date + dt.timedelta(days=rng.randint(0, max(span - 1, 0)))
    return dt.datetime(day.year, day.month, day.day, rng.randint(0, 23), rng.randint(0, 59), rng.randint(0, 59))


# ---------------------------------------------------------------------------
def inject_brute_force(profiles, start_date, end_date, rng, n_campaigns=8):
    rows = []
    targets = [p for p in profiles if p["entity_type"] in ("user", "service_account")]
    for _ in range(n_campaigns):
        target = rng.choice(targets)
        attacker_ip = _random_ip(rng)
        attacker_city = rng.choice(CITIES)
        gid = _gid("bruteforce")
        t0 = _rand_ts(rng, start_date, end_date)
        n_attempts = rng.randint(15, 40)
        succeeds = rng.random() < 0.3
        for i in range(n_attempts):
            ts = t0 + dt.timedelta(seconds=i * rng.randint(3, 12))
            is_last = (i == n_attempts - 1)
            result = "success" if (is_last and succeeds) else "failure"
            rows.append(make_row(
                entity_id=target["entity_id"], entity_type=target["entity_type"], timestamp=ts,
                source_ip=attacker_ip, geo_city=attacker_city[0], geo_country=attacker_city[1],
                geo_lat=attacker_city[2], geo_lon=attacker_city[3],
                resource="auth:login_portal", auth_method="password", auth_result=result,
                duration_sec=rng.uniform(1, 4),
                command_sequence="login" if result == "failure" else "login;logout",
                device_os=rng.choice(DEVICE_OS_POOL), device_mac=_random_mac(rng), protocol="HTTPS",
                label="anomaly_brute_force", attack_group_id=gid,
            ))
    return rows


# ---------------------------------------------------------------------------
def inject_impossible_travel(profiles, start_date, end_date, rng, n_incidents=40):
    rows = []
    targets = [p for p in profiles if p["entity_type"] == "user"]
    for _ in range(n_incidents):
        target = rng.choice(targets)
        gid = _gid("impossible_travel")
        t0 = _rand_ts(rng, start_date, end_date)
        home = (target["home_city"], target["home_country"], target["home_lat"], target["home_lon"])
        # pick a far city such that required speed is physically impossible for the time gap
        gap_minutes = rng.uniform(15, 180)
        far_city = max(CITIES, key=lambda c: haversine_km(home[2], home[3], c[2], c[3]))
        dist_km = haversine_km(home[2], home[3], far_city[2], far_city[3])
        implied_speed = dist_km / (gap_minutes / 60)  # km/h, will be absurd (>2000 km/h)

        rows.append(make_row(
            entity_id=target["entity_id"], entity_type="user", timestamp=t0,
            source_ip=rng.choice(target["usual_ips"]), geo_city=home[0], geo_country=home[1],
            geo_lat=home[2], geo_lon=home[3], resource=rng.choice(target["typical_resources"]),
            auth_method=rng.choice(list(target["auth_method_weights"].keys())), auth_result="success",
            duration_sec=rng.uniform(60, 600), command_sequence=sample_command_sequence(rng),
            device_os=target["device_os"], device_mac=target["device_mac"], protocol=target["protocol"],
            label="anomaly_impossible_travel", attack_group_id=gid,
        ))
        rows.append(make_row(
            entity_id=target["entity_id"], entity_type="user",
            timestamp=t0 + dt.timedelta(minutes=gap_minutes),
            source_ip=_random_ip(rng), geo_city=far_city[0], geo_country=far_city[1],
            geo_lat=far_city[2], geo_lon=far_city[3], resource=rng.choice(target["typical_resources"]),
            auth_method=rng.choice(list(target["auth_method_weights"].keys())), auth_result="success",
            duration_sec=rng.uniform(60, 600), command_sequence=sample_command_sequence(rng),
            device_os=rng.choice(DEVICE_OS_POOL), device_mac=_random_mac(rng), protocol=target["protocol"],
            label="anomaly_impossible_travel", attack_group_id=gid,
        ))
    return rows


# ---------------------------------------------------------------------------
def inject_credential_stuffing(profiles, start_date, end_date, rng, n_campaigns=5):
    rows = []
    for _ in range(n_campaigns):
        attacker_ips = [_random_ip(rng) for _ in range(rng.randint(2, 3))]
        attacker_city = rng.choice(CITIES)
        gid = _gid("cred_stuffing")
        t0 = _rand_ts(rng, start_date, end_date)
        n_targets = rng.randint(30, 80)
        targets = rng.sample(profiles, k=min(n_targets, len(profiles)))
        for i, target in enumerate(targets):
            ts = t0 + dt.timedelta(seconds=i * rng.randint(1, 8))
            result = "success" if rng.random() < 0.07 else "failure"
            rows.append(make_row(
                entity_id=target["entity_id"], entity_type=target["entity_type"], timestamp=ts,
                source_ip=rng.choice(attacker_ips), geo_city=attacker_city[0], geo_country=attacker_city[1],
                geo_lat=attacker_city[2], geo_lon=attacker_city[3],
                resource="auth:login_portal", auth_method="password", auth_result=result,
                duration_sec=rng.uniform(1, 3),
                command_sequence="login" if result == "failure" else "login;logout",
                device_os=rng.choice(DEVICE_OS_POOL), device_mac=_random_mac(rng), protocol="HTTPS",
                label="anomaly_credential_stuffing", attack_group_id=gid,
            ))
    return rows


# ---------------------------------------------------------------------------
def inject_lateral_movement(profiles, start_date, end_date, rng, n_campaigns=15):
    rows = []
    targets = [p for p in profiles if p["entity_type"] in ("user", "service_account")]
    all_resources = sorted({r for pool in RESOURCE_POOL.values() for r in pool})
    for _ in range(n_campaigns):
        target = rng.choice(targets)
        gid = _gid("lateral_movement")
        t0 = _rand_ts(rng, start_date, end_date)
        unseen = [r for r in all_resources if r not in target["typical_resources"]]
        n_hops = rng.randint(10, 25)
        chosen = rng.sample(unseen, k=min(n_hops, len(unseen)))
        for i, resource in enumerate(chosen):
            ts = t0 + dt.timedelta(minutes=i * rng.uniform(1, 12))
            rows.append(make_row(
                entity_id=target["entity_id"], entity_type=target["entity_type"], timestamp=ts,
                source_ip=rng.choice(target["usual_ips"]), geo_city=target["home_city"],
                geo_country=target["home_country"], geo_lat=target["home_lat"], geo_lon=target["home_lon"],
                resource=resource, auth_method=rng.choice(list(target["auth_method_weights"].keys())),
                auth_result="success", duration_sec=rng.uniform(20, 300),
                command_sequence=sample_command_sequence(rng, sensitive_bias=0.55, length=rng.randint(3, 6)),
                device_os=target["device_os"], device_mac=target["device_mac"], protocol=target["protocol"],
                label="anomaly_lateral_movement", attack_group_id=gid,
            ))
    return rows


# ---------------------------------------------------------------------------
def inject_device_spoofing(profiles, start_date, end_date, rng, n_incidents=20):
    rows = []
    targets = [p for p in profiles if p["entity_type"] == "edge_device"]
    for _ in range(n_incidents):
        target = rng.choice(targets)
        gid = _gid("device_spoof")
        n_rows = rng.randint(1, 3)
        t0 = _rand_ts(rng, start_date, end_date)
        spoof_os = rng.choice([o for o in DEVICE_OS_POOL if o != target["device_os"]])
        spoof_mac = _random_mac(rng)
        spoof_protocol = rng.choice([p for p in PROTOCOLS if p != target["protocol"]])
        for i in range(n_rows):
            ts = t0 + dt.timedelta(minutes=i * rng.uniform(1, 30))
            rows.append(make_row(
                entity_id=target["entity_id"], entity_type="edge_device", timestamp=ts,
                source_ip=_random_ip(rng), geo_city=target["home_city"], geo_country=target["home_country"],
                geo_lat=target["home_lat"], geo_lon=target["home_lon"],
                resource=rng.choice(target["typical_resources"]), auth_method="certificate",
                auth_result="success", duration_sec=rng.uniform(1, 20),
                command_sequence=sample_command_sequence(rng, length=2),
                device_os=spoof_os, device_mac=spoof_mac, protocol=spoof_protocol,
                label="anomaly_device_spoofing", attack_group_id=gid,
            ))
    return rows


# ---------------------------------------------------------------------------
def inject_low_and_slow_exfiltration(profiles, start_date, end_date, rng, n_campaigns=10):
    rows = []
    targets = [p for p in profiles if p["entity_type"] in ("user", "service_account")]
    for _ in range(n_campaigns):
        target = rng.choice(targets)
        gid = _gid("low_and_slow")
        campaign_days = rng.randint(10, 30)
        campaign_start = start_date + dt.timedelta(
            days=rng.randint(0, max((end_date - start_date).days - campaign_days, 1)))
        touch_days = sorted(rng.sample(range(campaign_days), k=max(3, campaign_days // 3)))
        for d in touch_days:
            day = campaign_start + dt.timedelta(days=d)
            for _ in range(rng.randint(1, 3)):
                off_hour = rng.choice(list(range(0, 5)) + list(range(22, 24)))
                ts = dt.datetime(day.year, day.month, day.day, off_hour, rng.randint(0, 59), rng.randint(0, 59))
                rows.append(make_row(
                    entity_id=target["entity_id"], entity_type=target["entity_type"], timestamp=ts,
                    source_ip=rng.choice(target["usual_ips"]), geo_city=target["home_city"],
                    geo_country=target["home_country"], geo_lat=target["home_lat"], geo_lon=target["home_lon"],
                    resource=rng.choice(target["typical_resources"]),
                    auth_method=rng.choice(list(target["auth_method_weights"].keys())), auth_result="success",
                    duration_sec=rng.uniform(30, 180),
                    command_sequence=sample_command_sequence(rng, sensitive_bias=0.6, length=rng.randint(2, 4)),
                    device_os=target["device_os"], device_mac=target["device_mac"], protocol=target["protocol"],
                    label="anomaly_low_and_slow_exfil", attack_group_id=gid,
                ))
    return rows


# ---------------------------------------------------------------------------
def inject_insider_drift(profiles, start_date, end_date, rng, n_entities=8):
    """Ambiguous edge case: a legitimate entity's footprint widens gradually
    over the whole window. Not a hard label of 'anomaly' — used to tune the
    false-positive rate of the detector rather than as a detection target."""
    rows = []
    targets = [p for p in profiles if p["entity_type"] == "user"]
    all_resources = sorted({r for pool in RESOURCE_POOL.values() for r in pool})
    for target in rng.sample(targets, k=min(n_entities, len(targets))):
        gid = _gid("insider_drift")
        n_days = (end_date - start_date).days
        n_touches = rng.randint(15, 30)
        drift_pool = [r for r in all_resources if r not in target["typical_resources"]]
        rng.shuffle(drift_pool)
        for i in range(n_touches):
            day_offset = int((i / n_touches) * n_days)  # spread across the window, widening over time
            day = start_date + dt.timedelta(days=day_offset)
            hour = rng.randint(*target["active_hours"]) if target["active_hours"][0] <= target["active_hours"][1] \
                else rng.randint(0, 23)
            ts = dt.datetime(day.year, day.month, day.day, hour, rng.randint(0, 59), rng.randint(0, 59))
            n_new = min(1 + i // 6, len(drift_pool))  # footprint widens slowly
            resource = drift_pool[n_new - 1] if n_new - 1 < len(drift_pool) else rng.choice(target["typical_resources"])
            rows.append(make_row(
                entity_id=target["entity_id"], entity_type="user", timestamp=ts,
                source_ip=rng.choice(target["usual_ips"]), geo_city=target["home_city"],
                geo_country=target["home_country"], geo_lat=target["home_lat"], geo_lon=target["home_lon"],
                resource=resource, auth_method=rng.choice(list(target["auth_method_weights"].keys())),
                auth_result="success", duration_sec=rng.uniform(60, 400),
                command_sequence=sample_command_sequence(rng, sensitive_bias=0.15),
                device_os=target["device_os"], device_mac=target["device_mac"], protocol=target["protocol"],
                label="insider_drift_edge_case", attack_group_id=gid, is_edge_case=True,
            ))
    return rows

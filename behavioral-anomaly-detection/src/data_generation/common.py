"""
common.py — shared helpers used by both the normal-traffic generator and
the attack injectors, so every row (benign or malicious) has the same shape.
"""

import math
import random
import itertools

from .entity_profiles import _weighted_choice, _random_ip, BENIGN_ACTIONS, SENSITIVE_ACTIONS

_session_counter = itertools.count(1)


def next_session_id():
    return f"sess_{next(_session_counter):08d}"


def haversine_km(lat1, lon1, lat2, lon2):
    R = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * R * math.asin(math.sqrt(a))


def device_fingerprint(os_name, mac, protocol):
    return f"{os_name}|{mac}|{protocol}"


def sample_command_sequence(rng, sensitive_bias=0.0, length=None):
    """A short ordered list of actions taken during the session."""
    if length is None:
        length = rng.randint(2, 4)
    seq = ["login"]
    pool_choices = BENIGN_ACTIONS[:]
    for _ in range(length):
        if rng.random() < sensitive_bias:
            seq.append(rng.choice(SENSITIVE_ACTIONS))
        else:
            seq.append(rng.choice(pool_choices))
    seq.append("logout")
    return ";".join(seq)


def make_row(entity_id, entity_type, timestamp, source_ip, geo_city, geo_country,
             geo_lat, geo_lon, resource, auth_method, auth_result, duration_sec,
             command_sequence, device_os, device_mac, protocol, label,
             attack_group_id="", is_edge_case=False):
    return {
        "session_id": next_session_id(),
        "entity_id": entity_id,
        "entity_type": entity_type,
        "timestamp": timestamp.isoformat(),
        "source_ip": source_ip,
        "geo_city": geo_city,
        "geo_country": geo_country,
        "geo_lat": round(geo_lat, 4),
        "geo_lon": round(geo_lon, 4),
        "resource_accessed": resource,
        "auth_method": auth_method,
        "auth_result": auth_result,
        "session_duration_sec": max(1, round(duration_sec)),
        "command_sequence": command_sequence,
        "device_fingerprint": device_fingerprint(device_os, device_mac, protocol),
        "label": label,
        "attack_group_id": attack_group_id,
        "is_edge_case": is_edge_case,
    }

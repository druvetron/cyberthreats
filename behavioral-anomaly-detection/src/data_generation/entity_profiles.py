"""
entity_profiles.py

Builds per-entity behavioural baselines ("what normal looks like") for
users, service accounts, and edge devices. These profiles drive the
normal-traffic generator and give the attack injectors something concrete
to deviate from (e.g. "resource this entity has never touched",
"geo-location far from its usual city").
"""

import random
import numpy as np

# ---------------------------------------------------------------------------
# Reference pools
# ---------------------------------------------------------------------------

CITIES = [
    # (city, country, lat, lon)
    ("New York", "USA", 40.7128, -74.0060),
    ("Los Angeles", "USA", 34.0522, -118.2437),
    ("Chicago", "USA", 41.8781, -87.6298),
    ("London", "UK", 51.5074, -0.1278),
    ("Paris", "France", 48.8566, 2.3522),
    ("Berlin", "Germany", 52.5200, 13.4050),
    ("Mumbai", "India", 19.0760, 72.8777),
    ("Delhi", "India", 28.7041, 77.1025),
    ("Bangalore", "India", 12.9716, 77.5946),
    ("Singapore", "Singapore", 1.3521, 103.8198),
    ("Tokyo", "Japan", 35.6762, 139.6503),
    ("Sydney", "Australia", -33.8688, 151.2093),
    ("Sao Paulo", "Brazil", -23.5505, -46.6333),
    ("Moscow", "Russia", 55.7558, 37.6173),
    ("Dubai", "UAE", 25.2048, 55.2708),
    ("Toronto", "Canada", 43.6532, -79.3832),
    ("Lagos", "Nigeria", 6.5244, 3.3792),
    ("Cape Town", "South Africa", -33.9249, 18.4241),
    ("Beijing", "China", 39.9042, 116.4074),
    ("Seoul", "South Korea", 37.5665, 126.9780),
]

RESOURCE_POOL = {
    "user": [
        "/api/v1/users", "/api/v1/orders", "files/reports/Q1.xlsx",
        "files/hr/payroll.csv", "endpoint:/admin/config", "email:exchange-server",
        "file:/home/shared/contracts", "dashboard:grafana", "dashboard:kibana",
        "endpoint:/api/v2/payments", "endpoint:/api/v2/refunds",
        "repo:frontend-app", "repo:backend-service", "bucket:s3-backups",
        "printer:office_3", "vpn:gateway_1",
    ],
    "service_account": [
        "db:customer_db", "db:finance_db", "db:analytics_dw",
        "service:billing_api", "service:inventory_api", "queue:rabbitmq-tasks",
        "topic:kafka-orders", "container:k8s-node-3", "container:k8s-node-7",
        "secrets:vault/db-creds", "cert:vault/root-ca", "bucket:s3-logs",
        "endpoint:/api/v2/payments", "network:core-switch-1",
    ],
    "edge_device": [
        "scada:plc_12/read", "scada:plc_12/write", "iot:thermostat_5",
        "iot:camera_9", "device:actuator_1/set_state", "device:sensor_3/read",
        "port:22/ssh", "port:443/https", "network:core-switch-1",
        "iot:hvac_controller_2", "iot:badge_reader_4",
    ],
}

AUTH_METHOD_WEIGHTS = {
    "user": {"password": 0.55, "biometric": 0.25, "token": 0.15, "certificate": 0.05},
    "service_account": {"token": 0.55, "certificate": 0.40, "password": 0.05, "biometric": 0.0},
    "edge_device": {"certificate": 0.65, "token": 0.30, "password": 0.05, "biometric": 0.0},
}

DEVICE_OS_POOL = ["Windows 11", "Windows 10", "macOS 15", "Ubuntu 24.04",
                   "iOS 18", "Android 15", "RHEL 9", "FirmwareOS 3.2",
                   "FirmwareOS 4.0", "EmbeddedLinux 5.1"]

PROTOCOLS = ["HTTPS", "SSH", "MQTT", "Modbus/TCP", "RDP", "SFTP"]

BENIGN_ACTIONS = ["login", "logout", "read_file", "list_dir", "view_dashboard",
                   "download", "query_db", "read_sensor", "update_config"]
SENSITIVE_ACTIONS = ["write_file", "upload", "execute_script", "delete_user",
                      "change_permission", "create_user", "restart_service",
                      "write_actuator", "escalate_privilege", "access_admin_panel",
                      "export_data"]


def _weighted_choice(weights: dict):
    items, probs = zip(*weights.items())
    probs = np.array(probs)
    probs = probs / probs.sum()
    return np.random.choice(items, p=probs)


def _random_ip(rng):
    return f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def _random_mac(rng):
    return ":".join(f"{rng.randint(0, 255):02X}" for _ in range(6))


def build_entities(n_users=150, n_service_accounts=30, n_edge_devices=40, seed=42):
    """
    Returns a list of entity profile dicts. Each profile fully describes
    that entity's "normal" behaviour and is later used both to sample
    benign sessions and as the ground truth an attack injector deviates from.
    """
    rng = random.Random(seed)
    np.random.seed(seed)
    profiles = []

    def make_profile(idx, entity_type, prefix):
        entity_id = f"{prefix}_{idx:04d}"
        home_city = rng.choice(CITIES)
        n_res = {"user": rng.randint(3, 7), "service_account": rng.randint(2, 5),
                 "edge_device": rng.randint(1, 3)}[entity_type]
        typical_resources = rng.sample(RESOURCE_POOL[entity_type],
                                        k=min(n_res, len(RESOURCE_POOL[entity_type])))
        # working-hour window (some entities are night-shift / always-on devices)
        if entity_type == "edge_device":
            active_hours = (0, 23)  # always on
        elif rng.random() < 0.12:
            active_hours = (20, 5)  # night shift, wraps midnight
        else:
            start = rng.randint(6, 9)
            active_hours = (start, start + rng.randint(7, 9))

        profile = {
            "entity_id": entity_id,
            "entity_type": entity_type,
            "home_city": home_city[0],
            "home_country": home_city[1],
            "home_lat": home_city[2],
            "home_lon": home_city[3],
            "usual_ips": [_random_ip(rng) for _ in range(rng.randint(1, 3))],
            "typical_resources": typical_resources,
            "auth_method_weights": AUTH_METHOD_WEIGHTS[entity_type],
            "active_hours": active_hours,
            "avg_session_minutes": max(1, rng.gauss(
                {"user": 22, "service_account": 4, "edge_device": 1.5}[entity_type],
                {"user": 10, "service_account": 2, "edge_device": 0.8}[entity_type],
            )),
            "device_os": rng.choice(DEVICE_OS_POOL),
            "device_mac": _random_mac(rng),
            "protocol": rng.choice(PROTOCOLS),
            "sessions_per_day_lambda": {"user": 4, "service_account": 8, "edge_device": 8}[entity_type],
        }
        return profile

    idx = 0
    for _ in range(n_users):
        idx += 1
        profiles.append(make_profile(idx, "user", "u"))
    idx = 0
    for _ in range(n_service_accounts):
        idx += 1
        profiles.append(make_profile(idx, "service_account", "svc"))
    idx = 0
    for _ in range(n_edge_devices):
        idx += 1
        profiles.append(make_profile(idx, "edge_device", "dev"))

    return profiles

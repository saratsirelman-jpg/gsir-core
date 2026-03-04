def migrate_v1_to_v2(payload_v1: dict) -> dict:
    # Deterministic, explicit upgrade
    out = dict(payload_v1)
    out["migration_level"] = 2
    return out
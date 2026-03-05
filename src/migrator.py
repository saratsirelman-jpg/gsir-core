import os
import sys
import json
import hashlib
from datetime import datetime, timezone

import yaml
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

# Ensure repo root is importable (so we can import migrations/*)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from src.canonical import canonical_json_bytes, canonical_sha256_hex  # noqa: E402

# ---- Files/paths
REGISTRY_DIR = os.path.join(BASE_DIR, "registry")
LOCK_FILE = os.path.join(BASE_DIR, "requirements.lock")
TRUSTED_KEYS_FILE = os.path.join(BASE_DIR, "trusted_keys.json")
VERSION_FILE = os.path.join(BASE_DIR, "transform_versions.json")
MIGRATION_PLAN_FILE = os.path.join(BASE_DIR, "migrations", "migration_plan.yaml")

PRIVATE_KEY_PATH = os.path.join(BASE_DIR, "keys", "private_key.pem")

# Choose which trusted key entry to use for NEW migrated artifacts
SIGNING_KEY_ID = "local-dev-1"


def sha256_file_hex(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def get_environment_fingerprint() -> dict:
    import platform
    import sys as pysys
    return {
        "python_version": pysys.version.split(" ")[0],
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "os_name": os.name,
    }


def load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_yaml(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_private_key():
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def sign_bytes(data: bytes) -> str:
    priv = load_private_key()
    sig = priv.sign(data, padding.PKCS1v15(), hashes.SHA256())
    return sig.hex()


def load_trusted_keys() -> dict:
    return load_json(TRUSTED_KEYS_FILE)


def trusted_entry_for(key_id: str) -> dict:
    doc = load_trusted_keys()
    for entry in doc.get("trusted_keys", []):
        if entry.get("key_id") == key_id:
            return entry
    raise RuntimeError(f"Untrusted key_id: {key_id}")


def load_public_key(pub_path: str):
    with open(os.path.join(BASE_DIR, pub_path), "rb") as f:
        return serialization.load_pem_public_key(f.read())


def verify_signature(pub_key, data: bytes, signature_hex: str):
    sig = bytes.fromhex(signature_hex)
    pub_key.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())


def verify_existing_artifact_is_trusted_and_signed(artifact: dict) -> dict:
    """
    Verifies trusted key policy + signature using canonical bytes of artifact_core.
    Returns artifact_core (the signed portion).
    """
    signature = artifact.get("signature")
    key_id = artifact.get("key_id")
    if not signature or not key_id:
        raise RuntimeError("Artifact is not signed (missing signature/key_id)")

    entry = trusted_entry_for(key_id)

    pub_path = entry.get("public_key_path")
    expected_fp = entry.get("public_key_fingerprint_sha256")
    if not pub_path or not expected_fp:
        raise RuntimeError("trusted_keys.json entry incomplete")

    pub_abs = os.path.join(BASE_DIR, pub_path)
    actual_fp = sha256_file_hex(pub_abs)
    if actual_fp != expected_fp:
        raise RuntimeError("Trusted public key fingerprint mismatch")

    pub_key = load_public_key(pub_path)

    # Rebuild artifact_core exactly (what was signed)
    artifact_core = {
        "canonicalization": artifact.get("canonicalization"),
        "spec_hash": artifact.get("spec_hash"),
        "input_hash": artifact.get("input_hash"),
        "transform_version": artifact.get("transform_version"),
        "payload": artifact.get("payload"),
        "environment_hash": artifact.get("environment_hash"),
        "deps_lock_hash": artifact.get("deps_lock_hash"),
        "code_tree_hash": artifact.get("code_tree_hash"),
        "produced_by_commit": artifact.get("produced_by_commit"),
    }

    core_bytes = canonical_json_bytes(artifact_core)

    try:
        verify_signature(pub_key, core_bytes, signature)
    except InvalidSignature:
        raise RuntimeError("Signature invalid for input artifact")

    computed_id = hashlib.sha256(core_bytes).hexdigest()
    if artifact.get("artifact_id") != computed_id:
        raise RuntimeError("artifact_id mismatch for input artifact")

    return artifact_core


def load_artifact_by_id(artifact_id: str) -> dict:
    fname = artifact_id if artifact_id.endswith(".json") else f"{artifact_id}.json"
    path = os.path.join(REGISTRY_DIR, fname)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Artifact not found in registry: {fname}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_latest_transform_version() -> str:
    tv = load_json(VERSION_FILE)
    latest = tv.get("latest_version")
    approved = set(tv.get("approved_versions", []))
    if not latest or latest not in approved:
        raise RuntimeError("transform_versions.json inconsistent (latest not approved)")
    return latest


def load_migration_plan() -> dict:
    mp = load_yaml(MIGRATION_PLAN_FILE)
    if not mp:
        raise RuntimeError("migration_plan.yaml missing/empty")
    return mp


def apply_migration(from_v: str, to_v: str, payload: dict) -> dict:
    # Minimal explicit wiring (extend as you add more migrations)
    if from_v == "v1" and to_v == "v2":
        from migrations.migrate_v1_to_v2 import migrate_v1_to_v2
        return migrate_v1_to_v2(payload)

    raise RuntimeError(f"No migration function registered for {from_v} -> {to_v}")


def next_hop(plan: dict, current_version: str, target_version: str):
    """
    Finds a single hop migration current->next toward target (minimal v1->v2 now).
    """
    for m in plan.get("allowed_migrations", []):
        if m.get("from") == current_version and m.get("to") == target_version:
            return (current_version, target_version)
    return None


def main():
    if len(sys.argv) != 2:
        print("Usage: python src\\migrator.py <artifact_id_or_filename>")
        sys.exit(1)

    if not os.path.exists(LOCK_FILE):
        raise RuntimeError("requirements.lock missing (deps must be locked)")

    deps_lock_hash = sha256_file_hex(LOCK_FILE)
    env_hash = canonical_sha256_hex(get_environment_fingerprint())

    artifact_id_in = sys.argv[1]
    artifact_full = load_artifact_by_id(artifact_id_in)

    # Verify input artifact integrity and trust
    input_core = verify_existing_artifact_is_trusted_and_signed(artifact_full)

    from_version = input_core.get("transform_version")
    if not from_version:
        raise RuntimeError("Input artifact missing transform_version")

    latest = load_latest_transform_version()
    if from_version == latest:
        raise RuntimeError(f"No migration needed: artifact already at latest ({latest})")

    plan = load_migration_plan()

    hop = next_hop(plan, from_version, latest)
    if not hop:
        raise RuntimeError(f"No allowed migration path: {from_version} -> {latest}")

    (v_from, v_to) = hop

    migrated_payload = apply_migration(v_from, v_to, input_core["payload"])

    migration_chain = [{
        "from": v_from,
        "to": v_to,
        "function": f"migrate_{v_from}_to_{v_to}",
    }]

    # Build NEW artifact_core (what we sign)
    new_core = {
        "canonicalization": "gsir-cjson-v1",
        "spec_hash": input_core["spec_hash"],
        "input_hash": input_core["input_hash"],
        "transform_version": v_to,
        "payload": migrated_payload,

        # provenance/fingerprints (migration is a new execution)
        "environment_hash": env_hash,
        "deps_lock_hash": deps_lock_hash,
        "code_tree_hash": input_core.get("code_tree_hash"),

        # trace
        "produced_by_commit": "migration",
        "migrated_from_artifact_id": artifact_full["artifact_id"],
        "migration_chain": migration_chain,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }

    core_bytes = canonical_json_bytes(new_core)
    new_artifact_id = hashlib.sha256(core_bytes).hexdigest()

    # Sign NEW core
    signature_hex = sign_bytes(core_bytes)

    # Attach key policy metadata
    trusted = trusted_entry_for(SIGNING_KEY_ID)
    signature_alg = trusted.get("signature_alg", "RSASSA-PKCS1v15-SHA256")
    pub_path = trusted.get("public_key_path")
    pub_fp = trusted.get("public_key_fingerprint_sha256")

    new_full = dict(new_core)
    new_full.update({
        "artifact_id": new_artifact_id,
        "key_id": SIGNING_KEY_ID,
        "signature_alg": signature_alg,
        "public_key_fingerprint_sha256": pub_fp,
        "signature": signature_hex,
    })

    # Append-only write
    out_path = os.path.join(REGISTRY_DIR, f"{new_artifact_id}.json")
    if os.path.exists(out_path):
        raise RuntimeError("Registry violation: migrated artifact already exists")

    with open(out_path, "wb") as f:
        f.write(canonical_json_bytes(new_full))

    print("MIGRATION SUCCESS")
    print(f"from_artifact: {artifact_full['artifact_id']}")
    print(f"to_artifact:   {new_artifact_id}")
    print(f"from_version:  {from_version}")
    print(f"to_version:    {latest}")


if __name__ == "__main__":
    main()
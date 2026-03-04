import os
import sys
import json
import hashlib
import subprocess
from datetime import datetime, timezone

import yaml
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from canonical import canonical_json_bytes, canonical_sha256_hex


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPECS_DIR = os.path.join(BASE_DIR, "specs")
REGISTRY_DIR = os.path.join(BASE_DIR, "registry")
METADATA_DIR = os.path.join(BASE_DIR, "build_metadata")

VERSION_FILE = os.path.join(BASE_DIR, "transform_versions.json")
LOCK_FILE = os.path.join(BASE_DIR, "requirements.lock")

TRUSTED_KEYS_FILE = os.path.join(BASE_DIR, "trusted_keys.json")
PRIVATE_KEY_PATH = os.path.join(BASE_DIR, "keys", "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(BASE_DIR, "keys", "public_key.pem")

# Choose which trusted key entry to use (must exist in trusted_keys.json)
SIGNING_KEY_ID = "local-dev-1"


def sha256_file_hex(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def get_git_commit() -> str:
    try:
        out = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=BASE_DIR)
        return out.decode("utf-8").strip()
    except Exception:
        return "unknown"


def get_code_tree_hash() -> str:
    # Stronger than commit for content fingerprinting
    try:
        out = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=BASE_DIR)
        return out.decode("utf-8").strip()
    except Exception:
        return "unknown"


def get_environment_fingerprint() -> dict:
    import platform
    import sys as pysys
    return {
        "python_version": pysys.version.split(" ")[0],
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "os_name": os.name,
    }


def load_version_registry() -> dict:
    with open(VERSION_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def load_spec(spec_filename: str) -> dict:
    path = os.path.join(SPECS_DIR, spec_filename)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Spec not found: {spec_filename}")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_private_key():
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def public_key_fingerprint_sha256() -> str:
    return sha256_file_hex(PUBLIC_KEY_PATH)


def load_trusted_keys() -> dict:
    with open(TRUSTED_KEYS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def get_trusted_key_entry(key_id: str) -> dict:
    doc = load_trusted_keys()
    for entry in doc.get("trusted_keys", []):
        if entry.get("key_id") == key_id:
            return entry
    raise RuntimeError(f"Key policy violation: key_id not trusted: {key_id}")


def sign_bytes(data: bytes) -> str:
    priv = load_private_key()
    sig = priv.sign(data, padding.PKCS1v15(), hashes.SHA256())
    return sig.hex()


# -------- VERSIONED TRANSFORMS (migration protocol baseline) --------

def transform_v1(spec: dict) -> dict:
    return {
        "task_type": spec.get("task_type"),
        "schema_version": spec.get("schema_version"),
        "inputs": spec.get("inputs"),
        "normalized": True,
    }


def transform_v2(spec: dict) -> dict:
    return {
        "task_type": spec.get("task_type"),
        "schema_version": spec.get("schema_version"),
        "inputs": spec.get("inputs"),
        "normalized": True,
        "migration_level": 2,
    }


def deterministic_transform(spec: dict, version: str) -> dict:
    if version == "v1":
        return transform_v1(spec)
    if version == "v2":
        return transform_v2(spec)
    raise RuntimeError(f"Unsupported transform version: {version}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python src\\task_runner.py <spec_filename>")
        sys.exit(1)

    # --- governance: approved transform versions ---
    vr = load_version_registry()
    version = vr["latest_version"]
    if version not in vr.get("approved_versions", []):
        raise RuntimeError("Transform version not approved in transform_versions.json")

    # --- deps lock ---
    if not os.path.exists(LOCK_FILE):
        raise RuntimeError("requirements.lock missing (deps must be locked)")
    deps_lock_hash = sha256_file_hex(LOCK_FILE)

    # --- environment fingerprint ---
    env_fp = get_environment_fingerprint()
    environment_hash = canonical_sha256_hex(env_fp)

    # --- code fingerprint ---
    code_tree_hash = get_code_tree_hash()

    # --- key policy ---
    trusted = get_trusted_key_entry(SIGNING_KEY_ID)
    expected_fp = trusted.get("public_key_fingerprint_sha256", "")
    actual_fp = public_key_fingerprint_sha256()
    if not expected_fp or expected_fp != actual_fp:
        raise RuntimeError("Key policy violation: public key fingerprint mismatch")

    signature_alg = trusted.get("signature_alg", "RSASSA-PKCS1v15-SHA256")

    # --- load spec ---
    spec_filename = sys.argv[1]
    spec = load_spec(spec_filename)

    spec_hash = canonical_sha256_hex({"spec_filename": spec_filename})
    input_hash = canonical_sha256_hex(spec)

    payload = deterministic_transform(spec, version)

    # --- artifact core (WHAT WE HASH + SIGN) ---
    artifact_core = {
        "canonicalization": "gsir-cjson-v1",
        "spec_hash": spec_hash,
        "input_hash": input_hash,
        "transform_version": version,
        "payload": payload,

        # provenance/fingerprints
        "environment_hash": environment_hash,
        "deps_lock_hash": deps_lock_hash,
        "code_tree_hash": code_tree_hash,

        # trace (not part of determinism, but still recorded)
        "produced_by_commit": get_git_commit(),
    }

    core_bytes = canonical_json_bytes(artifact_core)
    artifact_id = hashlib.sha256(core_bytes).hexdigest()

    signature_hex = sign_bytes(core_bytes)

    artifact_full = dict(artifact_core)
    artifact_full.update({
        "artifact_id": artifact_id,
        "key_id": SIGNING_KEY_ID,
        "signature_alg": signature_alg,
        "public_key_fingerprint_sha256": actual_fp,
        "signature": signature_hex,
    })

    # Append-only immutability by artifact_id
    out_path = os.path.join(REGISTRY_DIR, f"{artifact_id}.json")
    if os.path.exists(out_path):
        raise RuntimeError("Registry violation: artifact already exists (append-only enforced)")

    # Write canonical full JSON (still canonical bytes contract)
    full_bytes = canonical_json_bytes(artifact_full)
    with open(out_path, "wb") as f:
        f.write(full_bytes)

    # Metadata (execution receipt)
    metadata = {
        "artifact_id": artifact_id,
        "spec_filename": spec_filename,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "environment_hash": environment_hash,
        "deps_lock_hash": deps_lock_hash,
        "code_tree_hash": code_tree_hash,
        "produced_by_commit": get_git_commit(),
    }
    meta_path = os.path.join(METADATA_DIR, f"{artifact_id}_metadata.json")
    with open(meta_path, "wb") as f:
        f.write(canonical_json_bytes(metadata))

    print("SUCCESS")
    print(f"artifact_id: {artifact_id}")
    print(f"transform_version: {version}")
    print(f"environment_hash: {environment_hash}")
    print(f"deps_lock_hash: {deps_lock_hash}")


if __name__ == "__main__":
    main()
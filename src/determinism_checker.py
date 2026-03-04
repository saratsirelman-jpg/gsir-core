import os
import sys
import json
import hashlib

import yaml
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

from canonical import canonical_json_bytes, canonical_sha256_hex


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPECS_DIR = os.path.join(BASE_DIR, "specs")
REGISTRY_DIR = os.path.join(BASE_DIR, "registry")

LOCK_FILE = os.path.join(BASE_DIR, "requirements.lock")
TRUSTED_KEYS_FILE = os.path.join(BASE_DIR, "trusted_keys.json")


def sha256_file_hex(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def load_spec(spec_filename: str) -> dict:
    path = os.path.join(SPECS_DIR, spec_filename)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Spec not found: {spec_filename}")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_trusted_keys() -> dict:
    with open(TRUSTED_KEYS_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


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


# --- versioned transforms must match task_runner versions ---

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
        print("Usage: python src\\determinism_checker.py <spec_filename>")
        sys.exit(1)

    spec_filename = sys.argv[1]
    spec = load_spec(spec_filename)

    if not os.path.exists(LOCK_FILE):
        raise RuntimeError("requirements.lock missing (deps must be locked)")
    deps_lock_hash = sha256_file_hex(LOCK_FILE)

    spec_hash = canonical_sha256_hex({"spec_filename": spec_filename})
    input_hash = canonical_sha256_hex(spec)

    # Look for a matching signed artifact
    for fname in os.listdir(REGISTRY_DIR):
        if not fname.endswith(".json"):
            continue

        path = os.path.join(REGISTRY_DIR, fname)
        with open(path, "rb") as f:
            stored_bytes = f.read()

        # Stored file is canonical JSON bytes by contract
        stored = json.loads(stored_bytes.decode("utf-8"))

        # must be signed
        signature = stored.get("signature")
        key_id = stored.get("key_id")
        if not signature or not key_id:
            continue

        entry = trusted_entry_for(key_id)

        # Fingerprint check
        expected_fp = entry.get("public_key_fingerprint_sha256", "")
        pub_path = entry.get("public_key_path")
        if not expected_fp or not pub_path:
            raise RuntimeError("trusted_keys.json entry incomplete")

        # load public key and validate fingerprint
        pub_abs = os.path.join(BASE_DIR, pub_path)
        actual_fp = sha256_file_hex(pub_abs)
        if actual_fp != expected_fp:
            raise RuntimeError("Trusted public key fingerprint mismatch")

        pub_key = load_public_key(pub_path)

        # Reconstruct artifact_core (what was signed)
        version = stored.get("transform_version")
        payload = deterministic_transform(spec, version)

        artifact_core = {
            "canonicalization": stored.get("canonicalization"),
            "spec_hash": stored.get("spec_hash"),
            "input_hash": stored.get("input_hash"),
            "transform_version": stored.get("transform_version"),
            "payload": stored.get("payload"),
            "environment_hash": stored.get("environment_hash"),
            "deps_lock_hash": stored.get("deps_lock_hash"),
            "code_tree_hash": stored.get("code_tree_hash"),
            "produced_by_commit": stored.get("produced_by_commit"),
        }

        # Verify core hash/signature
        core_bytes = canonical_json_bytes(artifact_core)
        try:
            verify_signature(pub_key, core_bytes, signature)
        except InvalidSignature:
            raise RuntimeError(f"Signature invalid for artifact {fname}")

        # Verify artifact_id matches core bytes
        computed_id = hashlib.sha256(core_bytes).hexdigest()
        if stored.get("artifact_id") != computed_id:
            raise RuntimeError(f"artifact_id mismatch for {fname}")

        # Origin checks (canonical hashes + deps lock)
        if stored.get("spec_hash") != spec_hash:
            continue
        if stored.get("input_hash") != input_hash:
            continue
        if stored.get("payload") != payload:
            continue
        if stored.get("deps_lock_hash") != deps_lock_hash:
            raise RuntimeError("deps_lock_hash mismatch (environment drift)")

        print("Origin Determinism Verified")
        print("Signature Verified")
        print(f"Artifact File: {fname}")
        print(f"artifact_id: {computed_id}")
        return

    raise RuntimeError("Origin verification failed: no matching trusted signed artifact found")


if __name__ == "__main__":
    main()
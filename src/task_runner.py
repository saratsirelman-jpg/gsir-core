import os
import sys
import json
import yaml
import hashlib
from datetime import datetime, timezone
import subprocess
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPECS_DIR = os.path.join(BASE_DIR, "specs")
REGISTRY_DIR = os.path.join(BASE_DIR, "registry")
VERSION_FILE = os.path.join(BASE_DIR, "transform_versions.json")
PRIVATE_KEY_PATH = os.path.join(BASE_DIR, "keys", "private_key.pem")


def sha256_of_string(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def load_private_key():
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )


def sign_data(data: bytes) -> str:
    private_key = load_private_key()
    signature = private_key.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return signature.hex()


def load_version_registry():
    with open(VERSION_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def get_git_commit():
    try:
        result = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=BASE_DIR
        )
        return result.decode("utf-8").strip()
    except Exception:
        return "unknown"


def load_spec(spec_filename: str):
    spec_path = os.path.join(SPECS_DIR, spec_filename)
    with open(spec_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def transform_v1(spec: dict) -> dict:
    return {
        "task_type": spec.get("task_type"),
        "schema_version": spec.get("schema_version"),
        "inputs": spec.get("inputs"),
        "normalized": True
    }


def transform_v2(spec: dict) -> dict:
    return {
        "task_type": spec.get("task_type"),
        "schema_version": spec.get("schema_version"),
        "inputs": spec.get("inputs"),
        "normalized": True,
        "migration_level": 2
    }


def deterministic_transform(spec: dict, version: str) -> dict:
    if version == "v1":
        return transform_v1(spec)
    if version == "v2":
        return transform_v2(spec)
    raise RuntimeError("Unsupported transform version")


def main():
    if len(sys.argv) != 2:
        print("Usage: python task_runner.py <spec_filename>")
        sys.exit(1)

    registry = load_version_registry()
    version = registry["latest_version"]

    if version not in registry["approved_versions"]:
        raise RuntimeError("Transform version not approved")

    spec_filename = sys.argv[1]
    spec = load_spec(spec_filename)

    spec_serialized = json.dumps(spec, sort_keys=True, separators=(",", ":"))
    input_hash = sha256_of_string(spec_serialized)
    spec_hash = sha256_of_string(spec_filename)

    output_data = deterministic_transform(spec, version)

    artifact = {
        "spec_hash": spec_hash,
        "input_hash": input_hash,
        "produced_by_commit": get_git_commit(),
        "transform_version": version,
        "payload": output_data
    }

    serialized = json.dumps(artifact, sort_keys=True, separators=(",", ":")).encode()

    signature = sign_data(serialized)
    artifact["signature"] = signature

    final_serialized = json.dumps(artifact, sort_keys=True, separators=(",", ":"))
    output_hash = sha256_of_string(final_serialized)

    output_path = os.path.join(REGISTRY_DIR, f"{output_hash}.json")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(final_serialized)

    print("SUCCESS")
    print("Signed artifact created")
    print(f"Output Hash: {output_hash}")


if __name__ == "__main__":
    main()
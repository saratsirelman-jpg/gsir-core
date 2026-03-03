import os
import sys
import json
import yaml
import hashlib
from datetime import datetime, timezone
import subprocess


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPECS_DIR = os.path.join(BASE_DIR, "specs")
REGISTRY_DIR = os.path.join(BASE_DIR, "registry")
METADATA_DIR = os.path.join(BASE_DIR, "build_metadata")
VERSION_FILE = os.path.join(BASE_DIR, "transform_versions.json")


def sha256_of_string(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def load_version_registry():
    if not os.path.exists(VERSION_FILE):
        raise RuntimeError("Version registry file missing")

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

    if not os.path.exists(spec_path):
        raise FileNotFoundError(f"Spec not found: {spec_filename}")

    with open(spec_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# -------- VERSIONED TRANSFORMS --------

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

    raise RuntimeError(f"Unsupported transform version: {version}")


# -------- REGISTRY WRITE --------

def write_registry_artifact(
    output_payload: dict,
    spec_hash: str,
    input_hash: str,
    version: str
):
    git_commit = get_git_commit()

    artifact = {
        "spec_hash": spec_hash,
        "input_hash": input_hash,
        "produced_by_commit": git_commit,
        "transform_version": version,
        "payload": output_payload
    }

    serialized = json.dumps(artifact, sort_keys=True, separators=(",", ":"))
    output_hash = sha256_of_string(serialized)

    filename = f"{output_hash}.json"
    output_path = os.path.join(REGISTRY_DIR, filename)

    if os.path.exists(output_path):
        raise RuntimeError("Registry violation: artifact already exists")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(serialized)

    return output_hash


def write_metadata(spec_name: str, input_hash: str, output_hash: str):
    metadata = {
        "spec": spec_name,
        "input_hash": input_hash,
        "output_hash": output_hash,
        "git_commit": get_git_commit(),
        "timestamp_utc": datetime.now(timezone.utc).isoformat()
    }

    serialized = json.dumps(metadata, sort_keys=True, separators=(",", ":"))
    filename = f"{output_hash}_metadata.json"
    path = os.path.join(METADATA_DIR, filename)

    with open(path, "w", encoding="utf-8") as f:
        f.write(serialized)


def main():
    if len(sys.argv) != 2:
        print("Usage: python task_runner.py <spec_filename>")
        sys.exit(1)

    registry = load_version_registry()
    version = registry["latest_version"]

    if version not in registry["approved_versions"]:
        raise RuntimeError("Transform version not approved in registry")

    spec_filename = sys.argv[1]
    spec = load_spec(spec_filename)

    spec_serialized = json.dumps(spec, sort_keys=True, separators=(",", ":"))
    input_hash = sha256_of_string(spec_serialized)
    spec_hash = sha256_of_string(spec_filename)

    output_data = deterministic_transform(spec, version)

    output_hash = write_registry_artifact(
        output_payload=output_data,
        spec_hash=spec_hash,
        input_hash=input_hash,
        version=version
    )

    write_metadata(spec_filename, input_hash, output_hash)

    print("SUCCESS")
    print(f"Transform Version: {version}")
    print(f"Output Hash: {output_hash}")


if __name__ == "__main__":
    main()
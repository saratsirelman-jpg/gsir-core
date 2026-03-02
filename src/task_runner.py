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


def sha256_of_string(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def get_git_commit():
    try:
        result = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=BASE_DIR
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


def deterministic_transform(spec: dict) -> dict:
    """
    Deterministic transformation of spec into registry artifact.
    No randomness. No external calls.
    """
    return {
        "task_type": spec.get("task_type"),
        "schema_version": spec.get("schema_version"),
        "inputs": spec.get("inputs"),
        "normalized": True
    }


def write_registry_artifact(output_data: dict):
    serialized = json.dumps(output_data, sort_keys=True, separators=(",", ":"))
    output_hash = sha256_of_string(serialized)

    filename = f"{output_hash}.json"
    output_path = os.path.join(REGISTRY_DIR, filename)

    # STRICT APPEND-ONLY ENFORCEMENT
    if os.path.exists(output_path):
        raise RuntimeError(
            "Registry violation: artifact already exists (append-only enforced)"
        )

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(serialized)

    return output_hash, filename


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

    spec_filename = sys.argv[1]

    spec = load_spec(spec_filename)

    spec_serialized = json.dumps(spec, sort_keys=True, separators=(",", ":"))
    input_hash = sha256_of_string(spec_serialized)

    output_data = deterministic_transform(spec)
    output_hash, _ = write_registry_artifact(output_data)

    write_metadata(spec_filename, input_hash, output_hash)

    print(f"SUCCESS")
    print(f"Input Hash:  {input_hash}")
    print(f"Output Hash: {output_hash}")


if __name__ == "__main__":
    main()
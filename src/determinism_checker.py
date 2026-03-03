import os
import sys
import json
import yaml
import hashlib
import subprocess

TRANSFORM_VERSION = "v1"

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPECS_DIR = os.path.join(BASE_DIR, "specs")
REGISTRY_DIR = os.path.join(BASE_DIR, "registry")


def sha256_of_string(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


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


def deterministic_transform(spec: dict) -> dict:
    return {
        "task_type": spec.get("task_type"),
        "schema_version": spec.get("schema_version"),
        "inputs": spec.get("inputs"),
        "normalized": True
    }


def main():
    if len(sys.argv) != 2:
        print("Usage: python determinism_checker.py <spec_filename>")
        sys.exit(1)

    spec_filename = sys.argv[1]
    spec = load_spec(spec_filename)

    # Recompute input hash
    spec_serialized = json.dumps(spec, sort_keys=True, separators=(",", ":"))
    input_hash = sha256_of_string(spec_serialized)

    # Recompute deterministic payload
    payload = deterministic_transform(spec)

    # Recompute spec hash
    spec_hash = sha256_of_string(spec_filename)

    # Reconstruct full artifact
    artifact = {
        "spec_hash": spec_hash,
        "input_hash": input_hash,
        "produced_by_commit": get_git_commit(),
        "transform_version": TRANSFORM_VERSION,
        "payload": payload
    }

    serialized = json.dumps(artifact, sort_keys=True, separators=(",", ":"))
    expected_output_hash = sha256_of_string(serialized)

    artifact_path = os.path.join(REGISTRY_DIR, f"{expected_output_hash}.json")

    if not os.path.exists(artifact_path):
        raise RuntimeError("Replay failure: artifact not found in registry")

    # Load actual artifact from registry
    with open(artifact_path, "r", encoding="utf-8") as f:
        stored_artifact = json.load(f)

    # Strict structural equality check
    if stored_artifact != artifact:
        raise RuntimeError("Origin violation: artifact structure mismatch")

    print("Origin Determinism Verified")
    print(f"Input Hash: {input_hash}")
    print(f"Output Hash: {expected_output_hash}")


if __name__ == "__main__":
    main()
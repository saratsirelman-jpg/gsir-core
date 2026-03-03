import os
import sys
import json
import yaml
import hashlib

TRANSFORM_VERSION = "v1"

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPECS_DIR = os.path.join(BASE_DIR, "specs")
REGISTRY_DIR = os.path.join(BASE_DIR, "registry")


def sha256_of_string(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


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

    spec_serialized = json.dumps(spec, sort_keys=True, separators=(",", ":"))
    input_hash = sha256_of_string(spec_serialized)

    payload = deterministic_transform(spec)
    spec_hash = sha256_of_string(spec_filename)

    # Compute expected artifact hash WITHOUT commit binding
    artifact_core = {
        "spec_hash": spec_hash,
        "input_hash": input_hash,
        "transform_version": TRANSFORM_VERSION,
        "payload": payload
    }

    core_serialized = json.dumps(artifact_core, sort_keys=True, separators=(",", ":"))
    core_hash = sha256_of_string(core_serialized)

    # Search registry for artifact matching core structure
    found = False

    for filename in os.listdir(REGISTRY_DIR):
        if not filename.endswith(".json"):
            continue

        path = os.path.join(REGISTRY_DIR, filename)

        with open(path, "r", encoding="utf-8") as f:
            stored_artifact = json.load(f)

        candidate_core = {
            "spec_hash": stored_artifact.get("spec_hash"),
            "input_hash": stored_artifact.get("input_hash"),
            "transform_version": stored_artifact.get("transform_version"),
            "payload": stored_artifact.get("payload")
        }

        candidate_serialized = json.dumps(
            candidate_core, sort_keys=True, separators=(",", ":")
        )

        if sha256_of_string(candidate_serialized) == core_hash:
            # Additional strict checks
            if stored_artifact.get("transform_version") != TRANSFORM_VERSION:
                raise RuntimeError("Transform version mismatch")

            if stored_artifact.get("input_hash") != input_hash:
                raise RuntimeError("Input hash mismatch")

            if stored_artifact.get("spec_hash") != spec_hash:
                raise RuntimeError("Spec hash mismatch")

            found = True
            print("Origin Determinism Verified")
            print(f"Input Hash: {input_hash}")
            print(f"Artifact File: {filename}")
            break

    if not found:
        raise RuntimeError("Origin verification failed: no matching artifact found")


if __name__ == "__main__":
    main()
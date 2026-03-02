import os
import sys
import json
import yaml
import hashlib

from task_runner import deterministic_transform, sha256_of_string

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPECS_DIR = os.path.join(BASE_DIR, "specs")
REGISTRY_DIR = os.path.join(BASE_DIR, "registry")


def load_spec(spec_filename: str):
    spec_path = os.path.join(SPECS_DIR, spec_filename)
    if not os.path.exists(spec_path):
        raise FileNotFoundError(f"Spec not found: {spec_filename}")

    with open(spec_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def registry_artifact_exists(output_hash: str) -> bool:
    expected_path = os.path.join(REGISTRY_DIR, f"{output_hash}.json")
    return os.path.exists(expected_path)


def replay_check(spec_filename: str) -> bool:
    spec = load_spec(spec_filename)

    spec_serialized = json.dumps(spec, sort_keys=True, separators=(",", ":"))
    input_hash = sha256_of_string(spec_serialized)

    output_data = deterministic_transform(spec)
    output_serialized = json.dumps(output_data, sort_keys=True, separators=(",", ":"))
    output_hash = sha256_of_string(output_serialized)

    if not registry_artifact_exists(output_hash):
        print("FAIL: Registry artifact missing.")
        return False

    print("Replay Determinism Verified")
    print(f"Input Hash:  {input_hash}")
    print(f"Output Hash: {output_hash}")

    return True


def main():
    if len(sys.argv) != 2:
        print("Usage: python determinism_checker.py <spec_filename>")
        sys.exit(1)

    spec_filename = sys.argv[1]

    try:
        success = replay_check(spec_filename)
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"ERROR: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
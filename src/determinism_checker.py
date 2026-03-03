import os
import sys
import json
import yaml
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SPECS_DIR = os.path.join(BASE_DIR, "specs")
REGISTRY_DIR = os.path.join(BASE_DIR, "registry")
PUBLIC_KEY_PATH = os.path.join(BASE_DIR, "keys", "public_key.pem")


def sha256_of_string(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def load_public_key():
    with open(PUBLIC_KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def verify_signature(data: bytes, signature_hex: str):
    public_key = load_public_key()
    signature = bytes.fromhex(signature_hex)

    public_key.verify(
        signature,
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )


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
        print("Usage: python determinism_checker.py <spec_filename>")
        sys.exit(1)

    spec_filename = sys.argv[1]
    spec = load_spec(spec_filename)

    spec_serialized = json.dumps(spec, sort_keys=True, separators=(",", ":"))
    input_hash = sha256_of_string(spec_serialized)
    spec_hash = sha256_of_string(spec_filename)

    match_found = False

    for filename in os.listdir(REGISTRY_DIR):
        if not filename.endswith(".json"):
            continue

        path = os.path.join(REGISTRY_DIR, filename)

        with open(path, "r", encoding="utf-8") as f:
            stored_artifact = json.load(f)

        signature = stored_artifact.pop("signature", None)

        if signature is None:
            continue

        # Verify signature first
        serialized_without_sig = json.dumps(
            stored_artifact,
            sort_keys=True,
            separators=(",", ":")
        ).encode()

        try:
            verify_signature(serialized_without_sig, signature)
        except InvalidSignature:
            raise RuntimeError("Signature verification failed — artifact tampered")

        version = stored_artifact.get("transform_version")
        payload = deterministic_transform(spec, version)

        reconstructed_core = {
            "spec_hash": spec_hash,
            "input_hash": input_hash,
            "produced_by_commit": stored_artifact.get("produced_by_commit"),
            "transform_version": version,
            "payload": payload
        }

        if reconstructed_core == stored_artifact:
            match_found = True
            print("Origin Determinism Verified")
            print("Signature Verified")
            print(f"Artifact File: {filename}")
            break

    if not match_found:
        raise RuntimeError("Origin verification failed")


if __name__ == "__main__":
    main()
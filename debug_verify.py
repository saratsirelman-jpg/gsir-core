# debug_verify.py
import os, sys, json, hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import yaml

BASE = os.path.abspath(".")
REGISTRY = os.path.join(BASE, "registry")
SPECS = os.path.join(BASE, "specs")
PUB = os.path.join(BASE, "keys", "public_key.pem")

def sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def load_pub():
    with open(PUB, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def verify(sig_hex, data_bytes):
    pub = load_pub()
    sig = bytes.fromhex(sig_hex)
    pub.verify(sig, data_bytes, padding.PKCS1v15(), hashes.SHA256())

def transform_v1(spec):
    return {
        "task_type": spec.get("task_type"),
        "schema_version": spec.get("schema_version"),
        "inputs": spec.get("inputs"),
        "normalized": True
    }

def transform_v2(spec):
    return {
        "task_type": spec.get("task_type"),
        "schema_version": spec.get("schema_version"),
        "inputs": spec.get("inputs"),
        "normalized": True,
        "migration_level": 2
    }

def deterministic_transform(spec, version):
    if version == "v1":
        return transform_v1(spec)
    if version == "v2":
        return transform_v2(spec)
    raise RuntimeError("unsupported version")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python debug_verify.py <artifact.json> <spec.yaml>")
        sys.exit(1)

    artfile = sys.argv[1]
    specfile = sys.argv[2]

    artpath = os.path.join(REGISTRY, artfile)
    specpath = os.path.join(SPECS, specfile)

    if not os.path.exists(artpath):
        print("ERROR: artifact not found:", artpath); sys.exit(2)
    if not os.path.exists(specpath):
        print("ERROR: spec not found:", specpath); sys.exit(2)

    with open(artpath, "r", encoding="utf-8") as f:
        artifact = json.load(f)

    signature = artifact.get("signature")
    print("Artifact file:", artfile)
    print("Has signature field?:", signature is not None)

    # copy without signature
    art_copy = dict(artifact)
    art_copy.pop("signature", None)

    serialized = json.dumps(art_copy, sort_keys=True, separators=(",", ":")).encode()
    print("Serialized length (no-sig):", len(serialized))

    # verify signature
    try:
        if signature is None:
            print("VERIFY: no signature present -> fails")
        else:
            verify(signature, serialized)
            print("VERIFY: signature is VALID")
    except InvalidSignature:
        print("VERIFY: signature INVALID (signature mismatch)")
    except Exception as e:
        print("VERIFY: signature verify raised:", type(e).__name__, str(e))

    # compute input & spec hashes
    with open(specpath, "r", encoding="utf-8") as f:
        spec = yaml.safe_load(f)

    spec_serialized = json.dumps(spec, sort_keys=True, separators=(",", ":"))
    input_hash = sha(spec_serialized)
    spec_hash = sha(specfile)

    print("Spec filename:", specfile)
    print("Computed input_hash:", input_hash)
    print("Artifact input_hash:", artifact.get("input_hash"))
    print("Computed spec_hash:", spec_hash)
    print("Artifact spec_hash:", artifact.get("spec_hash"))
    print("Artifact transform_version:", art_copy.get("transform_version"))

    # compute expected payload
    version = art_copy.get("transform_version")
    try:
        expected_payload = deterministic_transform(spec, version)
        print("Computed expected payload:", expected_payload)
    except Exception as e:
        print("ERROR computing payload for version:", version, str(e))
        sys.exit(3)

    print("Artifact payload from file:", art_copy.get("payload"))
    print("Payload equals expected?:", art_copy.get("payload") == expected_payload)
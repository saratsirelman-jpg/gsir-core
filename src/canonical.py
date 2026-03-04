import json
import unicodedata
from typing import Any

# GSIR Canonicalization v1
# - UTF-8
# - NFC normalization for ALL strings (including dict keys)
# - JSON with sorted keys, separators=(",", ":"), ensure_ascii=False
# - allow_nan=False (reject NaN/Infinity)
# - floats are rejected (require exact deterministic representations)


def _nfc(s: str) -> str:
    return unicodedata.normalize("NFC", s)


def _normalize(obj: Any) -> Any:
    if obj is None:
        return None

    if isinstance(obj, bool):
        return obj

    if isinstance(obj, int):
        return obj

    if isinstance(obj, float):
        # Avoid non-deterministic float serialization and platform differences.
        raise TypeError("Floats are forbidden in canonical GSIR payloads (use int or string).")

    if isinstance(obj, str):
        return _nfc(obj)

    if isinstance(obj, (list, tuple)):
        return [_normalize(x) for x in obj]

    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if not isinstance(k, str):
                k = str(k)
            out[_nfc(k)] = _normalize(v)
        return out

    # Fallback: force deterministic string form
    return _nfc(str(obj))


def canonical_json_bytes(obj: Any) -> bytes:
    normalized = _normalize(obj)
    s = json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return s.encode("utf-8")


def canonical_sha256_hex(obj: Any) -> str:
    import hashlib
    return hashlib.sha256(canonical_json_bytes(obj)).hexdigest()
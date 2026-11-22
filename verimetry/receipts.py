"""DSSE v1 Ed25519 signing (PAE domain separation), strict duplicate-key JSON parsing, and offline verification."""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from .core import (
    DSSE_COMPARE_PAYLOAD_TYPE,
    DSSE_RECEIPT_PAYLOAD_TYPE,
    assert_no_floats,
    canonical_bytes,
    validate_receipt,
)

SUPPORTED_DSSE_PAYLOAD_TYPES = (
    DSSE_RECEIPT_PAYLOAD_TYPE,
    DSSE_COMPARE_PAYLOAD_TYPE,
)


def _reject_duplicate_keys(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise ValueError(f"Duplicate JSON key detected: {k!r}")
        obj[k] = v
    return obj


def _reject_constant(token):
    raise ValueError(f"Invalid JSON constant forbidden: {token!r}")


def parse_json_strict(raw: str | bytes):
    """Parse JSON strictly, rejecting duplicate keys and NaN/Infinity constants."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    return json.loads(raw, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant)


def load_json_strict(path: str | Path):
    return parse_json_strict(Path(path).read_bytes())


def dsse_pae(payload_type: str, payload_bytes: bytes) -> bytes:
    """DSSE v1 Pre-Authentication Encoding (in-toto / Sigstore standard domain separation)."""
    pt_bytes = payload_type.encode("utf-8")
    return (
        b"DSSEv1 "
        + str(len(pt_bytes)).encode("ascii")
        + b" "
        + pt_bytes
        + b" "
        + str(len(payload_bytes)).encode("ascii")
        + b" "
        + payload_bytes
    )


def init_keys(private_path: Path):
    private_path = Path(private_path)
    if private_path.exists():
        raise FileExistsError(f"Refusing to overwrite key: {private_path}")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    fd = os.open(str(private_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(raw)
    public_path = private_path.with_suffix(".pub.pem")
    public_path.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return public_path


def _infer_payload_type(receipt: dict, payload_type: str | None = None) -> str:
    if payload_type is not None:
        return payload_type
    test_id = (receipt.get("test") or {}).get("id")
    if test_id == "WIN-ASSURANCE-COMPARE":
        return DSSE_COMPARE_PAYLOAD_TYPE
    return DSSE_RECEIPT_PAYLOAD_TYPE


def sign(receipt: dict, private_path: str | Path, payload_type: str | None = None) -> dict:
    """Sign a float-free Verimetry receipt into a DSSE v1 envelope using Ed25519 over DSSE PAE."""
    assert_no_floats(receipt)
    key = serialization.load_pem_private_key(Path(private_path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Expected Ed25519 private key")
    public_bytes = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    keyid = hashlib.sha256(public_bytes).hexdigest()
    pt = _infer_payload_type(receipt, payload_type=payload_type)
    raw = canonical_bytes(receipt)
    pae = dsse_pae(pt, raw)
    sig_b64 = base64.b64encode(key.sign(pae)).decode("ascii")
    return {
        "payloadType": pt,
        "payload": base64.b64encode(raw).decode("ascii"),
        "signatures": [
            {
                "keyid": keyid,
                "sig": sig_b64,
            }
        ],
    }


def extract_receipt(package: dict) -> tuple[dict, str, str, str]:
    """Extract (decoded_receipt_dict, payload_sha256, signer_keyid, payload_type) from a DSSE envelope."""
    if not isinstance(package, dict) or "payload" not in package or "payloadType" not in package:
        raise ValueError("Expected DSSE v1 envelope with payloadType, payload, and signatures")
    pt = package["payloadType"]
    raw_bytes = base64.b64decode(package["payload"], validate=True)
    receipt = parse_json_strict(raw_bytes)
    payload_sha = hashlib.sha256(raw_bytes).hexdigest()
    sigs = package.get("signatures") or []
    keyid = sigs[0].get("keyid", "") if sigs and isinstance(sigs[0], dict) else ""
    return receipt, payload_sha, keyid, pt


def verify(
    package: dict | str | bytes,
    trusted_public_path: str | Path,
    expected_nonce: str | None = None,
    expected_payload_type: str | None = None,
) -> tuple[bool, str]:
    """Verify DSSE v1 envelope offline: duplicate-key guard, PAE Ed25519 sig, no-floats, nonce, and rule recomputation."""
    try:
        if isinstance(package, (str, bytes)):
            package = parse_json_strict(package)
        if not isinstance(package, dict):
            return False, "INVALID_ENVELOPE: Expected JSON object"

        pt = package.get("payloadType")
        if pt not in SUPPORTED_DSSE_PAYLOAD_TYPES:
            return False, f"UNSUPPORTED_PAYLOAD_TYPE: Unrecognized DSSE payloadType {pt!r}"
        if expected_payload_type is not None and pt != expected_payload_type:
            return False, f"PAYLOAD_TYPE_MISMATCH: Expected {expected_payload_type!r}, got {pt!r}"

        payload_b64 = package.get("payload")
        if not isinstance(payload_b64, str) or not payload_b64:
            return False, "MISSING_PAYLOAD: DSSE payload missing"
        raw_bytes = base64.b64decode(payload_b64, validate=True)

        sigs = package.get("signatures")
        if not isinstance(sigs, list) or not sigs:
            return False, "MISSING_SIGNATURES: DSSE signatures array is empty"

        key = serialization.load_pem_public_key(Path(trusted_public_path).read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            return False, "INVALID_PUBLIC_KEY: Not an Ed25519 public key"
        public_raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        fingerprint = hashlib.sha256(public_raw).hexdigest()

        matching_sig = None
        for entry in sigs:
            if isinstance(entry, dict) and entry.get("keyid") == fingerprint:
                matching_sig = entry
                break
        if matching_sig is None:
            return False, "Trusted public key fingerprint mismatch"

        sig_bytes = base64.b64decode(matching_sig["sig"], validate=True)
        pae = dsse_pae(pt, raw_bytes)
        key.verify(sig_bytes, pae)

        # Verify exact bytes parse cleanly with zero duplicate keys and zero floats
        rec = parse_json_strict(raw_bytes)
        assert_no_floats(rec)

        # Ensure payloadType matches inner receipt test type (prevent cross-type replay)
        test_id = (rec.get("test") or {}).get("id")
        if pt == DSSE_COMPARE_PAYLOAD_TYPE and test_id != "WIN-ASSURANCE-COMPARE":
            return False, "PAYLOAD_TYPE_MISMATCH: Compare envelope contains non-compare receipt"
        if pt == DSSE_RECEIPT_PAYLOAD_TYPE and test_id == "WIN-ASSURANCE-COMPARE":
            return False, "PAYLOAD_TYPE_MISMATCH: Standard receipt envelope contains comparison receipt"

        if expected_nonce is not None:
            actual_nonce = (rec.get("target") or {}).get("challenge_nonce")
            if actual_nonce != expected_nonce:
                return False, f"NONCE_MISMATCH: Expected challenge_nonce {expected_nonce!r}, got {actual_nonce!r}"

        valid, explanation = validate_receipt(rec)
        if not valid:
            return False, explanation

        digest_hex = hashlib.sha256(raw_bytes).hexdigest()
        return True, f"DSSE Ed25519 signature and deterministic verdict verified; payload SHA-256 {digest_hex[:16]}...; signer {fingerprint}"
    except (InvalidSignature, ValueError, TypeError, KeyError, json.JSONDecodeError, UnicodeDecodeError) as e:
        if isinstance(e, ValueError) and ("Duplicate JSON key" in str(e) or "FLOAT_FORBIDDEN" in str(e)):
            return False, f"Verification failed: {e}"
        return False, f"Verification failed: {type(e).__name__}"

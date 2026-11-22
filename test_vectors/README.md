# Verimetry DSSE v1 Conformance Test Vectors

These golden vectors define the cross-language offline verification specification for **Verimetry `v1.0.0-rc1`** (`Apache-2.0`). Any Go, Rust, TypeScript, or Python verifier implementation **MUST** pass all 8 vectors against [`test-signer.pub.pem`](./test-signer.pub.pem).

- **Trusted Test Public Key:** [`test-signer.pub.pem`](./test-signer.pub.pem) (Ed25519; private key discarded after generation)
- **Expected `keyid` (SHA-256 of raw 32-byte Ed25519 public key):** `beb5f0c825a380ea51be7b271dc941114c5bb3dc36049f3a77933155fde0751c`
- **DSSE PAE Format:**
  ```text
  "DSSEv1 " + len(payloadType) + " " + payloadType + " " + len(rawPayloadBytes) + " " + rawPayloadBytes
  ```
  *(Lengths are ASCII base-10 byte counts; signatures are standard Base64 over the PAE byte sequence.)*

## Vector Matrix

All semantically invalid vectors (`invalid_duplicate_key`, `invalid_float_payload`, `invalid_mismatched_reason_codes`, `invalid_unknown_rule_version`, `invalid_wrong_payload_type`) carry **valid Ed25519 signatures from `test-signer.pub.pem` over their exact payload bytes**. Verifiers cannot pass merely by checking Ed25519—they must enforce the strict parser, zero-float, domain-separation, and deterministic rule invariants.

| File | `payloadType` | Nonce | Expected | Required Failure Class |
| :--- | :--- | :--- | :---: | :--- |
| [`valid_receipt_v1.dsse.json`](./valid_receipt_v1.dsse.json) | `application/vnd.verimetry.receipt.v1+json` | `verimetry-vector-nonce-2026-01` | **ACCEPT** | Valid single-check DSSE receipt (`WIN-LSA-SSP-AUDIT`, `FAIL`, sorted `reason_codes[]`, zero floats) |
| [`valid_compare_v1.dsse.json`](./valid_compare_v1.dsse.json) | `application/vnd.verimetry.compare.v1+json` | `verimetry-compare-nonce-2026-01` | **ACCEPT** | Valid multi-run comparison receipt (integer `*_bps` basis points, `host_fingerprint_consistent: true`, zero floats) |
| [`invalid_duplicate_key.dsse.json`](./invalid_duplicate_key.dsse.json) | `application/vnd.verimetry.receipt.v1+json` | — | **REJECT** | Duplicate JSON key (`"verdict"`) inside signed payload |
| [`invalid_float_payload.dsse.json`](./invalid_float_payload.dsse.json) | `application/vnd.verimetry.receipt.v1+json` | — | **REJECT** | `FLOAT_FORBIDDEN` (`sacl_rule_count: 0.0` inside signed payload) |
| [`invalid_mismatched_reason_codes.dsse.json`](./invalid_mismatched_reason_codes.dsse.json) | `application/vnd.verimetry.receipt.v1+json` | — | **REJECT** | `VERDICT_MISMATCH` (`verdict == "FAIL"` matches, but `reason_codes[]` omits `LSA_SACL_MISSING`) |
| [`invalid_unknown_rule_version.dsse.json`](./invalid_unknown_rule_version.dsse.json) | `application/vnd.verimetry.receipt.v1+json` | — | **REJECT** | `UNKNOWN_RULE_VERSION` (`lsa-ssp-audit-v99` must fail closed) |
| [`invalid_wrong_payload_type.dsse.json`](./invalid_wrong_payload_type.dsse.json) | `application/vnd.verimetry.compare.v1+json` | — | **REJECT** | `PAYLOAD_TYPE_MISMATCH` (cross-protocol replay: compare `payloadType` wrapping single-check receipt) |
| [`invalid_tampered_sig.dsse.json`](./invalid_tampered_sig.dsse.json) | `application/vnd.verimetry.receipt.v1+json` | — | **REJECT** | `InvalidSignature` (1-byte payload mutation after signing) |

## Quick CLI Verification

```bash
python3 -m verimetry verify \
  --receipt ./test_vectors/valid_receipt_v1.dsse.json \
  --public ./test_vectors/test-signer.pub.pem \
  --nonce verimetry-vector-nonce-2026-01 \
  --show
```

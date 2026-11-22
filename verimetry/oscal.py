"""Experimental OSCAL-shaped mapping; NOT a certified/schema-validated OSCAL artifact."""
from uuid import uuid4
from .core import utc_now, TEST_SPECS
from .receipts import extract_receipt

VERIMETRY_OSCAL_NS = "urn:verimetry:ns"


def export_draft(packages):
    observations = []
    controls = []
    for p in packages:
        r, payload_sha, keyid, payload_type = extract_receipt(p)
        test = r.get("test") or {}
        test_id = test.get("id", "WIN-4688-CANARY")
        spec = TEST_SPECS.get(test_id, {})
        for ctrl in spec.get("oscal_controls", ["au-12"]):
            if ctrl not in controls:
                controls.append(ctrl)
        props = [
            {"name": "test-id", "value": test_id, "ns": VERIMETRY_OSCAL_NS},
            {"name": "verimetry-verdict", "value": r["verdict"], "ns": VERIMETRY_OSCAL_NS},
            {"name": "reason-codes", "value": ",".join(r.get("reason_codes") or []), "ns": VERIMETRY_OSCAL_NS},
            {"name": "dsse-payload-type", "value": payload_type, "ns": VERIMETRY_OSCAL_NS},
            {"name": "receipt-sha256", "value": payload_sha, "ns": VERIMETRY_OSCAL_NS},
            {"name": "signer-keyid", "value": keyid, "ns": VERIMETRY_OSCAL_NS},
        ]
        host_fp = (r.get("target") or {}).get("host_fingerprint_sha256")
        if host_fp:
            props.append({"name": "host-fingerprint-sha256", "value": host_fp, "ns": VERIMETRY_OSCAL_NS})
        if test.get("mitre_attack"):
            props.append({"name": "mitre-attack", "value": test["mitre_attack"], "ns": VERIMETRY_OSCAL_NS})
        title_prefix = test.get("title") or "Canary"
        observations.append({
            "uuid": str(uuid4()),
            "title": f"{title_prefix}: {r['target']['host']}",
            "description": r["rationale"],
            "collected": r["created_at"],
            "methods": ["TEST"],
            "props": props,
        })
    if not controls:
        controls = ["au-12"]
    return {
        "assessment-results": {
            "uuid": str(uuid4()),
            "metadata": {
                "title": "Verimetry experimental assessment results",
                "last-modified": utc_now(),
                "version": "1.0.0-rc1",
                "oscal-version": "1.1.3",
            },
            "import-ap": {"href": "./assessment-plan.json"},
            "results": [{
                "uuid": str(uuid4()),
                "title": "Windows Internals telemetry & readiness checks",
                "description": "Limited, point-in-time telemetry objectives only; NOT schema-validated OSCAL",
                "start": utc_now(),
                "reviewed-controls": {
                    "control-selections": [{"include-controls": [{"control-id": c} for c in controls]}]
                },
                "observations": observations,
            }],
        }
    }

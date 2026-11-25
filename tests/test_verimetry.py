import base64
import copy
import json
from pathlib import Path
from types import SimpleNamespace
import pytest

from verimetry.core import (
    make_receipt,
    decide,
    decide_detailed,
    validate_receipt,
    compute_host_fingerprint,
    assert_no_floats,
    DSSE_COMPARE_PAYLOAD_TYPE,
    DSSE_RECEIPT_PAYLOAD_TYPE,
    WINDOWS_INTERNALS_CHECK_IDS,
    TEST_SPECS,
)
from verimetry.simulate import scenario_observation, internals_observation
from verimetry.receipts import extract_unverified_receipt, init_keys, parse_json_strict, sign, verify
from verimetry.oscal import export_draft
from verimetry.report import build_report, build_inventory_report
from verimetry import cli, windows, inventory


@pytest.mark.parametrize("scenario,expected", [("A", "PASS"), ("B", "FAIL"), ("C", "INCONCLUSIVE")])
def test_scenarios(scenario, expected):
    assert decide(scenario_observation(scenario))[0] == expected


def test_missing_policy_is_not_failure():
    data = scenario_observation("B")
    data["audit_policy"] = "unknown"
    assert decide(data)[0] == "INCONCLUSIVE"


def test_truncation_is_not_failure():
    data = scenario_observation("B")
    data["query_truncated"] = True
    assert decide(data)[0] == "INCONCLUSIVE"


def _tamper_dsse_payload(signed: dict, mutator) -> dict:
    altered = copy.deepcopy(signed)
    rec, _sha, _kid, _pt = extract_unverified_receipt(altered)
    mutator(rec)
    altered["payload"] = base64.b64encode(json.dumps(rec, sort_keys=True, separators=(",", ":")).encode("utf-8")).decode("ascii")
    return altered


def test_signed_receipts(tmp_path):
    priv = tmp_path / "key.pem"
    pub = init_keys(priv)
    receipt = make_receipt("Environment A", scenario_observation("A"), "synthetic")
    signed = sign(receipt, priv)
    assert signed["payloadType"] == DSSE_RECEIPT_PAYLOAD_TYPE
    assert verify(signed, pub)[0]
    assert not verify(_tamper_dsse_payload(signed, lambda r: r.__setitem__("verdict", "FAIL")), pub)[0]
    assert not verify(_tamper_dsse_payload(signed, lambda r: r["observation"].__setitem__("matching_event", False)), pub)[0]
    impostor = tmp_path / "other.pem"
    impostor_pub = init_keys(impostor)
    assert not verify(signed, impostor_pub)[0]


def test_export_and_report(tmp_path):
    priv = tmp_path / "key.pem"
    init_keys(priv)
    packages = [sign(make_receipt(f"Environment {c}", scenario_observation(c), "synthetic"), priv) for c in "ABC"]
    path = tmp_path / "report.html"
    build_report(packages, path)
    assert "INCONCLUSIVE" in path.read_text()
    assert len(export_draft(packages)["assessment-results"]["results"][0]["observations"]) == 3


def test_inventory_requires_real_windows(monkeypatch):
    monkeypatch.setattr(inventory.platform, "system", lambda: "Linux")
    with pytest.raises(OSError):
        inventory.collect()


def test_inventory_marks_failed_sections_without_inventing_results(monkeypatch):
    monkeypatch.setattr(inventory.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        inventory.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(
            returncode=0,
            stdout='{"defender":{"status":"unavailable","error_type":"AccessDenied"}}',
        ),
    )
    result = inventory.collect()
    assert result["status"] == "observed"
    assert result["sections"]["defender"]["status"] == "unavailable"


def test_plain_english_report_has_tabs_and_retains_unknown(tmp_path):
    data = {
        "status": "observed",
        "collected_at": "2026-11-18T10:00:00Z",
        "sections": {
            "defender": {"status": "unavailable", "error_type": "AccessDenied"},
            "firewall": {
                "status": "observed",
                "data": [{"Name": "Domain", "Enabled": True}, {"Name": "Public", "Enabled": 0}],
            },
            "os": {"status": "observed", "data": {"Caption": "Windows Test", "BuildNumber": "99999"}},
            "audit_process_creation": {"status": "unavailable"},
        },
    }
    path = tmp_path / "inventory-report.html"
    build_inventory_report(data, path)
    html = path.read_text()
    assert "Plain English" in html
    assert "Technical evidence (JSON)" in html
    assert "does not mean Defender is turned off" in html
    assert "Domain: <b>on</b>" in html
    assert "Public: <b>off</b>" in html
    assert "AccessDenied" in html
    assert "Windows Test" in html


@pytest.mark.parametrize("test_id", WINDOWS_INTERNALS_CHECK_IDS)
@pytest.mark.parametrize("outcome", ["PASS", "FAIL", "INCONCLUSIVE"])
def test_all_five_checks_verdict_and_signing(tmp_path, test_id, outcome):
    obs = internals_observation(test_id, outcome)
    verdict, rationale = decide(obs, test_id=test_id)
    assert verdict == outcome
    assert rationale

    priv = tmp_path / f"{test_id}-{outcome}.pem"
    pub = init_keys(priv)
    receipt = make_receipt("WIN-HOST-01", obs, "synthetic", test_id=test_id)
    assert receipt["test"]["mitre_attack"] == TEST_SPECS[test_id]["mitre_attack"]
    assert validate_receipt(receipt)[0]

    signed = sign(receipt, priv)
    assert verify(signed, pub)[0]

    tampered = _tamper_dsse_payload(signed, lambda r: r.__setitem__("verdict", "PASS" if outcome != "PASS" else "FAIL"))
    assert not verify(tampered, pub)[0]


def test_evidence_gates_never_fabricate_fail():
    # Check 1: truncated Application log -> INCONCLUSIVE
    obs1 = internals_observation("WIN-ETW-INTEGRITY", "FAIL")
    obs1["query_truncated"] = True
    assert decide(obs1, "WIN-ETW-INTEGRITY")[0] == "INCONCLUSIVE"

    # Check 2: unreadable CodeIntegrity log -> INCONCLUSIVE
    obs2 = internals_observation("WIN-KERNEL-PPL-HVCI", "FAIL")
    obs2["ci_log_query_status"] = "access_denied"
    assert decide(obs2, "WIN-KERNEL-PPL-HVCI")[0] == "INCONCLUSIVE"

    # Check 3: failed OpenProcess handle -> INCONCLUSIVE
    obs3 = internals_observation("WIN-XPROC-HANDLE", "FAIL")
    obs3["handle_opened"] = False
    assert decide(obs3, "WIN-XPROC-HANDLE")[0] == "INCONCLUSIVE"

    # Check 4: missing SeSecurityPrivilege for SACL -> INCONCLUSIVE
    obs4 = internals_observation("WIN-LSA-SSP-AUDIT", "FAIL")
    obs4["sacl_query_status"] = "access_denied"
    assert decide(obs4, "WIN-LSA-SSP-AUDIT")[0] == "INCONCLUSIVE"

    # Check 5: Security log truncated or WMI query failed -> INCONCLUSIVE
    obs5 = internals_observation("WIN-CMDLINE-WMI", "FAIL")
    obs5["wmi_log_truncated"] = True
    assert decide(obs5, "WIN-CMDLINE-WMI")[0] == "INCONCLUSIVE"
    obs5b = internals_observation("WIN-CMDLINE-WMI", "FAIL")
    obs5b["wmi_query_completed"] = False
    assert decide(obs5b, "WIN-CMDLINE-WMI")[0] == "INCONCLUSIVE"


def test_windows_checks_require_windows(monkeypatch):
    monkeypatch.setattr(windows.platform, "system", lambda: "Linux")
    with pytest.raises(OSError):
        windows.run_all_internals_checks()


def test_read_audit_subcategory_parses_numeric_and_inclusion_and_denied(monkeypatch):
    csv_numeric = (
        "\nMachine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting,Setting Value\n"
        "HOST,System,Process Creation,{0cce922b-69ae-11d9-bed3-505054503030},Success,,1\n"
    )
    monkeypatch.setattr(windows, "_run", lambda *a, **k: SimpleNamespace(returncode=0, stdout=csv_numeric, stderr=""))
    assert windows.read_audit_subcategory(windows.PROCESS_CREATION_GUID)[0] == "enabled"

    csv_inclusion_only = (
        "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting\n"
        "HOST,System,Registry,{0cce921e-69ae-11d9-bed3-505054503030},No Auditing\n"
    )
    monkeypatch.setattr(windows, "_run", lambda *a, **k: SimpleNamespace(returncode=0, stdout=csv_inclusion_only, stderr=""))
    assert windows.read_audit_subcategory(windows.AUDIT_REGISTRY_GUID)[0] == "disabled"

    monkeypatch.setattr(
        windows,
        "_run",
        lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="Error 0x00000522: A required privilege is not held"),
    )
    status, note = windows.read_audit_subcategory(windows.AUDIT_REGISTRY_GUID)
    assert status == "unknown"
    assert "access denied" in note.lower()


def test_mocked_windows_runners_all_five(monkeypatch):
    monkeypatch.setattr(windows.platform, "system", lambda: "Windows")
    monkeypatch.setattr(windows.time, "sleep", lambda s: None)

    class DummyChild:
        pid = 5432

        def wait(self, timeout=10):
            return 0

    monkeypatch.setattr(windows.subprocess, "Popen", lambda *a, **k: DummyChild())
    monkeypatch.setattr(
        windows,
        "_open_readonly_process_handle",
        lambda pid: (True, r"C:\Windows\System32\cmd.exe", 0),
    )
    monkeypatch.setattr(windows, "read_audit_subcategory", lambda guid, label="": ("enabled", f"{label} enabled"))

    responses = iter([
        # Check 1: ETW query, emit marker, read Application log
        ({"status": "ok", "method": "Get-EtwTraceSession", "total_sessions": 20, "eventlog_system": True, "diagtrack_listener": True}, "ok"),
        ({"emitted": True, "method": "WScript.Shell.LogEvent"}, "ok"),
        ({"status": "ok", "events_scanned": 5, "truncated": False, "match": {"record_id": 101, "event_id": 4, "provider": "WSH"}}, "ok"),
        # Check 2: Kernel/PPL/HVCI
        ({
            "device_guard": {"status": "ok", "vbs_status": 2, "configured": [1, 2], "running": [1, 2]},
            "lsa": {"status": "ok", "run_as_ppl": 1, "run_as_ppl_boot": 1},
            "code_integrity": {"status": "ok", "enabled": True, "readable": True, "record_count": 42, "events_sampled": 5},
        }, "ok"),
        # Check 3: XProc handle Security log query
        ({"status": "ok", "events_scanned": 12, "truncated": False, "handle_match": {"record_id": 202, "event_id": 4656}, "proc_match": {"record_id": 201, "event_id": 4688}}, "ok"),
        # Check 4: LSA SSP registry & SACL
        ({
            "registry": {"status": "ok", "security_packages": ["kerberos", "msv1_0", "schannel"], "run_as_ppl": 1},
            "sacl": {"status": "ok", "rule_count": 1, "rules": [{"identity": "Everyone", "rights": "SetValue", "flags": "Success"}]},
        }, "ok"),
        # Check 5: cmdline policy, WMI probe, Security + WMI-Activity logs
        ({"status": "ok", "value": 1}, "ok"),
        ({"completed": True, "caption": "Microsoft Windows 11 Pro", "build": "26100"}, "ok"),
        ({
            "security": {"status": "ok", "events_scanned": 8, "truncated": False, "match": {"record_id": 303, "command_line": "cmd.exe /d /c echo VERIMETRY_CANARY_PING"}, "cmdline_matched": True},
            "wmi_activity": {"status": "ok", "enabled": True, "readable": True, "events_scanned": 3, "truncated": False, "record_count": 150},
        }, "ok"),
    ])
    monkeypatch.setattr(windows, "_run_ps_json", lambda script, timeout=35: next(responses))

    results = windows.run_all_internals_checks(window_seconds=1)
    assert len(results) == 5
    for slug, test_id, obs in results:
        verdict, rationale = decide(obs, test_id=test_id)
        assert verdict == "PASS", f"{test_id} failed: {rationale}"


def test_cli_assess_wires_all_five_checks(tmp_path, monkeypatch):
    monkeypatch.setattr(
        cli,
        "collect",
        lambda: {"kind": "real-windows-inventory", "collected_at": "2026-11-18T10:00:00Z", "status": "observed", "sections": {}},
    )
    fake_results = [
        (TEST_SPECS[tid]["slug"], tid, internals_observation(tid, out_state))
        for tid, out_state in zip(WINDOWS_INTERNALS_CHECK_IDS, ("PASS", "FAIL", "INCONCLUSIVE", "PASS", "FAIL"))
    ]
    monkeypatch.setattr(windows, "run_all_internals_checks", lambda window_seconds=4, selected=None: fake_results)

    out_dir = tmp_path / "live-out"
    cli.main(["assess", "--out", str(out_dir), "--window", "2"])

    pub = out_dir / "signer.pub.pem"
    assert pub.exists()
    assert (out_dir / "windows-inventory.json").exists()
    assert (out_dir / "inventory-report.html").exists()
    assert (out_dir / "report.html").exists()
    assert (out_dir / "oscal-draft.json").exists()

    for tid in WINDOWS_INTERNALS_CHECK_IDS:
        slug = TEST_SPECS[tid]["slug"]
        rec_path = out_dir / f"receipt-{slug}.json"
        assert rec_path.exists()
        ok, msg = verify(json.loads(rec_path.read_text(encoding="utf-8")), pub)
        assert ok, msg

    oscal = json.loads((out_dir / "oscal-draft.json").read_text(encoding="utf-8"))
    assert len(oscal["assessment-results"]["results"][0]["observations"]) == 5
    report_html = (out_dir / "report.html").read_text(encoding="utf-8")
    for tid in WINDOWS_INTERNALS_CHECK_IDS:
        assert tid in report_html
        for tech in TEST_SPECS[tid]["mitre_attack"].split("/"):
            tech_clean = tech.strip()
            assert tech_clean in report_html
            assert f'href="https://attack.mitre.org/techniques/{tech_clean.replace(".", "/")}/"' in report_html


def test_cli_demo_internals_suite(tmp_path):
    out_dir = tmp_path / "demo-internals"
    cli.main(["demo", "--suite", "internals", "--out", str(out_dir)])
    pub = out_dir / "signer.pub.pem"
    for tid in WINDOWS_INTERNALS_CHECK_IDS:
        slug = TEST_SPECS[tid]["slug"]
        rec_path = out_dir / f"receipt-{slug}.json"
        assert rec_path.exists()
        assert verify(json.loads(rec_path.read_text(encoding="utf-8")), pub)[0]


def test_etw_zero_sessions_is_inconclusive_not_fail(monkeypatch):
    monkeypatch.setattr(windows.platform, "system", lambda: "Windows")
    monkeypatch.setattr(windows.time, "sleep", lambda s: None)
    responses = iter([
        ({"status": "ok", "method": "Get-EtwTraceSession", "total_sessions": 0, "eventlog_system": False, "diagtrack_listener": False}, "ok"),
        ({"emitted": True, "method": "WScript.Shell.LogEvent"}, "ok"),
        ({"status": "ok", "events_scanned": 2, "truncated": False, "match": {"record_id": 55, "event_id": 4, "provider": "WSH"}}, "ok"),
    ])
    monkeypatch.setattr(windows, "_run_ps_json", lambda script, timeout=35: next(responses))
    obs = windows.run_etw_integrity(window_seconds=1)
    assert obs["etw_query_status"] == "insufficient_visibility"
    assert decide(obs, "WIN-ETW-INTEGRITY")[0] == "INCONCLUSIVE"


def _write_run_dir(directory: Path, verdicts: dict[str, str], created_at: str, host: str = "Tha", key_path: Path | None = None):
    directory.mkdir(parents=True, exist_ok=True)
    priv = key_path if key_path is not None else (directory / "signer.pem")
    if not priv.exists():
        init_keys(priv)
    for tid, state in verdicts.items():
        slug = TEST_SPECS[tid]["slug"]
        obs = internals_observation(tid, state)
        rec = make_receipt(host, obs, "live-host", test_id=tid)
        rec["created_at"] = created_at
        signed = sign(rec, priv)
        cli.save_json(directory / f"receipt-{slug}.json", signed)
    return priv, priv.with_suffix(".pub.pem")


def test_compare_tha_non_elevated_to_elevated_metrics_and_signing(tmp_path):
    """Reproduce exact Tha non-elevated (.\\evidence) vs elevated (.\\evidence-elevated) run."""
    before_dir = tmp_path / "evidence"
    after_dir = tmp_path / "evidence-elevated"
    out_dir = tmp_path / "evidence-comparison"
    cmp_key = tmp_path / "verimetry_private.pem"
    cmp_pub = tmp_path / "verimetry_private.pub.pem"

    _write_run_dir(
        before_dir,
        {
            "WIN-ETW-INTEGRITY": "INCONCLUSIVE",
            "WIN-KERNEL-PPL-HVCI": "PASS",
            "WIN-XPROC-HANDLE": "INCONCLUSIVE",
            "WIN-LSA-SSP-AUDIT": "INCONCLUSIVE",
            "WIN-CMDLINE-WMI": "INCONCLUSIVE",
        },
        created_at="2026-11-18T17:10:00+00:00",
        host="Tha",
    )
    _write_run_dir(
        after_dir,
        {
            "WIN-ETW-INTEGRITY": "FAIL",
            "WIN-KERNEL-PPL-HVCI": "PASS",
            "WIN-XPROC-HANDLE": "INCONCLUSIVE",
            "WIN-LSA-SSP-AUDIT": "FAIL",
            "WIN-CMDLINE-WMI": "INCONCLUSIVE",
        },
        created_at="2026-11-18T17:25:30+00:00",
        host="Tha",
    )

    cli.main([
        "compare",
        "--before", str(before_dir),
        "--after", str(after_dir),
        "--out", str(out_dir),
        "--key", str(cmp_key),
        "--public", str(cmp_pub),
    ])

    rec_path = out_dir / "comparison-receipt.json"
    html_path = out_dir / "comparison-report.html"
    assert rec_path.exists()
    assert html_path.exists()

    signed_cmp = json.loads(rec_path.read_text(encoding="utf-8"))
    ok, why = verify(signed_cmp, cmp_pub)
    assert ok, why
    assert signed_cmp["payloadType"] == DSSE_COMPARE_PAYLOAD_TYPE

    rec, _sha, _kid, _pt = extract_unverified_receipt(signed_cmp)
    assert rec["verdict"] == "FAIL"
    assert_no_floats(rec)
    m = rec["observation"]["metrics"]
    assert m["total_checks"] == 5
    assert m["before_coverage_bps"] == 2000
    assert m["after_coverage_bps"] == 2000
    assert m["coverage_delta_bps"] == 0
    assert m["before_inconclusive_count"] == 4
    assert m["after_inconclusive_count"] == 2
    assert m["inconclusive_burndown_bps"] == 5000
    assert m["inconclusive_burndown_pct_str"] == "50.0%"
    assert m["visibility_unlocked_count"] == 2
    assert m["hardening_candidates_count"] == 4
    assert m["hardened_to_pass_count"] == 0
    assert m["hardening_verification_bps"] == 0
    assert m["regression_count"] == 0
    assert m["drift_detected"] is False
    assert m["elapsed_seconds"] == 930
    assert m["elapsed_ms"] == 930000
    assert m["elapsed_human"] == "15m 30s"

    html = html_path.read_text(encoding="utf-8")
    assert "VISIBILITY UNLOCKED -&gt; GAP EXPOSED" in html or "VISIBILITY UNLOCKED -> GAP EXPOSED" in html
    assert "50.0%" in html
    assert "15m 30s" in html


def test_compare_full_hardening_to_pass_and_regression_detection(tmp_path):
    before_dir = tmp_path / "day1"
    after_pass_dir = tmp_path / "day30-hardened"
    after_reg_dir = tmp_path / "day45-regressed"

    shared_key = tmp_path / "shared.pem"
    shared_pub = init_keys(shared_key)

    _write_run_dir(
        before_dir,
        {
            "WIN-ETW-INTEGRITY": "FAIL",
            "WIN-KERNEL-PPL-HVCI": "PASS",
            "WIN-XPROC-HANDLE": "INCONCLUSIVE",
            "WIN-LSA-SSP-AUDIT": "FAIL",
            "WIN-CMDLINE-WMI": "INCONCLUSIVE",
        },
        created_at="2026-11-01T09:00:00+00:00",
        host="Tha",
        key_path=shared_key,
    )
    _write_run_dir(
        after_pass_dir,
        {tid: "PASS" for tid in WINDOWS_INTERNALS_CHECK_IDS},
        created_at="2026-11-15T09:00:00+00:00",
        host="Tha",
        key_path=shared_key,
    )

    out_pass = tmp_path / "cmp-pass"
    cli.main([
        "compare",
        "--before", str(before_dir),
        "--after", str(after_pass_dir),
        "--out", str(out_pass),
        "--key", str(shared_key),
        "--public", str(shared_pub),
    ])
    pack_pass = json.loads((out_pass / "comparison-receipt.json").read_text(encoding="utf-8"))
    assert verify(pack_pass, shared_pub)[0]
    rec_pass, _sha, _kid, _pt = extract_unverified_receipt(pack_pass)
    assert rec_pass["verdict"] == "PASS"
    mp = rec_pass["observation"]["metrics"]
    assert mp["before_coverage_bps"] == 2000
    assert mp["after_coverage_bps"] == 10000
    assert mp["coverage_delta_bps"] == 8000
    assert mp["inconclusive_burndown_bps"] == 10000
    assert mp["hardening_verification_bps"] == 10000
    assert mp["drift_detected"] is False

    # Now simulate telemetry drift / regression from day30-hardened to day45-regressed
    _write_run_dir(
        after_reg_dir,
        {
            "WIN-ETW-INTEGRITY": "PASS",
            "WIN-KERNEL-PPL-HVCI": "PASS",
            "WIN-XPROC-HANDLE": "INCONCLUSIVE",
            "WIN-LSA-SSP-AUDIT": "FAIL",
            "WIN-CMDLINE-WMI": "PASS",
        },
        created_at="2026-11-20T09:00:00+00:00",
        host="Tha",
        key_path=shared_key,
    )
    out_reg = tmp_path / "cmp-reg"
    cli.main([
        "compare",
        "--before", str(after_pass_dir),
        "--after", str(after_reg_dir),
        "--out", str(out_reg),
        "--key", str(shared_key),
        "--public", str(shared_pub),
    ])
    pack_reg = json.loads((out_reg / "comparison-receipt.json").read_text(encoding="utf-8"))
    assert verify(pack_reg, shared_pub)[0]
    rec_reg, _sha2, _kid2, _pt2 = extract_unverified_receipt(pack_reg)
    assert rec_reg["verdict"] == "FAIL"
    assert "TELEMETRY_DRIFT_DETECTED" in rec_reg["reason_codes"]
    assert "Telemetry drift / regression detected" in rec_reg["rationale"]
    mr = rec_reg["observation"]["metrics"]
    assert mr["drift_detected"] is True
    assert mr["regression_count"] == 2
    assert set(mr["regressions"]) == {"WIN-XPROC-HANDLE", "WIN-LSA-SSP-AUDIT"}


def test_compare_rejects_tampered_receipt_or_untrusted_public_key(tmp_path):
    before_dir = tmp_path / "before-ok"
    after_dir = tmp_path / "after-tampered"
    _write_run_dir(
        before_dir,
        {tid: "INCONCLUSIVE" for tid in WINDOWS_INTERNALS_CHECK_IDS},
        created_at="2026-11-18T10:00:00+00:00",
    )
    _write_run_dir(
        after_dir,
        {tid: "PASS" for tid in WINDOWS_INTERNALS_CHECK_IDS},
        created_at="2026-11-18T11:00:00+00:00",
    )

    # Tamper with one DSSE receipt in after_dir
    target_file = after_dir / "receipt-etw-integrity.json"
    tampered = _tamper_dsse_payload(json.loads(target_file.read_text(encoding="utf-8")), lambda r: r.__setitem__("verdict", "FAIL"))
    target_file.write_text(json.dumps(tampered), encoding="utf-8")

    out_dir = tmp_path / "cmp-fail"
    with pytest.raises(SystemExit) as excinfo:
        cli.main([
            "compare",
            "--before", str(before_dir),
            "--after", str(after_dir),
            "--out", str(out_dir),
        ])
    assert excinfo.value.code == 2
    assert not (out_dir / "comparison-receipt.json").exists()

    # Also verify that passing an explicit wrong --public key without matching --key rejects
    clean_after = tmp_path / "after-clean"
    _write_run_dir(
        clean_after,
        {tid: "PASS" for tid in WINDOWS_INTERNALS_CHECK_IDS},
        created_at="2026-11-18T11:00:00+00:00",
    )
    impostor_priv = tmp_path / "impostor.pem"
    impostor_pub = init_keys(impostor_priv)
    with pytest.raises(SystemExit) as excinfo2:
        cli.main([
            "compare",
            "--before", str(before_dir),
            "--after", str(clean_after),
            "--out", str(out_dir),
            "--public", str(impostor_pub),
        ])
    assert excinfo2.value.code == 2


def test_mitre_attack_links_across_all_three_reports(tmp_path):
    from verimetry.report import mitre_url, render_mitre_badges

    assert mitre_url("T1562.006") == "https://attack.mitre.org/techniques/T1562/006/"
    assert mitre_url("T1068") == "https://attack.mitre.org/techniques/T1068/"
    badges_html = render_mitre_badges("T1068 / T1562.001")
    assert 'href="https://attack.mitre.org/techniques/T1068/"' in badges_html
    assert 'href="https://attack.mitre.org/techniques/T1562/001/"' in badges_html
    assert 'target="_blank" rel="noopener noreferrer"' in badges_html

    # 1. report.html (via demo --suite internals)
    demo_dir = tmp_path / "demo-mitre"
    cli.main(["demo", "--suite", "internals", "--out", str(demo_dir)])
    report_html = (demo_dir / "report.html").read_text(encoding="utf-8")
    for expected_url in (
        "https://attack.mitre.org/techniques/T1562/006/",
        "https://attack.mitre.org/techniques/T1068/",
        "https://attack.mitre.org/techniques/T1562/001/",
        "https://attack.mitre.org/techniques/T1106/",
        "https://attack.mitre.org/techniques/T1055/",
        "https://attack.mitre.org/techniques/T1547/005/",
        "https://attack.mitre.org/techniques/T1047/",
    ):
        assert f'href="{expected_url}"' in report_html
        assert 'target="_blank" rel="noopener noreferrer"' in report_html

    # 2. inventory-report.html
    inv_path = tmp_path / "inventory-report.html"
    build_inventory_report({"status": "observed", "collected_at": "2026-11-18T10:00:00Z", "sections": {}}, inv_path)
    inv_html = inv_path.read_text(encoding="utf-8")
    for expected_url in (
        "https://attack.mitre.org/techniques/T1082/",
        "https://attack.mitre.org/techniques/T1562/001/",
        "https://attack.mitre.org/techniques/T1562/004/",
        "https://attack.mitre.org/techniques/T1068/",
        "https://attack.mitre.org/techniques/T1059/",
        "https://attack.mitre.org/techniques/T1047/",
    ):
        assert f'href="{expected_url}"' in inv_html

    # 3. comparison-report.html
    before_dir = tmp_path / "b"
    after_dir = tmp_path / "a"
    cmp_dir = tmp_path / "c"
    _write_run_dir(before_dir, {tid: "INCONCLUSIVE" for tid in WINDOWS_INTERNALS_CHECK_IDS}, "2026-11-18T10:00:00+00:00")
    _write_run_dir(after_dir, {tid: "PASS" for tid in WINDOWS_INTERNALS_CHECK_IDS}, "2026-11-18T10:15:00+00:00")
    cli.main(["compare", "--before", str(before_dir), "--after", str(after_dir), "--out", str(cmp_dir)])
    cmp_html = (cmp_dir / "comparison-report.html").read_text(encoding="utf-8")
    for expected_url in (
        "https://attack.mitre.org/techniques/T1562/006/",
        "https://attack.mitre.org/techniques/T1068/",
        "https://attack.mitre.org/techniques/T1562/001/",
        "https://attack.mitre.org/techniques/T1106/",
        "https://attack.mitre.org/techniques/T1055/",
        "https://attack.mitre.org/techniques/T1547/005/",
        "https://attack.mitre.org/techniques/T1047/",
    ):
        assert f'href="{expected_url}"' in cmp_html


def test_customer_and_mssp_role_switcher_and_persona_cli(tmp_path):
    # 1. demo --suite internals --persona mssp
    demo_mssp = tmp_path / "demo-mssp"
    cli.main(["demo", "--suite", "internals", "--persona", "mssp", "--out", str(demo_mssp)])
    rep_html = (demo_mssp / "report.html").read_text(encoding="utf-8")
    assert "Customer View" in rep_html
    assert "MSSP Operations View" in rep_html
    assert "Copy Verification Proof" in rep_html
    assert 'id="role-mssp" checked' in rep_html
    assert "auditpol /set /subcategory:" in rep_html
    assert "RunAsPPL" in rep_html

    # 2. compare --persona customer
    before_dir = tmp_path / "b-role"
    after_dir = tmp_path / "a-role"
    cmp_dir = tmp_path / "c-role"
    _write_run_dir(before_dir, {tid: "INCONCLUSIVE" for tid in WINDOWS_INTERNALS_CHECK_IDS}, "2026-11-18T10:00:00+00:00")
    _write_run_dir(
        after_dir,
        {
            "WIN-ETW-INTEGRITY": "FAIL",
            "WIN-KERNEL-PPL-HVCI": "PASS",
            "WIN-XPROC-HANDLE": "INCONCLUSIVE",
            "WIN-LSA-SSP-AUDIT": "FAIL",
            "WIN-CMDLINE-WMI": "INCONCLUSIVE",
        },
        "2026-11-18T10:20:00+00:00",
    )
    cli.main(["compare", "--before", str(before_dir), "--after", str(after_dir), "--out", str(cmp_dir), "--persona", "customer"])
    cmp_html = (cmp_dir / "comparison-report.html").read_text(encoding="utf-8")
    assert "Customer View" in cmp_html
    assert "MSSP Operations View" in cmp_html
    assert "Copy Verification Proof" in cmp_html
    assert 'id="role-customer" checked' in cmp_html
    assert "Before &rarr; After Value Proof" in cmp_html
    assert "Telemetry Engineering &amp; Remediation Matrix" in cmp_html
    assert "ProcessCreationIncludeCmdLine_Enabled" in cmp_html

    # 3. inventory-report.html with persona="mssp"
    inv_path = tmp_path / "inv-mssp.html"
    build_inventory_report({"status": "observed", "collected_at": "2026-11-18T10:00:00Z", "sections": {}}, inv_path, persona="mssp")
    inv_html = inv_path.read_text(encoding="utf-8")
    assert "Customer View (Plain English)" in inv_html
    assert "MSSP Operations View (Technical evidence (JSON))" in inv_html
    assert 'id="technical" checked' in inv_html


@pytest.mark.parametrize("test_id", [
    "WIN-T1685-001-EDR-MINIFILTER",
    "WIN-T1685-002-CLOUD-LOG",
    "WIN-T1685-003-ETW-SYSCALL",
    "WIN-T1685-004-FIREWALL-WFP",
    "WIN-T1685-005-USN-EVTX",
    "WIN-T1685-006-VBS-VTL1-BCD",
    "WIN-T1685-007-SAFEBOOT-BCD",
])
@pytest.mark.parametrize("outcome", ["PASS", "FAIL", "INCONCLUSIVE"])
def test_all_seven_t1685_scenarios_verdict_signing_and_gates(tmp_path, test_id, outcome):
    obs = internals_observation(test_id, outcome)
    verdict, rationale = decide(obs, test_id=test_id)
    assert verdict == outcome
    assert rationale

    priv = tmp_path / f"{test_id}-{outcome}.pem"
    pub = init_keys(priv)
    receipt = make_receipt("WIN-HOST-T1685", obs, "synthetic", test_id=test_id)
    assert receipt["test"]["mitre_attack"] == TEST_SPECS[test_id]["mitre_attack"]
    assert validate_receipt(receipt)[0]

    signed = sign(receipt, priv)
    assert verify(signed, pub)[0]


def test_cli_demo_t1685_suite_and_compare(tmp_path):
    out_dir = tmp_path / "demo-t1685"
    cli.main(["demo", "--suite", "t1685", "--out", str(out_dir)])
    pub = out_dir / "signer.pub.pem"
    rep_html = (out_dir / "report.html").read_text(encoding="utf-8")
    assert "https://attack.mitre.org/techniques/T1685/001/" in rep_html
    assert "https://attack.mitre.org/techniques/T1685/002/" in rep_html
    assert "https://attack.mitre.org/techniques/T1685/006/" in rep_html
    assert "https://attack.mitre.org/techniques/T1685/007/" in rep_html

    oscal = json.loads((out_dir / "oscal-draft.json").read_text(encoding="utf-8"))
    assert len(oscal["assessment-results"]["results"][0]["observations"]) == 7

    for tid in (
        "WIN-T1685-001-EDR-MINIFILTER",
        "WIN-T1685-002-CLOUD-LOG",
        "WIN-T1685-003-ETW-SYSCALL",
        "WIN-T1685-004-FIREWALL-WFP",
        "WIN-T1685-005-USN-EVTX",
        "WIN-T1685-006-VBS-VTL1-BCD",
        "WIN-T1685-007-SAFEBOOT-BCD",
    ):
        slug = TEST_SPECS[tid]["slug"]
        rec_path = out_dir / f"receipt-{slug}.json"
        assert rec_path.exists()
        assert verify(json.loads(rec_path.read_text(encoding="utf-8")), pub)[0]


def test_dsse_security_guards_duplicate_keys_floats_domain_sep_nonce_and_prose_decoupling(tmp_path):
    priv = tmp_path / "k.pem"
    pub = init_keys(priv)

    # 1. Duplicate JSON key rejected
    with pytest.raises(ValueError, match="Duplicate JSON key"):
        parse_json_strict('{"verdict": "PASS", "verdict": "FAIL"}')
    assert not verify('{"payloadType":"application/vnd.verimetry.receipt.v1+json","payloadType":"dup","payload":"e30=","signatures":[]}', pub)[0]

    # 2. Floats strictly forbidden in signed receipts
    obs_float = internals_observation("WIN-ETW-INTEGRITY", "PASS")
    obs_float["bad_float"] = 20.0
    with pytest.raises(ValueError, match="Floating-point value forbidden"):
        make_receipt("HostA", obs_float, "synthetic", test_id="WIN-ETW-INTEGRITY")

    # 3. Host fingerprint binding + challenge nonce freshness
    fp = compute_host_fingerprint("11111111-2222-3333-4444-555555555555", "SMBIOS-UUID-9999")
    assert fp and len(fp) == 64
    rec = make_receipt(
        "HostA",
        internals_observation("WIN-LSA-SSP-AUDIT", "FAIL"),
        "live-host",
        test_id="WIN-LSA-SSP-AUDIT",
        host_fingerprint_sha256=fp,
        challenge_nonce="nonce-abc-123456",
    )
    assert rec["schema"] == "urn:verimetry:schema:receipt:v1"
    assert rec["reason_codes"] == ["LSA_SACL_MISSING"]
    signed = sign(rec, priv)
    assert verify(signed, pub, expected_nonce="nonce-abc-123456")[0]
    ok_bad_nonce, msg_bad_nonce = verify(signed, pub, expected_nonce="wrong-nonce")
    assert not ok_bad_nonce and "NONCE_MISMATCH" in msg_bad_nonce

    # 4. DSSE PAE domain separation prevents cross-payloadType replay
    replayed = copy.deepcopy(signed)
    replayed["payloadType"] = DSSE_COMPARE_PAYLOAD_TYPE
    assert not verify(replayed, pub)[0]

    # 5. Prose decoupling: reworded rationale passes validate_receipt if verdict & reason_codes match;
    # unknown rule_version fails closed with UNKNOWN_RULE_VERSION.
    rec_reworded = copy.deepcopy(rec)
    rec_reworded["rationale"] = "Localized or edited display prose for auditors."
    assert validate_receipt(rec_reworded)[0]

    rec_unknown_ver = copy.deepcopy(rec)
    rec_unknown_ver["test"]["rule_version"] = "lsa-ssp-audit-v99"
    ok_ver, msg_ver = validate_receipt(rec_unknown_ver)
    assert not ok_ver and "UNKNOWN_RULE_VERSION" in msg_ver


def test_t1685_enterprise_fleet_edge_cases():
    # 1. T1685.003: Commercial EDR signed inline hook on ntdll!NtTraceEvent + live canary arrives -> PASS with informational code
    obs_edr_hook = internals_observation("WIN-T1685-003-ETW-SYSCALL", "PASS")
    obs_edr_hook["ntdll_etw_stub_state"] = "signed_inline_hook"
    v, codes, _ = decide_detailed(obs_edr_hook, "WIN-T1685-003-ETW-SYSCALL")
    assert v == "PASS" and "ETW_STUB_SIGNED_HOOK_OBSERVED" in codes

    # Signed hook that blocks canary -> FAIL
    obs_edr_block = copy.deepcopy(obs_edr_hook)
    obs_edr_block["benign_test_event_recorded"] = False
    v, codes, _ = decide_detailed(obs_edr_block, "WIN-T1685-003-ETW-SYSCALL")
    assert v == "FAIL" and "ETW_SIGNED_HOOK_BLOCKED_CANARY" in codes

    # Unverifiable signature on hook target -> INCONCLUSIVE
    obs_edr_unverif = copy.deepcopy(obs_edr_hook)
    obs_edr_unverif["ntdll_etw_stub_state"] = "signed_hook_unverifiable"
    v, codes, _ = decide_detailed(obs_edr_unverif, "WIN-T1685-003-ETW-SYSCALL")
    assert v == "INCONCLUSIVE" and "ETW_HOOK_SIGNATURE_UNVERIFIABLE" in codes

    # Unbacked RWX hook -> FAIL
    obs_unbacked = copy.deepcopy(obs_edr_hook)
    obs_unbacked["ntdll_etw_stub_state"] = "unbacked_or_unsigned_hook"
    v, codes, _ = decide_detailed(obs_unbacked, "WIN-T1685-003-ETW-SYSCALL")
    assert v == "FAIL" and "ETW_STUB_UNBACKED_HOOK" in codes

    # 2. T1685.001: Third-party EDR minifilter in FSFilter band -> PASS; strict baseline without spec -> INCONCLUSIVE
    obs_band = internals_observation("WIN-T1685-001-EDR-MINIFILTER", "PASS")
    v, codes, _ = decide_detailed(obs_band, "WIN-T1685-001-EDR-MINIFILTER")
    assert v == "PASS" and "EDR_MINIFILTER_BAND_VERIFIED" in codes
    obs_strict = copy.deepcopy(obs_band)
    obs_strict["strict_baseline_required"] = True
    v, codes, _ = decide_detailed(obs_strict, "WIN-T1685-001-EDR-MINIFILTER")
    assert v == "INCONCLUSIVE" and "UNSPECIFIED_EDR_BASELINE" in codes

    # 3. T1685.004: Third-party host firewall/SASE disables Windows Firewall -> INCONCLUSIVE unless mandated; WFP block -> FAIL
    obs_fw = internals_observation("WIN-T1685-004-FIREWALL-WFP", "PASS")
    obs_fw["windows_firewall_mandated"] = False
    obs_fw["all_firewall_profiles_enabled"] = False
    obs_fw["firewall_logging_enabled"] = False
    v, codes, _ = decide_detailed(obs_fw, "WIN-T1685-004-FIREWALL-WFP")
    assert v == "INCONCLUSIVE" and "THIRD_PARTY_FIREWALL_POSSIBLE" in codes
    obs_fw_drop = copy.deepcopy(obs_fw)
    obs_fw_drop["no_unauthorized_wfp_telemetry_block"] = False
    v, codes, _ = decide_detailed(obs_fw_drop, "WIN-T1685-004-FIREWALL-WFP")
    assert v == "FAIL" and "WFP_TELEMETRY_DROP_DETECTED" in codes

    # 4. T1685.005: USN journal recreated without explicit delete indicator -> INCONCLUSIVE (not false FAIL)
    obs_usn = internals_observation("WIN-T1685-005-USN-EVTX", "PASS")
    obs_usn["usn_journal_id_changed"] = True
    obs_usn["usn_explicit_delete_indicator"] = False
    v, codes, _ = decide_detailed(obs_usn, "WIN-T1685-005-USN-EVTX")
    assert v == "INCONCLUSIVE" and "USN_JOURNAL_RECREATED" in codes

    # 5. T1685.006: Legacy BIOS / Gen1 VM -> INCONCLUSIVE; omitted hypervisorlaunchtype while VTL 1 runs -> PASS
    obs_bios = internals_observation("WIN-T1685-006-VBS-VTL1-BCD", "PASS")
    obs_bios["firmware_type"] = "BIOS"
    v, codes, _ = decide_detailed(obs_bios, "WIN-T1685-006-VBS-VTL1-BCD")
    assert v == "INCONCLUSIVE" and "FIRMWARE_NOT_UEFI" in codes
    obs_omitted = internals_observation("WIN-T1685-006-VBS-VTL1-BCD", "PASS")
    obs_omitted["bcd_hypervisorlaunchtype_value"] = "omitted_default"
    v, codes, _ = decide_detailed(obs_omitted, "WIN-T1685-006-VBS-VTL1-BCD")
    assert v == "PASS" and "BCD_HYPERVISOR_OS_DEFAULT" in codes

    # 6. T1685.002: Air-gapped host & async SIEM lag -> INCONCLUSIVE
    obs_airgap = internals_observation("WIN-T1685-002-CLOUD-LOG", "PASS")
    obs_airgap["forwarder_configured"] = False
    v, codes, _ = decide_detailed(obs_airgap, "WIN-T1685-002-CLOUD-LOG")
    assert v == "INCONCLUSIVE" and "CLOUD_FORWARDER_NOT_CONFIGURED" in codes
    obs_async = internals_observation("WIN-T1685-002-CLOUD-LOG", "PASS")
    obs_async["ingestion_mode"] = "async_pending"
    v, codes, _ = decide_detailed(obs_async, "WIN-T1685-002-CLOUD-LOG")
    assert v == "INCONCLUSIVE" and "ASYNC_INGESTION_PENDING" in codes


def test_locale_independent_audit_bitmask_and_non_english_csv(monkeypatch):
    # Direct Advapi32 bitmask decoder
    assert windows.decode_audit_bitmask(0x1)[0] == "enabled"
    assert windows.decode_audit_bitmask(0x3)[0] == "enabled"
    assert windows.decode_audit_bitmask(0x0)[0] == "disabled"
    assert windows.decode_audit_bitmask(0x2)[0] == "disabled"
    assert windows.decode_audit_bitmask(0x4)[0] == "disabled"

    # German Windows CSV fallback with localized headers ("Einstellungswert" instead of "Setting Value")
    german_csv = (
        "Computername,Richtlinienziel,Unterkategorie,Unterkategorie-GUID,Einschlusseinstellung,Ausschlusseinstellung,Einstellungswert\n"
        "DE-HOST,System,Prozesserstellung,{0cce922b-69ae-11d9-bed3-505054503030},Erfolgreich,,1\n"
    )
    monkeypatch.setattr(windows, "_query_audit_subcategory_win32", lambda guid, label="": None)
    monkeypatch.setattr(windows, "_run", lambda *a, **k: SimpleNamespace(returncode=0, stdout=german_csv, stderr=""))
    assert windows.read_audit_subcategory(windows.PROCESS_CREATION_GUID)[0] == "enabled"


def test_golden_test_vectors_directory():
    """Verify all cross-language DSSE v1 golden conformance vectors in test_vectors/."""
    tv_dir = Path(__file__).resolve().parent.parent / "test_vectors"
    pub = tv_dir / "test-signer.pub.pem"
    assert pub.exists(), "Missing test_vectors/test-signer.pub.pem"

    # Valid vectors (with nonce + payloadType assertions)
    ok_r, msg_r = verify(
        (tv_dir / "valid_receipt_v1.dsse.json").read_text(encoding="utf-8"),
        pub,
        expected_nonce="verimetry-vector-nonce-2026-01",
        expected_payload_type=DSSE_RECEIPT_PAYLOAD_TYPE,
    )
    assert ok_r, msg_r

    ok_c, msg_c = verify(
        (tv_dir / "valid_compare_v1.dsse.json").read_text(encoding="utf-8"),
        pub,
        expected_nonce="verimetry-compare-nonce-2026-01",
        expected_payload_type=DSSE_COMPARE_PAYLOAD_TYPE,
    )
    assert ok_c, msg_c

    # Wrong nonce must reject valid vector
    ok_bad_nonce, msg_bn = verify(
        (tv_dir / "valid_receipt_v1.dsse.json").read_text(encoding="utf-8"),
        pub,
        expected_nonce="wrong-nonce",
    )
    assert not ok_bad_nonce and "NONCE_MISMATCH" in msg_bn

    # Intentionally broken vectors MUST fail with their expected failure classes
    expected_failures = [
        ("invalid_duplicate_key.dsse.json", "Duplicate JSON key"),
        ("invalid_float_payload.dsse.json", "FLOAT_FORBIDDEN"),
        ("invalid_mismatched_reason_codes.dsse.json", "VERDICT_MISMATCH"),
        ("invalid_unknown_rule_version.dsse.json", "UNKNOWN_RULE_VERSION"),
        ("invalid_wrong_payload_type.dsse.json", "PAYLOAD_TYPE_MISMATCH"),
        ("invalid_tampered_sig.dsse.json", "InvalidSignature"),
    ]
    for fname, expected_substr in expected_failures:
        ok, msg = verify((tv_dir / fname).read_text(encoding="utf-8"), pub)
        assert not ok, f"Expected {fname} to fail verification, but it passed!"
        assert expected_substr in msg, f"{fname}: expected {expected_substr!r} in {msg!r}"


def test_piece1_review_hardening_crashes_multisig_ntfs_acl_junk_uuid_and_nonce(tmp_path, monkeypatch):
    """Regression coverage for all Piece 1 DSSE verifier & parser review findings."""
    import hashlib
    from cryptography.hazmat.primitives import serialization
    from verimetry import receipts as receipts_mod

    priv = tmp_path / "p1.pem"
    pub = init_keys(priv)
    priv_obj = serialization.load_pem_private_key(priv.read_bytes(), password=None)
    pub_obj = serialization.load_pem_public_key(pub.read_bytes())
    fp = hashlib.sha256(pub_obj.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).hexdigest()

    def _raw_dsse(raw_bytes: bytes, pt: str = DSSE_RECEIPT_PAYLOAD_TYPE) -> dict:
        sig = priv_obj.sign(receipts_mod.dsse_pae(pt, raw_bytes))
        return {
            "payloadType": pt,
            "payload": base64.b64encode(raw_bytes).decode("ascii"),
            "signatures": [{"keyid": fp, "sig": base64.b64encode(sig).decode("ascii")}],
        }

    # 1. Crafted non-dict payloads must return (False, ...) cleanly without crashing with AttributeError
    crafted_payloads = [
        b"[]",
        b'"hello"',
        b'{"test": ["x"], "target": {}}',
        b'{"test": {"id": "WIN-LSA-SSP-AUDIT"}, "target": ["x"]}',
        b'{"schema": "urn:verimetry:schema:receipt:v1", "test": {"id": "WIN-LSA-SSP-AUDIT", "rule_version": "lsa-ssp-audit-v1"}, "target": {}, "observation": null, "verdict": "FAIL", "reason_codes": []}',
        b'{"schema": "urn:verimetry:schema:receipt:v1", "test": {"id": "WIN-LSA-SSP-AUDIT", "rule_version": "lsa-ssp-audit-v1"}, "target": {}, "observation": ["x"], "verdict": "FAIL", "reason_codes": []}',
    ]
    for raw in crafted_payloads:
        ok, msg = verify(_raw_dsse(raw), pub)
        assert not ok, f"Crafted payload {raw!r} unexpectedly passed: {msg}"

    # 2. DSSE multi-signature: prepended bogus sig with matching keyid must NOT DoS a valid subsequent signature
    good_rec = make_receipt("HOST-P1", internals_observation("WIN-LSA-SSP-AUDIT", "FAIL"), "test", test_id="WIN-LSA-SSP-AUDIT")
    signed = sign(good_rec, priv)
    real_sig = signed["signatures"][0]
    signed["signatures"] = [
        {"keyid": fp, "sig": base64.b64encode(b"\x00" * 64).decode("ascii")},
        real_sig,
    ]
    ok_multi, msg_multi = verify(signed, pub)
    assert ok_multi, f"Multi-sig fallback failed: {msg_multi}"

    # 3. DSSE v1 optional keyid hint (empty string "" or omitted) should still verify when sig is valid
    signed_empty_kid = copy.deepcopy(signed)
    signed_empty_kid["signatures"] = [{"keyid": "", "sig": real_sig["sig"]}]
    assert verify(signed_empty_kid, pub)[0]

    # 4. Empty or whitespace expected_nonce must raise ValueError loudly
    with pytest.raises(ValueError, match="expected_nonce"):
        verify(signed, pub, expected_nonce="")
    with pytest.raises(ValueError, match="expected_nonce"):
        verify(signed, pub, expected_nonce="   ")

    # 5. Junk SMBIOS sentinel UUIDs must be treated as empty (prevent cross-VM fingerprint collision)
    assert compute_host_fingerprint(None, "00000000-0000-0000-0000-000000000000") is None
    assert compute_host_fingerprint("", "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF") is None
    assert compute_host_fingerprint(None, "03000200-0400-0500-0006-000700080009") is None
    fp_only_mg = compute_host_fingerprint("11111111-2222-4333-8444-555555555555", None)
    fp_junk_smbios = compute_host_fingerprint("11111111-2222-4333-8444-555555555555", "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF")
    assert fp_only_mg == fp_junk_smbios and fp_only_mg is not None

    # 6. Windows NTFS ACL hardening helper invokes locale-independent SID icacls lockdown
    calls = []
    def _fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[0] == "whoami":
            return SimpleNamespace(returncode=0, stdout='"CONTOSO\\alice","S-1-5-21-100-200-300-1001"\n', stderr="")
        return SimpleNamespace(returncode=0, stdout="processed file", stderr="")
    monkeypatch.setattr(receipts_mod.subprocess, "run", _fake_run)
    receipts_mod._harden_windows_private_key_acl(priv)
    assert any(c[0] == "icacls" and "/inheritance:r" in c and "*S-1-5-21-100-200-300-1001:(R,W)" in c and "*S-1-5-18:(F)" in c for c in calls)


def test_piece2_review_hardening_t1685_and_win32_null_guard():
    """Regression coverage for all Piece 2 T1685 verdict gate review findings."""
    # 1. T1685-004: missing/None firewall fields must NEVER silently PASS (mandated or unmandated)
    for mandated in (False, True):
        obs_missing_fw = internals_observation("WIN-T1685-004-FIREWALL-WFP", "PASS")
        obs_missing_fw["windows_firewall_mandated"] = mandated
        obs_missing_fw["all_firewall_profiles_enabled"] = None
        v, codes, _ = decide_detailed(obs_missing_fw, "WIN-T1685-004-FIREWALL-WFP")
        assert v == "INCONCLUSIVE" and "OBSERVATION_INCOMPLETE" in codes

    # Active WFP drop must still hard-FAIL even if firewall profile fields are omitted
    obs_drop_missing_fw = internals_observation("WIN-T1685-004-FIREWALL-WFP", "PASS")
    obs_drop_missing_fw["no_unauthorized_wfp_telemetry_block"] = False
    obs_drop_missing_fw["all_firewall_profiles_enabled"] = None
    v, codes, _ = decide_detailed(obs_drop_missing_fw, "WIN-T1685-004-FIREWALL-WFP")
    assert v == "FAIL" and "WFP_TELEMETRY_DROP_DETECTED" in codes

    # 2. T1685-006: vtl1_running=False with omitted_default must NOT falsely emit BCD_HYPERVISOR_STAGED_OFF
    obs_vtl_off_omitted = internals_observation("WIN-T1685-006-VBS-VTL1-BCD", "PASS")
    obs_vtl_off_omitted["vtl1_running"] = False
    obs_vtl_off_omitted["bcd_hypervisorlaunchtype_value"] = "omitted_default"
    v, codes, _ = decide_detailed(obs_vtl_off_omitted, "WIN-T1685-006-VBS-VTL1-BCD")
    assert v == "FAIL" and "VTL1_NOT_RUNNING" in codes
    assert "BCD_HYPERVISOR_STAGED_OFF" not in codes

    # 3. Stringified "false" on optional bool flags must fail closed to INCONCLUSIVE instead of bool("false") == True
    obs_001_str = internals_observation("WIN-T1685-001-EDR-MINIFILTER", "PASS")
    obs_001_str["strict_baseline_required"] = "false"
    v, codes, _ = decide_detailed(obs_001_str, "WIN-T1685-001-EDR-MINIFILTER")
    assert v == "INCONCLUSIVE" and "OBSERVATION_INCOMPLETE" in codes

    obs_004_str = internals_observation("WIN-T1685-004-FIREWALL-WFP", "PASS")
    obs_004_str["windows_firewall_mandated"] = "false"
    v, codes, _ = decide_detailed(obs_004_str, "WIN-T1685-004-FIREWALL-WFP")
    assert v == "INCONCLUSIVE" and "OBSERVATION_INCOMPLETE" in codes

    obs_005_str = internals_observation("WIN-T1685-005-USN-EVTX", "PASS")
    obs_005_str["usn_journal_id_changed"] = "false"
    v, codes, _ = decide_detailed(obs_005_str, "WIN-T1685-005-USN-EVTX")
    assert v == "INCONCLUSIVE" and "OBSERVATION_INCOMPLETE" in codes

    # 4. T1685-005: lowercase "ntfs" must normalize cleanly to PASS
    obs_005_lower = internals_observation("WIN-T1685-005-USN-EVTX", "PASS")
    obs_005_lower["filesystem_type"] = "ntfs"
    v, codes, _ = decide_detailed(obs_005_lower, "WIN-T1685-005-USN-EVTX")
    assert v == "PASS" and "USN_AND_EVTX_CONTINUITY_VERIFIED" in codes


def test_gui_headless_import_and_privilege_helpers(monkeypatch, capsys):
    """GUI module must import cleanly without tkinter and detect privilege / UAC safely."""
    import subprocess
    import sys
    from verimetry import gui

    # 1. Simulate Python runtime missing tkinter entirely via isolated subprocess import blocker
    blocker = (
        "import sys\n"
        "class _BlockTk:\n"
        "    def find_spec(self, name, path, target=None):\n"
        "        if name == 'tkinter' or name.startswith('tkinter.'):\n"
        "            raise ModuleNotFoundError('No module named tkinter')\n"
        "sys.meta_path.insert(0, _BlockTk())\n"
        "import verimetry.gui as g\n"
        "assert g.is_tkinter_available() is False\n"
        "assert g.launch_gui() == 1\n"
    )
    proc = subprocess.run([sys.executable, "-c", blocker], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, f"Headless import check failed: {proc.stderr}"
    assert "tkinter" in proc.stderr.lower()

    # 2. Headless launch_gui() when _TK_AVAILABLE is False returns exit code 1 cleanly
    monkeypatch.setattr(gui, "_TK_AVAILABLE", False)
    assert gui.launch_gui() == 1
    assert "tkinter" in capsys.readouterr().err.lower()

    # 3. Privilege context detection (Demo Mode, Standard User, Administrator)
    monkeypatch.setattr(gui.platform, "system", lambda: "Linux")
    ctx_demo = gui.get_privilege_context()
    assert ctx_demo["mode"] == "demo" and not ctx_demo["is_windows"]

    monkeypatch.setattr(gui.platform, "system", lambda: "Windows")
    fake_windll = SimpleNamespace(shell32=SimpleNamespace(IsUserAnAdmin=lambda: 0))
    monkeypatch.setattr(gui.ctypes, "windll", fake_windll, raising=False)
    ctx_std = gui.get_privilege_context()
    assert ctx_std["mode"] == "standard" and "Standard User" in ctx_std["badge_text"]

    fake_windll_admin = SimpleNamespace(shell32=SimpleNamespace(IsUserAnAdmin=lambda: 1))
    monkeypatch.setattr(gui.ctypes, "windll", fake_windll_admin, raising=False)
    ctx_adm = gui.get_privilege_context()
    assert ctx_adm["mode"] == "elevated" and "Administrator" in ctx_adm["badge_text"]

    # 4. Windows UAC ShellExecuteW('runas', sys.executable, '-m verimetry gui', None, 1)
    uac_calls = []
    def _fake_shell_exec(hwnd, verb, exe, params, directory, show):
        uac_calls.append((hwnd, verb, exe, params, directory, show))
        return 42

    monkeypatch.setattr(
        gui.ctypes,
        "windll",
        SimpleNamespace(shell32=SimpleNamespace(ShellExecuteW=_fake_shell_exec)),
        raising=False,
    )
    ok_uac, _msg = gui.relaunch_as_admin()
    assert ok_uac
    assert uac_calls == [(None, "runas", sys.executable, "-m verimetry gui", None, 1)]


def test_gui_tamper_trap_flips_payload_byte_and_rejects(tmp_path):
    """Tamper Trap copies receipt to forged.json, flips 1 payload byte, and fails closed REJECTED."""
    from verimetry import gui

    priv = tmp_path / "verimetry-key.pem"
    pub = init_keys(priv)
    receipt = make_receipt("LAB-HOST", internals_observation("WIN-ETW-INTEGRITY", "PASS"), "synthetic", test_id="WIN-ETW-INTEGRITY")
    signed = sign(receipt, priv)
    rec_path = tmp_path / "receipt-etw-integrity.json"
    original_text = json.dumps(signed, indent=2) + "\n"
    rec_path.write_text(original_text, encoding="utf-8")

    # Baseline verify must succeed
    ok_res = gui.run_verify_receipt(rec_path, pub)
    assert ok_res["ok"] and ok_res["status"] == "VERIFIED"

    # Tamper trap flips 1 decoded byte in forged.json and verifies fail-closed REJECTED
    forged_path = tmp_path / "forged.json"
    tamper_res = gui.run_tamper_trap(rec_path, pub, forged_path=forged_path)
    assert forged_path.exists()
    assert rec_path.read_text(encoding="utf-8") == original_text
    assert tamper_res["verified"] is False
    assert tamper_res["status"] == "REJECTED"
    assert "InvalidSignature" in tamper_res["message"]
    assert tamper_res["forged_byte"] == (tamper_res["original_byte"] ^ 0x01)

    orig_bytes = base64.b64decode(signed["payload"], validate=True)
    forged_env = json.loads(forged_path.read_text(encoding="utf-8"))
    forged_bytes = base64.b64decode(forged_env["payload"], validate=True)
    diffs = [i for i, (a, b) in enumerate(zip(orig_bytes, forged_bytes)) if a != b]
    assert diffs == [tamper_res["flipped_byte_offset"]]


def test_gui_issue_summary_strips_hostnames_and_private_keys(monkeypatch):
    """Anonymized Issue #1 summary must format 5 lines and strip hostnames and PEM private keys."""
    from verimetry import gui

    secret_host = "CORP-FINANCE-LAPTOP-99"
    monkeypatch.setattr(gui.platform, "node", lambda: secret_host)
    monkeypatch.setenv("COMPUTERNAME", secret_host)

    baseline = [
        {"test_id": "WIN-KERNEL-PPL-HVCI", "verdict": "PASS", "reason_codes": [], "target_host": secret_host},
        {"test_id": "WIN-ETW-INTEGRITY", "verdict": "INCONCLUSIVE", "reason_codes": ["ETW_QUERY_ACCESS_DENIED"], "target_host": secret_host},
        {"test_id": "WIN-LSA-SSP-AUDIT", "verdict": "INCONCLUSIVE", "reason_codes": ["LSA_SACL_ACCESS_DENIED"], "target_host": secret_host},
    ]
    elevated = [
        {"test_id": "WIN-KERNEL-PPL-HVCI", "verdict": "PASS", "reason_codes": [], "target_host": secret_host},
        {"test_id": "WIN-ETW-INTEGRITY", "verdict": "FAIL", "reason_codes": ["DIAGTRACK_ETW_INACTIVE"], "target_host": secret_host},
        {"test_id": "WIN-LSA-SSP-AUDIT", "verdict": "FAIL", "reason_codes": ["LSA_SACL_MISSING"], "target_host": secret_host},
    ]

    summary = gui.format_issue_summary(
        baseline_checks=baseline,
        elevated_checks=elevated,
        environment="Hyper-V Lab VM",
        edr=f"Defender on {secret_host}",
        os_build_locale="Windows 11 24H2 (Build 26100), `de-DE`",
    )
    lines = summary.splitlines()
    assert len(lines) == 5
    assert "Windows 11 24H2" in summary and "`de-DE`" in summary
    assert "`1` PASS / `0` FAIL / `2` INCONCLUSIVE" in summary
    assert "`1` PASS / `2` FAIL / `0` INCONCLUSIVE" in summary
    assert "WIN-ETW-INTEGRITY" in summary and "DIAGTRACK_ETW_INACTIVE" in summary
    assert secret_host not in summary
    assert secret_host.lower() not in summary.lower()

    # Private key material must never survive sanitization
    leaked = f"Host={secret_host}\n-----BEGIN PRIVATE KEY-----\nSECRET_KEY_BYTES\n-----END PRIVATE KEY-----\n"
    redacted = gui.sanitize_public_text(leaked)
    assert secret_host not in redacted
    assert "SECRET_KEY_BYTES" not in redacted
    assert "[REDACTED-PRIVATE-KEY]" in redacted


def test_gui_step1_step2_different_admin_sid_fallback_and_cleanup(tmp_path, monkeypatch):
    """Step 2 must handle PermissionError on shared verimetry-key.pem gracefully via per-folder keys."""
    from verimetry import gui

    # Keep an unrelated file to verify cleanup never deletes non-Verimetry files
    unrelated = tmp_path / "keep-me.txt"
    unrelated.write_text("do not delete", encoding="utf-8")

    # Step 1 baseline in demo mode
    s1 = gui.run_step1_baseline(tmp_path, live=False)
    assert (tmp_path / "verimetry-key.pem").exists()
    assert (tmp_path / "verimetry-key.pub.pem").exists()
    assert len(s1["checks"]) == 5

    # Simulate different Windows Admin SID hitting PermissionError on standard user's verimetry-key.pem
    shared_priv = (tmp_path / "verimetry-key.pem").resolve()
    orig_read_bytes = Path.read_bytes

    def _deny_shared_priv(self):
        if self.resolve() == shared_priv:
            raise PermissionError("Access is denied (simulated different Windows Admin SID ACL)")
        return orig_read_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", _deny_shared_priv)

    s2 = gui.run_step2_elevated_and_compare(tmp_path, live=False)
    assert s2["used_key_fallback"] is True
    assert "signer.pem" in s2["fallback_note"]
    assert s2["comparison_receipt_path"] and Path(s2["comparison_receipt_path"]).exists()
    assert s2["comparison_report_path"] and Path(s2["comparison_report_path"]).exists()

    # Comparison receipt must verify offline with its fallback public key
    ver = gui.run_verify_receipt(s2["comparison_receipt_path"], s2["comparison_pub_path"])
    assert ver["ok"], ver["message"]

    # Create forged.json and confirm cleanup removes only Verimetry artifacts
    gui.run_tamper_trap(s2["comparison_receipt_path"], s2["comparison_pub_path"], forged_path=tmp_path / "forged.json")
    assert (tmp_path / "forged.json").exists()

    cleaned = gui.cleanup_local_evidence(tmp_path)
    assert not cleaned["errors"]
    assert "evidence" in cleaned["deleted"]
    assert "evidence-elevated" in cleaned["deleted"]
    assert "evidence-comparison" in cleaned["deleted"]
    assert "verimetry-key.pem" in cleaned["deleted"]
    assert "verimetry-key.pub.pem" in cleaned["deleted"]
    assert "forged.json" in cleaned["deleted"]
    assert unrelated.exists() and unrelated.read_text(encoding="utf-8") == "do not delete"






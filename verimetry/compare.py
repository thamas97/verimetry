"""Multi-run cryptographic DSSE receipt comparison and float-free basis-point Bucket 2 MSSP assurance metrics."""
from __future__ import annotations
from datetime import datetime
from pathlib import Path
from .core import TEST_SPECS, ALL_VERIMETRY_CHECK_IDS, make_receipt
from .receipts import extract_receipt, load_json_strict, verify


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts or not isinstance(ts, str):
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def bps_to_pct_str(bps: int) -> str:
    """Format integer basis points (e.g. 5000 -> '50.0%', 3333 -> '33.33%') deterministically without floats."""
    sign = "-" if bps < 0 else ""
    ab = abs(int(bps))
    whole, frac = divmod(ab, 100)
    if frac == 0:
        return f"{sign}{whole}.0%"
    if frac % 10 == 0:
        return f"{sign}{whole}.{frac // 10}%"
    return f"{sign}{whole}.{frac:02d}%"


def _ratio_bps(numerator: int, denominator: int) -> int:
    """Exact rounded integer basis points (0..10000 for 0.00%..100.00%) using pure integer math."""
    if denominator == 0:
        return 0
    sign = -1 if (numerator < 0) ^ (denominator < 0) else 1
    num = abs(numerator) * 10000
    den = abs(denominator)
    return sign * ((num + den // 2) // den)


def _format_duration_ms(elapsed_ms: int | None) -> str:
    if elapsed_ms is None:
        return "n/a"
    sign = "-" if elapsed_ms < 0 else ""
    total = (abs(int(elapsed_ms)) + 500) // 1000
    days, rem = divmod(total, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    if minutes or hours or days:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")
    return sign + " ".join(parts)


def _check_guidance(test_id: str, before_v: str, after_v: str) -> tuple[str, str]:
    """Return deterministic plain-English (customer_impact, mssp_action) for a check transition."""
    transition = f"{before_v} -> {after_v}"

    if after_v == "PASS" and before_v in ("FAIL", "INCONCLUSIVE"):
        impacts = {
            "WIN-ETW-INTEGRITY": "Active user-mode ETW sessions (EventLog-System, DiagTrack-Listener) and live marker delivery are now cryptographically verified.",
            "WIN-KERNEL-PPL-HVCI": "Kernel VBS/HVCI memory integrity, LSA RunAsPPL protection, and CodeIntegrity operational logging are now verified active.",
            "WIN-XPROC-HANDLE": "Cross-process handle telemetry (Event 4656/4663) is now verified for process access attempts.",
            "WIN-LSA-SSP-AUDIT": "LSA SSP registry auditing (Audit Registry policy + HKLM\\...\\Lsa SACL) is now verified active against credential-theft persistence.",
            "WIN-CMDLINE-WMI": "Event 4688 process creation command-line capture and WMI-Activity/Operational readability are now verified active.",
        }
        return (
            impacts.get(test_id, "Telemetry and control assurance check transitioned to a verified PASS state."),
            "Retain signed comparison receipt as baseline proof and monitor for future drift.",
        )

    if before_v == "PASS" and after_v == "PASS":
        return (
            "Control and telemetry pipeline remained verified (PASS) across both runs with zero drift.",
            "No remediation required; continue scheduled drift verification.",
        )

    if before_v == "PASS" and after_v == "FAIL":
        return (
            "CRITICAL DRIFT: Previously verified telemetry or control protection regressed to a confirmed FAIL state, creating a live detection blind spot.",
            "Open a P1 telemetry-drift incident immediately; inspect recent GPO/Intune changes, service stops, or host tampering.",
        )

    if before_v == "PASS" and after_v == "INCONCLUSIVE":
        return (
            "VISIBILITY REGRESSION: Previously verified PASS check became unmeasurable (INCONCLUSIVE), indicating lost collector privileges or log accessibility.",
            "Verify runner elevation (Administrator / SeSecurityPrivilege) and Event Log service health; re-run assessment.",
        )

    if before_v == "INCONCLUSIVE" and after_v == "FAIL":
        specific_fail = {
            "WIN-ETW-INTEGRITY": "Elevated collection replaced an unmeasurable blind spot with a confirmed finding: DiagTrack-Listener ETW session is inactive or the benign marker was not observed.",
            "WIN-KERNEL-PPL-HVCI": "Elevated collection revealed a confirmed kernel/LSA hardening gap (VBS, HVCI, LSA RunAsPPL, or CodeIntegrity log disabled).",
            "WIN-XPROC-HANDLE": "Elevated collection confirmed that Kernel Object / Handle Manipulation auditing is enabled in policy, but no Event 4656/4663 was emitted for cross-process handle access.",
            "WIN-LSA-SSP-AUDIT": "Elevated collection unlocked SeSecurityPrivilege and confirmed a real audit gap: Registry Object Access auditing is disabled and/or HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa has no SACL audit rules.",
            "WIN-CMDLINE-WMI": "Elevated collection confirmed that Process Creation Event 4688 or command-line capture (ProcessCreationIncludeCmdLine_Enabled) or WMI-Activity logging is missing.",
        }
        specific_action = {
            "WIN-ETW-INTEGRITY": "Enable/start the DiagTrack (Connected User Experiences and Telemetry) service & DiagTrack-Listener ETW session (or document an intentional privacy exception) and verify Application log delivery.",
            "WIN-KERNEL-PPL-HVCI": "Enable Memory Integrity (HVCI), Virtualization-Based Security (VBS), and HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL=1 via GPO/Intune.",
            "WIN-XPROC-HANDLE": "Configure process SACLs or Sysmon Event ID 10 (ProcessAccess) to capture cross-process handle operations.",
            "WIN-LSA-SSP-AUDIT": "Enable 'Audit Registry' (Success) via GPO/Intune and attach a write-audit SACL (SetValue/CreateSubKey) on HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa.",
            "WIN-CMDLINE-WMI": "Enable 'Include command line in process creation events' (ProcessCreationIncludeCmdLine_Enabled=1) and ensure Microsoft-Windows-WMI-Activity/Operational is enabled.",
        }
        return (
            specific_fail.get(test_id, "Elevated visibility converted an unmeasurable INCONCLUSIVE check into a confirmed FAIL telemetry gap."),
            specific_action.get(test_id, "Apply baseline audit/hardening policy via GPO/Intune and re-run verimetry assess to verify PASS."),
        )

    if before_v == "INCONCLUSIVE" and after_v == "INCONCLUSIVE":
        specific_inc = {
            "WIN-CMDLINE-WMI": "Check remains INCONCLUSIVE because 'Audit Process Creation' is not enabled in Windows audit policy—Event 4688 command-line telemetry cannot be tested until the policy gate is enabled.",
            "WIN-XPROC-HANDLE": "Check remains INCONCLUSIVE because 'Audit Handle Manipulation' / 'Audit Kernel Object' is not enabled in Windows audit policy—Event 4656/4663 handle telemetry cannot be tested until the policy gate is enabled.",
            "WIN-ETW-INTEGRITY": "Check remains INCONCLUSIVE because active ETW sessions could not be enumerated (requires elevated Administrator session).",
            "WIN-LSA-SSP-AUDIT": "Check remains INCONCLUSIVE because the LSA registry SACL or Audit Registry policy could not be read (requires Administrator / SeSecurityPrivilege).",
            "WIN-KERNEL-PPL-HVCI": "Check remains INCONCLUSIVE because Win32_DeviceGuard, LSA registry, or CodeIntegrity log could not be read.",
        }
        specific_inc_action = {
            "WIN-CMDLINE-WMI": "Enable 'Audit Process Creation' (Success) (`auditpol /set /subcategory:\"{0cce922b-69ae-11d9-bed3-505054503030}\" /success:enable`) plus command-line logging (`ProcessCreationIncludeCmdLine_Enabled=1`).",
            "WIN-XPROC-HANDLE": "Enable 'Audit Kernel Object' / 'Audit Handle Manipulation' (`auditpol /set /subcategory:\"{0cce921f-69ae-11d9-bed3-505054503030}\" /success:enable`) or deploy Sysmon Event ID 10.",
            "WIN-ETW-INTEGRITY": "Re-run `verimetry assess` from an elevated Administrator PowerShell session.",
            "WIN-LSA-SSP-AUDIT": "Re-run `verimetry assess` from an elevated Administrator PowerShell session with SeSecurityPrivilege.",
            "WIN-KERNEL-PPL-HVCI": "Re-run `verimetry assess` with WMI and registry read permissions.",
        }
        return (
            specific_inc.get(test_id, "Telemetry prerequisite or collector privilege remains unconfigured/unavailable (INCONCLUSIVE)."),
            specific_inc_action.get(test_id, "Enable the prerequisite Windows audit policy subcategory or run elevated, then re-assess."),
        )

    if before_v == "FAIL" and after_v == "FAIL":
        return (
            "Confirmed telemetry or control gap (FAIL) persists across both assessment runs.",
            "Deploy the required GPO/Intune hardening or audit policy remediation and re-run verimetry assess.",
        )

    if before_v == "FAIL" and after_v == "INCONCLUSIVE":
        return (
            "Previously confirmed FAIL check became unmeasurable (INCONCLUSIVE) due to reduced collector privileges or disabled policy visibility.",
            "Restore elevated collection or audit policy visibility so remediation can be cryptographically verified.",
        )

    return (
        f"Check transitioned {transition}.",
        "Review receipt observations and re-assess after policy update.",
    )


def _classify_transition(before_v: str, after_v: str) -> str:
    if after_v == "PASS" and before_v in ("FAIL", "INCONCLUSIVE"):
        return "hardened_to_pass"
    if before_v == "PASS" and after_v == "PASS":
        return "sustained_pass"
    if before_v == "PASS" and after_v in ("FAIL", "INCONCLUSIVE"):
        return "regression"
    if before_v == "INCONCLUSIVE" and after_v == "FAIL":
        return "visibility_unlocked_gap_exposed"
    if before_v == "FAIL" and after_v == "INCONCLUSIVE":
        return "visibility_lost"
    if before_v == "FAIL" and after_v == "FAIL":
        return "persistent_fail"
    return "persistent_inconclusive"


def load_and_verify_dir(
    directory: str | Path,
    trusted_public: str | Path | None = None,
    allow_dir_public_fallback: bool = False,
) -> tuple[dict[str, dict], Path]:
    """Load and cryptographically verify every DSSE receipt-*.json in directory."""
    d = Path(directory)
    if not d.exists() or not d.is_dir():
        raise ValueError(f"Evidence directory does not exist: {d}")

    files = sorted(
        p for p in d.glob("receipt-*.json")
        if p.name != "comparison-receipt.json"
    )
    if not files:
        raise ValueError(f"No receipt-*.json files found in {d}")

    dir_pub = d / "signer.pub.pem"
    primary_pub = Path(trusted_public) if trusted_public is not None else dir_pub
    if not primary_pub.exists():
        if allow_dir_public_fallback and dir_pub.exists():
            primary_pub = dir_pub
        else:
            raise ValueError(f"Trusted public key not found for {d}: {primary_pub}")

    verified_by_test: dict[str, dict] = {}
    used_pub = primary_pub
    for fpath in files:
        try:
            package = load_json_strict(fpath)
        except Exception as exc:
            raise ValueError(f"Malformed or duplicate-key JSON in {fpath}: {exc}") from exc

        ok, why = verify(package, primary_pub)
        if (
            not ok
            and allow_dir_public_fallback
            and why == "Trusted public key fingerprint mismatch"
            and dir_pub.exists()
            and dir_pub.resolve() != primary_pub.resolve()
        ):
            ok_fb, why_fb = verify(package, dir_pub)
            if ok_fb:
                ok, why = ok_fb, why_fb
                used_pub = dir_pub

        if not ok:
            raise ValueError(f"Receipt verification failed for {fpath}: {why}")

        rec, payload_sha, keyid, _pt = extract_receipt(package)
        test_id = (rec.get("test") or {}).get("id")
        if not test_id:
            raise ValueError(f"Receipt missing test.id in {fpath}")
        if test_id == "WIN-ASSURANCE-COMPARE":
            continue
        verified_by_test[test_id] = {
            "file": fpath.name,
            "package": package,
            "receipt": rec,
            "payload_sha256": payload_sha,
            "signer_keyid": keyid,
            "public_key_used": str(used_pub),
        }

    if not verified_by_test:
        raise ValueError(f"No verifiable check receipts found in {d}")
    return verified_by_test, used_pub


def compare_runs(
    before_verified: dict[str, dict],
    after_verified: dict[str, dict],
    before_dir: str = "before",
    after_dir: str = "after",
) -> dict:
    """Compute paired check transitions and float-free integer basis-point Bucket 2 MSSP assurance metrics."""
    common_ids = [tid for tid in ALL_VERIMETRY_CHECK_IDS if tid in before_verified and tid in after_verified]
    extra_ids = sorted(
        tid for tid in (set(before_verified.keys()) & set(after_verified.keys()))
        if tid not in common_ids
    )
    ordered_ids = common_ids + extra_ids
    if not ordered_ids:
        raise ValueError("No matching test IDs found between --before and --after directories")

    before_only = sorted(set(before_verified.keys()) - set(after_verified.keys()))
    after_only = sorted(set(after_verified.keys()) - set(before_verified.keys()))

    transitions = []
    before_counts = {"PASS": 0, "FAIL": 0, "INCONCLUSIVE": 0}
    after_counts = {"PASS": 0, "FAIL": 0, "INCONCLUSIVE": 0}
    before_timestamps: list[datetime] = []
    after_timestamps: list[datetime] = []
    hosts: list[str] = []
    before_fps: set[str] = set()
    after_fps: set[str] = set()

    hardening_candidates = 0
    hardened_to_pass = 0
    visibility_unlocked = 0
    regressions: list[str] = []
    visibility_lost: list[str] = []

    for tid in ordered_ids:
        b_entry = before_verified[tid]
        a_entry = after_verified[tid]
        b_rec = b_entry["receipt"]
        a_rec = a_entry["receipt"]

        b_v = b_rec["verdict"]
        a_v = a_rec["verdict"]
        before_counts[b_v] = before_counts.get(b_v, 0) + 1
        after_counts[a_v] = after_counts.get(a_v, 0) + 1

        if b_v in ("FAIL", "INCONCLUSIVE"):
            hardening_candidates += 1
            if a_v == "PASS":
                hardened_to_pass += 1
        if b_v == "INCONCLUSIVE" and a_v in ("PASS", "FAIL"):
            visibility_unlocked += 1
        if b_v == "PASS" and a_v in ("FAIL", "INCONCLUSIVE"):
            regressions.append(tid)
        if b_v == "FAIL" and a_v == "INCONCLUSIVE":
            visibility_lost.append(tid)

        b_ts = _parse_iso(b_rec.get("created_at"))
        a_ts = _parse_iso(a_rec.get("created_at"))
        if b_ts is not None:
            before_timestamps.append(b_ts)
        if a_ts is not None:
            after_timestamps.append(a_ts)

        b_target = b_rec.get("target") or {}
        a_target = a_rec.get("target") or {}
        if b_target.get("host_fingerprint_sha256"):
            before_fps.add(b_target["host_fingerprint_sha256"])
        if a_target.get("host_fingerprint_sha256"):
            after_fps.add(a_target["host_fingerprint_sha256"])

        host = a_target.get("host") or b_target.get("host")
        if host and host not in hosts:
            hosts.append(host)

        spec = TEST_SPECS.get(tid, {})
        title = (a_rec.get("test") or {}).get("title") or spec.get("title") or tid
        mitre = (a_rec.get("test") or {}).get("mitre_attack") or spec.get("mitre_attack") or ""
        impact, action = _check_guidance(tid, b_v, a_v)

        transitions.append({
            "test_id": tid,
            "slug": spec.get("slug", tid.lower()),
            "title": title,
            "mitre_attack": mitre,
            "host": host or "unknown",
            "before_verdict": b_v,
            "after_verdict": a_v,
            "before_reason_codes": b_rec.get("reason_codes") or [],
            "after_reason_codes": a_rec.get("reason_codes") or [],
            "transition": f"{b_v} -> {a_v}",
            "transition_class": _classify_transition(b_v, a_v),
            "before_rationale": b_rec.get("rationale", ""),
            "after_rationale": a_rec.get("rationale", ""),
            "before_created_at": b_rec.get("created_at"),
            "after_created_at": a_rec.get("created_at"),
            "before_receipt_id": b_rec.get("receipt_id"),
            "after_receipt_id": a_rec.get("receipt_id"),
            "before_sha256": b_entry["payload_sha256"],
            "after_sha256": a_entry["payload_sha256"],
            "before_signer_fingerprint": b_entry["signer_keyid"],
            "after_signer_fingerprint": a_entry["signer_keyid"],
            "customer_impact": impact,
            "mssp_action": action,
        })

    total = len(ordered_ids)
    before_cov_bps = _ratio_bps(before_counts["PASS"], total) if total else 0
    after_cov_bps = _ratio_bps(after_counts["PASS"], total) if total else 0
    cov_delta_bps = after_cov_bps - before_cov_bps

    b_inc = before_counts["INCONCLUSIVE"]
    a_inc = after_counts["INCONCLUSIVE"]
    if b_inc > 0:
        inc_burndown_bps = _ratio_bps(b_inc - a_inc, b_inc)
    else:
        inc_burndown_bps = 10000 if a_inc == 0 else -10000

    if hardening_candidates > 0:
        hardening_rate_bps = _ratio_bps(hardened_to_pass, hardening_candidates)
    else:
        hardening_rate_bps = 10000 if after_counts["PASS"] == total else 0

    if b_inc > 0:
        visibility_unlock_bps = _ratio_bps(visibility_unlocked, b_inc)
    else:
        visibility_unlock_bps = 10000

    earliest_before = min(before_timestamps) if before_timestamps else None
    latest_after = max(after_timestamps) if after_timestamps else None
    elapsed_ms = (
        int(round((latest_after - earliest_before).total_seconds() * 1000))
        if earliest_before is not None and latest_after is not None
        else None
    )
    elapsed_seconds = (elapsed_ms // 1000) if elapsed_ms is not None else None

    host_fp_consistent = None
    if before_fps and after_fps:
        host_fp_consistent = (before_fps == after_fps) and len(before_fps) == 1

    metrics = {
        "total_checks": total,
        "before_pass_count": before_counts["PASS"],
        "before_fail_count": before_counts["FAIL"],
        "before_inconclusive_count": b_inc,
        "after_pass_count": after_counts["PASS"],
        "after_fail_count": after_counts["FAIL"],
        "after_inconclusive_count": a_inc,
        "before_coverage_bps": before_cov_bps,
        "after_coverage_bps": after_cov_bps,
        "coverage_delta_bps": cov_delta_bps,
        "before_coverage_pct_str": bps_to_pct_str(before_cov_bps),
        "after_coverage_pct_str": bps_to_pct_str(after_cov_bps),
        "coverage_delta_pct_str": ("+" if cov_delta_bps > 0 else "") + bps_to_pct_str(cov_delta_bps),
        "inconclusive_burndown_count": b_inc - a_inc,
        "inconclusive_burndown_bps": inc_burndown_bps,
        "inconclusive_burndown_pct_str": bps_to_pct_str(inc_burndown_bps),
        "hardening_candidates_count": hardening_candidates,
        "hardened_to_pass_count": hardened_to_pass,
        "hardening_verification_bps": hardening_rate_bps,
        "hardening_verification_pct_str": bps_to_pct_str(hardening_rate_bps),
        "visibility_unlocked_count": visibility_unlocked,
        "visibility_unlock_bps": visibility_unlock_bps,
        "visibility_unlock_pct_str": bps_to_pct_str(visibility_unlock_bps),
        "regression_count": len(regressions),
        "regressions": regressions,
        "drift_detected": len(regressions) > 0,
        "visibility_lost_count": len(visibility_lost),
        "visibility_lost": visibility_lost,
        "host_fingerprint_consistent": host_fp_consistent,
        "before_timestamp": earliest_before.isoformat() if earliest_before else None,
        "after_timestamp": latest_after.isoformat() if latest_after else None,
        "elapsed_ms": elapsed_ms,
        "elapsed_seconds": elapsed_seconds,
        "elapsed_human": _format_duration_ms(elapsed_ms),
    }

    return {
        "mode": "assurance-comparison",
        "inputs_verified": True,
        "before_directory": str(before_dir),
        "after_directory": str(after_dir),
        "hosts": hosts,
        "unpaired_before_checks": before_only,
        "unpaired_after_checks": after_only,
        "metrics": metrics,
        "transitions": transitions,
        "scope_note": "Cryptographically verified point-in-time delta between two Verimetry DSSE evidence runs (integer basis-point metrics; zero floats)",
    }


def build_comparison_receipt(
    before_dir: str | Path,
    after_dir: str | Path,
    trusted_public: str | Path | None = None,
    before_public: str | Path | None = None,
    after_public: str | Path | None = None,
    allow_dir_public_fallback: bool = False,
    challenge_nonce: str | None = None,
) -> dict:
    """Verify both directories and construct an unsigned WIN-ASSURANCE-COMPARE receipt."""
    b_pub_arg = before_public if before_public is not None else trusted_public
    a_pub_arg = after_public if after_public is not None else trusted_public

    before_map, b_used_pub = load_and_verify_dir(
        before_dir,
        trusted_public=b_pub_arg,
        allow_dir_public_fallback=(allow_dir_public_fallback and before_public is None),
    )
    after_map, a_used_pub = load_and_verify_dir(
        after_dir,
        trusted_public=a_pub_arg,
        allow_dir_public_fallback=(allow_dir_public_fallback and after_public is None),
    )
    observation = compare_runs(
        before_map,
        after_map,
        before_dir=str(before_dir),
        after_dir=str(after_dir),
    )
    observation["before_trusted_public_key"] = str(b_used_pub)
    observation["after_trusted_public_key"] = str(a_used_pub)
    hosts = observation.get("hosts") or ["Multi-Host"]
    host_label = ", ".join(hosts)

    # Carry forward host fingerprint if all compared receipts share the exact same host fingerprint
    fps = {
        (entry["receipt"].get("target") or {}).get("host_fingerprint_sha256")
        for entry in list(before_map.values()) + list(after_map.values())
    } - {None}
    common_fp = next(iter(fps)) if len(fps) == 1 else None

    return make_receipt(
        host_label,
        observation,
        scenario="comparison",
        test_id="WIN-ASSURANCE-COMPARE",
        host_fingerprint_sha256=common_fp,
        challenge_nonce=challenge_nonce,
    )

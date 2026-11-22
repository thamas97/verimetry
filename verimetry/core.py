"""Deterministic three-valued evidence gates and portable DSSE-ready evidence; zero model-based verdicts."""
from __future__ import annotations
import hashlib
import json
from datetime import datetime, timezone
from uuid import uuid4

RULE_VERSION = "process-4688-v1"
RECEIPT_SCHEMA_URN = "urn:verimetry:schema:receipt:v1"
DSSE_RECEIPT_PAYLOAD_TYPE = "application/vnd.verimetry.receipt.v1+json"
DSSE_COMPARE_PAYLOAD_TYPE = "application/vnd.verimetry.compare.v1+json"

TEST_SPECS = {
    "WIN-4688-CANARY": {
        "slug": "windows",
        "rule_version": RULE_VERSION,
        "title": "Process Creation Telemetry Canary",
        "mitre_attack": "T1059",
        "objective": "Verify process creation telemetry for one harmless child process",
        "control_reference": "NIST SP 800-53 Rev.5 AU-12 (illustrative mapping; not a full control assessment)",
        "oscal_controls": ["au-12"],
    },
    "WIN-ETW-INTEGRITY": {
        "slug": "etw-integrity",
        "rule_version": "etw-integrity-v1",
        "title": "ETW Provider Integrity & User-Mode Visibility",
        "mitre_attack": "T1562.006",
        "objective": "Verify active user-mode ETW sessions (EventLog-System, DiagTrack-Listener) and benign marker pipeline delivery",
        "control_reference": "NIST SP 800-53 Rev.5 AU-9 / AU-12 (illustrative mapping; not a full control assessment)",
        "oscal_controls": ["au-9", "au-12"],
    },
    "WIN-KERNEL-PPL-HVCI": {
        "slug": "kernel-ppl-hvci",
        "rule_version": "kernel-ppl-hvci-v1",
        "title": "Kernel Driver Load & PPL / HVCI Audit Readiness",
        "mitre_attack": "T1068 / T1562.001",
        "objective": "Verify Win32_DeviceGuard VBS/HVCI state, LSA RunAsPPL registry setting, and CodeIntegrity/Operational log readability",
        "control_reference": "NIST SP 800-53 Rev.5 SI-7 / AU-12 (illustrative mapping; not a full control assessment)",
        "oscal_controls": ["si-7", "au-12"],
    },
    "WIN-XPROC-HANDLE": {
        "slug": "xproc-handle",
        "rule_version": "xproc-handle-v1",
        "title": "Cross-Process Memory / Thread Telemetry Coverage",
        "mitre_attack": "T1106 / T1055",
        "objective": "Open a read-only PROCESS_QUERY_LIMITED_INFORMATION handle to a benign child process and check cross-process audit telemetry",
        "control_reference": "NIST SP 800-53 Rev.5 AU-12 / SI-4 (illustrative mapping; not a full control assessment)",
        "oscal_controls": ["au-12", "si-4"],
    },
    "WIN-LSA-SSP-AUDIT": {
        "slug": "lsa-ssp-audit",
        "rule_version": "lsa-ssp-audit-v1",
        "title": "LSA Security Support Provider (SSP) Registry Audit Policy",
        "mitre_attack": "T1547.005",
        "objective": "Inspect HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa (Security Packages, RunAsPPL), SACLs, and Registry Object Access audit policy",
        "control_reference": "NIST SP 800-53 Rev.5 AU-2 / AC-6 (illustrative mapping; not a full control assessment)",
        "oscal_controls": ["au-2", "ac-6"],
    },
    "WIN-CMDLINE-WMI": {
        "slug": "cmdline-wmi",
        "rule_version": "cmdline-wmi-v1",
        "title": "Process Creation Command-Line & WMI-Activity Log Readability",
        "mitre_attack": "T1047",
        "objective": "Verify Event 4688 command-line auditing for a benign ping process and WMI-Activity/Operational log readability",
        "control_reference": "NIST SP 800-53 Rev.5 AU-12 / AU-3 (illustrative mapping; not a full control assessment)",
        "oscal_controls": ["au-12", "au-3"],
    },
    "WIN-ASSURANCE-COMPARE": {
        "slug": "comparison",
        "rule_version": "assurance-compare-v1",
        "title": "Multi-Run Telemetry & Control Assurance Delta Comparison",
        "mitre_attack": "T1685 / T1562 / T1068 / T1055 / T1547 / T1047",
        "objective": "Cryptographically verify two assessment runs and compute telemetry coverage, INCONCLUSIVE burn-down, hardening verification, and drift metrics",
        "control_reference": "NIST SP 800-53 Rev.5 CA-7 / AU-12 (continuous monitoring & telemetry assurance delta)",
        "oscal_controls": ["ca-7", "au-12"],
    },
    "WIN-T1685-001-EDR-MINIFILTER": {
        "slug": "t1685-001-edr-minifilter",
        "rule_version": "t1685-001-edr-minifilter-v2",
        "title": "Scenario 1: Endpoint Security Service & Driver Tampering",
        "mitre_attack": "T1685.001 / T1562.001",
        "objective": "Query SCM service DACLs and FSFilter Anti-Virus (320000-329999) / Activity Monitor (360000-389999) minifilter altitudes via read-only Windows APIs",
        "control_reference": "NIST SP 800-53 Rev.5 SI-7 / AU-9 / AC-6 (endpoint service & minifilter driver tamper resistance)",
        "oscal_controls": ["si-7", "au-9", "ac-6"],
        "consolidated_parent_check": "WIN-KERNEL-PPL-HVCI",
    },
    "WIN-T1685-002-CLOUD-LOG": {
        "slug": "t1685-002-cloud-log",
        "rule_version": "t1685-002-cloud-log-v2",
        "title": "Scenario 2: Cloud & Hybrid Audit Log Pipeline Blindness",
        "mitre_attack": "T1685.002 / T1562.008",
        "objective": "Verify synchronous local cloud-log forwarder health, sink config hashes, audit-bypass flags, and synchronous or asynchronous downstream sink ingestion",
        "control_reference": "NIST SP 800-53 Rev.5 AU-4 / AU-6 / AU-9 / SI-4 (cloud & hybrid audit log pipeline assurance)",
        "oscal_controls": ["au-4", "au-6", "au-9", "si-4"],
        "consolidated_parent_check": "WIN-ETW-INTEGRITY",
    },
    "WIN-T1685-003-ETW-SYSCALL": {
        "slug": "t1685-003-etw-syscall",
        "rule_version": "t1685-003-etw-syscall-v2",
        "title": "Scenario 3: Windows Event Log & ETW Session Blinding",
        "mitre_attack": "T1685.003 / T1562.006 / T1562.003",
        "objective": "Classify ntdll!NtTraceEvent/EtwEventWrite stubs (clean vs. signed EDR inline hook vs. blinding 0xC3/unbacked patch), autologgers, and live auditpol delivery",
        "control_reference": "NIST SP 800-53 Rev.5 AU-9 / AU-12 / SI-7 (ntdll ETW stub & auditpol session integrity)",
        "oscal_controls": ["au-9", "au-12", "si-7"],
        "consolidated_parent_check": "WIN-ETW-INTEGRITY",
    },
    "WIN-T1685-004-FIREWALL-WFP": {
        "slug": "t1685-004-firewall-wfp",
        "rule_version": "t1685-004-firewall-wfp-v2",
        "title": "Scenario 4: Host Firewall & Network Telemetry Filtering",
        "mitre_attack": "T1685.004 / T1562.004",
        "objective": "Verify absence of unauthorized outbound WFP drop filters targeting telemetry endpoints and collector TLS egress, cleanly decoupled from third-party firewall profiles",
        "control_reference": "NIST SP 800-53 Rev.5 SC-7 / AU-12 / SI-4 (host firewall & WFP telemetry egress assurance)",
        "oscal_controls": ["sc-7", "au-12", "si-4"],
        "consolidated_parent_check": "WIN-CMDLINE-WMI",
    },
    "WIN-T1685-005-USN-EVTX": {
        "slug": "t1685-005-usn-evtx",
        "rule_version": "t1685-005-usn-evtx-v2",
        "title": "Scenario 5: Indicators on Host Removal & USN Journal Truncation",
        "mitre_attack": "T1685.005 / T1070.001",
        "objective": "Verify NTFS USN Change Journal liveness (FirstUsn <= NextUsn), in-range EVTX record continuity without penalizing circular rollover, and windowed Event 1102/104 clears",
        "control_reference": "NIST SP 800-53 Rev.5 AU-9 / AU-11 / SI-12 (NTFS USN journal & EVTX sequence continuity)",
        "oscal_controls": ["au-9", "au-11", "si-12"],
        "consolidated_parent_check": "WIN-LSA-SSP-AUDIT",
    },
    "WIN-T1685-006-VBS-VTL1-BCD": {
        "slug": "t1685-006-vbs-vtl1-bcd",
        "rule_version": "t1685-006-vbs-vtl1-bcd-v2",
        "title": "Scenario 6: Boot Configuration & VBS / VTL 1 Downgrade",
        "mitre_attack": "T1685.006 / T1562.001 / T1068",
        "objective": "Compare live Win32_DeviceGuard VTL 1 state against staged BCD hypervisorlaunchtype (treating explicit Off as drift while tolerating OS default omission) and UEFI Secure Boot",
        "control_reference": "NIST SP 800-53 Rev.5 SI-7 / CM-6 / SC-39 (VTL 0/1 boundary & BCD boot integrity)",
        "oscal_controls": ["si-7", "cm-6", "sc-39"],
        "consolidated_parent_check": "WIN-KERNEL-PPL-HVCI",
    },
    "WIN-T1685-007-SAFEBOOT-BCD": {
        "slug": "t1685-007-safeboot-bcd",
        "rule_version": "t1685-007-safeboot-bcd-v2",
        "title": "Scenario 7: Safe Mode & Recovery Environment Boot Tampering",
        "mitre_attack": "T1685.007 / T1562.009",
        "objective": "Inspect active BCD {current} elements for staged BcdOSLoaderBoolean_SafeBoot (0x25000080) flags and verify active EDR SafeBoot registry registrations",
        "control_reference": "NIST SP 800-53 Rev.5 CM-7 / SI-7 / AC-3 (Safe Mode boot-evasion & BCD staging detection)",
        "oscal_controls": ["cm-7", "si-7", "ac-3"],
        "consolidated_parent_check": "WIN-KERNEL-PPL-HVCI",
    },
}

WINDOWS_INTERNALS_CHECK_IDS = (
    "WIN-ETW-INTEGRITY",
    "WIN-KERNEL-PPL-HVCI",
    "WIN-XPROC-HANDLE",
    "WIN-LSA-SSP-AUDIT",
    "WIN-CMDLINE-WMI",
)

T1685_ASSURANCE_CHECK_IDS = (
    "WIN-T1685-001-EDR-MINIFILTER",
    "WIN-T1685-002-CLOUD-LOG",
    "WIN-T1685-003-ETW-SYSCALL",
    "WIN-T1685-004-FIREWALL-WFP",
    "WIN-T1685-005-USN-EVTX",
    "WIN-T1685-006-VBS-VTL1-BCD",
    "WIN-T1685-007-SAFEBOOT-BCD",
)

ALL_VERIMETRY_CHECK_IDS = WINDOWS_INTERNALS_CHECK_IDS + T1685_ASSURANCE_CHECK_IDS


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def assert_no_floats(value, path="$"):
    """Reject floating-point numbers anywhere in a receipt payload to eliminate cross-runtime float divergence."""
    if isinstance(value, float):
        raise ValueError(f"FLOAT_FORBIDDEN: Floating-point value forbidden in signed receipt schema at {path}: {value!r}")
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise ValueError(f"Non-string JSON key at {path}: {k!r}")
            assert_no_floats(v, f"{path}.{k}")
    elif isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            assert_no_floats(item, f"{path}[{i}]")


_JUNK_SMBIOS_UUIDS = frozenset({
    "00000000-0000-0000-0000-000000000000",
    "ffffffff-ffff-ffff-ffff-ffffffffffff",
    "03000200-0400-0500-0006-000700080009",
})


def compute_host_fingerprint(machine_guid: str | None, smbios_uuid: str | None, tpm_ek_sha256: str | None = None) -> str | None:
    """Compute privacy-preserving host binding hash: SHA-256('verimetry-host-v1:' + MachineGuid + ':' + SMBIOS_UUID)."""
    mg = (machine_guid or "").strip().lower()
    su = (smbios_uuid or "").strip().lower()
    if su in _JUNK_SMBIOS_UUIDS:
        su = ""
    if mg in _JUNK_SMBIOS_UUIDS:
        mg = ""
    if not mg and not su:
        return None
    parts = ["verimetry-host-v1", mg, su]
    if tpm_ek_sha256:
        parts.append(str(tpm_ek_sha256).strip().lower())
    return hashlib.sha256(":".join(parts).encode("utf-8")).hexdigest()


def canonical_bytes(value):
    assert_no_floats(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def sha256(value):
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _res(verdict: str, codes: list[str], rationale: str) -> tuple[str, list[str], str]:
    return verdict, sorted(set(codes)), rationale


def _decide_4688(observation):
    if not observation.get("canary_completed", False):
        return _res("INCONCLUSIVE", ["CANARY_INCOMPLETE"], "Canary did not complete; telemetry cannot be assessed.")
    if observation.get("query_status") != "ok":
        return _res("INCONCLUSIVE", ["SECURITY_LOG_UNREADABLE"], "Security log could not be read completely.")
    if observation.get("query_truncated"):
        return _res("INCONCLUSIVE", ["EVENT_QUERY_TRUNCATED"], "Event query was truncated.")
    if observation.get("audit_policy") != "enabled":
        return _res("INCONCLUSIVE", ["AUDIT_PROCESS_CREATION_NOT_ENABLED"], "Process Creation audit policy could not be verified as enabled.")
    if observation.get("matching_event") is True:
        return _res("PASS", ["EVENT_4688_OBSERVED"], "Matching Event 4688 was observed for the launched process PID.")
    if observation.get("matching_event") is False:
        return _res("FAIL", ["EVENT_4688_MISSING"], "No matching Event 4688 found in the bounded observation window.")
    return _res("INCONCLUSIVE", ["CORRELATION_RESULT_MISSING"], "Event correlation result missing.")


def _decide_etw_integrity(observation):
    if observation.get("etw_query_status") != "ok":
        return _res("INCONCLUSIVE", ["ETW_SESSIONS_UNREADABLE"], "Active ETW trace sessions could not be queried completely.")
    if not observation.get("marker_emitted", False):
        return _res("INCONCLUSIVE", ["ETW_MARKER_NOT_EMITTED"], "Benign ETW/EventLog marker event could not be emitted.")
    if observation.get("log_query_status") != "ok":
        return _res("INCONCLUSIVE", ["APPLICATION_LOG_UNREADABLE"], "Application event log could not be read completely.")
    if observation.get("query_truncated"):
        return _res("INCONCLUSIVE", ["EVENT_QUERY_TRUNCATED"], "Event query was truncated.")
    sessions = observation.get("etw_sessions")
    if not isinstance(sessions, dict):
        return _res("INCONCLUSIVE", ["ETW_SESSION_DATA_MISSING"], "ETW session observation missing.")
    evlog = sessions.get("EventLog-System")
    diag = sessions.get("DiagTrack-Listener")
    marker_obs = observation.get("marker_observed")
    if not isinstance(evlog, bool) or not isinstance(diag, bool) or not isinstance(marker_obs, bool):
        return _res("INCONCLUSIVE", ["CORRELATION_RESULT_MISSING"], "ETW session or marker correlation result missing.")
    if evlog and diag and marker_obs:
        return _res("PASS", ["ETW_SESSIONS_AND_MARKER_VERIFIED"], "Active ETW sessions (EventLog-System, DiagTrack-Listener) confirmed and benign marker event observed.")
    gaps, codes = [], []
    if not evlog:
        gaps.append("EventLog-System session inactive")
        codes.append("ETW_EVENTLOG_SYSTEM_INACTIVE")
    if not diag:
        gaps.append("DiagTrack-Listener session inactive")
        codes.append("ETW_DIAGTRACK_INACTIVE")
    if not marker_obs:
        gaps.append("benign marker event not observed in pipeline")
        codes.append("ETW_MARKER_NOT_OBSERVED")
    return _res("FAIL", codes, "ETW visibility gaps observed: " + "; ".join(gaps) + ".")


def _decide_kernel_ppl_hvci(observation):
    if observation.get("device_guard_status") != "ok":
        return _res("INCONCLUSIVE", ["DEVICE_GUARD_UNREADABLE"], "Win32_DeviceGuard WMI state could not be queried.")
    if observation.get("lsa_registry_status") != "ok":
        return _res("INCONCLUSIVE", ["LSA_REGISTRY_UNREADABLE"], "LSA RunAsPPL registry state could not be read.")
    if observation.get("ci_log_query_status") != "ok":
        return _res("INCONCLUSIVE", ["CODE_INTEGRITY_LOG_UNREADABLE"], "CodeIntegrity/Operational event log could not be inspected.")
    vbs = observation.get("vbs_running")
    hvci = observation.get("hvci_running")
    ppl = observation.get("run_as_ppl_enabled")
    ci_enabled = observation.get("ci_log_enabled")
    ci_readable = observation.get("ci_log_readable")
    flags = (vbs, hvci, ppl, ci_enabled, ci_readable)
    if any(not isinstance(x, bool) for x in flags):
        return _res("INCONCLUSIVE", ["OBSERVATION_INCOMPLETE"], "Kernel/PPL/HVCI readiness observation incomplete.")
    if all(flags):
        return _res("PASS", ["KERNEL_VBS_HVCI_PPL_VERIFIED"], "VBS and HVCI are running, LSA RunAsPPL is enabled, and CodeIntegrity/Operational log is enabled and readable.")
    gaps, codes = [], []
    if not vbs:
        gaps.append("VBS not running")
        codes.append("VBS_NOT_RUNNING")
    if not hvci:
        gaps.append("HVCI not running")
        codes.append("HVCI_NOT_RUNNING")
    if not ppl:
        gaps.append("LSA RunAsPPL not enabled")
        codes.append("LSA_RUNASPPL_DISABLED")
    if not ci_enabled:
        gaps.append("CodeIntegrity/Operational log disabled")
        codes.append("CODE_INTEGRITY_LOG_DISABLED")
    if not ci_readable:
        gaps.append("CodeIntegrity/Operational log not readable")
        codes.append("CODE_INTEGRITY_LOG_INACCESSIBLE")
    return _res("FAIL", codes, "Kernel/PPL/HVCI audit readiness gaps observed: " + "; ".join(gaps) + ".")


def _decide_xproc_handle(observation):
    if not observation.get("canary_completed", False):
        return _res("INCONCLUSIVE", ["CANARY_INCOMPLETE"], "Benign child process canary did not complete.")
    if not observation.get("handle_opened", False):
        return _res("INCONCLUSIVE", ["OPEN_PROCESS_FAILED"], "Read-only OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) handle could not be acquired.")
    if observation.get("query_status") != "ok":
        return _res("INCONCLUSIVE", ["SECURITY_LOG_UNREADABLE"], "Security log could not be read completely.")
    if observation.get("query_truncated"):
        return _res("INCONCLUSIVE", ["EVENT_QUERY_TRUNCATED"], "Event query was truncated.")
    if observation.get("handle_audit_policy") != "enabled":
        return _res("INCONCLUSIVE", ["AUDIT_HANDLE_POLICY_NOT_ENABLED"], "Kernel Object / Handle Manipulation audit policy could not be verified as enabled.")
    matched = observation.get("handle_event_matched")
    if matched is True:
        return _res("PASS", ["XPROC_HANDLE_EVENT_OBSERVED"], "Cross-process read-only handle telemetry (Event 4656/4663) was observed for the canary process.")
    if matched is False:
        return _res("FAIL", ["XPROC_HANDLE_EVENT_MISSING"], "No cross-process handle telemetry (Event 4656/4663) was observed in the bounded window.")
    return _res("INCONCLUSIVE", ["CORRELATION_RESULT_MISSING"], "Cross-process handle correlation result missing.")


def _decide_lsa_ssp_audit(observation):
    if observation.get("registry_query_status") != "ok":
        return _res("INCONCLUSIVE", ["LSA_REGISTRY_UNREADABLE"], "LSA registry key could not be read.")
    if observation.get("sacl_query_status") != "ok":
        return _res("INCONCLUSIVE", ["LSA_SACL_UNREADABLE_SE_SECURITY"], "LSA registry SACL could not be inspected (requires SeSecurityPrivilege).")
    reg_policy = observation.get("audit_registry_policy")
    if reg_policy not in ("enabled", "disabled"):
        return _res("INCONCLUSIVE", ["AUDIT_REGISTRY_POLICY_UNKNOWN"], "Registry Object Access audit policy could not be verified.")
    sacl_present = observation.get("sacl_present")
    if not isinstance(sacl_present, bool):
        return _res("INCONCLUSIVE", ["OBSERVATION_INCOMPLETE"], "LSA SACL inspection result missing.")
    if reg_policy == "enabled" and sacl_present:
        return _res("PASS", ["LSA_SSP_AUDIT_VERIFIED"], "Registry Object Access audit policy is enabled and LSA registry key has active SACL audit rules.")
    gaps, codes = [], []
    if reg_policy != "enabled":
        gaps.append("Registry Object Access audit policy is disabled")
        codes.append("AUDIT_REGISTRY_DISABLED")
    if not sacl_present:
        gaps.append("LSA registry key has no SACL audit rules")
        codes.append("LSA_SACL_MISSING")
    return _res("FAIL", codes, "LSA SSP audit policy gaps observed: " + "; ".join(gaps) + ".")


def _decide_cmdline_wmi(observation):
    if not observation.get("canary_completed", False):
        return _res("INCONCLUSIVE", ["CANARY_INCOMPLETE"], "Command-line canary process did not complete.")
    if not observation.get("wmi_query_completed", False):
        return _res("INCONCLUSIVE", ["WMI_PROBE_INCOMPLETE"], "Read-only WMI query did not complete.")
    if observation.get("security_query_status") != "ok":
        return _res("INCONCLUSIVE", ["SECURITY_LOG_UNREADABLE"], "Security log could not be read completely.")
    if observation.get("wmi_log_query_status") != "ok":
        return _res("INCONCLUSIVE", ["WMI_LOG_UNREADABLE"], "WMI-Activity/Operational log could not be read completely.")
    if observation.get("security_truncated") or observation.get("wmi_log_truncated"):
        return _res("INCONCLUSIVE", ["EVENT_QUERY_TRUNCATED"], "Event query was truncated.")
    if observation.get("audit_policy") != "enabled":
        return _res("INCONCLUSIVE", ["AUDIT_PROCESS_CREATION_NOT_ENABLED"], "Process Creation audit policy could not be verified as enabled.")
    matched = observation.get("matching_event")
    cmdline = observation.get("cmdline_matched")
    wmi_enabled = observation.get("wmi_log_enabled")
    wmi_readable = observation.get("wmi_log_readable")
    flags = (matched, cmdline, wmi_enabled, wmi_readable)
    if any(not isinstance(x, bool) for x in flags):
        return _res("INCONCLUSIVE", ["CORRELATION_RESULT_MISSING"], "Event 4688 or WMI-Activity correlation result missing.")
    if all(flags):
        return _res("PASS", ["CMDLINE_4688_AND_WMI_VERIFIED"], "Event 4688 with VERIMETRY_CANARY_PING command line observed and WMI-Activity/Operational log is enabled and readable.")
    gaps, codes = [], []
    if not matched:
        gaps.append("matching Event 4688 not found")
        codes.append("EVENT_4688_MISSING")
    elif not cmdline:
        gaps.append("Event 4688 missing VERIMETRY_CANARY_PING command line")
        codes.append("EVENT_4688_CMDLINE_MISSING")
    if not wmi_enabled:
        gaps.append("WMI-Activity/Operational log disabled")
        codes.append("WMI_ACTIVITY_LOG_DISABLED")
    if not wmi_readable:
        gaps.append("WMI-Activity/Operational log not readable")
        codes.append("WMI_ACTIVITY_LOG_INACCESSIBLE")
    return _res("FAIL", codes, "Command-line / WMI telemetry gaps observed: " + "; ".join(gaps) + ".")


def _opt_bool(observation: dict, key: str, default: bool = False) -> tuple[bool, bool]:
    """Read an optional boolean field strictly without coercing strings like 'false' to True."""
    val = observation.get(key)
    if val is None:
        return True, default
    if isinstance(val, bool):
        return True, val
    return False, False


def _decide_t1685_001_edr_minifilter(observation):
    """Hardened T1685.001 gate: supports tenant baseline OR dynamic AV/Activity-Monitor altitude band scan (320000-329999 / 360000-389999)."""
    if observation.get("scm_query_status") != "ok":
        return _res("INCONCLUSIVE", ["SCM_QUERY_ACCESS_DENIED"], "Service Control Manager (OpenSCManagerW) DACLs could not be queried (ERROR_ACCESS_DENIED or missing SeDebugPrivilege).")
    if observation.get("fltmc_query_status") != "ok":
        return _res("INCONCLUSIVE", ["FLTMC_QUERY_ACCESS_DENIED"], "Minifilter altitude enumeration (FilterFindFirst / fltmc) could not be completed (requires elevated Administrator privilege).")

    baseline_raw = observation.get("expected_edr_baseline")
    if baseline_raw is not None and not isinstance(baseline_raw, str):
        return _res("INCONCLUSIVE", ["OBSERVATION_INCOMPLETE"], "Expected EDR baseline identifier must be a string or null.")
    baseline_specified = isinstance(baseline_raw, str) and bool(baseline_raw.strip())

    ok_strict, strict_pinning = _opt_bool(observation, "strict_baseline_required", False)
    if not ok_strict:
        return _res("INCONCLUSIVE", ["OBSERVATION_INCOMPLETE"], "strict_baseline_required must be a boolean.")
    if strict_pinning and not baseline_specified:
        return _res("INCONCLUSIVE", ["UNSPECIFIED_EDR_BASELINE"], "Strict tenant EDR baseline pinning is required, but no expected_edr_baseline was provided.")

    service_active = observation.get("edr_service_running")
    minifilter_reg = observation.get("minifilter_altitude_registered")
    if minifilter_reg is None:
        minifilter_reg = observation.get("signed_security_minifilter_in_band")
    dacl_protected = observation.get("tamper_dacl_blocks_unauthorized_stop")
    flags = (service_active, minifilter_reg, dacl_protected)
    if any(not isinstance(x, bool) for x in flags):
        return _res("INCONCLUSIVE", ["OBSERVATION_INCOMPLETE"], "Endpoint service or minifilter tamper-protection observation incomplete.")
    if all(flags):
        if not baseline_specified:
            return _res(
                "PASS",
                ["EDR_MINIFILTER_BAND_VERIFIED", "SCM_DACL_PROTECTED"],
                "Signed security minifilter discovered in FSFilter AV/Activity-Monitor altitude band (320000-329999 / 360000-389999), active EDR service running, and SCM DACLs block unauthorized SERVICE_STOP.",
            )
        return _res(
            "PASS",
            ["EDR_BASELINE_VERIFIED", "SCM_DACL_PROTECTED"],
            "Expected EDR service is active, expected minifilter altitude is registered, and SCM DACLs block unauthorized SERVICE_STOP requests.",
        )
    gaps, codes = [], []
    if not service_active:
        gaps.append("active EDR/security service not running")
        codes.append("EDR_SERVICE_NOT_RUNNING")
    if not minifilter_reg:
        gaps.append("no expected/signed security minifilter attached in FSFilter AV or Activity Monitor altitude bands")
        codes.append("EDR_MINIFILTER_MISSING")
    if not dacl_protected:
        gaps.append("SCM DACL permits non-TrustedInstaller/non-PPL SERVICE_STOP modification")
        codes.append("SCM_DACL_PERMISSIVE")
    return _res("FAIL", codes, "Endpoint security service/driver tamper-resistance gaps observed: " + "; ".join(gaps) + ".")


def _decide_t1685_002_cloud_log(observation):
    """Hardened T1685.002 gate: handles air-gapped hosts and async cloud SIEM ingestion lag cleanly."""
    if observation.get("forwarder_configured") is False:
        return _res("INCONCLUSIVE", ["CLOUD_FORWARDER_NOT_CONFIGURED"], "No cloud log forwarder is configured on this host (air-gapped or on-premises endpoint).")
    if observation.get("forwarder_query_status") != "ok":
        return _res("INCONCLUSIVE", ["FORWARDER_QUERY_FAILED"], "Local cloud-log forwarder service/agent state could not be queried.")

    # Synchronous local forwarder integrity checks run first so clear local tampering is caught immediately
    fwd_active = observation.get("forwarder_service_active")
    sink_hash_ok = observation.get("sink_config_hash_matches_baseline")
    no_bypass = observation.get("audit_bypass_clear")
    encryption_ok = observation.get("log_validation_encryption_enabled")
    local_flags = (fwd_active, sink_hash_ok, no_bypass, encryption_ok)
    if any(not isinstance(x, bool) for x in local_flags):
        return _res("INCONCLUSIVE", ["OBSERVATION_INCOMPLETE"], "Local cloud-log forwarder configuration observation incomplete.")

    gaps, codes = [], []
    if not fwd_active:
        gaps.append("local cloud-log forwarder service inactive")
        codes.append("CLOUD_FORWARDER_INACTIVE")
    if not sink_hash_ok:
        gaps.append("forwarder sink URL/SNS topic detached or modified from baseline")
        codes.append("CLOUD_SINK_CONFIG_DRIFT")
    if not no_bypass:
        gaps.append("multi-region or mailbox audit-bypass flag tripped")
        codes.append("CLOUD_AUDIT_BYPASS_ENABLED")
    if not encryption_ok:
        gaps.append("cloud log file validation or encryption disabled (AN0801/AN0803)")
        codes.append("CLOUD_LOG_VALIDATION_DISABLED")

    if gaps:
        return _res("FAIL", codes, "Cloud & hybrid audit log pipeline gaps observed: " + "; ".join(gaps) + ".")

    ingestion_mode = observation.get("ingestion_mode", "sync")
    if ingestion_mode == "async_pending":
        return _res(
            "INCONCLUSIVE",
            ["ASYNC_INGESTION_PENDING", "LOCAL_FORWARDER_VERIFIED"],
            "Local forwarder health and sink configuration verified; asynchronous cloud SIEM ingestion confirmation is pending follow-up run after SLA window.",
        )
    if observation.get("ingestion_verify_status") in ("timeout", "rate_limited", "network_unreachable"):
        return _res("INCONCLUSIVE", ["CLOUD_INGESTION_VERIFY_TIMEOUT"], "Network egress timeout or API rate-limiting prevented confirming downstream cloud log ingestion within the canary window.")
    if observation.get("ingestion_verify_status") != "ok":
        return _res("INCONCLUSIVE", ["CLOUD_INGESTION_VERIFY_UNAVAILABLE"], "Downstream cloud log ingestion acknowledgment could not be verified.")

    ack_received = observation.get("synthetic_heartbeat_acknowledged")
    if not isinstance(ack_received, bool):
        return _res("INCONCLUSIVE", ["CORRELATION_RESULT_MISSING"], "Downstream synthetic heartbeat acknowledgment missing.")
    if ack_received:
        return _res(
            "PASS",
            ["CLOUD_LOG_PIPELINE_VERIFIED"],
            "Local cloud-log forwarder is active, TLS/endpoint sink hashes match baseline, audit-bypass flags are clear, and the synthetic heartbeat registered in the downstream cloud sink within SLA.",
        )
    return _res("FAIL", ["CLOUD_HEARTBEAT_NOT_ACKNOWLEDGED"], "Cloud & hybrid audit log pipeline gaps observed: synthetic telemetry heartbeat missing in downstream SIEM/cloud sink.")


def _decide_t1685_003_etw_syscall(observation):
    """Hardened T1685.003 gate: 3-way ntdll!NtTraceEvent classification (clean vs. signed EDR inline hook vs. blinding/unbacked patch)."""
    if observation.get("ntdll_inspect_status") != "ok":
        return _res("INCONCLUSIVE", ["NTDLL_INSPECT_RESTRICTED"], "In-memory ntdll.dll syscall stub (NtTraceEvent/EtwEventWrite) could not be inspected due to VBS/hypervisor or process memory restrictions.")
    if observation.get("etw_autologger_status") != "ok":
        return _res("INCONCLUSIVE", ["ETW_AUTOLOGGER_UNREADABLE"], "ETW autologger trace sessions (QueryAllTracesW) could not be enumerated.")
    if observation.get("auditpol_status") != "ok":
        return _res("INCONCLUSIVE", ["AUDITPOL_UNREADABLE"], "System audit policy subcategories could not be queried.")

    # Support new 3-way ntdll_etw_stub_state while remaining backwards-compatible with legacy ntdll_etw_stub_unpatched boolean
    stub_state = observation.get("ntdll_etw_stub_state")
    if stub_state is None and isinstance(observation.get("ntdll_etw_stub_unpatched"), bool):
        stub_state = "clean" if observation["ntdll_etw_stub_unpatched"] else "blinded_ret"

    if stub_state in ("signed_hook_unverifiable", "unknown", None):
        return _res("INCONCLUSIVE", ["ETW_HOOK_SIGNATURE_UNVERIFIABLE"], "In-memory ntdll!NtTraceEvent inline hook target module or Authenticode signature could not be verified.")

    autologgers_up = observation.get("core_autologgers_running")
    auditpol_active = observation.get("auditpol_subcategories_enabled")
    test_event_logged = observation.get("benign_test_event_recorded")
    if any(not isinstance(x, bool) for x in (autologgers_up, auditpol_active, test_event_logged)):
        return _res("INCONCLUSIVE", ["OBSERVATION_INCOMPLETE"], "ETW autologger, audit policy, or canary delivery observation incomplete.")

    gaps, codes = [], []
    if stub_state == "blinded_ret":
        gaps.append("in-memory ntdll!EtwEventWrite / NtTraceEvent blinding patch (0xC3 ret / xor eax,eax; ret) detected")
        codes.append("ETW_STUB_BLINDED")
    elif stub_state == "unbacked_or_unsigned_hook":
        gaps.append("in-memory ntdll!NtTraceEvent JMP/CALL redirects into unbacked, RWX, or unsigned memory")
        codes.append("ETW_STUB_UNBACKED_HOOK")
    elif stub_state != "clean" and stub_state != "signed_inline_hook":
        return _res("INCONCLUSIVE", ["ETW_STUB_STATE_UNKNOWN"], f"Unrecognized ntdll stub classification: {stub_state}")

    if not autologgers_up:
        gaps.append("core ETW autologger session stopped or EventLog thread suspended")
        codes.append("ETW_AUTOLOGGER_INACTIVE")
    if not auditpol_active:
        gaps.append("audit policy subcategories cleared / set to No Auditing")
        codes.append("AUDIT_SUBCATEGORIES_CLEARED")
    if not test_event_logged:
        if stub_state == "signed_inline_hook":
            gaps.append("signed inline hook present on ntdll!NtTraceEvent and benign ETW/EventLog canary failed to arrive")
            codes.append("ETW_SIGNED_HOOK_BLOCKED_CANARY")
        else:
            gaps.append("benign test event not recorded in Security/PowerShell operational log")
            codes.append("ETW_CANARY_EVENT_MISSING")

    if gaps:
        return _res("FAIL", codes, "Windows Event Log / ETW session blinding gaps observed: " + "; ".join(gaps) + ".")

    if stub_state == "signed_inline_hook":
        return _res(
            "PASS",
            ["ETW_PIPELINE_VERIFIED", "ETW_STUB_SIGNED_HOOK_OBSERVED"],
            "Authenticode-signed inline EDR hook observed on ntdll!NtTraceEvent; live ETW canary arrived cleanly, core autologgers are running, and audit subcategories are active.",
        )
    return _res(
        "PASS",
        ["ETW_PIPELINE_VERIFIED", "ETW_STUB_CLEAN"],
        "ntdll!NtTraceEvent/EtwEventWrite prologue bytes match clean disk image, core ETW autologger sessions are running, and audit subcategories recorded the benign test event (4688/4104).",
    )


def _decide_t1685_004_firewall_wfp(observation):
    """Hardened T1685.004 gate: decouples WFP telemetry-egress block (hard FAIL) from third-party firewall profiles (INCONCLUSIVE unless mandated)."""
    if observation.get("wfp_query_status") in ("vpn_split_tunnel_obscured", "proxy_obscured"):
        return _res("INCONCLUSIVE", ["WFP_ATTRIBUTION_OBSCURED"], "Split-tunnel VPN or proxy configuration obscures direct WFP filter attribution.")
    if observation.get("wfp_query_status") != "ok" or observation.get("firewall_profile_status") != "ok":
        return _res("INCONCLUSIVE", ["WFP_OR_FIREWALL_UNREADABLE"], "Windows Filtering Platform (FwpmEngineOpen0 / FwpmFilterEnum0) or firewall profiles could not be enumerated.")

    no_wfp_block = observation.get("no_unauthorized_wfp_telemetry_block")
    tls_ok = observation.get("collector_tls_handshake_ok")
    profiles_on = observation.get("all_firewall_profiles_enabled")
    fw_log_on = observation.get("firewall_logging_enabled")
    ok_mandated, wf_mandated = _opt_bool(observation, "windows_firewall_mandated", False)

    if not ok_mandated or any(not isinstance(x, bool) for x in (no_wfp_block, tls_ok)):
        return _res("INCONCLUSIVE", ["OBSERVATION_INCOMPLETE"], "WFP telemetry filter, collector TLS handshake, or mandate flag observation incomplete.")

    # Hard FAIL conditions: active outbound WFP drop targeting telemetry or broken collector TLS
    hard_gaps, hard_codes = [], []
    if not no_wfp_block:
        hard_gaps.append("active outbound WFP drop filter targets EDR/SIEM telemetry IP/port ranges")
        hard_codes.append("WFP_TELEMETRY_DROP_DETECTED")
    if not tls_ok:
        hard_gaps.append("telemetry collector endpoint TLS handshake failed")
        hard_codes.append("COLLECTOR_TLS_HANDSHAKE_FAILED")

    if wf_mandated:
        if profiles_on is False:
            hard_gaps.append("mandated Windows Firewall profile (Domain/Private/Public) disabled")
            hard_codes.append("MANDATED_WINDOWS_FIREWALL_DISABLED")
        if fw_log_on is False:
            hard_gaps.append("mandated Windows Firewall dropped-packet logging (pfirewall.log) disabled")
            hard_codes.append("MANDATED_FIREWALL_LOGGING_DISABLED")

    if hard_gaps:
        return _res("FAIL", hard_codes, "Host firewall / WFP network telemetry filtering gaps observed: " + "; ".join(hard_gaps) + ".")

    if not isinstance(profiles_on, bool) or not isinstance(fw_log_on, bool):
        return _res("INCONCLUSIVE", ["OBSERVATION_INCOMPLETE"], "Windows Firewall profile or dropped-packet logging observation missing or non-boolean.")

    if not wf_mandated and (profiles_on is False or fw_log_on is False):
        return _res(
            "INCONCLUSIVE",
            ["THIRD_PARTY_FIREWALL_POSSIBLE", "WFP_TELEMETRY_EGRESS_CLEAR"],
            "No unauthorized WFP telemetry drop filters were found and collector TLS succeeded, but Windows Firewall profiles/pfirewall.log are off (possible third-party host firewall/SASE control; set windows_firewall_mandated to enforce).",
        )

    return _res(
        "PASS",
        ["WFP_TELEMETRY_EGRESS_CLEAR", "WINDOWS_FIREWALL_VERIFIED"],
        "All three Windows Firewall profiles (Domain, Private, Public) are enabled, no unauthorized outbound WFP drop filters match telemetry ports, firewall logging is enabled, and collector TLS handshake succeeded.",
    )


def _decide_t1685_005_usn_evtx(observation):
    """Hardened T1685.005 gate: tolerates healthy circular rollover, windows 1102/104 clears, and separates USN recreation from confirmed deletion."""
    fs_type = observation.get("filesystem_type")
    if fs_type is not None and (not isinstance(fs_type, str) or fs_type.strip().upper() != "NTFS"):
        return _res("INCONCLUSIVE", ["NON_NTFS_FILESYSTEM"], f"Volume is hosted on a non-NTFS filesystem ({fs_type}) lacking standard USN Change Journal semantics.")
    if observation.get("usn_query_status") != "ok":
        return _res("INCONCLUSIVE", ["USN_JOURNAL_UNREADABLE"], "NTFS volume USN Change Journal metadata (FSCTL_QUERY_USN_JOURNAL) could not be queried (requires Administrator privilege or volume is read-only).")
    if observation.get("evtx_query_status") != "ok":
        return _res("INCONCLUSIVE", ["EVTX_METADATA_UNREADABLE"], "Security/Sysmon .evtx channel metadata could not be queried.")

    # Support both hardened fields and legacy fields with strict boolean checks
    usn_active = observation.get("usn_journal_active", observation.get("usn_journal_continuity_ok"))
    ok_bounds, usn_bounds = _opt_bool(observation, "usn_bounds_valid", True)
    ok_id_chg, usn_id_changed = _opt_bool(observation, "usn_journal_id_changed", False)
    ok_del, usn_explicit_delete = _opt_bool(observation, "usn_explicit_delete_indicator", False)

    evtx_monotonic = observation.get("evtx_in_range_monotonic", observation.get("evtx_sequence_monotonic"))
    ok_reset, evtx_reset_1 = _opt_bool(observation, "evtx_next_record_reset_to_1", False)
    clear_in_window = observation.get("log_clear_1102_104_in_window")
    if clear_in_window is None and isinstance(observation.get("no_log_clear_event_1102_104"), bool):
        clear_in_window = not observation["no_log_clear_event_1102_104"]

    if (
        not all((ok_bounds, ok_id_chg, ok_del, ok_reset))
        or any(not isinstance(x, bool) for x in (usn_active, evtx_monotonic, clear_in_window))
    ):
        return _res("INCONCLUSIVE", ["OBSERVATION_INCOMPLETE"], "USN Change Journal or .evtx sequence continuity observation incomplete.")

    gaps, codes = [], []
    if not usn_active or not usn_bounds:
        gaps.append("NTFS USN Change Journal is inactive or invalid (FirstUsn > NextUsn)")
        codes.append("USN_JOURNAL_INACTIVE_OR_INVALID")
    if usn_id_changed and usn_explicit_delete:
        gaps.append("NTFS UsnJournalID changed alongside explicit fsutil/journal deletion tamper indicator")
        codes.append("USN_JOURNAL_DELETED_TAMPERED")
    if not evtx_monotonic or evtx_reset_1:
        gaps.append(".evtx channel in-range record gap or NextRecordNumber reset to 1 detected")
        codes.append("EVTX_SEQUENCE_BROKEN")
    if clear_in_window:
        gaps.append("Event ID 1102 (Security audit log cleared) or Event ID 104 (System log cleared) observed within active verification window")
        codes.append("EVTX_LOG_CLEARED_IN_WINDOW")

    if gaps:
        return _res("FAIL", codes, "Host indicator removal / USN journal / EVTX truncation gaps observed: " + "; ".join(gaps) + ".")

    if usn_id_changed and not usn_explicit_delete:
        return _res(
            "INCONCLUSIVE",
            ["USN_JOURNAL_RECREATED"],
            "NTFS UsnJournalID changed since prior baseline without an explicit deletion indicator (could be VSS/backup/chkdsk maintenance or tampering; inspect host events).",
        )

    return _res(
        "PASS",
        ["USN_AND_EVTX_CONTINUITY_VERIFIED"],
        "NTFS USN Change Journal is active with valid bounds (FirstUsn <= NextUsn) and Security/Sysmon .evtx channels show monotonic in-range records with zero Event ID 1102/104 clears in window.",
    )


def _decide_t1685_006_vbs_vtl1_bcd(observation):
    """Hardened T1685.006 gate: handles non-UEFI/Gen1 VMs as INCONCLUSIVE and only emits BCD_HYPERVISOR_STAGED_OFF when explicitly 'off'."""
    if observation.get("virtualization_environment") == "nested_vm_no_vtx":
        return _res("INCONCLUSIVE", ["NESTED_VM_NO_VTX"], "Running inside a nested VM without exposed hardware virtualization extensions (VT-x/AMD-V).")
    if observation.get("firmware_type") == "BIOS" or observation.get("secure_boot_status") == "not_supported":
        return _res("INCONCLUSIVE", ["FIRMWARE_NOT_UEFI"], "Host uses legacy BIOS or Gen1 VM firmware without UEFI Secure Boot capability (ERROR_INVALID_FUNCTION).")
    if observation.get("device_guard_status") != "ok":
        return _res("INCONCLUSIVE", ["DEVICE_GUARD_UNREADABLE"], "Live Win32_DeviceGuard WMI state could not be queried.")
    if observation.get("bcd_query_status") != "ok":
        return _res("INCONCLUSIVE", ["BCD_STORE_UNREADABLE"], "Live BCD system store (BcdOpenSystemStore / bcdedit) could not be read (requires Administrator privilege).")

    vtl1_active = observation.get("vtl1_running")
    reg_matches_live = observation.get("registry_matches_running_vtl1_state")
    secure_boot_on = observation.get("uefi_secure_boot_enabled")

    # Support explicit bcd_hypervisorlaunchtype_value ("auto", "omitted_default", "off") AND legacy boolean
    bcd_val = observation.get("bcd_hypervisorlaunchtype_value")
    if bcd_val is None and isinstance(observation.get("bcd_hypervisorlaunchtype_auto"), bool):
        bcd_val = "auto" if observation["bcd_hypervisorlaunchtype_auto"] else "off"

    if any(not isinstance(x, bool) for x in (vtl1_active, reg_matches_live, secure_boot_on)) or bcd_val not in ("auto", "omitted_default", "off"):
        return _res("INCONCLUSIVE", ["OBSERVATION_INCOMPLETE"], "VTL 1 runtime or staged BCD/registry comparison observation incomplete.")

    gaps, codes = [], []
    if not vtl1_active:
        gaps.append("VTL 1 (Virtualization-Based Security / HVCI) is not actively running")
        codes.append("VTL1_NOT_RUNNING")
    if bcd_val == "off":
        gaps.append("staged BCD hypervisorlaunchtype is explicitly set to Off (pending VTL 1 downgrade on next reboot)")
        codes.append("BCD_HYPERVISOR_STAGED_OFF")
    if not reg_matches_live:
        gaps.append("staged DeviceGuard registry keys (EnableVirtualizationBasedSecurity=0) diverge from live VTL 1 state")
        codes.append("DEVICE_GUARD_REGISTRY_REBOOT_DRIFT")
    if not secure_boot_on:
        gaps.append("UEFI Secure Boot is disabled")
        codes.append("UEFI_SECURE_BOOT_DISABLED")

    if gaps:
        return _res("FAIL", codes, "Boot configuration / VBS VTL 1 downgrade gaps observed: " + "; ".join(gaps) + ".")

    pass_codes = ["VTL1_AND_BCD_INTEGRITY_VERIFIED"]
    if bcd_val == "omitted_default":
        pass_codes.append("BCD_HYPERVISOR_OS_DEFAULT")
    return _res(
        "PASS",
        pass_codes,
        "VTL 1 (securekernel.exe / LsaIso.exe) is actively running, BCD hypervisor launch configuration has no Off downgrade staged, UEFI Secure Boot is enabled, and staged registry keys match running state.",
    )


def _decide_t1685_007_safeboot_bcd(observation):
    """Hardened T1685.007 gate: checks active EDR SafeBoot registrations instead of hardcoding Defender."""
    if observation.get("bcd_query_status") in ("bitlocker_locked", "access_denied", "query_error"):
        return _res("INCONCLUSIVE", ["BCD_STORE_UNREADABLE"], "BitLocker recovery state, locked system hive, or insufficient privileges prevented reading the active BCD {current} store.")
    if observation.get("bcd_query_status") != "ok" or observation.get("safeboot_reg_status") != "ok":
        return _res("INCONCLUSIVE", ["SAFEBOOT_STATE_UNREADABLE"], "Active BCD {current} store or SafeBoot registry hive could not be inspected.")
    no_staged_safeboot = observation.get("bcd_safeboot_absent")
    edr_safeboot_reg_ok = observation.get("active_edr_safeboot_keys_intact", observation.get("edr_safeboot_keys_intact"))
    flags = (no_staged_safeboot, edr_safeboot_reg_ok)
    if any(not isinstance(x, bool) for x in flags):
        return _res("INCONCLUSIVE", ["OBSERVATION_INCOMPLETE"], "BCD SafeBoot flag or SafeBoot registry key observation incomplete.")
    if all(flags):
        return _res("PASS", ["BCD_SAFEBOOT_CLEAR", "ACTIVE_EDR_SAFEBOOT_KEYS_INTACT"], "No safeboot flag (0x25000080) is staged in BCD {current}, and active security service keys remain properly registered under HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot.")
    gaps, codes = [], []
    if not no_staged_safeboot:
        gaps.append("staged safeboot flag (minimal/network) detected in BCD {current} while running in normal mode (imminent Safe Mode evasion reboot)")
        codes.append("BCD_SAFEBOOT_STAGED")
    if not edr_safeboot_reg_ok:
        gaps.append("active EDR/security service keys missing or tampered under HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot")
        codes.append("ACTIVE_EDR_SAFEBOOT_KEYS_MISSING")
    return _res("FAIL", codes, "Safe Mode / Recovery boot tampering gaps observed: " + "; ".join(gaps) + ".")


def _decide_assurance_compare(observation):
    if not observation.get("inputs_verified", False):
        return _res("INCONCLUSIVE", ["COMPARE_INPUTS_UNVERIFIED"], "Input receipts could not be cryptographically verified.")
    transitions = observation.get("transitions")
    if not isinstance(transitions, list) or not transitions:
        return _res("INCONCLUSIVE", ["COMPARE_NO_TRANSITIONS"], "No paired check transitions available to compare.")
    metrics = observation.get("metrics")
    if not isinstance(metrics, dict):
        return _res("INCONCLUSIVE", ["COMPARE_METRICS_MISSING"], "Comparison metrics payload missing.")
    total = int(metrics.get("total_checks", len(transitions)) or 0)
    pass_after = int(metrics.get("after_pass_count", 0) or 0)
    fail_after = int(metrics.get("after_fail_count", 0) or 0)
    inc_after = int(metrics.get("after_inconclusive_count", 0) or 0)
    reg_count = int(metrics.get("regression_count", 0) or 0)
    if metrics.get("drift_detected") or reg_count > 0:
        reg_ids = ", ".join(str(x) for x in (metrics.get("regressions") or [])) or f"{reg_count} check(s)"
        return _res("FAIL", ["TELEMETRY_DRIFT_DETECTED"], f"Telemetry drift / regression detected in {reg_count} check(s) ({reg_ids}); post-run state has {pass_after}/{total} PASS, {fail_after} FAIL, {inc_after} INCONCLUSIVE.")
    if fail_after > 0:
        return _res("FAIL", ["POST_COMPARE_GAPS_REMAIN"], f"Post-comparison state has {fail_after} confirmed telemetry/readiness gap(s) ({pass_after}/{total} PASS, {fail_after} FAIL, {inc_after} INCONCLUSIVE; 0 regressions).")
    if inc_after > 0:
        return _res("INCONCLUSIVE", ["POST_COMPARE_INCONCLUSIVE_REMAIN"], f"Zero regressions or confirmed failures, but {inc_after} check(s) remain INCONCLUSIVE ({pass_after}/{total} PASS, 0 FAIL, {inc_after} INCONCLUSIVE).")
    if pass_after == total and total > 0:
        return _res("PASS", ["ALL_COMPARED_CHECKS_PASS"], f"All {total}/{total} compared checks achieved verified PASS verdicts with zero regressions.")
    return _res("INCONCLUSIVE", ["COMPARE_UNCLASSIFIED"], "Comparison state could not be deterministically classified.")


_DECIDERS = {
    "WIN-4688-CANARY": _decide_4688,
    "WIN-ETW-INTEGRITY": _decide_etw_integrity,
    "WIN-KERNEL-PPL-HVCI": _decide_kernel_ppl_hvci,
    "WIN-XPROC-HANDLE": _decide_xproc_handle,
    "WIN-LSA-SSP-AUDIT": _decide_lsa_ssp_audit,
    "WIN-CMDLINE-WMI": _decide_cmdline_wmi,
    "WIN-ASSURANCE-COMPARE": _decide_assurance_compare,
    "WIN-T1685-001-EDR-MINIFILTER": _decide_t1685_001_edr_minifilter,
    "WIN-T1685-002-CLOUD-LOG": _decide_t1685_002_cloud_log,
    "WIN-T1685-003-ETW-SYSCALL": _decide_t1685_003_etw_syscall,
    "WIN-T1685-004-FIREWALL-WFP": _decide_t1685_004_firewall_wfp,
    "WIN-T1685-005-USN-EVTX": _decide_t1685_005_usn_evtx,
    "WIN-T1685-006-VBS-VTL1-BCD": _decide_t1685_006_vbs_vtl1_bcd,
    "WIN-T1685-007-SAFEBOOT-BCD": _decide_t1685_007_safeboot_bcd,
}


def decide_detailed(observation, test_id="WIN-4688-CANARY"):
    """Evidence gates precede any positive/negative assertion; returns (verdict, sorted_reason_codes, rationale)."""
    if not isinstance(observation, dict):
        return _res("INCONCLUSIVE", ["OBSERVATION_INVALID"], "Observation payload is missing or invalid.")
    fn = _DECIDERS.get(test_id)
    if fn is None:
        return _res("INCONCLUSIVE", ["UNKNOWN_TEST_ID"], f"Unknown test id: {test_id}")
    return fn(observation)


def decide(observation, test_id="WIN-4688-CANARY"):
    """Backwards-compatible wrapper returning (verdict, rationale)."""
    verdict, _codes, rationale = decide_detailed(observation, test_id=test_id)
    return verdict, rationale


def make_receipt(
    host,
    observation,
    scenario="local",
    test_id="WIN-4688-CANARY",
    host_fingerprint_sha256=None,
    challenge_nonce=None,
):
    if test_id not in TEST_SPECS:
        raise ValueError(f"Unsupported test_id: {test_id}")
    assert_no_floats(observation, path="$.observation")
    spec = TEST_SPECS[test_id]
    verdict, reason_codes, rationale = decide_detailed(observation, test_id=test_id)
    test_meta = {
        "id": test_id,
        "rule_version": spec["rule_version"],
        "objective": spec["objective"],
        "control_reference": spec["control_reference"],
    }
    if test_id != "WIN-4688-CANARY":
        test_meta["title"] = spec["title"]
        test_meta["mitre_attack"] = spec["mitre_attack"]
    target_meta = {
        "host": host,
        "scenario": scenario,
        "host_fingerprint_sha256": host_fingerprint_sha256,
        "challenge_nonce": challenge_nonce,
    }
    return {
        "schema": RECEIPT_SCHEMA_URN,
        "receipt_id": str(uuid4()),
        "created_at": utc_now(),
        "test": test_meta,
        "target": target_meta,
        "observation": observation,
        "verdict": verdict,
        "reason_codes": reason_codes,
        "rationale": rationale,
        "limitations": [
            "Scoped point-in-time proof only; not comprehensive endpoint assurance.",
            "Local collector and test runner share a trust boundary.",
            "A signature authenticates a receipt, not the truth of data supplied by the collector.",
        ],
    }


def validate_receipt(receipt):
    """Fail-closed deterministic rule re-evaluation decoupled from human-readable rationale prose."""
    if not isinstance(receipt, dict):
        return False, "INVALID_RECEIPT_STRUCTURE: Invalid receipt structure"
    try:
        assert_no_floats(receipt)
    except ValueError as exc:
        return False, f"FLOAT_FORBIDDEN: {exc}"
    if receipt.get("schema") != RECEIPT_SCHEMA_URN:
        return False, f"UNKNOWN_SCHEMA: Expected {RECEIPT_SCHEMA_URN}"
    test = receipt.get("test")
    if not isinstance(test, dict):
        return False, "MISSING_TEST_METADATA: Missing test metadata"
    target = receipt.get("target")
    if not isinstance(target, dict):
        return False, "MISSING_TARGET_METADATA: Missing or invalid target metadata"
    observation = receipt.get("observation")
    if not isinstance(observation, dict):
        return False, "INVALID_OBSERVATION: Missing or non-object observation payload"
    test_id = test.get("id")
    spec = TEST_SPECS.get(test_id)
    if spec is None:
        return False, f"UNKNOWN_TEST_ID: Unexpected test id {test_id!r}"
    if test.get("rule_version") != spec["rule_version"]:
        return False, f"UNKNOWN_RULE_VERSION: Unrecognized rule_version {test.get('rule_version')!r}"
    stored_codes = receipt.get("reason_codes")
    if not isinstance(stored_codes, list) or not all(isinstance(c, str) for c in stored_codes):
        return False, "INVALID_REASON_CODES: Missing or invalid reason_codes list"
    v, expected_codes, _r = decide_detailed(observation, test_id=test_id)
    if v != receipt.get("verdict") or sorted(stored_codes) != expected_codes:
        return False, "VERDICT_MISMATCH: Stored verdict or reason_codes do not agree with observations"
    return True, "Recomputed verdict and reason_codes match"

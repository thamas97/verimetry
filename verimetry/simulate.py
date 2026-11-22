"""Synthetic scenarios are explicitly marked and never passed off as Windows evidence."""
from .core import utc_now, ALL_VERIMETRY_CHECK_IDS


def scenario_observation(which):
    labels = {"A": ("ok", "enabled", True), "B": ("ok", "enabled", False),
              "C": ("access_denied", "unknown", None)}
    if which not in labels:
        raise ValueError("Choose A, B or C")
    query, policy, matched = labels[which]
    return {"mode": "simulation", "canary_completed": True,
            "process": {"image": "C:\\Windows\\System32\\cmd.exe", "pid": 4020,
                        "command": "cmd /c exit 0", "simulated": True},
            "start_time": utc_now(), "end_time": utc_now(),
            "audit_policy": policy, "query_status": query,
            "query_truncated": False, "matching_event": matched,
            "evidence": {"source": "synthetic-fixture", "event_id": 4688,
                         "record_id": 10001 if matched else None,
                         "description": "Generated example, not evidence from a machine"}}


def internals_observation(test_id: str, outcome: str = "PASS"):
    """Generate explicitly marked synthetic observations for any of the 5 Windows Internals or 7 T1685 checks."""
    outcome = outcome.upper()
    if outcome not in ("PASS", "FAIL", "INCONCLUSIVE"):
        raise ValueError("outcome must be PASS, FAIL, or INCONCLUSIVE")
    now = utc_now()
    base = {"mode": "simulation", "simulated": True, "start_time": now, "end_time": now}

    if test_id == "WIN-ETW-INTEGRITY":
        if outcome == "PASS":
            return {**base, "etw_query_status": "ok", "etw_query_method": "synthetic",
                    "etw_sessions": {"EventLog-System": True, "DiagTrack-Listener": True},
                    "marker": "VERIMETRY_ETW_MARKER_SYNTH001", "marker_emitted": True,
                    "marker_method": "synthetic", "log_query_status": "ok",
                    "query_truncated": False, "marker_observed": True,
                    "evidence": {"source": "synthetic-fixture", "total_etw_sessions": 24}}
        if outcome == "FAIL":
            return {**base, "etw_query_status": "ok", "etw_query_method": "synthetic",
                    "etw_sessions": {"EventLog-System": True, "DiagTrack-Listener": False},
                    "marker": "VERIMETRY_ETW_MARKER_SYNTH002", "marker_emitted": True,
                    "marker_method": "synthetic", "log_query_status": "ok",
                    "query_truncated": False, "marker_observed": True,
                    "evidence": {"source": "synthetic-fixture", "total_etw_sessions": 23}}
        return {**base, "etw_query_status": "access_denied", "etw_query_method": "synthetic",
                "etw_sessions": {"EventLog-System": None, "DiagTrack-Listener": None},
                "marker": "VERIMETRY_ETW_MARKER_SYNTH003", "marker_emitted": True,
                "marker_method": "synthetic", "log_query_status": "ok",
                "query_truncated": False, "marker_observed": True,
                "evidence": {"source": "synthetic-fixture"}}

    if test_id == "WIN-KERNEL-PPL-HVCI":
        if outcome == "PASS":
            return {**base, "device_guard_status": "ok", "lsa_registry_status": "ok",
                    "ci_log_query_status": "ok", "vbs_running": True, "hvci_running": True,
                    "run_as_ppl_enabled": True, "ci_log_enabled": True, "ci_log_readable": True,
                    "evidence": {"source": "synthetic-fixture", "run_as_ppl_value": 1}}
        if outcome == "FAIL":
            return {**base, "device_guard_status": "ok", "lsa_registry_status": "ok",
                    "ci_log_query_status": "ok", "vbs_running": True, "hvci_running": False,
                    "run_as_ppl_enabled": False, "ci_log_enabled": True, "ci_log_readable": True,
                    "evidence": {"source": "synthetic-fixture", "run_as_ppl_value": 0}}
        return {**base, "device_guard_status": "access_denied", "lsa_registry_status": "ok",
                "ci_log_query_status": "ok", "vbs_running": None, "hvci_running": None,
                "run_as_ppl_enabled": True, "ci_log_enabled": True, "ci_log_readable": True,
                "evidence": {"source": "synthetic-fixture"}}

    if test_id == "WIN-XPROC-HANDLE":
        if outcome == "PASS":
            return {**base, "canary_completed": True, "handle_opened": True,
                    "handle_access_mask": "0x1000", "handle_audit_policy": "enabled",
                    "query_status": "ok", "query_truncated": False,
                    "handle_event_matched": True, "process_event_matched": True,
                    "evidence": {"source": "synthetic-fixture", "event_ids": [4656, 4663, 4688]}}
        if outcome == "FAIL":
            return {**base, "canary_completed": True, "handle_opened": True,
                    "handle_access_mask": "0x1000", "handle_audit_policy": "enabled",
                    "query_status": "ok", "query_truncated": False,
                    "handle_event_matched": False, "process_event_matched": True,
                    "evidence": {"source": "synthetic-fixture", "event_ids": [4656, 4663, 4688]}}
        return {**base, "canary_completed": True, "handle_opened": True,
                "handle_access_mask": "0x1000", "handle_audit_policy": "disabled",
                "query_status": "ok", "query_truncated": False,
                "handle_event_matched": False, "process_event_matched": True,
                "evidence": {"source": "synthetic-fixture"}}

    if test_id == "WIN-LSA-SSP-AUDIT":
        if outcome == "PASS":
            return {**base, "registry_query_status": "ok", "sacl_query_status": "ok",
                    "audit_registry_policy": "enabled", "sacl_present": True, "sacl_rule_count": 1,
                    "evidence": {"source": "synthetic-fixture", "security_packages": ["kerberos", "msv1_0", "schannel"]}}
        if outcome == "FAIL":
            return {**base, "registry_query_status": "ok", "sacl_query_status": "ok",
                    "audit_registry_policy": "enabled", "sacl_present": False, "sacl_rule_count": 0,
                    "evidence": {"source": "synthetic-fixture", "security_packages": ["kerberos", "msv1_0"]}}
        return {**base, "registry_query_status": "ok", "sacl_query_status": "access_denied",
                "audit_registry_policy": "unknown", "sacl_present": None, "sacl_rule_count": None,
                "evidence": {"source": "synthetic-fixture"}}

    if test_id == "WIN-CMDLINE-WMI":
        if outcome == "PASS":
            return {**base, "canary_completed": True, "wmi_query_completed": True,
                    "audit_policy": "enabled", "cmdline_audit_policy": "enabled",
                    "security_query_status": "ok", "security_truncated": False,
                    "wmi_log_query_status": "ok", "wmi_log_truncated": False,
                    "matching_event": True, "cmdline_matched": True,
                    "wmi_log_enabled": True, "wmi_log_readable": True,
                    "evidence": {"source": "synthetic-fixture", "event_id": 4688}}
        if outcome == "FAIL":
            return {**base, "canary_completed": True, "wmi_query_completed": True,
                    "audit_policy": "enabled", "cmdline_audit_policy": "disabled",
                    "security_query_status": "ok", "security_truncated": False,
                    "wmi_log_query_status": "ok", "wmi_log_truncated": False,
                    "matching_event": True, "cmdline_matched": False,
                    "wmi_log_enabled": True, "wmi_log_readable": True,
                    "evidence": {"source": "synthetic-fixture", "event_id": 4688}}
        return {**base, "canary_completed": True, "wmi_query_completed": True,
                "audit_policy": "unknown", "cmdline_audit_policy": "unknown",
                "security_query_status": "access_denied", "security_truncated": False,
                "wmi_log_query_status": "ok", "wmi_log_truncated": False,
                "matching_event": None, "cmdline_matched": None,
                "wmi_log_enabled": True, "wmi_log_readable": True,
                "evidence": {"source": "synthetic-fixture"}}

    if test_id == "WIN-T1685-001-EDR-MINIFILTER":
        if outcome == "PASS":
            return {**base, "scm_query_status": "ok", "fltmc_query_status": "ok",
                    "edr_service_running": True, "signed_security_minifilter_in_band": True,
                    "tamper_dacl_blocks_unauthorized_stop": True,
                    "evidence": {"source": "synthetic-fixture", "services": ["WinDefend", "Sense"], "minifilters": [{"name": "WdFilter", "altitude": "328010"}]}}
        if outcome == "FAIL":
            return {**base, "scm_query_status": "ok", "fltmc_query_status": "ok",
                    "edr_service_running": True, "signed_security_minifilter_in_band": False,
                    "tamper_dacl_blocks_unauthorized_stop": False,
                    "evidence": {"source": "synthetic-fixture", "services": ["WinDefend"], "minifilters": []}}
        return {**base, "scm_query_status": "access_denied", "fltmc_query_status": "access_denied",
                "edr_service_running": None, "signed_security_minifilter_in_band": None,
                "tamper_dacl_blocks_unauthorized_stop": None,
                "evidence": {"source": "synthetic-fixture", "error": "ERROR_ACCESS_DENIED (missing SeDebugPrivilege)"}}

    if test_id == "WIN-T1685-002-CLOUD-LOG":
        if outcome == "PASS":
            return {**base, "forwarder_configured": True, "forwarder_query_status": "ok",
                    "ingestion_mode": "sync", "ingestion_verify_status": "ok",
                    "forwarder_service_active": True, "sink_config_hash_matches_baseline": True,
                    "audit_bypass_clear": True, "log_validation_encryption_enabled": True,
                    "synthetic_heartbeat_acknowledged": True,
                    "evidence": {"source": "synthetic-fixture", "forwarder": "AzureMonitorAgent / EventLogForwarder", "heartbeat_tag": "VERIMETRY_CLOUD_HB_01"}}
        if outcome == "FAIL":
            return {**base, "forwarder_configured": True, "forwarder_query_status": "ok",
                    "ingestion_mode": "sync", "ingestion_verify_status": "ok",
                    "forwarder_service_active": True, "sink_config_hash_matches_baseline": False,
                    "audit_bypass_clear": False, "log_validation_encryption_enabled": False,
                    "synthetic_heartbeat_acknowledged": False,
                    "evidence": {"source": "synthetic-fixture", "anomalies": ["AN0801", "AN0803", "Set-MailboxAuditBypassAssociation"]}}
        return {**base, "forwarder_configured": True, "forwarder_query_status": "ok",
                "ingestion_mode": "sync", "ingestion_verify_status": "timeout",
                "forwarder_service_active": True, "sink_config_hash_matches_baseline": True,
                "audit_bypass_clear": True, "log_validation_encryption_enabled": True,
                "synthetic_heartbeat_acknowledged": None,
                "evidence": {"source": "synthetic-fixture", "error": "Egress timeout / API rate-limit during canary window"}}

    if test_id == "WIN-T1685-003-ETW-SYSCALL":
        if outcome == "PASS":
            return {**base, "ntdll_inspect_status": "ok", "etw_autologger_status": "ok", "auditpol_status": "ok",
                    "ntdll_etw_stub_state": "clean", "core_autologgers_running": True,
                    "auditpol_subcategories_enabled": True, "benign_test_event_recorded": True,
                    "evidence": {"source": "synthetic-fixture", "ntdll_prologue_hex": "4c8bd1b8", "event_ids_verified": [4688, 4104]}}
        if outcome == "FAIL":
            return {**base, "ntdll_inspect_status": "ok", "etw_autologger_status": "ok", "auditpol_status": "ok",
                    "ntdll_etw_stub_state": "blinded_ret", "core_autologgers_running": False,
                    "auditpol_subcategories_enabled": False, "benign_test_event_recorded": False,
                    "evidence": {"source": "synthetic-fixture", "ntdll_prologue_hex": "c3909090", "hook_detected": "0xC3 ret patch on ntdll!EtwEventWrite"}}
        return {**base, "ntdll_inspect_status": "vbs_restricted", "etw_autologger_status": "ok", "auditpol_status": "access_denied",
                "ntdll_etw_stub_state": "unknown", "core_autologgers_running": True,
                "auditpol_subcategories_enabled": None, "benign_test_event_recorded": None,
                "evidence": {"source": "synthetic-fixture"}}

    if test_id == "WIN-T1685-004-FIREWALL-WFP":
        if outcome == "PASS":
            return {**base, "wfp_query_status": "ok", "firewall_profile_status": "ok",
                    "windows_firewall_mandated": True,
                    "all_firewall_profiles_enabled": True, "no_unauthorized_wfp_telemetry_block": True,
                    "firewall_logging_enabled": True, "collector_tls_handshake_ok": True,
                    "evidence": {"source": "synthetic-fixture", "profiles": {"Domain": True, "Private": True, "Public": True}, "wfp_telemetry_block_rules": 0}}
        if outcome == "FAIL":
            return {**base, "wfp_query_status": "ok", "firewall_profile_status": "ok",
                    "windows_firewall_mandated": True,
                    "all_firewall_profiles_enabled": False, "no_unauthorized_wfp_telemetry_block": False,
                    "firewall_logging_enabled": False, "collector_tls_handshake_ok": False,
                    "evidence": {"source": "synthetic-fixture", "profiles": {"Domain": False, "Private": False, "Public": False}, "wfp_telemetry_block_rules": 2}}
        return {**base, "wfp_query_status": "vpn_split_tunnel_obscured", "firewall_profile_status": "ok",
                "windows_firewall_mandated": False,
                "all_firewall_profiles_enabled": True, "no_unauthorized_wfp_telemetry_block": None,
                "firewall_logging_enabled": True, "collector_tls_handshake_ok": None,
                "evidence": {"source": "synthetic-fixture"}}

    if test_id == "WIN-T1685-005-USN-EVTX":
        if outcome == "PASS":
            return {**base, "filesystem_type": "NTFS", "usn_query_status": "ok", "evtx_query_status": "ok",
                    "usn_journal_active": True, "usn_bounds_valid": True,
                    "usn_journal_id_changed": False, "usn_explicit_delete_indicator": False,
                    "evtx_in_range_monotonic": True, "evtx_next_record_reset_to_1": False,
                    "log_clear_1102_104_in_window": False,
                    "evidence": {"source": "synthetic-fixture", "usn_journal_id": "0x01DB3A9940C10000", "security_record_count": 48210}}
        if outcome == "FAIL":
            return {**base, "filesystem_type": "NTFS", "usn_query_status": "ok", "evtx_query_status": "ok",
                    "usn_journal_active": True, "usn_bounds_valid": True,
                    "usn_journal_id_changed": True, "usn_explicit_delete_indicator": True,
                    "evtx_in_range_monotonic": False, "evtx_next_record_reset_to_1": True,
                    "log_clear_1102_104_in_window": True,
                    "evidence": {"source": "synthetic-fixture", "usn_journal_id": "0x01DB3AA011110000", "log_clear_events_detected": [1102, 104]}}
        return {**base, "filesystem_type": "ReFS", "usn_query_status": "unsupported_fs", "evtx_query_status": "ok",
                "usn_journal_active": None, "evtx_in_range_monotonic": True, "log_clear_1102_104_in_window": False,
                "evidence": {"source": "synthetic-fixture"}}

    if test_id == "WIN-T1685-006-VBS-VTL1-BCD":
        if outcome == "PASS":
            return {**base, "virtualization_environment": "hardware_vtx", "firmware_type": "UEFI",
                    "secure_boot_status": "ok", "device_guard_status": "ok", "bcd_query_status": "ok",
                    "vtl1_running": True, "bcd_hypervisorlaunchtype_value": "auto",
                    "registry_matches_running_vtl1_state": True, "uefi_secure_boot_enabled": True,
                    "evidence": {"source": "synthetic-fixture", "vtl1_processes": ["securekernel.exe", "LsaIso.exe"], "bcd_hypervisorlaunchtype": "Auto"}}
        if outcome == "FAIL":
            return {**base, "virtualization_environment": "hardware_vtx", "firmware_type": "UEFI",
                    "secure_boot_status": "ok", "device_guard_status": "ok", "bcd_query_status": "ok",
                    "vtl1_running": True, "bcd_hypervisorlaunchtype_value": "off",
                    "registry_matches_running_vtl1_state": False, "uefi_secure_boot_enabled": True,
                    "evidence": {"source": "synthetic-fixture", "bcd_hypervisorlaunchtype": "Off", "staged_enable_vbs_reg": 0, "reboot_drift_detected": True}}
        return {**base, "virtualization_environment": "nested_vm_no_vtx", "firmware_type": "UEFI",
                "secure_boot_status": "ok", "device_guard_status": "ok", "bcd_query_status": "access_denied",
                "vtl1_running": False, "bcd_hypervisorlaunchtype_value": None,
                "registry_matches_running_vtl1_state": None, "uefi_secure_boot_enabled": None,
                "evidence": {"source": "synthetic-fixture"}}

    if test_id == "WIN-T1685-007-SAFEBOOT-BCD":
        if outcome == "PASS":
            return {**base, "bcd_query_status": "ok", "safeboot_reg_status": "ok",
                    "bcd_safeboot_absent": True, "active_edr_safeboot_keys_intact": True,
                    "evidence": {"source": "synthetic-fixture", "bcd_current_safeboot": None, "safeboot_minimal_services_count": 48}}
        if outcome == "FAIL":
            return {**base, "bcd_query_status": "ok", "safeboot_reg_status": "ok",
                    "bcd_safeboot_absent": False, "active_edr_safeboot_keys_intact": False,
                    "evidence": {"source": "synthetic-fixture", "bcd_current_safeboot": "Minimal (0x25000080)", "imminent_evasion_reboot": True}}
        return {**base, "bcd_query_status": "bitlocker_locked", "safeboot_reg_status": "ok",
                "bcd_safeboot_absent": None, "active_edr_safeboot_keys_intact": True,
                "evidence": {"source": "synthetic-fixture"}}

    raise ValueError(f"Unknown internals test_id: {test_id}. Expected one of {ALL_VERIMETRY_CHECK_IDS}")

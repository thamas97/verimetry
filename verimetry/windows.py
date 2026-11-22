"""Read-only Windows event/configuration collection and 5 safe, non-destructive internals canaries."""
from __future__ import annotations
import csv
import ctypes
import io
import json
import os
import platform
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

PROCESS_CREATION_GUID = "{0cce922b-69ae-11d9-bed3-505054503030}"
AUDIT_REGISTRY_GUID = "{0cce921e-69ae-11d9-bed3-505054503030}"
AUDIT_KERNEL_OBJECT_GUID = "{0cce921f-69ae-11d9-bed3-505054503030}"
AUDIT_HANDLE_MANIPULATION_GUID = "{0cce9223-69ae-11d9-bed3-505054503030}"

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
CMDLINE_CANARY_MARKER = "VERIMETRY_CANARY_PING"


def _require_windows():
    if platform.system() != "Windows":
        raise OSError("Host test is Windows-only; use 'demo' on other platforms")


def _validate_window(window_seconds: int):
    if not 1 <= window_seconds <= 15:
        raise ValueError("Window must be 1-15 seconds")


def _cmd_exe_path() -> str:
    return str(Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "cmd.exe")


def _run(args, timeout=25):
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def _run_ps_json(script: str, timeout: int = 35):
    try:
        result = _run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], timeout=timeout)
        if result.returncode != 0:
            return None, "ps_error"
        text = result.stdout.strip()
        if not text:
            return None, "empty_output"
        parsed = json.loads(text)
        if not isinstance(parsed, dict):
            return None, "unexpected_json"
        return parsed, "ok"
    except (subprocess.TimeoutExpired, ValueError, OSError) as exc:
        return None, type(exc).__name__


def _as_int_list(value) -> list[int]:
    if value is None:
        return []
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return [int(value)]
    if isinstance(value, list):
        out = []
        for item in value:
            if isinstance(item, (int, float)) and not isinstance(item, bool):
                out.append(int(item))
        return out
    return []


def _as_str_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [str(v) for v in value if v is not None and str(v) != ""]
    return []


import uuid
from .core import compute_host_fingerprint

POLICY_AUDIT_EVENT_UNCHANGED = 0x00000000
POLICY_AUDIT_EVENT_SUCCESS = 0x00000001
POLICY_AUDIT_EVENT_FAILURE = 0x00000002
POLICY_AUDIT_EVENT_NONE = 0x00000004


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class _AUDIT_POLICY_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("AuditSubCategoryGuid", _GUID),
        ("AuditingInformation", ctypes.c_uint32),
        ("AuditCategoryGuid", _GUID),
    ]


def _guid_from_str(guid_str: str) -> _GUID:
    u = uuid.UUID(guid_str)
    g = _GUID()
    g.Data1 = u.fields[0]
    g.Data2 = u.fields[1]
    g.Data3 = u.fields[2]
    tail = u.bytes[8:]
    for idx in range(8):
        g.Data4[idx] = tail[idx]
    return g


def decode_audit_bitmask(mask: int, label: str = "Audit subcategory") -> tuple[str, str]:
    """Decode numeric Windows AUDIT_POLICY_INFORMATION.AuditingInformation bitmask without any locale string parsing."""
    if mask & POLICY_AUDIT_EVENT_SUCCESS:
        return "enabled", f"{label} includes success auditing (Advapi32 bitmask 0x{mask:x})"
    if mask == 0 or (mask & POLICY_AUDIT_EVENT_NONE) or (mask & POLICY_AUDIT_EVENT_FAILURE):
        return "disabled", f"{label} does not include success auditing (Advapi32 bitmask 0x{mask:x})"
    return "unknown", f"{label}: unrecognized audit bitmask 0x{mask:x}"


def _query_audit_subcategory_win32(guid: str, label: str = "Audit subcategory"):
    """Call advapi32!AuditQuerySystemPolicy + AuditFree directly via ctypes (locale-independent, zero subprocesses)."""
    if platform.system() != "Windows" or not hasattr(ctypes, "WinDLL"):
        return None
    try:
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        advapi32.AuditQuerySystemPolicy.argtypes = [
            ctypes.POINTER(_GUID),
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.POINTER(_AUDIT_POLICY_INFORMATION)),
        ]
        advapi32.AuditQuerySystemPolicy.restype = ctypes.c_ubyte
        advapi32.AuditFree.argtypes = [ctypes.c_void_p]
        advapi32.AuditFree.restype = None

        sub_guid = _guid_from_str(guid)
        out_ptr = ctypes.POINTER(_AUDIT_POLICY_INFORMATION)()
        ok = advapi32.AuditQuerySystemPolicy(ctypes.byref(sub_guid), 1, ctypes.byref(out_ptr))
        if not ok:
            err = ctypes.get_last_error()
            if err in (5, 1314):  # ERROR_ACCESS_DENIED, ERROR_PRIVILEGE_NOT_HELD
                return "unknown", f"{label}: AuditQuerySystemPolicy access denied (Win32 error {err}; requires Administrator)"
            return None
        if not out_ptr:
            return None
        try:
            mask = int(out_ptr.contents.AuditingInformation)
            return decode_audit_bitmask(mask, label=label)
        finally:
            advapi32.AuditFree(out_ptr)
    except Exception:
        return None


def read_audit_subcategory(guid: str, label: str = "Audit subcategory"):
    """Read Windows audit subcategory setting via advapi32!AuditQuerySystemPolicy (locale-independent) with numeric CSV fallback."""
    win32_res = _query_audit_subcategory_win32(guid, label=label)
    if win32_res is not None:
        return win32_res
    try:
        r = _run(["auditpol", "/get", f"/subcategory:{guid}", "/r"])
        combined = f"{r.stdout}\n{r.stderr}".lower()
        if r.returncode != 0:
            if any(tok in combined for tok in ("0x00000522", "privilege", "access is denied", "unauthorized")):
                return "unknown", f"{label}: auditpol access denied (requires Administrator)"
            return "unknown", f"{label}: auditpol query failed"
        lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
        rows = list(csv.reader(io.StringIO("\n".join(lines))))
        if len(rows) < 2:
            return "unknown", f"{label}: auditpol CSV missing"
        header = [h.strip().lower() for h in rows[0]]
        data_row = rows[1]
        # Prefer numeric Setting Value column (works across locales by checking last numeric cell too)
        idx = next((i for i, h in enumerate(header) if h in ("setting value", "setting value (numeric)")), None)
        if idx is not None and len(data_row) > idx and data_row[idx].strip().isdigit():
            return decode_audit_bitmask(int(data_row[idx].strip()), label=label)
        if data_row and data_row[-1].strip() in ("0", "1", "2", "3"):
            return decode_audit_bitmask(int(data_row[-1].strip()), label=label)
        inc_idx = next((i for i, h in enumerate(header) if "inclusion setting" in h), None)
        if inc_idx is not None and len(data_row) > inc_idx:
            inc = data_row[inc_idx].strip().lower()
            if "success" in inc:
                return "enabled", f"{label} includes success auditing ({data_row[inc_idx].strip()})"
            if inc in ("no auditing", "failure"):
                return "disabled", f"{label} does not include success auditing ({data_row[inc_idx].strip()})"
        return "unknown", f"{label}: could not parse auditpol setting"
    except Exception as e:
        return "unknown", f"{label}: policy read error ({type(e).__name__})"


def collect_host_fingerprint() -> str | None:
    """Compute privacy-preserving SHA-256 host binding from MachineGuid + SMBIOS UUID on Windows."""
    if platform.system() != "Windows":
        return None
    script = r'''
$ErrorActionPreference='SilentlyContinue'
$mg = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
$uuid = (Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -First 1 -ExpandProperty UUID)
@{machine_guid=$mg;smbios_uuid=$uuid} | ConvertTo-Json -Compress
'''
    parsed, status = _run_ps_json(script, timeout=15)
    if status != "ok" or not isinstance(parsed, dict):
        return None
    return compute_host_fingerprint(parsed.get("machine_guid"), parsed.get("smbios_uuid"))


def read_policy():
    """Backward-compatible wrapper for Audit Process Creation policy."""
    return read_audit_subcategory(PROCESS_CREATION_GUID, "Audit Process Creation")


def run_canary(window_seconds=4):
    """Legacy single-event Process Creation (Event 4688) canary."""
    _require_windows()
    _validate_window(window_seconds)
    policy, policy_note = read_policy()
    start = datetime.now(timezone.utc)
    child = subprocess.Popen(
        [_cmd_exe_path(), "/d", "/c", "exit", "0"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    pid = child.pid
    completed = child.wait(timeout=10) == 0
    time.sleep(window_seconds)
    end = datetime.now(timezone.utc)
    start_ps = start.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_ps = end.strftime("%Y-%m-%dT%H:%M:%SZ")
    script = r'''
$ErrorActionPreference='Stop'
try {
  $start=[datetime]::Parse('START_HERE',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime().AddSeconds(-5)
  $end=[datetime]::Parse('END_HERE',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime().AddSeconds(5)
  $items=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688;StartTime=$start;EndTime=$end} -MaxEvents 2000 -ErrorAction Stop)
  $matched=$null
  foreach ($entry in $items) {
    [xml]$x=$entry.ToXml()
    $fields=@{}
    foreach($d in $x.Event.EventData.Data) {$fields[[string]$d.Name]=[string]$d.'#text'}
    if ($fields['NewProcessId'] -eq 'PID_HEX' -and $fields['NewProcessName'] -match '(?i)\\cmd\.exe$') {
      $matched=@{record_id=$entry.RecordId;event_time=$entry.TimeCreated.ToUniversalTime().ToString('o');image=$fields['NewProcessName'];pid=$fields['NewProcessId']}; break
    }
  }
  @{status='ok';events_scanned=$items.Count;truncated=($items.Count -ge 2000);match=$matched} | ConvertTo-Json -Compress -Depth 5
} catch {
  if ($_.FullyQualifiedErrorId -like '*NoMatchingEventsFound*' -or $_.Exception.Message -match 'No events were found') {
    @{status='ok';events_scanned=0;truncated=$false;match=$null} | ConvertTo-Json -Compress
  } elseif ($_.Exception.Message -match 'Access is denied|UnauthorizedAccess') {
    @{status='access_denied';events_scanned=0;truncated=$false;match=$null} | ConvertTo-Json -Compress
  } else {
    @{status='query_error';events_scanned=0;truncated=$false;match=$null} | ConvertTo-Json -Compress
  }
}
'''.replace("START_HERE", start_ps).replace("END_HERE", end_ps).replace("PID_HEX", hex(pid))
    parsed, _ = _run_ps_json(script, timeout=35)
    parsed = parsed or {}
    status = parsed.get("status", "query_error")
    scanned = parsed.get("events_scanned", 0)
    truncated = bool(parsed.get("truncated", False))
    match = parsed.get("match")
    return {
        "mode": "live-windows",
        "canary_completed": completed,
        "process": {"image": "cmd.exe", "pid": pid, "command": "cmd.exe /d /c exit 0"},
        "start_time": start.isoformat(),
        "end_time": end.isoformat(),
        "audit_policy": policy,
        "audit_policy_note": policy_note,
        "query_status": status,
        "query_truncated": truncated,
        "matching_event": bool(match) if status == "ok" else None,
        "evidence": {
            "source": "Windows Security log",
            "event_id": 4688,
            "events_scanned": scanned,
            "matched_record": match,
        },
        "scope_note": "One process creation event, no global monitoring claim",
    }


def run_etw_integrity(window_seconds=4):
    """Check 1 (MITRE T1562.006): ETW provider integrity & user-mode EventLog marker pipeline."""
    _require_windows()
    _validate_window(window_seconds)
    marker = f"VERIMETRY_ETW_MARKER_{uuid4().hex[:12].upper()}"
    start = datetime.now(timezone.utc)

    # Step 1: Query active ETW trace sessions (Get-EtwTraceSession with logman query -ets fallback)
    etw_script = r'''
$ErrorActionPreference='Stop'
$method='none'
$status='query_error'
$names=@()
try {
  $sessions=@(Get-EtwTraceSession -ErrorAction Stop)
  $names=@($sessions | ForEach-Object { [string]$_.Name } | Where-Object { $_ })
  $method='Get-EtwTraceSession'
  if ($names.Count -gt 0) { $status='ok' }
} catch {
  if ($_.Exception.Message -match 'Access is denied|UnauthorizedAccess|PermissionDenied') {
    $status='access_denied'
    $method='Get-EtwTraceSession'
  }
}
if ($status -ne 'ok' -and $status -ne 'access_denied') {
  try {
    $out = & logman query -ets 2>&1
    $code = $LASTEXITCODE
    $txt = ($out | Out-String)
    if ($code -ne 0) {
      if ($txt -match 'Access is denied|0x80070005|privilege') { $status='access_denied' }
      else { $status='query_error' }
      $method='logman'
    } else {
      $parsed = @()
      foreach ($line in ($txt -split "`r?`n")) {
        if ($line -match '^\s*(\S.+?)\s{2,}(Trace|Counter|Alert|Api|Unknown)\s+') {
          $parsed += $Matches[1].Trim()
        }
      }
      $names = $parsed
      $method='logman'
      $status = if ($names.Count -gt 0) { 'ok' } else { 'insufficient_visibility' }
    }
  } catch {
    $status='query_error'
    $method='logman'
  }
}
if ($status -eq 'ok' -and $names.Count -eq 0) {
  $status = 'insufficient_visibility'
}
$lower = @($names | ForEach-Object { $_.ToLowerInvariant() })
$hasEvlog = ($lower -contains 'eventlog-system')
$hasDiag = ($lower -contains 'diagtrack-listener')
@{
  status=$status
  method=$method
  total_sessions=$names.Count
  eventlog_system=$hasEvlog
  diagtrack_listener=$hasDiag
} | ConvertTo-Json -Compress -Depth 4
'''
    etw_parsed, _ = _run_ps_json(etw_script, timeout=30)
    etw_parsed = etw_parsed or {}
    etw_status = etw_parsed.get("status", "query_error")
    etw_method = etw_parsed.get("method", "none")
    total_sessions = int(etw_parsed.get("total_sessions", 0) or 0)
    if etw_status == "ok" and total_sessions == 0:
        etw_status = "insufficient_visibility"
    etw_sessions = (
        {
            "EventLog-System": bool(etw_parsed.get("eventlog_system", False)),
            "DiagTrack-Listener": bool(etw_parsed.get("diagtrack_listener", False)),
        }
        if etw_status == "ok"
        else {"EventLog-System": None, "DiagTrack-Listener": None}
    )

    # Step 2: Emit a benign custom EventLog/ETW marker without modifying registry sources
    emit_script = r'''
$ErrorActionPreference='Stop'
$emitted=$false
$method='none'
try {
  $wsh = New-Object -ComObject WScript.Shell
  $ok = $wsh.LogEvent(4, 'MARKER_HERE')
  if ($ok) {
    $emitted=$true
    $method='WScript.Shell.LogEvent'
  }
} catch {
  $emitted=$false
}
if (-not $emitted) {
  try {
    & eventcreate /T INFORMATION /ID 999 /L APPLICATION /D 'MARKER_HERE' *> $null
    if ($LASTEXITCODE -eq 0) {
      $emitted=$true
      $method='eventcreate'
    }
  } catch {
    $emitted=$false
  }
}
@{emitted=$emitted;method=$method} | ConvertTo-Json -Compress
'''.replace("MARKER_HERE", marker)
    emit_parsed, _ = _run_ps_json(emit_script, timeout=20)
    emit_parsed = emit_parsed or {}
    marker_emitted = bool(emit_parsed.get("emitted", False))
    marker_method = emit_parsed.get("method", "none")

    time.sleep(window_seconds)
    end = datetime.now(timezone.utc)

    # Step 3: Verify marker arrival in Application event log within bounded window
    log_status, scanned, truncated, matched_record = "query_error", 0, False, None
    if marker_emitted:
        start_ps = start.strftime("%Y-%m-%dT%H:%M:%SZ")
        end_ps = end.strftime("%Y-%m-%dT%H:%M:%SZ")
        read_script = r'''
$ErrorActionPreference='Stop'
try {
  $start=[datetime]::Parse('START_HERE',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime().AddSeconds(-5)
  $end=[datetime]::Parse('END_HERE',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime().AddSeconds(5)
  $items=@(Get-WinEvent -FilterHashtable @{LogName='Application';StartTime=$start;EndTime=$end} -MaxEvents 2000 -ErrorAction Stop)
  $matched=$null
  foreach ($entry in $items) {
    $msg = [string]$entry.Message
    $xml = ''
    try { $xml = [string]$entry.ToXml() } catch { $xml = '' }
    if (($msg -and $msg.Contains('MARKER_HERE')) -or ($xml -and $xml.Contains('MARKER_HERE'))) {
      $matched=@{record_id=$entry.RecordId;event_id=$entry.Id;provider=$entry.ProviderName;event_time=$entry.TimeCreated.ToUniversalTime().ToString('o')}; break
    }
  }
  @{status='ok';events_scanned=$items.Count;truncated=($items.Count -ge 2000);match=$matched} | ConvertTo-Json -Compress -Depth 5
} catch {
  if ($_.FullyQualifiedErrorId -like '*NoMatchingEventsFound*' -or $_.Exception.Message -match 'No events were found') {
    @{status='ok';events_scanned=0;truncated=$false;match=$null} | ConvertTo-Json -Compress
  } elseif ($_.Exception.Message -match 'Access is denied|UnauthorizedAccess') {
    @{status='access_denied';events_scanned=0;truncated=$false;match=$null} | ConvertTo-Json -Compress
  } else {
    @{status='query_error';events_scanned=0;truncated=$false;match=$null} | ConvertTo-Json -Compress
  }
}
'''.replace("START_HERE", start_ps).replace("END_HERE", end_ps).replace("MARKER_HERE", marker)
        read_parsed, _ = _run_ps_json(read_script, timeout=35)
        read_parsed = read_parsed or {}
        log_status = read_parsed.get("status", "query_error")
        scanned = int(read_parsed.get("events_scanned", 0) or 0)
        truncated = bool(read_parsed.get("truncated", False))
        matched_record = read_parsed.get("match")

    return {
        "mode": "live-windows",
        "start_time": start.isoformat(),
        "end_time": end.isoformat(),
        "etw_query_status": etw_status,
        "etw_query_method": etw_method,
        "etw_sessions": etw_sessions,
        "marker": marker,
        "marker_emitted": marker_emitted,
        "marker_method": marker_method,
        "log_query_status": log_status,
        "query_truncated": truncated,
        "marker_observed": bool(matched_record) if (marker_emitted and log_status == "ok") else None,
        "evidence": {
            "total_etw_sessions": total_sessions,
            "log_name": "Application",
            "events_scanned": scanned,
            "matched_record": matched_record,
        },
        "scope_note": "Checks active EventLog-System / DiagTrack-Listener ETW sessions and one benign marker event; does not prove all ETW providers are untampered",
    }


def run_kernel_ppl_hvci():
    """Check 2 (MITRE T1068 / T1562.001): Win32_DeviceGuard VBS/HVCI, LSA RunAsPPL, and CodeIntegrity/Operational log."""
    _require_windows()
    collected = datetime.now(timezone.utc).isoformat()
    script = r'''
$ErrorActionPreference='Stop'
$dg = @{status='query_error';vbs_status=$null;configured=@();running=@()}
try {
  $inst = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop | Select-Object -First 1
  if ($null -eq $inst) {
    $dg.status = 'query_error'
  } else {
    $dg = @{
      status='ok'
      vbs_status=$inst.VirtualizationBasedSecurityStatus
      configured=@($inst.SecurityServicesConfigured)
      running=@($inst.SecurityServicesRunning)
    }
  }
} catch {
  if ($_.Exception.Message -match 'Access is denied|UnauthorizedAccess') { $dg.status='access_denied' }
  else { $dg.status='query_error' }
}

$lsa = @{status='query_error';run_as_ppl=$null;run_as_ppl_boot=$null}
try {
  $props = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction Stop
  $ppl = if ($props.PSObject.Properties['RunAsPPL']) { $props.RunAsPPL } else { $null }
  $pplBoot = if ($props.PSObject.Properties['RunAsPPLBoot']) { $props.RunAsPPLBoot } else { $null }
  $lsa = @{status='ok';run_as_ppl=$ppl;run_as_ppl_boot=$pplBoot}
} catch {
  if ($_.Exception.Message -match 'Access is denied|UnauthorizedAccess|Requested registry access is not allowed') { $lsa.status='access_denied' }
  else { $lsa.status='query_error' }
}

$ci = @{status='query_error';enabled=$null;readable=$false;record_count=$null;events_sampled=0}
try {
  $logInfo = Get-WinEvent -ListLog 'Microsoft-Windows-CodeIntegrity/Operational' -ErrorAction Stop
  $ci.enabled = [bool]$logInfo.IsEnabled
  $ci.record_count = $logInfo.RecordCount
  try {
    $ev = @(Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 5 -ErrorAction Stop)
    $ci.status = 'ok'
    $ci.readable = $true
    $ci.events_sampled = $ev.Count
  } catch {
    if ($_.FullyQualifiedErrorId -like '*NoMatchingEventsFound*' -or $_.Exception.Message -match 'No events were found') {
      $ci.status = 'ok'
      $ci.readable = $true
      $ci.events_sampled = 0
    } elseif ($_.Exception.Message -match 'Access is denied|UnauthorizedAccess') {
      $ci.status = 'access_denied'
      $ci.readable = $false
    } else {
      $ci.status = 'query_error'
      $ci.readable = $false
    }
  }
} catch {
  if ($_.Exception.Message -match 'Access is denied|UnauthorizedAccess') { $ci.status='access_denied' }
  else { $ci.status='query_error' }
}

@{device_guard=$dg;lsa=$lsa;code_integrity=$ci} | ConvertTo-Json -Compress -Depth 6
'''
    parsed, _ = _run_ps_json(script, timeout=35)
    parsed = parsed or {}
    dg = parsed.get("device_guard") or {}
    lsa = parsed.get("lsa") or {}
    ci = parsed.get("code_integrity") or {}

    dg_status = dg.get("status", "query_error")
    lsa_status = lsa.get("status", "query_error")
    ci_status = ci.get("status", "query_error")

    vbs_status_val = dg.get("vbs_status")
    running_services = _as_int_list(dg.get("running"))
    configured_services = _as_int_list(dg.get("configured"))

    vbs_running = (vbs_status_val == 2) if dg_status == "ok" and vbs_status_val is not None else None
    hvci_running = (2 in running_services) if dg_status == "ok" else None

    ppl_val = lsa.get("run_as_ppl")
    run_as_ppl_enabled = (ppl_val in (1, 2)) if lsa_status == "ok" else None

    ci_enabled = bool(ci.get("enabled")) if ci_status == "ok" and ci.get("enabled") is not None else None
    ci_readable = bool(ci.get("readable")) if ci_status == "ok" else None

    return {
        "mode": "live-windows",
        "collected_at": collected,
        "device_guard_status": dg_status,
        "lsa_registry_status": lsa_status,
        "ci_log_query_status": ci_status,
        "vbs_running": vbs_running,
        "hvci_running": hvci_running,
        "run_as_ppl_enabled": run_as_ppl_enabled,
        "ci_log_enabled": ci_enabled,
        "ci_log_readable": ci_readable,
        "evidence": {
            "virtualization_based_security_status": vbs_status_val,
            "security_services_configured": configured_services,
            "security_services_running": running_services,
            "run_as_ppl_value": ppl_val,
            "run_as_ppl_boot_value": lsa.get("run_as_ppl_boot"),
            "code_integrity_log": "Microsoft-Windows-CodeIntegrity/Operational",
            "code_integrity_record_count": ci.get("record_count"),
            "code_integrity_events_sampled": int(ci.get("events_sampled", 0) or 0),
        },
        "scope_note": "Read-only inspection of VBS/HVCI, RunAsPPL, and CodeIntegrity/Operational log readability; does not verify kernel driver allowlists or absence of vulnerable drivers",
    }


def _open_readonly_process_handle(pid: int):
    """Open a read-only PROCESS_QUERY_LIMITED_INFORMATION handle via kernel32 and close it cleanly."""
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel32.OpenProcess.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
    kernel32.CloseHandle.restype = ctypes.c_int
    kernel32.QueryFullProcessImageNameW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    kernel32.QueryFullProcessImageNameW.restype = ctypes.c_int

    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, int(pid))
    if not handle:
        return False, None, ctypes.get_last_error()
    queried_image = None
    try:
        buf_size = ctypes.c_uint32(1024)
        buf = ctypes.create_unicode_buffer(1024)
        if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(buf_size)):
            queried_image = buf.value
    finally:
        kernel32.CloseHandle(handle)
    return True, queried_image, 0


def run_xproc_handle(window_seconds=4):
    """Check 3 (MITRE T1106 / T1055): Spawn benign child, open read-only handle via kernel32, check telemetry."""
    _require_windows()
    _validate_window(window_seconds)
    handle_pol, handle_note = read_audit_subcategory(AUDIT_HANDLE_MANIPULATION_GUID, "Audit Handle Manipulation")
    kernel_pol, kernel_note = read_audit_subcategory(AUDIT_KERNEL_OBJECT_GUID, "Audit Kernel Object")
    proc_pol, proc_note = read_audit_subcategory(PROCESS_CREATION_GUID, "Audit Process Creation")

    if "enabled" in (handle_pol, kernel_pol):
        combined_handle_pol = "enabled"
    elif handle_pol == "disabled" and kernel_pol == "disabled":
        combined_handle_pol = "disabled"
    else:
        combined_handle_pol = "unknown"

    parent_pid = os.getpid()
    start = datetime.now(timezone.utc)
    child = subprocess.Popen(
        [_cmd_exe_path(), "/d", "/c", "timeout /t 2 /nobreak >nul"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    child_pid = child.pid
    handle_opened, queried_image, win32_err = False, None, 0
    try:
        handle_opened, queried_image, win32_err = _open_readonly_process_handle(child_pid)
    except Exception:
        handle_opened = False
    try:
        child_rc = child.wait(timeout=15)
        canary_completed = True
    except subprocess.TimeoutExpired:
        child.kill()
        child_rc = None
        canary_completed = False

    time.sleep(window_seconds)
    end = datetime.now(timezone.utc)

    start_ps = start.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_ps = end.strftime("%Y-%m-%dT%H:%M:%SZ")
    script = r'''
$ErrorActionPreference='Stop'
try {
  $start=[datetime]::Parse('START_HERE',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime().AddSeconds(-5)
  $end=[datetime]::Parse('END_HERE',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime().AddSeconds(5)
  $items=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=@(4656,4663,4688);StartTime=$start;EndTime=$end} -MaxEvents 2000 -ErrorAction Stop)
  $handleMatch=$null
  $procMatch=$null
  foreach ($entry in $items) {
    [xml]$x=$entry.ToXml()
    $fields=@{}
    foreach($d in $x.Event.EventData.Data) {$fields[[string]$d.Name]=[string]$d.'#text'}
    if (($entry.Id -eq 4656 -or $entry.Id -eq 4663) -and $null -eq $handleMatch) {
      $objType = [string]$fields['ObjectType']
      $srcPid = [string]$fields['ProcessId']
      $objName = [string]$fields['ObjectName']
      if (($srcPid -ieq 'PARENT_HEX') -and (($objType -match '(?i)process') -or ($objName -match 'CHILD_DEC|CHILD_HEX'))) {
        $handleMatch=@{record_id=$entry.RecordId;event_id=$entry.Id;event_time=$entry.TimeCreated.ToUniversalTime().ToString('o');object_type=$objType;access_mask=$fields['AccessMask']}
      }
    }
    if ($entry.Id -eq 4688 -and $null -eq $procMatch) {
      if ($fields['NewProcessId'] -ieq 'CHILD_HEX' -and $fields['NewProcessName'] -match '(?i)\\cmd\.exe$') {
        $procMatch=@{record_id=$entry.RecordId;event_id=4688;event_time=$entry.TimeCreated.ToUniversalTime().ToString('o');image=$fields['NewProcessName'];pid=$fields['NewProcessId']}
      }
    }
  }
  @{status='ok';events_scanned=$items.Count;truncated=($items.Count -ge 2000);handle_match=$handleMatch;proc_match=$procMatch} | ConvertTo-Json -Compress -Depth 5
} catch {
  if ($_.FullyQualifiedErrorId -like '*NoMatchingEventsFound*' -or $_.Exception.Message -match 'No events were found') {
    @{status='ok';events_scanned=0;truncated=$false;handle_match=$null;proc_match=$null} | ConvertTo-Json -Compress
  } elseif ($_.Exception.Message -match 'Access is denied|UnauthorizedAccess') {
    @{status='access_denied';events_scanned=0;truncated=$false;handle_match=$null;proc_match=$null} | ConvertTo-Json -Compress
  } else {
    @{status='query_error';events_scanned=0;truncated=$false;handle_match=$null;proc_match=$null} | ConvertTo-Json -Compress
  }
}
'''.replace("START_HERE", start_ps).replace("END_HERE", end_ps).replace("PARENT_HEX", hex(parent_pid)).replace("CHILD_HEX", hex(child_pid)).replace("CHILD_DEC", str(child_pid))

    parsed, _ = _run_ps_json(script, timeout=35)
    parsed = parsed or {}
    status = parsed.get("status", "query_error")
    scanned = int(parsed.get("events_scanned", 0) or 0)
    truncated = bool(parsed.get("truncated", False))
    handle_match = parsed.get("handle_match")
    proc_match = parsed.get("proc_match")

    return {
        "mode": "live-windows",
        "start_time": start.isoformat(),
        "end_time": end.isoformat(),
        "canary_completed": canary_completed,
        "process": {
            "parent_pid": parent_pid,
            "child_pid": child_pid,
            "command": "cmd.exe /d /c timeout /t 2 /nobreak >nul",
            "child_returncode": child_rc,
        },
        "handle_opened": handle_opened,
        "handle_access_mask": hex(PROCESS_QUERY_LIMITED_INFORMATION),
        "queried_image": queried_image,
        "handle_win32_error": win32_err,
        "handle_audit_policy": combined_handle_pol,
        "audit_policies": {
            "handle_manipulation": handle_pol,
            "handle_manipulation_note": handle_note,
            "kernel_object": kernel_pol,
            "kernel_object_note": kernel_note,
            "process_creation": proc_pol,
            "process_creation_note": proc_note,
        },
        "query_status": status,
        "query_truncated": truncated,
        "handle_event_matched": bool(handle_match) if status == "ok" else None,
        "process_event_matched": bool(proc_match) if status == "ok" else None,
        "evidence": {
            "source": "Windows Security log",
            "event_ids": [4656, 4663, 4688],
            "events_scanned": scanned,
            "handle_record": handle_match,
            "process_record": proc_match,
        },
        "scope_note": "Read-only PROCESS_QUERY_LIMITED_INFORMATION handle test only; no memory reads/writes or thread injection are performed",
    }


def run_lsa_ssp_audit():
    """Check 4 (MITRE T1547.005): Read-only LSA SSP registry inspection, SACL check, and Registry audit policy."""
    _require_windows()
    collected = datetime.now(timezone.utc).isoformat()
    reg_policy, reg_policy_note = read_audit_subcategory(AUDIT_REGISTRY_GUID, "Audit Registry")

    script = r'''
$ErrorActionPreference='Stop'
$reg = @{status='query_error';security_packages=@();run_as_ppl=$null}
try {
  $props = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction Stop
  $pkgs = if ($props.PSObject.Properties['Security Packages']) { @($props.'Security Packages') } else { @() }
  $ppl = if ($props.PSObject.Properties['RunAsPPL']) { $props.RunAsPPL } else { $null }
  $reg = @{status='ok';security_packages=$pkgs;run_as_ppl=$ppl}
} catch {
  if ($_.Exception.Message -match 'Access is denied|UnauthorizedAccess|Requested registry access is not allowed') { $reg.status='access_denied' }
  else { $reg.status='query_error' }
}

$sacl = @{status='query_error';rule_count=0;rules=@()}
try {
  $acl = Get-Acl -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Audit -ErrorAction Stop
  $auditRules = @($acl.Audit)
  $summary = @()
  foreach ($rule in $auditRules) {
    $summary += @{
      identity=[string]$rule.IdentityReference
      rights=[string]$rule.RegistryRights
      flags=[string]$rule.AuditFlags
    }
  }
  $sacl = @{status='ok';rule_count=$summary.Count;rules=$summary}
} catch {
  if ($_.Exception.Message -match 'PrivilegeNotHeld|SeSecurityPrivilege|Access is denied|UnauthorizedAccess|Requested registry access is not allowed') {
    $sacl.status='access_denied'
  } else {
    $sacl.status='query_error'
  }
}

@{registry=$reg;sacl=$sacl} | ConvertTo-Json -Compress -Depth 6
'''
    parsed, _ = _run_ps_json(script, timeout=30)
    parsed = parsed or {}
    reg = parsed.get("registry") or {}
    sacl = parsed.get("sacl") or {}

    reg_status = reg.get("status", "query_error")
    sacl_status = sacl.get("status", "query_error")
    sacl_rules = sacl.get("rules") if isinstance(sacl.get("rules"), list) else ([] if sacl.get("rules") is None else [sacl.get("rules")])
    sacl_count = int(sacl.get("rule_count", len(sacl_rules)) or 0) if sacl_status == "ok" else None
    sacl_present = (sacl_count > 0) if sacl_status == "ok" and sacl_count is not None else None

    return {
        "mode": "live-windows",
        "collected_at": collected,
        "registry_path": r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "registry_query_status": reg_status,
        "sacl_query_status": sacl_status,
        "audit_registry_policy": reg_policy,
        "audit_registry_policy_note": reg_policy_note,
        "sacl_present": sacl_present,
        "sacl_rule_count": sacl_count,
        "evidence": {
            "security_packages": _as_str_list(reg.get("security_packages")),
            "run_as_ppl_value": reg.get("run_as_ppl"),
            "sacl_rules": sacl_rules,
        },
        "scope_note": "Read-only inspection of LSA registry values, SACL presence, and Audit Registry policy; does not validate whether listed SSP DLLs are trusted",
    }


def run_cmdline_wmi(window_seconds=4):
    """Check 5 (MITRE T1047): Event 4688 command-line auditing + read-only WMI query & WMI-Activity log readability."""
    _require_windows()
    _validate_window(window_seconds)
    policy, policy_note = read_policy()

    # Read command-line auditing registry policy (read-only)
    cmdline_pol_script = r'''
$ErrorActionPreference='Stop'
try {
  $p = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -ErrorAction Stop
  $val = if ($p.PSObject.Properties['ProcessCreationIncludeCmdLine_Enabled']) { $p.ProcessCreationIncludeCmdLine_Enabled } else { $null }
  @{status='ok';value=$val} | ConvertTo-Json -Compress
} catch {
  if ($_.Exception.Message -match 'Cannot find path') { @{status='ok';value=$null} | ConvertTo-Json -Compress }
  elseif ($_.Exception.Message -match 'Access is denied|UnauthorizedAccess') { @{status='access_denied';value=$null} | ConvertTo-Json -Compress }
  else { @{status='query_error';value=$null} | ConvertTo-Json -Compress }
}
'''
    cpol_parsed, _ = _run_ps_json(cmdline_pol_script, timeout=15)
    cpol_parsed = cpol_parsed or {}
    if cpol_parsed.get("status") == "ok":
        cmdline_audit_policy = "enabled" if cpol_parsed.get("value") == 1 else "disabled"
    else:
        cmdline_audit_policy = "unknown"

    start = datetime.now(timezone.utc)
    child = subprocess.Popen(
        [_cmd_exe_path(), "/d", "/c", f"echo {CMDLINE_CANARY_MARKER}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    pid = child.pid
    canary_completed = child.wait(timeout=10) == 0

    # Execute read-only WMI query
    wmi_probe_script = r'''
$ErrorActionPreference='Stop'
try {
  $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop | Select-Object Caption,BuildNumber
  @{completed=$true;caption=$os.Caption;build=$os.BuildNumber} | ConvertTo-Json -Compress
} catch {
  @{completed=$false;error=$_.Exception.GetType().Name} | ConvertTo-Json -Compress
}
'''
    wmi_probe, _ = _run_ps_json(wmi_probe_script, timeout=20)
    wmi_probe = wmi_probe or {}
    wmi_query_completed = bool(wmi_probe.get("completed", False))

    time.sleep(window_seconds)
    end = datetime.now(timezone.utc)

    start_ps = start.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_ps = end.strftime("%Y-%m-%dT%H:%M:%SZ")
    query_script = r'''
$ErrorActionPreference='Stop'
$sec = @{status='query_error';events_scanned=0;truncated=$false;match=$null;cmdline_matched=$false}
try {
  $start=[datetime]::Parse('START_HERE',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime().AddSeconds(-5)
  $end=[datetime]::Parse('END_HERE',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime().AddSeconds(5)
  $items=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688;StartTime=$start;EndTime=$end} -MaxEvents 2000 -ErrorAction Stop)
  $matched=$null
  $cmdOk=$false
  foreach ($entry in $items) {
    [xml]$x=$entry.ToXml()
    $fields=@{}
    foreach($d in $x.Event.EventData.Data) {$fields[[string]$d.Name]=[string]$d.'#text'}
    if ($fields['NewProcessId'] -ieq 'PID_HEX' -and $fields['NewProcessName'] -match '(?i)\\cmd\.exe$') {
      $cmdLine = [string]$fields['CommandLine']
      $cmdOk = ($cmdLine -like '*MARKER_HERE*')
      $matched=@{record_id=$entry.RecordId;event_time=$entry.TimeCreated.ToUniversalTime().ToString('o');image=$fields['NewProcessName'];pid=$fields['NewProcessId'];command_line=$cmdLine}
      break
    }
  }
  $sec = @{status='ok';events_scanned=$items.Count;truncated=($items.Count -ge 2000);match=$matched;cmdline_matched=$cmdOk}
} catch {
  if ($_.FullyQualifiedErrorId -like '*NoMatchingEventsFound*' -or $_.Exception.Message -match 'No events were found') {
    $sec = @{status='ok';events_scanned=0;truncated=$false;match=$null;cmdline_matched=$false}
  } elseif ($_.Exception.Message -match 'Access is denied|UnauthorizedAccess') {
    $sec = @{status='access_denied';events_scanned=0;truncated=$false;match=$null;cmdline_matched=$false}
  }
}

$wmi = @{status='query_error';enabled=$null;readable=$false;events_scanned=0;truncated=$false;record_count=$null}
try {
  $logInfo = Get-WinEvent -ListLog 'Microsoft-Windows-WMI-Activity/Operational' -ErrorAction Stop
  $wmi.enabled = [bool]$logInfo.IsEnabled
  $wmi.record_count = $logInfo.RecordCount
  try {
    $start=[datetime]::Parse('START_HERE',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime().AddSeconds(-5)
    $end=[datetime]::Parse('END_HERE',[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime().AddSeconds(5)
    $wev = @(Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational';StartTime=$start;EndTime=$end} -MaxEvents 2000 -ErrorAction Stop)
    $wmi.status = 'ok'
    $wmi.readable = $true
    $wmi.events_scanned = $wev.Count
    $wmi.truncated = ($wev.Count -ge 2000)
  } catch {
    if ($_.FullyQualifiedErrorId -like '*NoMatchingEventsFound*' -or $_.Exception.Message -match 'No events were found') {
      $wmi.status = 'ok'
      $wmi.readable = $true
      $wmi.events_scanned = 0
      $wmi.truncated = $false
    } elseif ($_.Exception.Message -match 'Access is denied|UnauthorizedAccess') {
      $wmi.status = 'access_denied'
      $wmi.readable = $false
    }
  }
} catch {
  if ($_.Exception.Message -match 'Access is denied|UnauthorizedAccess') { $wmi.status='access_denied' }
}

@{security=$sec;wmi_activity=$wmi} | ConvertTo-Json -Compress -Depth 6
'''.replace("START_HERE", start_ps).replace("END_HERE", end_ps).replace("PID_HEX", hex(pid)).replace("MARKER_HERE", CMDLINE_CANARY_MARKER)

    parsed, _ = _run_ps_json(query_script, timeout=40)
    parsed = parsed or {}
    sec = parsed.get("security") or {}
    wmi = parsed.get("wmi_activity") or {}

    sec_status = sec.get("status", "query_error")
    sec_truncated = bool(sec.get("truncated", False))
    sec_match = sec.get("match")
    wmi_status = wmi.get("status", "query_error")
    wmi_truncated = bool(wmi.get("truncated", False))

    return {
        "mode": "live-windows",
        "start_time": start.isoformat(),
        "end_time": end.isoformat(),
        "canary_completed": canary_completed,
        "wmi_query_completed": wmi_query_completed,
        "process": {
            "image": "cmd.exe",
            "pid": pid,
            "command": f"cmd.exe /d /c echo {CMDLINE_CANARY_MARKER}",
        },
        "audit_policy": policy,
        "audit_policy_note": policy_note,
        "cmdline_audit_policy": cmdline_audit_policy,
        "security_query_status": sec_status,
        "security_truncated": sec_truncated,
        "wmi_log_query_status": wmi_status,
        "wmi_log_truncated": wmi_truncated,
        "matching_event": bool(sec_match) if sec_status == "ok" else None,
        "cmdline_matched": bool(sec.get("cmdline_matched", False)) if sec_status == "ok" else None,
        "wmi_log_enabled": bool(wmi.get("enabled")) if wmi_status == "ok" and wmi.get("enabled") is not None else None,
        "wmi_log_readable": bool(wmi.get("readable")) if wmi_status == "ok" else None,
        "evidence": {
            "security_events_scanned": int(sec.get("events_scanned", 0) or 0),
            "matched_4688_record": sec_match,
            "wmi_probe_os": wmi_probe.get("caption"),
            "wmi_probe_build": wmi_probe.get("build"),
            "wmi_activity_log": "Microsoft-Windows-WMI-Activity/Operational",
            "wmi_events_scanned": int(wmi.get("events_scanned", 0) or 0),
            "wmi_record_count": wmi.get("record_count"),
        },
        "scope_note": "Verifies one Event 4688 command-line observation and WMI-Activity/Operational readability; does not verify full WMI attack detection",
    }


def run_all_internals_checks(window_seconds=4, selected=None):
    """Execute all 5 safe Windows Internals checks (or a selected subset) and return (slug, test_id, observation)."""
    _require_windows()
    _validate_window(window_seconds)
    runners = [
        ("etw-integrity", "WIN-ETW-INTEGRITY", lambda: run_etw_integrity(window_seconds=window_seconds)),
        ("kernel-ppl-hvci", "WIN-KERNEL-PPL-HVCI", run_kernel_ppl_hvci),
        ("xproc-handle", "WIN-XPROC-HANDLE", lambda: run_xproc_handle(window_seconds=window_seconds)),
        ("lsa-ssp-audit", "WIN-LSA-SSP-AUDIT", run_lsa_ssp_audit),
        ("cmdline-wmi", "WIN-CMDLINE-WMI", lambda: run_cmdline_wmi(window_seconds=window_seconds)),
    ]
    if selected:
        wanted = {s.strip().lower() for s in selected if s.strip()}
        runners = [item for item in runners if item[0].lower() in wanted or item[1].lower() in wanted]
        if not runners:
            raise ValueError(f"No matching checks for: {', '.join(selected)}")
    results = []
    for slug, test_id, fn in runners:
        results.append((slug, test_id, fn()))
    return results

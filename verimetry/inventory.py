"""Best-effort Windows-native, read-only inventory. No simulated values or security changes."""
from __future__ import annotations
import json
import platform
import subprocess
from datetime import datetime, timezone

SCRIPT = r'''
$ErrorActionPreference = 'Stop'
$sections = @{}
function ReadSection([string]$name,[scriptblock]$body) {
  try { $sections[$name] = @{status='observed'; data=(& $body)} }
  catch { $sections[$name] = @{status='unavailable'; error_type=$_.Exception.GetType().Name} }
}
ReadSection 'os' { Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture,LastBootUpTime }
ReadSection 'defender' { Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,AntispywareEnabled,AMServiceEnabled,AntivirusSignatureLastUpdated }
ReadSection 'firewall' { @(Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction) }
ReadSection 'hotfixes' { @(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 HotFixID,InstalledOn,Description) }
ReadSection 'audit_process_creation' { & auditpol /get '/subcategory:{0cce922b-69ae-11d9-bed3-505054503030}' /r | Out-String }
$sections | ConvertTo-Json -Depth 8 -Compress
'''

def collect():
    if platform.system() != 'Windows':
        raise OSError('Actual host collection requires Windows')
    collected = datetime.now(timezone.utc).isoformat()
    try:
        proc = subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',SCRIPT], capture_output=True, text=True, errors='replace', timeout=45, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        if proc.returncode != 0:
            return {'kind':'real-windows-inventory','collected_at':collected,'status':'unavailable','error':'PowerShell failed'}
        result=json.loads(proc.stdout)
        if not isinstance(result,dict):
            raise ValueError('Unexpected object')
        return {'kind':'real-windows-inventory','collected_at':collected,'status':'observed','sections':result,'interpretation':'Read-only observations, not a vulnerability scan or control compliance verdict'}
    except (OSError, subprocess.TimeoutExpired, ValueError, json.JSONDecodeError):
        return {'kind':'real-windows-inventory','collected_at':collected,'status':'unavailable','error':'Collector could not complete'}

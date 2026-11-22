# Verimetry — REAL Windows test (not a fictional simulation)

**This project has two separate modes.** `demo` is synthetic and **does not test Windows**. For an honest assessment of your own machine, use `inspect` and `assess` below. No software can guarantee a PASS: **PASS**, **FAIL**, and **INCONCLUSIVE** are all valid real outcomes.

## 1. Test environment

Use a Windows 10/11 or Windows Server sandbox/VM you own or have written authorization to assess. Make a VM snapshot first. The commands below use **only built-in Windows OS components** (no Sysmon, no third-party drivers, no network traffic) and do not modify audit policies, registry keys, services, or patches.

> **Privilege note:** Running from a standard (non-elevated) PowerShell terminal is safe and supported, but Windows restricts reading Security Event Logs, `auditpol`, ETW trace sessions, and registry SACLs (`SeSecurityPrivilege`) to elevated Administrator sessions. Any check whose required OS telemetry cannot be read cleanly will return **INCONCLUSIVE** rather than a false failure.

## 2. Setup (PowerShell in the `verimetry` directory)

Install Python 3.11+, then:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
```

## 3. Read the REAL machine state (no canaries)

```powershell
.\.venv\Scripts\python.exe -m verimetry inspect --out .\evidence\windows-inventory.json
start .\evidence\inventory-report.html
```

This queries actual Windows OS info, Defender, firewall profiles, recent Windows hotfix records, and process-creation audit policy, and builds a two-tab local HTML report (**Plain English** + **Technical evidence (JSON)**).

## 4. Assess all 5 Windows Internals telemetry & readiness checks

```powershell
.\.venv\Scripts\python.exe -m verimetry assess --out .\evidence
start .\evidence\report.html
```

To run a specific subset of checks, pass `--checks` (comma-separated slugs or test IDs):

```powershell
.\.venv\Scripts\python.exe -m verimetry assess --out .\evidence --checks etw-integrity,kernel-ppl-hvci,cmdline-wmi
```

`assess` runs `inspect` plus all 5 non-destructive checks:

1. **`etw-integrity` (`WIN-ETW-INTEGRITY` · MITRE T1562.006):** Queries active ETW sessions (`EventLog-System`, `DiagTrack-Listener`) and emits one benign EventLog/ETW marker event to confirm pipeline delivery.
2. **`kernel-ppl-hvci` (`WIN-KERNEL-PPL-HVCI` · MITRE T1068 / T1562.001):** Inspects `Win32_DeviceGuard` (VBS/HVCI), `RunAsPPL`, and `Microsoft-Windows-CodeIntegrity/Operational` log readability.
3. **`xproc-handle` (`WIN-XPROC-HANDLE` · MITRE T1106 / T1055):** Spawns `cmd.exe /d /c timeout /t 2 /nobreak >nul`, opens a read-only `PROCESS_QUERY_LIMITED_INFORMATION` handle via `ctypes`/`kernel32`, closes it, and checks handle/process Security log visibility.
4. **`lsa-ssp-audit` (`WIN-LSA-SSP-AUDIT` · MITRE T1547.005):** Reads `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` (`Security Packages`, `RunAsPPL`), inspects SACLs (`Get-Acl -Audit`), and checks `Audit Registry` policy (`auditpol`).
5. **`cmdline-wmi` (`WIN-CMDLINE-WMI` · MITRE T1047):** Runs `cmd.exe /d /c echo VERIMETRY_CANARY_PING` and `Get-CimInstance Win32_OperatingSystem`, verifying Event 4688 command-line capture and `Microsoft-Windows-WMI-Activity/Operational` log readability.

Outputs written to `--out`:
- `receipt-etw-integrity.json`, `receipt-kernel-ppl-hvci.json`, `receipt-xproc-handle.json`, `receipt-lsa-ssp-audit.json`, `receipt-cmdline-wmi.json`
- `signer.pem` (keep private!) and `signer.pub.pem` (share out-of-band for verification)
- `report.html` (static local verdict report)
- `windows-inventory.json` and `inventory-report.html`
- `oscal-draft.json` (experimental, unvalidated OSCAL 1.1.3 draft)

## 5. Independently check any receipt

```powershell
.\.venv\Scripts\python.exe -m verimetry verify --receipt .\evidence\receipt-cmdline-wmi.json --public .\evidence\signer.pub.pem
```

Verify the public key's identity by an independent channel before trusting who issued a receipt. Do not share `signer.pem`.

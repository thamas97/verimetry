---
name: New Non-Destructive Canary Check
about: Propose a new MITRE ATT&CK Windows Internals canary check for Verimetry
title: "[Canary] WIN-<ID>: <Short Title> (T<XXXX>)"
labels: enhancement, canary
---

## MITRE ATT&CK Mapping
- **Technique / Sub-Technique ID:** (e.g., `T1685.001`, `T1562.006`)
- **NIST SP 800-53 Rev.5 OSCAL Controls:** (e.g., `si-7`, `au-9`, `au-12`)

## Non-Destructive Canary Design
Describe the strictly read-only or benign, self-contained Windows OS primitive used (zero third-party drivers, zero credential access, zero permanent host mutations):
- **Built-in Windows APIs / Commands:** (e.g., `OpenSCManagerW`, `FilterFindFirst`, `FSCTL_QUERY_USN_JOURNAL`, `bcdedit /enum {current}`)

## Three-Valued Evidence Gate Criteria
- **`PASS` (Verified Telemetry / Control):**
- **`FAIL` (Confirmed Gap Under Verified Prerequisites):**
- **`INCONCLUSIVE` (Missing Privilege / Truncation / Unconfigured Prerequisite):**

## Copyable MSSP Remediation Command
```powershell
# Exact auditable remediation command for the MSSP Operations View
```

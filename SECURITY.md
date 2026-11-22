# Security Policy & Non-Destructive Canary Guarantee

## Non-Destructive Execution Policy

Verimetry is strictly scoped to **read-only host inspection** and **benign, bounded local telemetry canaries** using built-in Windows OS components (`kernel32.dll`, WMI/CIM, Registry, `auditpol`, `wevtutil`, `Get-WinEvent`, `logman`).

Verimetry explicitly **does not**:
- Install third-party kernel drivers, Sysmon binaries, or resident background daemons.
- Modify host audit policies, registry keys, firewall rules, or Boot Configuration Data during `inspect`, `assess`, `compare`, or `verify`.
- Read or write remote process memory, inject threads, dump credentials, clear logs, or transmit telemetry to external cloud servers.

## Trust Boundary & Verification Limitations

We publish our security boundaries openly so auditors, engineers, and MSSPs can reason accurately about every receipt:
1. **Scoped Point-in-Time Proof:** A `PASS` receipt proves only that a specific narrow canary observation arrived within the bounded observation window. It does not guarantee comprehensive endpoint defense or compliance certification.
2. **Local Collector / Signer Trust Boundary:** When running locally on an endpoint, the collector and Ed25519 signer share the host trust boundary. An Ed25519 signature authenticates post-collection integrity and deterministic verdict reproducibility; enterprise deployments must distribute and pin verifier public keys out-of-band.
3. **Private Key Hygiene:** Never commit `signer.pem` or any Ed25519 private key file to source control or share it alongside evidence bundles. Only share `.pub.pem` public keys over a trusted channel.

## Reporting a Vulnerability

If you discover a bug in Verimetry's deterministic decision logic, cryptographic receipt verification (`verimetry/receipts.py`), HTML escaping (`verimetry/report.py`), or PowerShell command parameterization (`verimetry/windows.py`):
- Please open a private GitHub Security Advisory on this repository or contact the maintainers directly before public disclosure.
- Include a minimal reproduction receipt JSON or test case so we can add a regression test to `tests/test_verimetry.py`.

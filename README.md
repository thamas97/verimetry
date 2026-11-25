# Verimetry — Evidence Before Assurance

![Tests](https://img.shields.io/badge/tests-65%20passing-10b981?style=flat-square)
![Python](https://img.shields.io/badge/python-3.11%2B-38bdf8?style=flat-square)
![Runtime Dependencies](https://img.shields.io/badge/runtime%20deps-1%20(cryptography)-6366f1?style=flat-square)
![Drivers](https://img.shields.io/badge/kernel%20drivers-0-10b981?style=flat-square)
![Envelope](https://img.shields.io/badge/envelope-DSSE%20v1%20Ed25519-0ea5e9?style=flat-square)
![License](https://img.shields.io/badge/license-Apache--2.0-10b981?style=flat-square)

**Local-first, zero-driver Windows Internals telemetry assurance with evidence-gated three-valued logic (`PASS`, `FAIL`, `INCONCLUSIVE`), offline-verifiable DSSE v1 Ed25519 receipts, locale-independent `advapi32!AuditQuerySystemPolicy` queries, and multi-run delta comparisons (`verimetry compare`).**

> **Why Verimetry exists:** According to *Mandiant M-Trends 2026*, organizations detect intrusions internally only **52%** of the time (**48%** learn from an external party) and median attacker hand-off time dropped to **22 seconds**, while *IBM's 2026 Cost of a Data Breach Report* puts average breach identification and containment at **247 days** (**\$4.99M**). On standard Windows builds, Event `4688` command-line logging, LSA registry SACLs (`T1547.005`), and cross-process handle auditing (`4656`/`4663`) are **off by default**—and domain Group Policy refreshes every **90 minutes**, silently creating telemetry drift without crashing any endpoint agent.

---

## Try It Now (30-Second Quickstart)

### Option 1: Interactive Browser Sandbox (Zero Install)
Open [`docs/sandbox.html`](./docs/sandbox.html) (or GitHub Pages) to replay real Windows 11 (`Tha`) runs, switch **Customer View ↔ MSSP Operations View**, and trigger the live **DSSE SHA-256 / Ed25519 Tamper Trap**.

### Option 2: Verify the Pre-Built DSSE v1 Sample Receipt & Golden Test Vectors Offline
```bash
python3 -m pip install -e ".[dev]"
pytest -q                                              # 65/65 tests passing (incl. test_vectors/)
python3 -m verimetry verify \
  --receipt ./docs/sample-pack/sample-comparison-receipt.json \
  --public ./docs/sample-pack/sample-signer.pub.pem \
  --show
```
Building a Go, Rust, or TypeScript verifier? See the 8 golden pass/fail DSSE conformance vectors in [`test_vectors/`](./test_vectors/README.md).

---

## 2-Minute Live Windows Test (Non-Elevated → Elevated Delta)

Run inside a disposable test VM or a Windows 10/11 / Server host you are authorized to assess (after one-time setup: `py -3 -m venv .venv; .\.venv\Scripts\Activate.ps1; python -m pip install -e .`):

- **Step 1 (Standard user, zero risk):** Generate a local Ed25519 keypair (`keygen --private`) and run `verimetry assess` non-elevated to verify privilege-gated checks cleanly output `INCONCLUSIVE` instead of fabricating `FAIL`s or crashing.
- **Step 2 (Elevated on a test VM or lab host):** Run `verimetry assess` as Administrator, then run `verimetry compare` against Step 1 (and `verimetry verify`) to watch `INCONCLUSIVE` burn down and real host telemetry gaps surface—backed by an offline-verifiable DSSE v1 receipt (and dual-persona HTML report at `.\evidence-comparison\comparison-report.html`).

```powershell
# Step 1 (Standard user, zero risk — observe honest INCONCLUSIVE gates):
python -m verimetry keygen --private .\verimetry-key.pem
python -m verimetry assess --out .\evidence --key .\verimetry-key.pem

# Step 2 (Elevated Administrator PowerShell on a test VM or lab host):
python -m verimetry assess --out .\evidence-elevated --key .\verimetry-key.pem
python -m verimetry compare --before .\evidence --after .\evidence-elevated --out .\evidence-comparison --key .\verimetry-key.pem --public .\verimetry-key.pub.pem
python -m verimetry verify --receipt .\evidence-comparison\comparison-receipt.json --public .\verimetry-key.pub.pem --show
```

> **Safety & privacy guarantee:** Verimetry is strictly read-only, installs `0` kernel drivers or daemons, makes `0` host mutations, and one-way hashes local host identifiers into `host_fingerprint_sha256`. Hit an edge case on a localized OS, third-party EDR, or nested VM? Share your verdict counts in the [pinned `v1.0.0` Live Fleet Test issue](https://github.com/thamas97/verimetry/issues/1).

---

## Real Windows 11 Empirical Result (Host: `Tha`)

| Assessment Run | `PASS` | `FAIL` | `INCONCLUSIVE` | Key Finding |
| :--- | :---: | :---: | :---: | :--- |
| **Non-Elevated (`.\evidence`)** | `1/5` (`20%`) | `0` | `4/5` | Confirmed `WIN-KERNEL-PPL-HVCI = PASS`; gated 4 privilege-dependent checks as `INCONCLUSIVE` (**0 fabricated failures**). |
| **Elevated Admin (`.\evidence-elevated`)** | `1/5` (`20%`) | `2/5` | `2/5` | **50% `INCONCLUSIVE` burn-down** (`4 -> 2`); exposed **2 genuine blind spots**: inactive `DiagTrack-Listener` ETW (`T1562.006`) and missing LSA Registry auditing/SACLs (`T1547.005`), while keeping unconfigured `4688` & Handle policies accurately gated as `INCONCLUSIVE`. |

Open [`docs/sample-comparison-report.html`](./docs/sample-comparison-report.html) to inspect the signed **Customer View** and **MSSP Operations View** generated from this exact transition.

---

## Core Architecture: 5 Live Canaries + 7 `T1685` Scenarios

### 5 Live Windows Internals Canaries (`verimetry assess`)
1. **`WIN-ETW-INTEGRITY`** (`T1562.006`) — Enumerates active ETW sessions (`EventLog-System`, `DiagTrack-Listener`) and verifies delivery of a benign marker in the `Application` log.
2. **`WIN-KERNEL-PPL-HVCI`** (`T1068` / `T1562.001`) — Inspects `Win32_DeviceGuard` (VBS/HVCI), `HKLM\...\Control\Lsa\RunAsPPL`, and `CodeIntegrity/Operational` log readability.
3. **`WIN-XPROC-HANDLE`** (`T1106` / `T1055`) — Opens a strictly read-only `PROCESS_QUERY_LIMITED_INFORMATION (0x1000)` handle via `kernel32.OpenProcess` to a harmless child process and checks Security Event `4656`/`4663`.
4. **`WIN-LSA-SSP-AUDIT`** (`T1547.005`) — Read-only inspection of `HKLM\...\Control\Lsa` (`Security Packages`, `RunAsPPL`), Registry SACLs (`SeSecurityPrivilege`), and `Audit Registry` policy.
5. **`WIN-CMDLINE-WMI`** (`T1047`) — Runs `cmd.exe /d /c echo VERIMETRY_CANARY_PING` + read-only WMI query, verifying Event `4688` command-line capture (`ProcessCreationIncludeCmdLine_Enabled`) and `WMI-Activity/Operational` readability.

### 7 Structured `T1685` (Disable or Modify Tools) Assurance Scenarios (`demo --suite t1685`)
Deterministic rules, NIST SP 800-53 OSCAL mappings, dual-persona playbooks, and synthetic fixtures are implemented for `T1685.001` (EDR/Minifilter DACLs), `T1685.002` (Cloud/Hybrid Audit Log Pipeline), `T1685.003` (`ntdll!NtTraceEvent` ETW Syscall Stubs), `T1685.004` (Host Firewall & WFP Filters), `T1685.005` (NTFS USN Journal & `.evtx` Monotonicity), `T1685.006` (VBS / VTL 1 BCD Downgrade Drift), and `T1685.007` (Safe Mode Boot Tampering). See [`docs/architecture.md`](./docs/architecture.md).

---

## Non-Destructive Guarantee & Explicit Boundaries

- **Zero host mutations:** `inspect`, `assess`, `compare`, and `verify` never modify registry keys, audit policies, firewall rules, or BCD entries, and install `0` kernel drivers or background daemons.
- **Scoped point-in-time proof:** A `PASS` receipt covers only its recorded bounded observation window—not comprehensive endpoint security or formal compliance certification.
- **Local trust boundary:** Local collection and Ed25519 signing share a host trust boundary. Signatures verify post-collection integrity and deterministic rule evaluation; pin `.pub.pem` keys out-of-band in production.
- **Experimental OSCAL:** `oscal-draft.json` is an experimental NIST SP 800-53 Rev.5 mapping and is not schema-validated OSCAL.
- **Synthetic transparency:** `demo` receipts are always marked `"mode": "simulation"` and `"simulated": true`.

---

## Open Roadmap (`good first issue` Contributors Welcome)

- [ ] Wire live `OpenSCManagerW` / `fltmc` collector in `verimetry/windows.py` for `WIN-T1685-001-EDR-MINIFILTER`
- [ ] Wire live `FSCTL_QUERY_USN_JOURNAL` continuity collector for `WIN-T1685-005-USN-EVTX`
- [ ] Wire live `bcdedit /enum {current}` VTL 1 & SafeBoot drift collectors for `WIN-T1685-006` & `WIN-T1685-007`

License: [Apache-2.0](./LICENSE) ([NOTICE](./NOTICE)) · Security Policy: [SECURITY.md](./SECURITY.md)

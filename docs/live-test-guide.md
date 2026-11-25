# Live Windows Test Guide & Teaching Notes (`v1.0.0`)

Use this guide when running your first live **Verimetry** assessment on a Windows 10/11 or Windows Server machine (or teaching a teammate step-by-step). Every command uses **zero extra dependencies** beyond `cryptography`—including the native Tkinter desktop GUI (`python -m verimetry gui`).

---

## 0. Ground Rules & Safety Guarantees (30 Seconds)

Before starting, confirm three facts:

1. **Windows-only for live host checks:** `assess` and `inspect` require Windows 10/11 or Windows Server. On Linux/macOS, `python -m verimetry gui` automatically runs in **Demo Mode** (synthetic Windows Internals suite) so you can still preview the 3-step workflow.
2. **Strictly read-only & zero-driver:** Verimetry installs **`0` kernel drivers**, **`0` background services/daemons**, makes **`0` outbound network calls**, and **never modifies** registry keys, audit policies, firewall rules, or BCD entries.
   - The only active actions during `assess` are 3 tiny, harmless local canaries:
     - Emit one informational `VERIMETRY_ETW_MARKER_*` entry to the local `Application` log (no registry source registration).
     - Spawn `cmd.exe /d /c timeout /t 2 /nobreak >nul`, open a strictly read-only `PROCESS_QUERY_LIMITED_INFORMATION (0x1000)` handle via `kernel32.OpenProcess`, and immediately close it (no memory reads/writes or injection).
     - Spawn `cmd.exe /d /c echo VERIMETRY_CANARY_PING` + a read-only `Get-CimInstance Win32_OperatingSystem` WMI query.
3. **Every outcome is honest:** `PASS`, `FAIL`, and `INCONCLUSIVE` are all normal, valid findings—especially on a stock Windows build.

---

## 1. One-Time Setup (Standard PowerShell)

Run inside a disposable lab VM or a Windows host you are authorized to assess:

```powershell
git clone --branch v1.0.0 https://github.com/thamas97/verimetry.git
cd verimetry
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

> **Gotcha #1 — PowerShell Execution Policy:** If `Activate.ps1` fails with *"running scripts is disabled on this system"*, **do not** loosen global execution policy. Either scope it to that single terminal (`Set-ExecutionPolicy -Scope Process Bypass`) or skip activation and prefix commands with `.\.venv\Scripts\python.exe -m verimetry ...`.

---

## 2. Side-by-Side Walkthrough: Track A (GUI) vs. Track B (PowerShell CLI)

| Stage | Track A — Native GUI (1-Click Visual Flow) | Track B — PowerShell CLI Flow |
| :--- | :--- | :--- |
| **Launch / Setup** | Run **`python -m verimetry gui`** (or `verimetry-gui`). Verify the top-right badge shows **`Standard User (Non-Elevated)`** and the green read-only banner is visible. | Stay in your standard (non-Administrator) PowerShell window in the `verimetry` folder. |
| **Step 1: Non-Elevated Baseline (`INCONCLUSIVE` Demo)** | In **Step 1 · Standard User Baseline**, click **Run Non-Elevated Assess**. The GUI auto-generates `.\verimetry-key.pem` via `init_keys()`, runs `assess` on a background thread into `.\evidence`, and renders color-coded `PASS` / `FAIL` / `INCONCLUSIVE` badges. | `python -m verimetry keygen --private .\verimetry-key.pem`<br>`python -m verimetry assess --out .\evidence --key .\verimetry-key.pem` |
| **Step 2: Elevate & Delta Compare** | Switch to **Step 2 · Elevated Assess & Compare** and click **Relaunch as Administrator (UAC)**. Once the elevated window opens (with Step 1 baseline auto-loaded), click **Run Elevated Assess & Compare**, then click **Open Dual-Persona HTML Report**. | Open an **Administrator PowerShell** in the same folder, then run:<br>`python -m verimetry assess --out .\evidence-elevated --key .\verimetry-key.pem`<br>`python -m verimetry compare --before .\evidence --after .\evidence-elevated --out .\evidence-comparison --key .\verimetry-key.pem --public .\verimetry-key.pub.pem`<br>`start .\evidence-comparison\comparison-report.html` |
| **Step 3: Offline Verify & Tamper Trap** | Switch to **Step 3 · Offline Verify & Tamper Trap** (receipt & `.pub.pem` auto-filled). Click **Verify Offline** to confirm `VERIFIED`, then click **Test Tamper Trap** to copy to `.\forged.json`, flip 1 payload byte, and watch `verify()` return fail-closed **`REJECTED`**. | `python -m verimetry verify --receipt .\evidence-comparison\comparison-receipt.json --public .\verimetry-key.pub.pem --show`<br>*(Tamper test: copy a receipt to `.\forged.json`, alter 1 character in `"payload"`, re-run `verify` → `REJECTED`.)* |
| **Share Edge Cases (Issue #1)** | Click **Copy Anonymized Summary for Issue #1** (copies the 5-line template with hostnames and private keys stripped), then click **Open Issue #1** and paste. | Fill in the 5-line template in [Issue #1](https://github.com/thamas97/verimetry/issues/1) (strip hostnames before posting; `host_fingerprint_sha256` is already hashed). |
| **Clean Teardown** | Click **Clean Up Local Evidence** and confirm the dialog (`.\evidence*`, `.\verimetry-key*.pem`, and `.\forged.json` are removed cleanly). | `Remove-Item -Recurse -Force .\evidence, .\evidence-elevated, .\evidence-comparison, .\verimetry-key.pem, .\verimetry-key.pub.pem, .\forged.json -ErrorAction SilentlyContinue` |

---

## 3. Teaching Moments: Reading Verdicts Without Guessing

### Why Step 1 (Non-Elevated) Shows `INCONCLUSIVE`
- **`WIN-KERNEL-PPL-HVCI`** can usually read `Win32_DeviceGuard`, `RunAsPPL`, and `CodeIntegrity/Operational` as a standard user, so it often reports a real **`PASS` or `FAIL`**.
- The remaining 4 checks (**`WIN-ETW-INTEGRITY`**, **`WIN-XPROC-HANDLE`**, **`WIN-LSA-SSP-AUDIT`**, **`WIN-CMDLINE-WMI`**) require Administrator / `SeSecurityPrivilege` to query ETW trace sessions, `advapi32!AuditQuerySystemPolicy`, Security Event Logs, or LSA registry SACLs—so they gate cleanly to **`INCONCLUSIVE`**.
- **Lesson:** Most binary tools silently pass green or spam false failures when deprived of visibility. Verimetry refuses to fabricate a verdict when prerequisites cannot be verified.

### Why Step 2 (Elevated) Still Leaves Some Checks `INCONCLUSIVE`
Even as Administrator, stock Windows disables two key audit policies by default:
- **Audit Process Creation** → `WIN-CMDLINE-WMI` stays `INCONCLUSIVE` rather than falsely claiming Event `4688` broke.
- **Audit Handle Manipulation / Kernel Object** → `WIN-XPROC-HANDLE` stays `INCONCLUSIVE` until enabled.
- Meanwhile, checks whose prerequisites *are* readable (such as `DiagTrack-Listener` ETW or `HKLM\...\Control\Lsa` SACLs) transition from **`INCONCLUSIVE → FAIL`** (or **`PASS`**), giving you **INCONCLUSIVE burn-down** and real, actionable telemetry gaps.

### Exploring the Dual-Persona HTML Report (`comparison-report.html`)
Have learners toggle between **Customer View** (plain-English coverage proof and cryptographic verification badge) and **MSSP Operations View** (root-cause evidence gates and copy-paste `auditpol` / PowerShell remediation snippets).

---

## 4. Common Windows Gotchas & Troubleshooting

- **Different Elevated Admin SID (`PermissionError` on `verimetry-key.pem`):**
  `keygen` hardens `verimetry-key.pem` with locale-independent NTFS SID ACLs (`icacls /inheritance:r /grant:r *<SID>:(R,W) *S-1-5-18:(F)`). Standard UAC elevation on the same account keeps the same User SID and works seamlessly. If you elevate with a **separate** Admin account:
  - **Track A (GUI):** Handled automatically—Step 2 catches `PermissionError` and falls back cleanly to per-folder `signer.pem` + `--before-public` / `--after-public` on `compare`.
  - **Track B (CLI):** Omit `--key` on both `assess` runs and pass `--before-public .\evidence\signer.pub.pem --after-public .\evidence-elevated\signer.pub.pem` to `compare`.
- **Missing `--public` on CLI `compare`:** Whenever `assess` was run with an external `--key .\verimetry-key.pem`, no `signer.pub.pem` exists inside `.\evidence`, so `compare` must pass `--public .\verimetry-key.pub.pem`.
- **Slow VM or busy Security Event Log:** If a canary event arrives slowly on an overloaded VM, raise the observation window (GUI spinbox or CLI `--window 10`, valid range `1..15`, default `4`). To re-test a single check quickly in CLI, pass `--checks etw-integrity,lsa-ssp-audit`.
- **Privacy before sharing:** Never share `verimetry-key.pem` or `signer.pem`. `host_fingerprint_sha256` is already one-way SHA-256 hashed, but `target.host` in raw JSON/HTML still contains the local machine name—use the GUI's **Copy Anonymized Summary for Issue #1** button or strip hostnames manually before posting to [Issue #1](https://github.com/thamas97/verimetry/issues/1).

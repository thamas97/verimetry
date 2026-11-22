"""Static, self-contained HTML reports with OpenRouter-inspired aesthetic, Dark/Light theme, and Customer vs. MSSP role switcher."""
from __future__ import annotations
from html import escape
import json
from pathlib import Path
import re
from . import __version__
from .receipts import extract_receipt
from .compare import bps_to_pct_str

_MITRE_ID_RE = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
VALID_PERSONAS = ("customer", "mssp", "both")

_OPENROUTER_DESIGN_CSS = """
:root, [data-theme="dark"] {
  color-scheme: dark;
  --bg: #090a0f;
  --bg-elev: #10131c;
  --bg-card: #121621;
  --bg-subtle: #181d2c;
  --bg-code: #0b0e16;
  --border: #232a3d;
  --border-strong: #323c56;
  --text: #f1f5f9;
  --text-muted: #94a3b8;
  --text-dim: #64748b;
  --accent: #6366f1;
  --accent-soft: rgba(99, 102, 241, 0.14);
  --cyan: #38bdf8;
  --cyan-soft: rgba(56, 189, 248, 0.12);
  --pass: #10b981;
  --pass-soft: rgba(16, 185, 129, 0.13);
  --pass-border: rgba(16, 185, 129, 0.38);
  --fail: #f43f5e;
  --fail-soft: rgba(244, 63, 94, 0.13);
  --fail-border: rgba(244, 63, 94, 0.38);
  --inc: #f59e0b;
  --inc-soft: rgba(245, 158, 11, 0.13);
  --inc-border: rgba(245, 158, 11, 0.38);
  --shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
}
[data-theme="light"] {
  color-scheme: light;
  --bg: #f8fafc;
  --bg-elev: #ffffff;
  --bg-card: #ffffff;
  --bg-subtle: #f1f5f9;
  --bg-code: #f1f5f9;
  --border: #e2e8f0;
  --border-strong: #cbd5e1;
  --text: #0f172a;
  --text-muted: #475569;
  --text-dim: #64748b;
  --accent: #4f46e5;
  --accent-soft: rgba(79, 70, 229, 0.09);
  --cyan: #0284c7;
  --cyan-soft: rgba(2, 132, 199, 0.09);
  --pass: #059669;
  --pass-soft: rgba(5, 150, 105, 0.1);
  --pass-border: rgba(5, 150, 105, 0.35);
  --fail: #e11d48;
  --fail-soft: rgba(225, 29, 72, 0.1);
  --fail-border: rgba(225, 29, 72, 0.35);
  --inc: #d97706;
  --inc-soft: rgba(217, 119, 6, 0.1);
  --inc-border: rgba(217, 119, 6, 0.35);
  --shadow: 0 4px 16px rgba(15, 23, 42, 0.06);
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font: 14.5px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, Roboto, sans-serif;
  -webkit-font-smoothing: antialiased;
}
code, pre, .mono {
  font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  font-variant-numeric: tabular-nums;
}
.topbar {
  position: sticky;
  top: 0;
  z-index: 40;
  background: var(--bg-elev);
  border-bottom: 1px solid var(--border);
  padding: 12px 24px;
}
.topbar-inner {
  max-width: 1280px;
  margin: 0 auto;
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
}
.brand {
  display: flex;
  align-items: center;
  gap: 10px;
}
.brand-dot {
  width: 10px;
  height: 10px;
  border-radius: 999px;
  background: linear-gradient(135deg, var(--accent), var(--cyan));
  box-shadow: 0 0 12px var(--accent);
}
.brand-name {
  font-weight: 800;
  letter-spacing: 0.08em;
  font-size: 13px;
  text-transform: uppercase;
}
.brand-tag {
  font-size: 12px;
  color: var(--text-muted);
  padding: 2px 8px;
  border-radius: 6px;
  background: var(--bg-subtle);
  border: 1px solid var(--border);
}
.controls-bar {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.role-switcher {
  display: inline-flex;
  background: var(--bg-subtle);
  border: 1px solid var(--border);
  border-radius: 9px;
  padding: 3px;
  gap: 3px;
}
.role- switcher label, .role-btn {
  cursor: pointer;
  padding: 6px 13px;
  border-radius: 6px;
  font-size: 12.5px;
  font-weight: 600;
  color: var(--text-muted);
  user-select: none;
  transition: all 0.15s ease;
  border: none;
  background: transparent;
}
.role-btn:hover {
  color: var(--text);
}
.theme-btn, .copy-btn {
  cursor: pointer;
  padding: 6px 12px;
  border-radius: 8px;
  font-size: 12px;
  font-weight: 600;
  color: var(--text);
  background: var(--bg-subtle);
  border: 1px solid var(--border);
  transition: all 0.15s ease;
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.theme-btn:hover, .copy-btn:hover {
  border-color: var(--border-strong);
  background: var(--accent-soft);
}
main {
  max-width: 1280px;
  margin: 0 auto;
  padding: 28px 24px 60px;
}
.view-radio {
  position: absolute;
  opacity: 0;
  pointer-events: none;
}
#role-customer:checked ~ .topbar label[for="role-customer"],
#role-mssp:checked ~ .topbar label[for="role-mssp"],
#plain:checked ~ .topbar label[for="plain"],
#technical:checked ~ .topbar label[for="technical"] {
  background: var(--bg-card);
  color: var(--text);
  box-shadow: 0 1px 3px rgba(0,0,0,0.2);
  border: 1px solid var(--border-strong);
}
.role-panel { display: none; }
#role-customer:checked ~ main .panel-customer,
#role-mssp:checked ~ main .panel-mssp,
#plain:checked ~ main .panel-customer,
#technical:checked ~ main .panel-mssp {
  display: block;
}
.trust-hero {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 24px;
  margin-bottom: 22px;
  box-shadow: var(--shadow);
}
.trust-top {
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  align-items: flex-start;
  gap: 18px;
  margin-bottom: 18px;
}
.trust-title h1 {
  margin: 6px 0 8px;
  font-size: clamp(22px, 3.2vw, 32px);
  letter-spacing: -0.02em;
  line-height: 1.2;
}
.trust-title p {
  margin: 0;
  color: var(--text-muted);
  max-width: 780px;
}
.eyebrow {
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: var(--cyan);
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
}
.score-box {
  background: var(--bg-subtle);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 14px 18px;
  min-width: 210px;
  text-align: right;
}
.score-box .score-lbl {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--text-muted);
}
.score-box .score-num {
  font-size: 30px;
  font-weight: 800;
  font-variant-numeric: tabular-nums;
  line-height: 1.15;
  margin: 4px 0;
}
.trust-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: center;
  padding-top: 16px;
  border-top: 1px solid var(--border);
  font-size: 12.5px;
  color: var(--text-muted);
}
.meta-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  background: var(--bg-subtle);
  border: 1px solid var(--border);
  border-radius: 7px;
}
.sig-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  border-radius: 7px;
  background: var(--pass-soft);
  border: 1px solid var(--pass-border);
  color: var(--pass);
  font-weight: 700;
  font-size: 12px;
}
.sparkbar {
  height: 8px;
  width: 100%;
  background: var(--bg-subtle);
  border-radius: 999px;
  overflow: hidden;
  display: flex;
  margin: 14px 0 6px;
  border: 1px solid var(--border);
}
.spark-seg.pass { background: var(--pass); }
.spark-seg.fail { background: var(--fail); }
.spark-seg.inconclusive { background: var(--inc); }
.kpi-strip {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(215px, 1fr));
  gap: 12px;
  margin-bottom: 22px;
}
.kpi-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 16px 18px;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
}
.kpi-card .k-lbl {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--text-muted);
  font-weight: 600;
}
.kpi-card .k-val {
  font-size: 24px;
  font-weight: 800;
  margin: 6px 0 4px;
  font-variant-numeric: tabular-nums;
}
.kpi-card.pass .k-val { color: var(--pass); }
.kpi-card.fail .k-val { color: var(--fail); }
.kpi-card.warn .k-val { color: var(--inc); }
.kpi-card .k-sub {
  font-size: 12px;
  color: var(--text-dim);
}
.mini-bar {
  height: 5px;
  background: var(--bg-subtle);
  border-radius: 999px;
  overflow: hidden;
  margin: 8px 0 4px;
}
.mini-bar-fill {
  height: 100%;
  background: linear-gradient(90deg, var(--accent), var(--pass));
  border-radius: 999px;
}
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(330px, 1fr));
  gap: 14px;
  margin-bottom: 22px;
}
.card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 20px;
  display: flex;
  flex-direction: column;
  gap: 10px;
  box-shadow: var(--shadow);
}
.card.pass { border-top: 3px solid var(--pass); }
.card.fail { border-top: 3px solid var(--fail); }
.card.inconclusive { border-top: 3px solid var(--inc); }
.card h2 {
  margin: 2px 0;
  font-size: 17px;
  line-height: 1.3;
}
.card p {
  margin: 0;
  color: var(--text-muted);
  font-size: 13.5px;
}
.pill {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 3px 10px;
  border-radius: 999px;
  font-weight: 700;
  font-size: 11.5px;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
.pill.pass { background: var(--pass-soft); color: var(--pass); border: 1px solid var(--pass-border); }
.pill.fail { background: var(--fail-soft); color: var(--fail); border: 1px solid var(--fail-border); }
.pill.inconclusive { background: var(--inc-soft); color: var(--inc); border: 1px solid var(--inc-border); }
.biz-headline {
  font-weight: 700;
  font-size: 14px;
  color: var(--text);
}
.impact-box {
  background: var(--bg-subtle);
  border: 1px solid var(--border);
  border-radius: 9px;
  padding: 11px 13px;
  font-size: 13px;
  color: var(--text-muted);
}
.impact-box b { color: var(--text); }
.table-wrap {
  overflow-x: auto;
  border: 1px solid var(--border);
  border-radius: 12px;
  background: var(--bg-card);
  margin-bottom: 22px;
  box-shadow: var(--shadow);
}
table {
  width: 100%;
  border-collapse: collapse;
  min-width: 900px;
}
th, td {
  padding: 14px 16px;
  text-align: left;
  vertical-align: top;
  border-bottom: 1px solid var(--border);
}
th {
  background: var(--bg-subtle);
  color: var(--text-muted);
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}
tr:last-child td { border-bottom: none; }
.cmd-box {
  background: var(--bg-code);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 10px 12px;
  margin-top: 8px;
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 10px;
}
.cmd-box code {
  font-size: 12px;
  color: var(--cyan);
  word-break: break-all;
  white-space: pre-wrap;
}
details.drawer {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 10px;
  margin-top: 12px;
  overflow: hidden;
}
details.drawer summary {
  cursor: pointer;
  padding: 11px 15px;
  font-weight: 600;
  font-size: 13px;
  color: var(--text-muted);
  background: var(--bg-subtle);
  user-select: none;
}
details.drawer summary:hover { color: var(--text); }
details.drawer pre {
  margin: 0;
  padding: 14px;
  font-size: 12px;
  background: var(--bg-code);
  overflow-x: auto;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
pre.raw-block {
  background: var(--bg-code);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 16px;
  font-size: 12px;
  overflow-x: auto;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
}
.notice {
  padding: 16px 18px;
  border: 1px solid var(--border-strong);
  background: var(--bg-subtle);
  border-radius: 10px;
  margin-top: 22px;
  font-size: 13px;
  color: var(--text-muted);
}
.notice b { color: var(--text); }
.section-hdr {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 10px;
  margin: 22px 0 12px;
}
.section-hdr h2 {
  margin: 0;
  font-size: 18px;
  letter-spacing: -0.01em;
}
.tbadge {
  display: inline-block;
  padding: 3px 9px;
  border-radius: 6px;
  font-size: 11px;
  font-weight: 800;
  letter-spacing: 0.05em;
  margin-bottom: 6px;
}
.badge-pass { background: var(--pass-soft); color: var(--pass); border: 1px solid var(--pass-border); }
.badge-fail { background: var(--fail-soft); color: var(--fail); border: 1px solid var(--fail-border); }
.badge-warn { background: var(--inc-soft); color: var(--inc); border: 1px solid var(--inc-border); }
.badge-inc { background: var(--accent-soft); color: var(--accent); border: 1px solid var(--border-strong); }
footer {
  margin-top: 38px;
  padding-top: 18px;
  border-top: 1px solid var(--border);
  color: var(--text-dim);
  font-size: 12.5px;
  display: flex;
  flex-wrap: wrap;
  justify-content: space-between;
  gap: 12px;
}
.mitre-links { display: inline-flex; flex-wrap: wrap; gap: 6px; align-items: center; vertical-align: middle; }
.mitre-label { font-size: 10.5px; letter-spacing: 0.08em; text-transform: uppercase; color: var(--text-dim); font-weight: 700; }
.mitre-link {
  display: inline-flex;
  align-items: center;
  gap: 3px;
  padding: 2px 8px;
  border-radius: 6px;
  background: var(--cyan-soft);
  border: 1px solid rgba(56, 189, 248, 0.35);
  color: var(--cyan);
  text-decoration: none;
  font-size: 11.5px;
  font-weight: 700;
  letter-spacing: 0.03em;
  line-height: 1.35;
  transition: all 0.15s ease;
}
.mitre-link:hover, .mitre-link:focus-visible {
  background: var(--cyan);
  border-color: var(--cyan);
  color: #090a0f;
  outline: none;
}
.mitre-link .ext { font-size: 10px; opacity: 0.85; }
"""

_INTERACTIVE_JS = """
<script>
(function(){
  var root = document.documentElement;
  try {
    var savedTheme = localStorage.getItem('verimetry_theme');
    if (savedTheme === 'light' || savedTheme === 'dark') {
      root.setAttribute('data-theme', savedTheme);
    }
  } catch (e) {}
  window.toggleVerimetryTheme = function() {
    var cur = root.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
    root.setAttribute('data-theme', cur);
    try { localStorage.setItem('verimetry_theme', cur); } catch (e) {}
  };
  window.copyVerimetryText = function(btn, text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function(){
        var old = btn.innerHTML;
        btn.innerHTML = 'Copied &#10003;';
        setTimeout(function(){ btn.innerHTML = old; }, 1600);
      });
    } else {
      var ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); btn.innerHTML = 'Copied &#10003;'; } catch (e) {}
      document.body.removeChild(ta);
    }
  };
})();
</script>
"""


def _normalize_persona(persona: str | None) -> str:
    p = (persona or "both").strip().lower()
    if p not in VALID_PERSONAS:
        raise ValueError(f"persona must be one of {VALID_PERSONAS}, got {persona!r}")
    return p


def mitre_url(tech_id: str) -> str:
    """Convert a MITRE ATT&CK technique ID (e.g. T1562.006) into its official attack.mitre.org URL."""
    clean_id = tech_id.strip().upper().replace(".", "/")
    return f"https://attack.mitre.org/techniques/{clean_id}/"


def render_mitre_badges(mitre_value: str | None, include_prefix: bool = True) -> str:
    """Render one or more MITRE technique IDs (e.g. 'T1068 / T1562.001') as clickable external-link badges."""
    if not mitre_value:
        return ""
    raw = str(mitre_value).strip()
    matches = _MITRE_ID_RE.findall(raw)
    if not matches:
        return escape(raw)
    badges = []
    for tid in matches:
        norm = tid.upper()
        url = escape(mitre_url(norm))
        badges.append(
            f'<a class="mitre-link" href="{url}" target="_blank" rel="noopener noreferrer" '
            f'title="Open MITRE ATT&amp;CK {escape(norm)} documentation in a new tab">'
            f'{escape(norm)}<span class="ext" aria-hidden="true">&#8599;</span></a>'
        )
    prefix = '<span class="mitre-label">MITRE</span> ' if include_prefix else ""
    joined = ' <span class="mitre-sep" style="color:#64748b">/</span> '.join(badges)
    return f'<span class="mitre-links">{prefix}{joined}</span>'


def _check_playbook(test_id: str, verdict: str, rationale: str) -> dict[str, str]:
    """Return Customer plain-English headline/meaning and MSSP root-cause/remediation snippet for a check."""
    playbooks = {
        "WIN-ETW-INTEGRITY": {
            "PASS": {
                "headline": "Verified End-to-End User-Mode ETW & EventLog Delivery",
                "customer": "Core Windows event tracing sessions (EventLog-System and DiagTrack-Listener) are active, and a live canary marker was delivered and verified in the Application log.",
                "blocker": "None — ETW sessions and EventLog marker pipeline verified.",
                "cmd": "Get-EtwTraceSession -Name 'EventLog-System','DiagTrack-Listener'",
            },
            "FAIL": {
                "headline": "Confirmed Telemetry Blind Spot — ETW Session or Marker Delivery Gap",
                "customer": "An attacker blinding user-mode ETW or stopping telemetry listeners could evade detection because DiagTrack-Listener is inactive or the canary marker did not arrive in the log.",
                "blocker": rationale or "DiagTrack-Listener ETW session inactive or Application log marker missing.",
                "cmd": "sc.exe config DiagTrack start= auto && sc.exe start DiagTrack && logman query -ets",
            },
            "INCONCLUSIVE": {
                "headline": "Unverified — Elevated Collector Privilege Required for ETW Enumeration",
                "customer": "Verimetry could not enumerate active kernel/user-mode ETW sessions without Administrator privileges. No failure is assumed, but ETW tamper resistance remains unverified.",
                "blocker": "etw_query_status != 'ok' (Get-EtwTraceSession / logman -ets requires elevated Administrator session).",
                "cmd": "Start-Process powershell -Verb RunAs -ArgumentList '-NoExit -Command python -m verimetry assess --out .\\evidence-elevated'",
            },
        },
        "WIN-KERNEL-PPL-HVCI": {
            "PASS": {
                "headline": "Verified Kernel Memory Integrity (HVCI), VBS, LSA RunAsPPL & CodeIntegrity Log",
                "customer": "Hardware/virtualization-based memory integrity (VBS + HVCI) and LSASS Protected Process Light (RunAsPPL) are active, and driver-integrity audit logs are readable.",
                "blocker": "None — VBS, HVCI, LSA RunAsPPL, and CodeIntegrity/Operational log verified.",
                "cmd": "Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard",
            },
            "FAIL": {
                "headline": "Confirmed Kernel / LSASS Hardening Gap — VBS, HVCI, or RunAsPPL Disabled",
                "customer": "The endpoint is exposed to bring-your-own-vulnerable-driver (BYOVD) or LSASS memory-dumping techniques because VBS/HVCI or LSA RunAsPPL protection is turned off.",
                "blocker": rationale or "VBS/HVCI not running or HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL not enabled.",
                "cmd": "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\" /v RunAsPPL /t REG_DWORD /d 1 /f && reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity\" /v Enabled /t REG_DWORD /d 1 /f",
            },
            "INCONCLUSIVE": {
                "headline": "Unverified — DeviceGuard WMI or CodeIntegrity Log Inaccessible",
                "customer": "Kernel virtualization security or CodeIntegrity operational logs could not be queried under current permissions.",
                "blocker": "Win32_DeviceGuard WMI query or Microsoft-Windows-CodeIntegrity/Operational log read returned access_denied/query_error.",
                "cmd": "wevtutil sl Microsoft-Windows-CodeIntegrity/Operational /e:true",
            },
        },
        "WIN-XPROC-HANDLE": {
            "PASS": {
                "headline": "Verified Cross-Process Handle Access Telemetry (Event 4656/4663)",
                "customer": "Windows Security auditing recorded our harmless read-only cross-process handle request, proving the SOC can observe process-access reconnaissance.",
                "blocker": "None — Kernel Object / Handle Manipulation audit policy and Event 4656/4663 correlation verified.",
                "cmd": "auditpol /get /subcategory:\"{0cce921f-69ae-11d9-bed3-505054503030}\" /r",
            },
            "FAIL": {
                "headline": "Confirmed Blind Spot — Cross-Process Handle Auditing Enabled but No Events Emitted",
                "customer": "Handle auditing policy is enabled, yet opening a cross-process handle generated no Security Event 4656/4663 in the observation window.",
                "blocker": rationale or "Audit policy enabled, but process object SACL or Event 4656/4663 emission absent.",
                "cmd": "auditpol /set /subcategory:\"{0cce921f-69ae-11d9-bed3-505054503030}\" /success:enable /failure:enable && auditpol /set /subcategory:\"{0cce9223-69ae-11d9-bed3-505054503030}\" /success:enable /failure:enable",
            },
            "INCONCLUSIVE": {
                "headline": "Unverified — Prerequisite Kernel Object / Handle Audit Policy Disabled or Unreadable",
                "customer": "Windows does not enable cross-process handle auditing by default. Until the audit policy prerequisite is enabled (and run elevated), handle telemetry cannot be tested.",
                "blocker": rationale or "handle_audit_policy != 'enabled' or Security log requires Administrator privilege.",
                "cmd": "auditpol /set /subcategory:\"{0cce921f-69ae-11d9-bed3-505054503030}\" /success:enable /failure:enable && auditpol /set /subcategory:\"{0cce9223-69ae-11d9-bed3-505054503030}\" /success:enable /failure:enable",
            },
        },
        "WIN-LSA-SSP-AUDIT": {
            "PASS": {
                "headline": "Verified LSA SSP Registry Auditing & SACL Tamper Coverage",
                "customer": "Both Windows Registry Object Access auditing and an active System Access Control List (SACL) on the LSA registry key are protecting against credential-stealing SSP persistence.",
                "blocker": "None — Audit Registry policy and HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa SACL verified.",
                "cmd": "Get-Acl -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Audit | Select-Object -ExpandProperty Audit",
            },
            "FAIL": {
                "headline": "Confirmed Blind Spot — LSA Registry Auditing or SACL Rule Missing",
                "customer": "An attacker registering a malicious Security Support Provider (SSP) DLL under HKLM\\...\\Control\\Lsa would not generate a registry audit alert for the SOC.",
                "blocker": rationale or "Audit Registry policy disabled and/or HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa has 0 SACL audit rules.",
                "cmd": "auditpol /set /subcategory:\"{0cce921e-69ae-11d9-bed3-505054503030}\" /success:enable /failure:enable && powershell -Command \"$acl=Get-Acl 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Audit; $rule=New-Object System.Security.AccessControl.RegistryAuditRule('Everyone','SetValue,CreateSubKey,Delete,ChangePermissions','ContainerInherit,ObjectInherit','None','Success,Failure'); $acl.AddAuditRule($rule); Set-Acl 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' $acl\"",
            },
            "INCONCLUSIVE": {
                "headline": "Unverified — SeSecurityPrivilege Required to Inspect LSA Registry SACL",
                "customer": "Inspecting registry SACLs requires an elevated Administrator session with SeSecurityPrivilege. Re-run elevated to verify whether LSA registry auditing is active.",
                "blocker": "sacl_query_status != 'ok' (requires elevated Administrator / SeSecurityPrivilege).",
                "cmd": "Start-Process powershell -Verb RunAs -ArgumentList '-NoExit -Command python -m verimetry assess --out .\\evidence-elevated'",
            },
        },
        "WIN-CMDLINE-WMI": {
            "PASS": {
                "headline": "Verified Event 4688 Process Command-Line Capture & WMI-Activity Logging",
                "customer": "Full process command-line arguments (Event 4688) and WMI-Activity operational logs are actively captured, enabling fast first-touch SOC alert triage.",
                "blocker": "None — Event 4688 command-line canary and WMI-Activity/Operational readability verified.",
                "cmd": "auditpol /get /subcategory:\"{0cce922b-69ae-11d9-bed3-505054503030}\" /r",
            },
            "FAIL": {
                "headline": "Confirmed Blind Spot — Process Command-Line Capture or WMI Log Missing",
                "customer": "Process creation auditing is active, but command-line arguments (ProcessCreationIncludeCmdLine_Enabled) or WMI operational events were missing—forcing slower manual triage.",
                "blocker": rationale or "ProcessCreationIncludeCmdLine_Enabled != 1 or matching Event 4688 / WMI-Activity log disabled.",
                "cmd": "auditpol /set /subcategory:\"{0cce922b-69ae-11d9-bed3-505054503030}\" /success:enable /failure:enable && reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit\" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f && wevtutil sl Microsoft-Windows-WMI-Activity/Operational /e:true",
            },
            "INCONCLUSIVE": {
                "headline": "Unverified — Prerequisite Process Creation Audit Policy Disabled or Unreadable",
                "customer": "Windows Process Creation auditing (Event 4688) is not enabled in policy (or the Security log was run non-elevated). Command-line visibility cannot be verified until enabled.",
                "blocker": rationale or "audit_policy != 'enabled' or Security log requires Administrator privilege.",
                "cmd": "auditpol /set /subcategory:\"{0cce922b-69ae-11d9-bed3-505054503030}\" /success:enable /failure:enable && reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit\" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f",
            },
        },
        "WIN-4688-CANARY": {
            "PASS": {
                "headline": "Verified Process Creation Telemetry (Security Event 4688)",
                "customer": "Windows recorded Security Event 4688 for the launched canary process PID within the bounded observation window.",
                "blocker": "None — Event 4688 correlation verified.",
                "cmd": "auditpol /get /subcategory:\"{0cce922b-69ae-11d9-bed3-505054503030}\" /r",
            },
            "FAIL": {
                "headline": "Confirmed Blind Spot — No Event 4688 Observed Despite Enabled Policy",
                "customer": "Process Creation auditing is reported as enabled, but no matching Event 4688 arrived for the canary process.",
                "blocker": rationale or "Matching Event 4688 absent in bounded observation window.",
                "cmd": "auditpol /set /subcategory:\"{0cce922b-69ae-11d9-bed3-505054503030}\" /success:enable /failure:enable",
            },
            "INCONCLUSIVE": {
                "headline": "Unverified — Process Creation Policy Disabled or Security Log Unreadable",
                "customer": "Security Event 4688 could not be tested because the audit policy is disabled/unknown or the Security log requires Administrator privileges.",
                "blocker": rationale or "Security log access denied or Audit Process Creation policy not enabled.",
                "cmd": "auditpol /set /subcategory:\"{0cce922b-69ae-11d9-bed3-505054503030}\" /success:enable /failure:enable",
            },
        },
        "WIN-T1685-001-EDR-MINIFILTER": {
            "PASS": {
                "headline": "Verified Endpoint Security Service DACLs & Kernel Minifilter Altitude Registration",
                "customer": "EDR/Defender services (WinDefend/Sense) are running, kernel minifilter altitudes (e.g. WdFilter 328010) are registered, and Service Control Manager DACLs block unauthorized SERVICE_STOP requests.",
                "blocker": "None — OpenSCManagerW DACLs and FilterFindFirst / fltmc minifilter altitudes verified.",
                "cmd": "fltmc filters && sc.exe sdshow WinDefend",
            },
            "FAIL": {
                "headline": "Confirmed Defense Tampering Risk — Missing Minifilter Altitude or Weak Service DACL",
                "customer": "An adversary could unload the endpoint security minifilter driver (fltmc unload) or stop the EDR service because the expected minifilter altitude is absent or SCM DACLs allow non-TrustedInstaller modification.",
                "blocker": rationale or "Expected security minifilter altitude missing or SCM DACL permits unauthorized SERVICE_STOP.",
                "cmd": "fltmc load WdFilter && Set-MpPreference -DisableTamperProtection $false",
            },
            "INCONCLUSIVE": {
                "headline": "Unverified — Elevated Privilege Required for Minifilter & SCM DACL Enumeration",
                "customer": "Canary process lacked SeDebugPrivilege or FilterFindFirst / OpenSCManagerW returned ERROR_ACCESS_DENIED due to non-elevated execution or third-party sandboxing.",
                "blocker": rationale or "scm_query_status / fltmc_query_status != 'ok' (requires Administrator / SeDebugPrivilege).",
                "cmd": "Start-Process powershell -Verb RunAs -ArgumentList '-NoExit -Command fltmc filters; sc.exe sdshow WinDefend'",
            },
        },
        "WIN-T1685-002-CLOUD-LOG": {
            "PASS": {
                "headline": "Verified Cloud & Hybrid Audit Log Forwarding & Downstream Sink Ingestion",
                "customer": "Local cloud-log forwarder service is active, TLS/endpoint sink hashes match baseline, audit-bypass flags are clear, and the synthetic heartbeat registered in the downstream SIEM/cloud sink within SLA.",
                "blocker": "None — Forwarder active, sink config hash verified, and synthetic heartbeat acknowledged.",
                "cmd": "Get-Service AzureMonitorAgent,HealthService,wecsvc -ErrorAction SilentlyContinue",
            },
            "FAIL": {
                "headline": "Confirmed Cloud Log Blindness — Detached Sink, Audit Bypass, or Disabled Log Validation",
                "customer": "Cloud telemetry forwarding is severed or degraded: the forwarder sink URL/SNS topic is detached, mailbox/multi-region audit-bypass flags are tripped, or log validation/encryption is disabled (AN0801/AN0803).",
                "blocker": rationale or "Forwarder sink detached, audit-bypass flag tripped, or AN0801/AN0803 log validation disabled.",
                "cmd": "wevtutil gli ForwardedEvents && Get-OrganizationConfig | Select-Object AuditDisabled",
            },
            "INCONCLUSIVE": {
                "headline": "Unverified — Egress Timeout or API Rate-Limiting During Downstream Ingestion Check",
                "customer": "Network egress timeout or cloud API rate-limiting prevented confirming downstream cloud log ingestion within the bounded canary window.",
                "blocker": rationale or "ingestion_verify_status in ('timeout', 'rate_limited', 'network_unreachable').",
                "cmd": "Test-NetConnection -ComputerName global.handler.control.monitor.azure.com -Port 443",
            },
        },
        "WIN-T1685-003-ETW-SYSCALL": {
            "PASS": {
                "headline": "Verified In-Memory ntdll!NtTraceEvent Syscall Integrity & Autologger Sessions",
                "customer": "In-memory ntdll.dll syscall prologue bytes match the clean disk image (no 0xC3 ret patches), core ETW autologger sessions are running, and auditpol subcategories recorded the benign test event (4688/4104).",
                "blocker": "None — ntdll!NtTraceEvent/EtwEventWrite unpatched, QueryAllTracesW active, and Event 4688/4104 verified.",
                "cmd": "logman query -ets && auditpol /get /category:* /r",
            },
            "FAIL": {
                "headline": "Confirmed ETW / EventLog Blinding — User-Mode ntdll Patch or Cleared Audit Policy",
                "customer": "User-mode ETW or EventLog collection is actively impaired: an in-memory EtwEventWrite/NtTraceEvent patch (0xC3 ret) was detected, EventLog threads are suspended, or auditpol policies were cleared.",
                "blocker": rationale or "In-memory ntdll!EtwEventWrite hook detected, EventLog suspended, or auditpol set to No Auditing.",
                "cmd": "auditpol /set /subcategory:\"{0cce922b-69ae-11d9-bed3-505054503030}\" /success:enable /failure:enable && wevtutil sl Microsoft-Windows-PowerShell/Operational /e:true",
            },
            "INCONCLUSIVE": {
                "headline": "Unverified — VBS Memory Protections or Missing Privilege Restricted Inspection",
                "customer": "Hypervisor/VBS memory protections or non-elevated execution restricted ntdll memory inspection or auditpol enumeration.",
                "blocker": rationale or "ntdll_inspect_status != 'ok' or auditpol_status != 'ok'.",
                "cmd": "Start-Process powershell -Verb RunAs -ArgumentList '-NoExit -Command logman query -ets; auditpol /get /category:*'",
            },
        },
        "WIN-T1685-004-FIREWALL-WFP": {
            "PASS": {
                "headline": "Verified Windows Firewall Profiles, WFP Telemetry Rules & Collector TLS Egress",
                "customer": "All three Windows Defender Firewall profiles (Domain, Private, Public) are enabled, no unauthorized outbound WFP drop filters block SIEM/EDR ports, firewall logging is enabled, and collector TLS handshake succeeded.",
                "blocker": "None — FwpmFilterEnum0 outbound filters, firewall profiles, and collector TLS verified.",
                "cmd": "Get-NetFirewallProfile | Select-Object Name,Enabled,LogBlocked,LogFileName",
            },
            "FAIL": {
                "headline": "Confirmed Network Telemetry Silencing — Firewall Disabled or WFP Outbound Block Rule",
                "customer": "An active outbound Windows Filtering Platform (WFP) drop rule is blocking EDR/SIEM telemetry egress, one or more firewall profiles are disabled, or firewall packet logging (pfirewall.log) is turned off.",
                "blocker": rationale or "Outbound WFP block rule targeting telemetry endpoints or Windows Firewall profile/logging disabled.",
                "cmd": "netsh advfirewall set allprofiles state on && netsh advfirewall set allprofiles logging droppedconnections enable",
            },
            "INCONCLUSIVE": {
                "headline": "Unverified — Split-Tunnel VPN or Proxy Obscures Direct WFP Filter Attribution",
                "customer": "An active split-tunnel VPN callout or proxy configuration prevented deterministic attribution of outbound WFP filter rules.",
                "blocker": rationale or "wfp_query_status in ('vpn_split_tunnel_obscured', 'proxy_obscured').",
                "cmd": "netsh wfp show filters file=wfp_filters.xml && Get-NetFirewallProfile",
            },
        },
        "WIN-T1685-005-USN-EVTX": {
            "PASS": {
                "headline": "Verified NTFS USN Change Journal Continuity & Monotonic EVTX Sequence Numbers",
                "customer": "The NTFS volume UsnJournalID is continuous across runs (no fsutil usn deletejournal tampering) and Security/Sysmon .evtx record numbers increment monotonically without log-clear resets (Event ID 1102/104).",
                "blocker": "None — FSCTL_QUERY_USN_JOURNAL UsnJournalID and EVTX RecordCount continuity verified.",
                "cmd": "fsutil usn queryjournal C: && Get-WinEvent -ListLog Security,Microsoft-Windows-Sysmon/Operational -ErrorAction SilentlyContinue",
            },
            "FAIL": {
                "headline": "Confirmed Forensic Artifact Tampering — USN Journal Deleted or EVTX Log Cleared",
                "customer": "Host forensic indicators were wiped or truncated: the NTFS UsnJournalID changed unexpectedly (indicating journal deletion/recreation) or the Security/Sysmon .evtx log sequence was reset (Event ID 1102 / 104).",
                "blocker": rationale or "UsnJournalID discontinuity or Event ID 1102/104 log-clear reset detected.",
                "cmd": "fsutil usn createjournal m=33554432 a=4194304 C: && Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102} -MaxEvents 5",
            },
            "INCONCLUSIVE": {
                "headline": "Unverified — Non-NTFS Volume or Insufficient Privileges for USN Journal Query",
                "customer": "The target volume is mounted read-only, uses a non-NTFS filesystem (ReFS/FAT32) lacking standard USN semantics, or fsutil usn queryjournal lacked Administrator privilege.",
                "blocker": rationale or "filesystem_type != 'NTFS' or usn_query_status != 'ok'.",
                "cmd": "Start-Process powershell -Verb RunAs -ArgumentList '-NoExit -Command fsutil usn queryjournal C:'",
            },
        },
        "WIN-T1685-006-VBS-VTL1-BCD": {
            "PASS": {
                "headline": "Verified VTL 1 Isolation Active & Zero Staged BCD / Registry Downgrade Drift",
                "customer": "VTL 1 (securekernel.exe / LsaIso.exe) is actively running, live BCD hypervisorlaunchtype is Auto, UEFI Secure Boot is enabled, and staged DeviceGuard registry keys match the running state (zero reboot drift).",
                "blocker": "None — Live Win32_DeviceGuard VTL 1 state matches staged BCD store and registry configuration.",
                "cmd": "bcdedit /enum {current} && Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\\Microsoft\\Windows\\DeviceGuard",
            },
            "FAIL": {
                "headline": "Confirmed VTL 1 / VBS Reboot Downgrade Staged — BCD or Registry Tampered",
                "customer": "Even if VTL 1 is currently active in memory, staged BCD (hypervisorlaunchtype off) or DeviceGuard registry keys (EnableVirtualizationBasedSecurity = 0) have been modified to disable VBS/HVCI/Credential Guard on the next reboot.",
                "blocker": rationale or "Staged BCD hypervisorlaunchtype=off or EnableVirtualizationBasedSecurity=0 diverges from running VTL 1 state.",
                "cmd": "bcdedit /set hypervisorlaunchtype auto && reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\" /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 1 /f",
            },
            "INCONCLUSIVE": {
                "headline": "Unverified — Nested VM Without Hardware Virtualization (VT-x/AMD-V) or BCD Access Denied",
                "customer": "The host is running inside a nested VM without exposed hardware virtualization extensions (VT-x/AMD-V) or the live BCD store could not be read without Administrator elevation.",
                "blocker": rationale or "virtualization_environment == 'nested_vm_no_vtx' or bcd_query_status != 'ok'.",
                "cmd": "Start-Process powershell -Verb RunAs -ArgumentList '-NoExit -Command bcdedit /enum {current}'",
            },
        },
        "WIN-T1685-007-SAFEBOOT-BCD": {
            "PASS": {
                "headline": "Verified Clean Normal-Boot BCD State & Intact SafeBoot Security Service Registrations",
                "customer": "No safeboot flag (0x25000080) is staged in the active BCD {current} entry, and critical security services remain properly registered under HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot.",
                "blocker": "None — Active BCD {current} free of staged safeboot flags and SafeBoot registry keys intact.",
                "cmd": "bcdedit /enum {current} && Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal'",
            },
            "FAIL": {
                "headline": "Confirmed Safe Mode Evasion Staged — BCD SafeBoot Flag or SafeBoot Registry Tampered",
                "customer": "A safeboot flag (minimal/network) is staged in the active BCD {current} store while the host is running in normal mode (indicating an imminent Safe Mode evasion reboot where EDR drivers will not load) or SafeBoot service keys were deleted.",
                "blocker": rationale or "Staged BcdOSLoaderBoolean_SafeBoot (0x25000080) detected in BCD {current} or SafeBoot registry keys tampered.",
                "cmd": "bcdedit /deletevalue {current} safeboot",
            },
            "INCONCLUSIVE": {
                "headline": "Unverified — BitLocker Recovery Lock or Insufficient Privileges for BCD Store Inspection",
                "customer": "BitLocker recovery state, a locked system hive, or non-elevated privileges prevented reading the active BCD {current} store.",
                "blocker": rationale or "bcd_query_status in ('bitlocker_locked', 'access_denied', 'query_error').",
                "cmd": "Start-Process powershell -Verb RunAs -ArgumentList '-NoExit -Command bcdedit /enum {current}'",
            },
        },
    }
    by_test = playbooks.get(test_id, {})
    entry = by_test.get(verdict)
    if entry:
        return entry
    return {
        "headline": f"{test_id} — {verdict}",
        "customer": rationale,
        "blocker": rationale,
        "cmd": "python -m verimetry assess --out .\\evidence-elevated",
    }


def build_report(packages, output, persona="both"):
    """Build static OpenRouter-inspired HTML report with Customer View and MSSP Operations View."""
    persona = _normalize_persona(persona)
    counts = {"PASS": 0, "FAIL": 0, "INCONCLUSIVE": 0}
    customer_cards = []
    mssp_rows = []
    hosts = []
    timestamps = []
    first_sha = ""
    first_fp = ""

    for p in packages:
        r, payload_sha, keyid, payload_type = extract_receipt(p)
        verdict = r["verdict"]
        counts[verdict] = counts.get(verdict, 0) + 1
        target_raw = r["target"]["host"]
        if target_raw not in hosts:
            hosts.append(target_raw)
        if r.get("created_at"):
            timestamps.append(r["created_at"])
        if not first_sha and payload_sha:
            first_sha = payload_sha
        if not first_fp and keyid:
            first_fp = keyid

        target = escape(target_raw)
        rationale = escape(r["rationale"])
        reason_codes_str = escape(", ".join(r.get("reason_codes") or []))
        mode = escape(r["observation"].get("mode", "unknown"))
        recid = escape(r["receipt_id"])
        sha_full = escape(payload_sha or "unsigned")
        sha_short = escape((payload_sha or "unsigned")[:16])
        fp_short = escape((keyid or "n/a")[:16])
        test = r.get("test") or {}
        test_id_raw = test.get("id", "WIN-4688-CANARY")
        test_id = escape(test_id_raw)
        rule_ver = escape(test.get("rule_version", "v1"))
        title = escape(test.get("title") or target_raw)
        mitre = test.get("mitre_attack")
        badge = f' · {render_mitre_badges(mitre)}' if mitre else ""
        host_line = f'<div class="mono" style="font-size:12px;color:var(--text-dim)">Host: {target}</div>' if test.get("title") else ""

        pb = _check_playbook(test_id_raw, verdict, r.get("rationale", ""))
        biz_headline = escape(pb["headline"])
        biz_customer = escape(pb["customer"])
        mssp_blocker = escape(pb["blocker"])
        mssp_cmd = escape(pb["cmd"])
        mssp_cmd_js = escape(json.dumps(pb["cmd"]))
        raw_obs_json = escape(json.dumps(r.get("observation", {}), indent=2, ensure_ascii=False))

        customer_cards.append(
            f'<article class="card {verdict.lower()}">'
            f'<div class="eyebrow"><span>{mode}</span> · <span>{test_id}</span>{badge}</div>'
            f'<h2>{title}</h2>'
            f'{host_line}'
            f'<div><span class="pill {verdict.lower()}"><strong>{verdict}</strong></span></div>'
            f'<div class="biz-headline">{biz_headline}</div>'
            f'<p>{biz_customer}</p>'
            f'<div class="impact-box"><b>Observed Evidence Rule:</b> {rationale}</div>'
            f'<details class="drawer"><summary>Inspect Technical Evidence &amp; DSSE Payload Digest ({sha_short}…)</summary>'
            f'<pre>Receipt ID:   {recid}\nPayload Type: {escape(payload_type)}\nReason Codes: {reason_codes_str}\nSHA-256:      {sha_full}\nRule:         {rule_ver}\n\n{raw_obs_json}</pre></details>'
            f'</article>'
        )

        mssp_rows.append(
            f'<tr>'
            f'<td><div class="mono" style="font-weight:800;color:var(--cyan)">{test_id}</div>'
            f'<div style="font-weight:700;margin:4px 0">{title}</div>'
            f'<div style="font-size:12px;color:var(--text-dim)">Rule: <code class="mono">{rule_ver}</code> · Host: {target}</div>'
            f'<div style="margin-top:6px">{render_mitre_badges(mitre) if mitre else ""}</div></td>'
            f'<td><span class="pill {verdict.lower()}"><strong>{verdict}</strong></span>'
            f'<div style="font-size:13px;margin:8px 0;color:var(--text)">{rationale}</div>'
            f'<div class="mono" style="font-size:11px;color:var(--text-dim)">Codes: {reason_codes_str}<br>Receipt: {recid}<br>SHA-256: {sha_short}…<br>Signer: {fp_short}…</div></td>'
            f'<td><div style="font-size:13px;color:var(--text)"><b>Root-Cause / Gate Evaluation:</b> {mssp_blocker}</div>'
            f'<div class="cmd-box"><code class="mono">{mssp_cmd}</code>'
            f'<button type="button" class="copy-btn" onclick=\'copyVerimetryText(this, {mssp_cmd_js})\'>Copy</button></div>'
            f'<details class="drawer"><summary>Full Collector Payload (JSON)</summary><pre>{raw_obs_json}</pre></details></td>'
            f'</tr>'
        )

    total = max(len(packages), 1)
    pass_pct = round((counts["PASS"] / total) * 100.0, 1)
    fail_pct = round((counts["FAIL"] / total) * 100.0, 1)
    inc_pct = round((counts["INCONCLUSIVE"] / total) * 100.0, 1)

    host_summary = escape(", ".join(hosts) if hosts else "Local Host")
    ts_summary = escape(max(timestamps) if timestamps else "point-in-time")
    verify_cmd = f"python -m verimetry verify --receipt .\\receipt-etw-integrity.json --public .\\signer.pub.pem"
    verify_proof_js = escape(json.dumps(f"{verify_cmd} # SHA-256: {first_sha}"))

    cust_checked = "checked" if persona in ("both", "customer") else ""
    mssp_checked = "checked" if persona == "mssp" else ""

    markup = f'''<!doctype html><html lang="en" data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Verimetry | Assurance Review</title><style>{_OPENROUTER_DESIGN_CSS}</style></head><body>
<input class="view-radio" type="radio" name="role_view" id="role-customer" {cust_checked}>
<input class="view-radio" type="radio" name="role_view" id="role-mssp" {mssp_checked}>
<header class="topbar">
  <div class="topbar-inner">
    <div class="brand">
      <span class="brand-dot"></span>
      <span class="brand-name">VERIMETRY</span>
      <span class="brand-tag mono">v1.0.0-rc1 · DSSE Ed25519</span>
    </div>
    <div class="controls-bar">
      <div class="role-switcher" role="tablist" aria-label="Role Switcher">
        <label class="role-btn" for="role-customer" role="tab" tabindex="0">Customer View</label>
        <label class="role-btn" for="role-mssp" role="tab" tabindex="0">MSSP Operations View</label>
      </div>
      <button type="button" class="theme-btn" onclick="toggleVerimetryTheme()" title="Toggle Dark / Light Mode">&#9680; Theme</button>
    </div>
  </div>
</header>
<main>
  <section class="trust-hero">
    <div class="trust-top">
      <div class="trust-title">
        <div class="eyebrow">EVIDENCE BEFORE ASSURANCE · BOUNDED WINDOWS INTERNALS TELEMETRY</div>
        <h1>Endpoint Telemetry &amp; Control Assurance</h1>
        <p>Reproducible, non-destructive Windows Internals canary checks. Missing visibility remains <b>INCONCLUSIVE</b> and is never fabricated into a failure.</p>
      </div>
      <div class="score-box">
        <div class="score-lbl">Verified Telemetry Coverage</div>
        <div class="score-num" style="color:var(--pass)">{pass_pct}%</div>
        <div class="mono" style="font-size:12px;color:var(--text-muted)">PASS <b>{counts['PASS']}</b> · FAIL <b>{counts['FAIL']}</b> · INCONCLUSIVE <b>{counts['INCONCLUSIVE']}</b></div>
      </div>
    </div>
    <div class="sparkbar" aria-label="Verdict Distribution">
      <div class="spark-seg pass" style="width:{pass_pct}%"></div>
      <div class="spark-seg fail" style="width:{fail_pct}%"></div>
      <div class="spark-seg inconclusive" style="width:{inc_pct}%"></div>
    </div>
    <div class="trust-meta">
      <span class="sig-badge">&#10003; Ed25519 Verified Offline</span>
      <span class="meta-chip"><b>Host:</b> <span class="mono">{host_summary}</span></span>
      <span class="meta-chip"><b>Assessed (UTC):</b> <span class="mono">{ts_summary}</span></span>
      <span class="meta-chip"><b>Signer SHA-256:</b> <span class="mono">{escape(first_fp[:18] or 'local')}…</span></span>
      <button type="button" class="copy-btn" onclick='copyVerimetryText(this, {verify_proof_js})'>Copy Verification Proof</button>
    </div>
  </section>

  <section class="role-panel panel-customer" aria-label="Customer View">
    <div class="section-hdr">
      <h2>Customer View — Proof of Protection &amp; Audit Readiness</h2>
      <span style="font-size:12.5px;color:var(--text-muted)">Plain-English business impact · Click any MITRE badge for official adversary &amp; mitigation docs</span>
    </div>
    <div class="grid">{''.join(customer_cards)}</div>
  </section>

  <section class="role-panel panel-mssp" aria-label="MSSP Operations View">
    <div class="section-hdr">
      <h2>MSSP Operations View — Telemetry Engineering &amp; Fleet Triage</h2>
      <span style="font-size:12.5px;color:var(--text-muted)">Root-cause evidence gates, copyable GPO/PowerShell remediations &amp; chain-of-custody digests</span>
    </div>
    <div class="kpi-strip">
      <article class="kpi-card pass">
        <div class="k-lbl">Verified Coverage (% PASS)</div>
        <div class="k-val">{pass_pct}%</div>
        <div class="mini-bar"><div class="mini-bar-fill" style="width:{pass_pct}%"></div></div>
        <div class="k-sub">{counts['PASS']} of {len(packages)} checks cryptographically verified</div>
      </article>
      <article class="kpi-card fail">
        <div class="k-lbl">Confirmed Telemetry Gaps (FAIL)</div>
        <div class="k-val">{counts['FAIL']}</div>
        <div class="k-sub">Prerequisites verified, expected telemetry absent</div>
      </article>
      <article class="kpi-card warn">
        <div class="k-lbl">Visibility / Policy Gates (INCONCLUSIVE)</div>
        <div class="k-val">{counts['INCONCLUSIVE']}</div>
        <div class="k-sub">Requires auditpol enablement or Administrator elevation</div>
      </article>
      <article class="kpi-card">
        <div class="k-lbl">Signer Key Fingerprint</div>
        <div class="k-val mono" style="font-size:15px">{escape(first_fp[:16] or 'n/a')}…</div>
        <div class="k-sub">Ed25519 canonical JSON receipt integrity</div>
      </article>
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th style="width:25%">Check, Rule &amp; MITRE ATT&amp;CK</th>
            <th style="width:28%">Deterministic Verdict &amp; Chain of Custody</th>
            <th style="width:47%">Engineering Blocker &amp; Copyable Remediation</th>
          </tr>
        </thead>
        <tbody>{''.join(mssp_rows)}</tbody>
      </table>
    </div>
  </section>

  <div class="notice"><b>Verification boundary</b><p style="margin:6px 0 0">Every result is limited to the recorded test conditions. A signature protects receipt integrity, not sensor independence. Synthetic observations are clearly marked and must not be presented as live host evidence. Independently verify exported JSON with the separately distributed trusted public key.</p></div>
  <footer>
    <span>Local-only output · Zero external assets · Air-gapped ready</span>
    <span class="mono">Verimetry {__version__} · Apache-2.0</span>
  </footer>
</main>
{_INTERACTIVE_JS}
</body></html>'''
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    Path(output).write_text(markup, encoding="utf-8")


def build_inventory_report(inventory, output, persona="both"):
    """Create offline plain-English (Customer View) and technical (MSSP Operations View) tabs from observed Windows data only."""
    persona = _normalize_persona(persona)
    sections = inventory.get('sections') or {}

    def read(name):
        item = sections.get(name)
        return item.get('data') if isinstance(item, dict) and item.get('status') == 'observed' else None

    def clean(v):
        return escape(str(v)) if v is not None else 'Not reported'

    entries = []
    mssp_rows = []

    def add_section(sec_key, title, condition, interpretation, detail, mitre_ids, remediation_cmd):
        label = 'Observed' if condition else 'Not available'
        pill_cls = 'pass' if condition else 'inconclusive'
        mitre_html = f' · {render_mitre_badges(mitre_ids)}' if mitre_ids else ''
        entries.append(
            f'<article class="card {pill_cls}">'
            f'<div class="eyebrow"><span class="tag">{label}</span>{mitre_html}</div>'
            f'<h2>{escape(title)}</h2>'
            f'<p>{interpretation}</p>'
            f'<small style="color:var(--text-dim)">{detail}</small>'
            f'</article>'
        )
        raw_sec = sections.get(sec_key) or {"status": "unavailable"}
        raw_sec_json = escape(json.dumps(raw_sec, indent=2, ensure_ascii=False))
        cmd_js = escape(json.dumps(remediation_cmd))
        mssp_rows.append(
            f'<tr>'
            f'<td><div class="mono" style="font-weight:800;color:var(--cyan)">{escape(sec_key)}</div>'
            f'<div style="font-weight:700;margin:4px 0">{escape(title)}</div>'
            f'<div style="margin-top:6px">{render_mitre_badges(mitre_ids) if mitre_ids else ""}</div></td>'
            f'<td><span class="pill {pill_cls}">{label}</span>'
            f'<div style="font-size:13px;margin-top:8px;color:var(--text-muted)">{interpretation}</div></td>'
            f'<td><div style="font-size:12.5px;color:var(--text-muted)"><b>Verification / Query Command:</b></div>'
            f'<div class="cmd-box"><code class="mono">{escape(remediation_cmd)}</code>'
            f'<button type="button" class="copy-btn" onclick=\'copyVerimetryText(this, {cmd_js})\'>Copy</button></div>'
            f'<details class="drawer"><summary>Section Payload ({escape(sec_key)})</summary><pre>{raw_sec_json}</pre></details></td>'
            f'</tr>'
        )

    osdata = read('os')
    if isinstance(osdata, list):
        osdata = osdata[0] if osdata else None
    if isinstance(osdata, dict):
        add_section(
            'os', 'Your Windows version', True,
            f"This machine reports <b>{clean(osdata.get('Caption'))}</b>, build <b>{clean(osdata.get('BuildNumber'))}</b>.",
            'This identifies the installed operating system; it is not a security rating.',
            'T1082', 'Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber',
        )
    else:
        add_section(
            'os', 'Your Windows version', False,
            'We could not read the operating system details.',
            'No conclusion about Windows security can be made from this missing information.',
            'T1082', 'Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber',
        )

    defender = read('defender')
    if isinstance(defender, list):
        defender = defender[0] if defender else None
    if isinstance(defender, dict):
        av = defender.get('AntivirusEnabled')
        rt = defender.get('RealTimeProtectionEnabled')
        av_word = 'enabled' if av is True else ('disabled' if av is False else 'not reported')
        rt_word = 'enabled' if rt is True else ('disabled' if rt is False else 'not reported')
        add_section(
            'defender', 'Microsoft Defender', True,
            f"Windows reports antivirus as <b>{av_word}</b> and real-time protection as <b>{rt_word}</b>.",
            'Reported configuration is not proof that Defender detects every threat.',
            'T1562.001', 'Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,IoavProtectionEnabled',
        )
    else:
        add_section(
            'defender', 'Microsoft Defender', False,
            'Defender status was not accessible or was not reported.',
            'This does not mean Defender is turned off.',
            'T1562.001', 'Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,IoavProtectionEnabled',
        )

    fw = read('firewall')
    if isinstance(fw, dict):
        fw = [fw]
    if isinstance(fw, list) and fw:
        profiles = []
        for profile in fw:
            if isinstance(profile, dict):
                v = profile.get('Enabled')
                state = 'on' if v in (True, 1) else ('off' if v in (False, 0) else 'unknown')
                profiles.append(f"{clean(profile.get('Name'))}: <b>{state}</b>")
        add_section(
            'firewall', 'Windows Firewall', True,
            'Windows reports these firewall profile settings: ' + ('; '.join(profiles) or 'No profile details') + '.',
            'These are configuration readings, not proof that every network connection is protected.',
            'T1562.004', 'Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction',
        )
    else:
        add_section(
            'firewall', 'Windows Firewall', False,
            'The firewall profile settings could not be read.',
            'Do not interpret missing data as firewall failure.',
            'T1562.004', 'Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction',
        )

    fixes = read('hotfixes')
    if isinstance(fixes, dict):
        fixes = [fixes]
    if isinstance(fixes, list):
        add_section(
            'hotfixes', 'Recorded Windows updates', True,
            f'The collector returned <b>{len(fixes)}</b> recent hotfix record(s).',
            'This is not a full vulnerability or missing-patch scan.',
            'T1068', 'Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10',
        )
    else:
        add_section(
            'hotfixes', 'Recorded Windows updates', False,
            'Recent hotfix records could not be retrieved.',
            'No patch-compliance conclusion is available.',
            'T1068', 'Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10',
        )

    audit = read('audit_process_creation')
    if isinstance(audit, str) and audit.strip():
        add_section(
            'audit_process_creation', 'Process-creation auditing', True,
            'Windows returned the process-creation audit policy configuration.',
            'Open the Technical evidence tab to see the exact policy output. A live canary assessment is needed to test whether a process event can actually be observed.',
            'T1059 / T1047', 'auditpol /get /subcategory:"{0cce922b-69ae-11d9-bed3-505054503030}" /r',
        )
    else:
        add_section(
            'audit_process_creation', 'Process-creation auditing', False,
            'The process-creation audit policy was not accessible.',
            'A missing policy reading does not prove that audit events are absent.',
            'T1059 / T1047', 'auditpol /get /subcategory:"{0cce922b-69ae-11d9-bed3-505054503030}" /r',
        )

    status = clean(inventory.get('status', 'unknown'))
    stamp = clean(inventory.get('collected_at', 'not supplied'))
    technical = escape(json.dumps(inventory, indent=2, ensure_ascii=False))
    observed_count = sum(1 for k in ('os', 'defender', 'firewall', 'hotfixes', 'audit_process_creation') if read(k) is not None)
    obs_pct = round((observed_count / 5.0) * 100.0, 1)

    plain_checked = "checked" if persona in ("both", "customer") else ""
    tech_checked = "checked" if persona == "mssp" else ""

    html = f'''<!doctype html><html lang="en" data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Verimetry | My Windows Security</title>
<style>{_OPENROUTER_DESIGN_CSS}</style></head><body>
<input class="view-radio" type="radio" name="view" id="plain" {plain_checked}>
<input class="view-radio" type="radio" name="view" id="technical" {tech_checked}>
<header class="topbar">
  <div class="topbar-inner">
    <div class="brand">
      <span class="brand-dot"></span>
      <span class="brand-name">VERIMETRY</span>
      <span class="brand-tag mono">Host Inventory · v{__version__}</span>
    </div>
    <div class="controls-bar">
      <div class="role-switcher" role="tablist" aria-label="Report view">
        <label class="role-btn" for="plain" role="tab" tabindex="0">Customer View (Plain English)</label>
        <label class="role-btn" for="technical" role="tab" tabindex="0">MSSP Operations View (Technical evidence (JSON))</label>
      </div>
      <button type="button" class="theme-btn" onclick="toggleVerimetryTheme()">&#9680; Theme</button>
    </div>
  </div>
</header>
<main>
  <section class="trust-hero">
    <div class="trust-top">
      <div class="trust-title">
        <div class="eyebrow">VERIMETRY / LOCAL WINDOWS INVENTORY</div>
        <h1>Understand your Windows security settings</h1>
        <p>Read-only observations from the machine being inspected, explained without technical jargon. Missing readings remain unknown and are never converted into failures.</p>
      </div>
      <div class="score-box">
        <div class="score-lbl">Readable Inventory Sections</div>
        <div class="score-num" style="color:var(--cyan)">{observed_count}/5</div>
        <div class="mono" style="font-size:12px;color:var(--text-muted)">{obs_pct}% observable under current privileges</div>
      </div>
    </div>
    <div class="trust-meta">
      <span class="meta-chip"><b>Collection Status:</b> <span class="mono">{status}</span></span>
      <span class="meta-chip"><b>Collected (UTC):</b> <span class="mono">{stamp}</span></span>
    </div>
  </section>

  <section class="role-panel panel-customer" id="plain-panel">
    <div class="section-hdr">
      <h2>Customer View — What we actually found</h2>
      <span style="font-size:12.5px;color:var(--text-muted)">Plain-English summary · Click any MITRE ATT&amp;CK badge to inspect official framework guidance</span>
    </div>
    <div class="grid">{''.join(entries)}</div>
    <div class="notice"><b>What this report does not prove</b><p style="margin:6px 0 0">Reading a security setting does not prove that a defense works against an attack. Verimetry has not performed a vulnerability scan, patch installation, or comprehensive compliance assessment. Missing readings remain unknown; they are never converted into failures.</p></div>
  </section>

  <section class="role-panel panel-mssp" id="tech-panel">
    <div class="section-hdr">
      <h2>MSSP Operations View — Collector Telemetry &amp; Raw JSON</h2>
      <span style="font-size:12.5px;color:var(--text-muted)">Direct PowerShell/WMI query verification commands &amp; unmodified inventory payload</span>
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th style="width:24%">Inventory Section &amp; MITRE</th>
            <th style="width:32%">Collector Observation</th>
            <th style="width:44%">Verification Query &amp; Section Payload</th>
          </tr>
        </thead>
        <tbody>{''.join(mssp_rows)}</tbody>
      </table>
    </div>
    <details class="drawer" open><summary>Original collected data — Full windows-inventory.json</summary><pre class="raw-block">{technical}</pre></details>
  </section>

  <footer>
    <span>Saved locally · No cloud services · No AI-generated verdicts</span>
    <span class="mono">Verimetry {__version__} · Apache-2.0</span>
  </footer>
</main>
{_INTERACTIVE_JS}
</body></html>'''
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    Path(output).write_text(html, encoding='utf-8')


def build_comparison_report(signed_package, output, persona="both"):
    """Build a static, self-contained HTML comparison report with Customer View and MSSP Operations View."""
    persona = _normalize_persona(persona)
    receipt, payload_sha, keyid, payload_type = extract_receipt(signed_package)
    obs = receipt.get("observation") or {}
    metrics = obs.get("metrics") or {}
    transitions = obs.get("transitions") or []

    overall_verdict = escape(str(receipt.get("verdict", "INCONCLUSIVE")))
    overall_rationale = escape(str(receipt.get("rationale", "")))
    host = escape(str((receipt.get("target") or {}).get("host", "Unknown")))
    before_dir = escape(str(obs.get("before_directory", "before")))
    after_dir = escape(str(obs.get("after_directory", "after")))
    rec_id = escape(str(receipt.get("receipt_id", "")))
    rec_sha = escape(str(payload_sha))
    signer_fp = escape(str(keyid))

    total = int(metrics.get("total_checks", len(transitions)) or 0)
    b_cov_bps = int(metrics.get("before_coverage_bps", 0) or 0)
    a_cov_bps = int(metrics.get("after_coverage_bps", 0) or 0)
    d_cov_bps = int(metrics.get("coverage_delta_bps", 0) or 0)
    b_cov_str = escape(str(metrics.get("before_coverage_pct_str") or bps_to_pct_str(b_cov_bps)))
    a_cov_str = escape(str(metrics.get("after_coverage_pct_str") or bps_to_pct_str(a_cov_bps)))
    d_cov_str = escape(str(metrics.get("coverage_delta_pct_str") or (("+" if d_cov_bps > 0 else "") + bps_to_pct_str(d_cov_bps))))
    a_cov_bar = max(min(a_cov_bps / 100.0, 100.0), 0.0)

    b_inc = int(metrics.get("before_inconclusive_count", 0) or 0)
    a_inc = int(metrics.get("after_inconclusive_count", 0) or 0)
    inc_bd_bps = int(metrics.get("inconclusive_burndown_bps", 0) or 0)
    inc_bd_str = escape(str(metrics.get("inconclusive_burndown_pct_str") or bps_to_pct_str(inc_bd_bps)))
    inc_bd_bar = max(min(inc_bd_bps / 100.0, 100.0), 0.0)

    hard_cand = int(metrics.get("hardening_candidates_count", 0) or 0)
    hard_pass = int(metrics.get("hardened_to_pass_count", 0) or 0)
    hard_bps = int(metrics.get("hardening_verification_bps", 0) or 0)
    hard_str = escape(str(metrics.get("hardening_verification_pct_str") or bps_to_pct_str(hard_bps)))
    hard_bar = max(min(hard_bps / 100.0, 100.0), 0.0)
    vis_unlocked = int(metrics.get("visibility_unlocked_count", 0) or 0)

    reg_count = int(metrics.get("regression_count", 0) or 0)
    drift_flag = bool(metrics.get("drift_detected", False))
    drift_label = f"{reg_count} Regression(s)" if drift_flag else "0 Regressions (Clean)"
    drift_class = "fail" if drift_flag else "pass"

    elapsed_human = escape(str(metrics.get("elapsed_human", "n/a")))
    b_ts = escape(str(metrics.get("before_timestamp") or "n/a"))
    a_ts = escape(str(metrics.get("after_timestamp") or "n/a"))

    class_labels = {
        "hardened_to_pass": ("HARDENED TO PASS", "badge-pass"),
        "sustained_pass": ("SUSTAINED PASS", "badge-pass"),
        "regression": ("DRIFT / REGRESSION", "badge-fail"),
        "visibility_unlocked_gap_exposed": ("VISIBILITY UNLOCKED -> GAP EXPOSED", "badge-warn"),
        "visibility_lost": ("VISIBILITY LOST", "badge-warn"),
        "persistent_fail": ("PERSISTENT FAIL", "badge-fail"),
        "persistent_inconclusive": ("NEEDS POLICY / ELEVATION", "badge-inc"),
    }

    customer_cards = []
    mssp_rows = []
    for item in transitions:
        tid_raw = str(item.get("test_id", ""))
        tid = escape(tid_raw)
        title = escape(str(item.get("title", "")))
        mitre_raw = str(item.get("mitre_attack", ""))
        mitre_html = render_mitre_badges(mitre_raw)
        bv = escape(str(item.get("before_verdict", "")))
        av_raw = str(item.get("after_verdict", "INCONCLUSIVE"))
        av = escape(av_raw)
        t_cls_key = str(item.get("transition_class", ""))
        cls_text, cls_style = class_labels.get(t_cls_key, (escape(t_cls_key.upper()), "badge-inc"))
        b_rat = escape(str(item.get("before_rationale", "")))
        a_rat = escape(str(item.get("after_rationale", "")))
        impact = escape(str(item.get("customer_impact", "")))
        action = escape(str(item.get("mssp_action", "")))
        b_sha_full = escape(str(item.get("before_sha256", "")))
        a_sha_full = escape(str(item.get("after_sha256", "")))
        b_sha = escape(str(item.get("before_sha256", ""))[:16])
        a_sha = escape(str(item.get("after_sha256", ""))[:16])

        pb = _check_playbook(tid_raw, av_raw, str(item.get("after_rationale", "")))
        biz_headline = escape(pb["headline"])
        mssp_cmd = escape(pb["cmd"])
        mssp_cmd_js = escape(json.dumps(pb["cmd"]))

        customer_cards.append(
            f'<article class="card {av_raw.lower()}">'
            f'<div class="eyebrow"><span>{tid}</span> · {mitre_html}</div>'
            f'<h2>{title}</h2>'
            f'<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">'
            f'<span class="pill {bv.lower()}">{bv}</span> <span style="color:var(--text-dim)">&rarr;</span> '
            f'<span class="pill {av.lower()}"><strong>{av}</strong></span>'
            f'<span class="tbadge {cls_style}" style="margin:0">{cls_text}</span>'
            f'</div>'
            f'<div class="biz-headline">{biz_headline}</div>'
            f'<p>{impact}</p>'
            f'<div class="impact-box"><b>Recommended Next Step:</b> {action}</div>'
            f'<details class="drawer"><summary>Before / After Evidence &amp; Receipt Hashes</summary>'
            f'<pre>Before ({before_dir}): {bv} — {b_rat}\nBefore SHA-256: {b_sha_full}\n\nAfter  ({after_dir}): {av} — {a_rat}\nAfter  SHA-256: {a_sha_full}</pre></details>'
            f'</article>'
        )

        mssp_rows.append(
            f'<tr>'
            f'<td><div class="mono" style="font-weight:800;color:var(--cyan)">{tid}</div>'
            f'<div style="font-weight:700;margin:4px 0">{title}</div>'
            f'<div style="margin-top:6px">{mitre_html}</div></td>'
            f'<td><span class="pill {bv.lower()}">{bv}</span>'
            f'<div style="font-size:12.5px;color:var(--text-muted);margin:8px 0">{b_rat}</div>'
            f'<div class="mono" style="font-size:11px;color:var(--text-dim)">SHA-256: {b_sha}…</div></td>'
            f'<td><span class="pill {av.lower()}">{av}</span>'
            f'<div style="font-size:12.5px;color:var(--text-muted);margin:8px 0">{a_rat}</div>'
            f'<div class="mono" style="font-size:11px;color:var(--text-dim)">SHA-256: {a_sha}…</div></td>'
            f'<td><span class="tbadge {cls_style}">{cls_text}</span>'
            f'<div style="font-size:13px;margin:6px 0"><b>Customer / SOC Impact:</b> {impact}</div>'
            f'<div style="font-size:13px;margin:6px 0"><b>MSSP Next Action:</b> {action}</div>'
            f'<div class="cmd-box"><code class="mono">{mssp_cmd}</code>'
            f'<button type="button" class="copy-btn" onclick=\'copyVerimetryText(this, {mssp_cmd_js})\'>Copy</button></div></td>'
            f'</tr>'
        )

    decoded_bundle = {"dsse_payloadType": payload_type, "payload_sha256": payload_sha, "signer_keyid": keyid, "receipt": receipt}
    raw_json = escape(json.dumps(decoded_bundle, indent=2, ensure_ascii=False))
    verify_cmd = f"python -m verimetry verify --receipt .\\evidence-comparison\\comparison-receipt.json --public .\\verimetry_private.pub.pem # SHA-256: {rec_sha}"
    verify_cmd_js = escape(json.dumps(verify_cmd))

    cust_checked = "checked" if persona in ("both", "customer") else ""
    mssp_checked = "checked" if persona == "mssp" else ""

    pass_after_pct = round((int(metrics.get("after_pass_count", 0) or 0) / max(total, 1)) * 100.0, 1)
    fail_after_pct = round((int(metrics.get("after_fail_count", 0) or 0) / max(total, 1)) * 100.0, 1)
    inc_after_pct = round((int(metrics.get("after_inconclusive_count", 0) or 0) / max(total, 1)) * 100.0, 1)

    html = f'''<!doctype html><html lang="en" data-theme="dark"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Verimetry | Multi-Run Assurance Comparison</title>
<style>{_OPENROUTER_DESIGN_CSS}</style></head><body>
<input class="view-radio" type="radio" name="role_view" id="role-customer" {cust_checked}>
<input class="view-radio" type="radio" name="role_view" id="role-mssp" {mssp_checked}>
<header class="topbar">
  <div class="topbar-inner">
    <div class="brand">
      <span class="brand-dot"></span>
      <span class="brand-name">VERIMETRY</span>
      <span class="brand-tag mono">Multi-Run Delta · DSSE v1 · v1.0.0-rc1</span>
    </div>
    <div class="controls-bar">
      <div class="role-switcher" role="tablist" aria-label="Role Switcher">
        <label class="role-btn" for="role-customer" role="tab" tabindex="0">Customer View</label>
        <label class="role-btn" for="role-mssp" role="tab" tabindex="0">MSSP Operations View</label>
      </div>
      <button type="button" class="theme-btn" onclick="toggleVerimetryTheme()">&#9680; Theme</button>
    </div>
  </div>
</header>
<main>
  <section class="trust-hero">
    <div class="trust-top">
      <div class="trust-title">
        <div class="eyebrow">VERIMETRY / MULTI-RUN ASSURANCE DELTA</div>
        <h1>Telemetry &amp; Control Assurance Comparison</h1>
        <p>{overall_rationale}</p>
      </div>
      <div class="score-box">
        <div class="score-lbl">Verified Telemetry Coverage</div>
        <div class="score-num" style="color:var(--pass)">{b_cov_str} &rarr; {a_cov_str}</div>
        <div class="mono" style="font-size:12px;color:var(--text-muted)">Delta Verdict: <span class="pill {overall_verdict.lower()}">{overall_verdict}</span></div>
      </div>
    </div>
    <div class="sparkbar" aria-label="Post-Comparison Verdict Distribution">
      <div class="spark-seg pass" style="width:{pass_after_pct}%"></div>
      <div class="spark-seg fail" style="width:{fail_after_pct}%"></div>
      <div class="spark-seg inconclusive" style="width:{inc_after_pct}%"></div>
    </div>
    <div class="trust-meta">
      <span class="sig-badge">&#10003; DSSE Ed25519 Verified Offline</span>
      <span class="meta-chip"><b>Host:</b> <span class="mono">{host}</span></span>
      <span class="meta-chip"><b>Before:</b> <span class="mono">{before_dir} ({b_ts})</span></span>
      <span class="meta-chip"><b>After:</b> <span class="mono">{after_dir} ({a_ts})</span></span>
      <span class="meta-chip"><b>Receipt SHA-256:</b> <span class="mono">{rec_sha[:16]}…</span></span>
      <button type="button" class="copy-btn" onclick='copyVerimetryText(this, {verify_cmd_js})'>Copy Verification Proof</button>
    </div>
  </section>

  <section class="kpi-strip" aria-label="MSSP Assurance Metrics">
    <article class="kpi-card">
      <div class="k-lbl">1. Verified Telemetry Coverage</div>
      <div class="k-val">{b_cov_str} &rarr; {a_cov_str}</div>
      <div class="mini-bar"><div class="mini-bar-fill" style="width:{a_cov_bar}%"></div></div>
      <div class="k-sub">{metrics.get('before_pass_count', 0)}/{total} &rarr; {metrics.get('after_pass_count', 0)}/{total} PASS ({d_cov_str})</div>
    </article>
    <article class="kpi-card">
      <div class="k-lbl">2. INCONCLUSIVE Burn-Down</div>
      <div class="k-val">{inc_bd_str}</div>
      <div class="mini-bar"><div class="mini-bar-fill" style="width:{inc_bd_bar}%"></div></div>
      <div class="k-sub">{b_inc} &rarr; {a_inc} INCONCLUSIVE ({vis_unlocked} check(s) unlocked to definitive verdict)</div>
    </article>
    <article class="kpi-card">
      <div class="k-lbl">3. Hardening Verification Rate</div>
      <div class="k-val">{hard_str}</div>
      <div class="mini-bar"><div class="mini-bar-fill" style="width:{hard_bar}%"></div></div>
      <div class="k-sub">{hard_pass} of {hard_cand} non-PASS check(s) transitioned to verified PASS</div>
    </article>
    <article class="kpi-card {drift_class}">
      <div class="k-lbl">4. Telemetry Drift / Regressions</div>
      <div class="k-val">{drift_label}</div>
      <div class="k-sub">PASS &rarr; FAIL or PASS &rarr; INCONCLUSIVE transitions</div>
    </article>
    <article class="kpi-card">
      <div class="k-lbl">5. Elapsed Time (&Delta;t)</div>
      <div class="k-val">{elapsed_human}</div>
      <div class="k-sub">{metrics.get('elapsed_seconds', 'n/a')}s between baseline and follow-up</div>
    </article>
  </section>

  <section class="role-panel panel-customer" aria-label="Customer View">
    <div class="section-hdr">
      <h2>Customer View — Before &rarr; After Value Proof &amp; Audit Readiness</h2>
      <span style="font-size:12.5px;color:var(--text-muted)">Plain-English onboarding &amp; hardening progress · Raw JSON tucked in expandable drawers</span>
    </div>
    <div class="grid">{''.join(customer_cards)}</div>
    <details class="drawer"><summary>Inspect Signed DSSE Comparison Receipt (JSON)</summary><pre class="raw-block">{raw_json}</pre></details>
  </section>

  <section class="role-panel panel-mssp" aria-label="MSSP Operations View">
    <div class="section-hdr">
      <h2>MSSP Operations View — Telemetry Engineering &amp; Remediation Matrix</h2>
      <span style="font-size:12.5px;color:var(--text-muted)">Side-by-side state transitions, SHA-256 chain of custody, and copyable GPO/PowerShell remediations</span>
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th style="width:20%">Check &amp; MITRE ATT&amp;CK</th>
            <th style="width:21%">Before ({before_dir})</th>
            <th style="width:21%">After ({after_dir})</th>
            <th style="width:38%">Transition, Impact &amp; Copyable Remediation</th>
          </tr>
        </thead>
        <tbody>
          {''.join(mssp_rows)}
        </tbody>
      </table>
    </div>
    <details class="drawer" open><summary>Signed DSSE Delta Receipt &amp; Cryptographic Chain of Custody (JSON)</summary><pre class="raw-block">{raw_json}</pre></details>
  </section>

  <div class="notice">
    <b>Cryptographic Verification Boundary</b>
    <p style="margin:6px 0 0">Every input DSSE receipt in <code class="mono">{before_dir}</code> and <code class="mono">{after_dir}</code> was independently verified (DSSE PAE Ed25519 signature, duplicate-key &amp; no-float guard, and deterministic verdict/reason_codes recomputation) before computing these metrics. Comparison Receipt ID: <code class="mono">{rec_id}</code> · Payload SHA-256: <code class="mono">{rec_sha}</code> · Signer KeyID: <code class="mono">{signer_fp}</code>.</p>
  </div>

  <footer>
    <span>Local-only output · Zero external assets · Independently verifiable via <code class="mono">verimetry verify</code></span>
    <span class="mono">Verimetry {__version__} · Apache-2.0</span>
  </footer>
</main>
{_INTERACTIVE_JS}
</body></html>'''
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    Path(output).write_text(html, encoding="utf-8")

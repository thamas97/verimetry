"""Zero-dependency native Tkinter GUI for Verimetry's guided 3-step live Windows test.

Uses only Python standard library (`tkinter` + `ttk`) and existing Verimetry modules so the
single runtime dependency (`cryptography`) guarantee stays intact. Safe to import on headless
Linux/CI environments where `_tkinter` is absent.
"""
from __future__ import annotations

import base64
import ctypes
import json
import locale
import os
import platform
import re
import shutil
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path
from typing import Any, Iterable

from . import __version__, cli
from .core import TEST_SPECS, WINDOWS_INTERNALS_CHECK_IDS
from .receipts import (
    extract_unverified_receipt,
    init_keys,
    load_json_strict,
    verify,
)

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    _TK_AVAILABLE = True
    _TK_IMPORT_ERROR: Exception | None = None
except Exception as exc:  # pragma: no cover - headless Python builds without _tkinter
    tk = None  # type: ignore[assignment]
    filedialog = None  # type: ignore[assignment]
    messagebox = None  # type: ignore[assignment]
    ttk = None  # type: ignore[assignment]
    _TK_AVAILABLE = False
    _TK_IMPORT_ERROR = exc


ISSUE_FEEDBACK_URL = "https://github.com/thamas97/verimetry/issues/1"
READONLY_BANNER_TEXT = "Strictly read-only · 0 drivers · 0 host mutations · Local Ed25519 signing"

_PEM_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)

_THEME = {
    "bg": "#090a0f",
    "bg_elev": "#10131c",
    "bg_card": "#121621",
    "bg_subtle": "#181d2c",
    "bg_code": "#0b0e16",
    "border": "#232a3d",
    "text": "#f1f5f9",
    "text_muted": "#94a3b8",
    "accent": "#6366f1",
    "accent_hover": "#4f46e5",
    "cyan": "#38bdf8",
    "pass": "#10b981",
    "pass_bg": "#0c2b23",
    "fail": "#f43f5e",
    "fail_bg": "#31101b",
    "inc": "#f59e0b",
    "inc_bg": "#2e200b",
    "info_bg": "#0f2438",
}


# ---------------------------------------------------------------------------
# Headless-safe pure helper functions (zero Tk dependency; unit-tested in CI)
# ---------------------------------------------------------------------------


def is_tkinter_available() -> bool:
    """Return True when stdlib tkinter is importable in the current Python runtime."""
    return bool(_TK_AVAILABLE)


def get_privilege_context() -> dict[str, Any]:
    """Inspect OS and Windows elevation state without spawning subprocesses."""
    sys_name = platform.system()
    if sys_name != "Windows":
        return {
            "platform": sys_name,
            "is_windows": False,
            "is_admin": False,
            "mode": "demo",
            "badge_text": f"Demo Mode ({sys_name})",
            "badge_kind": "info",
        }
    is_admin = False
    try:
        shell32 = getattr(getattr(ctypes, "windll", None), "shell32", None)
        if shell32 is not None:
            is_admin = bool(shell32.IsUserAnAdmin())
    except Exception:
        is_admin = False
    if is_admin:
        return {
            "platform": sys_name,
            "is_windows": True,
            "is_admin": True,
            "mode": "elevated",
            "badge_text": "Administrator (Elevated)",
            "badge_kind": "pass",
        }
    return {
        "platform": sys_name,
        "is_windows": True,
        "is_admin": False,
        "mode": "standard",
        "badge_text": "Standard User (Non-Elevated)",
        "badge_kind": "inc",
    }


def relaunch_as_admin(workdir: str | Path | None = None) -> tuple[bool, str]:
    """Prompt Windows UAC via ShellExecuteW('runas') to relaunch `python -m verimetry gui`."""
    if platform.system() != "Windows":
        return False, "UAC elevation is only available on Windows."
    try:
        shell32 = getattr(getattr(ctypes, "windll", None), "shell32", None)
        if shell32 is None:
            return False, "Windows shell32 API unavailable."
        if workdir is not None:
            resolved = str(Path(workdir).resolve())
            params = subprocess.list2cmdline(["-m", "verimetry", "gui", "--workdir", resolved])
            lp_dir: str | None = resolved
        else:
            params = "-m verimetry gui"
            lp_dir = None
        rc = shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            params,
            lp_dir,
            1,
        )
        if int(rc) > 32:
            return True, "Launched elevated Verimetry GUI via Windows UAC."
        return False, f"UAC elevation cancelled or declined (ShellExecuteW code {rc})."
    except Exception as exc:
        return False, f"Unable to trigger Windows UAC relaunch: {exc}"


def load_directory_verdicts(evidence_dir: str | Path) -> list[dict[str, Any]]:
    """Read signed receipt-*.json envelopes in a directory for UI display (ordered by check ID)."""
    d = Path(evidence_dir)
    if not d.exists() or not d.is_dir():
        return []
    by_id: dict[str, dict[str, Any]] = {}
    extra: list[dict[str, Any]] = []
    for fpath in sorted(d.glob("receipt-*.json")):
        if fpath.name == "comparison-receipt.json":
            continue
        try:
            pack = load_json_strict(fpath)
            rec, payload_sha, keyid, _pt = extract_unverified_receipt(pack)
        except Exception:
            continue
        test_meta = rec.get("test") or {}
        tid = str(test_meta.get("id") or fpath.stem)
        spec = TEST_SPECS.get(tid, {})
        item = {
            "test_id": tid,
            "slug": spec.get("slug") or fpath.stem.removeprefix("receipt-"),
            "title": test_meta.get("title") or spec.get("title") or tid,
            "mitre_attack": test_meta.get("mitre_attack") or spec.get("mitre_attack") or "",
            "verdict": str(rec.get("verdict") or "INCONCLUSIVE"),
            "reason_codes": list(rec.get("reason_codes") or []),
            "rationale": str(rec.get("rationale") or ""),
            "receipt_path": str(fpath),
            "payload_sha256": payload_sha,
            "signer_keyid": keyid,
            "target_host": str((rec.get("target") or {}).get("host") or ""),
            "simulated": bool(rec.get("simulated", False)),
        }
        if tid in WINDOWS_INTERNALS_CHECK_IDS:
            by_id[tid] = item
        else:
            extra.append(item)
    ordered = [by_id[tid] for tid in WINDOWS_INTERNALS_CHECK_IDS if tid in by_id]
    ordered.extend(extra)
    return ordered


def count_verdicts(checks: Iterable[dict[str, Any]]) -> dict[str, int]:
    """Count PASS / FAIL / INCONCLUSIVE verdicts from loaded check entries."""
    counts = {"PASS": 0, "FAIL": 0, "INCONCLUSIVE": 0}
    for chk in checks:
        v = str(chk.get("verdict") or "").upper()
        if v in counts:
            counts[v] += 1
    return counts


def _is_key_readable(key_path: Path) -> bool:
    """Return True if key_path exists and can be read by the current process token."""
    if not key_path.exists():
        return False
    try:
        key_path.read_bytes()
        return True
    except PermissionError:
        return False


def _resolve_dir_public_key(evidence_dir: Path, shared_pub: Path) -> Path | None:
    """Find which existing public key verifies the receipts in evidence_dir."""
    candidates: list[Path] = []
    if shared_pub.exists():
        candidates.append(shared_pub)
    dir_pub = evidence_dir / "signer.pub.pem"
    if dir_pub.exists() and dir_pub not in candidates:
        candidates.append(dir_pub)
    receipt_files = sorted(
        p for p in evidence_dir.glob("receipt-*.json") if p.name != "comparison-receipt.json"
    )
    if not receipt_files:
        return candidates[0] if candidates else None
    sample_path = receipt_files[0]
    try:
        sample_pack = load_json_strict(sample_path)
    except Exception:
        return candidates[0] if candidates else None
    for pub in candidates:
        ok, _why = verify(sample_pack, pub)
        if ok:
            return pub
    return candidates[0] if candidates else None


def run_step1_baseline(
    workdir: str | Path,
    live: bool | None = None,
    window: int = 4,
) -> dict[str, Any]:
    """Step 1 backend: ensure local keypair via init_keys() and run baseline assess into ./evidence."""
    base = Path(workdir).resolve()
    base.mkdir(parents=True, exist_ok=True)
    out_dir = base / "evidence"
    key_path = base / "verimetry-key.pem"
    pub_path = key_path.with_suffix(".pub.pem")
    key_created = False

    if not key_path.exists():
        pub_path = init_keys(key_path)
        key_created = True
    elif not _is_key_readable(key_path):
        # Fall back cleanly to per-folder signer.pem if an existing shared key is ACL-locked
        key_path = None  # type: ignore[assignment]
        pub_path = out_dir / "signer.pub.pem"
    elif not pub_path.exists():
        raise FileNotFoundError(f"Expected matching public key alongside {key_path}: {pub_path}")

    use_live = (platform.system() == "Windows") if live is None else bool(live)
    cli.generate(
        out=out_dir,
        key=key_path,
        live=use_live,
        window=window,
        suite="internals",
        persona="both",
    )
    if key_path is None:
        key_path = out_dir / "signer.pem"
        pub_path = out_dir / "signer.pub.pem"

    checks = load_directory_verdicts(out_dir)
    return {
        "mode": "live" if use_live else "demo",
        "out_dir": str(out_dir),
        "key_path": str(key_path),
        "pub_path": str(pub_path),
        "key_created": key_created,
        "checks": checks,
        "counts": count_verdicts(checks),
        "report_path": str(out_dir / "report.html"),
    }


def run_step2_elevated_and_compare(
    workdir: str | Path,
    live: bool | None = None,
    window: int = 4,
) -> dict[str, Any]:
    """Step 2 backend: run elevated assess into ./evidence-elevated and compare against ./evidence.

    Gracefully handles the Windows different-Admin-SID NTFS ACL gotcha: if ./verimetry-key.pem
    raises PermissionError under a different elevated account, falls back to per-folder signer.pem
    and passes --before-public / --after-public to compare instead of crashing.
    """
    base = Path(workdir).resolve()
    base.mkdir(parents=True, exist_ok=True)
    before_dir = base / "evidence"
    after_dir = base / "evidence-elevated"
    compare_dir = base / "evidence-comparison"
    shared_key = base / "verimetry-key.pem"
    shared_pub = shared_key.with_suffix(".pub.pem")

    use_live = (platform.system() == "Windows") if live is None else bool(live)
    used_key_fallback = False
    fallback_note = ""

    # Determine whether the shared private key is usable under the current elevated token
    elevated_key: Path | None = None
    if shared_key.exists():
        try:
            shared_key.read_bytes()
            if shared_pub.exists():
                elevated_key = shared_key
            else:
                used_key_fallback = True
                fallback_note = (
                    "Shared public key verimetry-key.pub.pem was missing; "
                    "using per-folder signer.pem for elevated evidence."
                )
        except PermissionError:
            used_key_fallback = True
            fallback_note = (
                "Different Windows Admin SID detected: verimetry-key.pem is ACL-locked to the "
                "standard user account. Fell back cleanly to per-folder signer.pem with "
                "--before-public / --after-public on compare."
            )
    else:
        try:
            init_keys(shared_key)
            elevated_key = shared_key
        except PermissionError:
            used_key_fallback = True
            fallback_note = (
                "Unable to create shared key at workspace root; using per-folder signer.pem."
            )

    try:
        cli.generate(
            out=after_dir,
            key=elevated_key,
            live=use_live,
            window=window,
            suite="internals",
            persona="both",
        )
    except PermissionError:
        # Defense-in-depth fallback if key ACL permission error happens during signing
        used_key_fallback = True
        fallback_note = (
            "PermissionError reading shared verimetry-key.pem under elevated account; "
            "fell back cleanly to per-folder signer.pem for elevated evidence and comparison."
        )
        elevated_key = None
        cli.generate(
            out=after_dir,
            key=None,
            live=use_live,
            window=window,
            suite="internals",
            persona="both",
        )

    after_pub = (
        elevated_key.with_suffix(".pub.pem")
        if elevated_key is not None
        else (after_dir / "signer.pub.pem")
    )
    after_checks = load_directory_verdicts(after_dir)
    after_counts = count_verdicts(after_checks)

    comparison_receipt_path: str | None = None
    comparison_report_path: str | None = None
    comparison_pub_path: str | None = None
    comparison_metrics: dict[str, Any] | None = None
    comparison_transitions: list[dict[str, Any]] = []
    comparison_verdict: str | None = None
    comparison_rationale: str | None = None
    has_before = before_dir.exists() and any(
        p.name != "comparison-receipt.json" for p in before_dir.glob("receipt-*.json")
    )

    if has_before:
        before_pub = _resolve_dir_public_key(before_dir, shared_pub)
        if before_pub is None:
            raise ValueError(
                f"Could not locate trusted public key for Step 1 receipts in {before_dir}"
            )
        compare_key = elevated_key if (elevated_key is not None and not used_key_fallback) else None
        if compare_key is not None and before_pub.resolve() == after_pub.resolve():
            cli.run_compare(
                before=before_dir,
                after=after_dir,
                out=compare_dir,
                key=compare_key,
                public=after_pub,
                persona="both",
            )
            comparison_pub_path = str(after_pub)
        else:
            cli.run_compare(
                before=before_dir,
                after=after_dir,
                out=compare_dir,
                key=compare_key,
                public=None,
                before_public=before_pub,
                after_public=after_pub,
                persona="both",
            )
            comparison_pub_path = (
                str(compare_key.with_suffix(".pub.pem"))
                if compare_key is not None
                else str(compare_dir / "signer.pub.pem")
            )

        rec_file = compare_dir / "comparison-receipt.json"
        html_file = compare_dir / "comparison-report.html"
        comparison_receipt_path = str(rec_file)
        comparison_report_path = str(html_file)
        pack = load_json_strict(rec_file)
        rec, _sha, _kid, _pt = extract_unverified_receipt(pack)
        obs = rec.get("observation") or {}
        comparison_metrics = obs.get("metrics") or {}
        comparison_transitions = obs.get("transitions") or []
        comparison_verdict = str(rec.get("verdict") or "")
        comparison_rationale = str(rec.get("rationale") or "")

    return {
        "mode": "live" if use_live else "demo",
        "after_dir": str(after_dir),
        "after_report_path": str(after_dir / "report.html"),
        "after_pub_path": str(after_pub),
        "after_checks": after_checks,
        "after_counts": after_counts,
        "has_before": has_before,
        "used_key_fallback": used_key_fallback,
        "fallback_note": fallback_note,
        "comparison_receipt_path": comparison_receipt_path,
        "comparison_report_path": comparison_report_path,
        "comparison_pub_path": comparison_pub_path,
        "comparison_verdict": comparison_verdict,
        "comparison_rationale": comparison_rationale,
        "comparison_metrics": comparison_metrics,
        "comparison_transitions": comparison_transitions,
    }


def run_verify_receipt(
    receipt_path: str | Path,
    public_path: str | Path,
    expected_nonce: str | None = None,
) -> dict[str, Any]:
    """Verify a DSSE v1 receipt offline against a trusted Ed25519 public key."""
    rpath = Path(receipt_path)
    ppath = Path(public_path)
    nonce = expected_nonce.strip() if isinstance(expected_nonce, str) and expected_nonce.strip() else None
    try:
        package = load_json_strict(rpath)
    except Exception as exc:
        return {
            "ok": False,
            "status": "REJECTED",
            "message": f"Invalid JSON ({exc})",
            "receipt": None,
            "payload_sha256": None,
            "keyid": None,
            "payload_type": None,
        }
    ok, why = verify(package, ppath, expected_nonce=nonce)
    if not ok:
        return {
            "ok": False,
            "status": "REJECTED",
            "message": why,
            "receipt": None,
            "payload_sha256": None,
            "keyid": None,
            "payload_type": package.get("payloadType") if isinstance(package, dict) else None,
        }
    rec, payload_sha, keyid, payload_type = extract_unverified_receipt(package)
    return {
        "ok": True,
        "status": "VERIFIED",
        "message": why,
        "receipt": rec,
        "payload_sha256": payload_sha,
        "keyid": keyid,
        "payload_type": payload_type,
    }


def run_tamper_trap(
    receipt_path: str | Path,
    public_path: str | Path,
    forged_path: str | Path | None = None,
) -> dict[str, Any]:
    """Copy a DSSE receipt to forged.json, flip 1 byte in 'payload', and run offline verify().

    Always operates on a separate copy (`forged_path`, defaulting to `./forged.json` in the
    receipt's parent or provided workdir) so original receipts remain untouched.
    """
    src = Path(receipt_path)
    pub = Path(public_path)
    dst = Path(forged_path) if forged_path is not None else (src.parent / "forged.json")

    envelope = load_json_strict(src)
    if not isinstance(envelope, dict) or not isinstance(envelope.get("payload"), str) or not envelope["payload"]:
        raise ValueError("Source file is not a valid DSSE envelope with a base64 payload")

    raw = bytearray(base64.b64decode(envelope["payload"], validate=True))
    if not raw:
        raise ValueError("DSSE payload is empty")

    # Flip 1 bit of 1 decoded payload byte and re-encode valid Base64 so Ed25519 PAE fails closed
    flip_idx = len(raw) // 2
    orig_byte = raw[flip_idx]
    raw[flip_idx] = orig_byte ^ 0x01
    forged_byte = raw[flip_idx]

    forged_env = dict(envelope)
    forged_env["payload"] = base64.b64encode(bytes(raw)).decode("ascii")
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(forged_env, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    ok, why = verify(load_json_strict(dst), pub)
    return {
        "forged_path": str(dst),
        "verified": ok,
        "status": "VERIFIED" if ok else "REJECTED",
        "message": why,
        "flipped_byte_offset": flip_idx,
        "original_byte": orig_byte,
        "forged_byte": forged_byte,
    }


def sanitize_public_text(text: str, forbidden_tokens: Iterable[str] = ()) -> str:
    """Strip PEM private keys and host/user identifiers from public issue-reporting text."""
    cleaned = _PEM_PRIVATE_KEY_RE.sub("[REDACTED-PRIVATE-KEY]", text)
    tokens: list[str] = []
    for candidate in (
        platform.node(),
        os.environ.get("COMPUTERNAME", ""),
        os.environ.get("HOSTNAME", ""),
        *forbidden_tokens,
    ):
        tok = (candidate or "").strip()
        if len(tok) >= 3 and tok not in tokens:
            tokens.append(tok)
    # Replace longer tokens first so hostnames containing shorter substrings redact completely
    for tok in sorted(tokens, key=len, reverse=True):
        cleaned = re.sub(re.escape(tok), "[REDACTED-HOST]", cleaned, flags=re.IGNORECASE)
    return cleaned


def _detect_os_and_locale(workdir: Path | None = None) -> tuple[str, str]:
    """Detect anonymized OS/Build + locale string and optional EDR/AV hint from local inventory."""
    os_label = f"{platform.system()} {platform.release()} ({platform.version()})"
    edr_hint = "<Defender / CrowdStrike / SentinelOne>"

    if workdir is not None:
        for inv_path in (
            workdir / "evidence-elevated" / "windows-inventory.json",
            workdir / "evidence" / "windows-inventory.json",
        ):
            if inv_path.exists():
                try:
                    inv = load_json_strict(inv_path)
                    sections = inv.get("sections") or {}
                    os_sec = (sections.get("os") or {}).get("data") or {}
                    caption = str(os_sec.get("Caption") or "").strip()
                    build = str(os_sec.get("BuildNumber") or "").strip()
                    if caption and build:
                        os_label = f"{caption} (Build {build})"
                    elif caption:
                        os_label = caption
                    def_sec = sections.get("defender") or {}
                    if def_sec.get("status") == "observed":
                        edr_hint = "Microsoft Defender (add any third-party EDR if installed)"
                    break
                except Exception:
                    continue

    loc_name = ""
    try:
        loc_tuple = locale.getlocale()
        if loc_tuple and loc_tuple[0]:
            loc_name = loc_tuple[0].replace("_", "-")
    except Exception:
        loc_name = ""
    if not loc_name:
        loc_name = os.environ.get("LANG", "unknown").split(".")[0].replace("_", "-") or "unknown"

    return f"{os_label}, `{loc_name}`", edr_hint


def format_issue_summary(
    workdir: str | Path | None = None,
    baseline_checks: list[dict[str, Any]] | None = None,
    elevated_checks: list[dict[str, Any]] | None = None,
    environment: str = "<Bare metal / VMware / Hyper-V / Cloud VM>",
    edr: str | None = None,
    os_build_locale: str | None = None,
    extra_forbidden_tokens: Iterable[str] = (),
) -> str:
    """Build the anonymized 5-line Issue #1 reporting template (zero hostnames, zero private keys)."""
    base = Path(workdir).resolve() if workdir is not None else None
    if baseline_checks is None and base is not None:
        baseline_checks = load_directory_verdicts(base / "evidence")
    if elevated_checks is None and base is not None:
        elevated_checks = load_directory_verdicts(base / "evidence-elevated")

    baseline_checks = list(baseline_checks or [])
    elevated_checks = list(elevated_checks or [])

    detected_os, detected_edr = _detect_os_and_locale(base)
    os_line = os_build_locale if os_build_locale is not None else detected_os
    edr_line = edr if edr is not None else detected_edr

    def _fmt_counts(checks: list[dict[str, Any]]) -> str:
        if not checks:
            return "not run"
        c = count_verdicts(checks)
        return f"`{c['PASS']}` PASS / `{c['FAIL']}` FAIL / `{c['INCONCLUSIVE']}` INCONCLUSIVE"

    counts_line = f"Non-elevated: {_fmt_counts(baseline_checks)} | Elevated: {_fmt_counts(elevated_checks)}"

    # Summarize non-PASS items by deterministic check ID + reason codes only (never raw paths/hostnames)
    findings_src = elevated_checks if elevated_checks else baseline_checks
    non_pass_notes: list[str] = []
    observed_hosts: list[str] = []
    for chk in baseline_checks + elevated_checks:
        th = str(chk.get("target_host") or "").strip()
        if th:
            observed_hosts.append(th)

    for chk in findings_src:
        verdict = str(chk.get("verdict") or "").upper()
        if verdict in ("FAIL", "INCONCLUSIVE"):
            tid = str(chk.get("test_id") or "UNKNOWN")
            codes = chk.get("reason_codes") or []
            code_str = ", ".join(str(c) for c in codes) if codes else "no reason codes"
            non_pass_notes.append(f"`{tid}`={verdict} ({code_str})")

    unexpected_line = "; ".join(non_pass_notes) if non_pass_notes else "None (all checks PASS)"

    raw_summary = "\n".join(
        [
            f"- **OS / Build & Locale:** {os_line}",
            f"- **Environment:** {environment}",
            f"- **Active EDR / AV:** {edr_line}",
            f"- **Non-elevated vs. Elevated verdict counts:** {counts_line}",
            f"- **Any unexpected `FAIL` or `INCONCLUSIVE`?** {unexpected_line}",
        ]
    )
    return sanitize_public_text(
        raw_summary,
        forbidden_tokens=[*observed_hosts, *extra_forbidden_tokens],
    )


def list_cleanup_targets(workdir: str | Path) -> list[Path]:
    """Return local Verimetry test artifacts inside workdir (evidence*, verimetry-key*.pem, forged.json)."""
    base = Path(workdir).resolve()
    if not base.exists() or not base.is_dir():
        return []
    targets: list[Path] = []
    seen: set[Path] = set()
    for pattern in ("evidence", "evidence-*", "verimetry-key*.pem", "forged.json"):
        for path in sorted(base.glob(pattern)):
            # Guard: only direct children inside workdir; never follow symlinks outside workdir
            if path.parent != base or path.is_symlink():
                continue
            if path not in seen:
                seen.add(path)
                targets.append(path)
    return targets


def cleanup_local_evidence(workdir: str | Path) -> dict[str, list[str]]:
    """Safely delete local Verimetry evidence folders, test keys, and forged.json in workdir."""
    deleted: list[str] = []
    errors: list[str] = []
    for target in list_cleanup_targets(workdir):
        try:
            if target.is_dir():
                shutil.rmtree(target)
            else:
                try:
                    target.unlink()
                except PermissionError:
                    # Try relaxing read-only bit before retrying unlink
                    os.chmod(target, 0o600)
                    target.unlink()
            deleted.append(target.name)
        except Exception as exc:
            errors.append(f"{target.name}: {exc}")
    return {"deleted": deleted, "errors": errors}


# ---------------------------------------------------------------------------
# Native Tkinter + ttk GUI Application (only instantiated when Tk is available)
# ---------------------------------------------------------------------------


class VerimetryGUI:
    """Guided 3-step native desktop GUI for Verimetry v1.0.0."""

    def __init__(self, root: "tk.Tk", workdir: str | Path | None = None):
        self.root = root
        self.workdir = Path(workdir).resolve() if workdir is not None else Path.cwd().resolve()
        self.priv = get_privilege_context()
        self._busy = False
        self._step1_result: dict[str, Any] | None = None
        self._step2_result: dict[str, Any] | None = None

        self.root.title(f"Verimetry v{__version__} — Guided Live Windows Telemetry Test")
        self.root.geometry("1040x760")
        self.root.minsize(900, 660)
        self.root.configure(bg=_THEME["bg"])

        self._configure_styles()
        self._build_layout()
        self._refresh_existing_state()

    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        style.configure(".", background=_THEME["bg"], foreground=_THEME["text"], font=("Segoe UI", 10))
        style.configure("TFrame", background=_THEME["bg"])
        style.configure("Card.TFrame", background=_THEME["bg_card"], relief="flat")
        style.configure("Header.TFrame", background=_THEME["bg_elev"])
        style.configure("TLabel", background=_THEME["bg"], foreground=_THEME["text"])
        style.configure("Card.TLabel", background=_THEME["bg_card"], foreground=_THEME["text"])
        style.configure("Muted.TLabel", background=_THEME["bg_card"], foreground=_THEME["text_muted"])
        style.configure("Header.TLabel", background=_THEME["bg_elev"], foreground=_THEME["text"])
        style.configure(
            "HeaderMuted.TLabel",
            background=_THEME["bg_elev"],
            foreground=_THEME["text_muted"],
            font=("Segoe UI", 9),
        )

        style.configure("TNotebook", background=_THEME["bg"], borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background=_THEME["bg_subtle"],
            foreground=_THEME["text_muted"],
            padding=(16, 9),
            font=("Segoe UI", 10, "bold"),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", _THEME["bg_card"]), ("active", _THEME["border"])],
            foreground=[("selected", _THEME["text"]), ("active", _THEME["text"])],
        )

        style.configure(
            "Primary.TButton",
            background=_THEME["accent"],
            foreground="#ffffff",
            padding=(14, 8),
            font=("Segoe UI", 10, "bold"),
            borderwidth=0,
        )
        style.map(
            "Primary.TButton",
            background=[("active", _THEME["accent_hover"]), ("disabled", _THEME["bg_subtle"])],
            foreground=[("disabled", _THEME["text_muted"])],
        )

        style.configure(
            "Secondary.TButton",
            background=_THEME["bg_subtle"],
            foreground=_THEME["text"],
            padding=(12, 7),
            font=("Segoe UI", 9, "bold"),
            borderwidth=1,
        )
        style.map(
            "Secondary.TButton",
            background=[("active", _THEME["border"]), ("disabled", _THEME["bg_elev"])],
            foreground=[("disabled", _THEME["text_muted"])],
        )

        style.configure(
            "Warn.TButton",
            background=_THEME["inc_bg"],
            foreground=_THEME["inc"],
            padding=(14, 8),
            font=("Segoe UI", 10, "bold"),
            borderwidth=1,
        )
        style.map("Warn.TButton", background=[("active", "#422d0d")])

        style.configure(
            "Danger.TButton",
            background=_THEME["fail_bg"],
            foreground=_THEME["fail"],
            padding=(12, 7),
            font=("Segoe UI", 9, "bold"),
            borderwidth=1,
        )
        style.map("Danger.TButton", background=[("active", "#4c1528")])

        style.configure(
            "Verimetry.Treeview",
            background=_THEME["bg_code"],
            foreground=_THEME["text"],
            fieldbackground=_THEME["bg_code"],
            rowheight=28,
            borderwidth=0,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Verimetry.Treeview.Heading",
            background=_THEME["bg_subtle"],
            foreground=_THEME["text"],
            font=("Segoe UI", 9, "bold"),
            relief="flat",
        )
        style.map("Verimetry.Treeview", background=[("selected", _THEME["border"])])

        style.configure(
            "TEntry",
            fieldbackground=_THEME["bg_code"],
            foreground=_THEME["text"],
            insertcolor=_THEME["text"],
            padding=6,
        )
        style.configure(
            "TSpinbox",
            fieldbackground=_THEME["bg_code"],
            foreground=_THEME["text"],
        )

    def _build_layout(self) -> None:
        # Top Header
        header = ttk.Frame(self.root, style="Header.TFrame", padding=(18, 12))
        header.pack(fill="x")

        title_row = ttk.Frame(header, style="Header.TFrame")
        title_row.pack(fill="x")

        brand = tk.Label(
            title_row,
            text=f"VERIMETRY  v{__version__}",
            bg=_THEME["bg_elev"],
            fg=_THEME["text"],
            font=("Segoe UI", 14, "bold"),
        )
        brand.pack(side="left")

        subtitle = tk.Label(
            title_row,
            text="  Evidence-Gated Windows Internals Telemetry Assurance",
            bg=_THEME["bg_elev"],
            fg=_THEME["text_muted"],
            font=("Segoe UI", 10),
        )
        subtitle.pack(side="left", padx=(6, 0))

        # Privilege Badge
        badge_bg = {
            "pass": _THEME["pass_bg"],
            "inc": _THEME["inc_bg"],
            "info": _THEME["info_bg"],
        }.get(self.priv["badge_kind"], _THEME["bg_subtle"])
        badge_fg = {
            "pass": _THEME["pass"],
            "inc": _THEME["inc"],
            "info": _THEME["cyan"],
        }.get(self.priv["badge_kind"], _THEME["text"])
        self.priv_badge = tk.Label(
            title_row,
            text=f"  ● {self.priv['badge_text']}  ",
            bg=badge_bg,
            fg=badge_fg,
            font=("Segoe UI", 9, "bold"),
            padx=8,
            pady=4,
            relief="flat",
        )
        self.priv_badge.pack(side="right")

        # Read-only guarantee banner + workspace display
        banner_row = ttk.Frame(header, style="Header.TFrame")
        banner_row.pack(fill="x", pady=(8, 0))

        banner = tk.Label(
            banner_row,
            text=f"🛡  {READONLY_BANNER_TEXT}",
            bg=_THEME["pass_bg"],
            fg=_THEME["pass"],
            font=("Segoe UI", 9, "bold"),
            padx=10,
            pady=4,
        )
        banner.pack(side="left")

        self.workdir_var = tk.StringVar(value=f"Workspace: {self.workdir}")
        workdir_lbl = ttk.Label(banner_row, textvariable=self.workdir_var, style="HeaderMuted.TLabel")
        workdir_lbl.pack(side="right", padx=(8, 0))

        change_dir_btn = ttk.Button(
            banner_row,
            text="Change Folder...",
            style="Secondary.TButton",
            command=self._choose_workdir,
        )
        change_dir_btn.pack(side="right")

        # Main Guided 3-Step Notebook
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=14, pady=(12, 8))

        self.tab_step1 = ttk.Frame(self.notebook, style="Card.TFrame", padding=16)
        self.tab_step2 = ttk.Frame(self.notebook, style="Card.TFrame", padding=16)
        self.tab_step3 = ttk.Frame(self.notebook, style="Card.TFrame", padding=16)

        self.notebook.add(self.tab_step1, text="  Step 1 · Standard User Baseline  ")
        self.notebook.add(self.tab_step2, text="  Step 2 · Elevated Assess & Compare  ")
        self.notebook.add(self.tab_step3, text="  Step 3 · Offline Verify & Tamper Trap  ")

        self._build_step1_tab()
        self._build_step2_tab()
        self._build_step3_tab()

        # Utility Action Bar (Issue #1 Copy + Clean Teardown)
        util_bar = ttk.Frame(self.root, style="Header.TFrame", padding=(14, 10))
        util_bar.pack(fill="x")

        self.copy_summary_btn = ttk.Button(
            util_bar,
            text="Copy Anonymized Summary for Issue #1",
            style="Primary.TButton",
            command=self._copy_issue_summary,
        )
        self.copy_summary_btn.pack(side="left")

        open_issue_btn = ttk.Button(
            util_bar,
            text="Open Issue #1",
            style="Secondary.TButton",
            command=lambda: webbrowser.open(ISSUE_FEEDBACK_URL),
        )
        open_issue_btn.pack(side="left", padx=(8, 0))

        self.cleanup_btn = ttk.Button(
            util_bar,
            text="Clean Up Local Evidence",
            style="Danger.TButton",
            command=self._confirm_cleanup,
        )
        self.cleanup_btn.pack(side="right")

        # Bottom Status Bar
        status_bar = ttk.Frame(self.root, padding=(14, 6))
        status_bar.pack(fill="x")

        self.status_var = tk.StringVar(value="Ready. Start with Step 1 (non-elevated) to observe honest INCONCLUSIVE gates.")
        status_lbl = ttk.Label(status_bar, textvariable=self.status_var, foreground=_THEME["text_muted"])
        status_lbl.pack(side="left", fill="x", expand=True)

        self.progress = ttk.Progressbar(status_bar, mode="indeterminate", length=160)
        self.progress.pack(side="right")

    def _build_step1_tab(self) -> None:
        intro = (
            "Step 1 — Zero-Risk Baseline (Standard User): Auto-generates .\\verimetry-key.pem (if absent) "
            "and runs all 5 read-only/canary checks into .\\evidence. Privilege-gated checks cleanly output "
            "INCONCLUSIVE instead of fabricating FAILs or crashing."
        )
        ttk.Label(
            self.tab_step1,
            text=intro,
            style="Muted.TLabel",
            wraplength=960,
            justify="left",
        ).pack(fill="x", pady=(0, 12))

        controls = ttk.Frame(self.tab_step1, style="Card.TFrame")
        controls.pack(fill="x", pady=(0, 12))

        btn_label = (
            "Run Non-Elevated Assess"
            if self.priv["is_windows"]
            else "Run Non-Elevated Assess (Demo Mode)"
        )
        self.step1_run_btn = ttk.Button(
            controls,
            text=btn_label,
            style="Primary.TButton",
            command=self._start_step1,
        )
        self.step1_run_btn.pack(side="left")

        self.step1_report_btn = ttk.Button(
            controls,
            text="Open Baseline HTML Report",
            style="Secondary.TButton",
            state="disabled",
            command=lambda: self._open_file_in_browser(self.workdir / "evidence" / "report.html"),
        )
        self.step1_report_btn.pack(side="left", padx=(10, 0))

        ttk.Label(controls, text="Observation window (s):", style="Muted.TLabel").pack(side="right", padx=(8, 4))
        self.window_var = tk.IntVar(value=4)
        ttk.Spinbox(controls, from_=1, to=15, width=4, textvariable=self.window_var).pack(side="right")

        # Summary pills row
        pills = ttk.Frame(self.tab_step1, style="Card.TFrame")
        pills.pack(fill="x", pady=(0, 10))
        self.step1_pass_lbl = self._make_pill(pills, "PASS: 0", _THEME["pass_bg"], _THEME["pass"])
        self.step1_fail_lbl = self._make_pill(pills, "FAIL: 0", _THEME["fail_bg"], _THEME["fail"])
        self.step1_inc_lbl = self._make_pill(pills, "INCONCLUSIVE: 0", _THEME["inc_bg"], _THEME["inc"])
        self.step1_key_lbl = ttk.Label(pills, text="", style="Muted.TLabel")
        self.step1_key_lbl.pack(side="right")

        # 5-check results treeview
        self.step1_tree = self._make_checks_tree(self.tab_step1)

    def _build_step2_tab(self) -> None:
        intro = (
            "Step 2 — Elevated Assess & Delta Compare: Runs all 5 checks as Administrator into "
            ".\\evidence-elevated, cryptographically compares against Step 1 (.\\evidence) into "
            ".\\evidence-comparison, and computes INCONCLUSIVE burn-down and real telemetry gaps."
        )
        ttk.Label(
            self.tab_step2,
            text=intro,
            style="Muted.TLabel",
            wraplength=960,
            justify="left",
        ).pack(fill="x", pady=(0, 10))

        self.step2_baseline_var = tk.StringVar(value="Step 1 baseline: checking .\\evidence...")
        ttk.Label(
            self.tab_step2,
            textvariable=self.step2_baseline_var,
            style="Card.TLabel",
            font=("Segoe UI", 9, "bold"),
        ).pack(fill="x", pady=(0, 10))

        controls = ttk.Frame(self.tab_step2, style="Card.TFrame")
        controls.pack(fill="x", pady=(0, 10))

        if self.priv["is_windows"] and not self.priv["is_admin"]:
            self.relaunch_btn = ttk.Button(
                controls,
                text="Relaunch as Administrator (UAC)",
                style="Warn.TButton",
                command=self._handle_relaunch_admin,
            )
            self.relaunch_btn.pack(side="left")

            self.step2_run_btn = ttk.Button(
                controls,
                text="Run Elevated Assess & Compare",
                style="Primary.TButton",
                state="disabled",
                command=self._start_step2,
            )
            self.step2_run_btn.pack(side="left", padx=(10, 0))
        else:
            step2_label = (
                "Run Elevated Assess & Compare"
                if self.priv["is_windows"]
                else "Run Elevated Assess & Compare (Demo Mode)"
            )
            self.step2_run_btn = ttk.Button(
                controls,
                text=step2_label,
                style="Primary.TButton",
                command=self._start_step2,
            )
            self.step2_run_btn.pack(side="left")

        self.step2_report_btn = ttk.Button(
            controls,
            text="Open Dual-Persona HTML Report",
            style="Secondary.TButton",
            state="disabled",
            command=self._open_step2_report,
        )
        self.step2_report_btn.pack(side="left", padx=(10, 0))

        # Optional key-ACL fallback banner (hidden unless triggered)
        self.step2_fallback_var = tk.StringVar(value="")
        self.step2_fallback_lbl = tk.Label(
            self.tab_step2,
            textvariable=self.step2_fallback_var,
            bg=_THEME["inc_bg"],
            fg=_THEME["inc"],
            font=("Segoe UI", 9),
            justify="left",
            wraplength=940,
            padx=10,
            pady=6,
        )

        # Delta metrics summary card
        metrics_card = tk.Frame(self.tab_step2, bg=_THEME["bg_code"], padx=12, pady=10, highlightbackground=_THEME["border"], highlightthickness=1)
        metrics_card.pack(fill="x", pady=(0, 10))
        self.step2_metrics_var = tk.StringVar(
            value="Delta Summary: Run Step 2 after Step 1 to compute Verified Coverage, INCONCLUSIVE Burn-Down, and Drift."
        )
        tk.Label(
            metrics_card,
            textvariable=self.step2_metrics_var,
            bg=_THEME["bg_code"],
            fg=_THEME["text"],
            font=("Consolas", 9),
            justify="left",
            anchor="w",
        ).pack(fill="x")

        # Elevated check / transition table
        self.step2_tree = self._make_checks_tree(self.tab_step2, transition_mode=True)

    def _build_step3_tab(self) -> None:
        intro = (
            "Step 3 — Offline DSSE v1 Verification & Tamper Trap: Verify any signed receipt offline "
            "against a trusted Ed25519 .pub.pem key, or trigger the Tamper Trap (copies receipt to "
            ".\\forged.json, flips 1 byte in 'payload', and confirms fail-closed REJECTED)."
        )
        ttk.Label(
            self.tab_step3,
            text=intro,
            style="Muted.TLabel",
            wraplength=960,
            justify="left",
        ).pack(fill="x", pady=(0, 12))

        form = ttk.Frame(self.tab_step3, style="Card.TFrame")
        form.pack(fill="x", pady=(0, 10))
        form.columnconfigure(1, weight=1)

        self.verify_receipt_var = tk.StringVar()
        self.verify_pub_var = tk.StringVar()
        self.verify_nonce_var = tk.StringVar()

        ttk.Label(form, text="DSSE Receipt (.json):", style="Card.TLabel").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Entry(form, textvariable=self.verify_receipt_var).grid(row=0, column=1, sticky="ew", padx=8, pady=4)
        ttk.Button(form, text="Browse...", style="Secondary.TButton", command=self._browse_receipt).grid(row=0, column=2, pady=4)

        ttk.Label(form, text="Trusted Public Key (.pub.pem):", style="Card.TLabel").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(form, textvariable=self.verify_pub_var).grid(row=1, column=1, sticky="ew", padx=8, pady=4)
        ttk.Button(form, text="Browse...", style="Secondary.TButton", command=self._browse_public_key).grid(row=1, column=2, pady=4)

        ttk.Label(form, text="Expected Nonce (optional):", style="Card.TLabel").grid(row=2, column=0, sticky="w", pady=4)
        ttk.Entry(form, textvariable=self.verify_nonce_var).grid(row=2, column=1, sticky="ew", padx=8, pady=4)

        btn_row = ttk.Frame(self.tab_step3, style="Card.TFrame")
        btn_row.pack(fill="x", pady=(4, 10))

        self.verify_btn = ttk.Button(
            btn_row,
            text="Verify Offline",
            style="Primary.TButton",
            command=self._handle_verify_offline,
        )
        self.verify_btn.pack(side="left")

        self.tamper_btn = ttk.Button(
            btn_row,
            text="Test Tamper Trap (Flip 1 Byte -> forged.json)",
            style="Danger.TButton",
            command=self._handle_tamper_trap,
        )
        self.tamper_btn.pack(side="left", padx=(10, 0))

        self.verify_banner = tk.Label(
            self.tab_step3,
            text="Select a DSSE receipt and public key, then click 'Verify Offline' or 'Test Tamper Trap'.",
            bg=_THEME["bg_subtle"],
            fg=_THEME["text_muted"],
            font=("Segoe UI", 10, "bold"),
            anchor="w",
            padx=12,
            pady=8,
            justify="left",
            wraplength=940,
        )
        self.verify_banner.pack(fill="x", pady=(0, 8))

        out_frame = ttk.Frame(self.tab_step3, style="Card.TFrame")
        out_frame.pack(fill="both", expand=True)
        self.verify_output = tk.Text(
            out_frame,
            bg=_THEME["bg_code"],
            fg=_THEME["text"],
            insertbackground=_THEME["text"],
            font=("Consolas", 9),
            wrap="word",
            relief="flat",
            padx=10,
            pady=8,
        )
        scroll = ttk.Scrollbar(out_frame, orient="vertical", command=self.verify_output.yview)
        self.verify_output.configure(yscrollcommand=scroll.set)
        self.verify_output.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def _make_pill(self, parent: "ttk.Frame", text: str, bg: str, fg: str) -> "tk.Label":
        lbl = tk.Label(
            parent,
            text=f"  {text}  ",
            bg=bg,
            fg=fg,
            font=("Segoe UI", 9, "bold"),
            padx=6,
            pady=3,
        )
        lbl.pack(side="left", padx=(0, 8))
        return lbl

    def _make_checks_tree(self, parent: "ttk.Frame", transition_mode: bool = False) -> "ttk.Treeview":
        frame = ttk.Frame(parent, style="Card.TFrame")
        frame.pack(fill="both", expand=True)

        if transition_mode:
            cols = ("test_id", "mitre", "verdict", "transition", "rationale")
            headings = {
                "test_id": ("Check ID", 170),
                "mitre": ("MITRE", 110),
                "verdict": ("Verdict", 110),
                "transition": ("Delta", 175),
                "rationale": ("Finding / Evidence Gate", 360),
            }
        else:
            cols = ("test_id", "mitre", "verdict", "codes", "rationale")
            headings = {
                "test_id": ("Check ID", 175),
                "mitre": ("MITRE", 110),
                "verdict": ("Verdict", 115),
                "codes": ("Reason Codes", 190),
                "rationale": ("Summary / Rationale", 340),
            }

        tree = ttk.Treeview(frame, columns=cols, show="headings", style="Verimetry.Treeview", height=10)
        for col, (label, width) in headings.items():
            tree.heading(col, text=label, anchor="w")
            tree.column(col, width=width, anchor="w", stretch=(col == "rationale"))

        tree.tag_configure("PASS", foreground=_THEME["pass"], background=_THEME["pass_bg"])
        tree.tag_configure("FAIL", foreground=_THEME["fail"], background=_THEME["fail_bg"])
        tree.tag_configure("INCONCLUSIVE", foreground=_THEME["inc"], background=_THEME["inc_bg"])

        yscroll = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=yscroll.set)
        tree.pack(side="left", fill="both", expand=True)
        yscroll.pack(side="right", fill="y")
        return tree

    def _set_busy(self, busy: bool, status: str) -> None:
        self._busy = busy
        self.status_var.set(status)
        state = "disabled" if busy else "normal"
        self.step1_run_btn.configure(state=state)
        if not (self.priv["is_windows"] and not self.priv["is_admin"]):
            self.step2_run_btn.configure(state=state)
        self.verify_btn.configure(state=state)
        self.tamper_btn.configure(state=state)
        self.cleanup_btn.configure(state=state)
        if busy:
            self.progress.start(12)
        else:
            self.progress.stop()

    def _choose_workdir(self) -> None:
        chosen = filedialog.askdirectory(initialdir=str(self.workdir), title="Select Verimetry Working Folder")
        if not chosen:
            return
        self.workdir = Path(chosen).resolve()
        self.workdir_var.set(f"Workspace: {self.workdir}")
        self._step1_result = None
        self._step2_result = None
        self._refresh_existing_state()
        self.status_var.set(f"Switched workspace to {self.workdir}")

    def _refresh_existing_state(self) -> None:
        # Load any existing Step 1 evidence (especially after UAC relaunch!)
        b_checks = load_directory_verdicts(self.workdir / "evidence")
        if b_checks:
            self._populate_step1_ui(
                {
                    "checks": b_checks,
                    "counts": count_verdicts(b_checks),
                    "key_path": str(self.workdir / "verimetry-key.pem"),
                    "report_path": str(self.workdir / "evidence" / "report.html"),
                }
            )
            # If launched elevated and Step 1 baseline already exists, guide user straight to Step 2
            if self.priv["is_admin"]:
                self.notebook.select(self.tab_step2)
                self.status_var.set(
                    "Elevated Admin mode active with Step 1 baseline detected — ready to run Step 2!"
                )
        else:
            self._clear_tree(self.step1_tree)
            self.step1_pass_lbl.configure(text="  PASS: 0  ")
            self.step1_fail_lbl.configure(text="  FAIL: 0  ")
            self.step1_inc_lbl.configure(text="  INCONCLUSIVE: 0  ")
            self.step1_key_lbl.configure(text="")
            self.step1_report_btn.configure(state="disabled")
            self.step2_baseline_var.set("Step 1 baseline: not yet run (.\\evidence not found)")

        # Load any existing Step 2 / comparison evidence
        comp_rec = self.workdir / "evidence-comparison" / "comparison-receipt.json"
        comp_html = self.workdir / "evidence-comparison" / "comparison-report.html"
        e_checks = load_directory_verdicts(self.workdir / "evidence-elevated")
        if comp_rec.exists():
            try:
                pack = load_json_strict(comp_rec)
                rec, _sha, _kid, _pt = extract_unverified_receipt(pack)
                obs = rec.get("observation") or {}
                comp_pub = (
                    self.workdir / "evidence-comparison" / "signer.pub.pem"
                    if (self.workdir / "evidence-comparison" / "signer.pub.pem").exists()
                    else self.workdir / "verimetry-key.pub.pem"
                )
                self._populate_step2_ui(
                    {
                        "after_checks": e_checks,
                        "after_counts": count_verdicts(e_checks),
                        "after_report_path": str(self.workdir / "evidence-elevated" / "report.html"),
                        "has_before": bool(b_checks),
                        "used_key_fallback": False,
                        "fallback_note": "",
                        "comparison_receipt_path": str(comp_rec),
                        "comparison_report_path": str(comp_html) if comp_html.exists() else None,
                        "comparison_pub_path": str(comp_pub),
                        "comparison_verdict": str(rec.get("verdict") or ""),
                        "comparison_rationale": str(rec.get("rationale") or ""),
                        "comparison_metrics": obs.get("metrics") or {},
                        "comparison_transitions": obs.get("transitions") or [],
                    }
                )
            except Exception:
                pass
        else:
            self._clear_tree(self.step2_tree)
            self.step2_report_btn.configure(state="disabled")
            self.step2_fallback_lbl.pack_forget()
            self.step2_metrics_var.set(
                "Delta Summary: Run Step 2 after Step 1 to compute Verified Coverage, INCONCLUSIVE Burn-Down, and Drift."
            )

        self._auto_fill_step3_paths()

    def _auto_fill_step3_paths(self) -> None:
        candidates = [
            (
                self.workdir / "evidence-comparison" / "comparison-receipt.json",
                self.workdir / "evidence-comparison" / "signer.pub.pem",
            ),
            (
                self.workdir / "evidence-comparison" / "comparison-receipt.json",
                self.workdir / "verimetry-key.pub.pem",
            ),
        ]
        for folder in (self.workdir / "evidence-elevated", self.workdir / "evidence"):
            if folder.exists():
                recs = sorted(folder.glob("receipt-*.json"))
                if recs:
                    candidates.append((recs[0], self.workdir / "verimetry-key.pub.pem"))
                    candidates.append((recs[0], folder / "signer.pub.pem"))

        for rpath, ppath in candidates:
            if rpath.exists() and ppath.exists():
                self.verify_receipt_var.set(str(rpath))
                self.verify_pub_var.set(str(ppath))
                return

    @staticmethod
    def _clear_tree(tree: "ttk.Treeview") -> None:
        for row in tree.get_children():
            tree.delete(row)

    def _populate_step1_ui(self, result: dict[str, Any]) -> None:
        self._step1_result = result
        counts = result["counts"]
        self.step1_pass_lbl.configure(text=f"  PASS: {counts['PASS']}  ")
        self.step1_fail_lbl.configure(text=f"  FAIL: {counts['FAIL']}  ")
        self.step1_inc_lbl.configure(text=f"  INCONCLUSIVE: {counts['INCONCLUSIVE']}  ")
        self.step1_key_lbl.configure(text=f"Key: {Path(result['key_path']).name}  |  Output: .\\evidence")

        self._clear_tree(self.step1_tree)
        for chk in result["checks"]:
            verdict = chk["verdict"]
            codes = ", ".join(chk.get("reason_codes") or []) or "—"
            self.step1_tree.insert(
                "",
                "end",
                values=(chk["test_id"], chk["mitre_attack"], verdict, codes, chk["rationale"]),
                tags=(verdict,),
            )

        if Path(result["report_path"]).exists():
            self.step1_report_btn.configure(state="normal")

        self.step2_baseline_var.set(
            f"Step 1 baseline ready (.\\evidence): {counts['PASS']} PASS · "
            f"{counts['FAIL']} FAIL · {counts['INCONCLUSIVE']} INCONCLUSIVE"
        )

    def _populate_step2_ui(self, result: dict[str, Any]) -> None:
        self._step2_result = result
        if result.get("used_key_fallback") and result.get("fallback_note"):
            self.step2_fallback_var.set(f"ℹ  {result['fallback_note']}")
            self.step2_fallback_lbl.pack(fill="x", pady=(0, 8), before=self.step2_tree.master)
        else:
            self.step2_fallback_lbl.pack_forget()

        self._clear_tree(self.step2_tree)
        transitions = result.get("comparison_transitions") or []
        metrics = result.get("comparison_metrics")

        if metrics and transitions:
            summary_lines = [
                f"Comparison Verdict        : {result.get('comparison_verdict')} — {result.get('comparison_rationale')}",
                f"Verified Telemetry Cover  : {metrics.get('before_coverage_pct_str')} -> {metrics.get('after_coverage_pct_str')} "
                f"({metrics.get('before_pass_count')}/{metrics.get('total_checks')} -> {metrics.get('after_pass_count')}/{metrics.get('total_checks')} PASS)",
                f"INCONCLUSIVE Burn-Down    : {metrics.get('inconclusive_burndown_pct_str')} "
                f"({metrics.get('before_inconclusive_count')} -> {metrics.get('after_inconclusive_count')} INCONCLUSIVE; "
                f"{metrics.get('visibility_unlocked_count')} unlocked)",
                f"Hardening Verification    : {metrics.get('hardening_verification_pct_str')} "
                f"({metrics.get('hardened_to_pass_count')}/{metrics.get('hardening_candidates_count')} non-PASS -> PASS)  |  "
                f"Drift/Regressions: {metrics.get('regression_count')}",
            ]
            self.step2_metrics_var.set("\n".join(summary_lines))
            for t in transitions:
                after_v = str(t.get("after_verdict") or "INCONCLUSIVE")
                delta = f"{t.get('before_verdict')} -> {after_v}"
                self.step2_tree.insert(
                    "",
                    "end",
                    values=(
                        t.get("test_id"),
                        t.get("mitre_attack"),
                        after_v,
                        delta,
                        t.get("after_rationale") or t.get("customer_impact") or "",
                    ),
                    tags=(after_v,),
                )
        else:
            c = result["after_counts"]
            self.step2_metrics_var.set(
                f"Elevated Assess Complete: {c['PASS']} PASS · {c['FAIL']} FAIL · {c['INCONCLUSIVE']} INCONCLUSIVE\n"
                "(Step 1 baseline .\\evidence was not present, so delta comparison was skipped. "
                "Run Step 1 first to generate a Before -> After comparison receipt.)"
            )
            for chk in result["after_checks"]:
                verdict = chk["verdict"]
                self.step2_tree.insert(
                    "",
                    "end",
                    values=(chk["test_id"], chk["mitre_attack"], verdict, "elevated-only", chk["rationale"]),
                    tags=(verdict,),
                )

        if result.get("comparison_report_path") and Path(result["comparison_report_path"]).exists():
            self.step2_report_btn.configure(state="normal")
        elif result.get("after_report_path") and Path(result["after_report_path"]).exists():
            self.step2_report_btn.configure(state="normal")

        if result.get("comparison_receipt_path") and result.get("comparison_pub_path"):
            self.verify_receipt_var.set(result["comparison_receipt_path"])
            self.verify_pub_var.set(result["comparison_pub_path"])

    def _start_step1(self) -> None:
        if self._busy:
            return
        window = max(1, min(15, int(self.window_var.get() or 4)))
        self._set_busy(True, "Running Step 1 baseline assessment in background...")

        def _worker() -> None:
            try:
                res = run_step1_baseline(self.workdir, window=window)
                self.root.after(0, lambda: self._on_step1_done(res))
            except Exception as exc:
                err = str(exc)
                self.root.after(0, lambda: self._on_worker_error("Step 1 failed", err))

        threading.Thread(target=_worker, daemon=True).start()

    def _on_step1_done(self, result: dict[str, Any]) -> None:
        self._populate_step1_ui(result)
        self._auto_fill_step3_paths()
        c = result["counts"]
        self._set_busy(
            False,
            f"Step 1 complete ({result['mode']}): {c['PASS']} PASS, {c['FAIL']} FAIL, "
            f"{c['INCONCLUSIVE']} INCONCLUSIVE. Proceed to Step 2 for elevated delta.",
        )

    def _handle_relaunch_admin(self) -> None:
        ok, msg = relaunch_as_admin(self.workdir)
        self.status_var.set(msg)
        if ok:
            self.root.after(400, self.root.destroy)
        else:
            messagebox.showwarning("UAC Elevation Not Completed", msg)

    def _start_step2(self) -> None:
        if self._busy:
            return
        window = max(1, min(15, int(self.window_var.get() or 4)))
        self._set_busy(True, "Running Step 2 elevated assessment & cryptographic comparison...")

        def _worker() -> None:
            try:
                res = run_step2_elevated_and_compare(self.workdir, window=window)
                self.root.after(0, lambda: self._on_step2_done(res))
            except Exception as exc:
                err = str(exc)
                self.root.after(0, lambda: self._on_worker_error("Step 2 failed", err))

        threading.Thread(target=_worker, daemon=True).start()

    def _on_step2_done(self, result: dict[str, Any]) -> None:
        self._populate_step2_ui(result)
        if result.get("comparison_receipt_path"):
            self._set_busy(
                False,
                "Step 2 complete: signed comparison-receipt.json & dual-persona HTML report generated.",
            )
        else:
            self._set_busy(
                False,
                "Step 2 elevated assess complete (run Step 1 to enable Before -> After delta compare).",
            )

    def _on_worker_error(self, title: str, err_msg: str) -> None:
        self._set_busy(False, f"{title}: {err_msg}")
        messagebox.showerror(title, err_msg)

    def _open_step2_report(self) -> None:
        if self._step2_result and self._step2_result.get("comparison_report_path"):
            target = Path(self._step2_result["comparison_report_path"])
        elif (self.workdir / "evidence-comparison" / "comparison-report.html").exists():
            target = self.workdir / "evidence-comparison" / "comparison-report.html"
        else:
            target = self.workdir / "evidence-elevated" / "report.html"
        self._open_file_in_browser(target)

    def _open_file_in_browser(self, path: Path) -> None:
        if not path.exists():
            messagebox.showwarning("Report Not Found", f"File does not exist yet:\n{path}")
            return
        webbrowser.open(path.resolve().as_uri())
        self.status_var.set(f"Opened {path.name} in default browser.")

    def _browse_receipt(self) -> None:
        chosen = filedialog.askopenfilename(
            initialdir=str(self.workdir),
            title="Select Verimetry DSSE Receipt JSON",
            filetypes=[("JSON Receipts", "*.json"), ("All Files", "*.*")],
        )
        if chosen:
            self.verify_receipt_var.set(chosen)

    def _browse_public_key(self) -> None:
        chosen = filedialog.askopenfilename(
            initialdir=str(self.workdir),
            title="Select Trusted Ed25519 Public Key (.pub.pem)",
            filetypes=[("PEM Public Keys", "*.pem"), ("All Files", "*.*")],
        )
        if chosen:
            self.verify_pub_var.set(chosen)

    def _set_verify_display(self, banner_text: str, ok: bool, body_text: str) -> None:
        self.verify_banner.configure(
            text=banner_text,
            bg=_THEME["pass_bg"] if ok else _THEME["fail_bg"],
            fg=_THEME["pass"] if ok else _THEME["fail"],
        )
        self.verify_output.delete("1.0", "end")
        self.verify_output.insert("1.0", body_text)

    def _handle_verify_offline(self) -> None:
        rpath = self.verify_receipt_var.get().strip()
        ppath = self.verify_pub_var.get().strip()
        if not rpath or not ppath:
            messagebox.showwarning("Missing Files", "Select both a DSSE receipt (.json) and public key (.pub.pem).")
            return
        res = run_verify_receipt(rpath, ppath, expected_nonce=self.verify_nonce_var.get())
        if res["ok"]:
            body = json.dumps(res["receipt"], indent=2, ensure_ascii=False)
            self._set_verify_display(f"✓ VERIFIED: {res['message']}", True, body)
            self.status_var.set("Offline DSSE v1 verification succeeded.")
        else:
            self._set_verify_display(
                f"✕ REJECTED: {res['message']}",
                False,
                f"Receipt: {rpath}\nPublic key: {ppath}\nResult: REJECTED\nReason: {res['message']}\n",
            )
            self.status_var.set(f"Offline verification REJECTED: {res['message']}")

    def _handle_tamper_trap(self) -> None:
        rpath = self.verify_receipt_var.get().strip()
        ppath = self.verify_pub_var.get().strip()
        if not rpath or not ppath:
            messagebox.showwarning("Missing Files", "Select a valid DSSE receipt and public key first.")
            return
        try:
            res = run_tamper_trap(rpath, ppath, forged_path=self.workdir / "forged.json")
        except Exception as exc:
            messagebox.showerror("Tamper Trap Error", str(exc))
            return

        detail = (
            f"Tamper Trap Simulation Complete\n"
            f"───────────────────────────────\n"
            f"Source receipt  : {rpath}\n"
            f"Forged copy     : {res['forged_path']}\n"
            f"Mutation        : Flipped 1 bit at payload byte offset {res['flipped_byte_offset']} "
            f"(0x{res['original_byte']:02x} -> 0x{res['forged_byte']:02x})\n"
            f"Verifier status : {res['status']}\n"
            f"Verifier reason : {res['message']}\n\n"
            "Because DSSE v1 signs the exact UTF-8 JSON bytes over PAE with Ed25519 (and recomputes "
            "deterministic verdict rules offline), any 1-byte modification fails closed immediately."
        )
        if not res["verified"]:
            self._set_verify_display(
                f"✕ REJECTED (Tamper Trap Passed!): {res['message']}",
                False,
                detail,
            )
            self.status_var.set("Tamper Trap verified fail-closed: forged.json REJECTED.")
        else:
            self._set_verify_display("UNEXPECTED: Forged receipt verified!", False, detail)

    def _copy_issue_summary(self) -> None:
        summary = format_issue_summary(
            workdir=self.workdir,
            baseline_checks=self._step1_result["checks"] if self._step1_result else None,
            elevated_checks=self._step2_result["after_checks"] if self._step2_result else None,
        )
        self.root.clipboard_clear()
        self.root.clipboard_append(summary)
        self.root.update()
        self.status_var.set("Copied anonymized 5-line Issue #1 summary (0 hostnames, 0 private keys) to clipboard.")
        messagebox.showinfo(
            "Copied to Clipboard",
            f"Anonymized summary copied (0 hostnames, 0 private keys).\n\n{summary}\n\n"
            f"Paste directly into:\n{ISSUE_FEEDBACK_URL}",
        )

    def _confirm_cleanup(self) -> None:
        targets = list_cleanup_targets(self.workdir)
        if not targets:
            messagebox.showinfo("Already Clean", "No local Verimetry evidence folders, test keys, or forged.json found.")
            return
        names = "\n".join(f"  • {p.name}" for p in targets)
        confirmed = messagebox.askyesno(
            "Confirm Local Evidence Cleanup",
            f"Permanently delete these local Verimetry test files in:\n{self.workdir}\n\n{names}\n\n"
            "Windows OS settings were never modified and require no teardown.",
        )
        if not confirmed:
            return
        res = cleanup_local_evidence(self.workdir)
        self._step1_result = None
        self._step2_result = None
        self.verify_receipt_var.set("")
        self.verify_pub_var.set("")
        self.verify_output.delete("1.0", "end")
        self._refresh_existing_state()
        if res["errors"]:
            msg = f"Deleted {len(res['deleted'])} item(s), with errors:\n" + "\n".join(res["errors"])
            self.status_var.set("Cleanup finished with warnings.")
            messagebox.showwarning("Cleanup Completed With Warnings", msg)
        else:
            self.status_var.set(f"Cleaned up {len(res['deleted'])} local artifact(s).")


def launch_gui(workdir: str | Path | None = None) -> int:
    """Launch the native Verimetry Tkinter GUI; returns process exit code."""
    if not _TK_AVAILABLE or tk is None:
        print(
            "Verimetry GUI unavailable: Python's stdlib 'tkinter' module is not installed "
            f"({_TK_IMPORT_ERROR}).\n"
            "Install python3-tk (Linux) or use the CLI directly: "
            "'python -m verimetry assess' / 'python -m verimetry demo --suite internals'.",
            file=sys.stderr,
        )
        return 1
    try:
        root = tk.Tk()
    except Exception as exc:
        print(
            f"Verimetry GUI could not open a desktop display ({type(exc).__name__}: {exc}).\n"
            "Use the CLI directly on headless hosts: 'python -m verimetry assess' or 'python -m verimetry demo'.",
            file=sys.stderr,
        )
        return 1
    VerimetryGUI(root, workdir=workdir)
    root.mainloop()
    return 0


def main(argv: list[str] | None = None) -> None:
    """Entry point for the `verimetry-gui` console script."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="verimetry-gui",
        description="Launch Verimetry's zero-dependency native Tkinter GUI",
    )
    parser.add_argument(
        "--workdir",
        help="Working directory for evidence folders and signing keys (default: current directory)",
    )
    args = parser.parse_args(argv)
    raise SystemExit(launch_gui(workdir=args.workdir))


if __name__ == "__main__":
    main()

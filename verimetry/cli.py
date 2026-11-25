"""Explicit, opt-in CLI. No agent daemon, scheduling, persistence or network traffic."""
from __future__ import annotations
import argparse
import json
import platform
from pathlib import Path
from .core import (
    make_receipt,
    compute_host_fingerprint,
    TEST_SPECS,
    WINDOWS_INTERNALS_CHECK_IDS,
    T1685_ASSURANCE_CHECK_IDS,
)
from .receipts import extract_unverified_receipt, init_keys, load_json_strict, sign, verify
from .simulate import scenario_observation, internals_observation
from .report import build_report, build_inventory_report, build_comparison_report
from .oscal import export_draft
from .inventory import collect
from .compare import build_comparison_receipt


def save_json(path, value):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def generate(out, key, live=False, window=4, checks=None, suite="classic", persona="both", nonce=None):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    if key is None:
        key = out / "signer.pem"
    key = Path(key)
    if not key.exists():
        pub = init_keys(key)
        print(f"Created signer key: {key}; trusted public key: {pub}")
    pub = key.with_suffix(".pub.pem")
    if not pub.exists():
        raise SystemExit("Public key missing; refusing to continue")
    packs = []
    if live:
        from .windows import run_all_internals_checks, collect_host_fingerprint
        inventory = collect()
        save_json(out / "windows-inventory.json", inventory)
        build_inventory_report(inventory, out / "inventory-report.html", persona=persona)
        selected = [c.strip() for c in checks.split(",") if c.strip()] if isinstance(checks, str) and checks else checks
        host = platform.node()
        host_fp = collect_host_fingerprint()
        packages = []
        for slug, test_id, observation in run_all_internals_checks(window_seconds=window, selected=selected):
            packages.append((
                slug,
                make_receipt(
                    host,
                    observation,
                    "live-host",
                    test_id=test_id,
                    host_fingerprint_sha256=host_fp,
                    challenge_nonce=nonce,
                ),
            ))
    elif suite == "internals":
        outcomes = ("PASS", "FAIL", "INCONCLUSIVE", "FAIL", "PASS")
        synth_fp = compute_host_fingerprint("00000000-0000-0000-0000-000000000001", "SIM-INTERNALS-01")
        packages = [
            (
                TEST_SPECS[tid]["slug"],
                make_receipt(
                    f"Simulated Host ({TEST_SPECS[tid]['mitre_attack']})",
                    internals_observation(tid, out_state),
                    "synthetic",
                    test_id=tid,
                    host_fingerprint_sha256=synth_fp,
                    challenge_nonce=nonce,
                ),
            )
            for tid, out_state in zip(WINDOWS_INTERNALS_CHECK_IDS, outcomes)
        ]
    elif suite == "t1685":
        outcomes = ("PASS", "FAIL", "PASS", "INCONCLUSIVE", "PASS", "FAIL", "PASS")
        synth_fp = compute_host_fingerprint("00000000-0000-0000-0000-000000001685", "SIM-T1685-01")
        packages = [
            (
                TEST_SPECS[tid]["slug"],
                make_receipt(
                    f"Simulated Host ({TEST_SPECS[tid]['mitre_attack']})",
                    internals_observation(tid, out_state),
                    "synthetic",
                    test_id=tid,
                    host_fingerprint_sha256=synth_fp,
                    challenge_nonce=nonce,
                ),
            )
            for tid, out_state in zip(T1685_ASSURANCE_CHECK_IDS, outcomes)
        ]
    else:
        packages = [
            (
                name,
                make_receipt(
                    f"Environment {name}",
                    scenario_observation(name),
                    "synthetic",
                    challenge_nonce=nonce,
                ),
            )
            for name in "ABC"
        ]
    for name, receipt in packages:
        pack = sign(receipt, key)
        verified, note = verify(pack, pub, expected_nonce=nonce)
        if not verified:
            raise RuntimeError(f"Self-validation failed: {note}")
        save_json(out / f"receipt-{name}.json", pack)
        packs.append(pack)
        test_id = receipt["test"]["id"]
        mitre = receipt["test"].get("mitre_attack")
        prefix = f"[{test_id} | {mitre}] " if mitre else ""
        print(f"{prefix}{receipt['target']['host']}: {receipt['verdict']} — {receipt['rationale']}")
    build_report(packs, out / "report.html", persona=persona)
    save_json(out / "oscal-draft.json", export_draft(packs))
    print(f"\nSaved to {out.resolve()}\nOpen report.html locally; use 'verify' with a separately trusted public key.")


def run_compare(before, after, out, key=None, public=None, before_public=None, after_public=None, persona="both", nonce=None):
    out_dir = Path(out)
    out_dir.mkdir(parents=True, exist_ok=True)
    key_arg_provided = key is not None
    key_path = Path(key) if key is not None else (out_dir / "signer.pem")
    if not key_path.exists():
        pub_created = init_keys(key_path)
        print(f"Created comparison signer key: {key_path}; trusted public key: {pub_created}")
    signer_pub = key_path.with_suffix(".pub.pem")
    if not signer_pub.exists():
        raise SystemExit("Comparison signer public key missing; refusing to continue")

    allow_fallback = False
    if public is not None and key_arg_provided:
        try:
            allow_fallback = Path(public).resolve() == signer_pub.resolve()
        except OSError:
            allow_fallback = False

    try:
        receipt = build_comparison_receipt(
            before,
            after,
            trusted_public=public,
            before_public=before_public,
            after_public=after_public,
            allow_dir_public_fallback=allow_fallback,
            challenge_nonce=nonce,
        )
    except ValueError as exc:
        print(f"REJECTED: {exc}")
        raise SystemExit(2) from exc

    signed_pack = sign(receipt, key_path)
    verify_pub = signer_pub
    ok, note = verify(signed_pack, verify_pub, expected_nonce=nonce)
    if not ok:
        raise RuntimeError(f"Comparison receipt self-validation failed: {note}")

    rec_path = out_dir / "comparison-receipt.json"
    html_path = out_dir / "comparison-report.html"
    save_json(rec_path, signed_pack)
    build_comparison_report(signed_pack, html_path, persona=persona)

    obs = receipt["observation"]
    m = obs["metrics"]
    print(f"[WIN-ASSURANCE-COMPARE] {receipt['target']['host']}: {receipt['verdict']} — {receipt['rationale']}")
    print(
        f"  1. Verified Telemetry Coverage : {m['before_coverage_pct_str']} -> {m['after_coverage_pct_str']} "
        f"({m['before_pass_count']}/{m['total_checks']} -> {m['after_pass_count']}/{m['total_checks']} PASS)"
    )
    print(
        f"  2. INCONCLUSIVE Burn-Down Rate : {m['inconclusive_burndown_pct_str']} "
        f"({m['before_inconclusive_count']} -> {m['after_inconclusive_count']} INCONCLUSIVE; "
        f"{m['visibility_unlocked_count']} unlocked)"
    )
    print(
        f"  3. Hardening Verification Rate : {m['hardening_verification_pct_str']} "
        f"({m['hardened_to_pass_count']}/{m['hardening_candidates_count']} non-PASS -> PASS)"
    )
    print(
        f"  4. Telemetry Drift/Regressions : {m['regression_count']} "
        f"({'DRIFT DETECTED: ' + ', '.join(m['regressions']) if m['drift_detected'] else '0 regressions'})"
    )
    print(f"  5. Elapsed Time (delta t)      : {m['elapsed_human']} ({m['elapsed_seconds']}s)")
    for t in obs["transitions"]:
        print(f"     - {t['test_id']}: {t['before_verdict']} -> {t['after_verdict']} [{t['transition_class']}]")
    print(f"\nSaved signed DSSE comparison receipt to {rec_path.resolve()}")
    print(f"Saved static comparison report to       {html_path.resolve()}")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="verimetry", description="Local-first, evidence-gated Windows Internals telemetry assurance (DSSE v1)")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("demo", "assess"):
        p = sub.add_parser(
            name,
            help="Synthetic scenarios (classic A/B/C, 5-check internals, or 7-check T1685 preview)"
            if name == "demo"
            else "Run all 5 read-only/canary Windows Internals checks + inventory",
        )
        p.add_argument("--out", default="./verimetry-output")
        p.add_argument("--key", help="Existing Ed25519 PEM signer key; otherwise generated in --out")
        p.add_argument("--nonce", help="Optional verifier-supplied challenge nonce for replay/freshness binding")
        p.add_argument(
            "--persona",
            choices=("customer", "mssp", "both"),
            default="both",
            help="Default active report view: 'customer' (plain-English), 'mssp' (engineering & remediation), or 'both'",
        )
        if name == "assess":
            p.add_argument("--window", type=int, default=4, help="Seconds to observe after canaries (1..15)")
            p.add_argument(
                "--checks",
                help="Optional comma-separated subset of check slugs/IDs (default: all 5 checks)",
            )
        else:
            p.add_argument("--suite", choices=("classic", "internals", "t1685"), default="classic", help="Synthetic demo suite (classic, internals, or t1685)")
    c = sub.add_parser("compare", help="Cryptographically verify two runs and compute Bucket 2 MSSP assurance delta metrics")
    c.add_argument("--before", required=True, help="Baseline evidence directory containing receipt-*.json")
    c.add_argument("--after", required=True, help="Follow-up evidence directory containing receipt-*.json")
    c.add_argument("--out", default="./verimetry-comparison", help="Output directory for comparison-receipt.json and comparison-report.html")
    c.add_argument("--key", help="Ed25519 private key PEM to sign comparison-receipt.json (generated if absent)")
    c.add_argument("--public", help="Trusted Ed25519 public key PEM for verifying input receipts")
    c.add_argument("--before-public", help="Optional public key override specifically for --before receipts")
    c.add_argument("--after-public", help="Optional public key override specifically for --after receipts")
    c.add_argument("--nonce", help="Optional verifier-supplied challenge nonce for comparison receipt freshness")
    c.add_argument(
        "--persona",
        choices=("customer", "mssp", "both"),
        default="both",
        help="Default active report view: 'customer' (plain-English), 'mssp' (engineering & remediation), or 'both'",
    )
    i = sub.add_parser("inspect", help="Read actual Windows security configuration without starting any processes")
    i.add_argument("--out", default="./verimetry-inventory.json")
    i.add_argument(
        "--persona",
        choices=("customer", "mssp", "both"),
        default="both",
        help="Default active report view: 'customer', 'mssp', or 'both'",
    )
    k = sub.add_parser("keygen", help="Generate one Ed25519 private/public key pair")
    k.add_argument("--private", required=True)
    g = sub.add_parser("gui", help="Launch zero-dependency native Tkinter GUI for the guided 3-step live test")
    g.add_argument("--workdir", help="Working directory for evidence folders and signing keys (default: current directory)")
    v = sub.add_parser("verify", help="Verify DSSE receipt against independently trusted public key")
    v.add_argument("--receipt", required=True)
    v.add_argument("--public", required=True)
    v.add_argument("--nonce", help="Optional expected challenge_nonce value for freshness verification")
    v.add_argument("--show", action="store_true", help="Pretty-print decoded DSSE receipt JSON after verification succeeds")
    args = parser.parse_args(argv)
    if args.command in ("demo", "assess"):
        generate(
            args.out,
            args.key,
            live=args.command == "assess",
            window=getattr(args, "window", 4),
            checks=getattr(args, "checks", None),
            suite=getattr(args, "suite", "classic"),
            persona=getattr(args, "persona", "both"),
            nonce=getattr(args, "nonce", None),
        )
    elif args.command == "compare":
        run_compare(
            args.before,
            args.after,
            args.out,
            key=args.key,
            public=args.public,
            before_public=args.before_public,
            after_public=args.after_public,
            persona=getattr(args, "persona", "both"),
            nonce=getattr(args, "nonce", None),
        )
    elif args.command == "inspect":
        data = collect()
        save_json(args.out, data)
        friendly = Path(args.out).with_name("inventory-report.html")
        build_inventory_report(data, friendly, persona=getattr(args, "persona", "both"))
        print(f"Real Windows inventory saved to {Path(args.out).resolve()} — status: {data['status']}")
        print(f"Plain-English report: {friendly.resolve()}")
    elif args.command == "keygen":
        print(f"Public key: {init_keys(Path(args.private))}")
    elif args.command == "gui":
        from .gui import launch_gui
        raise SystemExit(launch_gui(workdir=args.workdir))
    else:
        try:
            package = load_json_strict(args.receipt)
        except Exception as exc:
            print(f"REJECTED: Invalid JSON ({exc})")
            raise SystemExit(2) from exc
        ok, why = verify(package, args.public, expected_nonce=args.nonce)
        print(("VERIFIED: " if ok else "REJECTED: ") + why)
        if not ok:
            raise SystemExit(2)
        if args.show:
            rec, _sha, _kid, _pt = extract_unverified_receipt(package)
            print(json.dumps(rec, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

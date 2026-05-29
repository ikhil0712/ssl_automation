#!/usr/bin/env python3
"""
ssl_validator.py — Main entry point for the SSL Automation tool.

Orchestrates certificate checks, TLS checks, cipher checks,
and report generation across all configured targets.
"""

import sys
import argparse
import logging
import yaml
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from certificate_checks import CertificateChecker
from tls_checks import TLSChecker
from cipher_checks import CipherChecker
from report_generator import ReportGenerator


# ── Logging setup ────────────────────────────────────────────────────────────

LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)

log_file = LOG_DIR / f"ssl_validator_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file),
    ],
)
logger = logging.getLogger("ssl_validator")


# ── Config helpers ────────────────────────────────────────────────────────────

CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"


def load_yaml(path: Path) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


def load_configs(targets_path: Path | None, policy_path: Path | None) -> tuple[dict, dict]:
    t_path = targets_path or CONFIG_DIR / "targets.yaml"
    p_path = policy_path or CONFIG_DIR / "policy.yaml"
    logger.info("Loading targets from %s", t_path)
    logger.info("Loading policy from  %s", p_path)
    return load_yaml(t_path), load_yaml(p_path)


# ── Core validation ───────────────────────────────────────────────────────────

def validate_target(target: dict, policy: dict, defaults: dict) -> dict:
    """Run all checks for a single target and return a consolidated result dict."""
    host    = target["host"]
    port    = target.get("port", defaults.get("port", 443))
    timeout = target.get("timeout", defaults.get("timeout", 10))
    name    = target.get("name", host)

    logger.info("Validating [%s] %s:%d", name, host, port)

    result = {
        "name":      name,
        "host":      host,
        "port":      port,
        "tags":      target.get("tags", []),
        "notify":    target.get("notify", []),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "status":    "pass",          # upgraded to "warn" / "fail" below
        "checks":    {},
    }

    # ── Certificate checks ────────────────────────────────────────────────────
    cert_checker = CertificateChecker(host, port, timeout, policy)
    cert_result  = cert_checker.run()
    result["checks"]["certificate"] = cert_result

    # ── TLS version checks ────────────────────────────────────────────────────
    tls_checker  = TLSChecker(host, port, timeout, policy)
    tls_result   = tls_checker.run()
    result["checks"]["tls"] = tls_result

    # ── Cipher suite checks ───────────────────────────────────────────────────
    cipher_checker = CipherChecker(host, port, timeout, policy)
    cipher_result  = cipher_checker.run()
    result["checks"]["ciphers"] = cipher_result

    # ── Roll up status ────────────────────────────────────────────────────────
    statuses = [
        cert_result.get("status", "pass"),
        tls_result.get("status",  "pass"),
        cipher_result.get("status", "pass"),
    ]
    if "fail" in statuses:
        result["status"] = "fail"
    elif "warn" in statuses:
        result["status"] = "warn"

    logger.info(
        "Result [%s] %s:%d → %s",
        name, host, port, result["status"].upper(),
    )
    return result


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SSL/TLS automation validator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ssl_validator.py
  python ssl_validator.py --targets config/targets.yaml --policy config/policy.yaml
  python ssl_validator.py --tag production --format html
  python ssl_validator.py --host example.com --port 443
        """,
    )
    parser.add_argument("--targets",  type=Path, help="Path to targets.yaml")
    parser.add_argument("--policy",   type=Path, help="Path to policy.yaml")
    parser.add_argument("--tag",      help="Filter targets by tag")
    parser.add_argument("--host",     help="Validate a single ad-hoc host")
    parser.add_argument("--port",     type=int, default=443, help="Port for ad-hoc host")
    parser.add_argument(
        "--format",
        choices=["json", "html", "text"],
        default="html",
        help="Report output format (default: html)",
    )
    parser.add_argument(
        "--output", type=Path,
        help="Path for the generated report (default: reports/report_<timestamp>.<ext>)",
    )
    parser.add_argument(
        "--workers", type=int, default=5,
        help="Number of parallel workers (default: 5)",
    )
    parser.add_argument(
        "--fail-fast", action="store_true",
        help="Exit with code 1 if any target fails",
    )
    return parser.parse_args()


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    args = parse_args()

    targets_cfg, policy = load_configs(args.targets, args.policy)
    defaults = targets_cfg.get("defaults", {})

    # Build list of targets to validate
    if args.host:
        targets = [{"name": args.host, "host": args.host, "port": args.port}]
    else:
        targets = targets_cfg.get("targets", [])
        if args.tag:
            targets = [t for t in targets if args.tag in t.get("tags", [])]
            logger.info("Filtered to %d target(s) with tag '%s'", len(targets), args.tag)

    if not targets:
        logger.error("No targets to validate. Check your config or --tag filter.")
        return 1

    logger.info("Starting validation of %d target(s) with %d worker(s)",
                len(targets), args.workers)

    results = []

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(validate_target, t, policy, defaults): t
            for t in targets
        }
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:
                target = futures[future]
                logger.error("Unhandled error for %s: %s", target.get("host"), exc, exc_info=True)
                results.append({
                    "name":      target.get("name", target.get("host")),
                    "host":      target.get("host"),
                    "port":      target.get("port", 443),
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "status":    "error",
                    "checks":    {},
                    "error":     str(exc),
                })

    # Sort results alphabetically by host for deterministic output
    results.sort(key=lambda r: r["host"])

    # Generate report
    report_gen   = ReportGenerator(results, policy)
    report_path  = args.output or _default_report_path(args.format)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_gen.write(report_path, fmt=args.format)
    logger.info("Report written to %s", report_path)

    # Summary
    total  = len(results)
    passed = sum(1 for r in results if r["status"] == "pass")
    warned = sum(1 for r in results if r["status"] == "warn")
    failed = sum(1 for r in results if r["status"] in ("fail", "error"))

    logger.info("Summary — Total: %d  Pass: %d  Warn: %d  Fail: %d",
                total, passed, warned, failed)

    if args.fail_fast and failed:
        return 1
    return 0


def _default_report_path(fmt: str) -> Path:
    ext   = {"json": "json", "html": "html", "text": "txt"}.get(fmt, "txt")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path(__file__).resolve().parent.parent / "reports" / f"report_{stamp}.{ext}"


if __name__ == "__main__":
    sys.exit(main())

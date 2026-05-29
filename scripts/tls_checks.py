#!/usr/bin/env python3
"""
tls_checks.py — Probe which TLS protocol versions a server accepts or rejects.

Strategy
--------
For each TLS version defined in policy (allowed + forbidden), we attempt a
handshake using an ssl.SSLContext restricted to that single version.  The
outcome (success / ssl error / connection error) tells us whether the server
supports that version.

Python's ssl module exposes TLS versions through ssl.TLSVersion (3.7+).
Older constants (PROTOCOL_TLSv1, etc.) are deprecated and may be absent on
hardened builds, so we use the TLSVersion enum where possible and fall back
gracefully.

Checks performed:
  • Forbidden versions must NOT be accepted by the server.
  • Allowed versions SHOULD be accepted (warn if none of the allowed set work).
  • Preferred version is flagged if unavailable (informational).
  • Negotiated version is recorded for the "best" successful handshake.
"""

import ssl
import socket
import logging
from typing import Optional

logger = logging.getLogger("tls_checks")


# Map human-readable version strings → ssl.TLSVersion enum values (best-effort)
_VERSION_MAP: dict[str, Optional[ssl.TLSVersion]] = {}

def _build_version_map() -> None:
    mapping = {
        "TLSv1.0": "TLSv1",
        "TLSv1.1": "TLSv1_1",
        "TLSv1.2": "TLSv1_2",
        "TLSv1.3": "TLSv1_3",
    }
    for label, attr in mapping.items():
        _VERSION_MAP[label] = getattr(ssl.TLSVersion, attr, None)
    # Legacy names we can't probe via TLSVersion (OpenSSL usually blocks them)
    for legacy in ("SSLv2", "SSLv3"):
        _VERSION_MAP[legacy] = None   # sentinel: treat as "probably blocked"

_build_version_map()


class TLSChecker:
    def __init__(self, host: str, port: int, timeout: int, policy: dict):
        self.host    = host
        self.port    = port
        self.timeout = timeout
        self.tls_pol = policy.get("tls", {})
        self.reporting = policy.get("reporting", {})

    # ── Public API ─────────────────────────────────────────────────────────────

    def run(self) -> dict:
        result: dict = {
            "status":    "pass",
            "findings":  [],
            "details":   {
                "negotiated_version": None,
                "supported_versions": [],
                "rejected_versions":  [],
            },
        }

        allowed_versions   = self.tls_pol.get("allowed_versions", ["TLSv1.2", "TLSv1.3"])
        forbidden_versions = self.tls_pol.get("forbidden_versions",
                                              ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"])
        preferred_version  = self.tls_pol.get("preferred_version", "TLSv1.3")

        all_versions = list(dict.fromkeys(forbidden_versions + allowed_versions))

        # Probe each version
        probe_results: dict[str, str] = {}   # version → "supported" | "rejected" | "unknown"
        for version in all_versions:
            probe_results[version] = self._probe_version(version)

        # Categorise
        for version, probe in probe_results.items():
            if probe == "supported":
                result["details"]["supported_versions"].append(version)
            elif probe == "rejected":
                result["details"]["rejected_versions"].append(version)

        # ── Check forbidden versions ──────────────────────────────────────────
        for version in forbidden_versions:
            probe = probe_results.get(version, "unknown")
            if probe == "supported":
                if self.reporting.get("fail_on_forbidden_tls_version", True):
                    self._add_finding(result, "fail", "TLS_FORBIDDEN_VERSION",
                                      f"Forbidden TLS version accepted by server: {version}")
                else:
                    self._add_finding(result, "warn", "TLS_FORBIDDEN_VERSION",
                                      f"Forbidden TLS version accepted by server: {version}")
            elif probe == "unknown":
                # Legacy SSL (SSLv2/3) — Python can't probe them; note it
                logger.debug("Cannot probe %s on %s (not available in this Python build)",
                             version, self.host)

        # ── Check allowed versions ────────────────────────────────────────────
        any_allowed_working = any(
            probe_results.get(v) == "supported" for v in allowed_versions
        )
        if not any_allowed_working:
            self._add_finding(result, "fail", "TLS_NO_ALLOWED_VERSION",
                              f"None of the allowed TLS versions are supported: {allowed_versions}")

        # ── Check preferred version ────────────────────────────────────────────
        if preferred_version:
            if probe_results.get(preferred_version) != "supported":
                self._add_finding(result, "warn", "TLS_PREFERRED_UNAVAILABLE",
                                  f"Preferred TLS version {preferred_version} is not supported "
                                  f"(informational)")

        # ── Best negotiated version ────────────────────────────────────────────
        priority = ["TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0"]
        for v in priority:
            if probe_results.get(v) == "supported":
                result["details"]["negotiated_version"] = v
                break

        return result

    # ── Version probe ──────────────────────────────────────────────────────────

    def _probe_version(self, version_label: str) -> str:
        """
        Try to complete a TLS handshake restricted to a single version.

        Returns:
          "supported"  — handshake succeeded
          "rejected"   — handshake failed with an SSL/TLS error
          "unknown"    — could not probe (library limitation, network error)
        """
        tls_version = _VERSION_MAP.get(version_label)
        if tls_version is None:
            # SSLv2/SSLv3 or unmapped version — can't probe via Python ssl
            return "unknown"

        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.minimum_version = tls_version
            ctx.maximum_version = tls_version

            with socket.create_connection((self.host, self.port), self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host):
                    logger.debug("%s supports %s", self.host, version_label)
                    return "supported"

        except ssl.SSLError as e:
            logger.debug("%s rejected %s: %s", self.host, version_label, e)
            return "rejected"
        except AttributeError:
            # TLSVersion enum value not available in this Python/OpenSSL build
            logger.debug("TLSVersion.%s not available in this build", version_label)
            return "unknown"
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.warning("Network error probing %s on %s:%d — %s",
                           version_label, self.host, self.port, e)
            return "unknown"

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _add_finding(self, result: dict, severity: str, code: str, message: str) -> None:
        result["findings"].append({"severity": severity, "code": code, "message": message})
        logger.log(
            logging.WARNING if severity in ("warn", "fail") else logging.ERROR,
            "[%s] %s — %s", self.host, code, message,
        )
        if severity == "fail" and result["status"] != "error":
            result["status"] = "fail"
        elif severity == "warn" and result["status"] == "pass":
            result["status"] = "warn"

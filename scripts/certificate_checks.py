#!/usr/bin/env python3
"""
certificate_checks.py — Fetch and validate X.509 certificate details.

Checks performed:
  • Expiry date (warn / fail thresholds from policy)
  • Self-signed detection
  • Subject / SAN match for the target hostname
  • Key size (RSA / ECDSA minimum sizes from policy)
  • Signature algorithm (forbidden list from policy)
  • Basic chain validation (via ssl.create_default_context)
"""

import ssl
import socket
import logging
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
from cryptography.x509.oid import ExtensionOID

logger = logging.getLogger("certificate_checks")


class CertificateChecker:
    def __init__(self, host: str, port: int, timeout: int, policy: dict):
        self.host    = host
        self.port    = port
        self.timeout = timeout
        self.policy  = policy.get("certificate", {})
        self.reporting = policy.get("reporting", {})

    # ── Public API ─────────────────────────────────────────────────────────────

    def run(self) -> dict:
        result = {
            "status": "pass",
            "findings": [],
            "details": {},
        }

        cert_der, chain_valid, chain_error = self._fetch_certificate()

        if cert_der is None:
            result["status"] = "error"
            result["findings"].append({
                "severity": "error",
                "code":     "CERT_FETCH_FAILED",
                "message":  chain_error or "Failed to retrieve certificate",
            })
            return result

        # Parse with cryptography library for full introspection
        try:
            cert = x509.load_der_x509_certificate(cert_der)
        except Exception as exc:
            result["status"] = "error"
            result["findings"].append({
                "severity": "error",
                "code":     "CERT_PARSE_FAILED",
                "message":  f"Failed to parse certificate: {exc}",
            })
            return result

        # Populate details
        result["details"] = self._extract_details(cert)

        # Run individual checks
        self._check_expiry(cert, result)
        self._check_hostname(cert, result)
        self._check_self_signed(cert, chain_valid, chain_error, result)
        self._check_key_size(cert, result)
        self._check_signature_algorithm(cert, result)
        self._check_san(cert, result)

        return result

    # ── Certificate fetch ──────────────────────────────────────────────────────

    def _fetch_certificate(self) -> tuple:
        """
        Returns (cert_der_bytes, chain_valid_bool, error_str_or_None).
        Tries strict validation first; on failure retries without verification
        so we can still inspect a bad certificate.
        """
        # Attempt 1 — full chain validation
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.host, self.port), self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    der = ssock.getpeercert(binary_form=True)
                    return der, True, None
        except ssl.SSLCertVerificationError as e:
            chain_error = str(e)
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            return None, False, str(e)

        # Attempt 2 — no verification (to inspect the bad cert)
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((self.host, self.port), self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    der = ssock.getpeercert(binary_form=True)
                    return der, False, chain_error
        except Exception as e:
            return None, False, str(e)

    # ── Detail extraction ──────────────────────────────────────────────────────

    def _extract_details(self, cert: x509.Certificate) -> dict:
        details = {
            "subject":    cert.subject.rfc4514_string(),
            "issuer":     cert.issuer.rfc4514_string(),
            "serial":     str(cert.serial_number),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after":  cert.not_valid_after_utc.isoformat(),
            "sig_alg":    cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown",
            "key_type":   None,
            "key_size":   None,
            "san":        [],
        }

        pub = cert.public_key()
        if isinstance(pub, rsa.RSAPublicKey):
            details["key_type"] = "RSA"
            details["key_size"] = pub.key_size
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            details["key_type"] = "ECDSA"
            details["key_size"] = pub.key_size
        elif isinstance(pub, dsa.DSAPublicKey):
            details["key_type"] = "DSA"
            details["key_size"] = pub.key_size

        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            details["san"] = [str(n) for n in san_ext.value]
        except x509.ExtensionNotFound:
            pass

        return details

    # ── Individual checks ──────────────────────────────────────────────────────

    def _check_expiry(self, cert: x509.Certificate, result: dict) -> None:
        now  = datetime.now(timezone.utc)
        exp  = cert.not_valid_after_utc
        days = (exp - now).days

        warn_days  = self.policy.get("expiry_warning_days", 30)
        crit_days  = self.policy.get("expiry_critical_days", 14)

        if days < 0:
            self._add_finding(result, "fail", "CERT_EXPIRED",
                              f"Certificate expired {-days} day(s) ago on {exp.date()}")
        elif days <= crit_days:
            self._add_finding(result, "fail", "CERT_EXPIRY_CRITICAL",
                              f"Certificate expires in {days} day(s) on {exp.date()} "
                              f"(critical threshold: {crit_days} days)")
        elif days <= warn_days:
            self._add_finding(result, "warn", "CERT_EXPIRY_WARNING",
                              f"Certificate expires in {days} day(s) on {exp.date()} "
                              f"(warning threshold: {warn_days} days)")
        else:
            logger.debug("%s cert valid for %d more days", self.host, days)

    def _check_hostname(self, cert: x509.Certificate, result: dict) -> None:
        """
        Verify the certificate covers self.host.
        ssl.match_hostname() was removed in Python 3.12; we implement the
        check directly using the cryptography library.
        RFC 6125: if a SAN extension is present, only SANs are checked;
        the CN is ignored.  No SAN extension -> fall back to CN.
        """
        host = self.host.lower()

        def _wildcard_match(pattern: str, hostname: str) -> bool:
            pattern = pattern.lower()
            if pattern == hostname:
                return True
            if pattern.startswith("*."):
                suffix = pattern[2:]
                if hostname.endswith("." + suffix):
                    left = hostname[:-(len(suffix) + 1)]
                    if left and "." not in left:
                        return True
            return False

        # Check SANs first (RFC 6125 — CN ignored when SAN present)
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            for entry in san_ext.value:
                if isinstance(entry, x509.DNSName):
                    if _wildcard_match(entry.value, host):
                        return   # matched
            self._add_finding(result, "fail", "CERT_HOSTNAME_MISMATCH",
                              f"Certificate SANs do not cover hostname '{self.host}'")
            return
        except x509.ExtensionNotFound:
            pass   # no SAN extension — check CN

        # Fall back to Common Name
        try:
            cn = cert.subject.get_attributes_for_oid(
                x509.oid.NameOID.COMMON_NAME
            )[0].value
            if _wildcard_match(cn, host):
                return
        except IndexError:
            pass

        self._add_finding(result, "fail", "CERT_HOSTNAME_MISMATCH",
                          f"Certificate does not cover hostname '{self.host}'")
    def _check_self_signed(self, cert: x509.Certificate, chain_valid: bool,
                           chain_error: str | None, result: dict) -> None:
        is_self_signed = cert.issuer == cert.subject
        if is_self_signed and self.reporting.get("fail_on_self_signed", True):
            self._add_finding(result, "fail", "CERT_SELF_SIGNED",
                              "Certificate is self-signed")
        elif not chain_valid and chain_error:
            self._add_finding(result, "fail", "CERT_CHAIN_INVALID",
                              f"Certificate chain validation failed: {chain_error}")

    def _check_key_size(self, cert: x509.Certificate, result: dict) -> None:
        pub      = cert.public_key()
        key_type = type(pub).__name__

        if isinstance(pub, rsa.RSAPublicKey):
            min_size = self.policy.get("min_key_size_rsa", 2048)
            if pub.key_size < min_size:
                self._add_finding(result, "fail", "CERT_WEAK_KEY",
                                  f"RSA key size {pub.key_size} bits is below minimum {min_size} bits")
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            min_size = self.policy.get("min_key_size_ecdsa", 256)
            if pub.key_size < min_size:
                self._add_finding(result, "fail", "CERT_WEAK_KEY",
                                  f"ECDSA key size {pub.key_size} bits is below minimum {min_size} bits")

    def _check_signature_algorithm(self, cert: x509.Certificate, result: dict) -> None:
        sig_alg_oid  = cert.signature_algorithm_oid.dotted_string
        sig_alg_name = cert.signature_algorithm_oid._name if hasattr(
            cert.signature_algorithm_oid, "_name") else ""

        # Use the OID name from the cert's signature_hash_algorithm if available
        hash_alg = ""
        if cert.signature_hash_algorithm:
            hash_alg = cert.signature_hash_algorithm.name.lower()

        forbidden = [a.lower() for a in self.policy.get("forbidden_signature_algorithms", [])]
        for f in forbidden:
            if f in sig_alg_name.lower() or f in hash_alg:
                self._add_finding(result, "fail", "CERT_WEAK_SIGNATURE",
                                  f"Forbidden signature algorithm in use: {sig_alg_name or hash_alg}")
                return

    def _check_san(self, cert: x509.Certificate, result: dict) -> None:
        if not self.policy.get("require_san", True):
            return
        try:
            cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        except x509.ExtensionNotFound:
            self._add_finding(result, "warn", "CERT_NO_SAN",
                              "Certificate is missing Subject Alternative Names (SAN) extension")

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _add_finding(self, result: dict, severity: str, code: str, message: str) -> None:
        result["findings"].append({"severity": severity, "code": code, "message": message})
        logger.log(
            logging.WARNING if severity in ("warn", "fail") else logging.ERROR,
            "[%s] %s — %s", self.host, code, message,
        )
        # Promote status
        if severity == "fail" and result["status"] != "error":
            result["status"] = "fail"
        elif severity == "warn" and result["status"] == "pass":
            result["status"] = "warn"

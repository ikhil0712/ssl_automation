#!/usr/bin/env python3
"""
cipher_checks.py — Enumerate and validate cipher suites offered by a server.

Approach
--------
Two separate probe strategies are used:

  ALLOWED ciphers  — set the cipher on the context, verify OpenSSL kept at
                     least one cipher loaded (pre-handshake guard), then just
                     confirm the handshake succeeds.  We do NOT require the
                     negotiated name to match the string, because TLS 1.3
                     renames ciphers (ECDHE-RSA-AES256-GCM-SHA384 → TLS_AES_…).

  FORBIDDEN keywords — same pre-handshake guard, PLUS a post-handshake check
                       that the negotiated cipher name actually contains the
                       forbidden keyword.  This prevents false positives where
                       OpenSSL drops the keyword silently and falls back to
                       strong defaults.
"""

import ssl
import socket
import logging

logger = logging.getLogger("cipher_checks")


class CipherChecker:
    def __init__(self, host: str, port: int, timeout: int, policy: dict):
        self.host       = host
        self.port       = port
        self.timeout    = timeout
        self.cipher_pol = policy.get("ciphers", {})
        self.reporting  = policy.get("reporting", {})

    # ── Public API ─────────────────────────────────────────────────────────────

    def run(self) -> dict:
        result: dict = {
            "status":   "pass",
            "findings": [],
            "details":  {
                "negotiated_cipher":  None,
                "accepted_ciphers":   [],
                "rejected_ciphers":   [],
                "forbidden_accepted": [],
            },
        }

        # Record the cipher negotiated by a normal default connection
        result["details"]["negotiated_cipher"] = self._get_negotiated_cipher()

        allowed_ciphers    = self.cipher_pol.get("allowed", [])
        forbidden_keywords = self.cipher_pol.get("forbidden", [])

        # ── Probe allowed ciphers (handshake-success check only) ──────────────
        for cipher in list(dict.fromkeys(allowed_ciphers)):   # deduplicated
            if self._probe_allowed(cipher):
                result["details"]["accepted_ciphers"].append(cipher)
            else:
                result["details"]["rejected_ciphers"].append(cipher)

        # ── Check negotiated cipher against forbidden keywords ─────────────────
        negotiated = result["details"]["negotiated_cipher"]
        if negotiated:
            self._check_against_forbidden(negotiated, forbidden_keywords, result,
                                          source="negotiated cipher")

        # ── Probe forbidden keywords (strict negotiated-name check) ────────────
        for keyword in forbidden_keywords:
            if self._probe_forbidden(keyword):
                result["details"]["forbidden_accepted"].append(keyword)
                severity = "fail" if self.reporting.get("fail_on_forbidden_cipher", True) else "warn"
                self._add_finding(result, severity, "CIPHER_FORBIDDEN_ACCEPTED",
                                  f"Forbidden cipher keyword accepted by server: {keyword}")

        # ── At least one allowed cipher must work ──────────────────────────────
        if not result["details"]["accepted_ciphers"]:
            self._add_finding(result, "warn", "CIPHER_NO_ALLOWED_ACCEPTED",
                              "None of the policy-allowed ciphers were accepted by the server")

        return result

    # ── Negotiated cipher (default connection) ─────────────────────────────────

    def _get_negotiated_cipher(self) -> str | None:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            with socket.create_connection((self.host, self.port), self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cipher_tuple = ssock.cipher()
                    if cipher_tuple:
                        logger.debug("%s negotiated cipher: %s", self.host, cipher_tuple[0])
                        return cipher_tuple[0]
        except Exception as e:
            logger.warning("Could not determine negotiated cipher for %s: %s", self.host, e)
        return None

    # ── Allowed-cipher probe (handshake success = cipher supported) ────────────

    def _probe_allowed(self, cipher_string: str) -> bool:
        """
        Returns True if the server completes a TLS handshake when the client
        offers only *cipher_string*.

        We do NOT check the negotiated cipher name here because TLS 1.3
        silently upgrades/renames TLS 1.2 cipher strings, so a name-match
        would produce false negatives on modern servers.

        We DO verify that OpenSSL actually loaded the cipher (pre-handshake
        guard) to avoid false positives from the silent-fallback problem.
        """
        ctx = self._make_ctx(cipher_string)
        if ctx is None:
            return False   # cipher string rejected or silently dropped

        try:
            with socket.create_connection((self.host, self.port), self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host):
                    return True
        except ssl.SSLError:
            return False
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.debug("Network error probing allowed cipher '%s' on %s: %s",
                         cipher_string, self.host, e)
            return False

    # ── Forbidden-keyword probe (negotiated name must match keyword) ───────────

    def _probe_forbidden(self, keyword: str) -> bool:
        """
        Returns True ONLY if:
          1. OpenSSL actually loaded the keyword as a cipher (pre-handshake guard), AND
          2. The handshake succeeds, AND
          3. The negotiated cipher name contains the keyword.

        Step 3 is what prevents the false-positive: when OpenSSL drops a
        security keyword silently (NULL, eNULL, ADH…) and falls back to
        defaults, the negotiated name will be something like TLS_AES_256_GCM_SHA384,
        which does NOT contain "NULL" → correctly returns False.
        """
        ctx = self._make_ctx(keyword)
        if ctx is None:
            return False   # keyword not loaded — definitely not supported

        try:
            with socket.create_connection((self.host, self.port), self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    negotiated = ssock.cipher()
                    if not negotiated:
                        return False
                    negotiated_name = negotiated[0].upper()
                    matched = keyword.upper() in negotiated_name
                    if not matched:
                        logger.debug(
                            "Forbidden probe '%s' connected but negotiated '%s' "
                            "— OpenSSL fell back to defaults. Not a real match.",
                            keyword, negotiated[0],
                        )
                    return matched
        except ssl.SSLError:
            return False
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.debug("Network error probing forbidden keyword '%s' on %s: %s",
                         keyword, self.host, e)
            return False

    # ── Shared context builder with pre-handshake guard ────────────────────────

    def _make_ctx(self, cipher_string: str) -> ssl.SSLContext | None:
        """
        Build an SSLContext restricted to *cipher_string*.
        Returns None if:
          • set_ciphers() raises SSLError (completely invalid syntax), or
          • OpenSSL silently dropped the string (get_ciphers() shows no match).
        """
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            ctx.set_ciphers(cipher_string)
        except ssl.SSLError:
            logger.debug("Cipher string '%s' rejected by local OpenSSL", cipher_string)
            return None

        # Pre-handshake guard: verify OpenSSL actually kept this cipher.
        try:
            active = ctx.get_ciphers()   # list of dicts with 'name', 'description'
        except AttributeError:
            return ctx   # get_ciphers() not available — proceed without guard

        if not active:
            logger.debug("Cipher string '%s' silently dropped (empty cipher list)", cipher_string)
            return None

        keyword_upper = cipher_string.upper()
        loaded = any(
            keyword_upper in c.get("name", "").upper() or
            keyword_upper in c.get("description", "").upper()
            for c in active
        )
        if not loaded:
            logger.debug(
                "Cipher string '%s' silently dropped by OpenSSL "
                "(not present in active cipher list after set_ciphers)",
                cipher_string,
            )
            return None

        return ctx

    # ── Forbidden-keyword check against a known cipher name ───────────────────

    def _check_against_forbidden(self, cipher_name: str, forbidden_keywords: list[str],
                                 result: dict, source: str) -> None:
        cipher_upper = cipher_name.upper()
        for keyword in forbidden_keywords:
            if keyword.upper() in cipher_upper:
                severity = "fail" if self.reporting.get("fail_on_forbidden_cipher", True) else "warn"
                self._add_finding(result, severity, "CIPHER_FORBIDDEN_KEYWORD",
                                  f"Forbidden keyword '{keyword}' found in {source}: {cipher_name}")
                return

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _add_finding(self, result: dict, severity: str, code: str, message: str) -> None:
        for existing in result["findings"]:
            if existing["code"] == code and existing["message"] == message:
                return
        result["findings"].append({"severity": severity, "code": code, "message": message})
        logger.log(
            logging.WARNING if severity in ("warn", "fail") else logging.ERROR,
            "[%s] %s — %s", self.host, code, message,
        )
        if severity == "fail" and result["status"] != "error":
            result["status"] = "fail"
        elif severity == "warn" and result["status"] == "pass":
            result["status"] = "warn"
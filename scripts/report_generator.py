#!/usr/bin/env python3
"""
report_generator.py — Generate SSL validation reports in JSON, HTML, or plain text.

Usage
-----
    gen = ReportGenerator(results, policy)
    gen.write(Path("reports/report.html"), fmt="html")
"""

import json
import logging
from pathlib import Path
from datetime import datetime

logger = logging.getLogger("report_generator")

# Status → display metadata
_STATUS_META = {
    "pass":  {"label": "PASS",  "color": "#22c55e", "icon": "✔"},
    "warn":  {"label": "WARN",  "color": "#f59e0b", "icon": "⚠"},
    "fail":  {"label": "FAIL",  "color": "#ef4444", "icon": "✘"},
    "error": {"label": "ERROR", "color": "#8b5cf6", "icon": "!"},
}
_SEVERITY_COLOR = {
    "warn":  "#f59e0b",
    "fail":  "#ef4444",
    "error": "#8b5cf6",
}


class ReportGenerator:
    def __init__(self, results: list[dict], policy: dict):
        self.results   = results
        self.policy    = policy
        self.generated = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # ── Public API ─────────────────────────────────────────────────────────────

    def write(self, path: Path, fmt: str = "html") -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        if fmt == "json":
            content = self._render_json()
        elif fmt == "html":
            content = self._render_html()
        else:
            content = self._render_text()
        path.write_text(content, encoding="utf-8")
        logger.info("Report written → %s (%s)", path, fmt)

    # ── JSON ───────────────────────────────────────────────────────────────────

    def _render_json(self) -> str:
        summary = self._build_summary()
        payload = {
            "generated":  self.generated,
            "summary":    summary,
            "results":    self.results,
        }
        return json.dumps(payload, indent=2, default=str)

    # ── Plain text ─────────────────────────────────────────────────────────────

    def _render_text(self) -> str:
        lines: list[str] = []
        summary = self._build_summary()

        lines.append("=" * 72)
        lines.append("  SSL / TLS VALIDATION REPORT")
        lines.append(f"  Generated: {self.generated}")
        lines.append("=" * 72)
        lines.append(
            f"  Total: {summary['total']}  "
            f"Pass: {summary['pass']}  "
            f"Warn: {summary['warn']}  "
            f"Fail: {summary['fail']}  "
            f"Error: {summary['error']}"
        )
        lines.append("=" * 72)
        lines.append("")

        for r in self.results:
            meta   = _STATUS_META.get(r["status"], _STATUS_META["error"])
            header = f"  [{meta['label']}] {r['name']} ({r['host']}:{r['port']})"
            lines.append(header)
            lines.append("-" * 72)

            for section, check in r.get("checks", {}).items():
                s_meta = _STATUS_META.get(check.get("status", "pass"), _STATUS_META["pass"])
                lines.append(f"    {section.upper()} — {s_meta['label']}")
                for finding in check.get("findings", []):
                    sev   = finding["severity"].upper()
                    lines.append(f"      [{sev}] {finding['code']}: {finding['message']}")

            details = r.get("checks", {}).get("certificate", {}).get("details", {})
            if details:
                lines.append("    CERTIFICATE DETAILS")
                lines.append(f"      Subject:    {details.get('subject', 'n/a')}")
                lines.append(f"      Expires:    {details.get('not_after', 'n/a')}")
                lines.append(f"      Key:        {details.get('key_type', '?')} {details.get('key_size', '?')} bits")
                lines.append(f"      Sig Alg:    {details.get('sig_alg', 'n/a')}")

            tls_details = r.get("checks", {}).get("tls", {}).get("details", {})
            if tls_details:
                lines.append("    TLS DETAILS")
                lines.append(f"      Negotiated: {tls_details.get('negotiated_version', 'n/a')}")
                lines.append(f"      Supported:  {', '.join(tls_details.get('supported_versions', []))}")

            cipher_details = r.get("checks", {}).get("ciphers", {}).get("details", {})
            if cipher_details:
                lines.append("    CIPHER DETAILS")
                lines.append(f"      Negotiated: {cipher_details.get('negotiated_cipher', 'n/a')}")

            lines.append("")

        return "\n".join(lines)

    # ── HTML ───────────────────────────────────────────────────────────────────

    def _render_html(self) -> str:
        summary = self._build_summary()
        rows    = "\n".join(self._html_row(r) for r in self.results)
        overall_status = "fail" if summary["fail"] or summary["error"] else (
                         "warn" if summary["warn"] else "pass")
        overall_meta   = _STATUS_META[overall_status]

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SSL/TLS Validation Report — {self.generated}</title>
<style>
  :root {{
    --bg:       #0f172a;
    --surface:  #1e293b;
    --border:   #334155;
    --text:     #e2e8f0;
    --muted:    #94a3b8;
    --pass:     #22c55e;
    --warn:     #f59e0b;
    --fail:     #ef4444;
    --error:    #8b5cf6;
    --radius:   8px;
    --mono:     "JetBrains Mono", "Fira Code", monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg); color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    line-height: 1.6; padding: 32px 24px;
  }}
  h1 {{ font-size: 1.5rem; font-weight: 700; margin-bottom: 4px; }}
  .subtitle {{ color: var(--muted); font-size: 0.875rem; margin-bottom: 28px; }}
  .summary {{
    display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 32px;
  }}
  .stat {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 14px 22px; min-width: 100px; text-align: center;
  }}
  .stat-value {{ font-size: 2rem; font-weight: 800; line-height: 1; }}
  .stat-label {{ font-size: 0.75rem; color: var(--muted); text-transform: uppercase;
                 letter-spacing: .06em; margin-top: 4px; }}
  .card {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); margin-bottom: 16px; overflow: hidden;
  }}
  .card-header {{
    display: flex; align-items: center; gap: 12px;
    padding: 14px 18px; cursor: pointer; user-select: none;
  }}
  .card-header:hover {{ background: rgba(255,255,255,.04); }}
  .badge {{
    font-size: .7rem; font-weight: 700; letter-spacing: .06em;
    padding: 2px 8px; border-radius: 4px; text-transform: uppercase;
  }}
  .card-title {{ font-weight: 600; font-size: .95rem; flex: 1; }}
  .card-meta  {{ font-size: .8rem; color: var(--muted); font-family: var(--mono); }}
  .card-body  {{ padding: 0 18px 18px; }}
  .section    {{ margin-top: 14px; }}
  .section-title {{
    font-size: .7rem; font-weight: 700; text-transform: uppercase;
    letter-spacing: .08em; color: var(--muted); margin-bottom: 8px;
  }}
  .finding {{
    display: flex; gap: 10px; font-size: .84rem;
    padding: 7px 12px; border-radius: 5px; margin-bottom: 5px;
    background: rgba(0,0,0,.25);
  }}
  .finding-code  {{ font-family: var(--mono); font-weight: 600; white-space: nowrap; }}
  .finding-msg   {{ color: var(--muted); }}
  .detail-grid {{
    display: grid; grid-template-columns: max-content 1fr;
    gap: 4px 16px; font-size: .83rem; font-family: var(--mono);
  }}
  .detail-key   {{ color: var(--muted); }}
  .detail-value {{ color: var(--text); word-break: break-all; }}
  .chevron {{ color: var(--muted); transition: transform .2s; }}
  details[open] .chevron {{ transform: rotate(90deg); }}
  details summary {{ list-style: none; }}
  details summary::-webkit-details-marker {{ display: none; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .83rem; }}
  th, td {{ text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--border); }}
  th {{ color: var(--muted); font-weight: 600; font-size: .72rem;
        text-transform: uppercase; letter-spacing: .06em; }}
  code {{ font-family: var(--mono); font-size: .82em; }}
</style>
</head>
<body>
<h1>🔒 SSL / TLS Validation Report</h1>
<p class="subtitle">Generated {self.generated} &nbsp;·&nbsp; {summary['total']} target(s) scanned</p>

<div class="summary">
  <div class="stat"><div class="stat-value">{summary['total']}</div><div class="stat-label">Total</div></div>
  <div class="stat"><div class="stat-value" style="color:var(--pass)">{summary['pass']}</div><div class="stat-label">Pass</div></div>
  <div class="stat"><div class="stat-value" style="color:var(--warn)">{summary['warn']}</div><div class="stat-label">Warn</div></div>
  <div class="stat"><div class="stat-value" style="color:var(--fail)">{summary['fail']}</div><div class="stat-label">Fail</div></div>
  <div class="stat"><div class="stat-value" style="color:var(--error)">{summary['error']}</div><div class="stat-label">Error</div></div>
</div>

{rows}

</body>
</html>"""

    # ── HTML helpers ───────────────────────────────────────────────────────────

    def _html_row(self, r: dict) -> str:
        status = r.get("status", "error")
        meta   = _STATUS_META.get(status, _STATUS_META["error"])
        color  = meta["color"]
        label  = meta["label"]

        tags_html = " ".join(
            f'<span style="background:rgba(255,255,255,.07);border-radius:3px;'
            f'padding:1px 6px;font-size:.72rem">{t}</span>'
            for t in r.get("tags", [])
        )

        sections_html = ""
        for section_name, check in r.get("checks", {}).items():
            sections_html += self._html_section(section_name, check)

        # Certificate quick-details table
        cert_details = r.get("checks", {}).get("certificate", {}).get("details", {})
        tls_details  = r.get("checks", {}).get("tls",  {}).get("details", {})
        cip_details  = r.get("checks", {}).get("ciphers", {}).get("details", {})
        details_html = ""
        if cert_details or tls_details or cip_details:
            rows = ""
            def dr(k, v):
                return f'<tr><td class="detail-key">{k}</td><td class="detail-value"><code>{v or "n/a"}</code></td></tr>'
            if cert_details:
                rows += dr("Subject",    cert_details.get("subject"))
                rows += dr("Issuer",     cert_details.get("issuer"))
                rows += dr("Expires",    cert_details.get("not_after"))
                rows += dr("Key",        f"{cert_details.get('key_type','?')} {cert_details.get('key_size','?')} bits")
                rows += dr("Sig Alg",    cert_details.get("sig_alg"))
                if cert_details.get("san"):
                    rows += dr("SAN",    ", ".join(cert_details["san"][:4]))
            if tls_details:
                rows += dr("TLS Negotiated",  tls_details.get("negotiated_version"))
                rows += dr("TLS Supported",   ", ".join(tls_details.get("supported_versions", [])))
            if cip_details:
                rows += dr("Cipher Negotiated", cip_details.get("negotiated_cipher"))
                rows += dr("Ciphers Accepted",  str(len(cip_details.get("accepted_ciphers", []))))
            details_html = f"""
<div class="section">
  <div class="section-title">Details</div>
  <table>{rows}</table>
</div>"""

        return f"""
<div class="card">
  <details>
    <summary>
      <div class="card-header">
        <span class="badge" style="background:color-mix(in srgb,{color} 20%,transparent);color:{color}">{label}</span>
        <span class="card-title">{r.get('name', r.get('host'))}</span>
        <span class="card-meta">{r.get('host')}:{r.get('port', 443)}</span>
        {tags_html}
        <span class="chevron">▶</span>
      </div>
    </summary>
    <div class="card-body">
      {sections_html}
      {details_html}
    </div>
  </details>
</div>"""

    def _html_section(self, name: str, check: dict) -> str:
        status = check.get("status", "pass")
        meta   = _STATUS_META.get(status, _STATUS_META["pass"])
        color  = meta["color"]
        label  = meta["label"]

        findings_html = ""
        for f in check.get("findings", []):
            sev   = f["severity"]
            fcol  = _SEVERITY_COLOR.get(sev, "#94a3b8")
            findings_html += (
                f'<div class="finding">'
                f'<span class="finding-code" style="color:{fcol}">{f["code"]}</span>'
                f'<span class="finding-msg">{f["message"]}</span>'
                f'</div>'
            )
        if not findings_html:
            findings_html = '<span style="font-size:.82rem;color:#22c55e">No issues found</span>'

        return f"""
<div class="section">
  <div class="section-title">
    {name.upper()}
    <span class="badge" style="background:color-mix(in srgb,{color} 18%,transparent);
          color:{color};margin-left:6px">{label}</span>
  </div>
  {findings_html}
</div>"""

    # ── Summary ────────────────────────────────────────────────────────────────

    def _build_summary(self) -> dict:
        summary = {"total": len(self.results), "pass": 0, "warn": 0, "fail": 0, "error": 0}
        for r in self.results:
            s = r.get("status", "error")
            summary[s] = summary.get(s, 0) + 1
        return summary

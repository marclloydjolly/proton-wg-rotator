"""
SMTP notification for `protonwg refresh`.

Config lives in `state/notify.toml`, chmod 0600. Renders an HTML +
plain-text alternate via MIME multipart; sends through an IONOS-style
authenticating SMTP server with STARTTLS.

Nothing in this module writes passwords to logs.
"""

from __future__ import annotations

import html
import os
import smtplib
import socket
import ssl
import sys
import tomllib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid
from pathlib import Path
from typing import Any, Literal


# ---- data -----------------------------------------------------------------


@dataclass
class SMTPSettings:
    host: str
    port: int
    username: str
    password: str
    use_starttls: bool = True


@dataclass
class EmailSettings:
    from_address: str
    to_address: str
    subject_prefix: str = "[ProtonWG]"


@dataclass
class NotifyConfig:
    enabled: bool
    smtp: SMTPSettings
    email: EmailSettings


@dataclass
class PoolChange:
    index: int
    kind: Literal[
        "replaced", "endpoint_ip", "peer_key", "added", "offline_no_replacement"
    ]
    before: str
    after: str
    reason: str


@dataclass
class RefreshReport:
    host: str
    library_path: str
    started_at: datetime
    finished_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    exit_code: int = 0
    cert_serial: str | None = None
    cert_expires_at: str | None = None
    cert_days_remaining: int | None = None
    cert_rotated: bool = False
    pool_size: int = 0
    changes: list[PoolChange] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: str | None = None
    summary_line: str = ""

    @property
    def duration_seconds(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    @property
    def status_word(self) -> str:
        if self.error:
            return "failed"
        if self.changes:
            return f"{len(self.changes)} change{'s' if len(self.changes) != 1 else ''}"
        return "no changes"


# ---- config I/O -----------------------------------------------------------


def load_config(path: Path) -> NotifyConfig | None:
    """Load notify.toml; return None if the file doesn't exist."""
    if not path.exists():
        return None
    with path.open("rb") as fh:
        raw = tomllib.load(fh)
    if not raw.get("enabled", True):
        return NotifyConfig(
            enabled=False,
            smtp=SMTPSettings("", 0, "", ""),
            email=EmailSettings("", ""),
        )
    smtp_raw = raw.get("smtp", {})
    email_raw = raw.get("email", {})
    return NotifyConfig(
        enabled=True,
        smtp=SMTPSettings(
            host=smtp_raw["host"],
            port=int(smtp_raw.get("port", 587)),
            username=smtp_raw["username"],
            password=smtp_raw["password"],
            use_starttls=bool(smtp_raw.get("use_starttls", True)),
        ),
        email=EmailSettings(
            from_address=email_raw["from_address"],
            to_address=email_raw["to_address"],
            subject_prefix=email_raw.get("subject_prefix", "[ProtonWG]"),
        ),
    )


def write_config_interactively(path: Path) -> NotifyConfig:
    """Prompt the user and write notify.toml at 0600."""
    import getpass

    print(f"Writing SMTP notify config to {path}")
    host = input("SMTP host [smtp.ionos.co.uk]: ").strip() or "smtp.ionos.co.uk"
    port_raw = input("SMTP port [587]: ").strip() or "587"
    port = int(port_raw)
    username = input("SMTP username (usually your full email): ").strip()
    password = getpass.getpass("SMTP password: ")
    from_address = (
        input(f"From address [{username}]: ").strip() or username
    )
    to_address = input("To address (where reports go): ").strip()
    prefix = input("Subject prefix [[ProtonWG]]: ").strip() or "[ProtonWG]"

    # TOML by hand — keep deps slim. Escape backslashes and quotes.
    def q(s: str) -> str:
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'

    body = (
        "enabled = true\n\n"
        "[smtp]\n"
        f"host = {q(host)}\n"
        f"port = {port}\n"
        f"username = {q(username)}\n"
        f"password = {q(password)}\n"
        "use_starttls = true\n\n"
        "[email]\n"
        f"from_address = {q(from_address)}\n"
        f"to_address = {q(to_address)}\n"
        f"subject_prefix = {q(prefix)}\n"
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(body)
    tmp.chmod(0o600)
    tmp.replace(path)
    cfg = load_config(path)
    assert cfg is not None
    return cfg


# ---- rendering ------------------------------------------------------------


def _fmt_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _fmt_duration(seconds: float) -> str:
    if seconds < 1.0:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60.0:
        return f"{seconds:.1f}s"
    return f"{int(seconds // 60)}m{int(seconds % 60):02d}s"


def render_text(report: RefreshReport) -> str:
    lines = [
        f"ProtonWG refresh report",
        f"=======================",
        f"Host:        {report.host}",
        f"Library:     {report.library_path}",
        f"Started:     {_fmt_ts(report.started_at)}",
        f"Duration:    {_fmt_duration(report.duration_seconds)}",
        f"Status:      {report.status_word}",
        f"Exit:        {report.exit_code}",
        "",
    ]
    if report.cert_serial:
        rotated = "  [ROTATED THIS RUN]" if report.cert_rotated else ""
        lines += [
            f"Certificate{rotated}",
            f"  Serial:    {report.cert_serial}",
            f"  Expires:   {report.cert_expires_at} "
            f"({report.cert_days_remaining}d remaining)",
            "",
        ]
    lines += [
        f"Pool size: {report.pool_size}",
        f"Changes:   {len(report.changes)}",
        "",
    ]
    if report.changes:
        lines.append("Change log:")
        for c in report.changes:
            lines.append(
                f"  [{c.index:>2}] {c.kind}: {c.before} -> {c.after}   ({c.reason})"
            )
        lines.append("")
    if report.warnings:
        lines.append("Warnings:")
        for w in report.warnings:
            lines.append(f"  - {w}")
        lines.append("")
    if report.error:
        lines.append("Error:")
        lines.append(f"  {report.error}")
        lines.append("")
    if report.summary_line:
        lines.append(report.summary_line)
    return "\n".join(lines)


_HTML_STYLE = """
  body { font-family: -apple-system, Segoe UI, Helvetica, Arial, sans-serif; font-size: 14px; color: #222; background: #f6f7f9; margin: 0; padding: 24px; }
  .card { max-width: 720px; margin: 0 auto; background: #fff; border: 1px solid #e2e5ea; border-radius: 10px; overflow: hidden; }
  .hdr { padding: 18px 22px; border-bottom: 1px solid #eee; }
  .hdr h1 { margin: 0 0 4px; font-size: 18px; }
  .hdr .meta { color: #666; font-size: 13px; }
  .status { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; margin-left: 8px; vertical-align: 1px; }
  .status.ok { background: #e3f7e8; color: #1c6b2f; }
  .status.changed { background: #e8f0ff; color: #174ea6; }
  .status.failed { background: #fbe6e6; color: #a30b0b; }
  .kv { padding: 14px 22px; border-bottom: 1px solid #f1f2f5; }
  .kv table { width: 100%; border-collapse: collapse; }
  .kv td { padding: 3px 0; font-size: 13px; }
  .kv td.k { color: #666; width: 150px; }
  .kv td.v { color: #111; font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 12.5px; }
  h2 { font-size: 14px; margin: 20px 22px 8px; color: #333; }
  .chg { margin: 0 22px 14px; }
  .chg table { width: 100%; border-collapse: collapse; font-size: 13px; }
  .chg th, .chg td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #f1f2f5; }
  .chg th { background: #fafbfc; color: #555; font-weight: 600; }
  .chg td.idx { font-family: ui-monospace, monospace; color: #999; width: 36px; }
  .chg td.kind { font-family: ui-monospace, monospace; color: #555; width: 150px; }
  .warn { background: #fff8e1; border-left: 3px solid #e5b900; padding: 10px 14px; margin: 0 22px 14px; border-radius: 4px; font-size: 13px; }
  .err { background: #fcebea; border-left: 3px solid #c53a3a; padding: 10px 14px; margin: 0 22px 14px; border-radius: 4px; font-size: 13px; color: #7a1b1b; }
  .ftr { padding: 12px 22px; color: #888; font-size: 12px; background: #fafbfc; }
"""


def render_html(report: RefreshReport) -> str:
    if report.error:
        status_cls = "failed"
    elif report.changes:
        status_cls = "changed"
    else:
        status_cls = "ok"

    cert_block = ""
    if report.cert_serial:
        rotated = (
            ' <span class="status changed">rotated this run</span>'
            if report.cert_rotated
            else ""
        )
        cert_block = f"""
    <div class="kv">
      <table>
        <tr><td class="k">Cert serial</td><td class="v">{html.escape(report.cert_serial)}</td></tr>
        <tr><td class="k">Cert expires</td><td class="v">{html.escape(report.cert_expires_at or '')} ({report.cert_days_remaining}d remaining){rotated}</td></tr>
      </table>
    </div>"""

    changes_block = ""
    if report.changes:
        rows = []
        for c in report.changes:
            rows.append(
                "<tr>"
                f'<td class="idx">{c.index}</td>'
                f'<td class="kind">{html.escape(c.kind)}</td>'
                f"<td>{html.escape(c.before)} &rarr; {html.escape(c.after)}</td>"
                f"<td>{html.escape(c.reason)}</td>"
                "</tr>"
            )
        changes_block = f"""
    <h2>Changes ({len(report.changes)})</h2>
    <div class="chg">
      <table>
        <tr><th>#</th><th>Kind</th><th>Before &rarr; After</th><th>Reason</th></tr>
        {''.join(rows)}
      </table>
    </div>"""

    warnings_block = ""
    if report.warnings:
        items = "".join(f"<div>• {html.escape(w)}</div>" for w in report.warnings)
        warnings_block = f'<div class="warn"><strong>Warnings</strong>{items}</div>'

    error_block = ""
    if report.error:
        error_block = (
            f'<div class="err"><strong>Error</strong><br>'
            f"<code>{html.escape(report.error)}</code></div>"
        )

    return f"""<!doctype html>
<html>
<head><meta charset="utf-8"><style>{_HTML_STYLE}</style></head>
<body>
  <div class="card">
    <div class="hdr">
      <h1>ProtonWG refresh
        <span class="status {status_cls}">{html.escape(report.status_word)}</span>
      </h1>
      <div class="meta">{html.escape(report.host)} &middot; {_fmt_ts(report.started_at)} &middot; took {_fmt_duration(report.duration_seconds)}</div>
    </div>
    <div class="kv">
      <table>
        <tr><td class="k">Library</td><td class="v">{html.escape(report.library_path)}</td></tr>
        <tr><td class="k">Pool size</td><td class="v">{report.pool_size}</td></tr>
        <tr><td class="k">Exit code</td><td class="v">{report.exit_code}</td></tr>
      </table>
    </div>
    {cert_block}
    {changes_block}
    {warnings_block}
    {error_block}
    <div class="ftr">Generated by <code>protonwg refresh</code> &middot; {html.escape(report.summary_line)}</div>
  </div>
</body></html>"""


# ---- sending --------------------------------------------------------------


def _build_subject(cfg: NotifyConfig, report: RefreshReport) -> str:
    return (
        f"{cfg.email.subject_prefix} refresh — {report.status_word} "
        f"({_fmt_ts(report.started_at)})"
    )


def send(cfg: NotifyConfig, report: RefreshReport) -> None:
    """Send the rendered report. Raises on transport failure."""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = _build_subject(cfg, report)
    msg["From"] = cfg.email.from_address
    msg["To"] = cfg.email.to_address
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=cfg.email.from_address.split("@", 1)[-1])

    msg.attach(MIMEText(render_text(report), "plain", "utf-8"))
    msg.attach(MIMEText(render_html(report), "html", "utf-8"))

    context = ssl.create_default_context()
    with smtplib.SMTP(cfg.smtp.host, cfg.smtp.port, timeout=30) as s:
        s.ehlo()
        if cfg.smtp.use_starttls:
            s.starttls(context=context)
            s.ehlo()
        s.login(cfg.smtp.username, cfg.smtp.password)
        s.sendmail(
            cfg.email.from_address,
            [cfg.email.to_address],
            msg.as_string(),
        )


# ---- helpers for callers --------------------------------------------------


def current_hostname() -> str:
    return socket.gethostname()


def safe_send(cfg: NotifyConfig | None, report: RefreshReport) -> None:
    """Send if configured; swallow errors so refresh itself never fails on notify."""
    if cfg is None or not cfg.enabled:
        return
    try:
        send(cfg, report)
    except Exception as exc:
        print(f"notifier: failed to send report: {exc}", file=sys.stderr)


# ---- swap reports ---------------------------------------------------------


@dataclass
class SwapReport:
    host: str
    when: datetime
    # Filled from hotloop.Decision + hotloop.SwapResult. We keep them as plain
    # attributes (not typed imports) to avoid circular imports.
    action: str  # 'swap' | 'emergency_swap' | 'bootstrap_swap'
    reason: str
    before_name: str
    before_ip: str
    before_score: float | None
    before_load: int | None
    before_handshake_age_s: int | None
    after_name: str
    after_ip: str
    after_score: float
    after_load: int
    improvement: float | None
    result_ok: bool
    rolled_back: bool
    error: str | None
    duration_ms: int
    handshake_age_after_s: int | None
    top_candidates: list[tuple[str, float, int, str, bool]] = field(default_factory=list)
    # each tuple: (name, score, load, endpoint_ip, was_current)


def _swap_status_word(r: SwapReport) -> tuple[str, str]:
    """Return (word, css_class)."""
    if r.result_ok:
        if r.action == "bootstrap_swap":
            return "bootstrapped", "changed"
        if r.action == "emergency_swap":
            return "emergency swap", "changed"
        return "swapped", "changed"
    if r.rolled_back:
        return "rolled back", "failed"
    return "failed", "failed"


def render_swap_text(r: SwapReport) -> str:
    word, _ = _swap_status_word(r)
    lines = [
        f"ProtonWG swap report — {word}",
        "=" * (22 + len(word)),
        f"Host:       {r.host}",
        f"When:       {_fmt_ts(r.when)}",
        f"Action:     {r.action}",
        f"Duration:   {_fmt_duration(r.duration_ms / 1000)}",
        "",
        "Before:",
        f"  logical:      {r.before_name}",
        f"  endpoint:     {r.before_ip}",
        f"  score:        {r.before_score if r.before_score is not None else 'n/a'}",
        f"  load:         {f'{r.before_load}%' if r.before_load is not None else 'n/a'}",
        f"  handshake age: {r.before_handshake_age_s}s"
        if r.before_handshake_age_s is not None
        else "  handshake age: none",
        "",
        "After:",
        f"  logical:      {r.after_name}",
        f"  endpoint:     {r.after_ip}",
        f"  score:        {r.after_score:.2f}",
        f"  load:         {r.after_load}%",
        f"  handshake:    {r.handshake_age_after_s}s ago"
        if r.handshake_age_after_s is not None
        else "  handshake:    NO handshake",
        "",
    ]
    if r.improvement is not None:
        lines.append(f"Improvement: {r.improvement:.1%}")
        lines.append("")
    lines.append(f"Reason: {r.reason}")
    lines.append("")
    if r.error:
        lines.append("Error:")
        lines.append(f"  {r.error}")
        lines.append("")
    if r.top_candidates:
        lines.append("Top 5 candidates by score at decision time:")
        for name, score, load, ip, is_current in r.top_candidates[:5]:
            marker = " <-- current" if is_current else ""
            lines.append(f"  {name:<10}  score={score:.2f}  load={load:>3}%  {ip}{marker}")
    return "\n".join(lines)


def render_swap_html(r: SwapReport) -> str:
    word, cls = _swap_status_word(r)
    improvement_row = ""
    if r.improvement is not None:
        improvement_row = (
            f'<tr><td class="k">Score improvement</td>'
            f'<td class="v">{r.improvement:.1%}</td></tr>'
        )
    before_hs = (
        f"{r.before_handshake_age_s}s ago"
        if r.before_handshake_age_s is not None
        else "<em>none</em>"
    )
    after_hs = (
        f"{r.handshake_age_after_s}s ago"
        if r.handshake_age_after_s is not None
        else '<strong style="color:#a30b0b">no handshake</strong>'
    )
    before_score = (
        f"{r.before_score:.2f}" if r.before_score is not None else "<em>n/a</em>"
    )
    before_load = f"{r.before_load}%" if r.before_load is not None else "<em>n/a</em>"

    cand_rows = ""
    for name, score, load, ip, is_current in r.top_candidates[:5]:
        marker = ' <span class="status changed">current</span>' if is_current else ""
        cand_rows += (
            "<tr>"
            f'<td style="font-family:ui-monospace,monospace">{html.escape(name)}{marker}</td>'
            f'<td style="font-family:ui-monospace,monospace">{score:.2f}</td>'
            f'<td style="font-family:ui-monospace,monospace">{load}%</td>'
            f'<td style="font-family:ui-monospace,monospace">{html.escape(ip)}</td>'
            "</tr>"
        )
    cand_block = (
        f"""
    <h2>Top 5 candidates at decision time</h2>
    <div class="chg">
      <table>
        <tr><th>Logical</th><th>Score</th><th>Load</th><th>Endpoint</th></tr>
        {cand_rows}
      </table>
    </div>"""
        if cand_rows
        else ""
    )

    error_block = (
        f'<div class="err"><strong>Error</strong><br><code>{html.escape(r.error)}</code></div>'
        if r.error
        else ""
    )

    return f"""<!doctype html>
<html>
<head><meta charset="utf-8"><style>{_HTML_STYLE}
  .pair {{ display: table; width: 100%; border-collapse: collapse; margin: 0 22px 14px; }}
  .pair .side {{ display: table-cell; width: 50%; padding: 10px 14px; vertical-align: top; font-size: 13px; }}
  .pair .side.before {{ background: #fafbfc; border-right: 1px solid #eaecef; border-radius: 6px 0 0 6px; }}
  .pair .side.after  {{ background: #eef5ff; border-radius: 0 6px 6px 0; }}
  .pair h3 {{ margin: 0 0 6px; font-size: 12px; color: #666; text-transform: uppercase; letter-spacing: .04em; }}
  .pair .name {{ font-family: ui-monospace, monospace; font-size: 14px; font-weight: 600; }}
  .pair .small {{ color: #666; font-size: 12px; margin-top: 4px; }}
</style></head>
<body>
  <div class="card">
    <div class="hdr">
      <h1>ProtonWG swap <span class="status {cls}">{html.escape(word)}</span></h1>
      <div class="meta">{html.escape(r.host)} &middot; {_fmt_ts(r.when)} &middot; took {_fmt_duration(r.duration_ms / 1000)}</div>
    </div>
    <div class="kv">
      <table>
        <tr><td class="k">Action</td><td class="v">{html.escape(r.action)}</td></tr>
        <tr><td class="k">Reason</td><td class="v">{html.escape(r.reason)}</td></tr>
        {improvement_row}
      </table>
    </div>
    <div class="pair">
      <div class="side before">
        <h3>Before</h3>
        <div class="name">{html.escape(r.before_name)}</div>
        <div class="small">{html.escape(r.before_ip)}</div>
        <div class="small">score {before_score} · load {before_load}</div>
        <div class="small">handshake: {before_hs}</div>
      </div>
      <div class="side after">
        <h3>After</h3>
        <div class="name">{html.escape(r.after_name)}</div>
        <div class="small">{html.escape(r.after_ip)}</div>
        <div class="small">score {r.after_score:.2f} · load {r.after_load}%</div>
        <div class="small">handshake: {after_hs}</div>
      </div>
    </div>
    {error_block}
    {cand_block}
    <div class="ftr">Generated by <code>protonwg swap-check</code></div>
  </div>
</body></html>"""


def send_swap_report(cfg: NotifyConfig, report: SwapReport) -> None:
    word, _ = _swap_status_word(report)
    msg = MIMEMultipart("alternative")
    msg["Subject"] = (
        f"{cfg.email.subject_prefix} swap {word} — "
        f"{report.after_name} ({_fmt_ts(report.when)})"
    )
    msg["From"] = cfg.email.from_address
    msg["To"] = cfg.email.to_address
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain=cfg.email.from_address.split("@", 1)[-1])
    msg.attach(MIMEText(render_swap_text(report), "plain", "utf-8"))
    msg.attach(MIMEText(render_swap_html(report), "html", "utf-8"))

    context = ssl.create_default_context()
    with smtplib.SMTP(cfg.smtp.host, cfg.smtp.port, timeout=30) as s:
        s.ehlo()
        if cfg.smtp.use_starttls:
            s.starttls(context=context)
            s.ehlo()
        s.login(cfg.smtp.username, cfg.smtp.password)
        s.sendmail(
            cfg.email.from_address,
            [cfg.email.to_address],
            msg.as_string(),
        )


def safe_send_swap(cfg: NotifyConfig | None, report: SwapReport) -> None:
    if cfg is None or not cfg.enabled:
        return
    try:
        send_swap_report(cfg, report)
    except Exception as exc:
        print(f"notifier: swap email failed: {exc}", file=sys.stderr)

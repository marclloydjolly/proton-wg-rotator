"""
Small HTTP API for a frontend to inspect + control the rotator.

Design constraints:
  - Stdlib only (`http.server.ThreadingHTTPServer` + `json` + `subprocess`).
    Keeps the dependency footprint identical to v0.2.x.
  - Bind to loopback by default. There is no auth layer — the trust model
    is "processes on the same host".
  - Runs as root (needed to `wg show`, `systemctl start protonwg-*`,
    read/write `/etc/wireguard/wg0.conf`).
  - Cheap 1-second in-memory cache on the merged /state so a chatty
    frontend polling multiple times per second doesn't hammer Proton's
    `/vpn/loads`.

Routes:

    GET  /health              is the API up? (version + timestamp)
    GET  /state               everything a frontend needs in one blob
    GET  /pool                pool array joined to live scores
    GET  /tunnel              current wg0 state
    GET  /cert                cert serial + expiry
    GET  /history             hotloop.json contents

    POST /actions/health-check     systemctl start protonwg-health-check
    POST /actions/swap-check       systemctl start protonwg-swap-check
    POST /actions/refresh          systemctl start protonwg-refresh
    POST /actions/rebuild-pool     runs `protonwg rebuild-pool` sync (~5s)
"""

from __future__ import annotations

import hmac
import ipaddress
import json
import os
import secrets
import signal
import stat
import subprocess
import sys
import threading
import time
from dataclasses import asdict
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from . import __version__
from ._fsutil import chown_to_parent_owner
from .api import ProtonClient
from .hotloop import (
    HotLoopState,
    TunnelSnapshot,
    fetch_loads,
    get_tunnel_snapshot,
)
from .library import Library
from .paths import ProjectPaths


# ---- auth -----------------------------------------------------------------


def _is_loopback(host: str) -> bool:
    """Is this bind host a loopback address? Loopback binds skip auth by default."""
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_loopback
    except ValueError:
        return host in ("localhost",)


def resolve_or_generate_token(token_path: Path, cli_token: str | None) -> str:
    """
    Pick / persist the API bearer token.

    Precedence:
      1. --auth-token CLI flag (or PROTONWG_API_TOKEN env var), if set.
      2. Existing token in state/api-token.
      3. Fresh 32-byte random token, written to state/api-token (chmod 0600,
         chown to parent-dir owner).

    Returning the same token across restarts means the frontend doesn't
    need reconfiguring every time the rotator bounces.
    """
    if cli_token:
        return cli_token
    if token_path.exists():
        return token_path.read_text().strip()
    token = secrets.token_urlsafe(32)
    token_path.parent.mkdir(parents=True, exist_ok=True)
    token_path.write_text(token + "\n")
    os.chmod(token_path, stat.S_IRUSR | stat.S_IWUSR)
    chown_to_parent_owner(token_path)
    return token


# ---- state cache ----------------------------------------------------------


class StateCache:
    """1-second in-memory cache so /state can be polled aggressively."""

    def __init__(self, ttl_seconds: float = 1.0):
        self.ttl = ttl_seconds
        self._value: dict | None = None
        self._expires_at: float = 0.0
        self._lock = threading.Lock()

    def get(self, compute_fn) -> dict:
        with self._lock:
            now = time.monotonic()
            if self._value is not None and now < self._expires_at:
                return self._value
            self._value = compute_fn()
            self._expires_at = now + self.ttl
            return self._value


# ---- snapshot builders ----------------------------------------------------


def _cert_block(lib: Library) -> dict | None:
    if lib.identity is None:
        return None
    try:
        expires = datetime.fromisoformat(lib.identity.cert_expires_at)
        days_remaining = int(
            (expires - datetime.now(timezone.utc)).total_seconds() // 86400
        )
    except ValueError:
        days_remaining = None
    return {
        "serial": lib.identity.cert_serial,
        "expires_at": lib.identity.cert_expires_at,
        "days_remaining": days_remaining,
    }


def _pool_block(
    lib: Library,
    loads_by_id: dict[str, dict],
    current_pubkey: str | None,
) -> list[dict]:
    rows = []
    for entry in lib.pool:
        ld = loads_by_id.get(entry.logical_id) or {}
        rows.append(
            {
                "index": entry.index,
                "logical_id": entry.logical_id,
                "logical_name": entry.logical_name,
                "country": entry.country,
                "city": entry.city,
                "tier": entry.tier,
                "features": entry.features,
                "endpoint_ip": entry.endpoint_ip,
                "endpoint_port": entry.endpoint_port,
                "peer_public_key": entry.peer_public_key,
                "config_file": entry.config_file,
                # Live from /vpn/loads — may be None if the fetch failed.
                "score": float(ld["Score"]) if "Score" in ld else None,
                "load": int(ld["Load"]) if "Load" in ld else None,
                "status": int(ld["Status"]) if "Status" in ld else None,
                "is_current": (
                    current_pubkey is not None
                    and current_pubkey == entry.peer_public_key
                ),
            }
        )
    return rows


def _current_block(lib: Library, snapshot: TunnelSnapshot) -> dict:
    current_entry = next(
        (e for e in lib.pool if e.peer_public_key == snapshot.peer_pubkey),
        None,
    )
    return {
        "peer_pubkey": snapshot.peer_pubkey,
        "endpoint": snapshot.endpoint,
        "endpoint_ip": snapshot.endpoint_ip,
        "endpoint_port": snapshot.endpoint_port,
        "handshake_age_seconds": snapshot.handshake_age_s,
        "rx_bytes": snapshot.rx_bytes,
        "tx_bytes": snapshot.tx_bytes,
        "keepalive_seconds": snapshot.keepalive_s,
        "in_pool": current_entry is not None,
        "pool_index": current_entry.index if current_entry else None,
        "logical_name": current_entry.logical_name if current_entry else None,
        "city": current_entry.city if current_entry else None,
    }


def build_state_snapshot(paths: ProjectPaths, iface: str = "wg0") -> dict:
    """The complete state document — everything a frontend needs in one call."""
    lib = Library.load(paths.library_file)
    hotloop_state = HotLoopState.load(paths.hotloop_state)

    loads_error: str | None = None
    loads_by_id: dict[str, dict] = {}
    if paths.session_file.exists():
        try:
            loads_by_id = fetch_loads(ProtonClient(paths.session_file))
        except Exception as exc:
            # Frontend should render the pool without live scores rather than
            # blank; we surface the failure explicitly so the UI can indicate it.
            loads_error = f"{type(exc).__name__}: {exc}"
    else:
        loads_error = "not logged in — run `protonwg login`"

    snapshot = get_tunnel_snapshot(iface)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "version": __version__,
        "interface": iface,
        "cert": _cert_block(lib),
        "current": _current_block(lib, snapshot),
        "pool": _pool_block(lib, loads_by_id, snapshot.peer_pubkey),
        "filters": lib.filters,
        "history": {
            "last_swap_at": hotloop_state.last_swap_at,
            "last_swap_target_logical": hotloop_state.last_swap_target_logical,
            "last_swap_result": hotloop_state.last_swap_result,
            "swap_count_total": hotloop_state.swap_count_total,
        },
        "loads_error": loads_error,
    }


# ---- action runners -------------------------------------------------------


ACTION_UNITS = {
    "health-check": "protonwg-health-check.service",
    "swap-check": "protonwg-swap-check.service",
    "refresh": "protonwg-refresh.service",
}


def trigger_unit(unit: str) -> dict:
    """Kick a systemd unit and return immediately."""
    r = subprocess.run(
        ["systemctl", "start", unit],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return {
        "unit": unit,
        "started": r.returncode == 0,
        "returncode": r.returncode,
        "stdout": r.stdout.strip(),
        "stderr": r.stderr.strip(),
    }


def run_rebuild_pool(project_root: Path) -> dict:
    """Run `protonwg rebuild-pool` synchronously; return stdout for the frontend."""
    binary = project_root / ".venv" / "bin" / "protonwg"
    r = subprocess.run(
        [str(binary), "rebuild-pool"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    return {
        "ok": r.returncode == 0,
        "returncode": r.returncode,
        "stdout": r.stdout.strip(),
        "stderr": r.stderr.strip(),
    }


# ---- HTTP handler ---------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    """Route dispatch is dumb-simple — the API surface is tiny and stable."""

    # We handle our own logging via journalctl-friendly stderr writes;
    # BaseHTTPRequestHandler's default access log noise isn't useful here.
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        sys.stderr.write(
            f"[{self.log_date_time_string()}] {self.address_string()} - "
            f"{format % args}\n"
        )

    # ---- helpers ----------------------------------------------------------

    def _write(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # Localhost service, no auth: CORS * is intentional. The trust
        # boundary is "same host". See README security notes.
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj: Any, status: int = 200) -> None:
        body = json.dumps(obj, default=str).encode("utf-8")
        self._write(status, body, "application/json; charset=utf-8")

    def _not_found(self) -> None:
        self._json(
            {"error": "not found", "path": self.path},
            status=404,
        )

    def _get_paths(self) -> ProjectPaths:
        return self.server.paths  # type: ignore[attr-defined]

    def _get_cache(self) -> StateCache:
        return self.server.state_cache  # type: ignore[attr-defined]

    def _get_iface(self) -> str:
        return self.server.iface  # type: ignore[attr-defined]

    def _authorised(self) -> bool:
        """
        Enforce Authorization: Bearer <token> when the server requires auth.
        /health is always public so external monitors can probe.
        OPTIONS is always allowed for CORS preflight.
        """
        token = getattr(self.server, "auth_token", None)  # type: ignore[attr-defined]
        if token is None:
            return True
        if self.command == "OPTIONS":
            return True
        if self.path.split("?", 1)[0] == "/health":
            return True
        header = self.headers.get("Authorization", "")
        if not header.lower().startswith("bearer "):
            return False
        supplied = header[len("Bearer "):].strip()
        return hmac.compare_digest(supplied, token)

    def _reject_unauthenticated(self) -> None:
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Bearer realm="protonwg"')
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        body = json.dumps(
            {"error": "unauthorised", "hint": "send Authorization: Bearer <token>"}
        ).encode("utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ---- HTTP verbs -------------------------------------------------------

    def do_OPTIONS(self) -> None:  # noqa: N802
        # CORS preflight for POST from browsers.
        self._write(204, b"", "text/plain")

    def do_GET(self) -> None:  # noqa: N802
        if not self._authorised():
            self._reject_unauthenticated()
            return
        path = self.path.split("?", 1)[0]

        if path == "/health":
            self._json(
                {
                    "ok": True,
                    "version": __version__,
                    "timestamp": datetime.now(timezone.utc).isoformat(
                        timespec="seconds"
                    ),
                }
            )
            return

        try:
            paths = self._get_paths()
            iface = self._get_iface()
        except Exception as exc:
            self._json({"error": f"server misconfigured: {exc}"}, status=500)
            return

        try:
            if path == "/state":
                snap = self._get_cache().get(
                    lambda: build_state_snapshot(paths, iface=iface)
                )
                self._json(snap)
                return
            if path == "/pool":
                snap = self._get_cache().get(
                    lambda: build_state_snapshot(paths, iface=iface)
                )
                self._json(snap["pool"])
                return
            if path == "/tunnel":
                snap = self._get_cache().get(
                    lambda: build_state_snapshot(paths, iface=iface)
                )
                self._json(snap["current"])
                return
            if path == "/cert":
                lib = Library.load(paths.library_file)
                self._json(_cert_block(lib) or {})
                return
            if path == "/history":
                state = HotLoopState.load(paths.hotloop_state)
                self._json(asdict(state))
                return
        except FileNotFoundError as exc:
            self._json(
                {"error": f"required file missing: {exc}"},
                status=503,
            )
            return
        except Exception as exc:  # noqa: BLE001
            self._json(
                {"error": f"{type(exc).__name__}: {exc}"},
                status=500,
            )
            return

        self._not_found()

    def do_POST(self) -> None:  # noqa: N802
        if not self._authorised():
            self._reject_unauthenticated()
            return
        path = self.path.split("?", 1)[0]

        if path.startswith("/actions/"):
            action = path[len("/actions/"):]
            try:
                if action in ACTION_UNITS:
                    result = trigger_unit(ACTION_UNITS[action])
                    # 202 Accepted: systemd has queued the oneshot; the
                    # actual work runs asynchronously.
                    status = 202 if result["started"] else 502
                    self._json(result, status=status)
                    return
                if action == "rebuild-pool":
                    paths = self._get_paths()
                    result = run_rebuild_pool(paths.root)
                    status = 200 if result["ok"] else 502
                    self._json(result, status=status)
                    return
            except Exception as exc:  # noqa: BLE001
                self._json(
                    {"error": f"{type(exc).__name__}: {exc}"},
                    status=500,
                )
                return

        self._not_found()


# ---- server bootstrap -----------------------------------------------------


class _ApiServer(ThreadingHTTPServer):
    """ThreadingHTTPServer carrying config on the instance for handlers to read."""

    daemon_threads = True

    def __init__(
        self,
        addr,
        handler,
        *,
        paths: ProjectPaths,
        iface: str,
        cache_ttl: float,
        auth_token: str | None,
    ):
        super().__init__(addr, handler)
        self.paths = paths
        self.iface = iface
        self.state_cache = StateCache(ttl_seconds=cache_ttl)
        # None = auth disabled; string = required Bearer token.
        self.auth_token = auth_token


def serve(
    *,
    project_root: Path,
    bind_host: str = "127.0.0.1",
    bind_port: int = 8787,
    iface: str = "wg0",
    cache_ttl: float = 1.0,
    auth_token: str | None = None,
    no_auth: bool = False,
) -> int:
    paths = ProjectPaths.from_root(project_root)

    # Auth policy:
    #   --no-auth              -> off, no matter the bind
    #   loopback bind          -> off by default (same-host trust)
    #   any other bind         -> ON, token resolved-or-generated
    if no_auth:
        effective_token: str | None = None
        auth_note = "disabled (--no-auth)"
    elif _is_loopback(bind_host):
        effective_token = auth_token  # allow explicit override even on loopback
        auth_note = (
            "disabled (loopback bind; same-host trust)"
            if effective_token is None
            else "enabled (explicit --auth-token on loopback)"
        )
    else:
        effective_token = resolve_or_generate_token(paths.api_token, auth_token)
        auth_note = f"enabled (token at {paths.api_token})"

    server = _ApiServer(
        (bind_host, bind_port),
        _Handler,
        paths=paths,
        iface=iface,
        cache_ttl=cache_ttl,
        auth_token=effective_token,
    )
    print(
        f"protonwg api {__version__} listening on http://{bind_host}:{bind_port} "
        f"(iface={iface}, cache_ttl={cache_ttl}s, auth={auth_note})",
        file=sys.stderr,
    )
    if effective_token is not None and auth_token is None and not _is_loopback(bind_host):
        # Print the token so root+journalctl viewers can copy it. It's also
        # in state/api-token but this saves an extra step.
        print(
            f"protonwg api: bearer token = {effective_token}",
            file=sys.stderr,
        )

    stop = threading.Event()

    def _shutdown(signum, frame):  # noqa: ARG001
        print(
            f"protonwg api: received signal {signum}, shutting down",
            file=sys.stderr,
        )
        stop.set()
        # server.shutdown() must be called from a thread other than the
        # one running serve_forever(); the signal handler runs on main.
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
    return 0

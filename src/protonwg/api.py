"""
Thin wrapper around Proton's API for the three things we need:

    1. Authenticated session (SRP via proton-client).
    2. Listing logical servers (/vpn/v1/logicals).
    3. Registering a WireGuard client certificate (/vpn/v1/certificate).

Session state is persisted as JSON via proton-client's dump/load so the CLI
doesn't re-prompt for credentials on every run.
"""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from proton.api import Session

# See research notes: Linux-app version string; web-* triggers CAPTCHA (code 9001).
API_URL = "https://vpn-api.proton.me"
APP_VERSION = "linux-vpn@4.13.1"
USER_AGENT = "ProtonVPN/4.13.1 (Linux; Ubuntu)"


class ProtonAPIError(RuntimeError):
    """Raised when a Proton API call returns a non-success Code."""


@dataclass
class CertificateResponse:
    serial_number: str
    certificate_pem: str
    server_public_key_pem: str
    expiration_time: int  # unix seconds
    refresh_time: int
    mode: str
    device_name: str


class ProtonClient:
    """Authenticated client; instantiate once, reuse for multiple calls."""

    def __init__(self, session_path: Path):
        self.session_path = session_path
        self._session: Session | None = None

    # ---- session lifecycle ------------------------------------------------

    def _new_session(self) -> Session:
        # TLSPinning=False is required: proton-client 0.5.1's
        # TLSPinningHTTPSConnectionPool passes `strict` positionally to
        # urllib3's HTTPSConnectionPool, but urllib3 removed that arg — so the
        # boolean lands in the `timeout` slot and urllib3 rejects it. We lose
        # Proton's public-key pinning but still get standard HTTPS + CA
        # validation, which is fine against a well-known CA-signed endpoint.
        return Session(
            api_url=API_URL,
            appversion=APP_VERSION,
            user_agent=USER_AGENT,
            TLSPinning=False,
        )

    def login(self, username: str, password: str) -> None:
        """Interactive SRP login. Writes the session to disk on success."""
        sess = self._new_session()
        sess.authenticate(username, password)
        self._session = sess
        self._save()

    def logout(self) -> None:
        if self.session_path.exists():
            try:
                sess = self._load_session()
                sess.logout()
            except Exception:
                pass
            self.session_path.unlink(missing_ok=True)
        self._session = None

    def is_logged_in(self) -> bool:
        return self.session_path.exists()

    def _load_session(self) -> Session:
        with self.session_path.open("r") as fh:
            dump = json.load(fh)
        # Session.load is a static method that returns a fresh Session object
        # with the dump applied; calling it as an instance method throws the
        # loaded state away and returns nothing.
        return Session.load(dump, TLSPinning=False)

    def _save(self) -> None:
        if self._session is None:
            return
        self.session_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.session_path.with_suffix(".tmp")
        with tmp.open("w") as fh:
            json.dump(self._session.dump(), fh, indent=2)
        os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        tmp.replace(self.session_path)

    def _ensure_session(self) -> Session:
        if self._session is None:
            if not self.session_path.exists():
                raise ProtonAPIError(
                    "Not logged in. Run `protonwg login` first."
                )
            self._session = self._load_session()
        return self._session

    # ---- API calls --------------------------------------------------------

    def _call(
        self,
        endpoint: str,
        *,
        jsondata: dict[str, Any] | None = None,
        method: str | None = None,
    ) -> dict[str, Any]:
        sess = self._ensure_session()
        try:
            resp = sess.api_request(endpoint, jsondata=jsondata, method=method)
        finally:
            # proton-client rotates refresh tokens; re-persist after every call.
            self._save()
        if not isinstance(resp, dict):
            raise ProtonAPIError(f"Unexpected response type: {type(resp)}")
        code = resp.get("Code")
        if code not in (1000, 1001):
            raise ProtonAPIError(
                f"Proton API error on {endpoint}: Code={code} "
                f"Error={resp.get('Error', '<no error field>')}"
            )
        return resp

    def get_logicals(self) -> list[dict[str, Any]]:
        """Full list of logical servers with metadata."""
        resp = self._call("/vpn/v1/logicals")
        return resp.get("LogicalServers", [])

    def register_certificate(
        self,
        ed25519_public_pem: str,
        *,
        device_name: str,
        duration: str = "525600 min",  # 365 days, Proton's stated maximum
        features: dict[str, Any] | None = None,
    ) -> CertificateResponse:
        """
        Issue (or rotate) a WireGuard cert tied to this client public key.
        The same cert authorises the client for every server on the account's
        tier — per-server targeting happens at connect time.
        """
        body = {
            "ClientPublicKey": ed25519_public_pem,
            "ClientPublicKeyMode": "EC",
            "Mode": "persistent",
            "DeviceName": device_name,
            "Duration": duration,
            "Features": features
            or {
                "NetShieldLevel": 0,
                "RandomNAT": False,
                "PortForwarding": False,
                "SplitTCP": True,
            },
        }
        resp = self._call("/vpn/v1/certificate", jsondata=body, method="POST")
        return CertificateResponse(
            serial_number=resp["SerialNumber"],
            certificate_pem=resp["Certificate"],
            server_public_key_pem=resp["ServerPublicKey"],
            expiration_time=int(resp["ExpirationTime"]),
            refresh_time=int(resp["RefreshTime"]),
            mode=resp["Mode"],
            device_name=resp["DeviceName"],
        )

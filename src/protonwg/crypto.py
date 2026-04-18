"""
Key generation and conversion for ProtonVPN WireGuard.

Proton issues certificates over an Ed25519 public key (PKIX PEM) and derives the
WireGuard X25519 peer key server-side. For `wg-quick` we need the *X25519*
private key in the [Interface] block, which can be derived from the Ed25519
private key via the standard NaCl sign-to-kx conversion.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from nacl.bindings import (
    crypto_sign_ed25519_pk_to_curve25519,
    crypto_sign_ed25519_sk_to_curve25519,
)


@dataclass(frozen=True)
class Identity:
    """An Ed25519 keypair plus its derived WireGuard (X25519) form."""

    ed25519_private_pem: str
    ed25519_public_pem: str
    wg_private_key_b64: str
    wg_public_key_b64: str


def generate_identity() -> Identity:
    """Generate a fresh Ed25519 keypair and derive the WG X25519 material."""
    ed_priv = ed25519.Ed25519PrivateKey.generate()
    return _identity_from_ed25519(ed_priv)


def load_identity(ed25519_private_pem: str) -> Identity:
    """Rehydrate an Identity from a stored Ed25519 private-key PEM."""
    ed_priv = serialization.load_pem_private_key(
        ed25519_private_pem.encode("ascii"), password=None
    )
    if not isinstance(ed_priv, ed25519.Ed25519PrivateKey):
        raise ValueError("Stored key is not Ed25519")
    return _identity_from_ed25519(ed_priv)


def _identity_from_ed25519(ed_priv: ed25519.Ed25519PrivateKey) -> Identity:
    ed_pub = ed_priv.public_key()

    # PEM encodings — what we store on disk and send to Proton.
    priv_pem = ed_priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    pub_pem = ed_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")

    # Raw 32-byte seed + 32-byte pubkey form the 64-byte NaCl-style Ed25519 SK.
    seed = ed_priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_raw = ed_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    nacl_sk = seed + pub_raw

    wg_priv = crypto_sign_ed25519_sk_to_curve25519(nacl_sk)
    wg_pub = crypto_sign_ed25519_pk_to_curve25519(pub_raw)

    return Identity(
        ed25519_private_pem=priv_pem,
        ed25519_public_pem=pub_pem,
        wg_private_key_b64=base64.standard_b64encode(wg_priv).decode("ascii"),
        wg_public_key_b64=base64.standard_b64encode(wg_pub).decode("ascii"),
    )

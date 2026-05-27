"""gateway_auth - Ed25519 signature library for Portal Gateway authentication.

Contrato canonico (ver ../README.md raiz do repo):

    METHOD\\nPATH\\nUID\\nUNIX_TIMESTAMP_S\\nsha256:HEX_BODY_HASH

- METHOD: uppercase
- PATH: path interno (sem querystring, sem prefixo module-access)
- UID: string
- UNIX_TIMESTAMP_S: unix seconds, decimal sem zero-padding
- HEX_BODY_HASH: sha256 do body bruto, hex lowercase (body vazio = sha256 de "")

Signature: Ed25519, 64 bytes, encoded como hex lowercase (128 chars).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature as _CryptoInvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

__all__ = [
    "CanonicalInput",
    "canonical_payload",
    "sign",
    "verify",
    "parse_pubkey",
    "verify_with_pubkey",
    "InvalidSignature",
    "MissingRawBody",
    "TimestampOutOfWindow",
]

__version__ = "0.1.0"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class InvalidSignature(Exception):
    """Signature failed Ed25519 verification."""


class MissingRawBody(Exception):
    """Raw body was not preserved (downstream consumed it before middleware)."""


class TimestampOutOfWindow(Exception):
    """Request timestamp outside the allowed skew window."""


# ---------------------------------------------------------------------------
# Canonical payload
# ---------------------------------------------------------------------------


@dataclass
class CanonicalInput:
    """Input used to build the canonical payload.

    Attributes:
        method: HTTP method, will be uppercased internally.
        path: Internal path (no querystring, no module-access prefix).
        uid: Authenticated user id (string).
        timestamp: Unix timestamp in seconds.
        body: Raw request body bytes (empty bytes if no body).
    """

    method: str
    path: str
    uid: str
    timestamp: int
    body: bytes


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_payload(inp: CanonicalInput) -> bytes:
    """Build the canonical payload bytes that get fed into Ed25519.

    Format (literal LF separators, no trailing newline):

        METHOD\\nPATH\\nUID\\nUNIX_TIMESTAMP_S\\nsha256:HEX_BODY_HASH
    """
    body_hash = _sha256_hex(inp.body)
    payload = (
        f"{inp.method.upper()}\n"
        f"{inp.path}\n"
        f"{inp.uid}\n"
        f"{int(inp.timestamp)}\n"
        f"sha256:{body_hash}"
    )
    return payload.encode("utf-8")


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------


def _privkey_from_hex(privkey_hex: str) -> Ed25519PrivateKey:
    raw = bytes.fromhex(privkey_hex)
    if len(raw) != 32:
        raise ValueError(
            f"Ed25519 private key must be 32 bytes (got {len(raw)})"
        )
    return Ed25519PrivateKey.from_private_bytes(raw)


def _pubkey_from_hex(pubkey_hex: str) -> Ed25519PublicKey:
    raw = bytes.fromhex(pubkey_hex)
    if len(raw) != 32:
        raise ValueError(
            f"Ed25519 public key must be 32 bytes (got {len(raw)})"
        )
    return Ed25519PublicKey.from_public_bytes(raw)


# ---------------------------------------------------------------------------
# Sign / verify
# ---------------------------------------------------------------------------


def sign(privkey_hex: str, inp: CanonicalInput) -> str:
    """Sign the canonical payload with an Ed25519 private key.

    Returns the 64-byte signature encoded as hex lowercase (128 chars).
    """
    privkey = _privkey_from_hex(privkey_hex)
    payload = canonical_payload(inp)
    sig = privkey.sign(payload)
    return sig.hex()


def parse_pubkey(pubkey_hex: str) -> Ed25519PublicKey:
    """Parse a 32-byte Ed25519 public key from hex.

    Use this once at startup (e.g. in a middleware constructor) and pass the
    result to :func:`verify_with_pubkey` on every request — avoids re-parsing
    hex on each verification.

    Raises:
        ValueError: if hex is malformed or not 32 bytes.
    """
    return _pubkey_from_hex(pubkey_hex)


def verify_with_pubkey(
    pubkey: Ed25519PublicKey, signature_hex: str, inp: CanonicalInput
) -> bool:
    """Verify with a pre-parsed pubkey. Hot-path variant.

    Equivalent to :func:`verify` (pubkey_hex, ...) minus the per-call hex
    parse. Call :func:`parse_pubkey` once at startup and reuse the result.
    """
    try:
        signature = bytes.fromhex(signature_hex)
    except ValueError:
        return False
    if len(signature) != 64:
        return False
    payload = canonical_payload(inp)
    try:
        pubkey.verify(signature, payload)
        return True
    except _CryptoInvalidSignature:
        return False


def verify(pubkey_hex: str, signature_hex: str, inp: CanonicalInput) -> bool:
    """Verify an Ed25519 signature for the canonical payload.

    Returns True if valid, False otherwise. Does not raise on cryptographic
    mismatch (only on malformed key/signature input).

    For hot paths (HTTP middleware), prefer :func:`parse_pubkey` once +
    :func:`verify_with_pubkey` per request to avoid re-parsing pubkey hex
    on every call.
    """
    pubkey = _pubkey_from_hex(pubkey_hex)
    return verify_with_pubkey(pubkey, signature_hex, inp)

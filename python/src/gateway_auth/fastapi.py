"""Starlette/FastAPI ASGI middleware for gateway_auth.

Usage:

    from fastapi import FastAPI
    from gateway_auth.fastapi import GatewayAuthMiddleware, AuthMode

    app = FastAPI()
    app.add_middleware(
        GatewayAuthMiddleware,
        pubkey_hex=os.environ["GATEWAY_SIGNING_PUBKEY"],
        mode=AuthMode(os.environ.get("GATEWAY_AUTH_MODE", "off")),
    )
"""

from __future__ import annotations

import json
import logging
import re
import time
from enum import Enum
from typing import Awaitable, Callable, Optional

from . import CanonicalInput, parse_pubkey, verify_with_pubkey

__all__ = ["AuthMode", "GatewayAuthMiddleware"]


class AuthMode(str, Enum):
    OFF = "off"
    WARN = "warn"
    ENFORCE = "enforce"


# Headers (ASGI delivers them lowercased; we compare in lowercase)
HEADER_UID = b"x-gateway-user-id"
HEADER_TIMESTAMP = b"x-gateway-timestamp"
HEADER_SIGNATURE = b"x-gateway-signature"

# Strict numeric format — int() alone accepts whitespace, '+' prefix, etc.
# Match Node regex /^\d+$/ for cross-lang parity (see issue #3).
_TIMESTAMP_RE = re.compile(r"\d+")


class BodyTooLarge(Exception):
    """Request body exceeded the configured max_body_bytes limit."""


async def _read_body(
    receive: Callable[[], Awaitable[dict]], max_body_bytes: Optional[int] = None
) -> tuple[bytes, list[dict]]:
    """Consume the ASGI receive callable and concatenate the request body.

    Returns the body bytes plus the list of original messages so we can
    replay them downstream verbatim. This preserves streaming semantics
    (more_body flags, message boundaries) for the wrapped app.

    If max_body_bytes is set and the accumulated body would exceed it,
    raises BodyTooLarge before allocating further memory. Use this in
    public endpoints to avoid OOM from a hostile upload.
    """
    messages: list[dict] = []
    body = b""
    more_body = True
    while more_body:
        message = await receive()
        messages.append(message)
        if message["type"] == "http.request":
            chunk = message.get("body", b"") or b""
            if max_body_bytes is not None and len(body) + len(chunk) > max_body_bytes:
                raise BodyTooLarge(
                    f"request body exceeded max_body_bytes={max_body_bytes}"
                )
            body += chunk
            more_body = message.get("more_body", False)
        else:
            # http.disconnect or anything unexpected; stop draining
            more_body = False
    return body, messages


def _make_replay_receive(
    messages: list[dict],
) -> Callable[[], Awaitable[dict]]:
    """Build an ASGI receive callable that replays the captured messages."""
    iterator = iter(messages)

    async def receive() -> dict:
        try:
            return next(iterator)
        except StopIteration:
            # After replay, hang waiting for disconnect (matches ASGI contract).
            return {"type": "http.disconnect"}

    return receive


def _header_get(headers: list[tuple[bytes, bytes]], name: bytes) -> Optional[str]:
    for k, v in headers:
        if k.lower() == name:
            try:
                return v.decode("latin-1")
            except UnicodeDecodeError:
                return None
    return None


async def _send_401(send: Callable[[dict], Awaitable[None]], reason: str) -> None:
    body = json.dumps({"error": "invalid_gateway_signature", "reason": reason}).encode(
        "utf-8"
    )
    await send(
        {
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("latin-1")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


async def _send_413(send: Callable[[dict], Awaitable[None]], reason: str) -> None:
    body = json.dumps({"error": "payload_too_large", "reason": reason}).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("latin-1")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


class GatewayAuthMiddleware:
    """Pure ASGI middleware enforcing the Portal Gateway Ed25519 contract.

    Modes:
        - off: pass-through (validation disabled)
        - warn: validate; on failure log a warning and continue
        - enforce: validate; on failure respond 401

    Captures the raw body via ASGI receive and re-emits it downstream so
    the wrapped FastAPI endpoint still sees the original bytes.
    """

    def __init__(
        self,
        app,
        pubkey_hex: str,
        mode: AuthMode,
        max_skew_seconds: int = 60,
        max_body_bytes: Optional[int] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.app = app
        self.pubkey_hex = pubkey_hex
        self.mode = AuthMode(mode) if not isinstance(mode, AuthMode) else mode
        self.max_skew_seconds = max_skew_seconds
        self.max_body_bytes = max_body_bytes
        self.logger = logger or logging.getLogger("gateway_auth")
        # Parse pubkey once at startup; reused per request.
        # In off mode pubkey_hex may be empty — defer parsing until needed.
        self._pubkey = None
        if self.mode != AuthMode.OFF and self.pubkey_hex:
            self._pubkey = parse_pubkey(self.pubkey_hex)

    async def __call__(self, scope, receive, send):
        # Only intercept HTTP; pass websocket/lifespan untouched.
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        if self.mode == AuthMode.OFF:
            await self.app(scope, receive, send)
            return

        method: str = scope.get("method", "GET")
        path: str = scope.get("path", "/")
        headers: list[tuple[bytes, bytes]] = scope.get("headers", [])

        uid = _header_get(headers, HEADER_UID)
        ts_raw = _header_get(headers, HEADER_TIMESTAMP)
        sig = _header_get(headers, HEADER_SIGNATURE)

        # We need the raw body before we can validate, but we must replay it.
        try:
            body, captured = await _read_body(receive, self.max_body_bytes)
        except BodyTooLarge:
            reason = "body_too_large"
            extra = {
                "path": path,
                "method": method,
                "max_body_bytes": self.max_body_bytes,
            }
            if self.mode == AuthMode.WARN:
                self.logger.warning(
                    "gateway_auth: %s", reason, extra={"gateway_auth": extra}
                )
                # In warn we cannot replay (we aborted mid-read), so 413.
                await _send_413(send, reason)
                return
            await _send_413(send, reason)
            return
        replay_receive = _make_replay_receive(captured)

        # Missing headers -> fail per mode
        if uid is None or ts_raw is None or sig is None:
            reason = "missing_required_headers"
            extra = {
                "path": path,
                "method": method,
                "has_uid": uid is not None,
                "has_timestamp": ts_raw is not None,
                "has_signature": sig is not None,
            }
            if self.mode == AuthMode.WARN:
                self.logger.warning(
                    "gateway_auth: %s", reason, extra={"gateway_auth": extra}
                )
                await self.app(scope, replay_receive, send)
                return
            # enforce
            await _send_401(send, reason)
            return

        # Parse timestamp (strict: digits only, no whitespace, no sign — match Node)
        if not _TIMESTAMP_RE.fullmatch(ts_raw):
            reason = "invalid_timestamp_format"
            if self.mode == AuthMode.WARN:
                self.logger.warning(
                    "gateway_auth: %s",
                    reason,
                    extra={"gateway_auth": {"path": path, "ts_raw": ts_raw}},
                )
                await self.app(scope, replay_receive, send)
                return
            await _send_401(send, reason)
            return

        try:
            timestamp = int(ts_raw)
        except ValueError:
            # Defensive: regex already enforced digits-only, but keep as safety net.
            reason = "invalid_timestamp_format"
            if self.mode == AuthMode.WARN:
                self.logger.warning(
                    "gateway_auth: %s",
                    reason,
                    extra={"gateway_auth": {"path": path, "ts_raw": ts_raw}},
                )
                await self.app(scope, replay_receive, send)
                return
            await _send_401(send, reason)
            return

        # Skew window
        now = int(time.time())
        if abs(now - timestamp) > self.max_skew_seconds:
            reason = "timestamp_out_of_window"
            extra = {
                "path": path,
                "skew_seconds": now - timestamp,
                "max_skew_seconds": self.max_skew_seconds,
            }
            if self.mode == AuthMode.WARN:
                self.logger.warning(
                    "gateway_auth: %s", reason, extra={"gateway_auth": extra}
                )
                await self.app(scope, replay_receive, send)
                return
            await _send_401(send, reason)
            return

        # Verify signature
        inp = CanonicalInput(
            method=method,
            path=path,
            uid=uid,
            timestamp=timestamp,
            body=body,
        )
        try:
            ok = verify_with_pubkey(self._pubkey, sig, inp) if self._pubkey else False
        except ValueError:
            # Malformed signature hex
            ok = False

        if not ok:
            reason = "invalid_signature"
            extra = {
                "path": path,
                "method": method,
                "uid": uid,
                "timestamp": timestamp,
            }
            if self.mode == AuthMode.WARN:
                self.logger.warning(
                    "gateway_auth: %s", reason, extra={"gateway_auth": extra}
                )
                await self.app(scope, replay_receive, send)
                return
            await _send_401(send, reason)
            return

        # Valid: pass through with replayed body.
        await self.app(scope, replay_receive, send)

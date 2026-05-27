"""Smoke tests for the FastAPI/Starlette middleware.

Covers the three modes (off/warn/enforce), header parsing, body preservation,
and the timestamp skew window. Uses httpx + the in-process ASGI transport so
no real network is touched.
"""

from __future__ import annotations

import json
import logging
import time

import httpx
import pytest
from fastapi import FastAPI, Request

from gateway_auth import CanonicalInput, sign
from gateway_auth.fastapi import AuthMode, GatewayAuthMiddleware


# Test keys from fixtures/vectors.json (same shared test keys; never use in prod)
TEST_PRIVKEY = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
TEST_PUBKEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"


def _build_app(mode: AuthMode, pubkey: str = TEST_PUBKEY, **kwargs) -> FastAPI:
    app = FastAPI()

    @app.get("/echo")
    async def echo(request: Request):
        return {"method": request.method, "path": request.url.path}

    @app.post("/echo")
    async def echo_post(request: Request):
        # Read the body to confirm the middleware preserved it.
        raw = await request.body()
        try:
            payload = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            payload = {"_raw_hex": raw.hex()}
        return {
            "method": request.method,
            "path": request.url.path,
            "body_len": len(raw),
            "body": payload,
        }

    app.add_middleware(
        GatewayAuthMiddleware, pubkey_hex=pubkey, mode=mode, **kwargs
    )
    return app


def _client(app: FastAPI) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


def _sign_request(method: str, path: str, uid: str, timestamp: int, body: bytes) -> dict[str, str]:
    sig = sign(
        TEST_PRIVKEY,
        CanonicalInput(method=method, path=path, uid=uid, timestamp=timestamp, body=body),
    )
    return {
        "x-gateway-user-id": uid,
        "x-gateway-timestamp": str(timestamp),
        "x-gateway-signature": sig,
    }


@pytest.mark.asyncio
async def test_mode_off_passes_through_without_headers():
    app = _build_app(AuthMode.OFF)
    async with _client(app) as ac:
        r = await ac.get("/echo")
    assert r.status_code == 200
    assert r.json() == {"method": "GET", "path": "/echo"}


@pytest.mark.asyncio
async def test_mode_enforce_blocks_unsigned_request():
    app = _build_app(AuthMode.ENFORCE)
    async with _client(app) as ac:
        r = await ac.get("/echo")
    assert r.status_code == 401
    payload = r.json()
    assert payload["error"] == "invalid_gateway_signature"
    assert payload["reason"] == "missing_required_headers"


@pytest.mark.asyncio
async def test_mode_warn_logs_and_passes_through_unsigned(caplog):
    caplog.set_level(logging.WARNING, logger="gateway_auth")
    app = _build_app(AuthMode.WARN)
    async with _client(app) as ac:
        r = await ac.get("/echo")
    assert r.status_code == 200
    # Should have logged a warning about missing headers
    assert any(
        "missing_required_headers" in rec.getMessage() for rec in caplog.records
    )


@pytest.mark.asyncio
async def test_mode_enforce_accepts_valid_signature_get():
    app = _build_app(AuthMode.ENFORCE)
    ts = int(time.time())
    headers = _sign_request("GET", "/echo", "42", ts, b"")
    async with _client(app) as ac:
        r = await ac.get("/echo", headers=headers)
    assert r.status_code == 200
    assert r.json() == {"method": "GET", "path": "/echo"}


@pytest.mark.asyncio
async def test_mode_enforce_accepts_valid_signature_post_and_preserves_body():
    app = _build_app(AuthMode.ENFORCE)
    ts = int(time.time())
    body = json.dumps({"sku": "ABC123", "qty": 2}).encode("utf-8")
    headers = _sign_request("POST", "/echo", "42", ts, body)
    headers["content-type"] = "application/json"
    async with _client(app) as ac:
        r = await ac.post("/echo", content=body, headers=headers)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["method"] == "POST"
    assert data["body_len"] == len(body)
    assert data["body"] == {"sku": "ABC123", "qty": 2}


@pytest.mark.asyncio
async def test_mode_enforce_rejects_tampered_body():
    app = _build_app(AuthMode.ENFORCE)
    ts = int(time.time())
    body = b'{"sku":"ABC123","qty":2}'
    headers = _sign_request("POST", "/echo", "42", ts, body)
    headers["content-type"] = "application/json"
    # Send a different body than what was signed
    async with _client(app) as ac:
        r = await ac.post("/echo", content=b'{"sku":"XYZ","qty":99}', headers=headers)
    assert r.status_code == 401
    assert r.json()["reason"] == "invalid_signature"


@pytest.mark.asyncio
async def test_mode_enforce_rejects_out_of_window_timestamp():
    app = _build_app(AuthMode.ENFORCE, max_skew_seconds=60)
    ts = int(time.time()) - 3600  # 1h in the past
    headers = _sign_request("GET", "/echo", "42", ts, b"")
    async with _client(app) as ac:
        r = await ac.get("/echo", headers=headers)
    assert r.status_code == 401
    assert r.json()["reason"] == "timestamp_out_of_window"


@pytest.mark.asyncio
async def test_mode_warn_logs_and_passes_invalid_signature(caplog):
    caplog.set_level(logging.WARNING, logger="gateway_auth")
    app = _build_app(AuthMode.WARN)
    ts = int(time.time())
    headers = {
        "x-gateway-user-id": "42",
        "x-gateway-timestamp": str(ts),
        # 128 hex chars but not a real signature
        "x-gateway-signature": "00" * 64,
    }
    async with _client(app) as ac:
        r = await ac.get("/echo", headers=headers)
    assert r.status_code == 200
    assert any(
        "invalid_signature" in rec.getMessage() for rec in caplog.records
    )


@pytest.mark.asyncio
async def test_mode_enforce_rejects_invalid_timestamp_format():
    app = _build_app(AuthMode.ENFORCE)
    headers = {
        "x-gateway-user-id": "42",
        "x-gateway-timestamp": "not-a-number",
        "x-gateway-signature": "00" * 64,
    }
    async with _client(app) as ac:
        r = await ac.get("/echo", headers=headers)
    assert r.status_code == 401
    assert r.json()["reason"] == "invalid_timestamp_format"

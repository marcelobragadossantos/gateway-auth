"""Multi-pubkey: any trusted key may validate the gateway signature (v0.5.0)."""

from __future__ import annotations

import logging
import time

import httpx
import pytest
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI, Request

from gateway_auth import CanonicalInput, parse_pubkeys, sign
from gateway_auth.fastapi import AuthMode, GatewayAuthMiddleware


def _keypair() -> tuple[str, str]:
    k = Ed25519PrivateKey.generate()
    priv = k.private_bytes(ser.Encoding.Raw, ser.PrivateFormat.Raw, ser.NoEncryption())
    pub = k.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    return priv.hex(), pub.hex()


PRIV_A, PUB_A = _keypair()
PRIV_B, PUB_B = _keypair()
PRIV_X, PUB_X = _keypair()  # never listed


def _app(mode: AuthMode, pubkeys: str) -> FastAPI:
    app = FastAPI()

    @app.get("/who")
    async def who(request: Request):
        return {
            "principal": getattr(request.state, "gateway_principal", None),
            "key_id": getattr(request.state, "gateway_key_id", None),
        }

    app.add_middleware(GatewayAuthMiddleware, pubkey_hex=pubkeys, mode=mode)
    return app


def _headers(priv: str, uid: str = "42") -> dict[str, str]:
    ts = int(time.time())
    sig = sign(priv, CanonicalInput("GET", "/who", uid, ts, b""))
    return {
        "x-gateway-user-id": uid,
        "x-gateway-timestamp": str(ts),
        "x-gateway-signature": sig,
    }


async def _get(app, headers):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://t"
    ) as ac:
        return await ac.get("/who", headers=headers)


async def test_single_key_regression_principal_shape_unchanged():
    r = await _get(_app(AuthMode.ENFORCE, PUB_A), _headers(PRIV_A))
    assert r.status_code == 200
    assert r.json()["principal"] == {"kind": "user", "id": "42"}
    assert r.json()["key_id"] == PUB_A[:8]


async def test_two_keys_each_validates_and_reports_key_id():
    app = _app(AuthMode.ENFORCE, f"{PUB_A},{PUB_B}")
    ra = await _get(app, _headers(PRIV_A))
    rb = await _get(app, _headers(PRIV_B))
    assert ra.status_code == rb.status_code == 200
    assert ra.json()["key_id"] == PUB_A[:8]
    assert rb.json()["key_id"] == PUB_B[:8]
    assert rb.json()["principal"] == {"kind": "user", "id": "42"}


async def test_unlisted_key_rejected_enforce():
    r = await _get(_app(AuthMode.ENFORCE, f"{PUB_A},{PUB_B}"), _headers(PRIV_X))
    assert r.status_code == 401
    assert r.json()["reason"] == "invalid_signature"


async def test_unlisted_key_warn_has_no_principal(caplog):
    with caplog.at_level(logging.WARNING, logger="gateway_auth"):
        r = await _get(_app(AuthMode.WARN, f"{PUB_A},{PUB_B}"), _headers(PRIV_X))
    assert r.status_code == 200
    assert r.json() == {"principal": None, "key_id": None}
    assert "invalid_signature" in caplog.text


async def test_whitespace_newline_and_empty_items_tolerated():
    app = _app(AuthMode.ENFORCE, f" {PUB_A} ,\n\n, {PUB_B}\n,")
    assert (await _get(app, _headers(PRIV_B))).status_code == 200
    assert (await _get(app, _headers(PRIV_A))).status_code == 200


def test_malformed_key_in_list_fails_at_boot_without_leaking_value():
    bad = "zz" * 32
    with pytest.raises(ValueError, match="position 2 of 2") as ei:
        GatewayAuthMiddleware(None, pubkey_hex=f"{PUB_A},{bad}", mode=AuthMode.ENFORCE)
    assert bad not in str(ei.value)


def test_short_key_in_list_fails_at_boot():
    with pytest.raises(ValueError, match="position 1"):
        GatewayAuthMiddleware(None, pubkey_hex=f"abcd,{PUB_A}", mode=AuthMode.WARN)


def test_duplicate_key_fails_at_boot():
    with pytest.raises(ValueError, match="duplicate"):
        parse_pubkeys(f"{PUB_A},{PUB_A.upper()}")


def test_off_mode_does_not_parse_keys():
    GatewayAuthMiddleware(None, pubkey_hex="garbage", mode=AuthMode.OFF)

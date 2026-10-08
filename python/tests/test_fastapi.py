"""Smoke tests for the FastAPI/Starlette middleware.

Covers the three modes (off/warn/enforce), header parsing, body preservation,
and the timestamp skew window. Uses httpx + the in-process ASGI transport so
no real network is touched.
"""

from __future__ import annotations

import json
from pathlib import Path
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

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    @app.get("/whoami")
    async def whoami(request: Request):
        return {"principal": getattr(request.state, "gateway_principal", None)}

    @app.get("/api/health")
    async def api_health():
        return {"status": "ok"}

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
async def test_max_skew_seconds_from_env(monkeypatch):
    """Sem max_skew_seconds explícito, a janela vem de GATEWAY_MAX_SKEW_S —
    permite afrouxar p/ hosts com clock dessincronizado (NTP) sem mudar código."""
    monkeypatch.setenv("GATEWAY_MAX_SKEW_S", "600")
    app = _build_app(AuthMode.ENFORCE)  # nao passa max_skew_seconds
    ts = int(time.time()) - 300  # 5min no passado: fora dos 60s default, dentro de 600
    headers = _sign_request("GET", "/echo", "42", ts, b"")
    async with _client(app) as ac:
        r = await ac.get("/echo", headers=headers)
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_default_skew_60_when_env_unset(monkeypatch):
    monkeypatch.delenv("GATEWAY_MAX_SKEW_S", raising=False)
    app = _build_app(AuthMode.ENFORCE)
    ts = int(time.time()) - 300  # 5min: fora dos 60s default
    headers = _sign_request("GET", "/echo", "42", ts, b"")
    async with _client(app) as ac:
        r = await ac.get("/echo", headers=headers)
    assert r.status_code == 401
    assert r.json()["reason"] == "timestamp_out_of_window"


@pytest.mark.asyncio
async def test_explicit_skew_arg_overrides_env(monkeypatch):
    # Arg explícito tem precedência sobre a env.
    monkeypatch.setenv("GATEWAY_MAX_SKEW_S", "600")
    app = _build_app(AuthMode.ENFORCE, max_skew_seconds=60)
    ts = int(time.time()) - 300
    headers = _sign_request("GET", "/echo", "42", ts, b"")
    async with _client(app) as ac:
        r = await ac.get("/echo", headers=headers)
    assert r.status_code == 401


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


@pytest.mark.parametrize("path", ["/health", "/api/health"])
@pytest.mark.asyncio
async def test_enforce_exempts_default_health_paths(path):
    """Health/liveness probes carry no signature; enforce must let them through
    so the orchestrator's health check doesn't crash-loop the container."""
    app = _build_app(AuthMode.ENFORCE)
    async with _client(app) as ac:
        r = await ac.get(path)
    assert r.status_code == 200, r.text
    assert r.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_custom_exempt_paths_replace_default():
    # Custom set exempts /echo but NOT /health (default is replaced, not merged).
    app = _build_app(AuthMode.ENFORCE, exempt_paths={"/echo"})
    async with _client(app) as ac:
        r_echo = await ac.get("/echo")
        r_health = await ac.get("/health")
    assert r_echo.status_code == 200
    assert r_health.status_code == 401
    assert r_health.json()["reason"] == "missing_required_headers"


@pytest.mark.parametrize(
    "ts_value,label",
    [
        (" 1748390401 ", "whitespace"),
        ("+1748390401", "plus_sign"),
        ("1748390401abc", "trailing_junk"),
        ("-1748390401", "minus_sign"),
        ("1.748390401e9", "scientific_notation"),
    ],
)
@pytest.mark.asyncio
async def test_mode_enforce_rejects_non_canonical_timestamp(ts_value, label):
    """Cross-lang parity (issue #3): Node regex /^\\d+$/ rejects these,
    Python int() previously accepted whitespace, '+' sign, etc. — now strict."""
    app = _build_app(AuthMode.ENFORCE)
    headers = {
        "x-gateway-user-id": "42",
        "x-gateway-timestamp": ts_value,
        "x-gateway-signature": "00" * 64,
    }
    async with _client(app) as ac:
        r = await ac.get("/echo", headers=headers)
    assert r.status_code == 401, f"{label}: expected 401, got {r.status_code}"
    assert r.json()["reason"] == "invalid_timestamp_format", (
        f"{label}: expected invalid_timestamp_format, got {r.json()}"
    )


# ---------------------------------------------------------------------------
# Service principal (service_authenticator)
# ---------------------------------------------------------------------------

SERVICE_TOKEN = "s3rv1ce-t0ken-dedicated-and-strong"


def _service_auth(headers):
    """Sample authenticator: a fixed dedicated header == trusted service."""
    tok = headers.get("x-service-token")
    if tok and tok == SERVICE_TOKEN:
        return "svc:test-front-realtime"
    return None


@pytest.mark.asyncio
async def test_service_principal_bypasses_signature_in_enforce():
    app = _build_app(AuthMode.ENFORCE, service_authenticator=_service_auth)
    async with _client(app) as ac:
        r = await ac.get("/echo", headers={"x-service-token": SERVICE_TOKEN})
    assert r.status_code == 200
    assert r.json() == {"method": "GET", "path": "/echo"}


@pytest.mark.asyncio
async def test_service_principal_recorded_in_state():
    app = _build_app(AuthMode.ENFORCE, service_authenticator=_service_auth)
    async with _client(app) as ac:
        r = await ac.get("/whoami", headers={"x-service-token": SERVICE_TOKEN})
    assert r.status_code == 200
    assert r.json()["principal"] == {"kind": "service", "id": "svc:test-front-realtime"}


@pytest.mark.asyncio
async def test_user_principal_recorded_in_state():
    app = _build_app(AuthMode.ENFORCE)
    ts = int(time.time())
    headers = _sign_request("GET", "/whoami", "42", ts, b"")
    async with _client(app) as ac:
        r = await ac.get("/whoami", headers=headers)
    assert r.status_code == 200
    assert r.json()["principal"] == {"kind": "user", "id": "42"}


@pytest.mark.asyncio
async def test_invalid_service_token_does_not_bypass():
    # Wrong token -> authenticator returns None -> normal signature gate applies.
    app = _build_app(AuthMode.ENFORCE, service_authenticator=_service_auth)
    async with _client(app) as ac:
        r = await ac.get("/echo", headers={"x-service-token": "wrong"})
    assert r.status_code == 401
    assert r.json()["reason"] == "missing_required_headers"


@pytest.mark.asyncio
async def test_no_authenticator_is_unchanged_behavior():
    # Default (no service_authenticator): service header is meaningless, 401.
    app = _build_app(AuthMode.ENFORCE)
    async with _client(app) as ac:
        r = await ac.get("/echo", headers={"x-service-token": SERVICE_TOKEN})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_authenticator_exception_does_not_crash_request():
    def boom(headers):
        raise RuntimeError("authenticator blew up")

    app = _build_app(AuthMode.ENFORCE, service_authenticator=boom)
    async with _client(app) as ac:
        # No signature, authenticator raises -> falls through to 401 (not 500).
        r = await ac.get("/echo")
    assert r.status_code == 401
    assert r.json()["reason"] == "missing_required_headers"


@pytest.mark.asyncio
async def test_signature_still_works_with_authenticator_present():
    # A valid gateway signature must still authenticate as user even when a
    # service_authenticator is configured (signature path unaffected).
    app = _build_app(AuthMode.ENFORCE, service_authenticator=_service_auth)
    ts = int(time.time())
    headers = _sign_request("GET", "/whoami", "7", ts, b"")
    async with _client(app) as ac:
        r = await ac.get("/whoami", headers=headers)
    assert r.status_code == 200
    assert r.json()["principal"] == {"kind": "user", "id": "7"}


# --- Paridade de path percent-encoded com o portal / Node (fixtures cross-lang) ---

def _wire_path_cases() -> list[dict]:
    fixtures = json.loads(
        (Path(__file__).resolve().parents[2] / "fixtures" / "vectors.json").read_text(encoding="utf-8")
    )
    return fixtures["wire_path_cases"]


@pytest.mark.asyncio
@pytest.mark.parametrize("case", [c for c in _wire_path_cases() if c["name"] != "wire_malformed"], ids=lambda c: c["name"])
async def test_enforce_accepts_wire_encoded_path_signed_on_decoded(case):
    """ASGI entrega scope['path'] decodado: a mesma assinatura do vetor (path
    canonico) que o Node aceita com req.path encoded deve passar aqui."""
    app = FastAPI()

    @app.get("/{rest:path}")
    async def any_path(rest: str):
        return {"ok": True}

    app.add_middleware(GatewayAuthMiddleware, pubkey_hex=TEST_PUBKEY, mode=AuthMode.ENFORCE, max_skew_seconds=10**9)
    headers = {
        "x-gateway-user-id": case["input"]["uid"],
        "x-gateway-timestamp": str(case["input"]["timestamp"]),
        "x-gateway-signature": case["expected_signature_hex"],
    }
    async with _client(app) as ac:
        r = await ac.get(case["wire_path"], headers=headers)
    assert r.status_code == 200, r.text

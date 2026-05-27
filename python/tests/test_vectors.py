"""Cross-language test vectors validation.

Reads ../../fixtures/vectors.json and verifies that the Python implementation
produces and accepts the canonical payloads and Ed25519 signatures listed
there. Any divergence here means the libs (Python vs Node) have drifted from
the shared contract.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gateway_auth import CanonicalInput, canonical_payload, sign, verify


FIXTURES_PATH = (
    Path(__file__).resolve().parents[2] / "fixtures" / "vectors.json"
)


def _load_fixtures() -> dict:
    assert FIXTURES_PATH.exists(), f"vectors.json missing at {FIXTURES_PATH}"
    return json.loads(FIXTURES_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def fixtures() -> dict:
    return _load_fixtures()


@pytest.fixture(scope="module")
def cases(fixtures) -> list[dict]:
    return fixtures["cases"]


@pytest.fixture(scope="module")
def keys(fixtures) -> dict:
    return fixtures["test_keys"]


def _make_input(case: dict) -> CanonicalInput:
    inp = case["input"]
    body_hex = inp["body_hex"]
    body = bytes.fromhex(body_hex) if body_hex else b""
    return CanonicalInput(
        method=inp["method"],
        path=inp["path"],
        uid=inp["uid"],
        timestamp=inp["timestamp"],
        body=body,
    )


def test_fixtures_metadata(fixtures):
    assert fixtures["algorithm"] == "Ed25519"
    assert fixtures["encoding"] == "hex-lowercase"
    assert len(fixtures["cases"]) >= 3


def test_canonical_payload_matches_hex(cases):
    for case in cases:
        inp = _make_input(case)
        produced = canonical_payload(inp).hex()
        assert produced == case["canonical_payload_hex"], (
            f"canonical_payload diverged for case '{case['name']}'\n"
            f"  expected: {case['canonical_payload_hex']}\n"
            f"  got:      {produced}"
        )


def test_canonical_payload_matches_utf8(cases):
    for case in cases:
        inp = _make_input(case)
        produced = canonical_payload(inp).decode("utf-8")
        assert produced == case["canonical_payload_utf8"], (
            f"canonical_payload utf8 diverged for case '{case['name']}'"
        )


def test_sign_matches_expected_signature(cases, keys):
    privkey = keys["privkey_hex"]
    for case in cases:
        inp = _make_input(case)
        produced = sign(privkey, inp)
        assert produced == case["expected_signature_hex"], (
            f"signature diverged for case '{case['name']}'\n"
            f"  expected: {case['expected_signature_hex']}\n"
            f"  got:      {produced}"
        )


def test_verify_accepts_expected_signature(cases, keys):
    pubkey = keys["pubkey_hex"]
    for case in cases:
        inp = _make_input(case)
        assert verify(pubkey, case["expected_signature_hex"], inp) is True, (
            f"verify rejected valid signature for case '{case['name']}'"
        )


def test_verify_detects_body_tamper(cases, keys):
    pubkey = keys["pubkey_hex"]
    for case in cases:
        inp = _make_input(case)
        # Tamper: flip one byte (or add a byte when body is empty).
        if inp.body:
            tampered = bytearray(inp.body)
            tampered[0] ^= 0x01
            tampered_bytes = bytes(tampered)
        else:
            tampered_bytes = b"\x00"
        tampered_inp = CanonicalInput(
            method=inp.method,
            path=inp.path,
            uid=inp.uid,
            timestamp=inp.timestamp,
            body=tampered_bytes,
        )
        assert (
            verify(pubkey, case["expected_signature_hex"], tampered_inp) is False
        ), f"verify accepted tampered body for case '{case['name']}'"


def test_verify_detects_timestamp_tamper(cases, keys):
    pubkey = keys["pubkey_hex"]
    for case in cases:
        inp = _make_input(case)
        tampered_inp = CanonicalInput(
            method=inp.method,
            path=inp.path,
            uid=inp.uid,
            timestamp=inp.timestamp + 1,
            body=inp.body,
        )
        assert (
            verify(pubkey, case["expected_signature_hex"], tampered_inp) is False
        ), f"verify accepted tampered timestamp for case '{case['name']}'"


def test_verify_detects_method_tamper(cases, keys):
    pubkey = keys["pubkey_hex"]
    for case in cases:
        inp = _make_input(case)
        # Swap method to something else.
        new_method = "PATCH" if inp.method != "PATCH" else "DELETE"
        tampered_inp = CanonicalInput(
            method=new_method,
            path=inp.path,
            uid=inp.uid,
            timestamp=inp.timestamp,
            body=inp.body,
        )
        assert (
            verify(pubkey, case["expected_signature_hex"], tampered_inp) is False
        )


def test_verify_detects_path_tamper(cases, keys):
    pubkey = keys["pubkey_hex"]
    for case in cases:
        inp = _make_input(case)
        tampered_inp = CanonicalInput(
            method=inp.method,
            path=inp.path + "/extra",
            uid=inp.uid,
            timestamp=inp.timestamp,
            body=inp.body,
        )
        assert (
            verify(pubkey, case["expected_signature_hex"], tampered_inp) is False
        )


def test_verify_rejects_malformed_signature(cases, keys):
    pubkey = keys["pubkey_hex"]
    case = cases[0]
    inp = _make_input(case)
    # Too short
    assert verify(pubkey, "deadbeef", inp) is False
    # Not hex
    assert verify(pubkey, "zzzz" * 32, inp) is False


def test_method_is_uppercased(keys):
    """Lowercase method input must produce the same signature as uppercase."""
    inp_lower = CanonicalInput(
        method="get",
        path="/v1/users/me",
        uid="42",
        timestamp=1748390400,
        body=b"",
    )
    inp_upper = CanonicalInput(
        method="GET",
        path="/v1/users/me",
        uid="42",
        timestamp=1748390400,
        body=b"",
    )
    assert sign(keys["privkey_hex"], inp_lower) == sign(
        keys["privkey_hex"], inp_upper
    )

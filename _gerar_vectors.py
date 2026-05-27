"""Gera fixtures/vectors.json com casos canonicos + signatures Ed25519 reais.

Usa privkey fixa de teste (NUNCA em prod). Pubkey derivada da mesma.
Roda uma vez, commitar saida. Script fica no repo so como referencia.
"""
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives import serialization


TEST_PRIVKEY_HEX = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"

priv_bytes = bytes.fromhex(TEST_PRIVKEY_HEX)
priv = Ed25519PrivateKey.from_private_bytes(priv_bytes)
pub = priv.public_key()
pub_hex = pub.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
).hex()


def canonical_payload(method: str, path: str, uid: str, ts: int, body: bytes) -> bytes:
    body_hash = hashlib.sha256(body).hexdigest()
    return f"{method}\n{path}\n{uid}\n{ts}\nsha256:{body_hash}".encode("utf-8")


def make_case(name: str, description: str, method: str, path: str, uid: str, ts: int, body: bytes):
    payload = canonical_payload(method, path, uid, ts, body)
    signature = priv.sign(payload).hex()
    return {
        "name": name,
        "description": description,
        "input": {
            "method": method,
            "path": path,
            "uid": uid,
            "timestamp": ts,
            "body_hex": body.hex(),
        },
        "canonical_payload_utf8": payload.decode("utf-8"),
        "canonical_payload_hex": payload.hex(),
        "expected_signature_hex": signature,
    }


cases = [
    make_case(
        name="get_no_body",
        description="GET sem body. Body hash = SHA-256 de string vazia.",
        method="GET",
        path="/v1/users/me",
        uid="42",
        ts=1748390400,
        body=b"",
    ),
    make_case(
        name="post_json_body",
        description="POST com body JSON. Body bytes sao os exatos enviados ao back.",
        method="POST",
        path="/v1/orders",
        uid="42",
        ts=1748390401,
        body=b'{"sku":"ABC123","qty":2}',
    ),
    make_case(
        name="put_after_api_strip",
        description="PUT em path APOS o strip de /api do Express front. Demonstra que path canonico = path que chega no back final.",
        method="PUT",
        path="/relatorios/2026-05",
        uid="9",
        ts=1748390402,
        body=b'{"status":"closed"}',
    ),
]

output = {
    "version": "1",
    "algorithm": "Ed25519",
    "encoding": "hex-lowercase",
    "test_keys": {
        "_warning": "TEST KEYS ONLY. Nunca usar em producao. Para producao, gerar par novo (ver README).",
        "privkey_hex": TEST_PRIVKEY_HEX,
        "pubkey_hex": pub_hex,
    },
    "canonical_payload_format": "METHOD\\nPATH\\nUID\\nUNIX_TIMESTAMP_S\\nsha256:HEX_BODY_HASH",
    "cases": cases,
}

out_path = Path(__file__).parent / "fixtures" / "vectors.json"
out_path.parent.mkdir(parents=True, exist_ok=True)
out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

print(f"OK: {out_path}")
print(f"PUBKEY: {pub_hex}")
print(f"Casos gerados: {len(cases)}")
for c in cases:
    print(f"  - {c['name']}: sig={c['expected_signature_hex'][:32]}...")

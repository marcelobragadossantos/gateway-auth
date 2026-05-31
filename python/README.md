# gateway_auth (Python)

Lib Python de assinatura **Ed25519** para autenticacao de requisicoes do **Portal Gateway** (Opcao A do projeto de unificacao de auth Hiperfarma).

Contrato canonico (METHOD, PATH, UID, timestamp e sha256 do body) esta documentado no [README raiz](../README.md). Vetores de teste cross-lang em [`../fixtures/vectors.json`](../fixtures/vectors.json) — qualquer divergencia entre as libs Node e Python explode `tests/test_vectors.py`.

---

## Instalacao

```bash
pip install "gateway-auth @ git+https://github.com/marcelobragadossantos/gateway-auth.git@v0.1.0#subdirectory=python"
```

Para o middleware FastAPI/Starlette, instale o extra:

```bash
pip install "gateway-auth[fastapi] @ git+https://github.com/marcelobragadossantos/gateway-auth.git@v0.1.0#subdirectory=python"
```

Em dev local (dentro deste repo):

```bash
pip install -e .[test,fastapi]
pytest
```

Requer Python >= 3.10.

---

## API

### `CanonicalInput`

```python
from gateway_auth import CanonicalInput

inp = CanonicalInput(
    method="POST",        # uppercase aplicado internamente
    path="/v1/orders",    # path interno (sem querystring, sem prefixo module-access)
    uid="42",             # string
    timestamp=1748390401, # unix seconds
    body=b'{"sku":"ABC"}',
)
```

### `canonical_payload(inp) -> bytes`

Retorna os bytes UTF-8 do payload canonico:

```
METHOD\nPATH\nUID\nUNIX_TIMESTAMP_S\nsha256:HEX_BODY_HASH
```

(sem trailing newline, separador literal `\n` = LF 0x0A).

### `sign(privkey_hex, inp) -> str`

Assina com Ed25519. Retorna a signature em **hex lowercase** (128 chars / 64 bytes).

```python
from gateway_auth import sign

sig = sign("9d61b19d...7f60", inp)
# "4551458409f3e799..."
```

### `verify(pubkey_hex, signature_hex, inp) -> bool`

Verifica. Retorna `True`/`False`, nao levanta excecao em mismatch criptografico. So levanta `ValueError` em chave mal formatada (tamanho errado, hex invalido).

```python
from gateway_auth import verify

ok = verify("d75a9801...511a", sig, inp)
```

### Excecoes

- `InvalidSignature` — signature falhou verificacao Ed25519
- `MissingRawBody` — body bruto nao foi preservado (downstream consumiu antes do middleware)
- `TimestampOutOfWindow` — timestamp fora da janela de skew

(O middleware nao levanta essas excecoes — ele converte em 401 ou log. As classes existem pro usuario reaproveitar em codigo proprio.)

---

## Exemplo standalone

```python
from gateway_auth import CanonicalInput, sign, verify

PRIV = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
PUB  = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"

inp = CanonicalInput(
    method="GET",
    path="/v1/users/me",
    uid="42",
    timestamp=1748390400,
    body=b"",
)

sig = sign(PRIV, inp)
assert verify(PUB, sig, inp) is True

# Tampering muda o resultado
tampered = CanonicalInput(**{**inp.__dict__, "uid": "43"})
assert verify(PUB, sig, tampered) is False
```

---

## Integracao FastAPI / Starlette

```python
import os
from fastapi import FastAPI
from gateway_auth.fastapi import GatewayAuthMiddleware, AuthMode

app = FastAPI()

app.add_middleware(
    GatewayAuthMiddleware,
    pubkey_hex=os.environ["GATEWAY_SIGNING_PUBKEY"],
    mode=AuthMode(os.environ.get("GATEWAY_AUTH_MODE", "off")),
    max_skew_seconds=60,
)
```

### Modos

| Modo | Comportamento |
|---|---|
| `off` | Middleware nao valida nada (pass-through). Use em deploy inicial. |
| `warn` | Valida. Em falha, loga `warning` (logger `gateway_auth`) e deixa passar. |
| `enforce` | Valida. Em falha, retorna `401 {"error": "invalid_gateway_signature", "reason": "..."}`. |

### Comportamento interno

- Le os headers `x-gateway-user-id`, `x-gateway-timestamp`, `x-gateway-signature` (case-insensitive — ASGI ja entrega lowercase).
- **Captura o body bruto via ASGI receive** e re-emite pro downstream. O endpoint FastAPI continua vendo os bytes originais (`await request.body()` funciona normalmente).
- Janela anti-replay: `abs(now - timestamp) <= max_skew_seconds` (default 60s).
- Headers ausentes em `enforce` → 401 com `reason=missing_required_headers`.
- Timestamp nao-numerico → 401 com `reason=invalid_timestamp_format`.
- Timestamp fora da janela → 401 com `reason=timestamp_out_of_window`.
- Signature invalida → 401 com `reason=invalid_signature`.
- Scope nao-HTTP (websocket, lifespan) passa direto sem inspecao.

### Principal de servico (`service_authenticator`) — v0.4.0

Chamadas **server-to-server** (cron, webhook, jobs) nao tem usuario e — na Opcao A, com a privkey **so no gateway** — nao tem como assinar. Pra elas passarem em `enforce` sem afrouxar a verificacao de identidade do browser, passe um `service_authenticator`: um callable que recebe os headers (dict, chaves lowercase) e retorna um **id de servico** (str truthy) quando reconhece um chamador confiavel — tipicamente um **token de servico dedicado**.

```python
import hmac, os
from gateway_auth.fastapi import GatewayAuthMiddleware, AuthMode

SERVICE_TOKEN = os.environ["GATEWAY_SERVICE_TOKEN"]  # dedicado, forte, rotacionavel

def service_auth(headers):
    tok = headers.get("x-service-token")
    if tok and hmac.compare_digest(tok, SERVICE_TOKEN):
        return "svc:meu-front"   # id do servico (sem identidade de usuario)
    return None

app.add_middleware(
    GatewayAuthMiddleware,
    pubkey_hex=os.environ["GATEWAY_SIGNING_PUBKEY"],
    mode=AuthMode(os.environ.get("GATEWAY_AUTH_MODE", "off")),
    service_authenticator=service_auth,   # None (default) = feature desligada
)
```

Quando o authenticator retorna um id, o request **pula a verificacao de assinatura** e segue como principal de servico. Regras:

- **`None` por default** → comportamento identico ao anterior (zero breaking change pros backs que nao usam).
- O principal resolvido fica em `request.state.gateway_principal` = `{"kind": "user"|"service", "id": ...}`. Use pra escopar permissao (servico **nunca** vira usuario; gates de admin que exigem prova de `uid` **nao** sao satisfeitos por servico).
- Use um **segredo dedicado** (nao um segredo de canal reusado) e **nao o envie no caminho do browser** — senao o exempt reabre o bypass de assinatura que o `enforce` existe pra fechar.
- Excecao no authenticator nunca derruba o request (cai pro fluxo normal de assinatura).

### Logger

Default: `logging.getLogger("gateway_auth")`. Em `warn`, cada falha vira um `logger.warning(...)` com campo `extra={"gateway_auth": {...}}` carregando path, method, uid, motivo. Compativel com formatters JSON estruturados.

Voce pode passar um logger proprio:

```python
import logging
logger = logging.getLogger("meu_app.auth_gateway")

app.add_middleware(
    GatewayAuthMiddleware,
    pubkey_hex=...,
    mode=AuthMode.WARN,
    logger=logger,
)
```

---

## Rodar testes

```bash
cd python
python -m venv .venv
.venv\Scripts\activate           # Windows
# source .venv/bin/activate      # Linux/Mac
pip install -e .[test,fastapi]
pytest
```

Os testes em `tests/test_vectors.py` cobrem:

- `canonical_payload(...).hex()` == `case.canonical_payload_hex`
- `sign(privkey, inp)` == `case.expected_signature_hex` (exato)
- `verify(pubkey, expected_sig, inp)` retorna `True`
- Tamper em body / timestamp / method / path → `verify` retorna `False`
- Signature mal-formada → `verify` retorna `False` sem raise

Os testes em `tests/test_fastapi.py` cobrem os 3 modos (off/warn/enforce), preservacao do body raw, janela de skew e logging em modo warn.

---

## Versao

`0.4.0` — `service_authenticator` (principal de servico) + `request.state.gateway_principal`. Antes: `0.3.1` (janela de skew via env `GATEWAY_MAX_SKEW_S`). Roadmap completo no [README raiz](../README.md#roadmap).

---

## Referencias

- Contrato canonico Ed25519: [`../README.md`](../README.md)
- Fixtures cross-lang: [`../fixtures/vectors.json`](../fixtures/vectors.json)
- Lib criptografica: [`cryptography`](https://cryptography.io/) (PyCA, Ed25519 nativo)

# @grupohiperfarma/gateway-auth-node

Node/TypeScript implementation of the **Portal Gateway** Ed25519 request-signing contract (Hiperfarma Opção A).

Contract canônico: ver [README do repo](../README.md). Vetores de teste cross-lang: [`../fixtures/vectors.json`](../fixtures/vectors.json).

> v0.1.0 — Fase 0. Pacote privado, distribuído por tag GitHub (não publicado no npm público).

---

## Instalação

```bash
npm install github:marcelobragadossantos/gateway-auth#v0.1.0 --workspaces=node
```

Sempre pinar por tag (`v0.1.0`, `v0.2.0`, ...). Nunca `main`.

---

## API standalone

```ts
import { sign, verify, canonicalPayload } from '@grupohiperfarma/gateway-auth-node';

const PRIV = process.env.GATEWAY_SIGNING_PRIVKEY!;   // 64 hex chars (32 bytes)
const PUB  = process.env.GATEWAY_SIGNING_PUBKEY!;    // 64 hex chars (32 bytes)

const input = {
  method: 'POST',
  path: '/v1/orders',                                 // path interno (já strippado)
  uid: '42',
  timestamp: Math.floor(Date.now() / 1000),
  body: Buffer.from('{"sku":"ABC","qty":2}', 'utf8'), // bytes brutos, NÃO restringify
};

const sig = sign(PRIV, input);                        // -> hex lowercase, 128 chars
const ok  = verify(PUB, sig, input);                  // -> boolean

// Bytes que serão assinados (debug / interop testing):
const payload = canonicalPayload(input);              // -> Buffer
```

### `CanonicalInput`

| Campo | Tipo | Obs |
|---|---|---|
| `method` | `string` | uppercased internamente |
| `path` | `string` | path interno, sem querystring, sem prefixo `/api` ou `module-access/<token>` |
| `uid` | `string` | id do user autenticado no gateway |
| `timestamp` | `number` | unix **seconds** (não ms), inteiro |
| `body` | `Buffer \| Uint8Array \| string` | bytes brutos; string vira UTF-8 |

### Erros

`GatewayAuthError` (com `code`) é lançado só pra inputs malformados (`invalid_input`, `invalid_key`, `invalid_hex`). Assinatura inválida nunca lança — `verify` retorna `false`.

---

## Middleware Express

Entrada secundária: `@grupohiperfarma/gateway-auth-node/express`.

```ts
import express from 'express';
import { gatewayAuthMiddleware } from '@grupohiperfarma/gateway-auth-node/express';

const app = express();

// 1. Capturar o body bruto ANTES de qualquer parse.
app.use(express.raw({ type: '*/*' }));

// 2. Expor como req.rawBody (express.raw seta req.body como Buffer).
app.use((req, _res, next) => {
  (req as any).rawBody = req.body;
  next();
});

// 3. Validar.
app.use(gatewayAuthMiddleware({
  pubkeyHex: process.env.GATEWAY_SIGNING_PUBKEY!,
  mode: (process.env.GATEWAY_AUTH_MODE ?? 'off') as 'off' | 'warn' | 'enforce',
  maxSkewSeconds: 60,
}));

// 4. AGORA parsear JSON pros handlers (sem destruir o rawBody capturado acima).
app.use(express.json());

app.post('/v1/orders', (req, res) => { /* ... */ });
```

> **Importante**: `req.rawBody` precisa conter **exatamente os bytes que o gateway assinou**. Se você usar `express.json()` antes do middleware, ele faz parse + restringify e o hash diverge. Sempre capture os bytes brutos primeiro.

### Opções

```ts
interface ExpressMiddlewareOptions {
  pubkeyHex: string;            // 32-byte Ed25519 pubkey, hex lowercase
  mode: 'off' | 'warn' | 'enforce';
  maxSkewSeconds?: number;      // default 60
  logger?: { warn(msg, ctx?) };
  now?: () => number;           // unix seconds, override pra testes
}
```

### Modos

| Modo | Comportamento |
|---|---|
| `off` | Passa direto. Útil pra primeiro deploy só pra confirmar que sobe limpo. |
| `warn` | Valida. Em falha, `logger.warn(...)` e segue (`next()`). Observação de 48h sem quebrar tráfego. |
| `enforce` | Valida. Em qualquer falha -> `401 { error: 'invalid_gateway_signature', reason: '<motivo>' }` (shape uniforme com a lib Python). `reason` ∈ `missing_raw_body | missing_gateway_headers | invalid_timestamp | timestamp_outside_window | invalid_signature`. |

`mode=off` ignora `pubkeyHex` (pode passar string vazia). `mode=warn|enforce` exige `pubkeyHex` válido — **64 chars hex** (32 bytes Ed25519 pubkey). Comprimento/encoding errado faz o construtor lançar imediatamente (em vez de virar 401 silencioso em runtime).

Rollback de produção: `GATEWAY_AUTH_MODE=warn` ou `off`, restart do container (~10s).

---

## Por que `req.rawBody` (não `req.body`)?

Body parsers (`express.json`, `body-parser`) parseiam e re-stringificam o body. Mesmo um `JSON.stringify(JSON.parse(x))` reordena chaves e remove espaços — qualquer mudança quebra o SHA-256 do payload canônico. A lib **exige** acesso aos bytes brutos exatos que saíram do gateway.

Se você já tem outro middleware capturando rawBody (helmet, csurf, etc), só garanta que `req.rawBody` seja um `Buffer` antes deste middleware.

---

## Geração de chaves

Single source of truth no [README raiz](../README.md#chaves). Resumo:

- 32 bytes priv + 32 bytes pub
- Encoding hex lowercase
- Gateway guarda priv (`GATEWAY_SIGNING_PRIVKEY`, secret)
- Cada back guarda pub (`GATEWAY_SIGNING_PUBKEY`, não-secret)

---

## Testes

```bash
cd node
npm install
npm test
```

`test/vectors.test.ts` valida os 3 casos de [`fixtures/vectors.json`](../fixtures/vectors.json) cross-lang:

1. Bytes do `canonicalPayload` batem exatamente (hex e UTF-8)
2. `sign()` produz a `expected_signature_hex` exata (determinismo Ed25519 / RFC 8032)
3. `verify()` aceita a signature esperada
4. Tamper de body / timestamp / method / path -> `verify` retorna `false`

`test/express.test.ts` cobre os 3 modos do middleware + integração end-to-end com `express.raw`.

---

## Decisões de design

- **`@noble/ed25519` v2 (sync)**: zero deps, auditada. v2 expõe `ed.sign` síncrono — Ed25519 é determinístico por especificação (RFC 8032), então não há diferença observável vs. async. Hash SHA-512 é injetado via `@noble/hashes` (requisito da v2).
- **SHA-256 via `node:crypto`**: hash do body roda em código nativo do Node, ~ordem de grandeza mais rápido que JS puro.
- **`verify` retorna `boolean`, não throws**: signature inválida é um caso de runtime, não uma exception. Inputs malformados (path vazio, timestamp não-int) ainda lançam `GatewayAuthError`.
- **`canonicalPayload` é export público**: facilita debug interop com Python — você pode imprimir os bytes exatos que vão pra Ed25519 nos dois lados e bisect onde diverge.

---

## Roadmap

Ver [README raiz](../README.md#roadmap). v0.2.0 adiciona pubkey overlap pra rotação e cache anti-replay opcional.

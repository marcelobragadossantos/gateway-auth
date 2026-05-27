# gateway-auth

Lib de assinatura **Ed25519** para autenticação de requisições do **Portal Gateway** (Opção A do projeto de unificação de auth Hiperfarma).

Repo único, multi-linguagem. Backs (Node e Python) consomem a lib correspondente. Vetor de testes compartilhado garante interoperabilidade.

> **Estado**: contrato em formalização (Fase 0). Libs Node/Python entram em PRs separados antes da tag `v0.1.0`.

---

## Por que Ed25519 (e não HMAC)

A primeira versão da Opção A previa HMAC-SHA256 com segredo compartilhado entre gateway e backs. Foi trocada por assinatura assimétrica Ed25519 em 2026-05-27 pelos motivos:

- **Backs guardam só chave pública** — leak de env/log de back não compromete nada
- **Sem lateral movement** — back invadido não consegue forjar requests pros outros backs (só valida, não assina)
- **Rotação trivial** — gateway gera novo par, distribui pubkey nova. Backs trocam env de forma independente

Trade-off aceito: lib é um pouco mais complexa (curva Ed25519 vs HMAC), mas a complexidade fica num lugar só.

---

## Contrato canônico

### Payload assinado

```
METHOD\nPATH_INTERNO\nUID\nUNIX_TIMESTAMP_S\nsha256:HEX_BODY_HASH
```

Concatenação literal com `\n` (LF, 0x0A) como separador. Sem trailing newline.

Campos:

| Campo | Definição |
|---|---|
| `METHOD` | Método HTTP em **uppercase** (`GET`, `POST`, ...) |
| `PATH_INTERNO` | Path **que sai do gateway** rumo ao back. Sem querystring. Sem prefixo de `module-access/<token>/`. Se houver Express front que faz strip de `/api`, este path é o **já strippado**, ou seja, o que o serviço final processa. |
| `UID` | ID do usuário autenticado no gateway (string) |
| `UNIX_TIMESTAMP_S` | Unix timestamp em **segundos** (não ms), decimal sem zero-padding |
| `HEX_BODY_HASH` | SHA-256 do body bruto (bytes), hex **lowercase**. Para body vazio: SHA-256 de string vazia (`e3b0c44...b855`) |

### Headers enviados pelo gateway ao back

```
x-gateway-user-id: <uid>
x-gateway-timestamp: <unix-seconds>
x-gateway-signature: <ed25519-hex-lowercase>
```

Signature: 64 bytes (Ed25519) → 128 chars hex lowercase.

### Regras de implementação

- **Path canônico = path no momento da entrega ao back.** Gateway sabe o path final; back valida contra o path que recebeu. Qualquer Express intermediário **não pode** reescrever path sem que gateway+back concordem.
- **Body bruto: bytes idênticos do gateway até o back.** Sem parse e re-stringify. Express intermediário usa `req.pipe(proxyReq)` (ver pré-requisitos por back no doc de Opção A).
- **Headers preservados:** os 3 chegam intactos até o back final.
- **Anti-replay:** janela de ±60s entre `UNIX_TIMESTAMP_S` e horário do back. Fora da janela → reject.
- **Encoding da signature:** hex lowercase. **Não** base64.
- **Body hash:** sempre presente, mesmo quando body é vazio.

### Anti-replay v2 (não obrigatório no v0.1.0)

Cache `(uid, timestamp)` por 120s pra impedir replay dentro da janela. Implementação fica a cargo do back (Redis, in-memory LRU, etc.). Em v0.1.0 a defesa é só a janela de tempo.

---

## Chaves

Par Ed25519: 32 bytes privada + 32 bytes pública. Encoding hex lowercase.

Geração (qualquer lado, basta uma vez):

```bash
# Python (cryptography)
python -c "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey; from cryptography.hazmat.primitives import serialization; k = Ed25519PrivateKey.generate(); priv = k.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption()); pub = k.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw); print('PRIV:', priv.hex()); print('PUB :', pub.hex())"
```

Distribuição:
- **Gateway**: env `GATEWAY_SIGNING_PRIVKEY` (32 bytes hex, secret)
- **Cada back**: env `GATEWAY_SIGNING_PUBKEY` (32 bytes hex, **não é secret**)

### Rotação

1. Gateway gera novo par
2. Backs aceitam **as duas pubkeys** por um período (env `GATEWAY_SIGNING_PUBKEY_NEXT` opcional, validar com qualquer das duas)
3. Gateway começa a assinar com a nova
4. Backs removem a antiga depois de janela de overlap

v0.1.0 só prevê 1 pubkey por back. Overlap fica pra v0.2.0 quando precisar.

---

## Modos de enforcement

Env por back: `GATEWAY_AUTH_MODE = off | warn | enforce`

| Modo | Comportamento |
|---|---|
| `off` | Ignora signature. Lib não roda. Usado em deploy inicial só pra confirmar que a integração subiu sem quebrar. |
| `warn` | Valida signature. Em falha, **loga** com nível WARN e **deixa passar**. Janela de 48h de observação. |
| `enforce` | Valida signature. Em falha, **rejeita com 401**. |

Workflow padrão pra cada back:

```
1. PR no back integrando a lib (deploy em mode=off, valida que sobe limpo)
2. Trocar pra mode=warn (Easypanel restart, sem deploy). 48h de observação
3. Confirmar 0 falhas em warn → trocar pra mode=enforce
4. Rollback = env de volta pra warn ou off em ~10s
```

Gateway começa a emitir signature pra **todos** os backs desde a Fase 2 — cada back decide quando validar. Migrações são independentes, sem coordenação cruzada.

---

## Estrutura do repo

```
gateway-auth/
├── node/                 ← @grupohiperfarma/gateway-auth-node (npm/Node lib)
├── python/               ← gateway_auth (pyproject.toml, pip lib)
├── fixtures/
│   └── vectors.json      ← vetores cross-lang (caso + chaves + signature esperada)
└── README.md             ← este arquivo
```

Novas stacks (Go, Rust, ...) viram novo subdirectory com mesmo `fixtures/vectors.json` como contrato de teste.

---

## Consumo

### Python

```bash
pip install "gateway-auth @ git+https://github.com/marcelobragadossantos/gateway-auth.git@v0.1.0#subdirectory=python"
```

### Node

```bash
npm install github:marcelobragadossantos/gateway-auth#v0.1.0 --workspaces=node
```

Ou via tarball anexado à GitHub Release.

**Sempre pinar por tag** (`v0.1.0`, `v0.2.0`, ...). Nunca `main`.

---

## Testes cross-lang

`fixtures/vectors.json` lista casos canônicos com chaves de teste e signature esperada. Cada lib valida:

1. **Gerar**: dadas as inputs do vetor, a signature produzida bate com `expected_signature`
2. **Validar**: dadas as inputs + a `expected_signature`, a verificação passa
3. **Detectar tamper**: trocar 1 char do body → verificação falha

CI roda os dois lados (Node gera, Python valida; Python gera, Node valida). Garante que o algoritmo não diverge entre stacks.

---

## Roadmap

| Versão | Conteúdo |
|---|---|
| `v0.1.0` | Lib Node + Lib Python + vectors.json + CI cross-lang |
| `v0.2.0` | Rotação com 2 pubkeys ativas (overlap) + cache anti-replay opcional |
| `v0.3.0` | Suporte a novos métodos (PATCH/DELETE com edge cases), Go ou Rust se demandado |

---

## Referências

- Plano da iniciativa: memória `opcao-a-estado` (memory store local)
- Padrão de auth gateway: memória `padrao-auth-gateway`
- Apps embeddados afetados: memória `apps-embedded-gateway`
- Lib Ed25519 recomendada Node: [`@noble/ed25519`](https://github.com/paulmillr/noble-ed25519) (auditada, zero deps)
- Lib Ed25519 recomendada Python: [`cryptography`](https://cryptography.io/) (Ed25519 nativo) ou [`pynacl`](https://pynacl.readthedocs.io/)

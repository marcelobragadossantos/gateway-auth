/**
 * Express middleware for gateway signature validation.
 *
 * Requires `req.rawBody: Buffer` to be set by an upstream middleware
 * (e.g. `express.raw({ type: '*\/*' })`). The raw bytes must match exactly
 * what the gateway signed — body-parser's parsed/restringified JSON will NOT.
 */
import type { Request, RequestHandler, Response, NextFunction } from 'express';
import { parsePubkey, verifyWithPubkey, GatewayAuthError } from './index.js';

export type AuthMode = 'off' | 'warn' | 'enforce';

export interface MiddlewareLogger {
  warn: (msg: string, ctx?: object) => void;
}

export interface ExpressMiddlewareOptions {
  /**
   * Gateway public key(s): 32 bytes hex each. Not a secret. Accepts several
   * separated by comma/whitespace; a signature valid for ANY of them passes.
   * The validating key id (first 8 hex chars) is set as `req.gatewayKeyId`.
   */
  pubkeyHex: string;
  /** off | warn | enforce. */
  mode: AuthMode;
  /** Anti-replay window in seconds. Default: env GATEWAY_MAX_SKEW_S or 60. */
  maxSkewSeconds?: number;
  /** Custom logger (defaults to console). */
  logger?: MiddlewareLogger;
  /**
   * Request paths exempt from validation in every mode (matched against the decoded
   * `req.path`). Health/liveness probes carry no signature; in enforce they
   * would 401 and crash-loop the container. Defaults to DEFAULT_EXEMPT_PATHS;
   * pass your own array to replace it.
   */
  exemptPaths?: string[];
  /** Now provider, mostly for tests. Returns unix seconds. */
  now?: () => number;
}

const HEADER_UID = 'x-gateway-user-id';
const HEADER_TS = 'x-gateway-timestamp';
const HEADER_SIG = 'x-gateway-signature';

/** Liveness/health paths kept public by default (gateway never signs probes). */
export const DEFAULT_EXEMPT_PATHS = ['/health', '/api/health'];

/**
 * Skew window from env GATEWAY_MAX_SKEW_S. Lets you loosen the timestamp
 * anti-replay window when gateway/back host clocks drift (NTP) without code
 * changes. Returns undefined if unset/invalid (caller falls back to 60s).
 */
function envMaxSkewSeconds(): number | undefined {
  const raw = process.env.GATEWAY_MAX_SKEW_S;
  if (!raw) return undefined;
  const n = Number.parseInt(raw, 10);
  return Number.isInteger(n) && n > 0 ? n : undefined;
}

interface RequestWithRawBody extends Request {
  rawBody?: Buffer;
  gatewayKeyId?: string;
}

function defaultLogger(): MiddlewareLogger {
  return {
    warn: (msg, ctx) => {
      if (ctx) console.warn(`[gateway-auth] ${msg}`, ctx);
      else console.warn(`[gateway-auth] ${msg}`);
    },
  };
}

function readHeader(req: Request, name: string): string | undefined {
  const v = req.headers[name];
  if (Array.isArray(v)) return v[0];
  return v;
}

interface ValidationFailure {
  reason: string;
  keyId?: string;
  detail?: object;
}

interface ValidationContext {
  pubkeys: Array<{ id: string; key: Uint8Array }>;
  maxSkewSeconds: number;
  now: () => number;
}

function validateSignature(
  req: RequestWithRawBody,
  ctx: ValidationContext,
): ValidationFailure | null {
  if (!req.rawBody || !Buffer.isBuffer(req.rawBody)) {
    return { reason: 'missing_raw_body' };
  }

  const uid = readHeader(req, HEADER_UID);
  const tsRaw = readHeader(req, HEADER_TS);
  const sigHex = readHeader(req, HEADER_SIG);

  if (!uid || !tsRaw || !sigHex) {
    return {
      reason: 'missing_gateway_headers',
      detail: {
        hasUid: Boolean(uid),
        hasTimestamp: Boolean(tsRaw),
        hasSignature: Boolean(sigHex),
      },
    };
  }

  // Strict numeric format — match Python int() behavior, not parseInt's permissive trailing-junk acceptance.
  if (!/^\d+$/.test(tsRaw)) {
    return { reason: 'invalid_timestamp', detail: { raw: tsRaw } };
  }
  const timestamp = Number.parseInt(tsRaw, 10);
  if (!Number.isInteger(timestamp)) {
    return { reason: 'invalid_timestamp', detail: { raw: tsRaw } };
  }

  const now = ctx.now();
  if (Math.abs(now - timestamp) > ctx.maxSkewSeconds) {
    return {
      reason: 'timestamp_outside_window',
      detail: { now, timestamp, skewSeconds: now - timestamp },
    };
  }

  let validKeyId: string | undefined;
  try {
    const input = {
      method: req.method,
      path: canonicalPath(req),
      uid,
      timestamp,
      body: req.rawBody,
    };
    for (const { id, key } of ctx.pubkeys) {
      if (verifyWithPubkey(key, sigHex, input)) {
        validKeyId = id;
        break;
      }
    }
  } catch (err) {
    if (err instanceof GatewayAuthError) {
      return { reason: err.code, detail: { message: err.message } };
    }
    throw err;
  }

  if (validKeyId === undefined) {
    return { reason: 'invalid_signature' };
  }
  req.gatewayKeyId = validKeyId;
  return null;
}

/**
 * Path canonico = o que o portal ASSINA: `decodeURIComponent(path)`.
 * `req.path` do Express vem percent-encoded (espaco -> %20, acento -> %C3..),
 * entao sem decodar um back com espaco/acento no path tomaria 401.
 * Espelha `decodeCanonicalPath` de portalgateway/src/helpers/gatewaySigner.js:
 * se o decode lancar (URL malformada, ex.: `%E0%A4%A`), usa o path cru — o
 * portal assina o cru nesse caso. Nunca lanca.
 */
export function decodeCanonicalPath(path: string): string {
  try {
    return decodeURIComponent(path);
  } catch {
    return path;
  }
}

function canonicalPath(req: Request): string {
  return decodeCanonicalPath(req.path);
}

export function gatewayAuthMiddleware(
  opts: ExpressMiddlewareOptions,
): RequestHandler {
  if (!opts || typeof opts !== 'object') {
    throw new Error('gatewayAuthMiddleware: options are required');
  }
  const mode: AuthMode = opts.mode;
  if (mode !== 'off' && mode !== 'warn' && mode !== 'enforce') {
    throw new Error(
      `gatewayAuthMiddleware: invalid mode '${mode}' (expected off|warn|enforce)`,
    );
  }
  let parsedPubkeys: Array<{ id: string; key: Uint8Array }> = [];
  if (mode !== 'off') {
    if (!opts.pubkeyHex || typeof opts.pubkeyHex !== 'string') {
      throw new Error('gatewayAuthMiddleware: pubkeyHex is required for warn|enforce');
    }
    const items = opts.pubkeyHex.split(/[,\s]+/).filter((x) => x.length > 0);
    if (items.length === 0) {
      throw new Error('gatewayAuthMiddleware: pubkeyHex is required for warn|enforce');
    }
    const seen = new Set<string>();
    items.forEach((item, i) => {
      if (!/^[0-9a-f]{64}$/i.test(item)) {
        throw new Error(
          `gatewayAuthMiddleware: pubkeyHex entry ${i + 1} of ${items.length} must be 64 hex chars (32-byte Ed25519 public key)`,
        );
      }
      const lower = item.toLowerCase();
      if (seen.has(lower)) {
        throw new Error(`gatewayAuthMiddleware: duplicate pubkeyHex entry ${i + 1}`);
      }
      seen.add(lower);
      // Parse once at startup; reused per request.
      parsedPubkeys.push({ id: lower.slice(0, 8), key: parsePubkey(item) });
    });
  }

  const ctx: ValidationContext = {
    pubkeys: parsedPubkeys,
    maxSkewSeconds: opts.maxSkewSeconds ?? envMaxSkewSeconds() ?? 60,
    now: opts.now ?? (() => Math.floor(Date.now() / 1000)),
  };
  const logger = opts.logger ?? defaultLogger();
  const exemptPaths = new Set(opts.exemptPaths ?? DEFAULT_EXEMPT_PATHS);

  return function gatewayAuth(
    req: RequestWithRawBody,
    res: Response,
    next: NextFunction,
  ): void {
    if (mode === 'off') {
      next();
      return;
    }

    // Health/liveness paths bypass validation so unsigned orchestrator probes
    // don't 401 into a crash-loop.
    if (exemptPaths.has(canonicalPath(req))) {
      next();
      return;
    }

    const failure = validateSignature(req, ctx);

    if (!failure) {
      next();
      return;
    }

    if (mode === 'warn') {
      logger.warn(`gateway signature invalid: ${failure.reason}`, {
        path: canonicalPath(req),
        method: req.method,
        ...failure.detail,
      });
      next();
      return;
    }

    // enforce: uniform error shape across all failure reasons (matches Python middleware).
    res.status(401).json({
      error: 'invalid_gateway_signature',
      reason: failure.reason,
    });
  };
}

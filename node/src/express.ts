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
  /** Gateway public key, 32 bytes hex lowercase. Not a secret. */
  pubkeyHex: string;
  /** off | warn | enforce. */
  mode: AuthMode;
  /** Anti-replay window in seconds (default 60). */
  maxSkewSeconds?: number;
  /** Custom logger (defaults to console). */
  logger?: MiddlewareLogger;
  /** Now provider, mostly for tests. Returns unix seconds. */
  now?: () => number;
}

const HEADER_UID = 'x-gateway-user-id';
const HEADER_TS = 'x-gateway-timestamp';
const HEADER_SIG = 'x-gateway-signature';

interface RequestWithRawBody extends Request {
  rawBody?: Buffer;
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
  detail?: object;
}

interface ValidationContext {
  pubkey: Uint8Array;
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

  let ok = false;
  try {
    ok = verifyWithPubkey(ctx.pubkey, sigHex, {
      method: req.method,
      path: req.path,
      uid,
      timestamp,
      body: req.rawBody,
    });
  } catch (err) {
    if (err instanceof GatewayAuthError) {
      return { reason: err.code, detail: { message: err.message } };
    }
    throw err;
  }

  if (!ok) {
    return { reason: 'invalid_signature' };
  }
  return null;
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
  let parsedPubkey: Uint8Array;
  if (mode !== 'off') {
    if (!opts.pubkeyHex || typeof opts.pubkeyHex !== 'string') {
      throw new Error('gatewayAuthMiddleware: pubkeyHex is required for warn|enforce');
    }
    if (!/^[0-9a-f]{64}$/i.test(opts.pubkeyHex)) {
      throw new Error(
        'gatewayAuthMiddleware: pubkeyHex must be 64 hex chars (32-byte Ed25519 public key)',
      );
    }
    // Parse once at startup; reused per request (avoids re-parsing hex on every verify).
    parsedPubkey = parsePubkey(opts.pubkeyHex);
  } else {
    // Off mode never reaches validateSignature; placeholder bytes are fine.
    parsedPubkey = new Uint8Array(32);
  }

  const ctx: ValidationContext = {
    pubkey: parsedPubkey,
    maxSkewSeconds: opts.maxSkewSeconds ?? 60,
    now: opts.now ?? (() => Math.floor(Date.now() / 1000)),
  };
  const logger = opts.logger ?? defaultLogger();

  return function gatewayAuth(
    req: RequestWithRawBody,
    res: Response,
    next: NextFunction,
  ): void {
    if (mode === 'off') {
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
        path: req.path,
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

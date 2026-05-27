/**
 * Smoke tests for the Express middleware in the three modes.
 *
 * Uses a real Express app + supertest-style flow via raw http calls — kept
 * minimal because the cryptographic core is fully covered by vectors.test.ts.
 */
import { describe, it, expect, vi } from 'vitest';
import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Buffer } from 'node:buffer';
import { sign } from '../src/index.js';
import { gatewayAuthMiddleware } from '../src/express.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const vectorsPath = resolve(__dirname, '../../fixtures/vectors.json');
const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8'));
const { privkey_hex, pubkey_hex } = vectors.test_keys;

interface MockReq {
  method: string;
  path: string;
  url: string;
  headers: Record<string, string>;
  rawBody?: Buffer;
}

function buildReq(overrides: Partial<MockReq> = {}): Request {
  const req: MockReq = {
    method: 'POST',
    path: '/v1/orders',
    url: '/v1/orders',
    headers: {},
    ...overrides,
  };
  return req as unknown as Request;
}

function buildRes(): {
  res: Response;
  status: ReturnType<typeof vi.fn>;
  json: ReturnType<typeof vi.fn>;
} {
  const json = vi.fn();
  const status = vi.fn().mockImplementation(() => ({ json }));
  const res = { status, json } as unknown as Response;
  return { res, status, json };
}

function freshNow(): number {
  return 1748390401;
}

function signedHeaders(opts: {
  method: string;
  path: string;
  uid: string;
  timestamp: number;
  body: Buffer;
}): Record<string, string> {
  const sig = sign(privkey_hex, opts);
  return {
    'x-gateway-user-id': opts.uid,
    'x-gateway-timestamp': String(opts.timestamp),
    'x-gateway-signature': sig,
  };
}

describe('gatewayAuthMiddleware - mode=off', () => {
  it('passes through without checking anything', () => {
    const mw = gatewayAuthMiddleware({ pubkeyHex: pubkey_hex, mode: 'off' });
    const next = vi.fn();
    const { res, status } = buildRes();
    mw(buildReq(), res, next as NextFunction);
    expect(next).toHaveBeenCalledOnce();
    expect(status).not.toHaveBeenCalled();
  });
});

describe('gatewayAuthMiddleware - mode=enforce', () => {
  it('accepts a valid request', () => {
    const body = Buffer.from('{"sku":"ABC123","qty":2}', 'utf8');
    const ts = freshNow();
    const headers = signedHeaders({
      method: 'POST',
      path: '/v1/orders',
      uid: '42',
      timestamp: ts,
      body,
    });

    const mw = gatewayAuthMiddleware({
      pubkeyHex: pubkey_hex,
      mode: 'enforce',
      now: freshNow,
    });
    const next = vi.fn();
    const { res, status } = buildRes();
    mw(buildReq({ headers, rawBody: body }), res, next as NextFunction);
    expect(next).toHaveBeenCalledOnce();
    expect(status).not.toHaveBeenCalled();
  });

  it('rejects with 401 when rawBody is missing', () => {
    const mw = gatewayAuthMiddleware({
      pubkeyHex: pubkey_hex,
      mode: 'enforce',
      now: freshNow,
    });
    const next = vi.fn();
    const { res, status, json } = buildRes();
    mw(buildReq(), res, next as NextFunction);
    expect(next).not.toHaveBeenCalled();
    expect(status).toHaveBeenCalledWith(401);
    expect(json).toHaveBeenCalledWith({ error: 'missing_raw_body' });
  });

  it('rejects with 401 on tampered body', () => {
    const body = Buffer.from('{"sku":"ABC123","qty":2}', 'utf8');
    const ts = freshNow();
    const headers = signedHeaders({
      method: 'POST',
      path: '/v1/orders',
      uid: '42',
      timestamp: ts,
      body,
    });
    const tampered = Buffer.from('{"sku":"XYZ999","qty":2}', 'utf8');

    const mw = gatewayAuthMiddleware({
      pubkeyHex: pubkey_hex,
      mode: 'enforce',
      now: freshNow,
    });
    const next = vi.fn();
    const { res, status, json } = buildRes();
    mw(buildReq({ headers, rawBody: tampered }), res, next as NextFunction);
    expect(next).not.toHaveBeenCalled();
    expect(status).toHaveBeenCalledWith(401);
    expect(json).toHaveBeenCalledWith({ error: 'invalid_gateway_signature' });
  });

  it('rejects when timestamp is outside the window', () => {
    const body = Buffer.alloc(0);
    const ts = freshNow();
    const headers = signedHeaders({
      method: 'GET',
      path: '/v1/users/me',
      uid: '42',
      timestamp: ts,
      body,
    });

    const mw = gatewayAuthMiddleware({
      pubkeyHex: pubkey_hex,
      mode: 'enforce',
      maxSkewSeconds: 60,
      now: () => ts + 120, // 120s in the future
    });
    const next = vi.fn();
    const { res, status, json } = buildRes();
    mw(
      buildReq({
        method: 'GET',
        path: '/v1/users/me',
        url: '/v1/users/me',
        headers,
        rawBody: body,
      }),
      res,
      next as NextFunction,
    );
    expect(next).not.toHaveBeenCalled();
    expect(status).toHaveBeenCalledWith(401);
    expect(json).toHaveBeenCalledWith({ error: 'invalid_gateway_signature' });
  });

  it('rejects when gateway headers are missing', () => {
    const body = Buffer.alloc(0);
    const mw = gatewayAuthMiddleware({
      pubkeyHex: pubkey_hex,
      mode: 'enforce',
      now: freshNow,
    });
    const next = vi.fn();
    const { res, status, json } = buildRes();
    mw(buildReq({ rawBody: body }), res, next as NextFunction);
    expect(next).not.toHaveBeenCalled();
    expect(status).toHaveBeenCalledWith(401);
    expect(json).toHaveBeenCalledWith({ error: 'invalid_gateway_signature' });
  });
});

describe('gatewayAuthMiddleware - mode=warn', () => {
  it('passes through on invalid signature but logs', () => {
    const body = Buffer.from('original', 'utf8');
    const tampered = Buffer.from('tampered', 'utf8');
    const ts = freshNow();
    const headers = signedHeaders({
      method: 'POST',
      path: '/v1/orders',
      uid: '42',
      timestamp: ts,
      body,
    });

    const logger = { warn: vi.fn() };
    const mw = gatewayAuthMiddleware({
      pubkeyHex: pubkey_hex,
      mode: 'warn',
      now: freshNow,
      logger,
    });
    const next = vi.fn();
    const { res, status } = buildRes();
    mw(buildReq({ headers, rawBody: tampered }), res, next as NextFunction);
    expect(next).toHaveBeenCalledOnce();
    expect(status).not.toHaveBeenCalled();
    expect(logger.warn).toHaveBeenCalledOnce();
    const [msg] = logger.warn.mock.calls[0] as [string, object];
    expect(msg).toMatch(/invalid_signature/);
  });

  it('passes through on missing rawBody but logs', () => {
    const logger = { warn: vi.fn() };
    const mw = gatewayAuthMiddleware({
      pubkeyHex: pubkey_hex,
      mode: 'warn',
      now: freshNow,
      logger,
    });
    const next = vi.fn();
    const { res } = buildRes();
    mw(buildReq(), res, next as NextFunction);
    expect(next).toHaveBeenCalledOnce();
    expect(logger.warn).toHaveBeenCalledOnce();
    const [msg] = logger.warn.mock.calls[0] as [string, object];
    expect(msg).toMatch(/missing_raw_body/);
  });

  it('passes through silently on valid signature', () => {
    const body = Buffer.from('payload', 'utf8');
    const ts = freshNow();
    const headers = signedHeaders({
      method: 'POST',
      path: '/v1/orders',
      uid: '42',
      timestamp: ts,
      body,
    });

    const logger = { warn: vi.fn() };
    const mw = gatewayAuthMiddleware({
      pubkeyHex: pubkey_hex,
      mode: 'warn',
      now: freshNow,
      logger,
    });
    const next = vi.fn();
    const { res } = buildRes();
    mw(buildReq({ headers, rawBody: body }), res, next as NextFunction);
    expect(next).toHaveBeenCalledOnce();
    expect(logger.warn).not.toHaveBeenCalled();
  });
});

describe('gatewayAuthMiddleware - construction', () => {
  it('throws on invalid mode', () => {
    expect(() =>
      // @ts-expect-error invalid mode
      gatewayAuthMiddleware({ pubkeyHex: pubkey_hex, mode: 'bogus' }),
    ).toThrow();
  });

  it('throws when pubkeyHex missing in enforce mode', () => {
    expect(() =>
      gatewayAuthMiddleware({ pubkeyHex: '', mode: 'enforce' }),
    ).toThrow();
  });

  it('off mode does not require pubkey', () => {
    expect(() =>
      gatewayAuthMiddleware({ pubkeyHex: '', mode: 'off' }),
    ).not.toThrow();
  });
});

describe('integration with real Express app', () => {
  it('end-to-end accept with express.raw', async () => {
    const body = Buffer.from('{"x":1}', 'utf8');
    const ts = freshNow();
    const headers = signedHeaders({
      method: 'POST',
      path: '/echo',
      uid: '42',
      timestamp: ts,
      body,
    });

    const app = express();
    app.use(express.raw({ type: '*/*' }));
    app.use((req, _res, next) => {
      // express.raw sets req.body to the Buffer; mirror it as rawBody for the middleware.
      (req as Request & { rawBody?: Buffer }).rawBody = req.body as Buffer;
      next();
    });
    app.use(
      gatewayAuthMiddleware({
        pubkeyHex: pubkey_hex,
        mode: 'enforce',
        now: freshNow,
      }),
    );
    app.post('/echo', (_req, res) => {
      res.json({ ok: true });
    });

    const server = app.listen(0);
    const port = (server.address() as { port: number }).port;
    try {
      const resp = await fetch(`http://127.0.0.1:${port}/echo`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...headers,
        },
        body,
      });
      expect(resp.status).toBe(200);
      const json = await resp.json();
      expect(json).toEqual({ ok: true });
    } finally {
      server.close();
    }
  });

  it('end-to-end reject with tampered body', async () => {
    const body = Buffer.from('{"x":1}', 'utf8');
    const ts = freshNow();
    const headers = signedHeaders({
      method: 'POST',
      path: '/echo',
      uid: '42',
      timestamp: ts,
      body,
    });

    const app = express();
    app.use(express.raw({ type: '*/*' }));
    app.use((req, _res, next) => {
      (req as Request & { rawBody?: Buffer }).rawBody = req.body as Buffer;
      next();
    });
    app.use(
      gatewayAuthMiddleware({
        pubkeyHex: pubkey_hex,
        mode: 'enforce',
        now: freshNow,
      }),
    );
    app.post('/echo', (_req, res) => {
      res.json({ ok: true });
    });

    const server = app.listen(0);
    const port = (server.address() as { port: number }).port;
    try {
      const resp = await fetch(`http://127.0.0.1:${port}/echo`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...headers,
        },
        body: Buffer.from('{"x":2}', 'utf8'),
      });
      expect(resp.status).toBe(401);
      const json = await resp.json();
      expect(json).toEqual({ error: 'invalid_gateway_signature' });
    } finally {
      server.close();
    }
  });
});

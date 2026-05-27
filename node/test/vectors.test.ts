/**
 * Cross-language validation against fixtures/vectors.json.
 *
 * This is the canonical contract test. If any case here fails, the lib has
 * diverged from the Python implementation and the gateway/back wiring will
 * break interop.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Buffer } from 'node:buffer';
import { canonicalPayload, sign, verify } from '../src/index.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const vectorsPath = resolve(__dirname, '../../fixtures/vectors.json');

interface Vector {
  name: string;
  description: string;
  input: {
    method: string;
    path: string;
    uid: string;
    timestamp: number;
    body_hex: string;
  };
  canonical_payload_utf8: string;
  canonical_payload_hex: string;
  expected_signature_hex: string;
}

interface VectorsFile {
  version: string;
  algorithm: string;
  encoding: string;
  test_keys: {
    privkey_hex: string;
    pubkey_hex: string;
  };
  cases: Vector[];
}

const vectors: VectorsFile = JSON.parse(readFileSync(vectorsPath, 'utf8'));

describe('vectors.json contract', () => {
  it('uses Ed25519 + hex-lowercase', () => {
    expect(vectors.algorithm).toBe('Ed25519');
    expect(vectors.encoding).toBe('hex-lowercase');
  });

  it('has at least the three documented cases', () => {
    expect(vectors.cases.length).toBeGreaterThanOrEqual(3);
  });
});

describe.each(vectors.cases)('case: $name', (vec) => {
  const body = Buffer.from(vec.input.body_hex, 'hex');
  const input = {
    method: vec.input.method,
    path: vec.input.path,
    uid: vec.input.uid,
    timestamp: vec.input.timestamp,
    body,
  };

  it('builds canonical payload bytes exactly', () => {
    const payload = canonicalPayload(input);
    expect(payload.toString('hex')).toBe(vec.canonical_payload_hex);
    expect(payload.toString('utf8')).toBe(vec.canonical_payload_utf8);
  });

  it('signs to the expected signature (deterministic)', () => {
    const sig = sign(vectors.test_keys.privkey_hex, input);
    expect(sig).toBe(vec.expected_signature_hex);
  });

  it('verifies the expected signature', () => {
    const ok = verify(
      vectors.test_keys.pubkey_hex,
      vec.expected_signature_hex,
      input,
    );
    expect(ok).toBe(true);
  });

  it('detects tampered body', () => {
    // Build a body that differs by at least one byte. If body is empty, use a
    // single byte so the tampered hash diverges from the empty-string hash.
    const tampered = body.length === 0 ? Buffer.from([0x21]) : Buffer.from(body);
    if (tampered.length > 0 && body.length > 0) {
      const first = tampered[0] ?? 0;
      tampered[0] = first ^ 0x01;
    }
    const ok = verify(vectors.test_keys.pubkey_hex, vec.expected_signature_hex, {
      ...input,
      body: tampered,
    });
    expect(ok).toBe(false);
  });

  it('detects tampered timestamp', () => {
    const ok = verify(vectors.test_keys.pubkey_hex, vec.expected_signature_hex, {
      ...input,
      timestamp: input.timestamp + 1,
    });
    expect(ok).toBe(false);
  });

  it('detects tampered method', () => {
    const swapped = input.method === 'GET' ? 'POST' : 'GET';
    const ok = verify(vectors.test_keys.pubkey_hex, vec.expected_signature_hex, {
      ...input,
      method: swapped,
    });
    expect(ok).toBe(false);
  });

  it('detects tampered path', () => {
    const ok = verify(vectors.test_keys.pubkey_hex, vec.expected_signature_hex, {
      ...input,
      path: input.path + '/extra',
    });
    expect(ok).toBe(false);
  });
});

describe('canonicalPayload', () => {
  it('uppercases the method', () => {
    const lower = canonicalPayload({
      method: 'get',
      path: '/x',
      uid: '1',
      timestamp: 1,
      body: '',
    });
    const upper = canonicalPayload({
      method: 'GET',
      path: '/x',
      uid: '1',
      timestamp: 1,
      body: '',
    });
    expect(lower.equals(upper)).toBe(true);
  });

  it('treats string body as UTF-8', () => {
    const fromString = canonicalPayload({
      method: 'POST',
      path: '/x',
      uid: '1',
      timestamp: 1,
      body: 'hello',
    });
    const fromBytes = canonicalPayload({
      method: 'POST',
      path: '/x',
      uid: '1',
      timestamp: 1,
      body: Buffer.from('hello', 'utf8'),
    });
    expect(fromString.equals(fromBytes)).toBe(true);
  });

  it('rejects non-integer timestamps', () => {
    expect(() =>
      canonicalPayload({
        method: 'GET',
        path: '/x',
        uid: '1',
        timestamp: 1.5,
        body: '',
      }),
    ).toThrow();
  });
});

describe('verify edge cases', () => {
  const validInput = {
    method: 'GET',
    path: '/x',
    uid: '1',
    timestamp: 1,
    body: '',
  };

  it('returns false on malformed signature hex', () => {
    expect(verify(vectors.test_keys.pubkey_hex, 'not-hex', validInput)).toBe(false);
  });

  it('returns false on wrong-length signature', () => {
    expect(verify(vectors.test_keys.pubkey_hex, 'aabb', validInput)).toBe(false);
  });

  it('returns false on wrong-length pubkey', () => {
    expect(verify('aabb', 'aa'.repeat(64), validInput)).toBe(false);
  });
});

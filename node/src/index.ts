/**
 * @grupohiperfarma/gateway-auth-node
 *
 * Ed25519 signing/verification for the Portal Gateway -> back trust boundary.
 *
 * Contract: see ../../README.md (canonical payload, headers, replay window).
 * Cross-lang test vectors: see ../../fixtures/vectors.json.
 */
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha512';
import { createHash } from 'node:crypto';
import { Buffer } from 'node:buffer';

// @noble/ed25519 v2 is sync but requires the sha512 hook to be set explicitly
// (it ships zero-dep, so the caller provides the hash impl).
ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

export interface CanonicalInput {
  /** HTTP method. Will be uppercased internally. */
  method: string;
  /** Internal path (already stripped of /api or module-access prefixes). No querystring. */
  path: string;
  /** Authenticated user id (string). */
  uid: string;
  /** Unix timestamp in seconds (not ms). */
  timestamp: number;
  /** Raw body bytes. A string is treated as UTF-8. */
  body: Buffer | Uint8Array | string;
}

export class GatewayAuthError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'GatewayAuthError';
    this.code = code;
  }
}

function toBytes(body: Buffer | Uint8Array | string): Uint8Array {
  if (typeof body === 'string') return new TextEncoder().encode(body);
  if (body instanceof Uint8Array) return body;
  throw new GatewayAuthError(
    'invalid_body',
    'body must be Buffer, Uint8Array, or string',
  );
}

function sha256Hex(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function hexToBytes(hex: string, label: string): Uint8Array {
  if (typeof hex !== 'string') {
    throw new GatewayAuthError('invalid_hex', `${label} must be a hex string`);
  }
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) {
    throw new GatewayAuthError('invalid_hex', `${label} is not valid hex`);
  }
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('hex');
}

/**
 * Build the canonical payload bytes that get signed.
 *
 * Format (literal LF as separator, no trailing newline):
 *   METHOD\nPATH\nUID\nUNIX_TIMESTAMP_S\nsha256:HEX_BODY_HASH
 */
export function canonicalPayload(input: CanonicalInput): Buffer {
  if (!input || typeof input !== 'object') {
    throw new GatewayAuthError('invalid_input', 'input is required');
  }
  const { method, path, uid, timestamp, body } = input;
  if (typeof method !== 'string' || method.length === 0) {
    throw new GatewayAuthError('invalid_input', 'method is required');
  }
  if (typeof path !== 'string' || path.length === 0) {
    throw new GatewayAuthError('invalid_input', 'path is required');
  }
  if (typeof uid !== 'string' || uid.length === 0) {
    throw new GatewayAuthError('invalid_input', 'uid is required');
  }
  if (!Number.isInteger(timestamp)) {
    throw new GatewayAuthError(
      'invalid_input',
      'timestamp must be an integer (unix seconds)',
    );
  }

  const bodyBytes = toBytes(body ?? '');
  const bodyHashHex = sha256Hex(bodyBytes);

  const payload = `${method.toUpperCase()}\n${path}\n${uid}\n${timestamp}\nsha256:${bodyHashHex}`;
  return Buffer.from(payload, 'utf8');
}

/**
 * Sign the canonical payload. Returns the Ed25519 signature as 128-char hex (lowercase).
 *
 * @param privkeyHex 32-byte Ed25519 private key, hex lowercase.
 */
export function sign(privkeyHex: string, input: CanonicalInput): string {
  const priv = hexToBytes(privkeyHex, 'privkey');
  if (priv.length !== 32) {
    throw new GatewayAuthError(
      'invalid_key',
      `privkey must be 32 bytes (got ${priv.length})`,
    );
  }
  const payload = canonicalPayload(input);
  const sig = ed.sign(payload, priv);
  return bytesToHex(sig);
}

/**
 * Parse a 32-byte Ed25519 public key from hex. Use this once at startup
 * (e.g. in a middleware constructor) and pass the result to `verifyWithPubkey`
 * on every request — avoids re-parsing hex on each verification.
 *
 * Throws GatewayAuthError if the hex is malformed or not 32 bytes.
 */
export function parsePubkey(pubkeyHex: string): Uint8Array {
  const pub = hexToBytes(pubkeyHex, 'pubkey');
  if (pub.length !== 32) {
    throw new GatewayAuthError(
      'invalid_key',
      `pubkey must be 32 bytes (got ${pub.length})`,
    );
  }
  return pub;
}

/**
 * Verify with a pre-parsed pubkey. Hot-path variant — `parsePubkey` once at
 * startup, then call this per request. Equivalent to `verify(pubkeyHex, ...)`
 * minus the per-call hex parse.
 */
export function verifyWithPubkey(
  pubkey: Uint8Array,
  signatureHex: string,
  input: CanonicalInput,
): boolean {
  let sig: Uint8Array;
  try {
    sig = hexToBytes(signatureHex, 'signature');
  } catch {
    return false;
  }
  if (pubkey.length !== 32 || sig.length !== 64) return false;

  let payload: Buffer;
  try {
    payload = canonicalPayload(input);
  } catch (err) {
    // Bubble up bad-input errors so callers can distinguish from "bad signature".
    throw err;
  }

  try {
    return ed.verify(sig, payload, pubkey);
  } catch {
    return false;
  }
}

/**
 * Verify a signature for the canonical payload built from `input`.
 *
 * Returns true on valid signature, false otherwise. Never throws on a bad
 * signature/key shape — only on invalid input (missing method/path/uid).
 *
 * For hot paths (HTTP middleware), prefer `parsePubkey` once + `verifyWithPubkey`
 * per request to avoid re-parsing pubkey hex on every call.
 *
 * @param pubkeyHex 32-byte Ed25519 public key, hex lowercase.
 * @param signatureHex 64-byte Ed25519 signature, hex lowercase.
 */
export function verify(
  pubkeyHex: string,
  signatureHex: string,
  input: CanonicalInput,
): boolean {
  let pub: Uint8Array;
  try {
    pub = hexToBytes(pubkeyHex, 'pubkey');
  } catch {
    return false;
  }
  if (pub.length !== 32) return false;
  return verifyWithPubkey(pub, signatureHex, input);
}

import { createHash, randomBytes } from 'node:crypto';

/** Hex SHA-256. Used to store refresh tokens and OAuth state: only the hash is persisted. */
export function sha256Hex(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

/** Cryptographically random, URL-safe string. 32 bytes gives 43 characters. */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

/** PKCE S256: BASE64URL(SHA256(code_verifier)), no padding. */
export function pkceChallenge(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Untrusted input must be checked before it reaches a uuid column, or Postgres raises an error. */
export function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID.test(value);
}

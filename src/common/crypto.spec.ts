import { isUuid, pkceChallenge, randomToken, sha256Hex } from './crypto';

describe('crypto helpers', () => {
  it('computes the PKCE S256 challenge from the RFC 7636 appendix B test vector', () => {
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    expect(pkceChallenge(verifier)).toBe(
      'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
    );
  });

  it('generates URL-safe random tokens of the PKCE verifier length', () => {
    const a = randomToken(32);
    const b = randomToken(32);
    expect(a).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(a).not.toBe(b);
  });

  it('hashes deterministically to 64 hex characters', () => {
    expect(sha256Hex('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });

  it('accepts only well-formed uuids', () => {
    expect(isUuid('3f2b8c1e-5d4a-4b6f-9a7e-1c2d3e4f5a6b')).toBe(true);
    expect(isUuid('not-a-uuid')).toBe(false);
    expect(isUuid("' OR 1=1 --")).toBe(false);
    expect(isUuid(undefined)).toBe(false);
  });
});

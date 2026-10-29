/** @jest-environment node */
import { ALGORITHMS, MIN_HMAC_BYTES, algorithmSpec, keyWarnings, randomSecret } from './keys';

const text = (secret) => ({ secret, secretEncoding: 'text', pem: '' });
const b64 = (bytes) => ({ secret: Buffer.from(bytes).toString('base64url'), secretEncoding: 'base64url', pem: '' });
const codes = (alg, material) => keyWarnings(alg, material).map((w) => w.code);

describe('keyWarnings', () => {
  test('uses the RFC 7518 minimums: the hash output length', () => {
    expect(MIN_HMAC_BYTES).toEqual({ HS256: 32, HS384: 48, HS512: 64 });
    for (const [alg, min] of Object.entries(MIN_HMAC_BYTES)) {
      expect(codes(alg, text('x'.repeat(min - 1)))).toEqual(['weak-key']);
      expect(codes(alg, text('x'.repeat(min)))).toEqual([]);
    }
  });

  test('the same key can be fine for HS256 and weak for HS512', () => {
    const key = text('x'.repeat(40));
    expect(codes('HS256', key)).toEqual([]);
    expect(codes('HS384', key)).toEqual(['weak-key']);
    expect(codes('HS512', key)).toEqual(['weak-key']);
  });

  test('measures bytes, not characters', () => {
    // 11 two-byte characters = 22 bytes < 32; 16 of them = 32 bytes.
    expect(codes('HS256', text('é'.repeat(11)))).toEqual(['weak-key']);
    expect(codes('HS256', text('é'.repeat(16)))).toEqual([]);
    expect(keyWarnings('HS256', text('é'.repeat(11)))[0].message).toMatch(/22 bytes/);
  });

  test('base64url keys are measured after decoding', () => {
    expect(codes('HS256', b64(Buffer.alloc(31)))).toEqual(['weak-key']);
    expect(codes('HS256', b64(Buffer.alloc(32, 7)))).toEqual([]);
  });

  test('the published example key is flagged however it is entered', () => {
    expect(codes('HS256', text('your-256-bit-secret'))).toEqual(['known-key', 'weak-key']);
    expect(codes('HS256', b64(Buffer.from('your-256-bit-secret')))).toEqual(['known-key', 'weak-key']);
    expect(codes('HS256', text('your-256-bit-secret!'))).toEqual(['weak-key']);
  });

  test('says nothing when there is no key, an invalid encoding, or no HMAC algorithm', () => {
    expect(keyWarnings('HS256', text(''))).toEqual([]);
    expect(keyWarnings('HS256', { secret: 'not base64url!', secretEncoding: 'base64url', pem: '' })).toEqual([]);
    for (const alg of ['RS256', 'PS256', 'ES256', 'EdDSA', 'none', undefined, null, 5, { toString: null }]) {
      expect(keyWarnings(alg, text('short'))).toEqual([]);
    }
  });
});

describe('randomSecret', () => {
  test('is 64 bytes of base64url, never repeats, and is strong for every HMAC algorithm', () => {
    const seen = new Set();
    for (let i = 0; i < 50; i += 1) {
      const secret = randomSecret();
      expect(secret).toMatch(/^[A-Za-z0-9_-]{86}$/);
      for (const alg of ['HS256', 'HS384', 'HS512']) expect(codes(alg, text(secret))).toEqual([]);
      seen.add(secret);
    }
    expect(seen.size).toBe(50);
  });
});

describe('algorithmSpec', () => {
  test('returns registry entries only for own string keys', () => {
    expect(algorithmSpec('HS256')).toBe(ALGORITHMS.HS256);
    for (const hostile of ['constructor', '__proto__', 'toString', 'hasOwnProperty', '', undefined, null, 5, [], {}, { toString: null }]) {
      expect(algorithmSpec(hostile)).toBeNull();
    }
  });
});

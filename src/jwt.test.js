// @vitest-environment node
import { createHmac } from 'crypto';
import {
  base64UrlDecode,
  base64UrlEncode,
  decodeToken,
  describeClaims,
  signToken,
  verifyToken,
} from './jwt';
import { ERROR_CODES, toError } from './jwtErrors';

const HEADER = '{"alg":"HS256","typ":"JWT"}';
const PAYLOAD = '{"sub":"usr_2041","name":"Zoë \u{1F680}"}';
const SECRET = 'your-256-bit-secret';
const material = (secret = SECRET) => ({ secret, secretEncoding: 'text', pem: '' });

const nodeSign = (alg, header, payload, secret) => {
  const input = `${Buffer.from(header).toString('base64url')}.${Buffer.from(payload).toString('base64url')}`;
  const mac = createHmac(alg.replace('HS', 'sha'), secret).update(input).digest('base64url');
  return `${input}.${mac}`;
};
const enc = (text) => Buffer.from(text).toString('base64url');

describe('base64url', () => {
  test('round-trips unicode without padding or + and /', () => {
    const text = 'Zoë \u{1F680} ???>>>';
    const encoded = base64UrlEncode(text);
    expect(encoded).toBe(Buffer.from(text).toString('base64url'));
    expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(base64UrlDecode(encoded)).toBe(text);
  });

  test('rejects standard base64, padding and impossible lengths with codes', () => {
    expect(() => base64UrlDecode('ab+/')).toThrow(/base64url/);
    expect(() => base64UrlDecode('abcd==')).toThrow(/padding/);
    expect(() => base64UrlDecode('abcde')).toThrow(/length/);
    try {
      base64UrlDecode('abcde', 'payload', 'Payload');
    } catch (error) {
      expect(toError(error)).toMatchObject({ code: 'base64url-length', part: 'payload' });
    }
  });

  test('rejects invalid UTF-8', () => {
    expect(() => base64UrlDecode(Buffer.from([0xff, 0xfe]).toString('base64url'))).toThrow(/UTF-8/);
  });
});

describe('error contract', () => {
  test('unexpected failures stay generic and carry no input', () => {
    const e = toError(new TypeError('secret=hunter2 leaked'));
    expect(e).toEqual({ code: 'unexpected', part: null, message: 'Something went wrong while processing this input.' });
    expect(ERROR_CODES).toContain('signature-mismatch');
  });
});

describe('decodeToken', () => {
  test('reports empty input', () => {
    expect(decodeToken('  ')).toMatchObject({ status: 'empty', header: null, payload: null });
  });

  test('decodes a valid token into pretty JSON that belongs to this input', () => {
    const decoded = decodeToken(nodeSign('HS256', HEADER, PAYLOAD, SECRET));
    expect(decoded.status).toBe('valid');
    expect(decoded.header.object).toEqual({ alg: 'HS256', typ: 'JWT' });
    expect(decoded.payload.object.name).toBe('Zoë \u{1F680}');
    expect(decoded.segments.signature).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  test('segment count is a structural error', () => {
    expect(decodeToken('a.b')).toMatchObject({
      status: 'malformed',
      error: { code: 'segment-count', part: 'token' },
      header: null,
      payload: null,
    });
    expect(decodeToken('abc.def.ghi').status).toBe('malformed');
  });

  test('errors name the part that failed and keep the good part', () => {
    const decoded = decodeToken(`${enc('not json')}.${enc(PAYLOAD)}.sig`);
    expect(decoded.status).toBe('malformed');
    expect(decoded.errors.header).toMatchObject({ code: 'json', part: 'header' });
    expect(decoded.errors.payload).toBeUndefined();
    expect(decoded.header).toBeNull();
    expect(decoded.payload.object.sub).toBe('usr_2041');
  });

  test('non-object JSON is rejected distinctly from invalid JSON', () => {
    expect(decodeToken(`${enc('[1]')}.${enc(PAYLOAD)}.sig`).errors.header.code).toBe('json-object');
  });

  test('whitespace policy: trims surrounding space with disclosure, rejects inner space', () => {
    const token = nodeSign('HS256', HEADER, PAYLOAD, SECRET);
    const padded = `  ${token}\n`;
    const decoded = decodeToken(padded);
    expect(decoded).toMatchObject({ status: 'valid', trimmed: true, candidate: token });
    expect(decodeToken(token).trimmed).toBe(false);
    const inner = token.replace('.', ' .');
    expect(decodeToken(inner).errors.header.code).toBe('base64url-syntax');
  });
});

describe('signToken', () => {
  test.each(['HS256', 'HS384', 'HS512'])('%s matches an independent HMAC', async (alg) => {
    const header = JSON.stringify({ alg, typ: 'JWT' });
    const result = await signToken({ headerText: header, payloadText: PAYLOAD }, material());
    expect(result.status).toBe('ready');
    expect(result.token).toBe(nodeSign(alg, header, JSON.stringify(JSON.parse(PAYLOAD)), SECRET));
  });

  test('empty drafts are neutral', async () => {
    expect(await signToken({ headerText: ' ', payloadText: '' }, material())).toEqual({ status: 'empty' });
  });

  test('refuses none, unsupported and missing algorithms', async () => {
    for (const alg of ['"none"', '"NONE"', '"RS1"', '"ES256K"', '5']) {
      const r = await signToken({ headerText: `{"alg":${alg}}`, payloadText: PAYLOAD }, material());
      expect(r).toMatchObject({ status: 'invalid', error: { code: 'unsupported-algorithm', part: 'header' } });
    }
    const missing = await signToken({ headerText: '{}', payloadText: PAYLOAD }, material());
    expect(missing.error.code).toBe('unsupported-algorithm');
  });

  test('reports each editor problem with its part', async () => {
    expect((await signToken({ headerText: HEADER, payloadText: PAYLOAD }, material(''))).error).toMatchObject({
      code: 'missing-key',
      part: 'key',
    });
    expect((await signToken({ headerText: '[]', payloadText: PAYLOAD }, material())).error).toMatchObject({
      code: 'json-object',
      part: 'header',
    });
    expect((await signToken({ headerText: HEADER, payloadText: '{' }, material())).error).toMatchObject({
      code: 'json',
      part: 'payload',
    });
  });

  test('refuses critical extensions', async () => {
    const r = await signToken({ headerText: '{"alg":"HS256","crit":["exp"]}', payloadText: PAYLOAD }, material());
    expect(r).toMatchObject({ status: 'invalid', error: { code: 'crit-unsupported' } });
  });
});

describe('verifyToken', () => {
  const token = nodeSign('HS256', HEADER, PAYLOAD, SECRET);

  test('verifies the right secret without touching the token', async () => {
    expect(await verifyToken(token, material())).toEqual({ status: 'verified', algorithm: 'HS256' });
  });

  test('wrong secret is a mismatch; the right one verifies again', async () => {
    expect(await verifyToken(token, material('other'))).toMatchObject({
      status: 'invalid',
      error: { code: 'signature-mismatch' },
    });
    expect((await verifyToken(token, material())).status).toBe('verified');
  });

  test('tampered header, payload and signature all fail', async () => {
    const [h, p, s] = token.split('.');
    const flipped = s.slice(0, -2) + (s.endsWith('AA') ? 'BB' : 'AA');
    for (const bad of [
      `${enc('{"alg":"HS256","typ":"X"}')}.${p}.${s}`,
      `${h}.${enc('{"sub":"admin"}')}.${s}`,
      `${h}.${p}.${flipped}`,
    ]) {
      expect((await verifyToken(bad, material())).status).toBe('invalid');
    }
  });

  test('missing key is unverified, not invalid', async () => {
    expect(await verifyToken(token, material(''))).toMatchObject({
      status: 'unverified',
      error: { code: 'missing-key', part: 'key' },
    });
  });

  test('alg none is never verified, whatever the signature', async () => {
    for (const sig of ['', 'abc']) {
      const r = await verifyToken(`${enc('{"alg":"none"}')}.${enc(PAYLOAD)}.${sig}`, material());
      expect(r).toMatchObject({ status: 'unsupported', error: { code: 'unsupported-algorithm' } });
    }
  });

  test('critical extensions are unsupported, even with a correct signature', async () => {
    const crit = nodeSign('HS256', '{"alg":"HS256","crit":["x"],"x":1}', PAYLOAD, SECRET);
    expect(await verifyToken(crit, material())).toMatchObject({
      status: 'unsupported',
      error: { code: 'crit-unsupported' },
    });
  });

  test('structural problems are errors, distinct from a mismatch', async () => {
    expect((await verifyToken('', material())).status).toBe('idle');
    expect(await verifyToken('x.y', material())).toMatchObject({ status: 'error', error: { code: 'segment-count' } });
    expect(await verifyToken(`${token.split('.').slice(0, 2).join('.')}.@@`, material())).toMatchObject({
      status: 'error',
      error: { code: 'signature-encoding', part: 'signature' },
    });
    expect(await verifyToken(`${token.split('.').slice(0, 2).join('.')}.`, material())).toMatchObject({
      status: 'error',
      error: { code: 'signature-encoding' },
    });
  });

  test('surrounding whitespace is trimmed; the signature covers the original segments', async () => {
    expect((await verifyToken(`\n ${token}  `, material())).status).toBe('verified');
  });

  test('never rejects: a crypto failure resolves to a generic error', async () => {
    const original = globalThis.crypto;
    Object.defineProperty(globalThis, 'crypto', { value: {}, configurable: true });
    try {
      expect(await verifyToken(token, material())).toMatchObject({
        status: 'error',
        error: { code: 'crypto-unavailable' },
      });
    } finally {
      Object.defineProperty(globalThis, 'crypto', { value: original, configurable: true });
    }
  });
});

describe('describeClaims', () => {
  const now = Date.UTC(2026, 0, 1, 12, 0, 0);
  const sec = now / 1000;
  const by = (payload) => Object.fromEntries(describeClaims(payload, now).map((c) => [c.claim, c]));

  test('describes registered claims in a fixed order with what each one means', () => {
    const rows = describeClaims({ jti: 'x', exp: sec + 60, iss: 'issuer.test', aud: ['a', 'b'], sub: 7, extra: 1 }, now);
    expect(rows.map((r) => r.claim)).toEqual(['iss', 'sub', 'aud', 'exp', 'jti']);
    expect(rows[0]).toMatchObject({ label: 'Issuer', value: 'issuer.test' });
    expect(rows[0].description).toBe('Claimed issuer: who the token says created it.');
    // No description asserts a claim as fact.
    for (const row of describeClaims({ iss: 1, sub: 1, aud: 1, exp: 1, nbf: 1, iat: 1, jti: 1 }, now)) {
      expect(row.description).toMatch(/claim|says|gives itself/i);
    }
    expect(rows[2].value).toBe('["a","b"]');
    expect(rows[1].value).toBe('7');
  });

  test('flags expired and not-yet-valid tokens', () => {
    const c = by({ iat: sec - 60, nbf: sec + 3600, exp: sec - 86400 });
    expect(c.exp.flag).toBe('expired');
    expect(c.exp.relative).toBe('yesterday');
    expect(c.nbf.flag).toBe('not yet valid');
    expect(c.iat.flag).toBeNull();
    expect(c.iat.utc).toBe('2026-01-01 11:59:00 UTC');
  });

  test('time boundaries: expiry at exactly now is expired, not-before at exactly now is valid', () => {
    expect(by({ exp: sec }).exp.flag).toBe('expired');
    expect(by({ exp: sec + 1 }).exp.flag).toBeNull();
    expect(by({ nbf: sec }).nbf.flag).toBeNull();
    expect(by({ nbf: sec + 1 }).nbf.flag).toBe('not yet valid');
  });

  test('non-numeric and out-of-range times are shown as written, never as a date', () => {
    const c = by({ exp: 'soon', iat: 1e20, nbf: null });
    expect(c.exp).toMatchObject({ flag: 'not a number', value: 'soon' });
    expect(c.iat).toMatchObject({ flag: 'out of range', value: '100000000000000000000' });
    expect(c.nbf).toMatchObject({ flag: 'not a number', value: 'null' });
    expect(c.exp.utc).toBeUndefined();
    expect(describeClaims(null, now)).toEqual([]);
  });

  test('does not read inherited properties', () => {
    expect(describeClaims(Object.create({ exp: 1 }), now)).toEqual([]);
  });
});

describe('HMAC secret formats', () => {
  // 32 bytes that are not valid UTF-8, so they cannot survive a text round trip.
  const binary = Buffer.from(Array.from({ length: 32 }, (_, i) => 0xff - i * 7));
  const binarySecret = binary.toString('base64url');
  const b64 = (secret = binarySecret) => ({ secret, secretEncoding: 'base64url', pem: '' });

  const nodeSignBytes = (alg, header, payload, key) => {
    const input = `${enc(header)}.${enc(payload)}`;
    return `${input}.${createHmac(alg.replace('HS', 'sha'), key).update(input).digest('base64url')}`;
  };

  test('the binary secret is not representable as UTF-8 text', () => {
    expect(() => new TextDecoder('utf-8', { fatal: true }).decode(binary)).toThrow();
  });

  test.each(['HS256', 'HS384', 'HS512'])('%s signs and verifies with raw secret bytes', async (alg) => {
    const header = JSON.stringify({ alg, typ: 'JWT' });
    const signed = await signToken({ headerText: header, payloadText: PAYLOAD }, b64());
    expect(signed.token).toBe(nodeSignBytes(alg, header, JSON.stringify(JSON.parse(PAYLOAD)), binary));
    expect((await verifyToken(signed.token, b64())).status).toBe('verified');
  });

  test('a known token verifies in text and in base64url when the bytes match', async () => {
    const token = nodeSign('HS256', HEADER, PAYLOAD, SECRET);
    expect((await verifyToken(token, material())).status).toBe('verified');
    expect((await verifyToken(token, b64(Buffer.from(SECRET).toString('base64url')))).status).toBe('verified');
    // The same characters read as text or as base64url are different keys.
    expect((await verifyToken(token, { ...material(), secretEncoding: 'base64url' })).status).not.toBe('verified');
  });

  test('invalid base64url is a format error, not a signature failure', async () => {
    const token = nodeSign('HS256', HEADER, PAYLOAD, SECRET);
    for (const bad of ['has space', 'pad==', 'a+b/', 'abcde']) {
      expect(await verifyToken(token, b64(bad))).toMatchObject({
        status: 'error',
        error: { code: 'secret-encoding', part: 'key' },
      });
    }
    expect(await signToken({ headerText: HEADER, payloadText: PAYLOAD }, b64('pad=='))).toMatchObject({
      status: 'invalid',
      error: { code: 'secret-encoding' },
    });
  });

  test('an empty secret is missing in both formats', async () => {
    const token = nodeSign('HS256', HEADER, PAYLOAD, SECRET);
    expect((await verifyToken(token, b64(''))).status).toBe('unverified');
  });
});

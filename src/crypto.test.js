/** @jest-environment node */
// Interoperability: Node's OpenSSL is the independent implementation. It signs tokens this app verifies,
// and verifies tokens this app signs, for every algorithm, plus the key and format rejections.
import { createPublicKey, createSign, createVerify, generateKeyPairSync, createHmac } from 'crypto';
import { signToken, verifyToken } from './jwt';

const enc = (v) => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');
const PAYLOAD = { sub: 'usr_2041', name: 'Ada Lovelace' };
const pem = (key, type) => key.export({ type, format: 'pem' });

const RSA = generateKeyPairSync('rsa', { modulusLength: 2048 });
const RSA_SMALL = generateKeyPairSync('rsa', { modulusLength: 1024 });
const RSA_OTHER = generateKeyPairSync('rsa', { modulusLength: 2048 });
const EC = {
  'P-256': generateKeyPairSync('ec', { namedCurve: 'P-256' }),
  'P-384': generateKeyPairSync('ec', { namedCurve: 'P-384' }),
  'P-521': generateKeyPairSync('ec', { namedCurve: 'P-521' }),
};
const EC_OTHER = generateKeyPairSync('ec', { namedCurve: 'P-256' });

const CASES = [
  ['RS256', 'sha256', () => RSA, () => RSA_OTHER],
  ['RS384', 'sha384', () => RSA, () => RSA_OTHER],
  ['RS512', 'sha512', () => RSA, () => RSA_OTHER],
  ['ES256', 'sha256', () => EC['P-256'], () => EC_OTHER],
  ['ES384', 'sha384', () => EC['P-384'], () => generateKeyPairSync('ec', { namedCurve: 'P-384' })],
  ['ES512', 'sha512', () => EC['P-521'], () => generateKeyPairSync('ec', { namedCurve: 'P-521' })],
];

const sign = (alg, hash, privateKey, header = { alg, typ: 'JWT' }, payload = PAYLOAD) => {
  const input = `${enc(header)}.${enc(payload)}`;
  const options = alg.startsWith('ES') ? { key: privateKey, dsaEncoding: 'ieee-p1363' } : privateKey;
  return `${input}.${createSign(hash).update(input).sign(options).toString('base64url')}`;
};
const pubMaterial = (pair) => ({ secret: '', secretEncoding: 'text', pem: pem(pair.publicKey, 'spki') });
const privMaterial = (pair) => ({ secret: '', secretEncoding: 'text', pem: pem(pair.privateKey, 'pkcs8') });

describe.each(CASES)('%s', (alg, hash, pair, other) => {
  test('verifies an independently signed token', async () => {
    const token = sign(alg, hash, pair().privateKey);
    expect(await verifyToken(token, pubMaterial(pair()))).toEqual({ status: 'verified', algorithm: alg });
  });

  test('rejects a wrong key and tampered header, payload and signature', async () => {
    const token = sign(alg, hash, pair().privateKey);
    const [h, p, s] = token.split('.');
    expect((await verifyToken(token, pubMaterial(other()))).status).toBe('invalid');
    const flipped = `${s.slice(0, 10)}${s[10] === 'A' ? 'B' : 'A'}${s.slice(11)}`;
    for (const bad of [
      `${enc({ alg, typ: 'X' })}.${p}.${s}`,
      `${h}.${enc({ sub: 'admin' })}.${s}`,
      `${h}.${p}.${flipped}`,
    ]) {
      expect((await verifyToken(bad, pubMaterial(pair()))).status).toBe('invalid');
    }
  });

  test('signs a token an independent implementation verifies', async () => {
    const header = JSON.stringify({ alg, typ: 'JWT' });
    const result = await signToken(
      { headerText: header, payloadText: JSON.stringify(PAYLOAD) },
      privMaterial(pair()),
    );
    expect(result.status).toBe('ready');
    const [h, p, s] = result.token.split('.');
    const options = alg.startsWith('ES') ? { key: pair().publicKey, dsaEncoding: 'ieee-p1363' } : pair().publicKey;
    expect(createVerify(hash).update(`${h}.${p}`).verify(options, Buffer.from(s, 'base64url'))).toBe(true);
    expect((await verifyToken(result.token, pubMaterial(pair()))).status).toBe('verified');
  });
});

describe('published vector: RFC 7515 appendix A.3 (ES256)', () => {
  const token =
    'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q';
  const jwk = {
    kty: 'EC',
    crv: 'P-256',
    x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
    y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
  };
  const material = {
    secret: '',
    secretEncoding: 'text',
    pem: createPublicKey({ key: jwk, format: 'jwk' }).export({ type: 'spki', format: 'pem' }),
  };

  test('verifies', async () => {
    expect(await verifyToken(token, material)).toEqual({ status: 'verified', algorithm: 'ES256' });
  });
  test('rejects when the payload changes', async () => {
    const [h, , s] = token.split('.');
    expect((await verifyToken(`${h}.${enc({ iss: 'mallory' })}.${s}`, material)).status).toBe('invalid');
  });
});

describe('ECDSA signature format', () => {
  test('a DER-encoded signature is a format error, not a mismatch', async () => {
    const input = `${enc({ alg: 'ES256' })}.${enc(PAYLOAD)}`;
    const der = createSign('sha256').update(input).sign(EC['P-256'].privateKey).toString('base64url');
    expect(await verifyToken(`${input}.${der}`, pubMaterial(EC['P-256']))).toMatchObject({
      status: 'error',
      error: { code: 'signature-encoding', part: 'signature' },
    });
  });

  test.each([['ES256', 'P-256', 64], ['ES384', 'P-384', 96], ['ES512', 'P-521', 132]])(
    '%s produces fixed-width raw R||S of %i bytes',
    async (alg, curve, bytes) => {
      const r = await signToken(
        { headerText: JSON.stringify({ alg }), payloadText: JSON.stringify(PAYLOAD) },
        privMaterial(EC[curve]),
      );
      expect(Buffer.from(r.token.split('.')[2], 'base64url')).toHaveLength(bytes);
    },
  );
});

describe('key problems are specific and never succeed', () => {
  const rsToken = () => sign('RS256', 'sha256', RSA.privateKey);
  const esToken = () => sign('ES256', 'sha256', EC['P-256'].privateKey);
  const code = async (token, material) => (await verifyToken(token, material)).error?.code;

  test('missing key is unverified', async () => {
    expect(await verifyToken(rsToken(), { secret: '', secretEncoding: 'text', pem: '' })).toMatchObject({
      status: 'unverified',
      error: { code: 'missing-key' },
    });
  });

  test('RSA keys under 2048 bits are rejected for verifying and signing', async () => {
    const token = sign('RS256', 'sha256', RSA_SMALL.privateKey);
    expect(await code(token, pubMaterial(RSA_SMALL))).toBe('key-size');
    const r = await signToken(
      { headerText: '{"alg":"RS256"}', payloadText: '{}' },
      privMaterial(RSA_SMALL),
    );
    expect(r).toMatchObject({ status: 'invalid', error: { code: 'key-size' } });
  });

  test('key type and curve must match the algorithm', async () => {
    expect(await code(esToken(), pubMaterial(RSA))).toBe('key-type');
    expect(await code(rsToken(), pubMaterial(EC['P-256']))).toBe('key-type');
    const wrongCurve = await verifyToken(esToken(), pubMaterial(EC['P-384']));
    expect(wrongCurve).toMatchObject({ status: 'error', error: { code: 'key-curve' } });
    expect(wrongCurve.error.message).toMatch(/P-384.*ES256 needs P-256/);
  });

  test('public keys verify and private keys sign, not the other way round', async () => {
    expect(await code(rsToken(), privMaterial(RSA))).toBe('key-type');
    const r = await signToken({ headerText: '{"alg":"RS256"}', payloadText: '{}' }, pubMaterial(RSA));
    expect(r).toMatchObject({ status: 'invalid', error: { code: 'key-type' } });
  });

  test('unsupported PEM containers get an actionable message', async () => {
    const material = (p) => ({ secret: '', secretEncoding: 'text', pem: p });
    const encrypted = '-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----';
    const result = await signToken({ headerText: '{"alg":"RS256"}', payloadText: '{}' }, material(encrypted));
    expect(result.error).toMatchObject({ code: 'key-format' });
    expect(result.error.message).toMatch(/Encrypted/);

    const pkcs1 = RSA.privateKey.export({ type: 'pkcs1', format: 'pem' });
    const r2 = await signToken({ headerText: '{"alg":"RS256"}', payloadText: '{}' }, material(pkcs1));
    expect(r2.error.message).toMatch(/openssl pkcs8/);

    expect(await code(rsToken(), material('not a key'))).toBe('key-format');
    expect(await code(rsToken(), material('-----BEGIN PUBLIC KEY-----\n!!!\n-----END PUBLIC KEY-----'))).toBe('key-format');
    expect(
      await code(rsToken(), material('-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----')),
    ).toBe('key-format');
    expect(await code(rsToken(), material(`${pem(RSA.publicKey, 'spki')}${pem(RSA.publicKey, 'spki')}`))).toBe('key-format');
  });

  test('errors never echo key material', async () => {
    const secretish = 'SUPERSECRETKEYBODY1234';
    const r = await verifyToken(rsToken(), {
      secret: '',
      secretEncoding: 'text',
      pem: `-----BEGIN PUBLIC KEY-----\n${secretish}\n-----END PUBLIC KEY-----`,
    });
    expect(JSON.stringify(r)).not.toContain(secretish);
  });
});

describe('algorithm confusion', () => {
  test('a public key used as an HMAC secret never verifies an HS256 token', async () => {
    const publicPem = pem(RSA.publicKey, 'spki');
    const input = `${enc({ alg: 'HS256' })}.${enc(PAYLOAD)}`;
    const forged = `${input}.${createHmac('sha256', publicPem).update(input).digest('base64url')}`;
    // Only the PEM field is set, as it would be when verifying a genuine RS256 token.
    const material = { secret: '', secretEncoding: 'text', pem: publicPem };
    expect(await verifyToken(forged, material)).toMatchObject({ status: 'unverified', error: { code: 'missing-key' } });
    // Even with the key text typed into the secret field the user asked for HMAC; that is their explicit key.
    // The token's alg decides the family and RS tokens never read the secret field.
    const rs = sign('RS256', 'sha256', RSA.privateKey);
    expect(await verifyToken(rs, { secret: publicPem, secretEncoding: 'text', pem: '' })).toMatchObject({
      status: 'unverified',
    });
  });

  test('alg none and unlisted algorithms stay unsupported', async () => {
    for (const alg of ['none', 'PS256', 'EdDSA', 'RS1']) {
      const t = `${enc({ alg })}.${enc(PAYLOAD)}.c2ln`;
      expect((await verifyToken(t, pubMaterial(RSA))).status).toBe('unsupported');
    }
  });
});

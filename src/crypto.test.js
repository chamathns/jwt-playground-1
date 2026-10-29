// @vitest-environment node
// Interoperability: Node's OpenSSL is the independent implementation. It signs tokens this app verifies,
// and verifies tokens this app signs, for every algorithm, plus the key and format rejections.
import {
  constants,
  createHmac,
  createPublicKey,
  createSign,
  createVerify,
  generateKeyPairSync,
  sign as signRaw,
  verify as verifyRaw,
} from 'crypto';
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
    const legacyEncrypted =
      '-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n-----END RSA PRIVATE KEY-----';
    expect((await signToken({ headerText: '{"alg":"RS256"}', payloadText: '{}' }, material(legacyEncrypted))).error).toMatchObject({
      code: 'key-format',
    });
    expect((await verifyToken(rsToken(), material('-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----'))).error.message).toMatch(/openssl x509/);
    const result = await signToken({ headerText: '{"alg":"RS256"}', payloadText: '{}' }, material(encrypted));
    expect(result.error).toMatchObject({ code: 'key-format' });
    expect(result.error.message).toMatch(/Encrypted/);

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
    for (const alg of ['none', 'RS1', 'ES256K', 'HS1', 'Ed448']) {
      const t = `${enc({ alg })}.${enc(PAYLOAD)}.c2ln`;
      expect((await verifyToken(t, pubMaterial(RSA))).status).toBe('unsupported');
    }
  });
});

const PAYLOAD_TEXT = JSON.stringify(PAYLOAD);
const signed = (alg, privateMaterial) => signToken({ headerText: JSON.stringify({ alg }), payloadText: PAYLOAD_TEXT }, privateMaterial);
const splitToken = (token) => {
  const [h, p, s] = token.split('.');
  return { input: `${h}.${p}`, signature: Buffer.from(s, 'base64url') };
};

describe.each([
  ['PS256', 'sha256', 32],
  ['PS384', 'sha384', 48],
  ['PS512', 'sha512', 64],
])('%s (RSA-PSS)', (alg, hash, saltLength) => {
  const options = (key) => ({ key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength });

  test('verifies an independently signed token', async () => {
    const input = `${enc({ alg, typ: 'JWT' })}.${enc(PAYLOAD)}`;
    const token = `${input}.${createSign(hash).update(input).sign(options(RSA.privateKey)).toString('base64url')}`;
    expect(await verifyToken(token, pubMaterial(RSA))).toEqual({ status: 'verified', algorithm: alg });
    expect((await verifyToken(token, pubMaterial(RSA_OTHER))).status).toBe('invalid');
  });

  test('signs a token an independent implementation verifies, with the digest-length salt', async () => {
    const result = await signed(alg, privMaterial(RSA));
    expect(result.status).toBe('ready');
    const { input, signature } = splitToken(result.token);
    expect(createVerify(hash).update(input).verify(options(RSA.publicKey), signature)).toBe(true);
    expect((await verifyToken(result.token, pubMaterial(RSA))).status).toBe('verified');
  });

  test('is not interchangeable with RS256 for the same key', async () => {
    const result = await signed(alg, privMaterial(RSA));
    const asRs256 = `${enc({ alg: 'RS256' })}.${result.token.split('.').slice(1).join('.')}`;
    expect((await verifyToken(asRs256, pubMaterial(RSA))).status).toBe('invalid');
  });

  test('rejects tampering and RSA keys under 2048 bits', async () => {
    const result = await signed(alg, privMaterial(RSA));
    const [h, , s] = result.token.split('.');
    expect((await verifyToken(`${h}.${enc({ sub: 'admin' })}.${s}`, pubMaterial(RSA))).status).toBe('invalid');
    const small = await signToken({ headerText: JSON.stringify({ alg }), payloadText: '{}' }, privMaterial(RSA_SMALL));
    expect(small).toMatchObject({ status: 'invalid', error: { code: 'key-size' } });
  });
});

describe('EdDSA (Ed25519)', () => {
  const ED = generateKeyPairSync('ed25519');
  const ED_OTHER = generateKeyPairSync('ed25519');

  test('verifies an independently signed token', async () => {
    const input = `${enc({ alg: 'EdDSA', typ: 'JWT' })}.${enc(PAYLOAD)}`;
    const token = `${input}.${signRaw(null, Buffer.from(input), ED.privateKey).toString('base64url')}`;
    expect(await verifyToken(token, pubMaterial(ED))).toEqual({ status: 'verified', algorithm: 'EdDSA' });
    expect((await verifyToken(token, pubMaterial(ED_OTHER))).status).toBe('invalid');
    const [h, , s] = token.split('.');
    expect((await verifyToken(`${h}.${enc({ sub: 'admin' })}.${s}`, pubMaterial(ED))).status).toBe('invalid');
  });

  test('signs a token an independent implementation verifies', async () => {
    const result = await signed('EdDSA', privMaterial(ED));
    expect(result.status).toBe('ready');
    const { input, signature } = splitToken(result.token);
    expect(signature).toHaveLength(64);
    expect(verifyRaw(null, Buffer.from(input), ED.publicKey, signature)).toBe(true);
  });

  test('key types are told apart from RSA and EC in both directions', async () => {
    const edToken = `${enc({ alg: 'EdDSA' })}.${enc(PAYLOAD)}.${Buffer.alloc(64).toString('base64url')}`;
    for (const pair of [RSA, EC['P-256']]) {
      expect(await verifyToken(edToken, pubMaterial(pair))).toMatchObject({ error: { code: 'key-type' } });
    }
    const rsToken = sign('RS256', 'sha256', RSA.privateKey);
    const esToken = sign('ES256', 'sha256', EC['P-256'].privateKey);
    const message = (await verifyToken(rsToken, pubMaterial(ED))).error;
    expect(message).toMatchObject({ code: 'key-type' });
    expect(message.message).toMatch(/Ed25519 key, but RS256 needs an RSA key/);
    expect((await verifyToken(esToken, pubMaterial(ED))).error.code).toBe('key-type');
  });

  test('a wrong signature length is an encoding error, not a mismatch', async () => {
    const token = `${enc({ alg: 'EdDSA' })}.${enc(PAYLOAD)}.${Buffer.alloc(63).toString('base64url')}`;
    expect(await verifyToken(token, pubMaterial(ED))).toMatchObject({ error: { code: 'signature-encoding' } });
  });

  test('a browser without Ed25519 gets an explanation, not a key-format error', async () => {
    const real = crypto;
    const subtle = {
      importKey: (...args) => {
        if (args[2] && args[2].name === 'Ed25519') {
          return Promise.reject(Object.assign(new Error('x'), { name: 'NotSupportedError' }));
        }
        return real.subtle.importKey(...args);
      },
    };
    Object.defineProperty(globalThis, 'crypto', { value: { subtle }, configurable: true });
    try {
      const token = `${enc({ alg: 'EdDSA' })}.${enc(PAYLOAD)}.${Buffer.alloc(64).toString('base64url')}`;
      const r = await verifyToken(token, pubMaterial(ED));
      expect(r).toMatchObject({ status: 'error', error: { code: 'crypto-unavailable' } });
      expect(r.error.message).toMatch(/does not support EdDSA/);
    } finally {
      Object.defineProperty(globalThis, 'crypto', { value: real, configurable: true });
    }
  });
});

describe('PKCS#1 and SEC1 key formats', () => {
  const pkcs1Private = (pair) => ({ secret: '', secretEncoding: 'text', pem: pair.privateKey.export({ type: 'pkcs1', format: 'pem' }) });
  const pkcs1Public = (pair) => ({ secret: '', secretEncoding: 'text', pem: pair.publicKey.export({ type: 'pkcs1', format: 'pem' }) });
  const sec1Private = (pair) => ({ secret: '', secretEncoding: 'text', pem: pair.privateKey.export({ type: 'sec1', format: 'pem' }) });

  test.each(['RS256', 'PS256'])('%s signs with a PKCS#1 private key and verifies with a PKCS#1 public key', async (alg) => {
    const result = await signed(alg, pkcs1Private(RSA));
    expect(result.status).toBe('ready');
    const viaPkcs1 = await verifyToken(result.token, pkcs1Public(RSA));
    expect(viaPkcs1.status).toBe('verified');
    // The same key in PKCS#8 / SPKI gives the same answer, so the re-wrapping changed no key bytes.
    expect((await verifyToken(result.token, pubMaterial(RSA))).status).toBe('verified');
    const { input, signature } = splitToken(result.token);
    const verifier = createVerify(alg === 'RS256' ? 'sha256' : 'sha256');
    const opts = alg === 'PS256' ? { key: RSA.publicKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 } : RSA.publicKey;
    expect(verifier.update(input).verify(opts, signature)).toBe(true);
  });

  test.each([
    ['ES256', 'P-256'],
    ['ES384', 'P-384'],
    ['ES512', 'P-521'],
  ])('%s signs with a SEC1 private key', async (alg, curve) => {
    const result = await signed(alg, sec1Private(EC[curve]));
    expect(result.status).toBe('ready');
    const { input, signature } = splitToken(result.token);
    const hash = `sha${alg.slice(2)}`;
    expect(createVerify(hash).update(input).verify({ key: EC[curve].publicKey, dsaEncoding: 'ieee-p1363' }, signature)).toBe(true);
    expect((await verifyToken(result.token, pubMaterial(EC[curve]))).status).toBe('verified');
  });

  test('the key kind is still checked after re-wrapping', async () => {
    const esToken = sign('ES256', 'sha256', EC['P-256'].privateKey);
    expect((await verifyToken(esToken, pkcs1Public(RSA))).error.code).toBe('key-type');
    const rsResult = await signed('RS256', sec1Private(EC['P-256']));
    expect(rsResult).toMatchObject({ status: 'invalid', error: { code: 'key-type' } });
    const wrongCurve = await signed('ES384', sec1Private(EC['P-256']));
    expect(wrongCurve).toMatchObject({ status: 'invalid', error: { code: 'key-curve' } });
  });

  test('public and private keys are not interchangeable in these formats either', async () => {
    const rsToken = sign('RS256', 'sha256', RSA.privateKey);
    expect((await verifyToken(rsToken, pkcs1Private(RSA))).error.code).toBe('key-type');
    expect((await verifyToken(rsToken, sec1Private(EC['P-256']))).error.code).toBe('key-type');
    const r = await signed('RS256', pkcs1Public(RSA));
    expect(r).toMatchObject({ status: 'invalid', error: { code: 'key-type' } });
  });

  test('malformed DER inside these labels is a key-format error, never a crash or success', async () => {
    const wrap = (label, bytes) => ({
      secret: '',
      secretEncoding: 'text',
      pem: `-----BEGIN ${label}-----\n${Buffer.from(bytes).toString('base64')}\n-----END ${label}-----`,
    });
    const good = Buffer.from(RSA.privateKey.export({ type: 'pkcs1', format: 'der' }));
    const cases = [
      ['RSA PRIVATE KEY', [0x30, 0x03, 0x02, 0x01, 0x00]],
      ['RSA PRIVATE KEY', good.subarray(0, good.length - 10)],
      ['RSA PRIVATE KEY', Buffer.concat([good, Buffer.from([0])])],
      ['RSA PRIVATE KEY', [0x31, 0x00]],
      ['EC PRIVATE KEY', [0x30, 0x00]],
      ['EC PRIVATE KEY', [0x30, 0x84, 0xff, 0xff, 0xff, 0xff]],
    ];
    for (const [label, bytes] of cases) {
      const r = await signToken({ headerText: '{"alg":"RS256"}', payloadText: '{}' }, wrap(label, bytes));
      expect(r).toMatchObject({ status: 'invalid', error: { code: 'key-format' } });
    }
    const pub = await verifyToken(sign('RS256', 'sha256', RSA.privateKey), wrap('RSA PUBLIC KEY', [0x30, 0x02, 0x02, 0x00]));
    expect(pub.error.code).toBe('key-format');
  });
});

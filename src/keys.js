import { base64UrlDecodeBytes } from './base64url';
import { JwtError } from './jwtErrors';
import { pkcs1PrivateToPkcs8, pkcs1PublicToSpki, sec1ToPkcs8 } from './der';

// The explicit algorithm registry. Nothing outside it is ever signed or verified, and there is no fallback.
// `signatureBytes` is the fixed width of a JOSE ECDSA signature (raw R || S, never ASN.1 DER).
export const ALGORITHMS = {
  HS256: { family: 'hmac', hash: 'SHA-256' },
  HS384: { family: 'hmac', hash: 'SHA-384' },
  HS512: { family: 'hmac', hash: 'SHA-512' },
  RS256: { family: 'rsa', hash: 'SHA-256' },
  RS384: { family: 'rsa', hash: 'SHA-384' },
  RS512: { family: 'rsa', hash: 'SHA-512' },
  ES256: { family: 'ec', hash: 'SHA-256', curve: 'P-256', signatureBytes: 64 },
  ES384: { family: 'ec', hash: 'SHA-384', curve: 'P-384', signatureBytes: 96 },
  ES512: { family: 'ec', hash: 'SHA-512', curve: 'P-521', signatureBytes: 132 },
  // JWA fixes the RSA-PSS salt length to the digest length.
  PS256: { family: 'rsapss', hash: 'SHA-256', saltLength: 32 },
  PS384: { family: 'rsapss', hash: 'SHA-384', saltLength: 48 },
  PS512: { family: 'rsapss', hash: 'SHA-512', saltLength: 64 },
  // EdDSA means Ed25519 here. Ed448 has no Web Crypto support in current browsers.
  EdDSA: { family: 'eddsa', curve: 'Ed25519', signatureBytes: 64 },
};

export const FAMILY_LABELS = { hmac: 'HMAC', rsa: 'RSA', rsapss: 'RSA-PSS', ec: 'ECDSA', eddsa: 'EdDSA' };

const MIN_RSA_BITS = 2048;
const EC_CURVES = ['P-256', 'P-384', 'P-521'];
const isRsaFamily = (family) => family === 'rsa' || family === 'rsapss';

/** The registry entry for an algorithm name, or null. Never indexes with a value that is not an own string key. */
export const algorithmSpec = (alg) =>
  typeof alg === 'string' && Object.prototype.hasOwnProperty.call(ALGORITHMS, alg) ? ALGORITHMS[alg] : null;

export const isSupportedAlgorithm = (alg) =>
  typeof alg === 'string' && Object.prototype.hasOwnProperty.call(ALGORITHMS, alg);

export function getSubtle() {
  const subtle = typeof crypto !== 'undefined' ? crypto.subtle : undefined;
  if (!subtle) {
    throw new JwtError(
      'crypto-unavailable',
      'key',
      'Web Crypto is unavailable. Open this page over HTTPS or on localhost in a current browser.',
    );
  }
  return subtle;
}

const encoder = new TextEncoder();

// RFC 7518 section 3.2: an HMAC key must be at least as long as the hash output.
export const MIN_HMAC_BYTES = { HS256: 32, HS384: 48, HS512: 64 };

// Keys printed in public documentation and examples. Anyone can sign with these.
export const PUBLISHED_EXAMPLE_SECRETS = ['your-256-bit-secret'];

/** 64 random bytes as base64url text: a key nobody else has, long enough for every HMAC algorithm. */
export function randomSecret() {
  const bytes = crypto.getRandomValues(new Uint8Array(64));
  let binary = '';
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Advice about the key for an HMAC algorithm. Never blocks: people legitimately check tokens made with short
 * keys. Returns [{ code, message }].
 */
export function keyWarnings(alg, material) {
  const spec = algorithmSpec(alg);
  if (!spec || spec.family !== 'hmac' || !material.secret) return [];
  let bytes;
  try {
    bytes = secretBytes(material);
  } catch {
    return []; // an invalid encoding is reported as an error, not a warning
  }
  const warnings = [];
  const matches = (known) => {
    const expected = encoder.encode(known);
    return bytes.length === expected.length && bytes.every((b, i) => b === expected[i]);
  };
  if (PUBLISHED_EXAMPLE_SECRETS.some(matches)) {
    warnings.push({
      code: 'known-key',
      message: 'This is the published example key. Anyone can sign tokens with it. Use it only to try the tool.',
    });
  }
  if (bytes.length < MIN_HMAC_BYTES[alg]) {
    warnings.push({
      code: 'weak-key',
      message: `This key is ${bytes.length} bytes. ${alg} needs at least ${MIN_HMAC_BYTES[alg]} bytes (RFC 7518 section 3.2); shorter keys can be guessed.`,
    });
  }
  return warnings;
}

/** Plain text becomes UTF-8 bytes. Base64URL is decoded straight to bytes, so binary secrets work. */
export function secretBytes({ secret, secretEncoding }) {
  if (!secret) throw new JwtError('missing-key', 'key', 'Enter a secret to continue.');
  if (secretEncoding === 'base64url') {
    try {
      return base64UrlDecodeBytes(secret, 'key', 'Secret');
    } catch (error) {
      throw new JwtError('secret-encoding', 'key', error.message);
    }
  }
  return encoder.encode(secret);
}

const PEM_BLOCK = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/g;

const NEXT_STEPS = {
  'ENCRYPTED PRIVATE KEY': 'Encrypted keys are not supported. Use an unencrypted test key.',
  CERTIFICATE: 'Certificates are not supported. Extract the public key: openssl x509 -pubkey -noout -in cert.pem',
};

// What each PEM label holds and how to turn it into something Web Crypto imports (SPKI or PKCS#8).
const PUBLIC_LABELS = { 'PUBLIC KEY': (der) => der, 'RSA PUBLIC KEY': pkcs1PublicToSpki };
const PRIVATE_LABELS = { 'PRIVATE KEY': (der) => der, 'RSA PRIVATE KEY': pkcs1PrivateToPkcs8, 'EC PRIVATE KEY': sec1ToPkcs8 };

function decodePemBody(body) {
  if (/[:]/.test(body)) {
    throw new JwtError('key-format', 'key', 'PEM headers (such as encryption info) are not supported.');
  }
  const compact = body.replace(/\s+/g, '');
  if (!compact || !/^[A-Za-z0-9+/]+={0,2}$/.test(compact) || compact.length % 4 !== 0) {
    throw new JwtError('key-format', 'key', 'The key body is not valid base64.');
  }
  const binary = atob(compact);
  const der = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) der[i] = binary.charCodeAt(i);
  return der;
}

function readPem(text, usage) {
  const verifying = usage === 'verify';
  const accepted = verifying ? PUBLIC_LABELS : PRIVATE_LABELS;
  const blocks = [...text.matchAll(PEM_BLOCK)];
  if (blocks.length === 0) {
    throw new JwtError(
      'key-format',
      'key',
      `Not a PEM key. Expected a block that starts with -----BEGIN ${verifying ? 'PUBLIC' : 'PRIVATE'} KEY-----.`,
    );
  }
  if (blocks.length > 1) {
    throw new JwtError('key-format', 'key', 'Paste a single PEM block, not several.');
  }
  const [, label, body] = blocks[0];

  if (Object.prototype.hasOwnProperty.call(accepted, label)) {
    return accepted[label](decodePemBody(body));
  }
  if (verifying && label.endsWith('PRIVATE KEY') && label !== 'ENCRYPTED PRIVATE KEY') {
    throw new JwtError('key-type', 'key', 'Verification needs a public key (BEGIN PUBLIC KEY). This is a private key.');
  }
  if (!verifying && label.endsWith('PUBLIC KEY')) {
    throw new JwtError('key-type', 'key', 'Signing needs a private key (BEGIN PRIVATE KEY). This is a public key.');
  }
  throw new JwtError(
    'key-format',
    'key',
    NEXT_STEPS[label] ||
      `PEM type "${label}" is not supported. Use ${verifying ? 'a public key (BEGIN PUBLIC KEY or BEGIN RSA PUBLIC KEY)' : 'an unencrypted private key (BEGIN PRIVATE KEY, BEGIN RSA PRIVATE KEY or BEGIN EC PRIVATE KEY)'}.`,
  );
}

const importParams = ({ family, hash, curve }) => {
  if (family === 'rsa') return { name: 'RSASSA-PKCS1-v1_5', hash };
  if (family === 'rsapss') return { name: 'RSA-PSS', hash };
  if (family === 'eddsa') return { name: 'Ed25519' };
  return { name: 'ECDSA', namedCurve: curve };
};

const requirement = (alg, spec) => {
  if (isRsaFamily(spec.family)) return `${alg} needs an RSA key`;
  if (spec.family === 'eddsa') return `${alg} needs an Ed25519 key`;
  return `${alg} needs an EC key on ${spec.curve}`;
};

/** Work out what a key that failed to import actually is, to give a precise message. */
async function describeKey(subtle, format, der, usage) {
  try {
    await subtle.importKey(format, der, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, [usage]);
    return { kind: 'rsa' };
  } catch {
    // not RSA
  }
  for (const curve of EC_CURVES) {
    try {
      // eslint-disable-next-line no-await-in-loop
      await subtle.importKey(format, der, { name: 'ECDSA', namedCurve: curve }, false, [usage]);
      return { kind: 'ec', curve };
    } catch {
      // not this curve
    }
  }
  try {
    await subtle.importKey(format, der, { name: 'Ed25519' }, false, [usage]);
    return { kind: 'okp' };
  } catch {
    return null;
  }
}

const KIND_NAMES = { rsa: 'an RSA key', okp: 'an Ed25519 key' };

async function importPemKey(alg, material, usage) {
  const spec = ALGORITHMS[alg];
  const subtle = getSubtle();
  const text = (material.pem || '').trim();
  if (!text) {
    throw new JwtError(
      'missing-key',
      'key',
      usage === 'verify' ? 'Paste a public key (PEM) to continue.' : 'Paste a private key (PEM) to continue.',
    );
  }
  const der = readPem(text, usage);
  const format = usage === 'verify' ? 'spki' : 'pkcs8';

  let key;
  try {
    key = await subtle.importKey(format, der, importParams(spec), false, [usage]);
  } catch (error) {
    if (error && error.name === 'NotSupportedError') {
      throw new JwtError(
        'crypto-unavailable',
        'key',
        `This browser does not support ${alg} in Web Crypto. Try a current Chrome, Edge, Firefox or Safari.`,
      );
    }
    const actual = await describeKey(subtle, format, der, usage);
    if (actual?.kind === 'ec' && spec.family === 'ec') {
      throw new JwtError('key-curve', 'key', `This key is on ${actual.curve}, but ${alg} needs ${spec.curve}.`);
    }
    if (actual) {
      const have = actual.kind === 'ec' ? `an EC key on ${actual.curve}` : KIND_NAMES[actual.kind];
      throw new JwtError('key-type', 'key', `This is ${have}, but ${requirement(alg, spec)}.`);
    }
    throw new JwtError(
      'key-format',
      'key',
      `The key could not be read. It must be a valid ${usage === 'verify' ? 'public' : 'private'} key for ${alg}.`,
    );
  }
  if (isRsaFamily(spec.family) && key.algorithm.modulusLength < MIN_RSA_BITS) {
    throw new JwtError(
      'key-size',
      'key',
      `This RSA key is ${key.algorithm.modulusLength} bits. At least ${MIN_RSA_BITS} bits are required.`,
    );
  }
  return key;
}

/**
 * Import key material for one operation ('sign' or 'verify'). The algorithm decides which field is read:
 * HMAC reads only the secret and RSA/ECDSA read only the PEM, so a public key can never be reused as an
 * HMAC secret (the classic algorithm-confusion attack).
 */
export async function importKey(alg, material, usage) {
  const spec = ALGORITHMS[alg];
  if (spec.family === 'hmac') {
    return getSubtle().importKey('raw', secretBytes(material), { name: 'HMAC', hash: spec.hash }, false, [usage]);
  }
  return importPemKey(alg, material, usage);
}

export function signParams(alg) {
  const { family, hash } = ALGORITHMS[alg];
  if (family === 'hmac') return { name: 'HMAC' };
  if (family === 'rsa') return { name: 'RSASSA-PKCS1-v1_5' };
  if (family === 'rsapss') return { name: 'RSA-PSS', saltLength: ALGORITHMS[alg].saltLength };
  if (family === 'eddsa') return { name: 'Ed25519' };
  return { name: 'ECDSA', hash };
}

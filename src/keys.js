import { base64UrlDecodeBytes } from './base64url';
import { JwtError } from './jwtErrors';

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
};

const MIN_RSA_BITS = 2048;
const EC_CURVES = ['P-256', 'P-384', 'P-521'];

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
  'RSA PUBLIC KEY': 'PKCS#1 public keys are not supported. Convert: openssl rsa -RSAPublicKey_in -pubout',
  'RSA PRIVATE KEY': 'PKCS#1 private keys are not supported. Convert: openssl pkcs8 -topk8 -nocrypt -in key.pem',
  'EC PRIVATE KEY': 'SEC1 private keys are not supported. Convert: openssl pkcs8 -topk8 -nocrypt -in key.pem',
  'ENCRYPTED PRIVATE KEY': 'Encrypted keys are not supported. Use an unencrypted test key.',
  CERTIFICATE: 'Certificates are not supported. Extract the public key: openssl x509 -pubkey -noout -in cert.pem',
};

function readPem(text, usage) {
  const wanted = usage === 'verify' ? 'PUBLIC KEY' : 'PRIVATE KEY';
  const blocks = [...text.matchAll(PEM_BLOCK)];
  if (blocks.length === 0) {
    throw new JwtError(
      'key-format',
      'key',
      `Not a PEM key. Expected a block that starts with -----BEGIN ${wanted}-----.`,
    );
  }
  if (blocks.length > 1) {
    throw new JwtError('key-format', 'key', 'Paste a single PEM block, not several.');
  }
  const [, label, body] = blocks[0];

  if (label === wanted) {
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

  const isPrivate = label.endsWith('PRIVATE KEY');
  if (usage === 'verify' && label === 'PRIVATE KEY') {
    throw new JwtError('key-type', 'key', 'Verification needs a public key (BEGIN PUBLIC KEY). This is a private key.');
  }
  if (usage === 'sign' && label === 'PUBLIC KEY') {
    throw new JwtError('key-type', 'key', 'Signing needs a private key (BEGIN PRIVATE KEY). This is a public key.');
  }
  if (usage === 'verify' && isPrivate) {
    throw new JwtError('key-type', 'key', 'Verification needs a public key (BEGIN PUBLIC KEY). This is a private key.');
  }
  throw new JwtError(
    'key-format',
    'key',
    NEXT_STEPS[label] || `PEM type "${label}" is not supported. Use ${wanted === 'PUBLIC KEY' ? 'a SubjectPublicKeyInfo public key' : 'a PKCS#8 private key'} (BEGIN ${wanted}).`,
  );
}

const importParams = ({ family, hash, curve }) =>
  family === 'rsa' ? { name: 'RSASSA-PKCS1-v1_5', hash } : { name: 'ECDSA', namedCurve: curve };

/** Work out what a key that failed to import actually is, to give a precise message. */
async function describeKey(subtle, format, der, usage) {
  try {
    const key = await subtle.importKey(format, der, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, [usage]);
    return { kind: 'rsa', bits: key.algorithm.modulusLength };
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
  return null;
}

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
  } catch {
    const actual = await describeKey(subtle, format, der, usage);
    if (spec.family === 'rsa' && actual?.kind === 'ec') {
      throw new JwtError('key-type', 'key', `This is an EC key on ${actual.curve}, but ${alg} needs an RSA key.`);
    }
    if (spec.family === 'ec' && actual?.kind === 'rsa') {
      throw new JwtError('key-type', 'key', `This is an RSA key, but ${alg} needs an EC key on ${spec.curve}.`);
    }
    if (spec.family === 'ec' && actual?.kind === 'ec') {
      throw new JwtError('key-curve', 'key', `This key is on ${actual.curve}, but ${alg} needs ${spec.curve}.`);
    }
    throw new JwtError(
      'key-format',
      'key',
      `The key could not be read. It must be a valid ${usage === 'verify' ? 'SubjectPublicKeyInfo' : 'PKCS#8'} key.`,
    );
  }
  if (spec.family === 'rsa' && key.algorithm.modulusLength < MIN_RSA_BITS) {
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
  return { name: 'ECDSA', hash };
}

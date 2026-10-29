// Pure JWT logic: no React, no DOM. Cryptography goes through Web Crypto; nothing is hand-rolled.
//
// Result contracts (see docs/jwt-playground-functionality-trd.md section 3.2):
//   decodeToken -> { status: 'empty' | 'valid' | 'malformed', header, payload, segments, errors, error }
//   verifyToken -> { status: 'idle' | 'verified' | 'invalid' | 'unverified' | 'unsupported' | 'error', error? }
//   signToken   -> { status: 'empty' | 'ready' | 'invalid' | 'error', token?, error? }
// Errors are { code, part, message }.

import { ALGORITHMS, importKey, isSupportedAlgorithm, signParams } from './keys';
import { JwtError, toError } from './jwtErrors';
import { base64UrlDecode, base64UrlDecodeBytes, base64UrlEncode } from './base64url';

export { base64UrlDecode, base64UrlDecodeBytes, base64UrlEncode };

export { ALGORITHMS };

const encoder = new TextEncoder();

export function parseJsonObject(text, part) {
  const label = part === 'header' ? 'Header' : 'Payload';
  let value;
  try {
    value = JSON.parse(text);
  } catch (error) {
    throw new JwtError('json', part, `${label} is not valid JSON (${error.message}).`);
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new JwtError('json-object', part, `${label} must be a JSON object.`);
  }
  return value;
}

export const prettyJson = (value) => JSON.stringify(value, null, 2);

function decodeSegment(segment, part) {
  const label = part === 'header' ? 'Header' : 'Payload';
  try {
    const object = parseJsonObject(base64UrlDecode(segment, part, label), part);
    return { value: { object, text: prettyJson(object) }, error: null };
  } catch (error) {
    return { value: null, error: toError(error) };
  }
}

/**
 * Whitespace policy: the caller's string is never modified. Surrounding whitespace is trimmed into a
 * separate candidate (and reported via `trimmed`); whitespace inside the candidate is a syntax error.
 * Signatures are always computed over the candidate's original encoded segments.
 *
 * Never throws. Decoded header and payload belong to this input only; a part that fails is null.
 */
export function decodeToken(input) {
  const candidate = input.trim();
  const trimmed = candidate !== input;
  const base = { candidate, trimmed, header: null, payload: null, segments: null, errors: {}, error: null };
  if (!candidate) return { ...base, status: 'empty', trimmed: false };

  const parts = candidate.split('.');
  if (parts.length !== 3) {
    const error = {
      code: 'segment-count',
      part: 'token',
      message: `A JWT has 3 dot-separated parts, this has ${parts.length}.`,
    };
    return { ...base, status: 'malformed', errors: { token: error }, error };
  }
  const header = decodeSegment(parts[0], 'header');
  const payload = decodeSegment(parts[1], 'payload');
  const errors = {};
  if (header.error) errors.header = header.error;
  if (payload.error) errors.payload = payload.error;
  const error = errors.header || errors.payload || null;
  return {
    ...base,
    status: error ? 'malformed' : 'valid',
    header: header.value,
    payload: payload.value,
    segments: { header: parts[0], payload: parts[1], signature: parts[2] },
    errors,
    error,
  };
}

/** Header features this tool cannot honour. Reporting them beats claiming a success it cannot back. */
function rejectUnsupportedHeader(header) {
  if (header.crit !== undefined) {
    throw new JwtError(
      'crit-unsupported',
      'header',
      'The header has a "crit" (critical extensions) parameter. This tool supports no JOSE extensions, so it will not verify or sign this token.',
    );
  }
  if (header.b64 === false) {
    throw new JwtError('crit-unsupported', 'header', 'Unencoded payloads (b64: false) are not supported.');
  }
}

function requireAlgorithm(header) {
  const { alg } = header;
  if (alg === 'none' || (typeof alg === 'string' && alg.toLowerCase() === 'none')) {
    throw new JwtError(
      'unsupported-algorithm',
      'header',
      'This token is unsigned (alg none). Unsigned tokens are never reported as verified.',
    );
  }
  if (!isSupportedAlgorithm(alg)) {
    const shown = typeof alg === 'string' ? JSON.stringify(alg) : 'missing or not a string';
    throw new JwtError(
      'unsupported-algorithm',
      'header',
      `Algorithm ${shown} is not supported. Supported: ${Object.keys(ALGORITHMS).join(', ')}.`,
    );
  }
  return alg;
}

/**
 * Check the signature of exactly the token given. Decoding, the algorithm allowlist and key handling are
 * checked in a fixed order: empty, structure, unsupported algorithm, signature encoding, key, signature.
 * `material` is { secret, secretEncoding, pem }.
 */
export async function verifyToken(input, material) {
  try {
    const decoded = decodeToken(input);
    if (decoded.status === 'empty') return { status: 'idle' };
    if (decoded.status === 'malformed') return { status: 'error', error: decoded.error };

    const header = decoded.header.object;
    let alg;
    try {
      rejectUnsupportedHeader(header);
      alg = requireAlgorithm(header);
    } catch (error) {
      return { status: 'unsupported', error: toError(error) };
    }

    const { signature: encodedSignature, header: h, payload: p } = decoded.segments;
    if (!encodedSignature) {
      return {
        status: 'error',
        algorithm: alg,
        error: { code: 'signature-encoding', part: 'signature', message: 'The signature part is empty.' },
      };
    }
    let signature;
    try {
      signature = base64UrlDecodeBytes(encodedSignature, 'signature', 'Signature');
    } catch (error) {
      const e = toError(error);
      return { status: 'error', algorithm: alg, error: { ...e, code: 'signature-encoding' } };
    }

    const expected = ALGORITHMS[alg].signatureBytes;
    if (expected && signature.length !== expected) {
      return {
        status: 'error',
        algorithm: alg,
        error: {
          code: 'signature-encoding',
          part: 'signature',
          message: `${alg} signatures are ${expected} bytes (raw R and S). This one is ${signature.length} bytes. DER-encoded ECDSA signatures are not valid in a JWT.`,
        },
      };
    }

    let key;
    try {
      key = await importKey(alg, material, 'verify');
    } catch (error) {
      const e = toError(error);
      return { status: e.code === 'missing-key' ? 'unverified' : 'error', algorithm: alg, error: e };
    }

    const ok = await crypto.subtle.verify(signParams(alg), key, signature, encoder.encode(`${h}.${p}`));
    return ok
      ? { status: 'verified', algorithm: alg }
      : {
          status: 'invalid',
          algorithm: alg,
          error: {
            code: 'signature-mismatch',
            part: 'signature',
            message: 'The signature does not match this header, payload and key.',
          },
        };
  } catch (error) {
    return { status: 'error', error: toError(error) };
  }
}

const INPUT_PROBLEMS = new Set([
  'json',
  'json-object',
  'unsupported-algorithm',
  'crit-unsupported',
  'missing-key',
  'secret-encoding',
  'key-format',
  'key-type',
  'key-curve',
  'key-size',
]);

/** Build a new signed token from header and payload JSON text. The result is always a new token. */
export async function signToken({ headerText, payloadText }, material) {
  if (!headerText.trim() && !payloadText.trim()) return { status: 'empty' };
  try {
    const header = parseJsonObject(headerText, 'header');
    const payload = parseJsonObject(payloadText, 'payload');
    rejectUnsupportedHeader(header);
    const alg = requireAlgorithm(header);
    const key = await importKey(alg, material, 'sign');
    const signingInput = `${base64UrlEncode(JSON.stringify(header))}.${base64UrlEncode(JSON.stringify(payload))}`;
    const signature = await crypto.subtle.sign(signParams(alg), key, encoder.encode(signingInput));
    return { status: 'ready', algorithm: alg, token: `${signingInput}.${base64UrlEncode(new Uint8Array(signature))}` };
  } catch (error) {
    const e = toError(error);
    return { status: INPUT_PROBLEMS.has(e.code) ? 'invalid' : 'error', error: e };
  }
}

const RELATIVE_UNITS = [
  ['year', 31536000],
  ['month', 2592000],
  ['day', 86400],
  ['hour', 3600],
  ['minute', 60],
  ['second', 1],
];

/** "in 3 days" / "2 hours ago" for a difference in seconds (target minus now). */
export function relativeTime(seconds) {
  const formatter = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });
  const [unit, size] =
    RELATIVE_UNITS.find(([, s]) => Math.abs(seconds) >= s) || RELATIVE_UNITS[RELATIVE_UNITS.length - 1];
  return formatter.format(Math.round(seconds / size), unit);
}

// Every description says what the token CLAIMS. None of these values is validated here, even when the
// signature verifies: a verified signature does not make an issuer, subject or audience true.
const REGISTERED_CLAIMS = [
  ['iss', 'Issuer', 'Claimed issuer: who the token says created it.'],
  ['sub', 'Subject', 'Claimed subject: who the token says it is about.'],
  ['aud', 'Audience', 'Claimed audience: who the token says it is for.'],
  ['exp', 'Expires', 'The token says it should not be accepted after this time.'],
  ['nbf', 'Not before', 'The token says it should not be accepted before this time.'],
  ['iat', 'Issued', 'When the token says it was created.'],
  ['jti', 'JWT ID', 'An identifier the token gives itself.'],
];
const TIME_CLAIMS = new Set(['exp', 'nbf', 'iat']);

const displayValue = (value) => (typeof value === 'string' ? value : JSON.stringify(value));

/**
 * The registered claims present in a payload, in a fixed order. Time claims are read as dates and flagged
 * against the device clock; that is separate from, and says nothing about, the signature. Non-numeric or
 * out-of-range time values are shown as written with a flag instead of a date.
 */
export function describeClaims(payload, nowMs = Date.now()) {
  if (!payload) return [];
  return REGISTERED_CLAIMS.flatMap(([claim, label, description]) => {
    if (!Object.prototype.hasOwnProperty.call(payload, claim)) return [];
    const row = { claim, label, description, value: displayValue(payload[claim]) };
    if (TIME_CLAIMS.has(claim)) {
      const seconds = payload[claim];
      const date = typeof seconds === 'number' && Number.isFinite(seconds) ? new Date(seconds * 1000) : null;
      if (!date || Number.isNaN(date.getTime())) {
        return [{ ...row, flag: typeof seconds === 'number' ? 'out of range' : 'not a number' }];
      }
      const difference = seconds - nowMs / 1000;
      let flag = null;
      if (claim === 'exp' && difference <= 0) flag = 'expired';
      if (claim === 'nbf' && difference > 0) flag = 'not yet valid';
      return [
        {
          ...row,
          utc: `${date.toISOString().replace('T', ' ').slice(0, 19)} UTC`,
          relative: relativeTime(difference),
          flag,
        },
      ];
    }
    return [row];
  });
}

/** Synthetic drafts for the signing editor. */
export function sampleDocument(nowMs = Date.now()) {
  const issued = Math.floor(nowMs / 1000);
  return {
    headerText: prettyJson({ alg: 'HS256', typ: 'JWT' }),
    payloadText: prettyJson({
      sub: 'usr_2041',
      name: 'Ada Lovelace',
      role: 'admin',
      iat: issued,
      exp: issued + 3600,
    }),
    secret: 'your-256-bit-secret',
  };
}

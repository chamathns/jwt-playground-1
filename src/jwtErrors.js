// Every failure the logic layer can name. Messages are written for the user and never contain
// token, secret or key material.
export class JwtError extends Error {
  constructor(code, part, message) {
    super(message);
    this.name = 'JwtError';
    this.code = code;
    this.part = part; // 'token' | 'header' | 'payload' | 'signature' | 'key'
  }
}

export const ERROR_CODES = [
  'segment-count',
  'base64url-syntax',
  'base64url-length',
  'utf8',
  'json',
  'json-object',
  'signature-encoding',
  'missing-key',
  'secret-encoding',
  'unsupported-algorithm',
  'crit-unsupported',
  'key-format',
  'key-type',
  'key-curve',
  'key-size',
  'signature-mismatch',
  'crypto-unavailable',
  'unexpected',
];

/** Convert anything thrown into a plain { code, part, message } object. Unexpected failures stay generic. */
export function toError(error) {
  if (error instanceof JwtError) return { code: error.code, part: error.part, message: error.message };
  return { code: 'unexpected', part: null, message: 'Something went wrong while processing this input.' };
}

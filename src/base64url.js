// Unpadded base64url, UTF-8 safe. Shared by token segments and secrets.
import { JwtError } from './jwtErrors';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export function base64UrlEncode(input) {
  const bytes = typeof input === 'string' ? encoder.encode(input) : input;
  let binary = '';
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Unpadded base64url only, the same rule for token segments and for secrets. */
export function base64UrlDecodeBytes(text, part = 'token', label = 'Value') {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) {
    throw new JwtError(
      'base64url-syntax',
      part,
      `${label} contains characters that are not base64url (A-Z, a-z, 0-9, - and _; no padding or spaces).`,
    );
  }
  if (text.length % 4 === 1) {
    throw new JwtError('base64url-length', part, `${label} has an invalid base64url length.`);
  }
  const padded = text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function base64UrlDecode(text, part = 'token', label = 'Value') {
  const bytes = base64UrlDecodeBytes(text, part, label);
  try {
    return decoder.decode(bytes);
  } catch {
    throw new JwtError('utf8', part, `${label} is not valid UTF-8.`);
  }
}


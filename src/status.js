// Turns result objects into the words shown to the user. Signature status and claim status never mix.

const STRUCTURAL = new Set(['segment-count', 'base64url-syntax', 'base64url-length', 'utf8', 'json', 'json-object']);
const KEY_PROBLEMS = new Set(['missing-key', 'secret-encoding', 'key-format', 'key-type', 'key-curve', 'key-size']);

const HINTS = {
  'segment-count': 'Paste the whole token: header, payload and signature separated by two dots.',
  'signature-encoding': 'The signature must be unpadded base64url.',
};

const withHint = (error) => [error.message, HINTS[error.code]].filter(Boolean).join(' ');

export function describeVerify(result) {
  switch (result.status) {
    case 'pending':
      return { tone: 'pending', title: 'Checking signature…', message: '' };
    case 'idle':
      return { tone: 'neutral', title: 'No token', message: 'Paste a token to decode it and check its signature.' };
    case 'verified':
      return {
        tone: 'positive',
        title: 'Signature verified',
        message: `The ${result.algorithm} signature matches this key. This checks the signature only, not the issuer, audience, authorization or time claims.`,
      };
    case 'invalid':
      return { tone: 'negative', title: 'Invalid signature', message: withHint(result.error) };
    case 'unverified':
      return {
        tone: 'warning',
        title: 'Unverified',
        message: 'The decoded values below are not verified. Enter the key to check the signature.',
      };
    case 'unsupported':
      return { tone: 'warning', title: 'Not supported', message: withHint(result.error) };
    case 'error': {
      const { code } = result.error;
      let title = 'Verification failed';
      if (STRUCTURAL.has(code)) title = 'Malformed token';
      else if (code === 'signature-encoding') title = 'Invalid signature encoding';
      else if (KEY_PROBLEMS.has(code)) title = 'Key problem';
      else if (code === 'crypto-unavailable') title = 'Crypto unavailable';
      return { tone: 'negative', title, message: withHint(result.error) };
    }
    default:
      return { tone: 'neutral', title: '', message: '' };
  }
}

export function describeSign(result) {
  switch (result.status) {
    case 'pending':
      return { tone: 'pending', title: 'Signing…', message: '' };
    case 'empty':
      return { tone: 'neutral', title: 'Nothing to sign', message: 'Enter a header and a payload.' };
    case 'ready':
      return {
        tone: 'positive',
        title: 'New token generated',
        message: `Signed with ${result.algorithm}. This is a newly generated token, not a verified one.`,
      };
    case 'invalid':
      return { tone: 'warning', title: 'Cannot sign yet', message: withHint(result.error) };
    case 'error':
      return { tone: 'negative', title: 'Signing failed', message: withHint(result.error) };
    default:
      return { tone: 'neutral', title: '', message: '' };
  }
}

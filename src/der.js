// Minimal ASN.1 DER re-wrapping so PKCS#1 and SEC1 keys can be imported through Web Crypto, which only
// reads SPKI and PKCS#8. This changes how a key is encoded, never its value, and performs no cryptography.
import { JwtError } from './jwtErrors';

const invalid = (what) => new JwtError('key-format', 'key', `This is not a valid ${what} key.`);

const concat = (parts) => Uint8Array.from(parts.flatMap((part) => [...part]));
const encodeLength = (n) => (n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff]);
const tlv = (tag, ...parts) => {
  const content = concat(parts);
  return concat([[tag], encodeLength(content.length), content]);
};

function readTlv(bytes, offset, what) {
  const tag = bytes[offset];
  const first = bytes[offset + 1];
  if (tag === undefined || first === undefined) throw invalid(what);
  let length = first;
  let next = offset + 2;
  if (first >= 0x80) {
    const count = first & 0x7f;
    if (count === 0 || count > 3) throw invalid(what);
    length = 0;
    for (let i = 0; i < count; i += 1) {
      if (bytes[next + i] === undefined) throw invalid(what);
      length = length * 256 + bytes[next + i];
    }
    next += count;
  }
  const end = next + length;
  if (end > bytes.length) throw invalid(what);
  return { tag, start: offset, end, content: bytes.subarray(next, end), full: bytes.subarray(offset, end) };
}

/** A SEQUENCE that spans the whole input, returned as its child elements. */
function readSequence(bytes, what) {
  const outer = readTlv(bytes, 0, what);
  if (outer.tag !== 0x30 || outer.end !== bytes.length) throw invalid(what);
  const children = [];
  let i = 0;
  while (i < outer.content.length) {
    const child = readTlv(outer.content, i, what);
    children.push(child);
    i = child.end;
  }
  return children;
}

const RSA_ALGORITHM = Uint8Array.from([0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]);
const EC_PUBLIC_KEY_OID = Uint8Array.from([0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
const INTEGER = 0x02;
const ZERO = tlv(INTEGER, [0]);

/** RSAPublicKey (BEGIN RSA PUBLIC KEY) to SubjectPublicKeyInfo. */
export function pkcs1PublicToSpki(der) {
  const parts = readSequence(der, 'PKCS#1 RSA public');
  if (parts.length !== 2 || parts.some((p) => p.tag !== INTEGER)) throw invalid('PKCS#1 RSA public');
  return tlv(0x30, RSA_ALGORITHM, tlv(0x03, [0], der));
}

/** RSAPrivateKey (BEGIN RSA PRIVATE KEY) to PKCS#8. */
export function pkcs1PrivateToPkcs8(der) {
  const parts = readSequence(der, 'PKCS#1 RSA private');
  if (parts.length < 9 || parts.some((p) => p.tag !== INTEGER)) throw invalid('PKCS#1 RSA private');
  return tlv(0x30, ZERO, RSA_ALGORITHM, tlv(0x04, der));
}

/** ECPrivateKey (BEGIN EC PRIVATE KEY) to PKCS#8. The curve moves into the algorithm identifier. */
export function sec1ToPkcs8(der) {
  const parts = readSequence(der, 'SEC1 EC private');
  if (parts.length < 2 || parts[0].tag !== INTEGER || parts[1].tag !== 0x04) throw invalid('SEC1 EC private');
  const params = parts.find((p) => p.tag === 0xa0);
  if (!params) {
    throw new JwtError('key-format', 'key', 'This EC key does not say which curve it uses, so it cannot be used.');
  }
  const curve = readTlv(params.content, 0, 'SEC1 EC private');
  if (curve.tag !== 0x06) throw invalid('SEC1 EC private');
  const ecPrivateKey = tlv(0x30, ...parts.filter((p) => p.tag !== 0xa0).map((p) => p.full));
  return tlv(0x30, ZERO, tlv(0x30, EC_PUBLIC_KEY_OID, curve.full), tlv(0x04, ecPrivateKey));
}

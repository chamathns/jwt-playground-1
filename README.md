# JWT Playground

Decode, verify and sign JSON Web Tokens in the browser. Nothing is sent to a server: the production build's
Content-Security-Policy denies all network connections, and nothing is written to storage.

```
npm install
npm start      # dev server (Vite)
npm test       # unit, interoperability and UI tests
npm run build  # production build in build/
```

## Two modes

- **Verify** decodes the token you paste (read-only) and checks its signature against the key you supply.
  Changing the key or its format only re-checks that exact token; it never signs, rewrites or normalises it.
  Surrounding whitespace is ignored for checking and disclosed; your input is left as typed.
- **Sign** builds a new token from an editable header and payload and a signing key. Any change re-signs.
  The output is labelled as newly generated, never as verified.

Each mode keeps its own draft. "Signature verified" means only that the signature matches the key. It does not
validate issuer, audience, authorization or time claims; time flags (expired, not yet valid) use the device clock
and are shown separately.

## Algorithms and keys

| Family | Algorithms | Key to verify | Key to sign |
| --- | --- | --- | --- |
| HMAC | HS256, HS384, HS512 | secret | same secret |
| RSA | RS256, RS384, RS512 | public key | private key |
| RSA-PSS | PS256, PS384, PS512 | public key | private key |
| ECDSA | ES256 (P-256), ES384 (P-384), ES512 (P-521) | public key | private key |
| EdDSA | EdDSA (Ed25519 only) | public key | private key |

- **HMAC secrets** are UTF-8 text or Base64URL bytes (binary secrets work).
- **PEM keys** are unencrypted. Public keys: `BEGIN PUBLIC KEY` (SPKI) or `BEGIN RSA PUBLIC KEY` (PKCS#1). Private
  keys: `BEGIN PRIVATE KEY` (PKCS#8), `BEGIN RSA PRIVATE KEY` (PKCS#1) or `BEGIN EC PRIVATE KEY` (SEC1). PKCS#1 and
  SEC1 keys are re-wrapped into PKCS#8 or SPKI before import (`src/der.js`); this changes the encoding, not the key.
  Encrypted keys, certificates and PEM headers are refused with a conversion hint.
- **Checks:** RSA keys must be 2048 bits or more. The key's type and curve must match the token's algorithm, and a
  public key is never accepted for signing or a private key for verifying.
- **RSA-PSS** uses a salt as long as the digest, as JWA requires. **EdDSA** needs a browser with Ed25519 in Web
  Crypto (current Chrome, Edge, Firefox and Safari); otherwise the key panel says so. Ed448 is not supported.
- `none` and every algorithm outside the table are reported as unsupported, never verified. Tokens with `crit`
  extensions or `b64: false` are refused. There is no key lookup, JWKS fetch or `kid` handling.

## Layout

- `src/jwt.js`: pure logic with typed results (`decodeToken`, `verifyToken`, `signToken`, `describeClaims`).
- `src/keys.js`: algorithm registry, secret bytes and PEM import. HMAC reads only the secret and RSA/ECDSA read only
  the PEM, so a public key can never be reused as an HMAC secret.
- `src/base64url.js`, `src/der.js`, `src/jwtErrors.js`: encoding, key re-wrapping and the error-code contract.
- `src/jwtState.js`, `src/useJwt.js`: two drafts with per-draft revisions bumped on every edit, so a late async
  result can never overwrite newer input.
- `src/status.js`: result objects to user-facing words. `src/App.jsx` and friends: plain components and
  `src/styles.css` (tokens, automatic dark mode). No UI library, no crypto dependency.

Cryptography is Web Crypto only; it needs a secure context (HTTPS or localhost).

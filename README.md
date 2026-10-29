# JWT Playground

Decode, verify and sign JSON Web Tokens in the browser. Nothing is sent to a server: the production build's
Content-Security-Policy denies all network connections, and nothing is written to storage.

```
npm install
npm start      # dev server
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

HS256/384/512 (secret as UTF-8 text or Base64URL bytes), RS256/384/512 and ES256/384/512 (PEM keys: public key as
SubjectPublicKeyInfo to verify, unencrypted PKCS#8 private key to sign; RSA keys of 2048 bits or more; ES256, ES384
and ES512 need P-256, P-384 and P-521). `none` and every algorithm outside this list are reported as unsupported,
never verified. Tokens with `crit` extensions or `b64: false` are refused. There is no key lookup, JWKS fetch or
`kid` handling.

## Layout

- `src/jwt.js`: pure logic with typed results (`decodeToken`, `verifyToken`, `signToken`, `describeClaims`).
- `src/keys.js`: algorithm registry, secret bytes and PEM import. HMAC reads only the secret and RSA/ECDSA read only
  the PEM, so a public key can never be reused as an HMAC secret.
- `src/base64url.js`, `src/jwtErrors.js`: encoding and the error-code contract.
- `src/jwtState.js`, `src/useJwt.js`: two drafts with per-draft revisions bumped on every edit, so a late async
  result can never overwrite newer input.
- `src/status.js`: result objects to user-facing words. `src/App.jsx` and friends: plain components and
  `src/styles.css` (tokens, automatic dark mode). No UI library, no crypto dependency.

Cryptography is Web Crypto only; it needs a secure context (HTTPS or localhost).

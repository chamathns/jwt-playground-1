import { ALGORITHMS } from './jwt';

// Key input that matches the token's algorithm. Verification and signing share the layout, not the state.
export default function KeyPanel({ title, algorithm, material, onChange, error, verifying }) {
  const family = ALGORITHMS[algorithm]?.family;

  return (
    <section className="panel" data-tone="signature">
      <h2>{title}</h2>
      {family === 'hmac' && (
        <div className="field">
          <div className="field-head">
            <label htmlFor="secret">Secret</label>
            <span className="hint">{verifying ? 'Checks the signature' : 'Signs the token'}</span>
            <select
              id="secret-format"
              name="secret-format"
              aria-label="Secret format"
              value={material.secretEncoding}
              onChange={(event) => onChange({ secretEncoding: event.target.value })}
            >
              <option value="text">Text (UTF-8)</option>
              <option value="base64url">Base64URL bytes</option>
            </select>
          </div>
          <input
            id="secret"
            className="secret"
            type="text"
            value={material.secret}
            onChange={(event) => onChange({ secret: event.target.value })}
            placeholder={material.secretEncoding === 'base64url' ? 'base64url-encoded secret' : 'your-256-bit-secret'}
            spellCheck={false}
            autoComplete="off"
            aria-invalid={Boolean(error)}
            aria-describedby={error ? 'key-error' : undefined}
          />
        </div>
      )}
      {(family === 'rsa' || family === 'ec') && (
        <div className="field">
          <div className="field-head">
            <label htmlFor="pem">{verifying ? 'Public key (PEM)' : 'Private key (PEM)'}</label>
            <span className="hint">
              {verifying ? 'SubjectPublicKeyInfo' : 'PKCS#8, unencrypted'}
              {family === 'ec' && ` \u00b7 ${ALGORITHMS[algorithm].curve}`}
            </span>
          </div>
          <textarea
            id="pem"
            className="json pem"
            rows={7}
            value={material.pem}
            onChange={(event) => onChange({ pem: event.target.value })}
            placeholder={`-----BEGIN ${verifying ? 'PUBLIC' : 'PRIVATE'} KEY-----`}
            spellCheck={false}
            autoComplete="off"
            aria-invalid={Boolean(error)}
            aria-describedby={error ? 'key-error' : undefined}
          />
          {!verifying && <p className="note">Use a throwaway test key. It stays in this browser tab.</p>}
        </div>
      )}
      {!family && (
        <p className="note">
          {algorithm === undefined || algorithm === null
            ? 'The key field appears once the token has a supported algorithm.'
            : `Algorithm ${JSON.stringify(algorithm)} is not supported, so no key is needed.`}
        </p>
      )}
      {error && (
        <p className="error" id="key-error">
          {error}
        </p>
      )}
      {family && verifying && <p className="note">Changing the key only re-checks the signature. The token is never changed.</p>}
    </section>
  );
}

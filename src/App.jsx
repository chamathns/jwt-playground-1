import { useEffect, useState } from 'react';
import ClaimsPanel from './ClaimsPanel';
import CopyButton from './CopyButton';
import JsonField from './JsonField';
import KeyPanel from './KeyPanel';
import Tabs from './Tabs';
import TokenField from './TokenField';
import useJwt from './useJwt';
import { ALGORITHMS } from './jwt';
import { describeSign, describeVerify } from './status';

const TABS = [
  { id: 'verify', label: 'Verify a token' },
  { id: 'sign', label: 'Sign a token' },
];

const keyError = (result) => (result.error?.part === 'key' ? result.error.message : null);
const partError = (result, part) => (result.error?.part === part ? result.error.message : null);

function Verdict({ view }) {
  return (
    <p className="verdict" data-tone={view.tone}>
      <strong>{view.title}</strong>
      {view.message && <span>{view.message}</span>}
    </p>
  );
}

function VerifyMode({ jwt, notify }) {
  const { verify, actions } = jwt;
  const { decoded } = verify;
  const algorithm = decoded.header?.object?.alg;
  const tokenError = decoded.errors.token?.message;

  return (
    <div className="columns">
      <div className="column">
        <section className="panel panel-grow">
          <h2>Encoded token</h2>
          <TokenField
            id="verify-token"
            label="Token to verify"
            value={verify.input}
            onChange={actions.verifyInput}
            error={tokenError}
            errorId="verify-token-error"
            placeholder="Paste a token here"
          />
          {tokenError && <p className="error" id="verify-token-error">{tokenError}</p>}
          {decoded.trimmed && (
            <p className="note">Spaces around the token were ignored. Your input is unchanged.</p>
          )}
          <ul className="legend" aria-label="Token parts">
            <li data-tone="header">Header</li>
            <li data-tone="payload">Payload</li>
            <li data-tone="signature">Signature</li>
          </ul>
        </section>
        <ClaimsPanel claims={verify.claims} />
      </div>

      <div className="column">
        <section className="panel">
          <h2>Decoded <span className="hint">read-only</span></h2>
          <JsonField
            label="Header"
            hint={algorithm ? `Algorithm ${String(algorithm)}` : 'Algorithm and token type'}
            tone="header"
            value={decoded.header?.text ?? ''}
            copyLabel="Copy header"
            readOnly
            error={decoded.errors.header?.message}
          />
          <JsonField
            label="Payload"
            hint="Claims"
            tone="payload"
            value={decoded.payload?.text ?? ''}
            copyLabel="Copy payload"
            readOnly
            error={decoded.errors.payload?.message}
          />
        </section>
        <KeyPanel
          title="Verification key"
          verifying
          algorithm={algorithm}
          material={verify.material}
          onChange={actions.verifyMaterial}
          error={keyError(verify.result)}
        />
      </div>
    </div>
  );
}

function SignMode({ jwt }) {
  const { sign, actions } = jwt;
  const algorithmOptions = Object.keys(ALGORITHMS);
  const known = algorithmOptions.includes(sign.alg);
  const headerInvalid = sign.result.error?.part === 'header' && ['json', 'json-object'].includes(sign.result.error.code);
  const ready = sign.result.status === 'ready';

  return (
    <div className="columns">
      <div className="column">
        <section className="panel">
          <h2>Edit</h2>
          <JsonField
            label="Header"
            hint="Algorithm and token type"
            tone="header"
            value={sign.headerText}
            copyLabel="Copy header"
            onChange={(headerText) => actions.signEdit({ headerText })}
            error={partError(sign.result, 'header')}
          >
            <select
              id="sign-algorithm"
              name="sign-algorithm"
              aria-label="Algorithm"
              value={known ? sign.alg : ''}
              onChange={(event) => actions.signAlgorithm(event.target.value, sign.headerText)}
              disabled={headerInvalid || !sign.headerText.trim()}
            >
              {!known && (
                <option value="" disabled>
                  {sign.alg ? String(sign.alg) : 'none'}
                </option>
              )}
              {algorithmOptions.map((name) => (
                <option key={name} value={name}>{name}</option>
              ))}
            </select>
          </JsonField>
          <JsonField
            label="Payload"
            hint="Claims"
            tone="payload"
            value={sign.payloadText}
            copyLabel="Copy payload"
            onChange={(payloadText) => actions.signEdit({ payloadText })}
            error={partError(sign.result, 'payload')}
          />
        </section>
        <KeyPanel
          title="Signing key"
          algorithm={sign.alg}
          material={sign.material}
          onChange={actions.signMaterial}
          error={keyError(sign.result)}
        />
      </div>

      <div className="column">
        <section className="panel panel-grow">
          <h2>Generated token <span className="hint">new, not verified</span></h2>
          <TokenField
            id="sign-token"
            label="Generated token"
            value={ready ? sign.result.token : ''}
            readOnly
            placeholder="The signed token appears here"
          />
          <ul className="legend" aria-label="Token parts">
            <li data-tone="header">Header</li>
            <li data-tone="payload">Payload</li>
            <li data-tone="signature">Signature</li>
          </ul>
        </section>
        <ClaimsPanel claims={sign.claims} />
      </div>
    </div>
  );
}

export default function App() {
  const jwt = useJwt();
  const { mode, verify, sign, actions } = jwt;
  const view = mode === 'verify' ? describeVerify(verify.result) : describeSign(sign.result);

  // Spoken status: settled results only, so typing does not announce every keystroke.
  const [spoken, setSpoken] = useState('');
  useEffect(() => {
    if (view.tone !== 'pending') setSpoken([view.title, view.message].filter(Boolean).join('. '));
  }, [view]);
  const [notice, setNotice] = useState('');

  const clear = () => {
    if (mode === 'verify') actions.verifyClear();
    else actions.signClear();
    setNotice(mode === 'verify' ? 'Token cleared.' : 'Header and payload cleared.');
  };
  const example = () => {
    if (mode === 'verify') actions.verifyExample();
    else actions.signExample();
    setNotice('Example loaded. It uses synthetic data.');
  };
  const canClear = mode === 'verify' ? Boolean(verify.input) : Boolean(sign.headerText || sign.payloadText);

  return (
    <div className="shell">
      <header className="topbar">
        <span className="mark" aria-hidden="true">JWT</span>
        <span className="product">JWT Playground</span>
        <span className="privacy">Runs in your browser. Tokens and keys are never sent anywhere.</span>
      </header>

      <main className="canvas">
        <div className="title-row">
          <div>
            <h1>Decode, verify and sign JSON Web Tokens</h1>
            <Verdict view={view} />
          </div>
          <div className="actions">
            <button type="button" onClick={example}>Load example</button>
            <button type="button" onClick={clear} disabled={!canClear}>Clear</button>
            {mode === 'verify' ? (
              <CopyButton text={verify.input} label="Copy token" disabled={!verify.input} primary />
            ) : (
              <CopyButton
                text={sign.result.token ?? ''}
                label="Copy token"
                disabled={sign.result.status !== 'ready'}
                primary
              />
            )}
          </div>
        </div>

        <Tabs tabs={TABS} value={mode} onChange={actions.setMode} label="Mode" />

        <div role="tabpanel" id={`panel-${mode}`} aria-labelledby={`tab-${mode}`}>
          {mode === 'verify' ? <VerifyMode jwt={jwt} /> : <SignMode jwt={jwt} />}
        </div>

        <div className="sr-only" role="status">{spoken}</div>
        <div className="sr-only" role="status">{notice}</div>
      </main>
    </div>
  );
}

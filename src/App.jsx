import { useEffect, useRef, useState } from 'react';
import ClaimsPanel from './ClaimsPanel';
import CopyButton, { CopyGlyph, CopyStatus, useCopy } from './CopyButton';
import JsonField from './JsonField';
import KeyPanel from './KeyPanel';
import SegmentChips from './SegmentChips';
import Tabs from './Tabs';
import TokenField from './TokenField';
import useJwt from './useJwt';
import { ALGORITHMS } from './jwt';
import { FAMILY_LABELS, algorithmSpec, displayAlgorithm, keyWarnings } from './keys';
import { reveal } from './motion';
import { describeSign, describeVerify } from './status';

const TABS = [
  { id: 'verify', label: 'Verify a token' },
  { id: 'sign', label: 'Sign a token' },
];

const keyError = (result) => (result.error?.part === 'key' ? result.error.message : null);
const partError = (result, part) => (result.error?.part === part ? result.error.message : null);

const PART_NAMES = ['Header', 'Payload', 'Signature'];

// One oversized segment of the sample token; clicking copies the whole segment.
function AnatomyPart({ name, index, segment }) {
  const { outcome, copy } = useCopy(segment);
  return (
    <>
      <button
        type="button"
        className={`anatomy-part anatomy-${index}`}
        data-ui
        data-state={outcome || undefined}
        disabled={!segment}
        onClick={copy}
        aria-label={`Copy the token’s ${name.toLowerCase()} segment`}
      >
        <span className="anatomy-name">{name}</span>
        <code>{segment ? `${segment.slice(0, 24)}${segment.length > 24 ? '…' : ''}` : '—'}</code>
        <span className="anatomy-copy" aria-hidden="true">
          <span className="anatomy-copy-text">{outcome === 'copied' ? 'Copied' : 'Copy'}</span>
          <CopyGlyph done={outcome === 'copied'} />
        </span>
      </button>
      <CopyStatus outcome={outcome} name={`${name} segment`} />
    </>
  );
}

function Verdict({ view }) {
  return (
    <div className="verdict" data-tone={view.tone} key={view.title}>
      <strong>{view.title}</strong>
      {view.title === 'Signature verified' && <span>The signature matches this key. Claims aren’t validated.</span>}
      {view.message && (view.tone === 'positive' ? <details className="verdict-details"><summary>What this means</summary><span>{view.message}</span></details> : <span>{view.message}</span>)}
    </div>
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
        <section className="panel panel-grow" data-ui data-reveal ref={reveal}>
          <h2>Encoded token</h2>
          <TokenField
            id="verify-token"
            label="Token to verify"
            value={verify.input}
            onChange={actions.verifyInput}
            error={tokenError}
            errorId="verify-token-error"
            placeholder="Paste a token here"
            copyLabel="Copy encoded token"
          />
          {tokenError && <p className="error" id="verify-token-error">{tokenError}</p>}
          {decoded.trimmed && (
            <p className="note">Spaces around the token were ignored for verification. Your input hasn’t changed.</p>
          )}
          <SegmentChips token={verify.input} />
        </section>
        <ClaimsPanel claims={verify.claims} />
      </div>

      <div className="column">
        <section className="panel" data-ui data-reveal ref={reveal}>
          <h2>Decoded <span className="hint">read-only</span></h2>
          <JsonField
            label="Header"
            hint={algorithm ? `Algorithm ${displayAlgorithm(algorithm)}` : ''}
            tone="header"
            value={decoded.header?.text ?? ''}
            copyLabel="Copy header"
            readOnly
            error={decoded.errors.header?.message}
          />
          <JsonField
            label="Payload"
            hint=""
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
  const families = Object.keys(FAMILY_LABELS);
  const known = Boolean(algorithmSpec(sign.alg));
  const headerInvalid = sign.result.error?.part === 'header' && ['json', 'json-object'].includes(sign.result.error.code);
  const ready = sign.result.status === 'ready';

  return (
    <div className="columns">
      <div className="column">
        <section className="panel" data-ui data-reveal ref={reveal}>
          <h2>Token contents</h2>
          <JsonField
            label="Header"
            hint=""
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
                  {sign.alg ? displayAlgorithm(sign.alg) : 'none'}
                </option>
              )}
              {families.map((family) => (
                <optgroup key={family} label={FAMILY_LABELS[family]}>
                  {algorithmOptions
                    .filter((name) => algorithmSpec(name).family === family)
                    .map((name) => (
                      <option key={name} value={name}>{name}</option>
                    ))}
                </optgroup>
              ))}
            </select>
          </JsonField>
          <JsonField
            label="Payload"
            hint=""
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
        <section className="panel panel-grow" data-ui data-reveal ref={reveal}>
          <h2>Generated token <span className="hint">new, not verified</span></h2>
          <TokenField
            id="sign-token"
            label="Generated token"
            value={ready ? sign.result.token : ''}
            readOnly
            placeholder="Your signed token will appear here"
            copyLabel="Copy generated token"
          />
          {ready && keyWarnings(sign.alg, sign.material).length > 0 && (
            <p className="warning">
              <strong>Warning:</strong> signed with a weak or published key. Anyone could forge a token like this.
            </p>
          )}
          <SegmentChips token={ready ? sign.result.token : ''} />
        </section>
        <ClaimsPanel claims={sign.claims} />
      </div>
    </div>
  );
}

export default function App() {
  const jwt = useJwt();
  const { mode, verify, sign, actions } = jwt;
  const heroRef = useRef(null);
  // The hero's three segments drift against the pointer. Fine pointers only; reduced motion keeps them still.
  useEffect(() => {
    const hero = heroRef.current;
    if (!hero || typeof window.matchMedia !== 'function') return undefined;
    if (!window.matchMedia('(hover: hover) and (pointer: fine) and (prefers-reduced-motion: no-preference)').matches) return undefined;
    let frame;
    const move = (event) => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        const box = hero.getBoundingClientRect();
        hero.style.setProperty('--px', ((event.clientX - box.left) / box.width - 0.5).toFixed(3));
        hero.style.setProperty('--py', ((event.clientY - box.top) / box.height - 0.5).toFixed(3));
      });
    };
    hero.addEventListener('pointermove', move);
    return () => {
      hero.removeEventListener('pointermove', move);
      cancelAnimationFrame(frame);
    };
  }, []);
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
  const clearAll = () => {
    actions.clearAll();
    setNotice('Cleared all tokens and keys in both modes.');
  };
  const example = () => {
    if (mode === 'verify') actions.verifyExample();
    else actions.signExample();
    setNotice(
      mode === 'verify'
        ? 'Example loaded. It uses synthetic data and the published example key.'
        : 'Example loaded with synthetic data and a new random key.',
    );
  };
  const hasAnything = [
    verify.input,
    verify.material.secret,
    verify.material.pem,
    sign.headerText,
    sign.payloadText,
    sign.material.secret,
    sign.material.pem,
  ].some(Boolean);
  const canClear = mode === 'verify' ? Boolean(verify.input) : Boolean(sign.headerText || sign.payloadText);

  return (
    <div className="shell">
      <div className="progress" aria-hidden="true"><i></i><i></i><i></i></div>
      <header className="topbar">
        <span className="mark" aria-hidden="true"><i></i><i></i><i></i></span>
        <span className="product">JWT Playground</span>
        <nav className="landing-nav" aria-label="Main navigation"><a href="#workspace">Playground</a><a href="#about">Privacy</a></nav>
        <span className="privacy"><span className="privacy-dot" aria-hidden="true"></span>Runs in your browser</span>
      </header>

      <section className="landing-hero" aria-labelledby="landing-title" ref={heroRef}>
        <div className="hero-copy">
          <h1 id="landing-title"><span className="line"><span>Decode, verify</span></span> <span className="line"><span>and sign JWTs.</span></span></h1>
          <p>Inspect and create JSON Web Tokens in your browser.</p>
          <a className="hero-action" href="#workspace">Try the playground <span aria-hidden="true">↘</span></a>
        </div>
        <div className="hero-anatomy" aria-label="A JSON Web Token has a header, payload, and signature">
          {PART_NAMES.map((part, index) => (
            <AnatomyPart key={part} name={part} index={index} segment={verify.input.trim().split('.')[index] || ''} />
          ))}
        </div>
      </section>

      <main className="canvas" id="workspace">
        <div className="title-row">
          <div>
            <h2 className="workspace-title">Token workspace</h2>
            <Verdict view={view} />
          </div>
          <div className="actions">
            <button type="button" onClick={example}>Load example</button>
            <button type="button" onClick={clear} disabled={!canClear}>Clear</button>
            <button
              type="button"
              onClick={clearAll}
              disabled={!hasAnything}
              title="Remove the tokens, JSON and keys in both modes"
            >
              Clear all
            </button>
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

        <div className="tabpanel" key={mode} role="tabpanel" id={`panel-${mode}`} aria-labelledby={`tab-${mode}`}>
          {mode === 'verify' ? <VerifyMode jwt={jwt} /> : <SignMode jwt={jwt} />}
        </div>

        <div className="sr-only" role="status">{spoken}</div>
        <div className="sr-only" role="status">{notice}</div>
      </main>
      <section className="about-section" id="about" data-stagger ref={reveal}>
        <div><h2>Your tokens stay<br />in your browser.</h2></div>
        <div className="about-copy"><p>Your tokens and keys are processed in your browser. They aren’t sent to a server or saved.</p><p>Decode a token to inspect its contents, verify its signature with a key, or sign a new token.</p><a href="#workspace">Go to the playground ↑</a></div>
      </section>
      <footer className="landing-footer" data-stagger ref={reveal}>
        <span>JWT Playground</span>
        <span>Decode · Verify · Sign</span>
      </footer>
    </div>
  );
}

import { useEffect, useMemo, useReducer } from 'react';
import { decodeToken, describeClaims, parseJsonObject, prettyJson, signToken, verifyToken } from './jwt';
import { toError } from './jwtErrors';
import { createInitialState, reducer } from './jwtState';
import useNow from './useNow';

const objectOrNull = (text, part) => {
  try {
    return parseJsonObject(text, part);
  } catch {
    return null;
  }
};

const failure = (error) => ({ status: 'error', error: toError(error) });

/**
 * Owns the two drafts and runs the async checks. `engine` can be swapped in tests.
 *
 * Invariant: every input change bumps its draft's revision (see jwtState.js). An effect starts work for the
 * revision on screen and its cleanup discards the result of any earlier one; the reducer rejects stale
 * results a second time. Verification reads the token and never writes it.
 */
export default function useJwt(engine = { verify: verifyToken, sign: signToken }) {
  const [state, dispatch] = useReducer(reducer, undefined, () => createInitialState());
  const { verify, sign } = state;
  const now = useNow();

  useEffect(() => {
    if (!verify.input.trim()) return undefined;
    let active = true;
    const { revision } = verify;
    Promise.resolve()
      .then(() => engine.verify(verify.input, verify.material))
      .catch(failure)
      .then((result) => {
        if (active) dispatch({ type: 'verify/result', revision, result });
      });
    return () => {
      active = false;
    };
    // The revision changes on every input edit, so it is the only dependency that matters.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [verify.revision]);

  useEffect(() => {
    if (!sign.headerText.trim() && !sign.payloadText.trim()) return undefined;
    let active = true;
    const { revision } = sign;
    Promise.resolve()
      .then(() => engine.sign({ headerText: sign.headerText, payloadText: sign.payloadText }, sign.material))
      .catch(failure)
      .then((result) => {
        if (active) dispatch({ type: 'sign/result', revision, result });
      });
    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sign.revision]);

  // Verify mode output comes from the token on screen and from nothing else.
  const decoded = useMemo(() => decodeToken(verify.input), [verify.input]);

  const signHeader = useMemo(() => objectOrNull(sign.headerText, 'header'), [sign.headerText]);
  const signPayload = useMemo(() => objectOrNull(sign.payloadText, 'payload'), [sign.payloadText]);

  const actions = useMemo(
    () => ({
      setMode: (mode) => dispatch({ type: 'mode', mode }),
      verifyInput: (value) => dispatch({ type: 'verify/input', value }),
      verifyMaterial: (patch) => dispatch({ type: 'verify/material', patch }),
      verifyClear: () => dispatch({ type: 'verify/clear' }),
      verifyExample: () => dispatch({ type: 'verify/example' }),
      signEdit: (patch) => dispatch({ type: 'sign/edit', patch }),
      signMaterial: (patch) => dispatch({ type: 'sign/material', patch }),
      signClear: () => dispatch({ type: 'sign/clear' }),
      signExample: () => dispatch({ type: 'sign/example', now: Date.now() }),
      signAlgorithm: (alg, headerText) => {
        const header = objectOrNull(headerText, 'header');
        if (header) dispatch({ type: 'sign/edit', patch: { headerText: prettyJson({ ...header, alg }) } });
      },
    }),
    [],
  );

  return {
    mode: state.mode,
    verify: { ...verify, decoded, claims: describeClaims(decoded.payload?.object, now) },
    sign: { ...sign, alg: signHeader?.alg ?? null, claims: describeClaims(signPayload, now) },
    actions,
  };
}

import { sampleDocument } from './jwt';
import { SAMPLE_SECRET, SAMPLE_TOKEN } from './samples';

// Two independent drafts. Each has its own revision that is bumped synchronously on EVERY edit,
// valid or not, so a result is applied only if it was computed from the input still on screen.
//   verify: token + key  -> read-only decode and a signature check. Never produces or changes a token.
//   sign:   header + payload + key -> a newly generated token.

export const emptyMaterial = (secret = '') => ({ secret, secretEncoding: 'text', pem: '' });

export function createInitialState(now = Date.now()) {
  const draft = sampleDocument(now);
  return {
    mode: 'verify',
    verify: {
      input: SAMPLE_TOKEN,
      material: emptyMaterial(SAMPLE_SECRET),
      revision: 0,
      result: { status: 'pending' },
    },
    sign: {
      headerText: draft.headerText,
      payloadText: draft.payloadText,
      material: emptyMaterial(), // no key until the user supplies one
      revision: 0,
      result: { status: 'pending' },
    },
  };
}

const verifyPending = (input) => (input.trim() ? { status: 'pending' } : { status: 'idle' });
const signPending = (s) => (s.headerText.trim() || s.payloadText.trim() ? { status: 'pending' } : { status: 'empty' });

function editVerify(state, patch) {
  const verify = { ...state.verify, ...patch, revision: state.verify.revision + 1 };
  verify.result = verifyPending(verify.input);
  return { ...state, verify };
}

function editSign(state, patch) {
  const sign = { ...state.sign, ...patch, revision: state.sign.revision + 1 };
  sign.result = signPending(sign);
  return { ...state, sign };
}

export function reducer(state, action) {
  switch (action.type) {
    case 'mode':
      return { ...state, mode: action.mode };

    case 'verify/input':
      return editVerify(state, { input: action.value });
    case 'verify/material':
      return editVerify(state, { material: { ...state.verify.material, ...action.patch } });
    case 'verify/clear':
      return editVerify(state, { input: '' });
    case 'verify/example':
      return editVerify(state, { input: SAMPLE_TOKEN, material: emptyMaterial(SAMPLE_SECRET) });
    case 'verify/result':
      return action.revision === state.verify.revision
        ? { ...state, verify: { ...state.verify, result: action.result } }
        : state;

    case 'sign/edit':
      return editSign(state, action.patch);
    case 'sign/material':
      return editSign(state, { material: { ...state.sign.material, ...action.patch } });
    case 'sign/clear':
      return editSign(state, { headerText: '', payloadText: '' });
    case 'sign/example': {
      const draft = sampleDocument(action.now);
      return editSign(state, {
        headerText: draft.headerText,
        payloadText: draft.payloadText,
        material: emptyMaterial(action.secret), // a fresh random key, never the published one
      });
    }
    case 'sign/result':
      return action.revision === state.sign.revision
        ? { ...state, sign: { ...state.sign, result: action.result } }
        : state;

    default:
      return state;
  }
}

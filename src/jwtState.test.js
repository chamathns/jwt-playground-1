import { createInitialState, reducer } from './jwtState';

const start = () => createInitialState(Date.UTC(2026, 9, 29));

describe('revisions', () => {
  test('every verify edit, valid or not, bumps the revision and drops the old result', () => {
    let state = start();
    state = reducer(state, { type: 'verify/result', revision: 0, result: { status: 'verified', algorithm: 'HS256' } });
    expect(state.verify.result.status).toBe('verified');
    for (const value of ['x', 'x.y', '', '   ']) {
      const before = state.verify.revision;
      state = reducer(state, { type: 'verify/input', value });
      expect(state.verify.revision).toBe(before + 1);
      expect(state.verify.result.status).toBe(value.trim() ? 'pending' : 'idle');
    }
  });

  test('a result for an older revision is ignored', () => {
    let state = reducer(start(), { type: 'verify/input', value: 'a.b.c' });
    const stale = state.verify.revision - 1;
    state = reducer(state, { type: 'verify/result', revision: stale, result: { status: 'verified' } });
    expect(state.verify.result.status).toBe('pending');
  });

  test('every sign edit, including invalid text, clears the old output', () => {
    let state = start();
    state = reducer(state, { type: 'sign/result', revision: 0, result: { status: 'ready', token: 't' } });
    state = reducer(state, { type: 'sign/edit', patch: { payloadText: '{' } });
    expect(state.sign.revision).toBe(1);
    expect(state.sign.result).toEqual({ status: 'pending' });
    state = reducer(state, { type: 'sign/material', patch: { secret: 'new' } });
    expect(state.sign.revision).toBe(2);
  });

  test('clear and example are edits too', () => {
    let state = start();
    state = reducer(state, { type: 'sign/clear' });
    expect(state.sign).toMatchObject({ revision: 1, headerText: '', payloadText: '', result: { status: 'empty' } });
    state = reducer(state, { type: 'sign/example', now: 0 });
    expect(state.sign.revision).toBe(2);
    expect(state.sign.result.status).toBe('pending');
  });
});

describe('separation', () => {
  test('key and format changes never touch the verified token', () => {
    const state = start();
    const token = state.verify.input;
    let next = reducer(state, { type: 'verify/material', patch: { secret: 'other' } });
    next = reducer(next, { type: 'verify/material', patch: { secretEncoding: 'base64url' } });
    expect(next.verify.input).toBe(token);
  });

  test('drafts are independent and mode switches change nothing else', () => {
    const state = start();
    const switched = reducer(state, { type: 'mode', mode: 'sign' });
    expect({ ...switched, mode: 'verify' }).toEqual(state);
    const cleared = reducer(switched, { type: 'sign/clear' });
    expect(cleared.verify).toEqual(state.verify);
    const exampled = reducer(reducer(state, { type: 'verify/clear' }), { type: 'sign/example', now: 5 });
    expect(exampled.verify.input).toBe('');
  });
});

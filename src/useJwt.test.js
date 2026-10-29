import { act, renderHook, waitFor } from '@testing-library/react';
import useJwt from './useJwt';

const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
};

function setup() {
  const verifyCalls = [];
  const signCalls = [];
  const engine = {
    verify: jest.fn((input, material) => {
      const d = deferred();
      verifyCalls.push({ ...d, input, material });
      return d.promise;
    }),
    sign: jest.fn((draft, material) => {
      const d = deferred();
      signCalls.push({ ...d, draft, material });
      return d.promise;
    }),
  };
  const hook = renderHook(() => useJwt(engine));
  return { engine, verifyCalls, signCalls, ...hook };
}

const verified = { status: 'verified', algorithm: 'HS256' };
const invalid = { status: 'invalid', error: { code: 'signature-mismatch', part: 'signature', message: 'no' } };

test('late verify results for earlier input cannot overwrite the current state', async () => {
  const { result, engine, verifyCalls } = setup();
  await waitFor(() => expect(engine.verify).toHaveBeenCalledTimes(1));
  act(() => result.current.actions.verifyInput('a.b.c'));
  await waitFor(() => expect(engine.verify).toHaveBeenCalledTimes(2));

  await act(async () => verifyCalls[1].resolve(invalid));
  expect(result.current.verify.result.status).toBe('invalid');
  await act(async () => verifyCalls[0].resolve(verified)); // the older check finishes last
  expect(result.current.verify.result.status).toBe('invalid');
});

test('the visible result is pending the moment input changes, never the previous verdict', async () => {
  const { result, engine, verifyCalls } = setup();
  await waitFor(() => expect(engine.verify).toHaveBeenCalledTimes(1));
  await act(async () => verifyCalls[0].resolve(verified));
  expect(result.current.verify.result.status).toBe('verified');

  act(() => result.current.actions.verifyMaterial({ secret: 'x' }));
  expect(result.current.verify.result.status).toBe('pending');
  act(() => result.current.actions.verifyInput(''));
  expect(result.current.verify.result.status).toBe('idle');
});

test('valid then invalid signing input: the old output never publishes', async () => {
  const { result, engine, signCalls } = setup();
  await waitFor(() => expect(engine.sign).toHaveBeenCalledTimes(1));
  act(() => result.current.actions.signEdit({ payloadText: '{"a":1}' }));
  await waitFor(() => expect(engine.sign).toHaveBeenCalledTimes(2));
  act(() => result.current.actions.signEdit({ payloadText: '{' }));
  await waitFor(() => expect(engine.sign).toHaveBeenCalledTimes(3));
  expect(result.current.sign.result.status).toBe('pending');

  await act(async () => signCalls[1].resolve({ status: 'ready', token: 'old.old.old', algorithm: 'HS256' }));
  expect(result.current.sign.result.status).toBe('pending');
  await act(async () => signCalls[2].resolve({ status: 'invalid', error: { code: 'json', part: 'payload', message: 'bad' } }));
  expect(result.current.sign.result.status).toBe('invalid');
  await act(async () => signCalls[0].resolve({ status: 'ready', token: 'older', algorithm: 'HS256' }));
  expect(result.current.sign.result.status).toBe('invalid');
});

test('clear cancels pending work', async () => {
  const { result, engine, verifyCalls } = setup();
  await waitFor(() => expect(engine.verify).toHaveBeenCalledTimes(1));
  act(() => result.current.actions.verifyClear());
  await act(async () => verifyCalls[0].resolve(verified));
  expect(result.current.verify.result.status).toBe('idle');
  expect(result.current.verify.input).toBe('');
});

test('verification never writes the token', async () => {
  const { result, engine, verifyCalls } = setup();
  await waitFor(() => expect(engine.verify).toHaveBeenCalledTimes(1));
  const token = result.current.verify.input;
  act(() => result.current.actions.verifyMaterial({ secret: 'wrong' }));
  act(() => result.current.actions.verifyMaterial({ secretEncoding: 'base64url' }));
  await waitFor(() => expect(engine.verify).toHaveBeenCalledTimes(3));
  await act(async () => verifyCalls[2].resolve(invalid));
  expect(result.current.verify.input).toBe(token);
});

test('changing the signing secret signs again', async () => {
  const { result, engine, signCalls } = setup();
  await waitFor(() => expect(engine.sign).toHaveBeenCalledTimes(1));
  act(() => result.current.actions.signMaterial({ secret: 'rotated' }));
  await waitFor(() => expect(engine.sign).toHaveBeenCalledTimes(2));
  expect(signCalls[1].material.secret).toBe('rotated');
});

test('an engine that rejects becomes a generic error without leaking its message', async () => {
  const { result, engine, verifyCalls } = setup();
  await waitFor(() => expect(engine.verify).toHaveBeenCalledTimes(1));
  await act(async () => verifyCalls[0].reject(new Error('secret=hunter2')));
  expect(result.current.verify.result).toEqual({
    status: 'error',
    error: { code: 'unexpected', part: null, message: 'Something went wrong while processing this input.' },
  });
});

test('modes keep separate drafts and results', async () => {
  const { result, engine, verifyCalls } = setup();
  await waitFor(() => expect(engine.verify).toHaveBeenCalledTimes(1));
  await act(async () => verifyCalls[0].resolve(verified));
  const signDraft = result.current.sign.headerText;
  act(() => result.current.actions.setMode('sign'));
  act(() => result.current.actions.signClear());
  act(() => result.current.actions.setMode('verify'));
  expect(result.current.verify.result.status).toBe('verified');
  expect(result.current.sign.headerText).toBe('');
  expect(signDraft).not.toBe('');
});

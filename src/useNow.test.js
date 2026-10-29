import { act, renderHook } from '@testing-library/react';
import useNow from './useNow';

beforeEach(() => jest.useFakeTimers().setSystemTime(new Date('2026-10-29T12:00:00Z')));
afterEach(() => jest.useRealTimers());

test('refreshes on an interval and when the window regains focus', () => {
  const { result } = renderHook(() => useNow(30000));
  const start = result.current;
  act(() => jest.advanceTimersByTime(30000));
  expect(result.current).toBe(start + 30000);
  jest.setSystemTime(new Date('2026-10-29T13:00:00Z'));
  act(() => {
    window.dispatchEvent(new Event('focus'));
  });
  expect(result.current).toBe(Date.parse('2026-10-29T13:00:00Z'));
});

test('refreshes when the tab becomes visible and cleans up on unmount', () => {
  const removeWindow = jest.spyOn(window, 'removeEventListener');
  const removeDoc = jest.spyOn(document, 'removeEventListener');
  const { result, unmount } = renderHook(() => useNow(30000));
  jest.setSystemTime(new Date('2026-10-29T14:00:00Z'));
  act(() => {
    document.dispatchEvent(new Event('visibilitychange'));
  });
  expect(result.current).toBe(Date.parse('2026-10-29T14:00:00Z'));
  unmount();
  expect(removeWindow).toHaveBeenCalledWith('focus', expect.any(Function));
  expect(removeDoc).toHaveBeenCalledWith('visibilitychange', expect.any(Function));
  expect(jest.getTimerCount()).toBe(0);
});

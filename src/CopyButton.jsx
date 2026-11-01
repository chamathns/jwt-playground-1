import { useCallback, useEffect, useRef, useState } from 'react';

// Copies text and reports the outcome: null | 'copied' | 'failed'. Resets after two seconds.
export function useCopy(text) {
  const [outcome, setOutcome] = useState(null);
  const timer = useRef();
  useEffect(() => () => clearTimeout(timer.current), []);

  const copy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(text);
      setOutcome('copied');
    } catch {
      setOutcome('failed');
    }
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setOutcome(null), 2000);
  }, [text]);

  return { outcome, copy };
}

// The clipboard glyph swaps for a check that draws itself.
export function CopyGlyph({ done }) {
  return (
    <span className="copy-glyph" data-done={done || undefined} aria-hidden="true">
      <svg className="copy-icon copy-icon-clip" viewBox="0 0 16 16" fill="none">
        <rect x="5" y="5" width="8" height="8" rx="1.5" />
        <path d="M10.5 5V3.5A1.5 1.5 0 0 0 9 2H3.5A1.5 1.5 0 0 0 2 3.5V9a1.5 1.5 0 0 0 1.5 1.5H5" />
      </svg>
      <svg className="copy-icon copy-icon-check" viewBox="0 0 16 16" fill="none">
        <path d="M3 8.5l3.2 3.2L13 4.5" pathLength="1" />
      </svg>
    </span>
  );
}

// Spoken result of a copy, for assistive technology.
export function CopyStatus({ outcome, name }) {
  return (
    <span className="sr-only" role="status">
      {outcome === 'copied' && `${name}: copied to the clipboard.`}
      {outcome === 'failed' && `${name}: the clipboard is not available. Select the text and copy it manually.`}
    </span>
  );
}

export default function CopyButton({
  text,
  label = 'Copy',
  ariaLabel,
  disabled = false,
  primary = false,
  icon = false,
  iconOnly = false,
  className = '',
}) {
  const { outcome, copy } = useCopy(text);
  const classes = [primary && 'primary', iconOnly && 'copy-only', className].filter(Boolean).join(' ') || undefined;

  return (
    <>
      <button
        type="button"
        className={classes}
        data-state={outcome || undefined}
        onClick={copy}
        disabled={disabled}
        aria-label={iconOnly ? ariaLabel || label : outcome ? undefined : ariaLabel}
        title={iconOnly ? ariaLabel || label : undefined}
      >
        {(icon || iconOnly) && <CopyGlyph done={outcome === 'copied'} />}
        {!iconOnly && (outcome === 'copied' ? 'Copied' : outcome === 'failed' ? 'Copy failed' : label)}
        {outcome && iconOnly && <span className="copy-pop" aria-hidden="true">{outcome === 'copied' ? 'Copied' : 'Failed'}</span>}
      </button>
      <CopyStatus outcome={outcome} name={ariaLabel || label} />
    </>
  );
}

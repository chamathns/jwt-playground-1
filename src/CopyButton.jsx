import { useEffect, useRef, useState } from 'react';

// Copies text and reports the outcome both on the button and to assistive technology.
export default function CopyButton({ text, label = 'Copy', ariaLabel, disabled = false, primary = false, icon = false }) {
  const [outcome, setOutcome] = useState(null); // null | 'copied' | 'failed'
  const timer = useRef();
  useEffect(() => () => clearTimeout(timer.current), []);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setOutcome('copied');
    } catch {
      setOutcome('failed');
    }
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setOutcome(null), 2000);
  };

  return (
    <>
      <button
        type="button"
        className={primary ? 'primary' : undefined}
        onClick={copy}
        disabled={disabled}
        aria-label={outcome ? undefined : ariaLabel}
      >
        {icon && !outcome && <svg className="copy-icon" viewBox="0 0 16 16" fill="none" aria-hidden="true"><rect x="5" y="5" width="8" height="8" rx="1.5"/><path d="M10.5 5V3.5A1.5 1.5 0 0 0 9 2H3.5A1.5 1.5 0 0 0 2 3.5V9a1.5 1.5 0 0 0 1.5 1.5H5"/></svg>}
        {outcome === 'copied' ? 'Copied' : outcome === 'failed' ? 'Copy failed' : label}
      </button>
      <span className="sr-only" role="status">
        {outcome === 'copied' && `${ariaLabel || label}: copied to the clipboard.`}
        {outcome === 'failed' &&
          `${ariaLabel || label}: the clipboard is not available. Select the text and copy it manually.`}
      </span>
    </>
  );
}

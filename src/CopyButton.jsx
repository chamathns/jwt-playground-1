import { useEffect, useRef, useState } from 'react';

// Copies text and reports the outcome both on the button and to assistive technology.
export default function CopyButton({ text, label = 'Copy', ariaLabel, disabled = false, primary = false }) {
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

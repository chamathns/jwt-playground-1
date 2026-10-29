import { useId } from 'react';
import CopyButton from './CopyButton';

export default function JsonField({ label, hint, value, onChange, error, tone, readOnly = false, copyLabel, children }) {
  const id = useId();
  const rows = Math.max(4, value.split('\n').length);
  return (
    <section className="field" data-tone={tone}>
      <div className="field-head">
        <label htmlFor={id}>{label}</label>
        <span className="hint">{hint}</span>
        {children}
        {copyLabel && (
          <span className={children ? undefined : 'push'}>
            <CopyButton text={value} label="Copy" ariaLabel={copyLabel} disabled={!value.trim()} />
          </span>
        )}
      </div>
      <textarea
        id={id}
        className="json"
        rows={rows}
        value={value}
        readOnly={readOnly}
        onChange={onChange ? (event) => onChange(event.target.value) : undefined}
        spellCheck={false}
        aria-invalid={Boolean(error)}
        aria-describedby={error ? `${id}-error` : undefined}
      />
      {error && (
        <p className="error" id={`${id}-error`}>
          {error}
        </p>
      )}
    </section>
  );
}

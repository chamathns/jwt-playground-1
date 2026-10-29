// The token is shown as three coloured segments. A transparent textarea sits over a mirror that
// holds the same text, so editing stays native while the header, payload and signature read apart.
export default function TokenField({ id, label, value, onChange, error, errorId, readOnly = false, placeholder }) {
  const [header = '', payload, ...signature] = value.split('.');
  const hasPayload = payload !== undefined;
  const hasSignature = signature.length > 0;

  const parts = [header, payload, signature.join('.')];
  const showSegments = hasPayload && signature.length === 1 && parts.every(Boolean);

  return (
    <>
    <div className="token" data-readonly={readOnly || undefined}>
      <pre className="token-mirror" aria-hidden="true">
        <span className="seg-header">{header}</span>
        {hasPayload && (
          <>
            <span className="dot">.</span>
            <span className="seg-payload">{payload}</span>
          </>
        )}
        {hasSignature && (
          <>
            <span className="dot">.</span>
            <span className="seg-signature">{signature.join('.')}</span>
          </>
        )}
        {'\n'}
      </pre>
      <textarea
        id={id}
        className="token-input"
        aria-label={label}
        aria-invalid={Boolean(error)}
        aria-describedby={error ? errorId : undefined}
        value={value}
        readOnly={readOnly}
        onChange={onChange ? (event) => onChange(event.target.value) : undefined}
        placeholder={placeholder}
        spellCheck={false}
        autoCapitalize="off"
        autoComplete="off"
      />
    </div>
    {showSegments && (
      <div className="token-segments" aria-hidden="true">
        {parts.map((part, index) => (
          <span key={index} className={`token-segment segment-${index}`} style={{ flexGrow: part.length }} />
        ))}
      </div>
    )}
    </>
  );
}

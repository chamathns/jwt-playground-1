import CopyButton from './CopyButton';

const PARTS = [
  { tone: 'header', label: 'Header' },
  { tone: 'payload', label: 'Payload' },
  { tone: 'signature', label: 'Signature' },
];

// The legend for the token's three colours. Each part is a chip that copies just that segment.
export default function SegmentChips({ token }) {
  const segments = token.trim().split('.');
  const whole = segments.length === 3 && segments.every(Boolean);
  return (
    <ul className="legend" aria-label="Token parts">
      {PARTS.map((part, index) => (
        <li key={part.tone} data-tone={part.tone}>
          <CopyButton
            className="chip"
            text={segments[index] ?? ''}
            label={part.label}
            ariaLabel={`Copy ${part.tone} segment`}
            disabled={!whole}
            icon
          />
        </li>
      ))}
    </ul>
  );
}

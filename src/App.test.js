import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import App from './App';

// Let any in-flight check finish inside act() so no state update lands after a test ends.
afterEach(async () => {
  await act(async () => {});
});

const token = () => screen.getByLabelText('Token to verify');
const verdict = () => document.querySelector('.verdict');

async function verified() {
  await waitFor(() => expect(verdict()).toHaveTextContent('Signature verified'));
}

describe('Verify mode', () => {
  test('starts on a verified example and says what that does and does not mean', async () => {
    render(<App />);
    await verified();
    expect(verdict()).toHaveTextContent(/not the issuer, audience, authorization or time claims/);
    expect(token().value.split('.')).toHaveLength(3);
    expect(screen.getByLabelText('Header')).toHaveAttribute('readonly');
  });

  test('a wrong secret fails, the token stays byte-for-byte, and the right secret verifies again', async () => {
    render(<App />);
    await verified();
    const original = token().value;
    const secret = screen.getByLabelText('Secret');
    fireEvent.change(secret, { target: { value: 'nope' } });
    await waitFor(() => expect(verdict()).toHaveTextContent('Invalid signature'));
    expect(token().value).toBe(original);
    fireEvent.change(secret, { target: { value: 'your-256-bit-secret' } });
    await verified();
    expect(token().value).toBe(original);
  });

  test('no key means unverified, not invalid, and the decoded data stays visible', async () => {
    render(<App />);
    await verified();
    fireEvent.change(screen.getByLabelText('Secret'), { target: { value: '' } });
    await waitFor(() => expect(verdict()).toHaveTextContent('Unverified'));
    expect(screen.getByLabelText('Payload').value).toContain('usr_2041');
    expect(screen.queryByText('Invalid signature')).not.toBeInTheDocument();
  });

  test('malformed input is labelled malformed and old decoded data and claims disappear', async () => {
    render(<App />);
    await verified();
    expect(screen.getByText('Registered claims')).toBeInTheDocument();
    fireEvent.change(token(), { target: { value: 'abc.def.ghi' } });
    await waitFor(() => expect(verdict()).toHaveTextContent('Malformed token'));
    expect(screen.getByLabelText('Payload').value).toBe('');
    expect(screen.getByLabelText('Header').value).toBe('');
    expect(screen.queryByText('Registered claims')).not.toBeInTheDocument();
    expect(screen.getAllByText(/is not valid|base64url/i).length).toBeGreaterThan(0);
  });

  test('wrong segment count gets a next step', async () => {
    render(<App />);
    fireEvent.change(token(), { target: { value: 'a.b' } });
    await waitFor(() => expect(verdict()).toHaveTextContent(/3 dot-separated parts, this has 2/));
    expect(verdict()).toHaveTextContent(/Paste the whole token/);
  });

  test('empty input is neutral', async () => {
    render(<App />);
    await verified();
    fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
    await waitFor(() => expect(verdict()).toHaveTextContent('No token'));
    expect(token().value).toBe('');
  });

  test('surrounding whitespace is disclosed and the input is left alone', async () => {
    render(<App />);
    await verified();
    const padded = `  ${token().value}\n`;
    fireEvent.change(token(), { target: { value: padded } });
    expect(await screen.findByText(/Spaces around the token were ignored/)).toBeInTheDocument();
    expect(token().value).toBe(padded);
    await verified();
  });
});

describe('Sign mode', () => {
  const openSign = () => fireEvent.click(screen.getByRole('tab', { name: 'Sign a token' }));

  test('generates a token labelled as new and enables copy', async () => {
    render(<App />);
    openSign();
    await waitFor(() => expect(verdict()).toHaveTextContent('New token generated'));
    expect(verdict()).toHaveTextContent(/not a verified one/);
    expect(screen.getByLabelText('Generated token').value.split('.')).toHaveLength(3);
    expect(screen.getByRole('button', { name: 'Copy token' })).toBeEnabled();
  });

  test('invalid payload JSON is reported at the payload, clears the output and blocks copy', async () => {
    render(<App />);
    openSign();
    await waitFor(() => expect(verdict()).toHaveTextContent('New token generated'));
    fireEvent.change(screen.getByLabelText('Payload'), { target: { value: '{"a":' } });
    await waitFor(() => expect(verdict()).toHaveTextContent('Cannot sign yet'));
    expect(screen.getByLabelText('Generated token').value).toBe('');
    expect(screen.getByRole('button', { name: 'Copy token' })).toBeDisabled();
    expect(screen.getByLabelText('Payload')).toHaveAttribute('aria-invalid', 'true');
    expect(screen.getByLabelText('Header')).toHaveAttribute('aria-invalid', 'false');
  });

  test('changing the signing secret generates a new token', async () => {
    render(<App />);
    openSign();
    await waitFor(() => expect(verdict()).toHaveTextContent('New token generated'));
    const before = screen.getByLabelText('Generated token').value;
    fireEvent.change(screen.getByLabelText('Secret'), { target: { value: 'rotated-secret' } });
    await waitFor(() => expect(screen.getByLabelText('Generated token').value).not.toBe(before));
    await waitFor(() => expect(verdict()).toHaveTextContent('New token generated'));
  });

  test('modes keep their own drafts', async () => {
    render(<App />);
    await verified();
    const verifyToken = token().value;
    openSign();
    fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
    fireEvent.click(screen.getByRole('tab', { name: 'Verify a token' }));
    expect(token().value).toBe(verifyToken);
  });
});

describe('accessibility and controls', () => {
  test('tabs are keyboard operable', async () => {
    render(<App />);
    const verifyTab = screen.getByRole('tab', { name: 'Verify a token' });
    verifyTab.focus();
    fireEvent.keyDown(verifyTab, { key: 'ArrowRight' });
    expect(screen.getByRole('tab', { name: 'Sign a token' })).toHaveAttribute('aria-selected', 'true');
    expect(screen.getByRole('tab', { name: 'Sign a token' })).toHaveFocus();
    fireEvent.keyDown(screen.getByRole('tab', { name: 'Sign a token' }), { key: 'Home' });
    expect(verifyTab).toHaveAttribute('aria-selected', 'true');
  });

  test('errors are associated with their field', async () => {
    render(<App />);
    fireEvent.change(token(), { target: { value: 'a.b' } });
    await waitFor(() => expect(verdict()).toHaveTextContent('Malformed token'));
    expect(token()).toHaveAttribute('aria-invalid', 'true');
    const described = token().getAttribute('aria-describedby');
    expect(document.getElementById(described)).toHaveTextContent(/3 dot-separated parts/);
  });

  test('copy reports success and failure', async () => {
    render(<App />);
    await verified();
    Object.assign(navigator, { clipboard: { writeText: jest.fn().mockResolvedValue() } });
    await act(async () => userEvent.click(screen.getByRole('button', { name: 'Copy token' })));
    expect(await screen.findByRole('button', { name: 'Copied' })).toBeInTheDocument();
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith(token().value);

    Object.assign(navigator, { clipboard: { writeText: jest.fn().mockRejectedValue(new Error('denied')) } });
    await waitFor(() => expect(screen.getByRole('button', { name: /Copy token|Copied/ })).toBeInTheDocument());
    await act(async () => userEvent.click(screen.getByRole('button', { name: /Copy token|Copied/ })));
    expect(await screen.findByRole('button', { name: 'Copy failed' })).toBeInTheDocument();
    expect(within(document.body).getByText(/clipboard is not available/)).toBeInTheDocument();
  });

  test('typing does not announce a pending state', async () => {
    render(<App />);
    await verified();
    fireEvent.change(screen.getByLabelText('Secret'), { target: { value: 'x' } });
    const spoken = [...document.querySelectorAll('.sr-only[role="status"]')].map((n) => n.textContent).join('|');
    expect(spoken).not.toMatch(/Checking/);
  });
});

describe('secret format', () => {
  test('changing the format re-checks the same token without changing it', async () => {
    render(<App />);
    await verified();
    const original = token().value;
    fireEvent.change(screen.getByLabelText('Secret format'), { target: { value: 'base64url' } });
    // "your-256-bit-secret" contains characters that are valid base64url, but means different bytes.
    await waitFor(() => expect(verdict()).toHaveTextContent('Invalid signature'));
    fireEvent.change(screen.getByLabelText('Secret'), { target: { value: 'not base64url!' } });
    await waitFor(() => expect(verdict()).toHaveTextContent('Key problem'));
    expect(screen.getByRole('textbox', { name: 'Secret' })).toHaveAttribute('aria-invalid', 'true');
    expect(token().value).toBe(original);
    fireEvent.change(screen.getByLabelText('Secret format'), { target: { value: 'text' } });
    fireEvent.change(screen.getByLabelText('Secret'), { target: { value: 'your-256-bit-secret' } });
    await verified();
    expect(token().value).toBe(original);
  });
});

describe('asymmetric keys', () => {
  // Synthetic P-256 key pair, generated per run with OpenSSL. It protects nothing.
  const { generateKeyPairSync, createSign } = require('crypto');
  const enc = (v) => Buffer.from(JSON.stringify(v)).toString('base64url');
  let es256;
  let publicPem;
  let privatePem;
  beforeAll(() => {
    const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const input = `${enc({ alg: 'ES256', typ: 'JWT' })}.${enc({ sub: 'usr_2041' })}`;
    const signature = createSign('sha256').update(input).sign({ key: pair.privateKey, dsaEncoding: 'ieee-p1363' });
    es256 = `${input}.${signature.toString('base64url')}`;
    publicPem = pair.publicKey.export({ type: 'spki', format: 'pem' });
    privatePem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  });

  test('an ES256 token asks for a public key, then verifies with it', async () => {
    render(<App />);
    fireEvent.change(token(), { target: { value: es256 } });
    await waitFor(() => expect(verdict()).toHaveTextContent('Unverified'));
    expect(screen.queryByLabelText('Secret')).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Public key (PEM)'), { target: { value: publicPem } });
    await waitFor(() => expect(verdict()).toHaveTextContent('Signature verified'));
    expect(verdict()).toHaveTextContent(/ES256 signature matches/);
    expect(token().value).toBe(es256);
  });

  test('a private key in the verify field is a key problem, not success', async () => {
    render(<App />);
    fireEvent.change(token(), { target: { value: es256 } });
    fireEvent.change(await screen.findByLabelText('Public key (PEM)'), { target: { value: privatePem } });
    await waitFor(() => expect(verdict()).toHaveTextContent('Key problem'));
    expect(verdict()).toHaveTextContent(/needs a public key/);
    expect(screen.getByLabelText('Public key (PEM)')).toHaveAttribute('aria-invalid', 'true');
  });

  test('signing with ES256 needs a private key and then generates a token', async () => {
    render(<App />);
    fireEvent.click(screen.getByRole('tab', { name: 'Sign a token' }));
    await waitFor(() => expect(verdict()).toHaveTextContent('New token generated'));
    fireEvent.change(screen.getAllByLabelText('Algorithm')[0], { target: { value: 'ES256' } });
    await waitFor(() => expect(verdict()).toHaveTextContent('Cannot sign yet'));
    expect(verdict()).toHaveTextContent(/Paste a private key/);
    fireEvent.change(screen.getByLabelText('Private key (PEM)'), { target: { value: privatePem } });
    await waitFor(() => expect(verdict()).toHaveTextContent('New token generated'));
    expect(screen.getByLabelText('Generated token').value.split('.')).toHaveLength(3);
  });
});

describe('claims and copy controls', () => {
  test('registered claims are described and labelled as separate from the signature', async () => {
    render(<App />);
    await verified();
    expect(screen.getByText('Registered claims')).toBeInTheDocument();
    expect(screen.getByText('Claimed subject: who the token says it is about.')).toBeInTheDocument();
    expect(screen.getByText(/separate from the signature check/)).toBeInTheDocument();
  });

  test('an expired token still verifies; expiry is flagged on its own', async () => {
    const { createHmac } = require('crypto');
    const enc = (v) => Buffer.from(JSON.stringify(v)).toString('base64url');
    const input = `${enc({ alg: 'HS256' })}.${enc({ exp: 1000, iss: 'issuer.test' })}`;
    const expired = `${input}.${createHmac('sha256', 'your-256-bit-secret').update(input).digest('base64url')}`;
    render(<App />);
    fireEvent.change(token(), { target: { value: expired } });
    await verified();
    expect(screen.getByText('expired')).toBeInTheDocument();
    expect(screen.getByText('issuer.test')).toBeInTheDocument();
  });

  test('header and payload can be copied separately in both modes', async () => {
    render(<App />);
    await verified();
    const writeText = jest.fn().mockResolvedValue();
    Object.assign(navigator, { clipboard: { writeText } });
    await act(async () => userEvent.click(screen.getByRole('button', { name: 'Copy payload' })));
    expect(writeText).toHaveBeenLastCalledWith(screen.getByLabelText('Payload').value);
    await act(async () => userEvent.click(screen.getByRole('button', { name: 'Copy header' })));
    expect(writeText).toHaveBeenLastCalledWith(screen.getByLabelText('Header').value);

    fireEvent.click(screen.getByRole('tab', { name: 'Sign a token' }));
    await waitFor(() => expect(verdict()).toHaveTextContent('New token generated'));
    await act(async () => userEvent.click(screen.getByRole('button', { name: 'Copy payload' })));
    expect(writeText).toHaveBeenLastCalledWith(screen.getByLabelText('Payload').value);
  });

  test('copy is disabled when there is nothing to copy', async () => {
    render(<App />);
    await verified();
    fireEvent.change(token(), { target: { value: 'abc.def.ghi' } });
    await waitFor(() => expect(verdict()).toHaveTextContent('Malformed token'));
    expect(screen.getByRole('button', { name: 'Copy payload' })).toBeDisabled();
  });
});

describe('RSA-PSS, EdDSA and legacy key formats', () => {
  const { generateKeyPairSync } = require('crypto');
  const select = () => screen.getAllByLabelText('Algorithm')[0];
  const openSign = () => fireEvent.click(screen.getByRole('tab', { name: 'Sign a token' }));

  test('the algorithm list is grouped by family and includes PS and EdDSA', async () => {
    render(<App />);
    openSign();
    await waitFor(() => expect(verdict()).toHaveTextContent('New token generated'));
    const groups = [...select().querySelectorAll('optgroup')].map((g) => g.label);
    expect(groups).toEqual(['HMAC', 'RSA', 'RSA-PSS', 'ECDSA', 'EdDSA']);
    const options = [...select().querySelectorAll('option')].map((o) => o.value);
    expect(options).toEqual(expect.arrayContaining(['PS256', 'PS384', 'PS512', 'EdDSA']));
  });

  test('EdDSA signs with an Ed25519 key and the key panel says which key it wants', async () => {
    const pair = generateKeyPairSync('ed25519');
    render(<App />);
    openSign();
    await waitFor(() => expect(verdict()).toHaveTextContent('New token generated'));
    fireEvent.change(select(), { target: { value: 'EdDSA' } });
    await waitFor(() => expect(verdict()).toHaveTextContent('Cannot sign yet'));
    expect(screen.getByText(/PKCS#8, PKCS#1 or SEC1, unencrypted \u00b7 Ed25519/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Private key (PEM)'), {
      target: { value: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }) },
    });
    await waitFor(() => expect(verdict()).toHaveTextContent('New token generated'));
    expect(verdict()).toHaveTextContent(/Signed with EdDSA/);
  });

  test('PS256 signs with a PKCS#1 private key', async () => {
    const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
    render(<App />);
    openSign();
    await waitFor(() => expect(verdict()).toHaveTextContent('New token generated'));
    fireEvent.change(select(), { target: { value: 'PS256' } });
    fireEvent.change(await screen.findByLabelText('Private key (PEM)'), {
      target: { value: pair.privateKey.export({ type: 'pkcs1', format: 'pem' }) },
    });
    await waitFor(() => expect(verdict()).toHaveTextContent(/Signed with PS256/));
  });
});

// @vitest-environment node
// Guards the privacy promise in the files that make it: no third-party requests, one CSP everywhere.
import { readFileSync } from 'fs';
import { join } from 'path';

const root = join(__dirname, '..');
const read = (file) => readFileSync(join(root, file), 'utf8');
const html = read('index.html');
const vercel = JSON.parse(read('vercel.json'));
const envCsp = /VITE_CSP="([^"]*)"/.exec(read('.env.production'))[1];
const headerValue = (key) =>
  vercel.headers[0].headers.find((h) => h.key.toLowerCase() === key.toLowerCase())?.value;
const directives = (policy) =>
  Object.fromEntries(policy.split(';').map((d) => d.trim().split(/\s+/)).map(([name, ...values]) => [name, values]));

describe('index.html', () => {
  test('loads nothing from another origin', () => {
    expect(html).not.toMatch(/(href|src)\s*=\s*"(https?:)?\/\//i);
    expect(html).not.toMatch(/preconnect|dns-prefetch|prefetch|preload/i);
    expect(html).not.toMatch(/fonts\.(googleapis|gstatic)\.com/);
  });

  test('the CSP meta is the first thing after the charset, before any link or script', () => {
    const head = html.slice(html.indexOf('<head>'), html.indexOf('</head>'));
    const withoutComments = head.replace(/<!--[\s\S]*?-->/g, '');
    const tags = [...withoutComments.matchAll(/<(meta|link|script|title)\b[^>]*>/gi)].map((m) => m[0]);
    expect(tags[0]).toMatch(/charset/i);
    expect(tags[1]).toMatch(/Content-Security-Policy/);
  });

  test('fonts are bundled, not linked', () => {
    const entry = read('src/main.jsx');
    expect(entry).toMatch(/@fontsource\/ibm-plex-sans\/latin-400\.css/);
    expect(entry).toMatch(/@fontsource\/ibm-plex-mono\/latin-400\.css/);
  });
});

describe('content security policy', () => {
  const policy = directives(envCsp);

  test('forbids network access, plugins, base changes and form posts', () => {
    expect(policy['default-src']).toEqual(["'self'"]);
    expect(policy['connect-src']).toEqual(["'none'"]);
    expect(policy['object-src']).toEqual(["'none'"]);
    expect(policy['base-uri']).toEqual(["'none'"]);
    expect(policy['form-action']).toEqual(["'none'"]);
  });

  test('allows no inline or eval code, and no other origin for anything', () => {
    expect(envCsp).not.toMatch(/unsafe-inline|unsafe-eval|https?:|\*/);
    expect(policy['script-src']).toEqual(["'self'"]);
    expect(policy['style-src']).toEqual(["'self'"]);
    expect(policy['font-src']).toEqual(["'self'"]);
  });

  test('the HTTP header is the same policy plus frame-ancestors none', () => {
    expect(headerValue('Content-Security-Policy')).toBe(`${envCsp}; frame-ancestors 'none'`);
  });
});

describe('deployment', () => {
  test('the host publishes the folder Vite builds into, whatever framework preset the project has', () => {
    const outDir = /outDir:\s*'([^']+)'/.exec(read('vite.config.mjs'))[1];
    expect(vercel.outputDirectory).toBe(outDir);
    expect(vercel.buildCommand).toBe('npm run build');
    expect(JSON.parse(read('package.json')).scripts.build).toBe('vite build');
  });
});

describe('response headers', () => {
  test('apply to every path and add the basic hardening set', () => {
    expect(vercel.headers[0].source).toBe('/(.*)');
    expect(headerValue('X-Content-Type-Options')).toBe('nosniff');
    expect(headerValue('Referrer-Policy')).toBe('no-referrer');
    expect(headerValue('X-Frame-Options')).toBe('DENY');
    expect(headerValue('Cross-Origin-Opener-Policy')).toBe('same-origin');
    expect(headerValue('Permissions-Policy')).toMatch(/camera=\(\)/);
  });
});

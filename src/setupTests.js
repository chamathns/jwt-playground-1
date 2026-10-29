import '@testing-library/jest-dom';
import { TextDecoder, TextEncoder } from 'util';
import { webcrypto } from 'crypto';

// jsdom (the CRA test environment) has no Web Crypto or text codecs; Node does.
Object.assign(globalThis, { TextEncoder, TextDecoder });
Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });

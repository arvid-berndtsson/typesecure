/**
 * @jest-environment node
 */
import { piiText, publicText, secretText, token, credential, reveal, isClassified } from '../src';

describe('Classification core', () => {
  test('constructors create classified values', () => {
    const s = secretText('shh');
    const p = piiText('user@example.com');
    const pub = publicText('hello');
    const t = token('abc.def.ghi');
    const c = credential('user:pass');

    expect(isClassified(s)).toBe(true);
    expect(isClassified(p)).toBe(true);
    expect(isClassified(pub)).toBe(true);
    expect(isClassified(t)).toBe(true);
    expect(isClassified(c)).toBe(true);
  });

  test('reveal returns underlying value', () => {
    const s = secretText('top-secret');
    expect(reveal(s)).toBe('top-secret');
  });
});


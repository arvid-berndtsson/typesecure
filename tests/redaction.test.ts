/**
 * @jest-environment node
 */
import { piiText, secretText, token, redact, safeJsonStringify } from '../src';

describe('Redaction', () => {
  test('redacts classified values deeply', () => {
    const payload = {
      user: { email: piiText('user@example.com') },
      auth: { token: token('abc') },
      secret: secretText('dont-leak'),
      arr: [secretText('x'), { nested: piiText('y') }],
    };

    const r = redact(payload);
    expect(JSON.stringify(r)).toContain('[REDACTED:pii]');
    expect(JSON.stringify(r)).toContain('[REDACTED:token]');
    expect(JSON.stringify(r)).toContain('[REDACTED:secret]');
    expect(JSON.stringify(r)).not.toContain('dont-leak');
  });

  test('guesses by suspicious keys', () => {
    const payload = { password: 'plain-text-password', apiKey: 'k', normal: 'ok' };
    const r = redact(payload);
    expect((r as any).password).toContain('[REDACTED:unknown]');
    expect((r as any).apiKey).toContain('[REDACTED:unknown]');
    expect((r as any).normal).toBe('ok');
  });

  test('safeJsonStringify produces JSON with redactions', () => {
    const payload = { token: token('abc') };
    const s = safeJsonStringify(payload);
    expect(s).toContain('[REDACTED:token]');
    expect(s).not.toContain('abc');
  });
});


/**
 * @jest-environment node
 */
import { defaultPolicy, assertAllowed, audit, secretText, piiText, token, publicText, policyLog } from '../src';

describe('Policy', () => {
  test('default policy denies logging secrets and pii', () => {
    const policy = defaultPolicy();
    expect(() => assertAllowed(policy, 'log', { s: secretText('x') })).toThrow();
    expect(() => assertAllowed(policy, 'log', { p: piiText('y') })).toThrow();
    expect(() => assertAllowed(policy, 'log', { ok: publicText('hello') })).not.toThrow();
  });

  test('default policy allows tokens over network', () => {
    const policy = defaultPolicy();
    expect(() => assertAllowed(policy, 'network', { token: token('abc') })).not.toThrow();
  });

  test('audit returns decision payload', () => {
    const policy = defaultPolicy();
    const evt = audit(policy, 'log', { s: secretText('x') });
    expect(evt.policy).toBe('typesecure.default');
    expect(evt.decision.allowed).toBe(false);
  });

  test('policyLog redacts (instead of leaking) when allowed', () => {
    const policy = defaultPolicy();
    const logger = { log: jest.fn(), info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() };
    // token is allowed for network, not for log; this should throw before logging
    expect(() => policyLog(policy, logger, 'log', publicText('hello'), { token: token('abc') })).toThrow();
    expect(logger.log).not.toHaveBeenCalled();
  });
});


/**
 * Testing utilities for typesecure.
 * Import these in your test files or add to jest.setup.ts for global availability.
 */

import {
  type DataClassification,
  classificationOf,
  isClassified,
} from "./classification";
import { type Policy, type PolicyDecision, decide } from "./policy";
import { redact } from "./redaction";

/**
 * Jest matcher to check if a value is classified as a specific kind.
 *
 * @example
 * ```ts
 * expect(piiText("user@example.com")).toBeClassifiedAs("pii");
 * ```
 */
export function toBeClassifiedAs(
  received: unknown,
  expectedKind: DataClassification,
): { pass: boolean; message: () => string } {
  const pass = isClassified(received) && received.kind === expectedKind;
  const kind = classificationOf(received);

  return {
    pass,
    message: () =>
      pass
        ? `Expected value not to be classified as "${expectedKind}"`
        : `Expected value to be classified as "${expectedKind}", but got ${
            kind ? `"${kind}"` : "unclassified"
          }`,
  };
}

/**
 * Jest matcher to check if a value is classified (any kind).
 *
 * @example
 * ```ts
 * expect(piiText("user@example.com")).toBeClassified();
 * expect("plain string").not.toBeClassified();
 * ```
 */
export function toBeClassified(
  received: unknown,
): { pass: boolean; message: () => string } {
  const pass = isClassified(received);
  const kind = classificationOf(received);

  return {
    pass,
    message: () =>
      pass
        ? "Expected value not to be classified"
        : `Expected value to be classified, but got ${
            kind ? `"${kind}"` : "unclassified"
          }`,
  };
}

/**
 * Jest matcher to check if a policy allows an action.
 *
 * @example
 * ```ts
 * expect(policy).toAllowAction("log", { message: publicText("OK") });
 * expect(policy).not.toAllowAction("log", { email: piiText("user@example.com") });
 * ```
 */
export function toAllowAction(
  received: Policy,
  action: string,
  data: unknown,
): { pass: boolean; message: () => string } {
  const decision = decide(received, action as Parameters<typeof decide>[1], data);
  const pass = decision.allowed;

  return {
    pass,
    message: () =>
      pass
        ? `Expected policy not to allow "${action}" with the given data`
        : `Expected policy to allow "${action}" with the given data, but it was denied: ${
            decision.reason ?? "Unknown reason"
          }`,
  };
}

/**
 * Jest matcher to check if a value is redacted.
 *
 * @example
 * ```ts
 * const redacted = redact({ email: piiText("user@example.com") });
 * expect(redacted.email).toBeRedacted();
 * ```
 */
export function toBeRedacted(received: unknown): { pass: boolean; message: () => string } {
  const isString = typeof received === "string";
  const looksRedacted =
    isString && /^\[REDACTED:/.test(received as string);

  return {
    pass: looksRedacted,
    message: () =>
      looksRedacted
        ? "Expected value not to be redacted"
        : `Expected value to be redacted, but got: ${JSON.stringify(received)}`,
  };
}

/**
 * Jest matcher to check if a value is redacted with a specific kind.
 *
 * @example
 * ```ts
 * const redacted = redact({ email: piiText("user@example.com") });
 * expect(redacted.email).toBeRedactedAs("pii");
 * ```
 */
export function toBeRedactedAs(
  received: unknown,
  expectedKind: DataClassification | "unknown",
): { pass: boolean; message: () => string } {
  const isString = typeof received === "string";
  const expectedPattern = `[REDACTED:${expectedKind}]`;
  const pass = isString && (received as string) === expectedPattern;

  return {
    pass,
    message: () =>
      pass
        ? `Expected value not to be redacted as "${expectedKind}"`
        : `Expected value to be redacted as "${expectedKind}", but got: ${JSON.stringify(
            received,
          )}`,
  };
}

/**
 * Type definitions for Jest custom matchers.
 * Add this to your jest.d.ts or test setup file.
 */
export interface TypesecureMatchers<R = unknown> {
  toBeClassifiedAs(expectedKind: DataClassification): R;
  toBeClassified(): R;
  toAllowAction(action: string, data: unknown): R;
  toBeRedacted(): R;
  toBeRedactedAs(expectedKind: DataClassification | "unknown"): R;
}

// ---- Test Helpers ----

/**
 * Create a mock policy for testing.
 *
 * @param overrides - Partial policy to override defaults
 * @returns A policy instance
 *
 * @example
 * ```ts
 * const permissivePolicy = createMockPolicy({
 *   name: "test",
 *   allow: {
 *     log: new Set(["public", "pii"]),
 *   }
 * });
 * ```
 */
export function createMockPolicy(
  overrides?: Partial<Policy>,
): Policy {
  const defaultPolicy: Policy = {
    name: "test-policy",
    allow: {
      log: new Set(["public", "pii", "secret", "token", "credential"]),
      network: new Set(["public", "pii", "secret", "token", "credential"]),
      storage: new Set(["public", "pii", "secret", "token", "credential"]),
      analytics: new Set(["public", "pii", "secret", "token", "credential"]),
    },
  };

  return { ...defaultPolicy, ...overrides } as Policy;
}

/**
 * Assert that a policy decision matches expectations.
 *
 * @param decision - The policy decision to check
 * @param expectedAllowed - Whether the action should be allowed
 * @param expectedKinds - Expected classification kinds detected
 *
 * @example
 * ```ts
 * const decision = decide(policy, "log", { email: piiText("user@example.com") });
 * assertPolicyDecision(decision, false, ["pii"]);
 * ```
 */
export function assertPolicyDecision(
  decision: PolicyDecision,
  expectedAllowed: boolean,
  expectedKinds?: DataClassification[],
): void {
  if (decision.allowed !== expectedAllowed) {
    throw new Error(
      `Expected decision.allowed to be ${expectedAllowed}, but got ${decision.allowed}`,
    );
  }

  if (expectedKinds !== undefined) {
    const actualKinds = decision.detectedKinds ?? [];
    const missing = expectedKinds.filter((k) => !actualKinds.includes(k));
    const extra = actualKinds.filter((k) => !expectedKinds.includes(k));

    if (missing.length > 0 || extra.length > 0) {
      throw new Error(
        `Expected detectedKinds to be [${expectedKinds.join(", ")}], but got [${actualKinds.join(", ")}]`,
      );
    }
  }
}

/**
 * Helper to test redaction behavior.
 *
 * @param input - Input value to redact
 * @param expectedOutput - Expected redacted output
 * @param options - Redaction options
 *
 * @example
 * ```ts
 * testRedaction(
 *   { email: piiText("user@example.com") },
 *   { email: "[REDACTED:pii]" }
 * );
 * ```
 */
export function testRedaction<T>(
  input: T,
  expectedOutput: T,
  options?: Parameters<typeof redact>[1],
): void {
  const result = redact(input, options);
  if (JSON.stringify(result) !== JSON.stringify(expectedOutput)) {
    throw new Error(
      `Expected redaction result to match, but got: ${JSON.stringify(result)}`,
    );
  }
}

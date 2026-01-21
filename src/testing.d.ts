/**
 * Type definitions for typesecure Jest matchers.
 * Add this to your tsconfig.json types array or import in your test files.
 */

import type { DataClassification } from "./classification";
import type { Policy } from "./policy";

export interface TypesecureMatchers<R = unknown> {
  /**
   * Check if a value is classified as a specific kind.
   *
   * @example
   * ```ts
   * expect(piiText("user@example.com")).toBeClassifiedAs("pii");
   * ```
   */
  toBeClassifiedAs(expectedKind: DataClassification): R;

  /**
   * Check if a value is classified (any kind).
   *
   * @example
   * ```ts
   * expect(piiText("user@example.com")).toBeClassified();
   * ```
   */
  toBeClassified(): R;

  /**
   * Check if a policy allows an action.
   *
   * @example
   * ```ts
   * expect(policy).toAllowAction("log", { message: publicText("OK") });
   * ```
   */
  toAllowAction(action: string, data: unknown): R;

  /**
   * Check if a value is redacted.
   *
   * @example
   * ```ts
   * const redacted = redact({ email: piiText("user@example.com") });
   * expect(redacted.email).toBeRedacted();
   * ```
   */
  toBeRedacted(): R;

  /**
   * Check if a value is redacted with a specific kind.
   *
   * @example
   * ```ts
   * expect(redacted.email).toBeRedactedAs("pii");
   * ```
   */
  toBeRedactedAs(expectedKind: DataClassification | "unknown"): R;
}

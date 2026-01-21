import {
  classificationOf,
  isClassified,
  type DataClassification,
} from "./classification";
import { redact, type RedactOptions } from "./redaction";

/**
 * Actions that can be performed with classified data.
 * Each action has different security requirements.
 *
 * - `log`: Writing to logs (console, file, etc.)
 * - `network`: Sending over network (HTTP requests, etc.)
 * - `storage`: Writing to storage (database, file system, etc.)
 * - `analytics`: Sending to analytics services
 */
export type PolicyAction = "log" | "network" | "storage" | "analytics";

/**
 * Result of a policy decision check.
 *
 * @example
 * ```ts
 * const decision = decide(policy, "log", { email: piiText("user@example.com") });
 * if (!decision.allowed) {
 *   console.error(decision.reason);
 * }
 * ```
 */
export type PolicyDecision = Readonly<{
  /** Whether the action is allowed */
  allowed: boolean;
  /** Human-readable reason if not allowed */
  reason?: string;
  /** All classification kinds detected in the data */
  detectedKinds?: DataClassification[];
}>;

/**
 * Security policy defining what classifications are allowed for each action.
 *
 * @example
 * ```ts
 * const policy = defaultPolicy();
 * // Allows: public in logs, public+token in network, all in storage
 * ```
 */
export type Policy = Readonly<{
  /** Policy name for identification */
  name: string;
  /** Map of actions to allowed classification kinds */
  allow: Record<PolicyAction, ReadonlySet<DataClassification>>;
  /** Actions that should redact data before execution */
  redactBefore?: ReadonlySet<PolicyAction>;
  /** Redaction options to use when redacting */
  redaction?: RedactOptions;
}>;

function detectedKindsDeep(
  value: unknown,
  maxDepth: number = 25,
): DataClassification[] {
  const kinds = new Set<DataClassification>();
  const seen = new WeakSet<object>();

  const walk = (v: unknown, depth: number): void => {
    if (depth > maxDepth) return;
    const kind = classificationOf(v);
    if (kind) kinds.add(kind);

    if (Array.isArray(v)) {
      for (const item of v) walk(item, depth + 1);
      return;
    }

    if (typeof v === "object" && v !== null) {
      if (seen.has(v)) return;
      seen.add(v);
      if (isClassified(v)) return; // already recorded kind above
      for (const val of Object.values(v as Record<string, unknown>)) {
        walk(val, depth + 1);
      }
    }
  };

  walk(value, 0);
  return [...kinds];
}

/**
 * Create the default security policy.
 *
 * Default rules:
 * - `log`: Only `public` allowed
 * - `analytics`: Only `public` allowed
 * - `network`: `public` and `token` allowed
 * - `storage`: All classifications allowed
 *
 * Logs and analytics automatically redact data before execution.
 *
 * @returns A new default policy instance
 *
 * @example
 * ```ts
 * const policy = defaultPolicy();
 * assertAllowed(policy, "log", { message: publicText("OK") }); // ✓
 * assertAllowed(policy, "log", { email: piiText("user@example.com") }); // ✗ throws
 * ```
 */
export function defaultPolicy(): Policy {
  const allow = {
    log: new Set<DataClassification>(["public"]),
    analytics: new Set<DataClassification>(["public"]),
    network: new Set<DataClassification>(["public", "token"]),
    storage: new Set<DataClassification>([
      "public",
      "pii",
      "secret",
      "token",
      "credential",
    ]),
  } as const;

  return {
    name: "typesecure.default",
    allow,
    redactBefore: new Set<PolicyAction>(["log", "analytics"]),
    redaction: { guessByKey: true },
  };
}

/**
 * Check if an action is allowed by the policy without throwing.
 * Use `assertAllowed()` if you want to throw on violation.
 *
 * @param policy - The policy to check against
 * @param action - The action to check
 * @param data - The data containing classified values
 * @returns A decision object with allowed status and details
 *
 * @example
 * ```ts
 * const decision = decide(policy, "log", { email: piiText("user@example.com") });
 * if (!decision.allowed) {
 *   console.error("Not allowed:", decision.reason);
 * }
 * ```
 */
export function decide(
  policy: Policy,
  action: PolicyAction,
  data: unknown,
): PolicyDecision {
  const detected = detectedKindsDeep(data);
  const allowedKinds = policy.allow[action];

  const disallowed = detected.filter((k) => !allowedKinds.has(k));
  if (disallowed.length > 0) {
    return {
      allowed: false,
      reason: `Policy '${policy.name}' disallows kinds [${disallowed.join(", ")}] for action '${action}'.`,
      detectedKinds: detected,
    };
  }

  return { allowed: true, detectedKinds: detected };
}

/**
 * Assert that an action is allowed by the policy. Throws if not allowed.
 * Use `decide()` if you want to handle violations without throwing.
 *
 * @param policy - The policy to check against
 * @param action - The action to check
 * @param data - The data containing classified values
 * @throws {Error} If the action is not allowed by the policy
 *
 * @example
 * ```ts
 * try {
 *   assertAllowed(policy, "log", { email: piiText("user@example.com") });
 * } catch (error) {
 *   // Policy violation: PII not allowed in logs
 * }
 * ```
 */
export function assertAllowed(
  policy: Policy,
  action: PolicyAction,
  data: unknown,
): void {
  const d = decide(policy, action, data);
  if (!d.allowed) {
    throw new Error(d.reason ?? "Policy denied action.");
  }
}

/**
 * Audit event recording a policy check.
 */
export type AuditEvent = Readonly<{
  /** Timestamp of the audit event */
  at: number;
  /** Policy name that was checked */
  policy: string;
  /** Action that was checked */
  action: PolicyAction;
  /** Decision result */
  decision: PolicyDecision;
}>;

/**
 * Create an audit event for a policy check without throwing.
 * Useful for logging policy decisions without enforcing them.
 *
 * @param policy - The policy to check
 * @param action - The action to check
 * @param data - The data containing classified values
 * @returns An audit event with the decision
 *
 * @example
 * ```ts
 * const event = audit(policy, "log", { email: piiText("user@example.com") });
 * console.log(`Policy check: ${event.decision.allowed ? "allowed" : "denied"}`);
 * ```
 */
export function audit(
  policy: Policy,
  action: PolicyAction,
  data: unknown,
): AuditEvent {
  return {
    at: Date.now(),
    policy: policy.name,
    action,
    decision: decide(policy, action, data),
  };
}

/**
 * Safe logging helper that enforces policy and optionally redacts data.
 * Throws if the policy disallows logging the data.
 *
 * @param policy - The policy to enforce
 * @param logger - Logger instance (console, pino, winston, etc.)
 * @param level - Log level to use
 * @param args - Arguments to log (will be checked and redacted if configured)
 * @throws {Error} If the policy disallows logging the data
 *
 * @example
 * ```ts
 * const policy = defaultPolicy();
 * policyLog(policy, console, "info", publicText("User logged in"), { userId: 123 });
 * // ✓ Allowed and logged (redacted if configured)
 *
 * policyLog(policy, console, "info", { email: piiText("user@example.com") });
 * // ✗ Throws: PII not allowed in logs
 * ```
 */
export function policyLog(
  policy: Policy,
  logger: Pick<Console, "info" | "warn" | "error" | "debug" | "log">,
  level: keyof Pick<Console, "info" | "warn" | "error" | "debug" | "log">,
  ...args: unknown[]
): void {
  assertAllowed(policy, "log", args);
  const shouldRedact = policy.redactBefore?.has("log") ?? false;
  const out = shouldRedact
    ? args.map((a) => redact(a, policy.redaction))
    : args;
  logger[level](...out);
}

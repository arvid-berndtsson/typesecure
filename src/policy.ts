import { classificationOf, isClassified, type DataClassification } from './classification';
import { redact, type RedactOptions } from './redaction';

export type PolicyAction = 'log' | 'network' | 'storage' | 'analytics';

export type PolicyDecision = Readonly<{
  allowed: boolean;
  reason?: string;
  detectedKinds?: DataClassification[];
}>;

export type Policy = Readonly<{
  name: string;
  allow: Record<PolicyAction, ReadonlySet<DataClassification>>;
  redactBefore?: ReadonlySet<PolicyAction>;
  redaction?: RedactOptions;
}>;

function detectedKindsDeep(value: unknown, maxDepth: number = 25): DataClassification[] {
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

    if (typeof v === 'object' && v !== null) {
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

export function defaultPolicy(): Policy {
  const allow = {
    log: new Set<DataClassification>(['public']),
    analytics: new Set<DataClassification>(['public']),
    network: new Set<DataClassification>(['public', 'token']),
    storage: new Set<DataClassification>(['public', 'pii', 'secret', 'token', 'credential']),
  } as const;

  return {
    name: 'typesecure.default',
    allow,
    redactBefore: new Set<PolicyAction>(['log', 'analytics']),
    redaction: { guessByKey: true },
  };
}

export function decide(policy: Policy, action: PolicyAction, data: unknown): PolicyDecision {
  const detected = detectedKindsDeep(data);
  const allowedKinds = policy.allow[action];

  const disallowed = detected.filter((k) => !allowedKinds.has(k));
  if (disallowed.length > 0) {
    return {
      allowed: false,
      reason: `Policy '${policy.name}' disallows kinds [${disallowed.join(', ')}] for action '${action}'.`,
      detectedKinds: detected,
    };
  }

  return { allowed: true, detectedKinds: detected };
}

export function assertAllowed(policy: Policy, action: PolicyAction, data: unknown): void {
  const d = decide(policy, action, data);
  if (!d.allowed) {
    throw new Error(d.reason ?? 'Policy denied action.');
  }
}

export type AuditEvent = Readonly<{
  at: number;
  policy: string;
  action: PolicyAction;
  decision: PolicyDecision;
}>;

export function audit(policy: Policy, action: PolicyAction, data: unknown): AuditEvent {
  return {
    at: Date.now(),
    policy: policy.name,
    action,
    decision: decide(policy, action, data),
  };
}

/**
 * Safe sink example: log with enforcement + redaction (if configured).
 */
export function policyLog(
  policy: Policy,
  logger: Pick<Console, 'info' | 'warn' | 'error' | 'debug' | 'log'>,
  level: keyof Pick<Console, 'info' | 'warn' | 'error' | 'debug' | 'log'>,
  ...args: unknown[]
): void {
  assertAllowed(policy, 'log', args);
  const shouldRedact = policy.redactBefore?.has('log') ?? false;
  const out = shouldRedact ? args.map((a) => redact(a, policy.redaction)) : args;
  logger[level](...out);
}


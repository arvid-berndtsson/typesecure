import {
  classificationOf,
  isClassified,
  reveal,
  type DataClassification,
} from "./classification";

/**
 * Options for redaction behavior.
 *
 * @example
 * ```ts
 * const redacted = redact(data, {
 *   guessByKey: true,
 *   placeholder: (kind) => `[REDACTED:${kind}]`,
 *   maxDepth: 10
 * });
 * ```
 */
export type RedactOptions = Readonly<{
  /**
   * If true, redact values for suspicious keys even if they aren't classified.
   * Defaults to true.
   *
   * @default true
   */
  guessByKey?: boolean;
  /**
   * Placeholder format for redacted values.
   * Defaults to "[REDACTED:<kind>]".
   *
   * @default (kind) => `[REDACTED:${kind}]`
   */
  placeholder?: (kind: DataClassification | "unknown") => string;
  /**
   * Max depth to traverse to avoid pathological structures.
   * Defaults to 25.
   *
   * @default 25
   */
  maxDepth?: number;
}>;

const DEFAULT_SUSPICIOUS_KEY =
  /pass(word)?|pwd|secret|token|api[_-]?key|auth|bearer|cookie|session|private[_-]?key|ssh|credential/i;

function defaultPlaceholder(kind: DataClassification | "unknown"): string {
  return `[REDACTED:${kind}]`;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    (Object.getPrototypeOf(value) === Object.prototype ||
      Object.getPrototypeOf(value) === null)
  );
}

/**
 * Deeply redact classified data and suspicious keys in objects/arrays.
 * Returns a new structure with classified values replaced by placeholders.
 *
 * @param value - The value to redact (can be any type)
 * @param options - Redaction options
 * @returns A redacted copy of the value
 *
 * @example
 * ```ts
 * const data = {
 *   email: piiText("user@example.com"),
 *   password: secretText("secret123"),
 *   name: "John"
 * };
 * const redacted = redact(data);
 * // { email: "[REDACTED:pii]", password: "[REDACTED:secret]", name: "John" }
 * ```
 */
export function redact<T>(value: T, options?: RedactOptions): T {
  const guessByKey = options?.guessByKey ?? true;
  const placeholder = options?.placeholder ?? defaultPlaceholder;
  const maxDepth = options?.maxDepth ?? 25;

  const seen = new WeakMap<object, unknown>();

  const walk = (v: unknown, depth: number, keyHint?: string): unknown => {
    if (depth > maxDepth) return placeholder("unknown");

    const kind = classificationOf(v);
    if (kind) return placeholder(kind);

    if (guessByKey && keyHint && DEFAULT_SUSPICIOUS_KEY.test(keyHint)) {
      // If the value is classified we already handled it above.
      // For suspicious keys, redact primitive values immediately, but still traverse objects/arrays
      // so we can preserve structure and redact nested classified fields with accurate kinds.
      if (v === null) return placeholder("unknown");
      const t = typeof v;
      if (
        t === "string" ||
        t === "number" ||
        t === "boolean" ||
        t === "bigint"
      ) {
        return placeholder("unknown");
      }
      // fall through for objects/arrays
    }

    if (Array.isArray(v)) {
      return v.map((item) => walk(item, depth + 1));
    }

    if (isPlainObject(v)) {
      if (seen.has(v)) return seen.get(v);
      const out: Record<string, unknown> = {};
      seen.set(v, out);
      for (const [k, val] of Object.entries(v)) {
        out[k] = walk(val, depth + 1, k);
      }
      return out;
    }

    if (isClassified(v)) {
      // Should be handled by classificationOf, but keep this for extra safety.
      return placeholder(v.kind);
    }

    // Leave primitives + non-plain objects alone.
    return v;
  };

  return walk(value, 0) as T;
}

/**
 * Safely stringify JSON with automatic redaction of classified data.
 * Equivalent to `JSON.stringify(redact(value, options), null, space)`.
 *
 * @param value - The value to stringify
 * @param options - Redaction options
 * @param space - JSON.stringify spacing (same as JSON.stringify)
 * @returns A JSON string with classified data redacted
 *
 * @example
 * ```ts
 * const data = { email: piiText("user@example.com") };
 * const json = safeJsonStringify(data, undefined, 2);
 * // '{\n  "email": "[REDACTED:pii]"\n}'
 * ```
 */
export function safeJsonStringify(
  value: unknown,
  options?: RedactOptions,
  space?: number,
): string {
  return JSON.stringify(redact(value, options), null, space);
}

/**
 * Convenience logger that will redact classified data and suspicious keys.
 * You can pass your own logger implementation (pino, winston, console, etc).
 */
export function safeLoggerAdapter(
  logger: Pick<Console, "info" | "warn" | "error" | "debug" | "log">,
): {
  info: (...args: unknown[]) => void;
  warn: (...args: unknown[]) => void;
  error: (...args: unknown[]) => void;
  debug: (...args: unknown[]) => void;
  log: (...args: unknown[]) => void;
} {
  return {
    info: (...args: unknown[]): void =>
      logger.info(...args.map((a) => redact(a))),
    warn: (...args: unknown[]): void =>
      logger.warn(...args.map((a) => redact(a))),
    error: (...args: unknown[]): void =>
      logger.error(...args.map((a) => redact(a))),
    debug: (...args: unknown[]): void =>
      logger.debug(...args.map((a) => redact(a))),
    log: (...args: unknown[]): void =>
      logger.log(...args.map((a) => redact(a))),
  };
}

/**
 * Helper for cases where you must emit a raw header value.
 * Prefer using the policy layer to validate crossings before revealing.
 */
export function httpAuthorizationBearer(
  tokenValue: import("./classification").TokenString,
): string {
  return `Bearer ${reveal(tokenValue)}`;
}

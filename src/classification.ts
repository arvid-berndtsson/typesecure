import { z } from "zod";

/**
 * Data classification levels for security enforcement.
 *
 * @example
 * ```ts
 * const email = piiText("user@example.com");
 * const token = token("abc.def.ghi");
 * ```
 */
export type DataClassification =
  | "public"
  | "pii"
  | "secret"
  | "token"
  | "credential";

const TYPESECURE_SYMBOL: unique symbol = Symbol.for(
  "typesecure.classified",
) as unknown as typeof TYPESECURE_SYMBOL;

/**
 * Base type for classified data. Use specific constructors like `publicText()`, `piiText()`, etc.
 *
 * @template K - The classification kind
 * @template T - The underlying value type (typically string)
 */
export type Classified<K extends DataClassification, T> = Readonly<{
  kind: K;
  value: T;
  [TYPESECURE_SYMBOL]: true;
}>;

/**
 * Public data that can be safely logged, sent over network, or stored.
 *
 * @example
 * ```ts
 * const message = publicText("User logged in");
 * console.log(message); // Safe to log
 * ```
 */
export type PublicString = Classified<"public", string>;

/**
 * Personally Identifiable Information (PII) - requires careful handling.
 * Allowed in storage but should be redacted before logging or analytics.
 *
 * @example
 * ```ts
 * const email = piiText("user@example.com");
 * // Can be stored, but will be redacted in logs
 * ```
 */
export type PIIString = Classified<"pii", string>;

/**
 * Secret data (passwords, API keys, etc.) - highest security level.
 * Should never appear in logs, analytics, or error messages.
 *
 * @example
 * ```ts
 * const password = secretText(process.env.DB_PASSWORD ?? "");
 * // Will be blocked from logging by default policy
 * ```
 */
export type SecretString = Classified<"secret", string>;

/**
 * Authentication tokens - can be sent over network but not logged.
 *
 * @example
 * ```ts
 * const jwt = token("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...");
 * // Can be used in Authorization header, but redacted in logs
 * ```
 */
export type TokenString = Classified<"token", string>;

/**
 * Credentials - similar to secrets but may be used in specific contexts.
 *
 * @example
 * ```ts
 * const apiKey = credential(process.env.API_KEY ?? "");
 * ```
 */
export type CredentialString = Classified<"credential", string>;

function makeClassified<K extends DataClassification, T>(
  kind: K,
  value: T,
): Classified<K, T> {
  return { kind, value, [TYPESECURE_SYMBOL]: true } as const;
}

/**
 * Type guard to check if a value is classified data.
 *
 * @param value - The value to check
 * @returns True if the value is classified data
 *
 * @example
 * ```ts
 * const email = piiText("user@example.com");
 * if (isClassified(email)) {
 *   console.log(email.kind); // "pii"
 * }
 * ```
 */
export function isClassified(
  value: unknown,
): value is Classified<DataClassification, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as Record<string | symbol, unknown>)[TYPESECURE_SYMBOL] === true &&
    typeof (value as { kind?: unknown }).kind === "string" &&
    "value" in (value as Record<string, unknown>)
  );
}

/**
 * Get the classification kind of a value, if it's classified.
 *
 * @param value - The value to check
 * @returns The classification kind, or undefined if not classified
 *
 * @example
 * ```ts
 * const email = piiText("user@example.com");
 * classificationOf(email); // "pii"
 * classificationOf("plain string"); // undefined
 * ```
 */
export function classificationOf(
  value: unknown,
): DataClassification | undefined {
  return isClassified(value) ? value.kind : undefined;
}

/**
 * Intentionally explicit: use this when you need the raw string (e.g. building an HTTP header).
 * Prefer passing classified values to safe sinks/policies instead of revealing early.
 */
export function reveal<T>(value: Classified<DataClassification, T>): T {
  return value.value;
}

// ---- Constructors (Zod-backed) ----

const NonEmptyString = z.string().min(1);

export const PublicStringSchema = NonEmptyString.transform((v) =>
  makeClassified("public", v),
);
export const PIIStringSchema = NonEmptyString.transform((v) =>
  makeClassified("pii", v),
);
export const SecretStringSchema = NonEmptyString.transform((v) =>
  makeClassified("secret", v),
);
export const TokenStringSchema = NonEmptyString.transform((v) =>
  makeClassified("token", v),
);
export const CredentialStringSchema = NonEmptyString.transform((v) =>
  makeClassified("credential", v),
);

/**
 * Create a public string that can be safely logged, sent over network, or stored.
 *
 * @param value - The string value to classify
 * @returns A classified public string
 * @throws {z.ZodError} If the value is empty
 *
 * @example
 * ```ts
 * const message = publicText("User logged in");
 * policyLog(policy, console, "info", message); // Allowed
 * ```
 */
export function publicText(value: string): PublicString {
  return PublicStringSchema.parse(value);
}

/**
 * Create a PII (Personally Identifiable Information) string.
 * Can be stored but will be redacted in logs and analytics.
 *
 * @param value - The string value to classify
 * @returns A classified PII string
 * @throws {z.ZodError} If the value is empty
 *
 * @example
 * ```ts
 * const email = piiText("user@example.com");
 * // Can be stored, but redacted in logs
 * ```
 */
export function piiText(value: string): PIIString {
  return PIIStringSchema.parse(value);
}

/**
 * Create a secret string (passwords, API keys, etc.).
 * Highest security level - blocked from logs and analytics by default.
 *
 * @param value - The string value to classify
 * @returns A classified secret string
 * @throws {z.ZodError} If the value is empty
 *
 * @example
 * ```ts
 * const password = secretText(process.env.DB_PASSWORD ?? "");
 * // Will throw if attempted to log with default policy
 * ```
 */
export function secretText(value: string): SecretString {
  return SecretStringSchema.parse(value);
}

/**
 * Create a token string (JWT, session tokens, etc.).
 * Can be sent over network but redacted in logs.
 *
 * @param value - The string value to classify
 * @returns A classified token string
 * @throws {z.ZodError} If the value is empty
 *
 * @example
 * ```ts
 * const jwt = token("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...");
 * // Can be used in Authorization header
 * ```
 */
export function token(value: string): TokenString {
  return TokenStringSchema.parse(value);
}

/**
 * Create a credential string.
 * Similar to secrets but may be used in specific contexts.
 *
 * @param value - The string value to classify
 * @returns A classified credential string
 * @throws {z.ZodError} If the value is empty
 *
 * @example
 * ```ts
 * const apiKey = credential(process.env.API_KEY ?? "");
 * ```
 */
export function credential(value: string): CredentialString {
  return CredentialStringSchema.parse(value);
}

// ---- Utility Types ----

/**
 * Extract the underlying value type from a classified type.
 *
 * @example
 * ```ts
 * type EmailValue = ExtractClassified<PIIString>; // string
 * ```
 */
export type ExtractClassified<T> = T extends Classified<DataClassification, infer U>
  ? U
  : never;

/**
 * Extract the classification kind from a classified type.
 *
 * @example
 * ```ts
 * type EmailKind = ExtractKind<PIIString>; // "pii"
 * ```
 */
export type ExtractKind<T> = T extends Classified<infer K, unknown> ? K : never;

/**
 * Get all classified keys from an object type.
 *
 * @example
 * ```ts
 * type User = {
 *   name: PublicString;
 *   email: PIIString;
 *   password: SecretString;
 * };
 * type ClassifiedKeys = ClassifiedKeys<User>; // "email" | "password"
 * ```
 */
export type ClassifiedKeys<T> = {
  [K in keyof T]: T[K] extends Classified<DataClassification, unknown> ? K : never;
}[keyof T];

import { z } from "zod";

export type DataClassification =
  | "public"
  | "pii"
  | "secret"
  | "token"
  | "credential";

const TYPESECURE_SYMBOL: unique symbol = Symbol.for(
  "typesecure.classified",
) as unknown as typeof TYPESECURE_SYMBOL;

export type Classified<K extends DataClassification, T> = Readonly<{
  kind: K;
  value: T;
  [TYPESECURE_SYMBOL]: true;
}>;

export type PublicString = Classified<"public", string>;
export type PIIString = Classified<"pii", string>;
export type SecretString = Classified<"secret", string>;
export type TokenString = Classified<"token", string>;
export type CredentialString = Classified<"credential", string>;

function makeClassified<K extends DataClassification, T>(
  kind: K,
  value: T,
): Classified<K, T> {
  return { kind, value, [TYPESECURE_SYMBOL]: true } as const;
}

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

export function publicText(value: string): PublicString {
  return PublicStringSchema.parse(value);
}
export function piiText(value: string): PIIString {
  return PIIStringSchema.parse(value);
}
export function secretText(value: string): SecretString {
  return SecretStringSchema.parse(value);
}
export function token(value: string): TokenString {
  return TokenStringSchema.parse(value);
}
export function credential(value: string): CredentialString {
  return CredentialStringSchema.parse(value);
}

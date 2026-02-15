import type { StringDetection, StringDetector } from "./types";

const EMAIL_RE = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const PHONE_RE =
  /\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b/g;
const SSN_RE = /\b\d{3}-\d{2}-\d{4}\b/g;
const DOB_RE = /\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b/g;
const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const CREDIT_CARD_RE = /\b(?:\d[ -]*?){13,19}\b/g;
const JWT_RE =
  /\b[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b/g;
const PRIVATE_KEY_BLOCK_RE =
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g;
const AWS_ACCESS_KEY_RE = /\bAKIA[0-9A-Z]{16}\b/g;
const GITHUB_TOKEN_RE = /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g;
const STRIPE_SECRET_RE = /\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b/g;
const OPENAI_KEY_RE = /\bsk-[A-Za-z0-9]{20,}\b/g;
const CREDENTIAL_PAIR_RE = /\b[^:\s]{1,128}:[^\s:]{1,256}\b/g;
const HIGH_ENTROPY_TOKEN_RE = /\b[A-Za-z0-9+/=_-]{28,}\b/g;

function luhnValid(input: string): boolean {
  const digits = input.replace(/[ -]/g, "");
  if (!/^\d{13,19}$/.test(digits)) return false;

  let sum = 0;
  let shouldDouble = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let d = Number(digits[i]);
    if (shouldDouble) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

function placeholderRanges(
  text: string,
): Array<{ start: number; end: number }> {
  const ranges: Array<{ start: number; end: number }> = [];
  const re = /\[REDACTED:[^\]]+\]/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    ranges.push({ start: m.index, end: m.index + m[0].length });
  }
  return ranges;
}

function overlapsRanges(
  start: number,
  end: number,
  ranges: Array<{ start: number; end: number }>,
): boolean {
  return ranges.some((r) => start < r.end && end > r.start);
}

function detectRegexRanges(
  value: string,
  re: RegExp,
  kind: StringDetection["kind"],
  source: string,
  guard?: (match: string) => boolean,
): StringDetection[] {
  const out: StringDetection[] = [];
  const execRe = new RegExp(re.source, re.flags);
  const protectedRanges = placeholderRanges(value);
  let m: RegExpExecArray | null;

  while ((m = execRe.exec(value)) !== null) {
    const match = m[0];
    const start = m.index;
    const end = start + match.length;

    if (
      !match ||
      (guard && !guard(match)) ||
      overlapsRanges(start, end, protectedRanges)
    ) {
      continue;
    }

    out.push({ start, end, kind, source, confidence: 1 });
    if (execRe.lastIndex === m.index) execRe.lastIndex += 1;
  }

  return out;
}

export const defaultRuleStringDetector: StringDetector = (value) => {
  const out: StringDetection[] = [];

  out.push(
    ...detectRegexRanges(
      value,
      PRIVATE_KEY_BLOCK_RE,
      "secret",
      "rule.private-key",
    ),
    ...detectRegexRanges(value, JWT_RE, "token", "rule.jwt"),
    ...detectRegexRanges(
      value,
      AWS_ACCESS_KEY_RE,
      "credential",
      "rule.aws-access-key",
    ),
    ...detectRegexRanges(value, GITHUB_TOKEN_RE, "token", "rule.github-token"),
    ...detectRegexRanges(
      value,
      STRIPE_SECRET_RE,
      "secret",
      "rule.stripe-secret",
    ),
    ...detectRegexRanges(value, OPENAI_KEY_RE, "secret", "rule.openai-key"),
    ...detectRegexRanges(
      value,
      CREDENTIAL_PAIR_RE,
      "credential",
      "rule.credential-pair",
    ),
  );

  out.push(
    ...detectRegexRanges(value, EMAIL_RE, "pii", "rule.email"),
    ...detectRegexRanges(value, PHONE_RE, "pii", "rule.phone"),
    ...detectRegexRanges(value, SSN_RE, "pii", "rule.ssn"),
    ...detectRegexRanges(value, DOB_RE, "pii", "rule.dob"),
    ...detectRegexRanges(value, IPV4_RE, "pii", "rule.ipv4", (m) =>
      m.split(".").every((p) => Number(p) >= 0 && Number(p) <= 255),
    ),
    ...detectRegexRanges(
      value,
      CREDIT_CARD_RE,
      "pii",
      "rule.credit-card",
      luhnValid,
    ),
  );

  out.push(
    ...detectRegexRanges(
      value,
      HIGH_ENTROPY_TOKEN_RE,
      "token",
      "rule.high-entropy",
      (m) => {
        if (/^[a-z]+$/i.test(m)) return false;
        return /\d/.test(m);
      },
    ),
  );

  return out;
};

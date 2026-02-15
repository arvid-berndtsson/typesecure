/**
 * @jest-environment node
 */
import {
  assertAllowed,
  defaultPolicy,
  piiText,
  policyLog,
  redact,
  safeJsonStringify,
  safeLoggerAdapter,
  token,
} from "../../src";
import { sampleEnronEmails } from "./helpers";

function preview(value: string, limit: number = 72): string {
  const normalized = value.replace(/\s+/g, " ").trim();
  return normalized.length <= limit
    ? normalized
    : `${normalized.slice(0, limit)}...`;
}

describe("Enron dataset checks", () => {
  test("1) sampled corpus looks like real mail (header/body sanity)", () => {
    const emails = sampleEnronEmails(60);
    expect(emails.length).toBeGreaterThanOrEqual(20);

    const withFrom = emails.filter((e) => Boolean(e.headers.from)).length;
    const withSubject = emails.filter((e) => Boolean(e.headers.subject)).length;
    const withBody = emails.filter((e) => e.body.trim().length > 0).length;

    expect(withFrom).toBeGreaterThanOrEqual(15);
    expect(withSubject).toBeGreaterThanOrEqual(10);
    expect(withBody).toBeGreaterThanOrEqual(20);
  });

  test("2) before/after example uses Enron values and proves targeted redaction", () => {
    const emails = sampleEnronEmails(12);
    expect(emails.length).toBeGreaterThan(0);
    const bodySnippet =
      emails[0].body.slice(0, 120) || emails[0].raw.slice(0, 120);
    const headerValue =
      emails[0].headers.from ??
      emails[0].headers.subject ??
      emails[0].raw.slice(0, 48);

    const beforeExample = {
      source: "enron",
      authToken: headerValue,
      sender: headerValue,
      subject: emails[0].headers.subject ?? "",
      body: bodySnippet,
    };
    const afterExample = redact({
      ...beforeExample,
      sender: piiText(headerValue),
    }) as Record<string, unknown>;

    const exampleCount = Math.min(5, emails.length);
    for (let i = 0; i < exampleCount; i += 1) {
      const e = emails[i];
      const tokenValue =
        e.headers.from ?? e.headers.subject ?? e.raw.slice(0, 48);
      const b = e.body.slice(0, 120) || e.raw.slice(0, 120);
      const before = {
        authToken: tokenValue,
        sender: tokenValue,
        subject: e.headers.subject ?? "",
        body: b,
      };
      const after = redact({
        ...before,
        sender: piiText(tokenValue),
      }) as Record<string, unknown>;
      console.info(
        `[enron-example-${i + 1}] token: "${preview(before.authToken)}" -> "${String(
          after.authToken,
        )}" | sender: "${preview(before.sender)}" -> "${String(
          after.sender,
        )}" | body_kept=${String(after.body === before.body)} | subject_kept=${String(
          after.subject === before.subject,
        )}`,
      );
    }

    const samplePayload = {
      messages: emails.map((e) => ({
        authToken: e.headers.from ?? e.headers.subject ?? e.raw.slice(0, 48),
        sender: piiText(e.headers.from ?? e.headers.to ?? e.raw.slice(0, 48)),
        subject: e.headers.subject ?? "",
        body: e.body.slice(0, 120) || e.raw.slice(0, 120),
      })),
    };
    const sampleOut = safeJsonStringify(samplePayload);
    const sampleUnknown = sampleOut.match(/\[REDACTED:unknown\]/g) ?? [];
    const samplePii = sampleOut.match(/\[REDACTED:pii\]/g) ?? [];
    console.info(
      `[enron-redaction-stats] sample_messages=${emails.length} pii_markers=${samplePii.length} unknown_markers=${sampleUnknown.length}`,
    );

    expect(afterExample.authToken).toBe("[REDACTED:unknown]");
    expect(afterExample.sender).toBe("[REDACTED:pii]");
    expect(afterExample.source).toBe("enron");
    expect(typeof afterExample.subject).toBe("string");
    expect(afterExample.subject).not.toBe("[REDACTED:pii]");
    expect(afterExample.subject).not.toBe("[REDACTED:unknown]");
    expect(typeof afterExample.body).toBe("string");
    expect(afterExample.body).not.toBe("[REDACTED:pii]");
    expect(afterExample.body).not.toBe("[REDACTED:unknown]");
  });

  test("3) bulk selective redaction keeps body while redacting sender and authToken", () => {
    const emails = sampleEnronEmails(15);
    expect(emails.length).toBeGreaterThan(0);

    const payload = {
      messages: emails.map((email) => ({
        authToken:
          email.headers.from ?? email.headers.subject ?? email.raw.slice(0, 48),
        sender: piiText(
          email.headers.from ?? email.headers.to ?? email.raw.slice(0, 48),
        ),
        subject: email.headers.subject ?? "",
        body: email.body.slice(0, 200) || email.raw.slice(0, 200),
      })),
    };
    const out = safeJsonStringify(payload, { guessByValue: false });
    const parsed = JSON.parse(out) as {
      messages: Array<{
        authToken: string;
        sender: string;
        subject: string;
        body: string;
      }>;
    };
    const piiMarkers = out.match(/\[REDACTED:pii\]/g) ?? [];
    const unknownMarkers = out.match(/\[REDACTED:unknown\]/g) ?? [];

    expect(piiMarkers.length).toBeGreaterThanOrEqual(emails.length);
    expect(unknownMarkers.length).toBeGreaterThanOrEqual(emails.length);
    expect(parsed.messages[0].sender).toBe("[REDACTED:pii]");
    expect(parsed.messages[0].authToken).toBe("[REDACTED:unknown]");
    expect(parsed.messages[0].body).toBe(payload.messages[0].body);
    expect(parsed.messages[0].subject).toBe(payload.messages[0].subject);
  });

  test("4) suspicious-key redaction is targeted while non-suspicious fields remain", () => {
    const emails = sampleEnronEmails(3);
    expect(emails.length).toBeGreaterThan(0);

    const fromValue = emails[0].headers.from ?? emails[0].raw.slice(0, 32);
    const safeNote = emails[0].headers.subject ?? "enron-note";
    const payload = {
      authToken: fromValue,
      note: safeNote,
      subject: emails[0].headers.subject ?? "",
    };
    const out = safeJsonStringify(payload, { guessByValue: false });
    const parsed = JSON.parse(out) as {
      authToken: string;
      note: string;
      subject: string;
    };

    expect(parsed.authToken).toBe("[REDACTED:unknown]");
    expect(parsed.note).toBe(safeNote);
    expect(parsed.subject).toBe(emails[0].headers.subject ?? "");
  });

  test("5) disabling key guessing keeps unclassified suspicious keys intact", () => {
    const emails = sampleEnronEmails(2);
    expect(emails.length).toBeGreaterThan(0);

    const tokenLike = emails[0].headers.subject ?? emails[0].raw.slice(0, 32);
    const out = safeJsonStringify(
      { authToken: tokenLike },
      {
        guessByKey: false,
        guessByValue: false,
      },
    );

    expect(out).toContain(tokenLike);
    expect(out).not.toContain("[REDACTED:unknown]");
    expect(out).not.toContain("[REDACTED:pii]");
  });

  test("6) safeLoggerAdapter redacts suspicious keys using Enron-derived values", () => {
    const emails = sampleEnronEmails(3);
    expect(emails.length).toBeGreaterThan(0);

    const sessionValue = emails[0].headers.from ?? emails[0].raw.slice(0, 24);
    const cookieValue =
      emails[1]?.headers.to ?? emails[1]?.raw.slice(0, 24) ?? sessionValue;
    const logger = {
      log: jest.fn(),
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
      debug: jest.fn(),
    };
    const safeLogger = safeLoggerAdapter(logger);

    safeLogger.info({
      session: sessionValue,
      cookie: cookieValue,
      message: emails[0].raw.slice(0, 300),
    });

    expect(logger.info).toHaveBeenCalledTimes(1);
    const logged = logger.info.mock.calls[0][0] as Record<string, unknown>;
    expect(logged.session).toBe("[REDACTED:unknown]");
    expect(logged.cookie).toBe("[REDACTED:unknown]");
    expect(typeof logged.message).toBe("string");
  });

  test("7) safeJsonStringify output remains valid JSON after deep redaction", () => {
    const emails = sampleEnronEmails(10);
    expect(emails.length).toBeGreaterThan(0);

    const payload = {
      source: "enron",
      messages: emails.map((e) => ({
        authToken: e.headers.from ?? e.headers.to ?? e.raw.slice(0, 48),
        sender: piiText(e.headers.from ?? e.headers.to ?? e.raw.slice(0, 48)),
        from: e.headers.from ?? "",
        body: e.body.slice(0, 500) || e.raw.slice(0, 500),
      })),
    };
    const out = safeJsonStringify(payload);
    const parsed = JSON.parse(out) as { source: string; messages: unknown[] };

    expect(parsed.source).toBe("enron");
    expect(Array.isArray(parsed.messages)).toBe(true);
    expect(parsed.messages).toHaveLength(emails.length);
  });

  test("8) default policy denies log action when Enron content is classified as pii", () => {
    const emails = sampleEnronEmails(2);
    expect(emails.length).toBeGreaterThan(0);

    const policy = defaultPolicy();
    const logPayload = {
      from: piiText(emails[0].headers.from ?? emails[0].raw.slice(0, 32)),
      subject: emails[0].headers.subject ?? "",
    };
    expect(() => assertAllowed(policy, "log", logPayload)).toThrow();

    const logger = {
      log: jest.fn(),
      info: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
      debug: jest.fn(),
    };
    expect(() =>
      policyLog(policy, logger, "info", "mail-event", logPayload),
    ).toThrow();
    expect(logger.info).not.toHaveBeenCalled();
  });

  test("9) default policy allows network action for token wrapping Enron value", () => {
    const emails = sampleEnronEmails(2);
    expect(emails.length).toBeGreaterThan(0);

    const policy = defaultPolicy();
    const tokenValue = emails[0].headers.from ?? emails[0].raw.slice(0, 32);
    const networkPayload = {
      auth: token(tokenValue),
      subject: emails[0].headers.subject ?? "",
    };

    expect(() =>
      assertAllowed(policy, "network", networkPayload),
    ).not.toThrow();
  });

  test("10) redact keeps object shape stable across sampled records", () => {
    const emails = sampleEnronEmails(6);
    expect(emails.length).toBeGreaterThan(0);

    const source = {
      items: emails.map((email) => ({
        file: email.file,
        headers: email.headers,
        credential: "user:pass",
      })),
    };
    const redacted = redact(source);

    expect(Array.isArray(redacted.items)).toBe(true);
    expect(redacted.items).toHaveLength(source.items.length);
    expect(JSON.stringify(redacted)).toContain("[REDACTED:unknown]");
    expect(
      Object.keys(redacted.items[0] as Record<string, unknown>).sort(),
    ).toEqual(["credential", "file", "headers"]);
  });
});

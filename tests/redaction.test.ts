/**
 * @jest-environment node
 */
import {
  detectText,
  piiText,
  redact,
  redactText,
  safeJsonStringify,
  secretText,
  token,
} from "../src";

describe("Redaction", () => {
  test("redacts classified values deeply", () => {
    const payload = {
      user: { email: piiText("user@example.com") },
      auth: { token: token("abc") },
      secret: secretText("dont-leak"),
      arr: [secretText("x"), { nested: piiText("y") }],
    };

    const r = redact(payload);
    expect(JSON.stringify(r)).toContain("[REDACTED:pii]");
    expect(JSON.stringify(r)).toContain("[REDACTED:token]");
    expect(JSON.stringify(r)).toContain("[REDACTED:secret]");
    expect(JSON.stringify(r)).not.toContain("dont-leak");
  });

  test("guesses by suspicious keys", () => {
    const payload = {
      password: "plain-text-password",
      apiKey: "k",
      normal: "ok",
    };
    const r = redact(payload);
    expect((r as any).password).toContain("[REDACTED:unknown]");
    expect((r as any).apiKey).toContain("[REDACTED:unknown]");
    expect((r as any).normal).toBe("ok");
  });

  test("safeJsonStringify produces JSON with redactions", () => {
    const payload = { token: token("abc") };
    const s = safeJsonStringify(payload);
    expect(s).toContain("[REDACTED:token]");
    expect(s).not.toContain("abc");
  });

  test("auto-detects sensitive values even with non-suspicious keys", () => {
    const payload = {
      notes: "reach me at user@example.com",
      blob: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlX3RleHQ",
      cert: "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC...\n-----END PRIVATE KEY-----",
    };

    const r = redact(payload) as Record<string, unknown>;
    expect(r.notes).toBe("reach me at [REDACTED:pii]");
    expect(r.blob).toBe("[REDACTED:token]");
    expect(r.cert).toBe("[REDACTED:secret]");
  });

  test("masks sensitive sections while keeping surrounding text", () => {
    const payload = {
      text: "Contact: user@example.com, phone 415-555-1212, ssn 123-45-6789, card 4242 4242 4242 4242.",
    };
    const r = redact(payload) as Record<string, unknown>;

    expect(r.text).toBe(
      "Contact: [REDACTED:pii], phone [REDACTED:pii], ssn [REDACTED:pii], card [REDACTED:pii].",
    );
  });

  test("detects additional sensitive token and key formats", () => {
    const payload = {
      logLine:
        "from 192.168.10.24 dob 1990-04-17 aws AKIAIOSFODNN7EXAMPLE gh ghp_abcdefghijklmnopqrstuvwxyz123456 stripe sk_test_1234567890abcdefghijkl openai sk-1234567890abcdefghijklmnop",
    };
    const r = redact(payload) as Record<string, unknown>;

    expect(r.logLine).toContain("[REDACTED:pii]");
    expect(r.logLine).toContain("[REDACTED:credential]");
    expect(r.logLine).toContain("[REDACTED:token]");
    expect(r.logLine).toContain("[REDACTED:secret]");
  });

  test("guessByValue can be disabled", () => {
    const payload = { notes: "user@example.com" };
    const r = redact(payload, { guessByValue: false }) as Record<
      string,
      unknown
    >;
    expect(r.notes).toBe("user@example.com");
  });

  test("supports custom string detectors alongside default detectors", () => {
    const payload = {
      text: "Customer Jane Doe uses jane@example.com",
    };

    const r = redact(payload, {
      stringDetectors: [
        (
          value,
        ): {
          start: number;
          end: number;
          kind: "pii";
          confidence: number;
          source: string;
        }[] => {
          const name = "Jane Doe";
          const idx = value.indexOf(name);
          return idx >= 0
            ? [
                {
                  start: idx,
                  end: idx + name.length,
                  kind: "pii",
                  confidence: 0.9,
                  source: "ml.ner",
                },
              ]
            : [];
        },
      ],
    }) as Record<string, unknown>;

    expect(r.text).toBe("Customer [REDACTED:pii] uses [REDACTED:pii]");
  });

  test("can disable default value detector and only use custom detectors", () => {
    const payload = {
      text: "email user@example.com and codename PROJECT-FALCON",
    };

    const r = redact(payload, {
      useDefaultValueDetector: false,
      stringDetectors: [
        (value): { start: number; end: number; kind: "secret" }[] => {
          const needle = "PROJECT-FALCON";
          const idx = value.indexOf(needle);
          return idx >= 0
            ? [{ start: idx, end: idx + needle.length, kind: "secret" }]
            : [];
        },
      ],
    }) as Record<string, unknown>;

    expect(r.text).toBe(
      "email user@example.com and codename [REDACTED:secret]",
    );
  });

  test("respects minDetectionConfidence for custom detectors", () => {
    const payload = {
      text: "entity: Alex Smith",
    };

    const r = redact(payload, {
      minDetectionConfidence: 0.8,
      stringDetectors: [
        (
          value,
        ): {
          start: number;
          end: number;
          kind: "pii";
          confidence: number;
        }[] => {
          const idx = value.indexOf("Alex Smith");
          return idx >= 0
            ? [
                {
                  start: idx,
                  end: idx + "Alex Smith".length,
                  kind: "pii",
                  confidence: 0.4,
                },
              ]
            : [];
        },
      ],
    }) as Record<string, unknown>;

    expect(r.text).toBe("entity: Alex Smith");
  });

  test("detectText returns ranges and kinds for text workflows", () => {
    const text = "Email user@example.com and call 415-555-1212";
    const hits = detectText(text);
    expect(hits.some((h) => h.kind === "pii")).toBe(true);
    expect(
      hits.some((h) => text.slice(h.start, h.end) === "user@example.com"),
    ).toBe(true);
  });

  test("redactText masks only sensitive fragments", () => {
    const text = "Notes: user@example.com is primary contact.";
    const out = redactText(text);
    expect(out).toBe("Notes: [REDACTED:pii] is primary contact.");
  });
});

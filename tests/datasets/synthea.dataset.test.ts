/**
 * @jest-environment node
 */
import {
  assertAllowed,
  audit,
  defaultPolicy,
  piiText,
  redact,
  safeJsonStringify,
} from "../../src";
import { collectStrings, sampleSyntheaJson } from "./helpers";

describe("Synthea FHIR dataset checks", () => {
  test("redacts suspicious credential fields while preserving nested structure", () => {
    const records = sampleSyntheaJson(4);
    expect(records.length).toBeGreaterThan(0);

    const payload = {
      source: "synthea",
      apiKey: "plain-api-key",
      records,
    };

    const redacted = redact(payload);
    const asJson = JSON.stringify(redacted);

    expect(Array.isArray((redacted as { records: unknown[] }).records)).toBe(
      true,
    );
    expect((redacted as { records: unknown[] }).records).toHaveLength(
      records.length,
    );
    expect(asJson).toContain("[REDACTED:unknown]");
    expect(asJson).not.toContain("plain-api-key");
  });

  test("safeJsonStringify handles large nested records", () => {
    const records = sampleSyntheaJson(3);
    expect(records.length).toBeGreaterThan(0);

    const payload = {
      bundleSet: records,
      bearer: "my-test-bearer",
    };

    const out = safeJsonStringify(payload);
    expect(out.startsWith("{")).toBe(true);
    expect(out).toContain("[REDACTED:unknown]");
    expect(out).not.toContain("my-test-bearer");
  });

  test("redaction maxDepth guard triggers on deeply nested records", () => {
    const records = sampleSyntheaJson(1);
    expect(records.length).toBeGreaterThan(0);

    const payload = {
      wrapper: {
        level1: {
          level2: {
            level3: records[0],
          },
        },
      },
    };

    const out = safeJsonStringify(payload, { maxDepth: 2 });
    expect(out).toContain("[REDACTED:unknown]");
  });

  test("policy and audit deny logging when classified record text is present", () => {
    const records = sampleSyntheaJson(2);
    expect(records.length).toBeGreaterThan(0);

    const extracted = collectStrings(records[0], 25);
    const sampleText = extracted.find((v) => v.length >= 5) ?? "synthea-record";

    const payload = {
      record: records[0],
      patientText: piiText(sampleText),
    };

    const policy = defaultPolicy();
    expect(() => assertAllowed(policy, "log", payload)).toThrow();

    const evt = audit(policy, "log", payload);
    expect(evt.policy).toBe("typesecure.default");
    expect(evt.decision.allowed).toBe(false);
    expect(evt.decision.detectedKinds).toContain("pii");
  });
});

/**
 * @jest-environment node
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { datasetRoot, parseEmail } from "./helpers";
import { piiText, redact } from "../../src";

jest.setTimeout(30 * 60 * 1000);

function isEnronMessageFile(filePath: string): boolean {
  return /\/\d+\.$/.test(filePath) || /\/\d+$/.test(filePath);
}

describe("Enron full scan redaction", () => {
  test("scans all Enron message files and verifies targeted redaction behavior", () => {
    const root = datasetRoot("enron-maildir");
    const stack = [root];

    let scanned = 0;
    let checked = 0;
    let tokenRedacted = 0;
    let senderRedacted = 0;
    let bodyMasked = 0;
    let bodyFullyRedacted = 0;
    let subjectChanged = 0;
    let skipped = 0;
    let tokenLeak = 0;
    let senderLeak = 0;

    while (stack.length > 0) {
      const current = stack.pop();
      if (!current) break;

      for (const name of readdirSync(current)) {
        const full = `${current}/${name}`;
        const st = statSync(full);
        if (st.isDirectory()) {
          stack.push(full);
          continue;
        }
        if (!st.isFile() || !isEnronMessageFile(full)) continue;

        scanned += 1;
        const raw = readFileSync(full, "utf8");
        const email = parseEmail(raw, full);

        const tokenCandidate =
          email.headers.from ?? email.headers.to ?? email.raw.slice(0, 40);
        const bodyCandidate = (email.body || email.raw).slice(0, 500);
        const subject = email.headers.subject ?? "";

        // Skip effectively empty messages where we cannot form useful assertions.
        if (
          tokenCandidate.trim().length === 0 ||
          bodyCandidate.trim().length === 0
        ) {
          skipped += 1;
          continue;
        }

        const before = {
          authToken: tokenCandidate,
          sender: piiText(tokenCandidate),
          subject,
          body: bodyCandidate,
        };
        const after = redact(before) as Record<string, unknown>;
        const afterAuthToken =
          typeof after.authToken === "string" ? after.authToken : "";
        const afterSender =
          typeof after.sender === "string" ? after.sender : "";
        const afterBody = typeof after.body === "string" ? after.body : "";
        const afterSubject =
          typeof after.subject === "string" ? after.subject : "";

        checked += 1;
        if (afterAuthToken === "[REDACTED:unknown]") tokenRedacted += 1;
        if (afterSender === "[REDACTED:pii]") senderRedacted += 1;
        if (afterBody !== bodyCandidate) bodyMasked += 1;
        if (
          afterBody === "[REDACTED:pii]" ||
          afterBody === "[REDACTED:unknown]"
        ) {
          bodyFullyRedacted += 1;
        }
        if (afterSubject !== subject) subjectChanged += 1;
        if (afterAuthToken.includes(tokenCandidate)) tokenLeak += 1;
        if (afterSender.includes(tokenCandidate)) senderLeak += 1;

        if (checked % 50000 === 0) {
          console.info(
            `[enron-fullscan] progress scanned=${scanned} checked=${checked} skipped=${skipped}`,
          );
        }
      }
    }

    console.info(
      `[enron-fullscan] summary scanned=${scanned} checked=${checked} skipped=${skipped} token_redacted=${tokenRedacted} sender_redacted=${senderRedacted} body_masked=${bodyMasked} body_fully_redacted=${bodyFullyRedacted} subject_changed=${subjectChanged} token_leak=${tokenLeak} sender_leak=${senderLeak}`,
    );

    expect(scanned).toBeGreaterThan(0);
    expect(checked).toBeGreaterThan(0);
    expect(tokenLeak).toBe(0);
    expect(senderLeak).toBe(0);
    expect(tokenRedacted).toBe(checked);
    expect(senderRedacted).toBe(checked);
    // Keep full-body replacement rare; selective masking should dominate.
    expect(bodyFullyRedacted / checked).toBeLessThan(0.005);
    expect(subjectChanged / checked).toBeLessThan(0.05);
    expect(bodyMasked).toBeGreaterThan(0);
  });
});

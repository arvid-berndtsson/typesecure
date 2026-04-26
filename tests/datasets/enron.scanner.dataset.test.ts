/**
 * @jest-environment node
 */
import { promises as fs } from "node:fs";
import path from "node:path";
import {
  classifyDeep,
  createBaseline,
  scanDirectory,
  scanFile,
  scanText,
} from "../../src";
import { runScanCli } from "../../src/cli";
import { createEnronSubsetFixture, sampleEnronEmails } from "./helpers";

jest.setTimeout(10 * 60 * 1000);

describe("Enron scanner subset dataset checks", () => {
  test("subset fixture can run classifyDeep + scanText on real Enron sample", () => {
    const sample = sampleEnronEmails(5);
    expect(sample.length).toBeGreaterThan(0);

    const findings = classifyDeep({
      from: sample[0].headers.from ?? "",
      to: sample[0].headers.to ?? "",
      subject: sample[0].headers.subject ?? "",
      body: sample[0].body.slice(0, 600),
    });

    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((f) => f.path.startsWith("$."))).toBe(true);

    const textOut = scanText(sample[0].raw.slice(0, 1200), {
      packs: ["compliance"],
    });
    expect(textOut.findings.length).toBeGreaterThan(0);
  });

  test("scanDirectory supports Enron subset + baseline diff + new-only", async () => {
    const subset = createEnronSubsetFixture(30);

    const first = await scanDirectory([subset.rootDir], {
      maxFindings: 500,
    });
    expect(first.scannedFiles).toBeGreaterThan(0);
    expect(first.findings.length).toBeGreaterThan(0);

    const baseline = createBaseline(first.findings);

    const markerFile = subset.files[0];
    const original = await fs.readFile(markerFile, "utf8");
    await fs.writeFile(
      markerFile,
      `${original}\nInjected token ghp_abcdefghijklmnopqrstuvwxyz123456\n`,
      "utf8",
    );

    const diff = await scanDirectory([subset.rootDir], {
      baseline,
      newOnly: true,
      maxFindings: 500,
    });

    expect(diff.findings.length).toBeGreaterThan(0);
    expect(diff.findings.every((f) => f.isNew)).toBe(true);
    expect(diff.blockingFindings.length).toBeGreaterThan(0);
  });

  test("scanFile sanitized-copy works for Enron file", async () => {
    const subset = createEnronSubsetFixture(5);
    const target = subset.files[0];
    const outputDir = path.join(subset.rootDir, "sanitized");

    const out = await scanFile(target, {
      fixMode: "sanitized-copy",
      outputDir,
    });

    expect(out.findings.length).toBeGreaterThan(0);
    expect(out.fixed).toBe(true);

    const sanitized = await fs.readFile(
      path.join(outputDir, path.basename(target)),
      "utf8",
    );
    expect(sanitized).toContain("[REDACTED:");
  });

  test("CLI --ci returns non-zero for blocking findings in Enron subset", async () => {
    const subset = createEnronSubsetFixture(20);

    const code = await runScanCli([
      "scan",
      subset.rootDir,
      "--ci",
      "--max-findings",
      "300",
      "--json",
    ]);

    expect(code).toBe(1);
  });

  test("detector packs can be compared on Enron subset", async () => {
    const subset = createEnronSubsetFixture(20);

    const compliance = await scanDirectory([subset.rootDir], {
      packs: ["compliance"],
      maxFindings: 300,
    });
    const cloudKeys = await scanDirectory([subset.rootDir], {
      packs: ["cloud-keys"],
      maxFindings: 300,
    });

    expect(compliance.findings.length).toBeGreaterThan(0);
    // On historical email corpora, cloud keys may or may not appear; enforce only non-negative sanity.
    expect(cloudKeys.findings.length).toBeGreaterThanOrEqual(0);
  });
});

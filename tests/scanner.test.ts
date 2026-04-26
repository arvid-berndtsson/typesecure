/**
 * @jest-environment node
 */
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  classifyDeep,
  scanDirectory,
  scanFile,
  scanText,
  createBaseline,
  applyBaselineDiff,
} from "../src";
import { runScanCli } from "../src/cli";

describe("Scanner", () => {
  test("classifyDeep finds nested pii with structured path", () => {
    const findings = classifyDeep({
      user: {
        email: "user@example.com",
      },
    });

    expect(findings.some((f) => f.kind === "pii")).toBe(true);
    expect(findings.some((f) => f.path === "$.user.email")).toBe(true);
  });

  test("scanText supports detector packs", () => {
    const text =
      "reach me user@example.com aws AKIAIOSFODNN7EXAMPLE token ghp_abcdefghijklmnopqrstuvwxyz123456";

    const compliance = scanText(text, { packs: ["compliance"] });
    const cloud = scanText(text, { packs: ["cloud-keys"] });

    expect(compliance.findings.some((f) => f.kind === "pii")).toBe(true);
    expect(
      compliance.findings.some(
        (f) => f.kind === "secret" || f.kind === "token",
      ),
    ).toBe(false);

    expect(cloud.findings.some((f) => f.kind === "credential")).toBe(true);
    expect(cloud.findings.some((f) => f.kind === "token")).toBe(true);
  });

  test("baseline diff returns only new findings", () => {
    const first = scanText("email user@example.com").findings;
    const baseline = createBaseline(first);
    const second = scanText(
      "email user@example.com token sk-1234567890abcdefghijklmnop",
    ).findings;

    const newOnly = applyBaselineDiff(second, baseline, true);
    expect(newOnly.length).toBeGreaterThan(0);
    expect(newOnly.every((f) => f.isNew)).toBe(true);
  });

  test("scanFile fix mode in-place redacts content", async () => {
    const tmp = await fs.mkdtemp(
      path.join(os.tmpdir(), "typesecure-scan-file-"),
    );
    const file = path.join(tmp, "app.log");
    await fs.writeFile(
      file,
      "token ghp_abcdefghijklmnopqrstuvwxyz123456",
      "utf8",
    );

    const out = await scanFile(file, { fixMode: "in-place" });
    const updated = await fs.readFile(file, "utf8");

    expect(out.fixed).toBe(true);
    expect(out.findings.length).toBeGreaterThan(0);
    expect(updated).toContain("[REDACTED:token]");
  });

  test("scanDirectory supports baseline/new-only and ci-style blocking checks", async () => {
    const tmp = await fs.mkdtemp(
      path.join(os.tmpdir(), "typesecure-scan-dir-"),
    );
    const file = path.join(tmp, "audit.log");
    await fs.writeFile(file, "email user@example.com", "utf8");

    const initial = await scanDirectory([tmp]);
    const baseline = createBaseline(initial.findings);

    await fs.writeFile(
      file,
      "email user@example.com key sk-1234567890abcdefghijklmnop",
      "utf8",
    );

    const diff = await scanDirectory([tmp], { baseline, newOnly: true });
    expect(diff.findings.length).toBeGreaterThan(0);
    expect(diff.findings.every((f) => f.isNew)).toBe(true);
    expect(diff.blockingFindings.length).toBeGreaterThan(0);
  });

  test("CLI returns non-zero in ci mode when blocking findings exist", async () => {
    const tmp = await fs.mkdtemp(path.join(os.tmpdir(), "typesecure-cli-"));
    const file = path.join(tmp, "attack.log");
    await fs.writeFile(file, "ghp_abcdefghijklmnopqrstuvwxyz123456", "utf8");

    const code = await runScanCli(["scan", tmp, "--ci", "--json"]);
    expect(code).toBe(1);
  });
});

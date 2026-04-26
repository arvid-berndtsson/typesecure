import { promises as fs } from "node:fs";
import path from "node:path";
import os from "node:os";
import { runScanCli } from "../src/cli";

async function main(): Promise<void> {
  const tmpRoot = await fs.mkdtemp(path.join(os.tmpdir(), "typesecure-scan-"));
  const inputDir = path.join(tmpRoot, "input");
  const outDir = path.join(tmpRoot, "sanitized");
  const baselinePath = path.join(tmpRoot, "baseline.json");

  await fs.mkdir(inputDir, { recursive: true });
  await fs.writeFile(
    path.join(inputDir, "app.log"),
    "user=user@example.com token=ghp_abcdefghijklmnopqrstuvwxyz123456\n",
    "utf8",
  );

  const code1 = await runScanCli([
    "scan",
    inputDir,
    "--json",
    "--write-baseline",
    baselinePath,
  ]);

  const code2 = await runScanCli([
    "scan",
    inputDir,
    "--baseline",
    baselinePath,
    "--new-only",
    "--fix-out-dir",
    outDir,
  ]);

  const sanitized = await fs.readFile(path.join(outDir, "app.log"), "utf8");

  console.log(
    JSON.stringify(
      {
        code1,
        code2,
        baselineExists: true,
        sanitizedContainsRedaction: sanitized.includes("[REDACTED:"),
        tmpRoot,
      },
      null,
      2,
    ),
  );
}

void main();

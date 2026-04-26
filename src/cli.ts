#!/usr/bin/env node
import { promises as fs } from "node:fs";
import path from "node:path";
import {
  createBaseline,
  parseBaseline,
  scanDirectory,
  serializeBaseline,
  type DataClassification,
  type DetectorPack,
  type FixMode,
} from "./index";

type CliOptions = Readonly<{
  command: "scan";
  paths: string[];
  json: boolean;
  ci: boolean;
  fixMode: FixMode;
  outputDir?: string;
  baselinePath?: string;
  writeBaselinePath?: string;
  newOnly: boolean;
  minConfidence?: number;
  packs: DetectorPack[];
  failOnKinds: DataClassification[];
  maxFindings?: number;
}>;

function printHelp(): void {
  console.info(`typesecure scan [paths...] [options]

Options:
  --json                     Output JSON report
  --ci                       Exit 1 when blocking findings are present
  --fix                      Redact findings in-place
  --fix-out-dir <dir>        Write sanitized copies to output dir
  --baseline <file>          Load baseline JSON for diff scanning
  --write-baseline <file>    Write baseline JSON from current findings
  --new-only                 Show only findings not in baseline
  --pack <name>              Detector pack: all|core|compliance|cloud-keys (repeatable)
  --min-confidence <n>       Minimum confidence (0..1)
  --fail-on <kinds>          Comma-separated kinds (default: secret,token,credential)
  --max-findings <n>         Stop after finding cap
  --help                     Show this help
`);
}

function parseKinds(value: string): DataClassification[] {
  const allowed = new Set<DataClassification>([
    "public",
    "pii",
    "secret",
    "token",
    "credential",
  ]);
  const out: DataClassification[] = [];
  for (const raw of value.split(",")) {
    const k = raw.trim() as DataClassification;
    if (allowed.has(k)) out.push(k);
  }
  return out;
}

function parsePack(value: string): DetectorPack | undefined {
  if (
    value === "all" ||
    value === "core" ||
    value === "compliance" ||
    value === "cloud-keys"
  ) {
    return value;
  }
  return undefined;
}

function parseArgs(argv: string[]): CliOptions | "help" {
  const args = [...argv];
  const commandRaw = args[0] ?? "scan";
  if (commandRaw === "--help" || commandRaw === "-h") return "help";
  const command = commandRaw === "scan" ? "scan" : "scan";

  const paths: string[] = [];
  let json = false;
  let ci = false;
  let fixMode: FixMode = "none";
  let outputDir: string | undefined;
  let baselinePath: string | undefined;
  let writeBaselinePath: string | undefined;
  let newOnly = false;
  let minConfidence: number | undefined;
  const packs: DetectorPack[] = [];
  let failOnKinds: DataClassification[] = ["secret", "token", "credential"];
  let maxFindings: number | undefined;

  for (let i = 1; i < args.length; i += 1) {
    const arg = args[i];
    switch (arg) {
      case "--help":
      case "-h":
        return "help";
      case "--json":
        json = true;
        break;
      case "--ci":
        ci = true;
        break;
      case "--fix":
        fixMode = "in-place";
        break;
      case "--fix-out-dir": {
        outputDir = args[i + 1];
        i += 1;
        fixMode = "sanitized-copy";
        break;
      }
      case "--baseline": {
        baselinePath = args[i + 1];
        i += 1;
        break;
      }
      case "--write-baseline": {
        writeBaselinePath = args[i + 1];
        i += 1;
        break;
      }
      case "--new-only":
        newOnly = true;
        break;
      case "--pack": {
        const pack = parsePack(args[i + 1] ?? "");
        i += 1;
        if (pack) packs.push(pack);
        break;
      }
      case "--min-confidence": {
        const parsed = Number(args[i + 1]);
        i += 1;
        if (Number.isFinite(parsed)) {
          minConfidence = Math.max(0, Math.min(1, parsed));
        }
        break;
      }
      case "--fail-on": {
        const parsedKinds = parseKinds(args[i + 1] ?? "");
        i += 1;
        if (parsedKinds.length > 0) failOnKinds = parsedKinds;
        break;
      }
      case "--max-findings": {
        const parsed = Number(args[i + 1]);
        i += 1;
        if (Number.isFinite(parsed) && parsed > 0) {
          maxFindings = Math.trunc(parsed);
        }
        break;
      }
      default:
        if (arg.startsWith("--")) {
          // ignore unknown flags for forward compatibility
        } else {
          paths.push(arg);
        }
        break;
    }
  }

  return {
    command,
    paths: paths.length > 0 ? paths : ["."],
    json,
    ci,
    fixMode,
    outputDir,
    baselinePath,
    writeBaselinePath,
    newOnly,
    minConfidence,
    packs: packs.length > 0 ? packs : ["all"],
    failOnKinds,
    maxFindings,
  };
}

function formatHuman(
  report: Awaited<ReturnType<typeof scanDirectory>>,
): string {
  const lines: string[] = [];
  lines.push(`Scanned files: ${report.scannedFiles}`);
  lines.push(`Findings: ${report.summary.totalFindings}`);
  lines.push(`Blocking findings: ${report.blockingFindings.length}`);
  lines.push(
    `Kinds: pii=${report.summary.byKind.pii}, secret=${report.summary.byKind.secret}, token=${report.summary.byKind.token}, credential=${report.summary.byKind.credential}, unknown=${report.summary.byKind.unknown}`,
  );
  if (report.newFindings.length > 0) {
    lines.push(`New findings: ${report.newFindings.length}`);
  }
  if (report.fixedFiles.length > 0) {
    lines.push(`Fixed files: ${report.fixedFiles.length}`);
  }
  return lines.join("\n");
}

export async function runScanCli(argv: string[]): Promise<number> {
  const parsed = parseArgs(argv);
  if (parsed === "help") {
    printHelp();
    return 0;
  }

  let baseline;
  if (parsed.baselinePath) {
    const baselineContent = await fs.readFile(parsed.baselinePath, "utf8");
    baseline = parseBaseline(baselineContent);
  }

  const report = await scanDirectory(parsed.paths, {
    baseline,
    newOnly: parsed.newOnly,
    minConfidence: parsed.minConfidence,
    packs: parsed.packs,
    failOnKinds: parsed.failOnKinds,
    fixMode: parsed.fixMode,
    outputDir: parsed.outputDir,
    maxFindings: parsed.maxFindings,
  });

  if (parsed.writeBaselinePath) {
    const baselineOut = serializeBaseline(createBaseline(report.findings));
    await fs.mkdir(path.dirname(parsed.writeBaselinePath), { recursive: true });
    await fs.writeFile(
      parsed.writeBaselinePath,
      `${JSON.stringify(baselineOut, null, 2)}\n`,
      "utf8",
    );
  }

  if (parsed.json) {
    console.info(
      JSON.stringify(
        {
          ...report,
          scannedPaths: report.scannedPaths,
        },
        null,
        2,
      ),
    );
  } else {
    console.info(formatHuman(report));
  }

  if (parsed.ci && report.blockingFindings.length > 0) {
    return 1;
  }

  return 0;
}

const argv = globalThis.process?.argv ?? [];
if (argv.length > 1 && argv[1]?.includes("cli")) {
  void runScanCli(argv.slice(2)).then((code) => {
    if (globalThis.process) globalThis.process.exitCode = code;
  });
}

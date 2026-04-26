import { promises as fs } from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import {
  classificationOf,
  isClassified,
  type DataClassification,
} from "./classification";
import {
  applyDetectionsToString,
  collectStringDetections,
  type StringDetectionOptions,
} from "./detectors/engine";
import type { StringDetection } from "./detectors/types";

const DEFAULT_SUSPICIOUS_KEY =
  /pass(word)?|pwd|secret|token|api[_-]?key|auth|bearer|cookie|session|private[_-]?key|ssh|credential/i;

export type DetectorPack = "all" | "core" | "compliance" | "cloud-keys";
export type ConfidenceBand = "low" | "medium" | "high";
export type FindingAction = "info" | "review" | "block";
export type FixMode = "none" | "in-place" | "sanitized-copy";

export type ClassificationFinding = Readonly<{
  fingerprint: string;
  kind: DataClassification | "unknown";
  confidence: number;
  confidenceBand: ConfidenceBand;
  recommendedAction: FindingAction;
  source: string;
  path: string;
  filePath?: string;
  start?: number;
  end?: number;
  excerpt?: string;
  isNew?: boolean;
}>;

export type ScanSummary = Readonly<{
  totalFindings: number;
  byKind: Record<DataClassification | "unknown", number>;
  byConfidenceBand: Record<ConfidenceBand, number>;
  byAction: Record<FindingAction, number>;
}>;

export type ScanReport = Readonly<{
  scannedPaths: string[];
  scannedFiles: number;
  findings: ClassificationFinding[];
  newFindings: ClassificationFinding[];
  blockingFindings: ClassificationFinding[];
  fixedFiles: string[];
  summary: ScanSummary;
}>;

export type ClassifyDeepOptions = Readonly<
  StringDetectionOptions & {
    maxDepth?: number;
    minConfidence?: number;
    packs?: readonly DetectorPack[];
    pathPrefix?: string;
    blockedKinds?: readonly DataClassification[];
    blockConfidenceMin?: number;
    includeSuspiciousKeyHeuristics?: boolean;
    includeClassifiedTags?: boolean;
  }
>;

export type ScanTextOptions = Readonly<
  StringDetectionOptions & {
    minConfidence?: number;
    packs?: readonly DetectorPack[];
    blockedKinds?: readonly DataClassification[];
    blockConfidenceMin?: number;
    filePath?: string;
    path?: string;
  }
>;

export type ScanFileOptions = Readonly<
  ScanTextOptions & {
    encoding?: "utf8";
    fixMode?: FixMode;
    outputDir?: string;
    placeholder?: (kind: DataClassification | "unknown") => string;
  }
>;

export type ScanDirectoryOptions = Readonly<
  ScanFileOptions & {
    includeExtensions?: readonly string[];
    excludeDirs?: readonly string[];
    baseline?: Baseline;
    newOnly?: boolean;
    failOnKinds?: readonly DataClassification[];
    maxFindings?: number;
  }
>;

export type Baseline = Readonly<{
  fingerprints: ReadonlySet<string>;
}>;

export type BaselineSerializable = Readonly<{
  fingerprints: string[];
}>;

const DEFAULT_BLOCKED_KINDS: readonly DataClassification[] = [
  "secret",
  "token",
  "credential",
];

const CLOUD_KEY_SOURCES = new Set([
  "rule.private-key",
  "rule.jwt",
  "rule.aws-access-key",
  "rule.github-token",
  "rule.stripe-secret",
  "rule.openai-key",
  "rule.credential-pair",
  "rule.high-entropy",
]);

function confidenceBandFor(confidence: number): ConfidenceBand {
  if (confidence >= 0.85) return "high";
  if (confidence >= 0.5) return "medium";
  return "low";
}

function normalizeConfidence(value: number | undefined): number {
  if (!Number.isFinite(value)) return 1;
  const n = value ?? 1;
  if (n < 0) return 0;
  if (n > 1) return 1;
  return n;
}

function shouldKeepByPack(
  detection: StringDetection,
  packs: readonly DetectorPack[],
): boolean {
  if (packs.includes("all") || packs.includes("core")) return true;
  if (
    packs.includes("compliance") &&
    (detection.kind === "pii" || detection.kind === "credential")
  ) {
    return true;
  }
  if (packs.includes("cloud-keys")) {
    if (
      detection.kind === "secret" ||
      detection.kind === "token" ||
      detection.kind === "credential"
    ) {
      if (detection.source && CLOUD_KEY_SOURCES.has(detection.source)) {
        return true;
      }
    }
  }

  return false;
}

function defaultPlaceholder(kind: DataClassification | "unknown"): string {
  return `[REDACTED:${kind}]`;
}

function excerptAround(value: string, start: number, end: number): string {
  const from = Math.max(0, start - 20);
  const to = Math.min(value.length, end + 20);
  return value.slice(from, to);
}

function createFingerprint(input: {
  kind: DataClassification | "unknown";
  source: string;
  path: string;
  filePath?: string;
  start?: number;
  end?: number;
  excerpt?: string;
}): string {
  const h = createHash("sha256");
  h.update(input.kind);
  h.update("|");
  h.update(input.source);
  h.update("|");
  h.update(input.path);
  h.update("|");
  h.update(input.filePath ?? "");
  h.update("|");
  h.update(String(input.start ?? -1));
  h.update("|");
  h.update(String(input.end ?? -1));
  h.update("|");
  h.update(input.excerpt ?? "");
  return h.digest("hex");
}

function recommendedAction(
  kind: DataClassification | "unknown",
  confidence: number,
  blockedKinds: readonly DataClassification[],
  blockConfidenceMin: number,
): FindingAction {
  const band = confidenceBandFor(confidence);
  if (
    band === "high" &&
    blockedKinds.includes(kind as DataClassification) &&
    confidence >= blockConfidenceMin
  ) {
    return "block";
  }
  if (band === "medium") return "review";
  if (band === "high") return "review";
  return "info";
}

function toFinding(
  input: Readonly<{
    kind: DataClassification | "unknown";
    confidence?: number;
    source?: string;
    path: string;
    filePath?: string;
    start?: number;
    end?: number;
    excerpt?: string;
    blockedKinds: readonly DataClassification[];
    blockConfidenceMin: number;
  }>,
): ClassificationFinding {
  const confidence = normalizeConfidence(input.confidence);
  const band = confidenceBandFor(confidence);
  const source = input.source ?? "unknown";
  const findingBase = {
    kind: input.kind,
    source,
    path: input.path,
    filePath: input.filePath,
    start: input.start,
    end: input.end,
    excerpt: input.excerpt,
  };

  return {
    fingerprint: createFingerprint(findingBase),
    ...findingBase,
    confidence,
    confidenceBand: band,
    recommendedAction: recommendedAction(
      input.kind,
      confidence,
      input.blockedKinds,
      input.blockConfidenceMin,
    ),
  };
}

export function classifyDeep(
  value: unknown,
  options?: ClassifyDeepOptions,
): ClassificationFinding[] {
  const maxDepth = options?.maxDepth ?? 25;
  const minConfidence = options?.minConfidence ?? 0;
  const packs = options?.packs ?? ["all"];
  const pathPrefix = options?.pathPrefix ?? "$";
  const blockedKinds = options?.blockedKinds ?? DEFAULT_BLOCKED_KINDS;
  const blockConfidenceMin = options?.blockConfidenceMin ?? 0.85;
  const includeSuspiciousKeyHeuristics =
    options?.includeSuspiciousKeyHeuristics ?? true;
  const includeClassifiedTags = options?.includeClassifiedTags ?? true;

  const findings: ClassificationFinding[] = [];
  const seen = new WeakSet<object>();

  const visit = (
    v: unknown,
    depth: number,
    valuePath: string,
    keyHint?: string,
  ): void => {
    if (depth > maxDepth) return;

    const taggedKind = classificationOf(v);
    if (taggedKind && includeClassifiedTags) {
      findings.push(
        toFinding({
          kind: taggedKind,
          confidence: 1,
          source: "classification.tag",
          path: valuePath,
          blockedKinds,
          blockConfidenceMin,
        }),
      );
    }

    if (
      includeSuspiciousKeyHeuristics &&
      keyHint &&
      DEFAULT_SUSPICIOUS_KEY.test(keyHint)
    ) {
      const primitive =
        v === null ||
        typeof v === "string" ||
        typeof v === "number" ||
        typeof v === "boolean" ||
        typeof v === "bigint";
      if (primitive) {
        findings.push(
          toFinding({
            kind: "unknown",
            confidence: 0.6,
            source: "heuristic.suspicious-key",
            path: valuePath,
            blockedKinds,
            blockConfidenceMin,
          }),
        );
      }
    }

    if (typeof v === "string") {
      const detections = collectStringDetections(
        v,
        { keyHint, depth },
        options,
      ).filter((d) => (d.confidence ?? 1) >= minConfidence);

      for (const d of detections) {
        if (!shouldKeepByPack(d, packs)) continue;
        findings.push(
          toFinding({
            kind: d.kind,
            confidence: d.confidence,
            source: d.source,
            path: valuePath,
            start: d.start,
            end: d.end,
            excerpt: excerptAround(v, d.start, d.end),
            blockedKinds,
            blockConfidenceMin,
          }),
        );
      }
    }

    if (Array.isArray(v)) {
      for (let i = 0; i < v.length; i += 1) {
        visit(v[i], depth + 1, `${valuePath}[${i}]`);
      }
      return;
    }

    if (typeof v === "object" && v !== null) {
      if (seen.has(v)) return;
      seen.add(v);
      if (isClassified(v)) return;
      for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
        const nextPath = `${valuePath}.${k}`;
        visit(val, depth + 1, nextPath, k);
      }
    }
  };

  visit(value, 0, pathPrefix);
  return findings;
}

export function scanText(
  value: string,
  options?: ScanTextOptions,
): Readonly<{
  findings: ClassificationFinding[];
  redactedText: string;
}> {
  const blockedKinds = options?.blockedKinds ?? DEFAULT_BLOCKED_KINDS;
  const blockConfidenceMin = options?.blockConfidenceMin ?? 0.85;
  const packs = options?.packs ?? ["all"];
  const pathValue = options?.path ?? "$";

  const detections = collectStringDetections(
    value,
    { depth: 0 },
    options,
  ).filter(
    (d) =>
      (d.confidence ?? 1) >= (options?.minConfidence ?? 0) &&
      shouldKeepByPack(d, packs),
  );

  const findings = detections.map((d) =>
    toFinding({
      kind: d.kind,
      confidence: d.confidence,
      source: d.source,
      path: pathValue,
      filePath: options?.filePath,
      start: d.start,
      end: d.end,
      excerpt: excerptAround(value, d.start, d.end),
      blockedKinds,
      blockConfidenceMin,
    }),
  );

  const redactedText = applyDetectionsToString(
    value,
    detections,
    defaultPlaceholder,
  );
  return { findings, redactedText };
}

export async function scanFile(
  filePath: string,
  options?: ScanFileOptions,
): Promise<
  Readonly<{
    findings: ClassificationFinding[];
    fixed: boolean;
    redactedText?: string;
  }>
> {
  const encoding: "utf8" = options?.encoding ?? "utf8";
  const content = await fs.readFile(filePath, { encoding });

  if (content.includes("\u0000")) {
    return { findings: [], fixed: false };
  }

  const textResult = scanText(content, {
    ...options,
    filePath,
    path: filePath,
  });

  let fixed = false;
  const mode = options?.fixMode ?? "none";

  if (mode !== "none" && textResult.findings.length > 0) {
    const redacted = textResult.redactedText;
    if (mode === "in-place") {
      await fs.writeFile(filePath, redacted, { encoding });
      fixed = true;
    } else if (mode === "sanitized-copy") {
      const outputDir = options?.outputDir ?? "typesecure-sanitized";
      const baseName = path.basename(filePath);
      await fs.mkdir(outputDir, { recursive: true });
      await fs.writeFile(path.join(outputDir, baseName), redacted, {
        encoding,
      });
      fixed = true;
    }
  }

  return {
    findings: textResult.findings,
    fixed,
    redactedText: textResult.redactedText,
  };
}

async function collectFiles(
  root: string,
  options: Readonly<{
    includeExtensions: readonly string[];
    excludeDirs: readonly string[];
  }>,
): Promise<string[]> {
  const stat = await fs.stat(root);
  if (stat.isFile()) return [root];

  const out: string[] = [];
  const walk = async (dir: string): Promise<void> => {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (options.excludeDirs.includes(entry.name)) continue;
        await walk(fullPath);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (
          options.includeExtensions.length > 0 &&
          !options.includeExtensions.includes(ext)
        ) {
          continue;
        }
        out.push(fullPath);
      }
    }
  };

  await walk(root);
  return out;
}

function emptySummary(): {
  totalFindings: number;
  byKind: Record<DataClassification | "unknown", number>;
  byConfidenceBand: Record<ConfidenceBand, number>;
  byAction: Record<FindingAction, number>;
} {
  return {
    totalFindings: 0,
    byKind: {
      public: 0,
      pii: 0,
      secret: 0,
      token: 0,
      credential: 0,
      unknown: 0,
    },
    byConfidenceBand: {
      low: 0,
      medium: 0,
      high: 0,
    },
    byAction: {
      info: 0,
      review: 0,
      block: 0,
    },
  };
}

function summarize(findings: readonly ClassificationFinding[]): ScanSummary {
  const summary = emptySummary();
  summary.totalFindings = findings.length;

  for (const finding of findings) {
    summary.byKind[finding.kind] += 1;
    summary.byConfidenceBand[finding.confidenceBand] += 1;
    summary.byAction[finding.recommendedAction] += 1;
  }

  return summary;
}

export function createBaseline(
  findings: readonly ClassificationFinding[],
): Baseline {
  return {
    fingerprints: new Set(findings.map((f) => f.fingerprint)),
  };
}

export function serializeBaseline(baseline: Baseline): BaselineSerializable {
  return {
    fingerprints: [...baseline.fingerprints],
  };
}

export function parseBaseline(input: string): Baseline {
  const parsed = JSON.parse(input) as unknown;
  if (!parsed || typeof parsed !== "object") {
    return { fingerprints: new Set() };
  }

  const obj = parsed as { fingerprints?: unknown };
  if (!Array.isArray(obj.fingerprints)) {
    return { fingerprints: new Set() };
  }

  const fingerprints = obj.fingerprints.filter(
    (x): x is string => typeof x === "string" && x.length > 0,
  );

  return {
    fingerprints: new Set(fingerprints),
  };
}

export function applyBaselineDiff(
  findings: readonly ClassificationFinding[],
  baseline: Baseline,
  newOnly: boolean,
): ClassificationFinding[] {
  const withFlags = findings.map((finding) => ({
    ...finding,
    isNew: !baseline.fingerprints.has(finding.fingerprint),
  }));

  if (!newOnly) return withFlags;
  return withFlags.filter((f) => f.isNew);
}

export async function scanDirectory(
  inputPaths: readonly string[],
  options?: ScanDirectoryOptions,
): Promise<ScanReport> {
  const includeExtensions = options?.includeExtensions ?? [
    ".log",
    ".txt",
    ".json",
    ".md",
    ".csv",
    ".env",
    ".yaml",
    ".yml",
    ".xml",
  ];
  const excludeDirs = options?.excludeDirs ?? [
    ".git",
    "node_modules",
    "dist",
    "coverage",
  ];

  const files = new Set<string>();
  for (const inputPath of inputPaths) {
    const resolved = path.resolve(inputPath);
    const items = await collectFiles(resolved, {
      includeExtensions,
      excludeDirs,
    });
    for (const file of items) files.add(file);
  }

  const sortedFiles = [...files].sort((a, b) => a.localeCompare(b));

  const allFindings: ClassificationFinding[] = [];
  const fixedFiles: string[] = [];

  for (const file of sortedFiles) {
    const { findings, fixed } = await scanFile(file, options);
    allFindings.push(...findings);
    if (fixed) fixedFiles.push(file);
    if (
      typeof options?.maxFindings === "number" &&
      options.maxFindings > 0 &&
      allFindings.length >= options.maxFindings
    ) {
      break;
    }
  }

  const baseline = options?.baseline;
  const findingsWithBaseline = baseline
    ? applyBaselineDiff(allFindings, baseline, options?.newOnly ?? false)
    : allFindings;

  const blockedKinds = options?.failOnKinds ?? DEFAULT_BLOCKED_KINDS;
  const blockingFindings = findingsWithBaseline.filter(
    (f) =>
      blockedKinds.includes(f.kind as DataClassification) &&
      (f.recommendedAction === "block" || f.confidenceBand === "high"),
  );

  const newFindings = findingsWithBaseline.filter((f) => f.isNew === true);

  return {
    scannedPaths: inputPaths.map((p) => path.resolve(p)),
    scannedFiles: sortedFiles.length,
    findings: findingsWithBaseline,
    newFindings,
    blockingFindings,
    fixedFiles,
    summary: summarize(findingsWithBaseline),
  };
}

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import process from "node:process";

export type ParsedEmail = Readonly<{
  file: string;
  headers: Record<string, string>;
  body: string;
  raw: string;
}>;

export function datasetRoot(...parts: string[]): string {
  return path.join(process.cwd(), "data", ...parts);
}

export function listFilesRecursive(root: string, limit: number): string[] {
  if (!existsSync(root)) return [];

  const out: string[] = [];
  const stack = [root];

  while (stack.length > 0 && out.length < limit) {
    const current = stack.pop();
    if (!current) break;

    for (const name of readdirSync(current)) {
      const full = path.join(current, name);
      const st = statSync(full);
      if (st.isDirectory()) {
        stack.push(full);
      } else if (st.isFile()) {
        out.push(full);
        if (out.length >= limit) break;
      }
    }
  }

  return out;
}

export function parseEmail(raw: string, file: string): ParsedEmail {
  const normalized = raw.replace(/\r\n/g, "\n");
  const splitAt = normalized.indexOf("\n\n");
  const headerBlock = splitAt >= 0 ? normalized.slice(0, splitAt) : normalized;
  const body = splitAt >= 0 ? normalized.slice(splitAt + 2) : "";

  const headers: Record<string, string> = {};
  const lines = headerBlock.split("\n");
  let lastKey: string | undefined;

  for (const line of lines) {
    if (/^\s/.test(line) && lastKey) {
      headers[lastKey] = `${headers[lastKey]} ${line.trim()}`.trim();
      continue;
    }

    const idx = line.indexOf(":");
    if (idx < 0) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();
    if (!key) continue;
    headers[key] = value;
    lastKey = key;
  }

  return { file, headers, body, raw };
}

export function sampleEnronEmails(limit: number): ParsedEmail[] {
  const root = datasetRoot("enron-maildir");
  const files = listFilesRecursive(root, limit * 4).filter(
    (file) => /\/\d+\.$/.test(file) || /\/\d+$/.test(file),
  );

  return files.slice(0, limit).map((file) => {
    const raw = readFileSync(file, "utf8");
    return parseEmail(raw, file);
  });
}

export function sampleSyntheaJson(limit: number): unknown[] {
  const root = datasetRoot("synthea_sample_data_fhir_latest");
  const files = listFilesRecursive(root, limit * 10)
    .filter((file) => file.endsWith(".json"))
    .slice(0, limit);

  return files.map((file) => {
    const parsed: unknown = JSON.parse(readFileSync(file, "utf8"));
    return parsed;
  });
}

export function collectStrings(value: unknown, limit: number): string[] {
  const out: string[] = [];
  const stack: unknown[] = [value];
  const seen = new WeakSet<object>();

  while (stack.length > 0 && out.length < limit) {
    const current = stack.pop();
    if (typeof current === "string") {
      const trimmed = current.trim();
      if (trimmed.length > 0) out.push(trimmed);
      continue;
    }
    if (Array.isArray(current)) {
      for (const item of current) stack.push(item);
      continue;
    }
    if (typeof current === "object" && current !== null) {
      if (seen.has(current)) continue;
      seen.add(current);
      for (const val of Object.values(current as Record<string, unknown>)) {
        stack.push(val);
      }
    }
  }

  return out;
}

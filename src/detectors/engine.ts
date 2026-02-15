import type { DataClassification } from "../classification";
import { defaultRuleStringDetector } from "./rules";
import type { StringDetection, StringDetector } from "./types";

export type StringDetectionOptions = Readonly<{
  useDefaultValueDetector?: boolean;
  stringDetectors?: readonly StringDetector[];
  minDetectionConfidence?: number;
}>;

export function collectStringDetections(
  value: string,
  context: Readonly<{
    keyHint?: string;
    depth: number;
  }>,
  options?: StringDetectionOptions,
): StringDetection[] {
  const useDefaultValueDetector = options?.useDefaultValueDetector ?? true;
  const customDetectors = options?.stringDetectors ?? [];
  const minDetectionConfidence = options?.minDetectionConfidence ?? 0;
  const detections: StringDetection[] = [];

  if (useDefaultValueDetector) {
    detections.push(...defaultRuleStringDetector(value, context));
  }
  for (const detector of customDetectors) {
    detections.push(...detector(value, context));
  }

  return detections.filter(
    (d) =>
      (d.confidence ?? 1) >= minDetectionConfidence &&
      Number.isFinite(d.start) &&
      Number.isFinite(d.end),
  );
}

export function applyDetectionsToString(
  value: string,
  detections: readonly StringDetection[],
  placeholder: (kind: DataClassification | "unknown") => string,
): string {
  if (detections.length === 0) return value;

  const owner = new Array<number>(value.length).fill(-1);
  const normalized: Array<{
    start: number;
    end: number;
    kind: DataClassification | "unknown";
  }> = [];

  for (const d of detections) {
    const start = Math.max(0, Math.min(value.length, Math.trunc(d.start)));
    const end = Math.max(start, Math.min(value.length, Math.trunc(d.end)));
    if (end <= start) continue;
    normalized.push({ start, end, kind: d.kind });
  }

  normalized.forEach((d, idx) => {
    for (let i = d.start; i < d.end; i += 1) {
      if (owner[i] === -1) owner[i] = idx;
    }
  });

  let out = "";
  let i = 0;
  while (i < value.length) {
    const idx = owner[i];
    if (idx < 0) {
      out += value[i];
      i += 1;
      continue;
    }
    const d = normalized[idx];
    out += placeholder(d.kind);
    i = d.end;
  }

  return out;
}

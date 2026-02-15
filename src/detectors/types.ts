import type { DataClassification } from "../classification";

export type StringDetection = Readonly<{
  start: number;
  end: number;
  kind: DataClassification | "unknown";
  confidence?: number;
  source?: string;
}>;

export type StringDetector = (
  value: string,
  context: Readonly<{
    keyHint?: string;
    depth: number;
  }>,
) => readonly StringDetection[];

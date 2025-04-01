import { Detection, UnsafePattern } from "../types";

/**
 * Scans code content for unsafe MongoDB query patterns
 */
export function scanForUnsafePatterns(
  content: string,
  patterns: UnsafePattern[],
  filePath?: string
): Detection[] {
  // Skip scanning if this is the patterns definition file
  if (
    filePath &&
    (filePath.includes("unsafe-queries.ts") ||
      filePath.includes("unsafe-queries.js"))
  ) {
    return [];
  }

  const detections: Detection[] = [];
  const lines = content.split("\n");

  // Scan each line for unsafe patterns
  lines.forEach((line, index) => {
    patterns.forEach((pattern) => {
      if (pattern.pattern.test(line)) {
        detections.push({
          pattern,
          lineNumber: index + 1, // 1-based line numbers
          matchedText: line.trim(),
        });
      }
    });
  });

  return detections;
}

/**
 * Provides a color code based on severity
 */
export function getSeverityColor(severity: string): string {
  switch (severity) {
    case "high":
      return "#FF4D4F"; // Red
    case "medium":
      return "#FAAD14"; // Orange
    case "low":
      return "#52C41A"; // Green
    default:
      return "#1890FF"; // Blue
  }
}

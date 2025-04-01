/**
 * Represents a security severity level for unsafe patterns
 */
export type Severity = "low" | "medium" | "high";

/**
 * Represents an unsafe MongoDB query pattern
 */
export interface UnsafePattern {
  /** Unique identifier for the pattern */
  id: string;

  /** Human-readable name of the pattern */
  name: string;

  /** Regular expression to match the pattern */
  pattern: RegExp;

  /** Description of why this pattern is unsafe */
  description: string;

  /** Severity level of this security issue */
  severity: Severity;

  /** Recommendation on how to fix the issue */
  suggestion: string;

  /** Example of the vulnerable code */
  example: string;

  /** Example of a safe alternative */
  safeExample: string;

  /** URL to MongoDB documentation reference */
  docUrl: string;
}

/**
 * Represents a detected vulnerability in the code
 */
export interface Detection {
  /** The unsafe pattern that was detected */
  pattern: UnsafePattern;

  /** The line number where the pattern was found */
  lineNumber: number;

  /** The matched text */
  matchedText: string;
}

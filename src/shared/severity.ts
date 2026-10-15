import type {
  Severity
} from "./alertTypes";

export function getSeverityFromCount(
  count: number
): Severity {
  if (count >= 10) {
    return "CRITICAL";
  }

  if (count >= 5) {
    return "HIGH";
  }

  if (count >= 3) {
    return "MEDIUM";
  }

  return "LOW";
}
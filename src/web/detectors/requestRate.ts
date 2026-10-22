import type { Alert } from "../../shared/alertTypes";
import { getSeverityFromCount } from "../../shared/severity";
import type { WebLogEntry } from "../types";

export function detectHighRequestRate(
  entries: WebLogEntry[],
  threshold: number = 4,
  windowMs: number = 5 * 1000
): Alert[] {
  const alerts: Alert[] = [];
  const requestsByIp: Record<string, number[]> = {};

  for (const entry of entries) {
    const timestamp = new Date(`${entry.date}T${entry.time}`).getTime();
    (requestsByIp[entry.ipAddress] ??= []).push(timestamp);
  }

  for (const ip in requestsByIp) {
    const timestamps = [...(requestsByIp[ip] ?? [])].sort((a, b) => a - b);

    for (let start = 0; start < timestamps.length; start++) {
      let count = 1;

      for (let end = start + 1; end < timestamps.length; end++) {
        if (timestamps[end]! - timestamps[start]! <= windowMs) {
          count++;
        } else {
          break;
        }
      }

      if (count >= threshold) {
        const baseSeverity = getSeverityFromCount(count);
        const severity = baseSeverity === "LOW" ? "MEDIUM" : baseSeverity;

        alerts.push({
          type: "HIGH_REQUEST_RATE",
          severity,
          sourceIp: ip,
          detectedAt: new Date().toISOString(),
          eventTimestamp: new Date(timestamps[start]!).toISOString(),
          message: `High HTTP request rate from ${ip}: ${count} requests within ${windowMs / 1000} seconds`,
          evidence: {
            requestCount: count,
            windowSeconds: windowMs / 1000
          }
        });

        break;
      }
    }
  }

  return alerts;
}

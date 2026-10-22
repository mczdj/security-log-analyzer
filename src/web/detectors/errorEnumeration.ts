import type { Alert } from "../../shared/alertTypes";
import type { WebLogEntry } from "../types";

export function detectWebEnumeration(
  entries: WebLogEntry[],
  threshold: number = 4,
  windowMs: number = 10 * 1000
): Alert[] {
  const alerts: Alert[] = [];
  const errorsByIp: Record<string, Array<{ timestamp: number; path: string }>> = {};

  for (const entry of entries) {
    if (entry.statusCode !== 404 && entry.statusCode !== 403) {
      continue;
    }

    (errorsByIp[entry.ipAddress] ??= []).push({
      timestamp: new Date(`${entry.date}T${entry.time}`).getTime(),
      path: entry.path
    });
  }

  for (const ip in errorsByIp) {
    const events = [...(errorsByIp[ip] ?? [])].sort((a, b) => a.timestamp - b.timestamp);

    for (let start = 0; start < events.length; start++) {
      const paths: string[] = [events[start]!.path];

      for (let end = start + 1; end < events.length; end++) {
        if (events[end]!.timestamp - events[start]!.timestamp <= windowMs) {
          paths.push(events[end]!.path);
        } else {
          break;
        }
      }

      if (paths.length >= threshold) {
        alerts.push({
          type: "WEB_ENUMERATION",
          severity: "HIGH",
          sourceIp: ip,
          detectedAt: new Date().toISOString(),
          eventTimestamp: new Date(events[start]!.timestamp).toISOString(),
          message: `Possible web resource enumeration from ${ip}: ${paths.length} denied/not-found requests`,
          evidence: {
            requestCount: paths.length,
            paths,
            windowSeconds: windowMs / 1000
          }
        });
        break;
      }
    }
  }

  return alerts;
}

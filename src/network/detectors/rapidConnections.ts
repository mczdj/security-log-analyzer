import type { Alert } from "../../shared/alertTypes";
import type { NetworkLogEntry } from "../types";

export function detectRapidConnections(
  entries: NetworkLogEntry[],
  threshold: number = 8,
  windowMs: number = 10 * 1000
): Alert[] {
  const alerts: Alert[] = [];
  const timesByIp: Record<string, number[]> = {};

  for (const entry of entries) {
    (timesByIp[entry.sourceIp] ??= []).push(
      new Date(`${entry.date}T${entry.time}`).getTime()
    );
  }

  for (const ip in timesByIp) {
    const times = [...(timesByIp[ip] ?? [])].sort((a, b) => a - b);
    for (let start = 0; start < times.length; start++) {
      let count = 1;
      for (let end = start + 1; end < times.length; end++) {
        if (times[end]! - times[start]! <= windowMs) count++;
        else break;
      }
      if (count >= threshold) {
        alerts.push({
          type: "RAPID_CONNECTIONS",
          severity: count >= 15 ? "CRITICAL" : "HIGH",
          sourceIp: ip,
          detectedAt: new Date().toISOString(),
          eventTimestamp: new Date(times[start]!).toISOString(),
          message: `Rapid connection activity from ${ip}: ${count} connections within ${windowMs / 1000} seconds`,
          evidence: {
            connectionCount: count,
            windowSeconds: windowMs / 1000
          }
        });
        break;
      }
    }
  }

  return alerts;
}

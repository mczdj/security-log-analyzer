import type { Alert } from "../../shared/alertTypes";
import type { WebLogEntry } from "../types";

export function detectSuspiciousHttpMethods(entries: WebLogEntry[]): Alert[] {
  const alerts: Alert[] = [];

  for (const entry of entries) {
    if (entry.method !== "TRACE" && entry.method !== "CONNECT") {
      continue;
    }

    alerts.push({
      type: "SUSPICIOUS_HTTP_METHOD",
      severity: "HIGH",
      sourceIp: entry.ipAddress,
      detectedAt: new Date().toISOString(),
      eventTimestamp: `${entry.date}T${entry.time}`,
      message: `Suspicious HTTP ${entry.method} request from ${entry.ipAddress}`,
      evidence: {
        method: entry.method,
        path: entry.path,
        statusCode: entry.statusCode
      }
    });
  }

  return alerts;
}

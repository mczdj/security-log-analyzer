import type { Alert } from "../../shared/alertTypes";
import type { NetworkLogEntry } from "../types";

export function detectDnsAnomalies(entries: NetworkLogEntry[]): Alert[] {
  const alerts: Alert[] = [];

  for (const entry of entries) {
    if (entry.protocol !== "DNS" || !entry.domain) continue;

    const labels = entry.domain.split(".");
    const longestLabel = Math.max(...labels.map((label) => label.length));
    const suspicious = entry.domain.length > 70 || longestLabel > 45;

    if (!suspicious) continue;

    alerts.push({
      type: "DNS_ANOMALY",
      severity: "HIGH",
      sourceIp: entry.sourceIp,
      detectedAt: new Date().toISOString(),
      eventTimestamp: `${entry.date}T${entry.time}`,
      message: `Suspicious DNS query from ${entry.sourceIp}: unusually long domain name`,
      evidence: {
        domain: entry.domain,
        domainLength: entry.domain.length,
        longestLabel
      }
    });
  }

  return alerts;
}

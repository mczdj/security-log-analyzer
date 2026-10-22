import type { Alert } from "../../shared/alertTypes";
import type { NetworkLogEntry } from "../types";

export function detectProtocolAnomalies(entries: NetworkLogEntry[]): Alert[] {
  const alerts: Alert[] = [];

  for (const entry of entries) {
    let reason: string | null = null;

    if (entry.protocol === "DNS" && entry.destinationPort !== 53) {
      reason = "DNS traffic used a non-standard destination port";
    } else if (entry.protocol === "ICMP" && (entry.sourcePort !== 0 || entry.destinationPort !== 0)) {
      reason = "ICMP entry unexpectedly contained transport-layer ports";
    } else if ((entry.protocol === "TCP" || entry.protocol === "UDP") && entry.destinationPort === 0) {
      reason = `${entry.protocol} traffic targeted destination port 0`;
    }

    if (!reason) continue;

    alerts.push({
      type: "PROTOCOL_ANOMALY",
      severity: "MEDIUM",
      sourceIp: entry.sourceIp,
      detectedAt: new Date().toISOString(),
      eventTimestamp: `${entry.date}T${entry.time}`,
      message: `Protocol anomaly from ${entry.sourceIp}: ${reason}`,
      evidence: {
        destinationIp: entry.destinationIp,
        sourcePort: entry.sourcePort,
        destinationPort: entry.destinationPort,
        protocol: entry.protocol,
        reason
      }
    });
  }

  return alerts;
}

import type { Alert } from "../../shared/alertTypes";
import type { NetworkLogEntry } from "../types";

const SUSPICIOUS_PORTS: Record<number, string> = {
  23: "Telnet",
  2323: "Alternate Telnet",
  3389: "RDP",
  445: "SMB",
  5900: "VNC"
};

export function detectSuspiciousPortAccess(entries: NetworkLogEntry[]): Alert[] {
  const alerts: Alert[] = [];

  for (const entry of entries) {
    const service = SUSPICIOUS_PORTS[entry.destinationPort];
    if (!service) continue;

    alerts.push({
      type: "SUSPICIOUS_PORT_ACCESS",
      severity: entry.destinationPort === 23 || entry.destinationPort === 2323 ? "HIGH" : "MEDIUM",
      sourceIp: entry.sourceIp,
      detectedAt: new Date().toISOString(),
      eventTimestamp: `${entry.date}T${entry.time}`,
      message: `Suspicious ${service} access from ${entry.sourceIp} to ${entry.destinationIp}:${entry.destinationPort}`,
      evidence: {
        destinationIp: entry.destinationIp,
        destinationPort: entry.destinationPort,
        protocol: entry.protocol,
        service
      }
    });
  }

  return alerts;
}

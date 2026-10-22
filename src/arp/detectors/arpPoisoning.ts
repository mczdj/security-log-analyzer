import type { Alert } from "../../shared/alertTypes";
import type { ArpLogEntry } from "../types";

export function detectArpPoisoning(entries: ArpLogEntry[]): Alert[] {
  const alerts: Alert[] = [];
  const mapping = new Map<string, string>();
  const seenChanges = new Set<string>();

  const sorted = [...entries].sort(
    (a, b) =>
      new Date(`${a.date}T${a.time}`).getTime() -
      new Date(`${b.date}T${b.time}`).getTime()
  );

  for (const entry of sorted) {
    const previousMac = mapping.get(entry.ipAddress);

    if (previousMac && previousMac !== entry.macAddress) {
      const changeKey = `${entry.ipAddress}|${previousMac}|${entry.macAddress}`;
      if (!seenChanges.has(changeKey)) {
        alerts.push({
          type: "ARP_POISONING",
          severity: entry.ipAddress.endsWith(".1") ? "CRITICAL" : "HIGH",
          sourceIp: entry.ipAddress,
          detectedAt: new Date().toISOString(),
          eventTimestamp: `${entry.date}T${entry.time}`,
          message: `ARP mapping changed for ${entry.ipAddress}: ${previousMac} -> ${entry.macAddress}`,
          evidence: {
            ipAddress: entry.ipAddress,
            previousMac,
            newMac: entry.macAddress
          }
        });
        seenChanges.add(changeKey);
      }
    }

    mapping.set(entry.ipAddress, entry.macAddress);
  }

  return alerts;
}

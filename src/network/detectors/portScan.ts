import type { Alert } from "../../shared/alertTypes";
import type { NetworkLogEntry } from "../types";

export function detectPortScan(
  entries: NetworkLogEntry[],
  threshold: number = 5,
  windowMs: number = 60 * 1000
): Alert[] {
  const alerts: Alert[] = [];
  const groups = new Map<string, NetworkLogEntry[]>();

  for (const entry of entries) {
    const key = `${entry.sourceIp}|${entry.destinationIp}`;
    const group = groups.get(key) ?? [];
    group.push(entry);
    groups.set(key, group);
  }

  for (const [key, group] of groups) {
    const sorted = [...group].sort(
      (a, b) =>
        new Date(`${a.date}T${a.time}`).getTime() -
        new Date(`${b.date}T${b.time}`).getTime()
    );

    for (let start = 0; start < sorted.length; start++) {
      const startTime = new Date(`${sorted[start]!.date}T${sorted[start]!.time}`).getTime();
      const ports = new Set<number>();

      for (let end = start; end < sorted.length; end++) {
        const endTime = new Date(`${sorted[end]!.date}T${sorted[end]!.time}`).getTime();
        if (endTime - startTime > windowMs) break;
        ports.add(sorted[end]!.destinationPort);
      }

      if (ports.size >= threshold) {
        const [sourceIp, destinationIp] = key.split("|");
        alerts.push({
          type: "PORT_SCAN",
          severity: ports.size >= 10 ? "CRITICAL" : "HIGH",
          sourceIp,
          detectedAt: new Date().toISOString(),
          eventTimestamp: new Date(startTime).toISOString(),
          message: `Possible port scan from ${sourceIp} against ${destinationIp}: ${ports.size} destination ports probed`,
          evidence: {
            destinationIp: destinationIp!,
            destinationPorts: Array.from(ports).sort((a, b) => a - b),
            uniquePorts: ports.size,
            windowSeconds: windowMs / 1000
          }
        });
        break;
      }
    }
  }

  return alerts;
}

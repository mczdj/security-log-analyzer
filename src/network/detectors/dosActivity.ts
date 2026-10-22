import type { Alert } from "../../shared/alertTypes";
import type { NetworkLogEntry } from "../types";

export function detectDosActivity(
  entries: NetworkLogEntry[],
  threshold: number = 10,
  windowMs: number = 5 * 1000
): Alert[] {
  const alerts: Alert[] = [];
  const groups = new Map<string, number[]>();

  for (const entry of entries) {
    const key = `${entry.sourceIp}|${entry.destinationIp}`;
    const times = groups.get(key) ?? [];
    times.push(new Date(`${entry.date}T${entry.time}`).getTime());
    groups.set(key, times);
  }

  for (const [key, rawTimes] of groups) {
    const times = [...rawTimes].sort((a, b) => a - b);
    for (let start = 0; start < times.length; start++) {
      let count = 1;
      for (let end = start + 1; end < times.length; end++) {
        if (times[end]! - times[start]! <= windowMs) count++;
        else break;
      }
      if (count >= threshold) {
        const [sourceIp, destinationIp] = key.split("|");
        alerts.push({
          type: "DOS_ACTIVITY",
          severity: "CRITICAL",
          sourceIp,
          detectedAt: new Date().toISOString(),
          eventTimestamp: new Date(times[start]!).toISOString(),
          message: `Possible DoS-like activity from ${sourceIp} against ${destinationIp}: ${count} connections in ${windowMs / 1000} seconds`,
          evidence: {
            destinationIp: destinationIp!,
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

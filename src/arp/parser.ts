import type { ArpLogEntry, ArpParseResult, InvalidArpLog } from "./types";
import { validateArpLog } from "./validator";

export function parseArpLogs(logs: string): ArpParseResult {
  const lines = logs.split(/\r?\n/).filter((line) => line.trim() !== "");
  const entries: ArpLogEntry[] = [];
  const invalidLogs: InvalidArpLog[] = [];

  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    const error = validateArpLog(parts);

    if (error) {
      invalidLogs.push({ line, reason: error });
      continue;
    }

    const ip = parts.find((part) => part.startsWith("ip="))!.replace("ip=", "");
    const mac = parts.find((part) => part.startsWith("mac="))!.replace("mac=", "");

    entries.push({
      date: parts[0]!,
      time: parts[1]!,
      event: "ARP_REPLY",
      ipAddress: ip,
      macAddress: mac.toUpperCase()
    });
  }

  return { entries, invalidLogs };
}

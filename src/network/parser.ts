import type {
  InvalidNetworkLog,
  NetworkLogEntry,
  NetworkParseResult,
  NetworkProtocol
} from "./types";
import { validateNetworkLog } from "./validator";

export function parseNetworkLogs(logs: string): NetworkParseResult {
  const lines = logs.split(/\r?\n/).filter((line) => line.trim() !== "");
  const entries: NetworkLogEntry[] = [];
  const invalidLogs: InvalidNetworkLog[] = [];

  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    const validationError = validateNetworkLog(parts);

    if (validationError) {
      invalidLogs.push({ line, reason: validationError });
      continue;
    }

    const value = (prefix: string) =>
      parts.find((part) => part.startsWith(prefix))!.replace(prefix, "");

    const domainPart = parts.find((part) => part.startsWith("domain="));

    entries.push({
      date: parts[0]!,
      time: parts[1]!,
      event: "NETWORK_CONNECTION",
      sourceIp: value("src="),
      destinationIp: value("dst="),
      sourcePort: Number(value("srcPort=")),
      destinationPort: Number(value("dstPort=")),
      protocol: value("protocol=").toUpperCase() as NetworkProtocol,
      bytes: Number(value("bytes=")),
      ...(domainPart ? { domain: domainPart.replace("domain=", "") } : {})
    });
  }

  return { entries, invalidLogs };
}

import type {
  LogEntry,
  InvalidLog,
  ParseResult
} from "./types";

import { validateLog } from "./validator";

export function parseLogs(logs: string): ParseResult {
  const logLines: string[] = logs
    .split(/\r?\n/)
    .filter((line: string) => line.trim() !== "");

  const entries: LogEntry[] = [];
  const invalidLogs: InvalidLog[] = [];

  for (const line of logLines) {
    const parts: string[] =
      line.trim().split(/\s+/);

    const validationError: string | null =
      validateLog(parts);

    if (validationError) {
      invalidLogs.push({
        line,
        reason: validationError
      });

      continue;
    }

    const userPart: string = parts.find(
      (part: string) => part.startsWith("user=")
    )!;

    const ipPart: string = parts.find(
      (part: string) => part.startsWith("ip=")
    )!;

    const entry: LogEntry = {
      date: parts[0]!,
      time: parts[1]!,
      event: parts[2]!,
      username: userPart.replace("user=", ""),
      ipAddress: ipPart.replace("ip=", "")
    };

    entries.push(entry);
  }

  return {
    entries,
    invalidLogs
  };
}
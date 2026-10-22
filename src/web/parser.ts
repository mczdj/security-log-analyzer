import type {
  HttpMethod,
  InvalidWebLog,
  WebLogEntry,
  WebParseResult
} from "./types";
import { validateWebLog } from "./validator";

export function parseWebLogs(logs: string): WebParseResult {
  const lines = logs
    .split(/\r?\n/)
    .filter((line) => line.trim() !== "");

  const entries: WebLogEntry[] = [];
  const invalidLogs: InvalidWebLog[] = [];

  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    const validationError = validateWebLog(parts);

    if (validationError) {
      invalidLogs.push({ line, reason: validationError });
      continue;
    }

    const methodPart = parts.find((part) => part.startsWith("method="))!;
    const pathPart = parts.find((part) => part.startsWith("path="))!;
    const statusPart = parts.find((part) => part.startsWith("status="))!;
    const ipPart = parts.find((part) => part.startsWith("ip="))!;

    entries.push({
      date: parts[0]!,
      time: parts[1]!,
      event: "HTTP_REQUEST",
      method: methodPart.replace("method=", "").toUpperCase() as HttpMethod,
      path: pathPart.replace("path=", ""),
      statusCode: Number(statusPart.replace("status=", "")),
      ipAddress: ipPart.replace("ip=", "")
    });
  }

  return { entries, invalidLogs };
}

import type { Alert } from "../../shared/alertTypes";
import type { WebLogEntry } from "../types";

function decodePath(path: string): string {
  try {
    return decodeURIComponent(path.replace(/\+/g, " "));
  } catch {
    return path;
  }
}

export function detectSqlInjection(entries: WebLogEntry[]): Alert[] {
  const alerts: Alert[] = [];

  const patterns: Array<{ name: string; regex: RegExp }> = [
    { name: "OR tautology", regex: /['\"]?\s+or\s+\d+\s*=\s*\d+/i },
    { name: "UNION SELECT", regex: /\bunion\s+(all\s+)?select\b/i },
    { name: "SQL SELECT/FROM", regex: /\bselect\b.+\bfrom\b/i },
    { name: "DROP TABLE", regex: /\bdrop\s+table\b/i },
    { name: "information_schema", regex: /information_schema/i },
    { name: "SQL comment", regex: /--|\/\*/ }
  ];

  for (const entry of entries) {
    const decodedPath = decodePath(entry.path);
    const match = patterns.find((pattern) => pattern.regex.test(decodedPath));

    if (!match) {
      continue;
    }

    alerts.push({
      type: "SQL_INJECTION",
      severity: "HIGH",
      sourceIp: entry.ipAddress,
      detectedAt: new Date().toISOString(),
      eventTimestamp: `${entry.date}T${entry.time}`,
      message: `Possible SQL injection attempt from ${entry.ipAddress} targeting ${entry.path}`,
      evidence: {
        method: entry.method,
        path: entry.path,
        decodedPath,
        statusCode: entry.statusCode,
        matchedPattern: match.name
      }
    });
  }

  return alerts;
}

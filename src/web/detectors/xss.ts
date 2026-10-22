import type { Alert } from "../../shared/alertTypes";
import type { WebLogEntry } from "../types";

function decodePath(path: string): string {
  try {
    return decodeURIComponent(path.replace(/\+/g, " "));
  } catch {
    return path;
  }
}

export function detectXss(entries: WebLogEntry[]): Alert[] {
  const alerts: Alert[] = [];
  const patterns: Array<{ name: string; regex: RegExp }> = [
    { name: "script tag", regex: /<\s*script\b/i },
    { name: "javascript URI", regex: /javascript\s*:/i },
    { name: "event handler", regex: /\bon(?:error|load|click|mouseover)\s*=/i },
    { name: "document.cookie", regex: /document\.cookie/i },
    { name: "HTML payload", regex: /<\s*(?:img|svg|iframe)\b/i }
  ];

  for (const entry of entries) {
    const decodedPath = decodePath(entry.path);
    const match = patterns.find((pattern) => pattern.regex.test(decodedPath));

    if (!match) {
      continue;
    }

    alerts.push({
      type: "XSS_ATTACK",
      severity: "HIGH",
      sourceIp: entry.ipAddress,
      detectedAt: new Date().toISOString(),
      eventTimestamp: `${entry.date}T${entry.time}`,
      message: `Possible cross-site scripting attempt from ${entry.ipAddress}`,
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

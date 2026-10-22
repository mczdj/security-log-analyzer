import type { Alert } from "../../shared/alertTypes";
import type { WebLogEntry } from "../types";

function decodePath(path: string): string {
  try {
    return decodeURIComponent(path.replace(/\+/g, " "));
  } catch {
    return path;
  }
}

export function detectPathTraversal(entries: WebLogEntry[]): Alert[] {
  const alerts: Alert[] = [];

  for (const entry of entries) {
    const decodedPath = decodePath(entry.path).toLowerCase();
    const suspicious =
      decodedPath.includes("../") ||
      decodedPath.includes("..\\") ||
      decodedPath.includes("/etc/passwd") ||
      decodedPath.includes("windows/system32") ||
      decodedPath.includes("win.ini");

    if (!suspicious) {
      continue;
    }

    alerts.push({
      type: "PATH_TRAVERSAL",
      severity: "HIGH",
      sourceIp: entry.ipAddress,
      detectedAt: new Date().toISOString(),
      eventTimestamp: `${entry.date}T${entry.time}`,
      message: `Possible path traversal attempt from ${entry.ipAddress}`,
      evidence: {
        method: entry.method,
        path: entry.path,
        decodedPath,
        statusCode: entry.statusCode
      }
    });
  }

  return alerts;
}

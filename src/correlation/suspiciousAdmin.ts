import type { Alert } from "../shared/alertTypes";
import { isPrivateIPv4 } from "../shared/validation";
import type { LogEntry } from "../authentication/types";

const PRIVILEGED_USERS = new Set(["admin", "administrator", "root"]);

export function detectSuspiciousAdminActivity(entries: LogEntry[]): Alert[] {
  const alerts: Alert[] = [];

  for (const entry of entries) {
    if (
      entry.event !== "LOGIN_SUCCESS" ||
      !PRIVILEGED_USERS.has(entry.username.toLowerCase()) ||
      isPrivateIPv4(entry.ipAddress)
    ) {
      continue;
    }

    alerts.push({
      type: "SUSPICIOUS_ADMIN_ACTIVITY",
      severity: "HIGH",
      sourceIp: entry.ipAddress,
      username: entry.username,
      detectedAt: new Date().toISOString(),
      eventTimestamp: `${entry.date}T${entry.time}`,
      message: `Privileged account "${entry.username}" logged in successfully from public IP ${entry.ipAddress}`,
      evidence: {
        username: entry.username,
        ipAddress: entry.ipAddress,
        privilegedAccount: true
      }
    });
  }

  return alerts;
}

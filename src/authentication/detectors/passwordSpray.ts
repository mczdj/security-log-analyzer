import type {
  Alert
} from "../../shared/alertTypes";

import {
  getSeverityFromCount
} from "../../shared/severity";

export function detectPasswordSpray(
  failedUsersByIp: Record<string, Set<string>>,
  threshold: number = 3
): Alert[] {
  const alerts: Alert[] = [];

  for (const ip in failedUsersByIp) {
    const usernames: Set<string> =
      failedUsersByIp[ip] ?? new Set<string>();

    if (usernames.size >= threshold) {
      const severity =
        getSeverityFromCount(
          usernames.size
        );

      const usernameList: string[] =
        Array.from(usernames);

      const alert: Alert = {
        type: "PASSWORD_SPRAY",

        severity,

        sourceIp: ip,

        detectedAt:
          new Date().toISOString(),

        message:
          `Possible password-spraying attack from ${ip} - ` +
          `attempted ${usernames.size} different usernames`,

        evidence: {
          uniqueUsernames:
            usernames.size,

          usernames:
            usernameList
        }
      };

      alerts.push(alert);
    }
  }

  return alerts;
}
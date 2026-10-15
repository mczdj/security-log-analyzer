import type {
  Alert
} from "../../shared/alertTypes";

import {
  getSeverityFromCount
} from "../../shared/severity";

export function detectDistributedAttack(
  failedIpsByUser: Record<string, Set<string>>,
  threshold: number = 3
): Alert[] {
  const alerts: Alert[] = [];

  for (const username in failedIpsByUser) {
    const ipAddresses: Set<string> =
      failedIpsByUser[username] ?? new Set<string>();

    if (ipAddresses.size >= threshold) {
      const severity =
        getSeverityFromCount(
          ipAddresses.size
        );

      const ipList: string[] =
        Array.from(ipAddresses);

      const alert: Alert = {
        type: "DISTRIBUTED_ACCOUNT_ATTACK",

        severity,

        username,

        sourceIps: ipList,

        detectedAt:
          new Date().toISOString(),

        message:
          `Possible distributed attack against account "${username}" - ` +
          `${ipAddresses.size} different IP addresses attempted this account`,

        evidence: {
          uniqueIpAddresses:
            ipAddresses.size,

          ipAddresses:
            ipList
        }
      };

      alerts.push(alert);
    }
  }

  return alerts;
}
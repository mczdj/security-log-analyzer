import type { Alert } from "../types";

import {
  getSeverityFromCount
} from "../severity";

export function detectBruteForce(
  failedLoginTimes: Record<string, number[]>,
  threshold: number = 3,
  windowMs: number = 2 * 60 * 1000
): Alert[] {
  const alerts: Alert[] = [];

  for (const ip in failedLoginTimes) {
    const timestamps: number[] = [
      ...(failedLoginTimes[ip] ?? [])
    ];

    // Sort timestamps from oldest to newest
    timestamps.sort(
      (a: number, b: number) => a - b
    );

    for (
      let start = 0;
      start < timestamps.length;
      start++
    ) {
      let attemptsInWindow: number = 1;

      for (
        let end = start + 1;
        end < timestamps.length;
        end++
      ) {
        const timeDifference: number =
          timestamps[end]! -
          timestamps[start]!;

        if (timeDifference <= windowMs) {
          attemptsInWindow++;
        } else {
          break;
        }
      }

      if (attemptsInWindow >= threshold) {
        const severity =
          getSeverityFromCount(
            attemptsInWindow
          );

        const alert: Alert = {
          type: "BRUTE_FORCE",

          severity,

          sourceIp: ip,

          detectedAt:
            new Date().toISOString(),

          eventTimestamp:
            new Date(
              timestamps[start]!
            ).toISOString(),

          message:
            `Possible brute-force attack from ${ip} - ` +
            `${attemptsInWindow} failed login attempts within 2 minutes`,

          evidence: {
            failedAttempts:
              attemptsInWindow,

            windowMinutes:
              windowMs / 60 / 1000
          }
        };

        alerts.push(alert);

        // Only one brute-force alert per IP
        break;
      }
    }
  }

  return alerts;
}
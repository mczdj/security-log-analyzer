import type {
  Alert,
  LogEntry
} from "../types";

export function detectSuccessAfterFailures(
  entries: LogEntry[],
  failureThreshold: number = 3,
  windowMs: number = 5 * 60 * 1000
): Alert[] {
  const alerts: Alert[] = [];

  // Create a copy and sort all logs
  // from oldest to newest
  const sortedEntries: LogEntry[] = [
    ...entries
  ].sort(
    (
      a: LogEntry,
      b: LogEntry
    ) => {
      const timeA: number =
        new Date(
          `${a.date}T${a.time}`
        ).getTime();

      const timeB: number =
        new Date(
          `${b.date}T${b.time}`
        ).getTime();

      return timeA - timeB;
    }
  );

  // -----------------------------------------
  // CHECK SUCCESSFUL LOGINS
  // -----------------------------------------

  for (
    let i = 0;
    i < sortedEntries.length;
    i++
  ) {
    const currentEntry: LogEntry =
      sortedEntries[i]!;

    // Ignore everything except successful logins
    if (
      currentEntry.event !==
      "LOGIN_SUCCESS"
    ) {
      continue;
    }

    const successTime: number =
      new Date(
        `${currentEntry.date}T${currentEntry.time}`
      ).getTime();

    let failedAttempts: number = 0;

    // -----------------------------------------
    // LOOK BACKWARDS FOR PREVIOUS FAILURES
    // -----------------------------------------

    for (
      let j = i - 1;
      j >= 0;
      j--
    ) {
      const previousEntry: LogEntry =
        sortedEntries[j]!;

      const previousTime: number =
        new Date(
          `${previousEntry.date}T${previousEntry.time}`
        ).getTime();

      const timeDifference: number =
        successTime - previousTime;

      // Stop checking once we leave
      // the configured time window
      if (timeDifference > windowMs) {
        break;
      }

      // Count failures from the same
      // username AND same IP
      if (
        previousEntry.event === "LOGIN_FAILED" &&
        previousEntry.username === currentEntry.username &&
        previousEntry.ipAddress === currentEntry.ipAddress
      ) {
        failedAttempts++;
      }
    }

    // -----------------------------------------
    // CREATE SECURITY ALERT
    // -----------------------------------------

    if (
      failedAttempts >= failureThreshold
    ) {
      const severity:
        "HIGH" | "CRITICAL" =
        failedAttempts >= 5
          ? "CRITICAL"
          : "HIGH";

      const alert: Alert = {
        type: "SUCCESS_AFTER_FAILURES",

        severity,

        sourceIp:
          currentEntry.ipAddress,

        username:
          currentEntry.username,

        detectedAt:
          new Date().toISOString(),

        eventTimestamp:
          `${currentEntry.date}T${currentEntry.time}`,

        message:
          `Successful login after repeated failures - ` +
          `user="${currentEntry.username}", ` +
          `ip=${currentEntry.ipAddress}, ` +
          `${failedAttempts} failures before success within 5 minutes`,

        evidence: {
          failedAttempts,

          windowMinutes:
            windowMs / 60 / 1000
        }
      };

      alerts.push(alert);
    }
  }

  return alerts;
}
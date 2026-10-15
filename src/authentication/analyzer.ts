import type {
  LogEntry,
  AuthenticationAnalysis
} from "./types";

export function analyzeAuthentication(
  entries: LogEntry[]
): AuthenticationAnalysis {

  let successfulLogins: number = 0;

  let failedLogins: number = 0;

  const failedLoginCounts:
    Record<string, number> = {};

  const failedLoginTimes:
    Record<string, number[]> = {};

  const failedUsersByIp:
    Record<string, Set<string>> = {};

  const failedIpsByUser:
    Record<string, Set<string>> = {};

  for (const entry of entries) {

    // =========================================
    // SUCCESSFUL LOGIN
    // =========================================

    if (
      entry.event ===
      "LOGIN_SUCCESS"
    ) {
      successfulLogins++;
    }

    // =========================================
    // FAILED LOGIN
    // =========================================

    if (
      entry.event ===
      "LOGIN_FAILED"
    ) {
      failedLogins++;

      // Failures by IP
      failedLoginCounts[
        entry.ipAddress
      ] =
        (
          failedLoginCounts[
            entry.ipAddress
          ] ?? 0
        ) + 1;

      // Failure timestamp
      const timestamp: number =
        new Date(
          `${entry.date}T${entry.time}`
        ).getTime();

      if (
        !failedLoginTimes[
          entry.ipAddress
        ]
      ) {
        failedLoginTimes[
          entry.ipAddress
        ] = [];
      }

      failedLoginTimes[
        entry.ipAddress
      ].push(
        timestamp
      );

      // Users targeted by IP
      if (
        !failedUsersByIp[
          entry.ipAddress
        ]
      ) {
        failedUsersByIp[
          entry.ipAddress
        ] =
          new Set<string>();
      }

      failedUsersByIp[
        entry.ipAddress
      ].add(
        entry.username
      );

      // IPs attacking user
      if (
        !failedIpsByUser[
          entry.username
        ]
      ) {
        failedIpsByUser[
          entry.username
        ] =
          new Set<string>();
      }

      failedIpsByUser[
        entry.username
      ].add(
        entry.ipAddress
      );
    }
  }

  return {
    successfulLogins,
    failedLogins,
    failedLoginCounts,
    failedLoginTimes,
    failedUsersByIp,
    failedIpsByUser
  };
}
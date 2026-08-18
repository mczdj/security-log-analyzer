import type {
  LogEntry,
  AuthenticationAnalysis
} from "./types";

export function analyzeAuthentication(
  entries: LogEntry[]
): AuthenticationAnalysis {
  let successfulLogins: number = 0;
  let failedLogins: number = 0;

  const failedLoginCounts: Record<string, number> = {};

  const failedLoginTimes: Record<string, number[]> = {};

  const failedUsersByIp: Record<string, Set<string>> = {};

  const failedIpsByUser: Record<string, Set<string>> = {};

  for (const entry of entries) {
    // -----------------------------------------
    // SUCCESSFUL LOGINS
    // -----------------------------------------

    if (entry.event === "LOGIN_SUCCESS") {
      successfulLogins++;
    }

    // -----------------------------------------
    // FAILED LOGINS
    // -----------------------------------------

    if (entry.event === "LOGIN_FAILED") {
      failedLogins++;

      // -----------------------------------------
      // COUNT FAILURES BY IP
      // -----------------------------------------

      failedLoginCounts[entry.ipAddress] =
        (failedLoginCounts[entry.ipAddress] ?? 0) + 1;

      // -----------------------------------------
      // STORE FAILURE TIMESTAMPS
      // -----------------------------------------

      const timestamp: number = new Date(
        `${entry.date}T${entry.time}`
      ).getTime();

      if (!failedLoginTimes[entry.ipAddress]) {
        failedLoginTimes[entry.ipAddress] = [];
      }

      failedLoginTimes[entry.ipAddress].push(timestamp);

      // -----------------------------------------
      // STORE USERNAMES TARGETED BY EACH IP
      // Used for password spraying
      // -----------------------------------------

      if (!failedUsersByIp[entry.ipAddress]) {
        failedUsersByIp[entry.ipAddress] =
          new Set<string>();
      }

      failedUsersByIp[entry.ipAddress].add(
        entry.username
      );

      // -----------------------------------------
      // STORE IPs ATTACKING EACH USER
      // Used for distributed account attacks
      // -----------------------------------------

      if (!failedIpsByUser[entry.username]) {
        failedIpsByUser[entry.username] =
          new Set<string>();
      }

      failedIpsByUser[entry.username].add(
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
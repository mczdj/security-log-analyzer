import { readFileSync } from "node:fs";

import type { Alert } from "./types";

import { parseLogs } from "./parser";
import { analyzeAuthentication } from "./analyzer";

import { detectBruteForce } from "./detectors/bruteForce";
import { detectPasswordSpray } from "./detectors/passwordSpray";
import { detectDistributedAttack } from "./detectors/distributedAttack";
import { detectSuccessAfterFailures } from "./detectors/successAfterFailures";

import {
  processNotifications
} from "./notification/notificationManager";

// -----------------------------------------
// MAIN APPLICATION
// -----------------------------------------

async function main(): Promise<void> {

  // -----------------------------------------
  // READ LOG FILE
  // -----------------------------------------

  const logs: string = readFileSync(
    "./logs/sample.log",
    "utf8"
  );

  // -----------------------------------------
  // PARSE LOGS
  // -----------------------------------------

  const {
    entries,
    invalidLogs
  } = parseLogs(logs);

  // -----------------------------------------
  // DISPLAY INVALID LOGS
  // -----------------------------------------

  for (const invalidLog of invalidLogs) {
    console.log(
      "⚠ Invalid log detected:"
    );

    console.log(
      invalidLog.line
    );

    console.log(
      `Reason: ${invalidLog.reason}\n`
    );
  }

  // -----------------------------------------
  // ANALYZE AUTHENTICATION EVENTS
  // -----------------------------------------

  const analysis =
    analyzeAuthentication(
      entries
    );

  // -----------------------------------------
  // AUTHENTICATION SUMMARY
  // -----------------------------------------

  console.log(
    "\n===== AUTHENTICATION SUMMARY ====="
  );

  console.log(
    `Total valid events: ${entries.length}`
  );

  console.log(
    `Successful logins: ${analysis.successfulLogins}`
  );

  console.log(
    `Failed logins: ${analysis.failedLogins}`
  );

  // -----------------------------------------
  // FAILED LOGIN ATTEMPTS BY IP
  // -----------------------------------------

  console.log(
    "\n===== FAILED LOGIN ATTEMPTS BY IP ====="
  );

  for (
    const ip in
    analysis.failedLoginCounts
  ) {
    const attempts: number =
      analysis.failedLoginCounts[ip] ?? 0;

    console.log(
      `${ip}: ${attempts} failed attempt(s)`
    );
  }

  // -----------------------------------------
  // RUN SECURITY DETECTORS
  // -----------------------------------------

  const bruteForceAlerts: Alert[] =
    detectBruteForce(
      analysis.failedLoginTimes
    );

  const passwordSprayAlerts: Alert[] =
    detectPasswordSpray(
      analysis.failedUsersByIp
    );

  const distributedAttackAlerts: Alert[] =
    detectDistributedAttack(
      analysis.failedIpsByUser
    );

  const successAfterFailureAlerts: Alert[] =
    detectSuccessAfterFailures(
      entries
    );

  // -----------------------------------------
  // COMBINE SECURITY ALERTS
  // -----------------------------------------

  const securityAlerts: Alert[] = [
    ...bruteForceAlerts,
    ...passwordSprayAlerts,
    ...distributedAttackAlerts,
    ...successAfterFailureAlerts
  ];

  // -----------------------------------------
  // DISPLAY SECURITY ALERTS
  // -----------------------------------------

  console.log(
    "\n===== SECURITY ALERTS ====="
  );

  if (securityAlerts.length === 0) {
    console.log(
      "No suspicious authentication activity detected."
    );
  } else {
    for (const alert of securityAlerts) {

      const icon: string =
        alert.severity === "HIGH" ||
        alert.severity === "CRITICAL"
          ? "🚨"
          : "⚠";

      console.log(
        `${icon} [${alert.severity}] ${alert.message}`
      );

      // -----------------------------------------
      // PASSWORD SPRAY DETAILS
      // -----------------------------------------

      if (
        alert.type ===
        "PASSWORD_SPRAY"
      ) {
        const usernames =
          alert.evidence.usernames;

        if (
          Array.isArray(usernames)
        ) {
          console.log(
            `   Usernames: ${usernames.join(", ")}`
          );
        }
      }

      // -----------------------------------------
      // DISTRIBUTED ATTACK DETAILS
      // -----------------------------------------

      if (
        alert.type ===
        "DISTRIBUTED_ACCOUNT_ATTACK"
      ) {
        const ipAddresses =
          alert.evidence.ipAddresses;

        if (
          Array.isArray(ipAddresses)
        ) {
          console.log(
            `   IP addresses: ${ipAddresses.join(", ")}`
          );
        }
      }
    }
  }

  // -----------------------------------------
  // PROCESS EMAIL NOTIFICATIONS
  // -----------------------------------------

  console.log(
    "\n===== NOTIFICATIONS ====="
  );

  const notificationSummary =
    await processNotifications(
      securityAlerts
    );

  // -----------------------------------------
  // NOTIFICATION SUMMARY
  // -----------------------------------------

  console.log(
    "\n===== NOTIFICATION SUMMARY ====="
  );

  console.log(
    `Emails sent: ${notificationSummary.sent}`
  );

  console.log(
    `Alerts included in emails: ${notificationSummary.alertsIncluded}`
  );

  console.log(
    `Duplicates skipped: ${notificationSummary.duplicateSkipped}`
  );

  console.log(
    `Cooldown skips: ${notificationSummary.cooldownSkipped}`
  );

  console.log(
    `Failed notifications: ${notificationSummary.failed}`
  );

  // -----------------------------------------
  // VALID LOGS
  // -----------------------------------------

  console.log(
    "\n===== VALID LOGS ====="
  );

  console.log(
    entries
  );
}

// -----------------------------------------
// START APPLICATION
// -----------------------------------------

main().catch(
  (error: unknown) => {
    console.error(
      "Fatal application error:"
    );

    if (
      error instanceof Error
    ) {
      console.error(
        error.message
      );
    } else {
      console.error(
        error
      );
    }
  }
);
import nodemailer from "nodemailer";

import type {
  Alert
} from "../types";

// -----------------------------------------
// GET REQUIRED ENVIRONMENT VARIABLE
// -----------------------------------------

function getRequiredEnvironmentVariable(
  name: string
): string {
  const value: string | undefined =
    process.env[name];

  if (!value) {
    throw new Error(
      `Missing environment variable: ${name}`
    );
  }

  return value;
}

// -----------------------------------------
// FORMAT ONE ALERT
// -----------------------------------------

function formatSingleAlert(
  alert: Alert,
  alertNumber: number
): string {
  const sourceIp: string =
    alert.sourceIp ??
    alert.sourceIps?.join(", ") ??
    "N/A";

  const username: string =
    alert.username ?? "N/A";

  return `
==================================================
ALERT ${alertNumber}
==================================================

Severity: ${alert.severity}
Type: ${alert.type}

Message:
${alert.message}

Source IP / IPs:
${sourceIp}

Username:
${username}

Detected At:
${alert.detectedAt}

Event Timestamp:
${alert.eventTimestamp ?? "N/A"}

Evidence:
${JSON.stringify(alert.evidence, null, 2)}
`;
}

// -----------------------------------------
// FORMAT COMPLETE SECURITY EMAIL
// -----------------------------------------

function formatAlertEmail(
  alerts: Alert[]
): string {
  const formattedAlerts: string =
    alerts
      .map(
        (
          alert: Alert,
          index: number
        ) =>
          formatSingleAlert(
            alert,
            index + 1
          )
      )
      .join("\n");

  return `
SECURITY ALERT SUMMARY

Total alerts: ${alerts.length}

The Log Analyzer detected security events that
require attention.

${formattedAlerts}

==================================================
Log Analyzer Security System
==================================================
`;
}

// -----------------------------------------
// GET HIGHEST SEVERITY
// -----------------------------------------

function getHighestSeverity(
  alerts: Alert[]
): "HIGH" | "CRITICAL" {
  const hasCriticalAlert: boolean =
    alerts.some(
      (alert: Alert) =>
        alert.severity === "CRITICAL"
    );

  return hasCriticalAlert
    ? "CRITICAL"
    : "HIGH";
}

// -----------------------------------------
// SEND SECURITY SUMMARY EMAIL
// -----------------------------------------

export async function sendEmailAlerts(
  alerts: Alert[]
): Promise<void> {
  if (alerts.length === 0) {
    return;
  }

  const emailUser: string =
    getRequiredEnvironmentVariable(
      "EMAIL_USER"
    );

  const emailAppPassword: string =
    getRequiredEnvironmentVariable(
      "EMAIL_APP_PASSWORD"
    );

  const alertEmail: string =
    getRequiredEnvironmentVariable(
      "ALERT_EMAIL"
    );

  const transporter =
    nodemailer.createTransport({
      host: "smtp.mail.yahoo.com",
      port: 465,
      secure: true,

      auth: {
        user: emailUser,
        pass: emailAppPassword
      }
    });

  const highestSeverity =
    getHighestSeverity(alerts);

  await transporter.sendMail({
    from: emailUser,

    to: alertEmail,

    subject:
      `[${highestSeverity}] Security Alert Summary - ` +
      `${alerts.length} alert(s) detected`,

    text:
      formatAlertEmail(alerts)
  });
}
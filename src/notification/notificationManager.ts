import {
  createHash
} from "node:crypto";

import type {
  Alert
} from "../types";

import {
  sendEmailAlerts
} from "./emailnotifier";

import {
  loadNotificationState,
  saveNotificationState,
  type NotificationState
} from "./notificationStore";

// -----------------------------------------
// NOTIFICATION SUMMARY
// -----------------------------------------

export type NotificationSummary = {
  sent: number;
  alertsIncluded: number;
  duplicateSkipped: number;
  cooldownSkipped: number;
  failed: number;
};

// -----------------------------------------
// PENDING EMAIL ALERT
// -----------------------------------------

type PendingAlert = {
  alert: Alert;
  alertId: string;
  cooldownKey: string;
};

// -----------------------------------------
// EMAIL SEVERITY RULE
// -----------------------------------------

function shouldSendEmail(
  alert: Alert
): boolean {
  return (
    alert.severity === "HIGH" ||
    alert.severity === "CRITICAL"
  );
}

// -----------------------------------------
// GET COOLDOWN
// -----------------------------------------

function getCooldownMilliseconds():
number {
  const value: string =
    process.env.NOTIFICATION_COOLDOWN_MINUTES
      ?? "10";

  const minutes: number =
    Number(value);

  if (
    !Number.isFinite(minutes) ||
    minutes <= 0
  ) {
    return 10 * 60 * 1000;
  }

  return minutes * 60 * 1000;
}

// -----------------------------------------
// CREATE UNIQUE ALERT ID
// -----------------------------------------

function createAlertId(
  alert: Alert
): string {
  const sortedSourceIps: string[] =
    alert.sourceIps
      ? [...alert.sourceIps].sort()
      : [];

  const alertData = {
    type: alert.type,

    severity: alert.severity,

    sourceIp:
      alert.sourceIp ?? null,

    sourceIps:
      sortedSourceIps,

    username:
      alert.username ?? null,

    eventTimestamp:
      alert.eventTimestamp ?? null,

    message:
      alert.message,

    evidence:
      alert.evidence
  };

  const serializedAlert: string =
    JSON.stringify(alertData);

  return createHash("sha256")
    .update(serializedAlert)
    .digest("hex");
}

// -----------------------------------------
// CREATE COOLDOWN KEY
// -----------------------------------------

function createCooldownKey(
  alert: Alert
): string {
  const source: string =
    alert.sourceIp ??
    alert.sourceIps
      ?.slice()
      .sort()
      .join(",")
    ??
    "NO_SOURCE";

  const username: string =
    alert.username ??
    "NO_USERNAME";

  return [
    alert.type,
    source,
    username
  ].join("|");
}

// -----------------------------------------
// CHECK EXACT DUPLICATE
// -----------------------------------------

function wasAlreadySent(
  alertId: string,
  state: NotificationState
): boolean {
  return Boolean(
    state.sentAlertIds[alertId]
  );
}

// -----------------------------------------
// CHECK COOLDOWN
// -----------------------------------------

function isCooldownActive(
  cooldownKey: string,
  state: NotificationState,
  cooldownMs: number
): boolean {
  const lastSent: string | undefined =
    state.cooldowns[cooldownKey];

  if (!lastSent) {
    return false;
  }

  const lastSentTime: number =
    new Date(lastSent).getTime();

  if (Number.isNaN(lastSentTime)) {
    return false;
  }

  const elapsed: number =
    Date.now() -
    lastSentTime;

  return elapsed < cooldownMs;
}

// -----------------------------------------
// PROCESS NOTIFICATIONS
// -----------------------------------------

export async function processNotifications(
  alerts: Alert[]
): Promise<NotificationSummary> {
  const state: NotificationState =
    loadNotificationState();

  const cooldownMs: number =
    getCooldownMilliseconds();

  const summary: NotificationSummary = {
    sent: 0,
    alertsIncluded: 0,
    duplicateSkipped: 0,
    cooldownSkipped: 0,
    failed: 0
  };

  const pendingAlerts: PendingAlert[] = [];

  // -----------------------------------------
  // FILTER ALERTS
  // -----------------------------------------

  for (const alert of alerts) {

    // Ignore LOW / MEDIUM
    if (!shouldSendEmail(alert)) {
      continue;
    }

    const alertId: string =
      createAlertId(alert);

    const cooldownKey: string =
      createCooldownKey(alert);

    // -----------------------------------------
    // DUPLICATE CHECK
    // -----------------------------------------

    if (
      wasAlreadySent(
        alertId,
        state
      )
    ) {
      summary.duplicateSkipped++;

      console.log(
        `♻️ Duplicate notification skipped for ${alert.type}`
      );

      continue;
    }

    // -----------------------------------------
    // COOLDOWN CHECK
    // -----------------------------------------

    if (
      isCooldownActive(
        cooldownKey,
        state,
        cooldownMs
      )
    ) {
      summary.cooldownSkipped++;

      console.log(
        `⏳ Notification cooldown active for ${alert.type}`
      );

      continue;
    }

    // Add this alert to the single email
    pendingAlerts.push({
      alert,
      alertId,
      cooldownKey
    });
  }

  // -----------------------------------------
  // NOTHING TO SEND
  // -----------------------------------------

  if (pendingAlerts.length === 0) {
    return summary;
  }

  // -----------------------------------------
  // SEND ONE EMAIL
  // -----------------------------------------

  try {
    const alertsToSend: Alert[] =
      pendingAlerts.map(
        (item: PendingAlert) =>
          item.alert
      );

    await sendEmailAlerts(
      alertsToSend
    );

    const sentAt: string =
      new Date().toISOString();

    // Save each included alert as sent
    for (const item of pendingAlerts) {
      state.sentAlertIds[
        item.alertId
      ] = sentAt;

      state.cooldowns[
        item.cooldownKey
      ] = sentAt;
    }

    saveNotificationState(
      state
    );

    // One actual email was sent
    summary.sent = 1;

    // Number of alerts inside the email
    summary.alertsIncluded =
      pendingAlerts.length;

    console.log(
      `📧 Security summary email sent with ${pendingAlerts.length} alert(s)`
    );

  } catch (error: unknown) {
    summary.failed++;

    console.error(
      "❌ Failed to send security summary email"
    );

    if (error instanceof Error) {
      console.error(
        `   Reason: ${error.message}`
      );
    }
  }

  return summary;
}
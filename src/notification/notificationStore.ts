import {
  existsSync,
  readFileSync,
  writeFileSync
} from "node:fs";

// -----------------------------------------
// NOTIFICATION STATE
// -----------------------------------------

export type NotificationState = {
  sentAlertIds: Record<string, string>;
  cooldowns: Record<string, string>;
};

const STATE_FILE: string =
  ".notification-state.json";

// -----------------------------------------
// CREATE EMPTY STATE
// -----------------------------------------

function createEmptyState(): NotificationState {
  return {
    sentAlertIds: {},
    cooldowns: {}
  };
}

// -----------------------------------------
// LOAD NOTIFICATION STATE
// -----------------------------------------

export function loadNotificationState():
NotificationState {
  if (!existsSync(STATE_FILE)) {
    return createEmptyState();
  }

  try {
    const rawData: string =
      readFileSync(
        STATE_FILE,
        "utf8"
      );

    if (rawData.trim() === "") {
      return createEmptyState();
    }

    const parsed: unknown =
      JSON.parse(rawData);

    if (
      typeof parsed !== "object" ||
      parsed === null
    ) {
      return createEmptyState();
    }

    const state =
      parsed as Partial<NotificationState>;

    return {
      sentAlertIds:
        state.sentAlertIds ?? {},

      cooldowns:
        state.cooldowns ?? {}
    };
  } catch {
    console.log(
      "⚠ Could not read notification history."
    );

    console.log(
      "Starting with an empty notification history."
    );

    return createEmptyState();
  }
}

// -----------------------------------------
// SAVE NOTIFICATION STATE
// -----------------------------------------

export function saveNotificationState(
  state: NotificationState
): void {
  writeFileSync(
    STATE_FILE,
    JSON.stringify(
      state,
      null,
      2
    ),
    "utf8"
  );
}
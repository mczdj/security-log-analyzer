import {
  isValidDate,
  isValidTime,
  isValidIPv4
} from "../shared/validation";

const ALLOWED_EVENTS: string[] = [
  "LOGIN_SUCCESS",
  "LOGIN_FAILED"
];

export function validateLog(
  parts: string[]
): string | null {

  // =========================================
  // BASIC FIELDS
  // =========================================

  if (parts.length < 3) {
    return "Missing date, time, or event";
  }

  const date: string =
    parts[0]!;

  const time: string =
    parts[1]!;

  const event: string =
    parts[2]!;

  // =========================================
  // DATE
  // =========================================

  if (!isValidDate(date)) {
    return "Invalid date format or value";
  }

  // =========================================
  // TIME
  // =========================================

  if (!isValidTime(time)) {
    return "Invalid time format or value";
  }

  // =========================================
  // EVENT TYPE
  // =========================================

  if (
    !ALLOWED_EVENTS.includes(
      event
    )
  ) {
    return `Invalid event type: ${event}`;
  }

  const dataFields: string[] =
    parts.slice(3);

  // =========================================
  // USER FIELDS
  // =========================================

  const userFields: string[] =
    dataFields.filter(
      (part: string) =>
        part.startsWith("user=")
    );

  // =========================================
  // IP FIELDS
  // =========================================

  const ipFields: string[] =
    dataFields.filter(
      (part: string) =>
        part.startsWith("ip=")
    );

  // =========================================
  // UNEXPECTED FIELDS
  // =========================================

  const unexpectedFields: string[] =
    dataFields.filter(
      (part: string) =>
        !part.startsWith("user=") &&
        !part.startsWith("ip=")
    );

  if (
    unexpectedFields.length > 0
  ) {
    return (
      `Unexpected field(s): ` +
      `${unexpectedFields.join(", ")}`
    );
  }

  // =========================================
  // USERNAME VALIDATION
  // =========================================

  if (
    userFields.length === 0 ||
    userFields[0] === "user="
  ) {
    return "Missing username";
  }

  if (userFields.length > 1) {
    return "Duplicate username field";
  }

  // =========================================
  // IP VALIDATION
  // =========================================

  if (
    ipFields.length === 0 ||
    ipFields[0] === "ip="
  ) {
    return "Missing IP address";
  }

  if (ipFields.length > 1) {
    return "Duplicate IP address field";
  }

  const ipAddress: string =
    ipFields[0]!.replace(
      "ip=",
      ""
    );

  if (
    !isValidIPv4(
      ipAddress
    )
  ) {
    return (
      `Invalid IP address: ` +
      `${ipAddress}`
    );
  }

  return null;
}
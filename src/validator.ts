const ALLOWED_EVENTS: string[] = [
  "LOGIN_SUCCESS",
  "LOGIN_FAILED"
];

function isValidDate(date: string): boolean {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(date);

  if (!match) {
    return false;
  }

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);

  const parsedDate = new Date(Date.UTC(year, month - 1, day));

  return (
    parsedDate.getUTCFullYear() === year &&
    parsedDate.getUTCMonth() === month - 1 &&
    parsedDate.getUTCDate() === day
  );
}

function isValidTime(time: string): boolean {
  return /^(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d$/.test(time);
}

function isValidIPv4(ipAddress: string): boolean {
  const parts: string[] = ipAddress.split(".");

  if (parts.length !== 4) {
    return false;
  }

  return parts.every((part: string) => {
    if (!/^\d{1,3}$/.test(part)) {
      return false;
    }

    const value: number = Number(part);

    return value >= 0 && value <= 255;
  });
}

export function validateLog(
  parts: string[]
): string | null {
  if (parts.length < 3) {
    return "Missing date, time, or event";
  }

  const date: string = parts[0]!;
  const time: string = parts[1]!;
  const event: string = parts[2]!;

  if (!isValidDate(date)) {
    return "Invalid date format or value";
  }

  if (!isValidTime(time)) {
    return "Invalid time format or value";
  }

  if (!ALLOWED_EVENTS.includes(event)) {
    return `Invalid event type: ${event}`;
  }

  const dataFields: string[] = parts.slice(3);

  const userFields: string[] = dataFields.filter(
    (part: string) => part.startsWith("user=")
  );

  const ipFields: string[] = dataFields.filter(
    (part: string) => part.startsWith("ip=")
  );

  const unexpectedFields: string[] = dataFields.filter(
    (part: string) =>
      !part.startsWith("user=") &&
      !part.startsWith("ip=")
  );

  if (unexpectedFields.length > 0) {
    return `Unexpected field(s): ${unexpectedFields.join(", ")}`;
  }

  if (userFields.length === 0 || userFields[0] === "user=") {
    return "Missing username";
  }

  if (userFields.length > 1) {
    return "Duplicate username field";
  }

  if (ipFields.length === 0 || ipFields[0] === "ip=") {
    return "Missing IP address";
  }

  if (ipFields.length > 1) {
    return "Duplicate IP address field";
  }

  const ipAddress: string =
    ipFields[0]!.replace("ip=", "");

  if (!isValidIPv4(ipAddress)) {
    return `Invalid IP address: ${ipAddress}`;
  }

  return null;
}
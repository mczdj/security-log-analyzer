import { isValidDate, isValidIPv4, isValidTime } from "../shared/validation";

function isValidMacAddress(mac: string): boolean {
  return /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/.test(mac);
}

export function validateArpLog(parts: string[]): string | null {
  if (parts.length < 3) return "Missing date, time, or event";

  const date = parts[0]!;
  const time = parts[1]!;
  const event = parts[2]!;

  if (!isValidDate(date)) return "Invalid date format or value";
  if (!isValidTime(time)) return "Invalid time format or value";
  if (event !== "ARP_REPLY") return `Invalid ARP event type: ${event}`;

  const fields = parts.slice(3);
  const ipFields = fields.filter((field) => field.startsWith("ip="));
  const macFields = fields.filter((field) => field.startsWith("mac="));
  const unexpected = fields.filter(
    (field) => !field.startsWith("ip=") && !field.startsWith("mac=")
  );

  if (unexpected.length > 0) return `Unexpected field(s): ${unexpected.join(", ")}`;
  if (ipFields.length === 0 || ipFields[0] === "ip=") return "Missing IP address";
  if (ipFields.length > 1) return "Duplicate IP address field";
  if (macFields.length === 0 || macFields[0] === "mac=") return "Missing MAC address";
  if (macFields.length > 1) return "Duplicate MAC address field";

  const ip = ipFields[0]!.replace("ip=", "");
  const mac = macFields[0]!.replace("mac=", "");

  if (!isValidIPv4(ip)) return `Invalid IP address: ${ip}`;
  if (!isValidMacAddress(mac)) return `Invalid MAC address: ${mac}`;

  return null;
}

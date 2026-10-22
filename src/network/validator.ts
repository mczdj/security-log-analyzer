import type { NetworkProtocol } from "./types";
import {
  isValidDate,
  isValidIPv4,
  isValidTime
} from "../shared/validation";

const ALLOWED_PROTOCOLS: NetworkProtocol[] = ["TCP", "UDP", "ICMP", "DNS"];

function parseNumberField(field: string, prefix: string): number | null {
  const value = field.replace(prefix, "");
  if (!/^\d+$/.test(value)) {
    return null;
  }
  return Number(value);
}

export function validateNetworkLog(parts: string[]): string | null {
  if (parts.length < 3) {
    return "Missing date, time, or event";
  }

  const date = parts[0]!;
  const time = parts[1]!;
  const event = parts[2]!;

  if (!isValidDate(date)) return "Invalid date format or value";
  if (!isValidTime(time)) return "Invalid time format or value";
  if (event !== "NETWORK_CONNECTION") return `Invalid network event type: ${event}`;

  const fields = parts.slice(3);
  const allowedPrefixes = [
    "src=",
    "dst=",
    "srcPort=",
    "dstPort=",
    "protocol=",
    "bytes=",
    "domain="
  ];

  const unexpected = fields.filter(
    (field) => !allowedPrefixes.some((prefix) => field.startsWith(prefix))
  );

  if (unexpected.length > 0) {
    return `Unexpected field(s): ${unexpected.join(", ")}`;
  }

  const getFields = (prefix: string) => fields.filter((field) => field.startsWith(prefix));

  const srcFields = getFields("src=");
  const dstFields = getFields("dst=");
  const srcPortFields = getFields("srcPort=");
  const dstPortFields = getFields("dstPort=");
  const protocolFields = getFields("protocol=");
  const bytesFields = getFields("bytes=");
  const domainFields = getFields("domain=");

  const required: Array<[string, string[]]> = [
    ["source IP", srcFields],
    ["destination IP", dstFields],
    ["source port", srcPortFields],
    ["destination port", dstPortFields],
    ["protocol", protocolFields],
    ["bytes", bytesFields]
  ];

  for (const [name, values] of required) {
    if (values.length === 0 || values[0]!.endsWith("=")) return `Missing ${name}`;
    if (values.length > 1) return `Duplicate ${name} field`;
  }

  if (domainFields.length > 1) return "Duplicate domain field";

  const sourceIp = srcFields[0]!.replace("src=", "");
  const destinationIp = dstFields[0]!.replace("dst=", "");

  if (!isValidIPv4(sourceIp)) return `Invalid source IP address: ${sourceIp}`;
  if (!isValidIPv4(destinationIp)) return `Invalid destination IP address: ${destinationIp}`;

  const sourcePort = parseNumberField(srcPortFields[0]!, "srcPort=");
  const destinationPort = parseNumberField(dstPortFields[0]!, "dstPort=");
  const bytes = parseNumberField(bytesFields[0]!, "bytes=");

  if (sourcePort === null || sourcePort < 0 || sourcePort > 65535) {
    return `Invalid source port: ${srcPortFields[0]!.replace("srcPort=", "")}`;
  }

  if (destinationPort === null || destinationPort < 0 || destinationPort > 65535) {
    return `Invalid destination port: ${dstPortFields[0]!.replace("dstPort=", "")}`;
  }

  if (bytes === null || bytes < 0) {
    return `Invalid byte count: ${bytesFields[0]!.replace("bytes=", "")}`;
  }

  const protocol = protocolFields[0]!.replace("protocol=", "").toUpperCase();
  if (!ALLOWED_PROTOCOLS.includes(protocol as NetworkProtocol)) {
    return `Invalid network protocol: ${protocol}`;
  }

  if (domainFields.length === 1 && domainFields[0] === "domain=") {
    return "Missing domain value";
  }

  return null;
}

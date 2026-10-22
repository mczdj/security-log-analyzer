import type { HttpMethod } from "./types";
import {
  isValidDate,
  isValidIPv4,
  isValidTime
} from "../shared/validation";

const ALLOWED_HTTP_METHODS: HttpMethod[] = [
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "HEAD",
  "OPTIONS",
  "TRACE",
  "CONNECT"
];

export function validateWebLog(parts: string[]): string | null {
  if (parts.length < 3) {
    return "Missing date, time, or event";
  }

  const date = parts[0]!;
  const time = parts[1]!;
  const event = parts[2]!;

  if (!isValidDate(date)) {
    return "Invalid date format or value";
  }

  if (!isValidTime(time)) {
    return "Invalid time format or value";
  }

  if (event !== "HTTP_REQUEST") {
    return `Invalid web event type: ${event}`;
  }

  const dataFields = parts.slice(3);
  const methodFields = dataFields.filter((part) => part.startsWith("method="));
  const pathFields = dataFields.filter((part) => part.startsWith("path="));
  const statusFields = dataFields.filter((part) => part.startsWith("status="));
  const ipFields = dataFields.filter((part) => part.startsWith("ip="));

  const unexpectedFields = dataFields.filter(
    (part) =>
      !part.startsWith("method=") &&
      !part.startsWith("path=") &&
      !part.startsWith("status=") &&
      !part.startsWith("ip=")
  );

  if (unexpectedFields.length > 0) {
    return `Unexpected field(s): ${unexpectedFields.join(", ")}`;
  }

  if (methodFields.length === 0 || methodFields[0] === "method=") {
    return "Missing HTTP method";
  }

  if (methodFields.length > 1) {
    return "Duplicate HTTP method field";
  }

  const method = methodFields[0]!.replace("method=", "").toUpperCase();

  if (!ALLOWED_HTTP_METHODS.includes(method as HttpMethod)) {
    return `Invalid HTTP method: ${method}`;
  }

  if (pathFields.length === 0 || pathFields[0] === "path=") {
    return "Missing request path";
  }

  if (pathFields.length > 1) {
    return "Duplicate request path field";
  }

  const path = pathFields[0]!.replace("path=", "");

  if (!path.startsWith("/")) {
    return `Invalid request path: ${path}`;
  }

  if (statusFields.length === 0 || statusFields[0] === "status=") {
    return "Missing HTTP status code";
  }

  if (statusFields.length > 1) {
    return "Duplicate HTTP status field";
  }

  const statusValue = statusFields[0]!.replace("status=", "");

  if (!/^\d{3}$/.test(statusValue)) {
    return `Invalid HTTP status code: ${statusValue}`;
  }

  const statusCode = Number(statusValue);

  if (statusCode < 100 || statusCode > 599) {
    return `Invalid HTTP status code: ${statusCode}`;
  }

  if (ipFields.length === 0 || ipFields[0] === "ip=") {
    return "Missing IP address";
  }

  if (ipFields.length > 1) {
    return "Duplicate IP address field";
  }

  const ipAddress = ipFields[0]!.replace("ip=", "");

  if (!isValidIPv4(ipAddress)) {
    return `Invalid IP address: ${ipAddress}`;
  }

  return null;
}

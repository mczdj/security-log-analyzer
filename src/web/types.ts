// =========================================
// HTTP METHODS
// =========================================

export type HttpMethod =
  | "GET"
  | "POST"
  | "PUT"
  | "PATCH"
  | "DELETE"
  | "HEAD"
  | "OPTIONS"
  | "TRACE"
  | "CONNECT";

// =========================================
// WEB LOG ENTRY
// =========================================

export type WebLogEntry = {
  date: string;

  time: string;

  event: "HTTP_REQUEST";

  method: HttpMethod;

  path: string;

  statusCode: number;

  ipAddress: string;
};

// =========================================
// INVALID WEB LOG
// =========================================

export type InvalidWebLog = {
  line: string;
  reason: string;
};

// =========================================
// WEB PARSER RESULT
// =========================================

export type WebParseResult = {
  entries: WebLogEntry[];

  invalidLogs: InvalidWebLog[];
};
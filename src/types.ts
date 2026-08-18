export type LogEntry = {
  date: string;
  time: string;
  event: string;
  username: string;
  ipAddress: string;
};

export type InvalidLog = {
  line: string;
  reason: string;
};

export type ParseResult = {
  entries: LogEntry[];
  invalidLogs: InvalidLog[];
};

// -----------------------------------------
// SECURITY SEVERITY
// -----------------------------------------

export type Severity =
  | "LOW"
  | "MEDIUM"
  | "HIGH"
  | "CRITICAL";

// -----------------------------------------
// ALERT TYPES
// -----------------------------------------

export type AlertType =
  | "BRUTE_FORCE"
  | "PASSWORD_SPRAY"
  | "DISTRIBUTED_ACCOUNT_ATTACK"
  | "SUCCESS_AFTER_FAILURES";

// -----------------------------------------
// STRUCTURED SECURITY ALERT
// -----------------------------------------

export type Alert = {
  type: AlertType;

  severity: Severity;

  message: string;

  sourceIp?: string;

  sourceIps?: string[];

  username?: string;

  detectedAt: string;

  eventTimestamp?: string;

  evidence: Record<
    string,
    string | number | string[]
  >;
};

// -----------------------------------------
// AUTHENTICATION ANALYSIS
// -----------------------------------------

export type AuthenticationAnalysis = {
  successfulLogins: number;

  failedLogins: number;

  failedLoginCounts: Record<
    string,
    number
  >;

  failedLoginTimes: Record<
    string,
    number[]
  >;

  failedUsersByIp: Record<
    string,
    Set<string>
  >;

  failedIpsByUser: Record<
    string,
    Set<string>
  >;
};
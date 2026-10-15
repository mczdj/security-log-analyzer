// =========================================
// SECURITY SEVERITY
// =========================================

export type Severity =
  | "LOW"
  | "MEDIUM"
  | "HIGH"
  | "CRITICAL";

// =========================================
// SECURITY ALERT TYPES
// =========================================

export type AlertType =
  // Authentication
  | "BRUTE_FORCE"
  | "PASSWORD_SPRAY"
  | "DISTRIBUTED_ACCOUNT_ATTACK"
  | "SUCCESS_AFTER_FAILURES"

  // Web
  | "SQL_INJECTION"
  | "XSS_ATTACK"
  | "PATH_TRAVERSAL"
  | "SUSPICIOUS_HTTP_METHOD"
  | "HIGH_REQUEST_RATE";

// =========================================
// STRUCTURED SECURITY ALERT
// =========================================

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
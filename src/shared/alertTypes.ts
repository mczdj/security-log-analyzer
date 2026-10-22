export type Severity =
  | "LOW"
  | "MEDIUM"
  | "HIGH"
  | "CRITICAL";

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
  | "HIGH_REQUEST_RATE"
  | "WEB_ENUMERATION"

  // Network
  | "PORT_SCAN"
  | "RAPID_CONNECTIONS"
  | "SUSPICIOUS_PORT_ACCESS"
  | "PROTOCOL_ANOMALY"
  | "DNS_ANOMALY"
  | "DOS_ACTIVITY"

  // ARP
  | "ARP_POISONING"

  // Correlation
  | "SUSPICIOUS_ADMIN_ACTIVITY"
  | "ATTACK_CHAIN";

export type AlertEvidenceValue =
  | string
  | number
  | boolean
  | string[]
  | number[];

export type Alert = {
  type: AlertType;
  severity: Severity;
  message: string;
  sourceIp?: string;
  sourceIps?: string[];
  username?: string;
  detectedAt: string;
  eventTimestamp?: string;
  riskScore?: number;
  evidence: Record<string, AlertEvidenceValue>;
};

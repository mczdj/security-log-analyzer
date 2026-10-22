export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type Alert = {
  type: string;
  severity: Severity;
  message: string;
  sourceIp?: string;
  sourceIps?: string[];
  username?: string;
  detectedAt: string;
  eventTimestamp?: string;
  riskScore?: number;
  evidence: Record<string, unknown>;
};

export type SourceStats = { valid: number; invalid: number };

export type Stats = {
  authentication: SourceStats;
  web: SourceStats;
  network: SourceStats;
  arp: SourceStats;
  totalEvents: number;
  totalInvalidLogs: number;
  totalAlerts: number;
  severityCounts: Record<Severity, number>;
};

export type SuspiciousIp = {
  ipAddress: string;
  alertCount: number;
  highestSeverity: Severity;
  maxRiskScore: number;
  alertTypes: string[];
};

export type AnalysisResult = {
  generatedAt: string;
  stats: Stats;
  alerts: Alert[];
  suspiciousIps: SuspiciousIp[];
  invalidLogs: Array<{ source: string; line: string; reason: string }>;
};

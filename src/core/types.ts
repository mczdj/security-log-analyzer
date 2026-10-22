import type { Alert, Severity } from "../shared/alertTypes";

export type LogSource = "authentication" | "web" | "network" | "arp";

export type InvalidLogRecord = {
  source: LogSource;
  line: string;
  reason: string;
};

export type SourceStats = {
  valid: number;
  invalid: number;
};

export type SeverityCounts = Record<Severity, number>;

export type SuspiciousIpSummary = {
  ipAddress: string;
  alertCount: number;
  highestSeverity: Severity;
  maxRiskScore: number;
  alertTypes: string[];
};

export type AnalysisStats = {
  authentication: SourceStats;
  web: SourceStats;
  network: SourceStats;
  arp: SourceStats;
  totalEvents: number;
  totalInvalidLogs: number;
  totalAlerts: number;
  severityCounts: SeverityCounts;
};

export type AnalysisResult = {
  generatedAt: string;
  stats: AnalysisStats;
  alerts: Alert[];
  invalidLogs: InvalidLogRecord[];
  suspiciousIps: SuspiciousIpSummary[];
};

export type LogBundle = {
  authenticationLogs: string;
  webLogs: string;
  networkLogs: string;
  arpLogs: string;
};

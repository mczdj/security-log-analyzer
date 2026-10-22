import { existsSync, readFileSync } from "node:fs";
import type { Alert, Severity } from "../shared/alertTypes";
import { parseLogs } from "../authentication/parser";
import { analyzeAuthentication } from "../authentication/analyzer";
import { detectBruteForce } from "../authentication/detectors/bruteForce";
import { detectPasswordSpray } from "../authentication/detectors/passwordSpray";
import { detectDistributedAttack } from "../authentication/detectors/distributedAttack";
import { detectSuccessAfterFailures } from "../authentication/detectors/successAfterFailures";
import { parseWebLogs } from "../web/parser";
import { detectSqlInjection } from "../web/detectors/sqlInjection";
import { detectXss } from "../web/detectors/xss";
import { detectPathTraversal } from "../web/detectors/pathTraversal";
import { detectSuspiciousHttpMethods } from "../web/detectors/suspiciousMethod";
import { detectHighRequestRate } from "../web/detectors/requestRate";
import { detectWebEnumeration } from "../web/detectors/errorEnumeration";
import { parseNetworkLogs } from "../network/parser";
import { detectPortScan } from "../network/detectors/portScan";
import { detectRapidConnections } from "../network/detectors/rapidConnections";
import { detectSuspiciousPortAccess } from "../network/detectors/suspiciousPort";
import { detectProtocolAnomalies } from "../network/detectors/protocolAnomaly";
import { detectDnsAnomalies } from "../network/detectors/dnsAnomaly";
import { detectDosActivity } from "../network/detectors/dosActivity";
import { parseArpLogs } from "../arp/parser";
import { detectArpPoisoning } from "../arp/detectors/arpPoisoning";
import { detectSuspiciousAdminActivity } from "../correlation/suspiciousAdmin";
import { correlateAttackChains } from "../correlation/attackChain";
import { applyRiskScores } from "../correlation/riskScoring";
import type {
  AnalysisResult,
  InvalidLogRecord,
  LogBundle,
  SuspiciousIpSummary
} from "./types";

const SEVERITY_RANK: Record<Severity, number> = {
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4
};

function safeRead(path: string): string {
  return existsSync(path) ? readFileSync(path, "utf8") : "";
}

export function loadDefaultLogBundle(): LogBundle {
  return {
    authenticationLogs: safeRead("./logs/authentication.log"),
    webLogs: safeRead("./logs/web.log"),
    networkLogs: safeRead("./logs/network.log"),
    arpLogs: safeRead("./logs/arp.log")
  };
}

function buildSuspiciousIpSummary(alerts: Alert[]): SuspiciousIpSummary[] {
  const summaries = new Map<string, SuspiciousIpSummary>();

  for (const alert of alerts) {
    const ips = new Set<string>();
    if (alert.sourceIp) ips.add(alert.sourceIp);
    for (const ip of alert.sourceIps ?? []) ips.add(ip);

    for (const ip of ips) {
      const current = summaries.get(ip) ?? {
        ipAddress: ip,
        alertCount: 0,
        highestSeverity: "LOW" as Severity,
        maxRiskScore: 0,
        alertTypes: []
      };

      current.alertCount++;
      if (SEVERITY_RANK[alert.severity] > SEVERITY_RANK[current.highestSeverity]) {
        current.highestSeverity = alert.severity;
      }
      current.maxRiskScore = Math.max(current.maxRiskScore, alert.riskScore ?? 0);
      if (!current.alertTypes.includes(alert.type)) current.alertTypes.push(alert.type);
      summaries.set(ip, current);
    }
  }

  return Array.from(summaries.values()).sort(
    (a, b) => b.maxRiskScore - a.maxRiskScore || b.alertCount - a.alertCount
  );
}

export function analyzeLogBundle(bundle: LogBundle): AnalysisResult {
  const authentication = parseLogs(bundle.authenticationLogs);
  const web = parseWebLogs(bundle.webLogs);
  const network = parseNetworkLogs(bundle.networkLogs);
  const arp = parseArpLogs(bundle.arpLogs);

  const authAnalysis = analyzeAuthentication(authentication.entries);

  const authenticationAlerts: Alert[] = [
    ...detectBruteForce(authAnalysis.failedLoginTimes),
    ...detectPasswordSpray(authAnalysis.failedUsersByIp),
    ...detectDistributedAttack(authAnalysis.failedIpsByUser),
    ...detectSuccessAfterFailures(authentication.entries),
    ...detectSuspiciousAdminActivity(authentication.entries)
  ];

  const webAlerts: Alert[] = [
    ...detectSqlInjection(web.entries),
    ...detectXss(web.entries),
    ...detectPathTraversal(web.entries),
    ...detectSuspiciousHttpMethods(web.entries),
    ...detectHighRequestRate(web.entries),
    ...detectWebEnumeration(web.entries)
  ];

  const networkAlerts: Alert[] = [
    ...detectPortScan(network.entries),
    ...detectRapidConnections(network.entries),
    ...detectSuspiciousPortAccess(network.entries),
    ...detectProtocolAnomalies(network.entries),
    ...detectDnsAnomalies(network.entries),
    ...detectDosActivity(network.entries)
  ];

  const arpAlerts = detectArpPoisoning(arp.entries);
  const baseAlerts = [
    ...authenticationAlerts,
    ...webAlerts,
    ...networkAlerts,
    ...arpAlerts
  ];

  const correlationAlerts = correlateAttackChains(baseAlerts);
  const alerts = applyRiskScores([...baseAlerts, ...correlationAlerts]);

  const invalidLogs: InvalidLogRecord[] = [
    ...authentication.invalidLogs.map((log) => ({ source: "authentication" as const, ...log })),
    ...web.invalidLogs.map((log) => ({ source: "web" as const, ...log })),
    ...network.invalidLogs.map((log) => ({ source: "network" as const, ...log })),
    ...arp.invalidLogs.map((log) => ({ source: "arp" as const, ...log }))
  ];

  const severityCounts: Record<Severity, number> = {
    LOW: 0,
    MEDIUM: 0,
    HIGH: 0,
    CRITICAL: 0
  };

  for (const alert of alerts) severityCounts[alert.severity]++;

  const totalEvents =
    authentication.entries.length +
    web.entries.length +
    network.entries.length +
    arp.entries.length;

  return {
    generatedAt: new Date().toISOString(),
    stats: {
      authentication: {
        valid: authentication.entries.length,
        invalid: authentication.invalidLogs.length
      },
      web: {
        valid: web.entries.length,
        invalid: web.invalidLogs.length
      },
      network: {
        valid: network.entries.length,
        invalid: network.invalidLogs.length
      },
      arp: {
        valid: arp.entries.length,
        invalid: arp.invalidLogs.length
      },
      totalEvents,
      totalInvalidLogs: invalidLogs.length,
      totalAlerts: alerts.length,
      severityCounts
    },
    alerts,
    invalidLogs,
    suspiciousIps: buildSuspiciousIpSummary(alerts)
  };
}

export function analyzeDefaultFiles(): AnalysisResult {
  return analyzeLogBundle(loadDefaultLogBundle());
}

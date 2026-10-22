import { mkdirSync, writeFileSync } from "node:fs";
import type { AnalysisResult } from "../core/types";

export function writeSecurityReports(
  result: AnalysisResult,
  outputDirectory: string = "./reports"
): { jsonPath: string; textPath: string } {
  mkdirSync(outputDirectory, { recursive: true });

  const jsonPath = `${outputDirectory}/security-report.json`;
  const textPath = `${outputDirectory}/security-summary.txt`;

  writeFileSync(jsonPath, JSON.stringify(result, null, 2), "utf8");

  const lines: string[] = [
    "SECURITY LOG ANALYZER REPORT",
    "============================",
    `Generated: ${result.generatedAt}`,
    "",
    `Total events: ${result.stats.totalEvents}`,
    `Invalid logs: ${result.stats.totalInvalidLogs}`,
    `Total alerts: ${result.stats.totalAlerts}`,
    `LOW: ${result.stats.severityCounts.LOW}`,
    `MEDIUM: ${result.stats.severityCounts.MEDIUM}`,
    `HIGH: ${result.stats.severityCounts.HIGH}`,
    `CRITICAL: ${result.stats.severityCounts.CRITICAL}`,
    "",
    "TOP SUSPICIOUS IPS",
    "------------------"
  ];

  for (const item of result.suspiciousIps.slice(0, 10)) {
    lines.push(
      `${item.ipAddress} | alerts=${item.alertCount} | severity=${item.highestSeverity} | risk=${item.maxRiskScore} | types=${item.alertTypes.join(",")}`
    );
  }

  lines.push("", "ALERTS", "------");

  for (const alert of result.alerts) {
    lines.push(
      `[${alert.severity}] ${alert.type} | risk=${alert.riskScore ?? 0} | ${alert.message}`
    );
  }

  writeFileSync(textPath, `${lines.join("\n")}\n`, "utf8");

  return { jsonPath, textPath };
}

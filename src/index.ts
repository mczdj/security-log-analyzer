import { analyzeDefaultFiles } from "./core/analyze";
import { processNotifications } from "./notification/notificationManager";
import { writeSecurityReports } from "./reporting/reportGenerator";

async function main(): Promise<void> {
  const result = analyzeDefaultFiles();

  console.log("\n===== SECURITY LOG ANALYZER =====");
  console.log(`Generated: ${result.generatedAt}`);

  console.log("\n===== EVENT SUMMARY =====");
  console.log(`Authentication: ${result.stats.authentication.valid} valid / ${result.stats.authentication.invalid} invalid`);
  console.log(`Web: ${result.stats.web.valid} valid / ${result.stats.web.invalid} invalid`);
  console.log(`Network: ${result.stats.network.valid} valid / ${result.stats.network.invalid} invalid`);
  console.log(`ARP: ${result.stats.arp.valid} valid / ${result.stats.arp.invalid} invalid`);
  console.log(`Total events: ${result.stats.totalEvents}`);

  console.log("\n===== INVALID LOGS =====");
  if (result.invalidLogs.length === 0) {
    console.log("No invalid logs detected.");
  } else {
    for (const invalidLog of result.invalidLogs) {
      console.log(`[${invalidLog.source}] ${invalidLog.line}`);
      console.log(`Reason: ${invalidLog.reason}\n`);
    }
  }

  console.log("\n===== SECURITY ALERTS =====");
  if (result.alerts.length === 0) {
    console.log("No suspicious activity detected.");
  } else {
    for (const alert of result.alerts) {
      const icon = alert.severity === "CRITICAL" ? "🛑" : alert.severity === "HIGH" ? "🚨" : "⚠";
      console.log(`${icon} [${alert.severity}] [Risk ${alert.riskScore ?? 0}] ${alert.type} - ${alert.message}`);
    }
  }

  console.log("\n===== SEVERITY SUMMARY =====");
  console.log(`LOW: ${result.stats.severityCounts.LOW}`);
  console.log(`MEDIUM: ${result.stats.severityCounts.MEDIUM}`);
  console.log(`HIGH: ${result.stats.severityCounts.HIGH}`);
  console.log(`CRITICAL: ${result.stats.severityCounts.CRITICAL}`);

  console.log("\n===== TOP SUSPICIOUS IPS =====");
  for (const item of result.suspiciousIps.slice(0, 10)) {
    console.log(`${item.ipAddress}: alerts=${item.alertCount}, severity=${item.highestSeverity}, risk=${item.maxRiskScore}`);
  }

  console.log("\n===== NOTIFICATIONS =====");
  const notificationsEnabled = process.env.NOTIFICATIONS_ENABLED !== "false";

  if (notificationsEnabled) {
    const notificationSummary = await processNotifications(result.alerts);
    console.log(`Emails sent: ${notificationSummary.sent}`);
    console.log(`Alerts included in emails: ${notificationSummary.alertsIncluded}`);
    console.log(`Duplicates skipped: ${notificationSummary.duplicateSkipped}`);
    console.log(`Cooldown skips: ${notificationSummary.cooldownSkipped}`);
    console.log(`Failed notifications: ${notificationSummary.failed}`);
  } else {
    console.log("Email notifications disabled by NOTIFICATIONS_ENABLED=false");
  }

  const reportPaths = writeSecurityReports(result);
  console.log("\n===== REPORTS =====");
  console.log(`JSON report: ${reportPaths.jsonPath}`);
  console.log(`Text summary: ${reportPaths.textPath}`);
}

main().catch((error: unknown) => {
  console.error("Fatal application error:");
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});

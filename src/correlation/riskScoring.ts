import type { Alert, Severity } from "../shared/alertTypes";

const BASE_SCORE: Record<Severity, number> = {
  LOW: 15,
  MEDIUM: 35,
  HIGH: 65,
  CRITICAL: 90
};

function sourcesForAlert(alert: Alert): string[] {
  const sources = new Set<string>();
  if (alert.sourceIp) sources.add(alert.sourceIp);
  for (const ip of alert.sourceIps ?? []) sources.add(ip);
  return Array.from(sources);
}

export function applyRiskScores(alerts: Alert[]): Alert[] {
  const alertCountByIp = new Map<string, number>();

  for (const alert of alerts) {
    for (const ip of sourcesForAlert(alert)) {
      alertCountByIp.set(ip, (alertCountByIp.get(ip) ?? 0) + 1);
    }
  }

  return alerts.map((alert) => {
    const sourceCounts = sourcesForAlert(alert).map((ip) => alertCountByIp.get(ip) ?? 1);
    const maxRelatedAlerts = sourceCounts.length > 0 ? Math.max(...sourceCounts) : 1;
    const repetitionBonus = Math.min(10, Math.max(0, maxRelatedAlerts - 1) * 2);
    const correlationBonus = alert.type === "ATTACK_CHAIN" ? 5 : 0;

    return {
      ...alert,
      riskScore: Math.min(100, BASE_SCORE[alert.severity] + repetitionBonus + correlationBonus)
    };
  });
}

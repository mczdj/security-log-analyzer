import type { Alert } from "../shared/alertTypes";

function alertSourceIps(alert: Alert): string[] {
  const ips = new Set<string>();
  if (alert.sourceIp) ips.add(alert.sourceIp);
  for (const ip of alert.sourceIps ?? []) ips.add(ip);
  return Array.from(ips);
}

export function correlateAttackChains(alerts: Alert[]): Alert[] {
  const alertsByIp = new Map<string, Alert[]>();

  for (const alert of alerts) {
    if (alert.type === "ATTACK_CHAIN") continue;

    for (const ip of alertSourceIps(alert)) {
      const group = alertsByIp.get(ip) ?? [];
      group.push(alert);
      alertsByIp.set(ip, group);
    }
  }

  const correlatedAlerts: Alert[] = [];

  for (const [ip, group] of alertsByIp) {
    const types = Array.from(new Set(group.map((alert) => alert.type)));

    if (types.length < 2) continue;

    correlatedAlerts.push({
      type: "ATTACK_CHAIN",
      severity: types.length >= 3 ? "CRITICAL" : "HIGH",
      sourceIp: ip,
      detectedAt: new Date().toISOString(),
      message: `Correlated attack chain detected from ${ip}: ${types.join(" -> ")}`,
      evidence: {
        alertCount: group.length,
        uniqueAttackTypes: types.length,
        alertTypes: types
      }
    });
  }

  return correlatedAlerts;
}

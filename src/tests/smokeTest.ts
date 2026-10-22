import { strict as assert } from "node:assert";
import { analyzeDefaultFiles } from "../core/analyze";

const result = analyzeDefaultFiles();
const types = new Set(result.alerts.map((alert) => alert.type));

assert.equal(result.stats.authentication.valid, 22, "Authentication regression count changed");
assert.ok(result.stats.web.valid >= 12, "Expected web sample entries");
assert.ok(result.stats.network.valid >= 10, "Expected network sample entries");
assert.ok(result.stats.arp.valid >= 4, "Expected ARP sample entries");

for (const requiredType of [
  "BRUTE_FORCE",
  "SQL_INJECTION",
  "XSS_ATTACK",
  "PATH_TRAVERSAL",
  "PORT_SCAN",
  "ARP_POISONING",
  "ATTACK_CHAIN"
]) {
  assert.ok(types.has(requiredType as never), `Missing expected alert type ${requiredType}`);
}

assert.ok(result.suspiciousIps.length > 0, "Expected suspicious IP summary");
assert.ok(result.alerts.every((alert) => typeof alert.riskScore === "number"), "Every alert needs a risk score");

console.log(`Smoke test passed: ${result.stats.totalEvents} events, ${result.stats.totalAlerts} alerts.`);

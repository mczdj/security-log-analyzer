import { useEffect, useMemo, useState } from "react";
import type { Alert, AnalysisResult, Severity } from "./types";

const severityOrder: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const logSources = ["authentication", "web", "network", "arp"] as const;
type LogSource = (typeof logSources)[number];

async function fetchJson<T>(url: string, options?: RequestInit): Promise<T> {
  const response = await fetch(url, options);
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `Request failed with ${response.status}`);
  }
  return response.json() as Promise<T>;
}

function App() {
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState<Severity | "ALL">("ALL");
  const [source, setSource] = useState<LogSource>("authentication");
  const [rawLog, setRawLog] = useState("");
  const [uploadMessage, setUploadMessage] = useState("");

  const loadReport = async () => {
    setLoading(true);
    setError("");
    try {
      const data = await fetchJson<AnalysisResult>("/api/report");
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load analyzer data");
    } finally {
      setLoading(false);
    }
  };

  const loadRawLog = async (nextSource: LogSource) => {
    setSource(nextSource);
    try {
      const data = await fetchJson<{ content: string }>(`/api/logs/${nextSource}`);
      setRawLog(data.content);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load log");
    }
  };

  useEffect(() => {
    void loadReport();
    void loadRawLog("authentication");
  }, []);

  const filteredAlerts = useMemo(() => {
    if (!result) return [];
    const needle = search.trim().toLowerCase();
    return result.alerts.filter((alert) => {
      const matchesSeverity = severity === "ALL" || alert.severity === severity;
      const haystack = [
        alert.type,
        alert.message,
        alert.sourceIp,
        ...(alert.sourceIps ?? []),
        alert.username
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return matchesSeverity && (!needle || haystack.includes(needle));
    });
  }, [result, search, severity]);

  const attackCounts = useMemo(() => {
    if (!result) return [];
    const counts = new Map<string, number>();
    for (const alert of result.alerts) counts.set(alert.type, (counts.get(alert.type) ?? 0) + 1);
    return Array.from(counts.entries())
      .map(([type, count]) => ({ type, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
  }, [result]);

  const maxAttackCount = Math.max(1, ...attackCounts.map((item) => item.count));

  const handleUpload = async (file: File | undefined) => {
    if (!file) return;
    setUploadMessage("Uploading...");
    try {
      const content = await file.text();
      await fetchJson("/api/logs/upload", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type: source, content })
      });
      setUploadMessage(`${source} log updated successfully.`);
      await Promise.all([loadReport(), loadRawLog(source)]);
    } catch (err) {
      setUploadMessage(err instanceof Error ? err.message : "Upload failed");
    }
  };

  if (loading && !result) {
    return <div className="center-state">Loading security telemetry…</div>;
  }

  if (!result) {
    return <div className="center-state error">{error || "No analysis data available."}</div>;
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div>
          <div className="brand-mark">SLA</div>
          <h1>Security Log Analyzer</h1>
          <p>Detection & correlation console</p>
        </div>
        <nav>
          <a href="#overview">Overview</a>
          <a href="#alerts">Alerts</a>
          <a href="#ips">Suspicious IPs</a>
          <a href="#logs">Raw Logs</a>
        </nav>
        <div className="sidebar-footer">
          <span className="status-dot" /> API connected
        </div>
      </aside>

      <main>
        <header className="topbar">
          <div>
            <p className="eyebrow">SECURITY OPERATIONS</p>
            <h2>Threat Overview</h2>
            <p className="muted">Last analysis: {new Date(result.generatedAt).toLocaleString()}</p>
          </div>
          <button className="primary" onClick={() => void loadReport()}>Refresh analysis</button>
        </header>

        {error && <div className="banner error">{error}</div>}

        <section id="overview" className="cards-grid">
          <MetricCard label="Events" value={result.stats.totalEvents} detail={`${result.stats.totalInvalidLogs} invalid`} />
          <MetricCard label="Alerts" value={result.stats.totalAlerts} detail="Across all sources" />
          <MetricCard label="High" value={result.stats.severityCounts.HIGH} detail="Needs attention" />
          <MetricCard label="Critical" value={result.stats.severityCounts.CRITICAL} detail="Immediate review" accent />
        </section>

        <section className="two-column">
          <div className="panel">
            <div className="panel-heading">
              <div>
                <p className="eyebrow">SEVERITY</p>
                <h3>Alert distribution</h3>
              </div>
            </div>
            <div className="severity-layout">
              <div
                className="donut"
                style={{
                  background: `conic-gradient(
                    #ff5d73 0 ${percent(result.stats.severityCounts.CRITICAL, result.stats.totalAlerts)}%,
                    #ff9f43 ${percent(result.stats.severityCounts.CRITICAL, result.stats.totalAlerts)}% ${percent(result.stats.severityCounts.CRITICAL + result.stats.severityCounts.HIGH, result.stats.totalAlerts)}%,
                    #ffd166 ${percent(result.stats.severityCounts.CRITICAL + result.stats.severityCounts.HIGH, result.stats.totalAlerts)}% ${percent(result.stats.severityCounts.CRITICAL + result.stats.severityCounts.HIGH + result.stats.severityCounts.MEDIUM, result.stats.totalAlerts)}%,
                    #59d6a2 0
                  )`
                }}
              >
                <span>{result.stats.totalAlerts}</span>
                <small>alerts</small>
              </div>
              <div className="legend">
                {severityOrder.map((item) => (
                  <div key={item}><span className={`legend-dot ${item.toLowerCase()}`} />{item}<strong>{result.stats.severityCounts[item]}</strong></div>
                ))}
              </div>
            </div>
          </div>

          <div className="panel">
            <div className="panel-heading">
              <div><p className="eyebrow">ATTACK TYPES</p><h3>Top detections</h3></div>
            </div>
            <div className="bar-chart">
              {attackCounts.map((item) => (
                <div className="bar-row" key={item.type}>
                  <span title={item.type}>{item.type.replaceAll("_", " ")}</span>
                  <div className="bar-track"><div className="bar-fill" style={{ width: `${(item.count / maxAttackCount) * 100}%` }} /></div>
                  <strong>{item.count}</strong>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section id="alerts" className="panel">
          <div className="panel-heading responsive-heading">
            <div><p className="eyebrow">DETECTIONS</p><h3>Security alerts</h3></div>
            <div className="filters">
              <input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search IP, user, attack…" />
              <select value={severity} onChange={(event) => setSeverity(event.target.value as Severity | "ALL")}>
                <option value="ALL">All severities</option>
                {severityOrder.map((item) => <option value={item} key={item}>{item}</option>)}
              </select>
            </div>
          </div>
          <div className="table-wrap">
            <table>
              <thead><tr><th>Severity</th><th>Detection</th><th>Source</th><th>Risk</th><th>Time</th></tr></thead>
              <tbody>
                {filteredAlerts.map((alert, index) => <AlertRow alert={alert} key={`${alert.type}-${alert.sourceIp ?? index}-${index}`} />)}
              </tbody>
            </table>
          </div>
        </section>

        <section id="ips" className="two-column">
          <div className="panel">
            <div className="panel-heading"><div><p className="eyebrow">RISK</p><h3>Suspicious IPs</h3></div></div>
            <div className="ip-list">
              {result.suspiciousIps.slice(0, 8).map((item) => (
                <div className="ip-item" key={item.ipAddress}>
                  <div><strong>{item.ipAddress}</strong><span>{item.alertTypes.slice(0, 3).join(" · ")}</span></div>
                  <div className="risk-badge">{item.maxRiskScore}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="panel timeline-panel">
            <div className="panel-heading"><div><p className="eyebrow">TIMELINE</p><h3>Recent activity</h3></div></div>
            <div className="timeline">
              {[...result.alerts]
                .sort((a, b) => new Date(b.eventTimestamp ?? b.detectedAt).getTime() - new Date(a.eventTimestamp ?? a.detectedAt).getTime())
                .slice(0, 8)
                .map((alert, index) => (
                  <div className="timeline-item" key={`${alert.type}-${index}`}>
                    <span className={`timeline-dot ${alert.severity.toLowerCase()}`} />
                    <div><strong>{alert.type.replaceAll("_", " ")}</strong><p>{alert.message}</p><small>{new Date(alert.eventTimestamp ?? alert.detectedAt).toLocaleString()}</small></div>
                  </div>
                ))}
            </div>
          </div>
        </section>

        <section id="logs" className="panel">
          <div className="panel-heading responsive-heading">
            <div><p className="eyebrow">LOG SOURCES</p><h3>Raw log viewer & upload</h3></div>
            <div className="filters">
              <select value={source} onChange={(event) => void loadRawLog(event.target.value as LogSource)}>
                {logSources.map((item) => <option key={item} value={item}>{item}</option>)}
              </select>
              <label className="upload-button">Replace {source} log<input type="file" accept=".log,.txt" onChange={(event) => void handleUpload(event.target.files?.[0])} /></label>
            </div>
          </div>
          {uploadMessage && <p className="upload-message">{uploadMessage}</p>}
          <pre className="log-viewer">{rawLog || "No log data."}</pre>
        </section>
      </main>
    </div>
  );
}

function MetricCard({ label, value, detail, accent = false }: { label: string; value: number; detail: string; accent?: boolean }) {
  return <div className={`metric-card ${accent ? "accent" : ""}`}><span>{label}</span><strong>{value}</strong><p>{detail}</p></div>;
}

function AlertRow({ alert }: { alert: Alert }) {
  return (
    <tr>
      <td><span className={`severity-pill ${alert.severity.toLowerCase()}`}>{alert.severity}</span></td>
      <td><strong>{alert.type.replaceAll("_", " ")}</strong><span className="table-message">{alert.message}</span></td>
      <td>{alert.sourceIp ?? alert.sourceIps?.join(", ") ?? "—"}</td>
      <td><span className="risk-number">{alert.riskScore ?? 0}</span></td>
      <td>{new Date(alert.eventTimestamp ?? alert.detectedAt).toLocaleString()}</td>
    </tr>
  );
}

function percent(value: number, total: number) {
  return total === 0 ? 0 : (value / total) * 100;
}

export default App;

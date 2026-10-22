import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { existsSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { extname, join, normalize } from "node:path";
import { analyzeDefaultFiles, analyzeLogBundle, loadDefaultLogBundle } from "../core/analyze";
import type { LogBundle, LogSource } from "../core/types";
import { processNotifications } from "../notification/notificationManager";
import { writeSecurityReports } from "../reporting/reportGenerator";

const PORT = Number(process.env.API_PORT ?? "3001");
const MAX_BODY_BYTES = 1_000_000;

function setCors(response: ServerResponse): void {
  response.setHeader("Access-Control-Allow-Origin", "*");
  response.setHeader("Access-Control-Allow-Headers", "Content-Type");
  response.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
}

function sendJson(response: ServerResponse, statusCode: number, data: unknown): void {
  setCors(response);
  response.writeHead(statusCode, { "Content-Type": "application/json; charset=utf-8" });
  response.end(JSON.stringify(data, null, 2));
}

function readBody(request: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk: string) => {
      body += chunk;
      if (Buffer.byteLength(body, "utf8") > MAX_BODY_BYTES) {
        reject(new Error("Request body exceeds 1 MB limit"));
        request.destroy();
      }
    });
    request.on("end", () => resolve(body));
    request.on("error", reject);
  });
}

function contentTypeFor(path: string): string {
  const extension = extname(path).toLowerCase();
  const types: Record<string, string> = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon"
  };
  return types[extension] ?? "application/octet-stream";
}

function serveDashboard(pathname: string, response: ServerResponse): boolean {
  const dashboardRoot = join(process.cwd(), "dashboard", "dist");
  if (!existsSync(dashboardRoot) || !statSync(dashboardRoot).isDirectory()) return false;

  const requested = pathname === "/" ? "/index.html" : pathname;
  const safeRelative = normalize(requested).replace(/^(\.\.[/\\])+/, "");
  let filePath = join(dashboardRoot, safeRelative);

  if (!filePath.startsWith(dashboardRoot)) return false;

  if (!existsSync(filePath) || statSync(filePath).isDirectory()) {
    filePath = join(dashboardRoot, "index.html");
  }

  if (!existsSync(filePath)) return false;

  response.writeHead(200, { "Content-Type": contentTypeFor(filePath) });
  response.end(readFileSync(filePath));
  return true;
}

function sourceFilePath(source: LogSource): string {
  return `./logs/${source}.log`;
}

async function handleApi(request: IncomingMessage, response: ServerResponse, pathname: string): Promise<void> {
  if (request.method === "OPTIONS") {
    setCors(response);
    response.writeHead(204);
    response.end();
    return;
  }

  if (request.method === "GET" && pathname === "/api/health") {
    sendJson(response, 200, { status: "ok", service: "security-log-analyzer" });
    return;
  }

  if (request.method === "GET" && pathname.startsWith("/api/logs/")) {
    const source = pathname.replace("/api/logs/", "") as LogSource;
    if (!["authentication", "web", "network", "arp"].includes(source)) {
      sendJson(response, 400, { error: "Invalid log source" });
      return;
    }
    const path = sourceFilePath(source);
    sendJson(response, 200, { source, content: existsSync(path) ? readFileSync(path, "utf8") : "" });
    return;
  }

  if (request.method === "GET" && ["/api/alerts", "/api/stats", "/api/suspicious-ips", "/api/report"].includes(pathname)) {
    const result = analyzeDefaultFiles();
    if (pathname === "/api/alerts") sendJson(response, 200, result.alerts);
    else if (pathname === "/api/stats") sendJson(response, 200, result.stats);
    else if (pathname === "/api/suspicious-ips") sendJson(response, 200, result.suspiciousIps);
    else sendJson(response, 200, result);
    return;
  }

  if (request.method === "POST" && pathname === "/api/analyze") {
    const body = await readBody(request);
    const payload = body ? (JSON.parse(body) as Partial<LogBundle> & { sendNotifications?: boolean }) : {};
    const defaults = loadDefaultLogBundle();
    const result = analyzeLogBundle({
      authenticationLogs: payload.authenticationLogs ?? defaults.authenticationLogs,
      webLogs: payload.webLogs ?? defaults.webLogs,
      networkLogs: payload.networkLogs ?? defaults.networkLogs,
      arpLogs: payload.arpLogs ?? defaults.arpLogs
    });

    let notificationSummary = null;
    if (payload.sendNotifications === true) {
      notificationSummary = await processNotifications(result.alerts);
    }

    writeSecurityReports(result);
    sendJson(response, 200, { ...result, notificationSummary });
    return;
  }

  if (request.method === "POST" && pathname === "/api/logs/upload") {
    const body = await readBody(request);
    const payload = JSON.parse(body) as { type?: LogSource; content?: string };

    if (!payload.type || !["authentication", "web", "network", "arp"].includes(payload.type)) {
      sendJson(response, 400, { error: "type must be authentication, web, network, or arp" });
      return;
    }

    if (typeof payload.content !== "string") {
      sendJson(response, 400, { error: "content must be a string" });
      return;
    }

    writeFileSync(sourceFilePath(payload.type), payload.content, "utf8");
    const result = analyzeDefaultFiles();
    writeSecurityReports(result);
    sendJson(response, 200, { message: `${payload.type} log updated`, result });
    return;
  }

  sendJson(response, 404, { error: "API route not found" });
}

export function startApiServer(): void {
  const server = createServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);

      if (url.pathname.startsWith("/api/")) {
        await handleApi(request, response, url.pathname);
        return;
      }

      if (serveDashboard(url.pathname, response)) return;

      sendJson(response, 404, {
        error: "Dashboard not built. Run npm run dashboard:build, or use the /api endpoints."
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Unknown server error";
      sendJson(response, 500, { error: message });
    }
  });

  server.listen(PORT, () => {
    console.log(`Security Log Analyzer API running on http://localhost:${PORT}`);
  });
}

if (require.main === module) {
  startApiServer();
}

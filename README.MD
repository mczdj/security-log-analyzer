# 🛡️ Security Log Analyzer

A modular TypeScript security monitoring platform that parses multiple log sources, validates events, detects suspicious behavior, correlates attacks across domains, scores risk, generates reports, exposes an API, sends email alerts, and provides a React security dashboard.

> **Status:** All 12 planned implementation phases are complete. The repository includes sample authentication, web, network, and ARP logs for testing.

## ✅ Project Progress

| Phase | Module | Status |
|---|---|---|
| 1 | Basic TypeScript Log Parser | ✅ Complete |
| 2 | Log Validation | ✅ Complete |
| 3 | Authentication Attack Detection | ✅ Complete |
| 4 | Modular TypeScript Architecture | ✅ Complete |
| 5 | Structured Alerts & Email Notifications | ✅ Complete |
| 6 | Web Attack Detection | ✅ Complete |
| 7 | Network Attack Detection | ✅ Complete |
| 8 | ARP Poisoning Detection | ✅ Complete |
| 9 | Detection, Correlation & Risk Scoring | ✅ Complete |
| 10 | Security Reports / JSON Output | ✅ Complete |
| 11 | Backend API | ✅ Complete |
| 12 | React Security Dashboard | ✅ Complete |

```text
Authentication ─┐
Web ─────────────┤
Network ─────────┼─→ Detection Engines ─→ Alert[] ─→ Correlation ─→ Risk Score
ARP ─────────────┘                                      │
                                                       ├─→ Yahoo Email
                                                       ├─→ JSON/Text Reports
                                                       ├─→ HTTP API
                                                       └─→ React Dashboard
```

## 🔎 Detection Capabilities

### Authentication
- Brute-force login attempts
- Password spraying
- Distributed account attacks
- Successful login after repeated failures
- Suspicious privileged-account logins

### Web
- SQL injection
- Cross-site scripting (XSS)
- Path traversal
- Suspicious HTTP methods
- High request rates
- Repeated 403/404 resource enumeration

### Network
- Port scanning
- Rapid connection activity
- Suspicious service/port access
- Protocol anomalies
- DNS anomalies
- DoS-like connection bursts

### ARP
- IP-to-MAC mapping changes
- Gateway mapping changes receive critical severity

### Correlation
- Same-source alerts are correlated into attack chains
- Alerts receive a 0–100 risk score
- Suspicious IPs are ranked by alert count, severity, and maximum risk

## 📁 Architecture

```text
security-log-analyzer/
├── logs/
│   ├── authentication.log
│   ├── web.log
│   ├── network.log
│   └── arp.log
├── src/
│   ├── authentication/
│   ├── web/
│   ├── network/
│   ├── arp/
│   ├── correlation/
│   ├── core/
│   ├── notification/
│   ├── reporting/
│   ├── api/
│   ├── shared/
│   ├── tests/
│   └── index.ts
├── dashboard/
│   ├── src/
│   ├── package.json
│   └── vite.config.ts
├── reports/                 # generated locally
├── .env.example
├── package.json
├── tsconfig.json
└── README.MD
```

## ⚙️ Requirements

- Node.js 20.19+ or 22.12+ recommended for the Vite dashboard
- npm
- Yahoo account + App Password only if email notifications are required

## 🚀 Installation

Clone the repository and enter it:

```bash
git clone https://github.com/mczdj/security-log-analyzer.git
cd security-log-analyzer
```

Install backend/analyzer dependencies:

```bash
npm install
```

Create `.env` from `.env.example`:

```env
EMAIL_USER=your-yahoo-email@yahoo.com
EMAIL_APP_PASSWORD=your-yahoo-app-password
ALERT_EMAIL=recipient@example.com
NOTIFICATION_COOLDOWN_MINUTES=10
NOTIFICATIONS_ENABLED=true
API_PORT=3001
```

Never commit `.env`.

## 🧪 Build and Test

Compile the TypeScript project:

```bash
npm run build
```

Run the automated smoke test:

```bash
npm test
```

The smoke test analyzes the bundled logs without sending email and verifies that authentication, web, network, ARP, correlation, and risk scoring are working.

## ▶️ Run the Analyzer

```bash
npm run build
npm run analyze
```

To test the CLI without sending email, set `NOTIFICATIONS_ENABLED=false` in `.env`.

The CLI:
- analyzes all four log sources
- displays invalid logs
- displays security alerts and risk scores
- ranks suspicious IPs
- sends one combined HIGH/CRITICAL email when required
- generates reports

Generated reports:

```text
reports/security-report.json
reports/security-summary.txt
```

## 📧 Email Notifications

The notification manager:
- sends only HIGH and CRITICAL alerts
- combines multiple alerts into one summary email
- fingerprints alerts with SHA-256
- suppresses exact duplicates
- applies a configurable cooldown to related alerts
- stores local notification history in `.notification-state.json`

`.notification-state.json` and `.env` are excluded from Git.

## 🌐 API

Build first:

```bash
npm run build
```

Start the API:

```bash
npm run start
```

Default address:

```text
http://localhost:3001
```

### Endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Service health |
| GET | `/api/alerts` | Current alerts |
| GET | `/api/stats` | Event and severity statistics |
| GET | `/api/suspicious-ips` | Ranked suspicious IPs |
| GET | `/api/report` | Complete analysis result |
| GET | `/api/logs/:type` | Raw log content |
| POST | `/api/analyze` | Analyze provided/default log content |
| POST | `/api/logs/upload` | Replace a local log source and re-analyze |

Supported log types:

```text
authentication
web
network
arp
```

Example POST `/api/analyze` body:

```json
{
  "webLogs": "2026-10-15 22:30:01 HTTP_REQUEST method=GET path=/ status=200 ip=192.168.1.10",
  "sendNotifications": false
}
```

## 🖥️ React Dashboard

Install dashboard dependencies:

```bash
npm run dashboard:install
```

### Development mode

Terminal 1:

```bash
npm run build
npm run start
```

Terminal 2:

```bash
npm run dashboard:dev
```

Open:

```text
http://localhost:5173
```

### Production-style local run

Build the dashboard:

```bash
npm run dashboard:build
```

Then start the API:

```bash
npm run start
```

Open:

```text
http://localhost:3001
```

The API serves `dashboard/dist` automatically when it exists.

### Dashboard Features

- Event/alert summary cards
- Severity visualization
- Attack-type chart
- Searchable alert table
- Severity filtering
- Risk scores
- Suspicious-IP ranking
- Alert timeline
- Raw log viewer
- Authentication/web/network/ARP source selector
- `.log` file upload/replacement
- Responsive layout

## 📊 Risk Scoring

Base scores:

| Severity | Base score |
|---|---:|
| LOW | 15 |
| MEDIUM | 35 |
| HIGH | 65 |
| CRITICAL | 90 |

Repeated activity from the same source and correlated attack chains can increase the score up to 100.

## 🧠 Correlation Example

A single IP appearing in several domains can produce an `ATTACK_CHAIN` alert:

```text
Brute force
    ↓
SQL injection
    ↓
Port scan
    ↓
Correlated CRITICAL attack chain
```

The bundled samples intentionally include cross-domain activity for testing this behavior.

## 🔐 Security Notes

This project is intended for defensive cybersecurity learning and authorized monitoring environments.

Do not commit:
- `.env`
- email App Passwords
- private production logs
- credentials or API keys
- `.notification-state.json`

Real-world logs should be sanitized before sharing or committing.

## 🛠️ Main Technologies

- TypeScript / Node.js
- Nodemailer + Yahoo SMTP
- Node built-in HTTP API server
- React
- Vite
- Git / GitHub

## 🧭 Useful Commands

```bash
npm install
npm run build
npm test
npm run analyze
npm run start
npm run dashboard:install
npm run dashboard:dev
npm run dashboard:build
npm run build:all
```

## 📜 License

MIT License. See `LICENSE`.

## 🔮 Optional Future Enhancement

Telegram mobile notifications can be added later by reusing the existing `Alert[]`, severity, deduplication, and cooldown pipeline.

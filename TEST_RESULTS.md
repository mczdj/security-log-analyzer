# Local Verification Results

The completed source was validated in the build environment on 2026-10-22.

## Backend / analyzer

- TypeScript type check: PASS
- TypeScript build: PASS
- Smoke test: PASS
- Sample events analyzed: 59 valid events
- Invalid sample logs handled: 15
- Alerts generated: 26
- Severity summary: 7 MEDIUM, 14 HIGH, 5 CRITICAL

Verified alert families include:

- Authentication: brute force, password spray, distributed account attack, success after failures
- Web: SQL injection, XSS, path traversal, suspicious HTTP methods, high request rate, enumeration
- Network: port scan, rapid connections, suspicious ports, protocol anomaly, DNS anomaly, DoS-like activity
- ARP: ARP poisoning / mapping change
- Correlation: cross-domain ATTACK_CHAIN
- Risk scoring: every alert receives a numeric score

## Reporting

- JSON report generation: PASS
- Text summary generation: PASS

## API

- `GET /api/health`: PASS
- `GET /api/stats`: PASS
- `POST /api/analyze` with notifications disabled: PASS
- Static dashboard serving behavior: PASS using a temporary built-file fixture

## Dashboard

The React source was syntax/type-checked with local React type shims because external npm installation is unavailable in the build environment. The actual Vite production build still needs to be run after `npm run dashboard:install` on the target machine.

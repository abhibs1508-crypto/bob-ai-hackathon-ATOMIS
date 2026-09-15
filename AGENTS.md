# AGENTS.md — CyberFusion Development Guide

> **This file governs all AI-assisted and human development on the CyberFusion project.**
> Every agent session, every pull request, and every code change must comply with
> the rules and conventions documented here.

---

## 1. Project Identity

| Field | Value |
|---|---|
| **Project name** | CyberFusion |
| **Type** | AI-powered Threat Intelligence Correlation & Alert Prioritisation Assistant |
| **Repository** | IBM BoB AI Hackathon submission template — ATOMIS team |
| **IBM BoB** | Primary development environment |
| **Target audience** | Defence / security analysts |

---

## 2. Repository Rules (CRITICAL — do not violate)

1. **Do not delete IBM-provided files.**
   The following files are part of the official hackathon template and must not be
   removed or renamed:
   - `README.md`
   - `submission.yaml`
   - `CONTRIBUTING.md`
   - `.gitignore`
   - `.github/workflows/validate.yml`
   - `docs/problem-statement.md`
   - `docs/solution-overview.md`
   - `docs/architecture.md`
   - `docs/setup-guide.md`
   - `docs/template-guide.md`
   - `demo/demo-video-link.txt`
   - `demo/live-demo-url.txt`
   - `demo/screenshots/README.md`
   - `presentation/README.md`
   - `src/README.md`
   - `src/.env.example`

2. **All CyberFusion source code lives under `src/`.**
   The directory layout outside `src/` is fixed by the IBM template.

3. **Never create a second repository.** The entire project — frontend, backend, AI service,
   database schema, seed data, and documentation — must remain in this repository.

4. **Never commit a `.env` file.** The `.gitignore` already excludes it. Use
   `src/.env.example` to document all required environment variables.

5. **Never hardcode secrets, API keys, or database credentials.** Use `process.env.*`
   with `dotenv` on the backend. Use `import.meta.env.VITE_*` on the frontend
   (non-secret config only).

6. **Do not modify `.github/workflows/validate.yml`.** The evaluation pipeline depends
   on it and ignores modifications.

---

## 3. Approved Project Structure

```
bob-ai-hackathon-ATOMIS/
│
├── submission.yaml             ← IBM template — fill required fields
├── README.md                   ← IBM template — fill CyberFusion content
├── CONTRIBUTING.md             ← IBM template — do not modify
├── AGENTS.md                   ← This file
├── .gitignore                  ← IBM template — do not modify
│
├── docs/
│   ├── architecture.md         ← CyberFusion architecture (completed)
│   ├── problem-statement.md    ← Fill with CyberFusion problem context
│   ├── solution-overview.md    ← Fill with CyberFusion solution description
│   ├── setup-guide.md          ← Fill with exact run instructions
│   └── template-guide.md       ← IBM template — do not modify
│
├── demo/
│   ├── screenshots/            ← Add 01-*.png 02-*.png 03-*.png after UI complete
│   ├── demo-video-link.txt     ← Add real video URL before submission
│   └── live-demo-url.txt       ← Add deployed URL or "NOT DEPLOYED"
│
├── presentation/               ← Add slides.pdf before submission
│
└── src/                        ← ALL source code
    ├── .env.example            ← CyberFusion env var template (updated)
    ├── README.md               ← IBM template — update src layout description
    │
    ├── backend/                ← Node.js / Express API
    │   ├── package.json
    │   └── src/
    │       ├── index.js        ← Express entry point
    │       ├── routes/         ← Route handlers
    │       │   ├── ingest.js
    │       │   ├── threats.js
    │       │   └── dashboard.js
    │       ├── services/
    │       │   ├── ingestion/  ← Ingest service
    │       │   ├── normalization/ ← Normalizer + NormalizedThreatEvent schema
    │       │   ├── correlation/   ← Deterministic correlation rules
    │       │   ├── risk/          ← Weighted risk scoring + risk.config.js
    │       │   └── ai/            ← AI abstraction + provider adapters
    │       ├── db/             ← MySQL connection pool + query helpers
    │       └── middleware/     ← Error handler, CORS, validation helpers
    │
    ├── frontend/               ← React + Vite + Tailwind CSS
    │   ├── package.json
    │   ├── vite.config.js
    │   ├── tailwind.config.js
    │   └── src/
    │       ├── main.jsx
    │       ├── App.jsx
    │       ├── api/            ← Axios client + API call functions
    │       ├── components/     ← Reusable UI components
    │       └── pages/          ← Dashboard page(s)
    │
    ├── database/
    │   └── schema.sql          ← MySQL DDL (completed)
    │
    └── data/
        └── seeds/
            └── demo-scenarios.js ← Demo scenario data (completed)
```

---

## 4. Technology Stack

| Layer | Technology | Version |
|---|---|---|
| Frontend framework | React | 18.x |
| Frontend build tool | Vite | 5.x |
| Frontend styling | Tailwind CSS | 3.x |
| Correlation visualisation | React Flow (react-flow-renderer) | 10.x |
| Metrics charting | Recharts | 2.x |
| HTTP client (frontend) | Axios | 1.x |
| Backend runtime | Node.js | ≥18 |
| Backend framework | Express.js | 4.x |
| Backend validation | express-validator | 7.x |
| Database | MySQL | 8.x |
| MySQL driver | mysql2 | 3.x |
| AI provider (primary) | IBM watsonx.ai — Granite model | via REST API |
| AI provider (fallback) | OpenAI GPT-4o | via REST API |
| AI provider (offline) | Mock provider | built-in |
| Secret management | dotenv | 16.x |
| Backend test runner | Jest + Supertest | 29.x |
| Frontend test runner | Vitest | 1.x |

---

## 5. API Contract

All backend routes are prefixed with `/api`.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/ingest` | Ingest one or more threat events |
| `GET` | `/api/dashboard` | Priority-ordered alert list with risk scores |
| `GET` | `/api/threats` | List all correlations (paginated) |
| `GET` | `/api/threats/:id` | Full correlation detail + risk breakdown + AI report |
| `POST` | `/api/threats/:id/analyse` | Trigger AI analysis for a correlation |
| `GET` | `/api/health` | Liveness check — returns `{ status: "ok", ai_available: bool }` |

### NormalizedThreatEvent schema

```js
{
  event_id:        String,  // required, unique source identifier
  source:          String,  // required: "siem" | "sensor" | "ti_feed" | "report"
  timestamp:       String,  // required, ISO 8601
  event_type:      String,  // required: "port_scan" | "failed_login" | "ioc_match" | ...
  source_ip:       String | null,
  target:          String | null,
  indicator_type:  String | null,  // "ip" | "domain" | "hash" | "url"
  indicator_value: String | null,
  severity:        String,  // required: "low" | "medium" | "high" | "critical"
  confidence:      Number,  // 0–100
  location:        String | null,
  raw_data:        Object | null,
}
```

---

## 6. Development Conventions

### General

- **Minimal change principle.** Every changed line must trace to a concrete requirement.
  Do not add features, refactors, or abstractions beyond what is asked.
- **Testable units.** Service modules (ingestion, normalization, correlation, risk, AI)
  must be pure functions or have injectable dependencies so they can be unit-tested
  without a running MySQL instance.
- **No unnecessary placeholder files.** Do not create empty `index.js` files, blank
  README stubs in every subdirectory, or TODO comments in code unless the comment
  describes a specific known gap.
- **No microservices.** The backend is a single Express process. Do not introduce
  message buses, gRPC, or service meshes.

### Backend conventions

- Use `require`/`module.exports` (CommonJS) throughout the backend.
- Database queries go in `src/backend/src/db/` helper functions — not inline in route handlers.
- Route handlers must not contain business logic. They call service functions and
  return the result.
- All service functions must return plain objects or throw typed errors.
- Use `express-validator` for request validation. Call `validationResult(req)` at the
  top of every route that accepts input.
- Errors returned to the client must never include stack traces or SQL text.
  Use a centralised error handler middleware in `src/backend/src/middleware/errorHandler.js`.
- Environment variables must be accessed through a single config module
  (`src/backend/src/config.js`), not scattered `process.env.*` calls.

### Frontend conventions

- Use ESM (`import`/`export`) throughout the frontend.
- One top-level page component: `src/frontend/src/pages/Dashboard.jsx`.
  Do not create multiple dashboard pages.
- All API calls go through `src/frontend/src/api/client.js` — no inline `fetch` or
  `axios` calls in components.
- Tailwind utility classes are the only styling mechanism. Do not introduce CSS
  modules, styled-components, or additional CSS-in-JS.
- The dashboard must show an appropriate state when the AI service is unavailable —
  do not hide the panel; render an "AI analysis unavailable" placeholder.

### Database conventions

- All schema changes go in `src/database/schema.sql`. Use `CREATE TABLE IF NOT EXISTS`.
- All queries use parameterised placeholders (`?`) — never string interpolation.
- The connection pool is created once in `src/backend/src/db/pool.js` and imported
  everywhere else.

### AI service conventions

- The AI provider is selected by `AI_PROVIDER` environment variable.
- Each provider is implemented as a separate adapter module in
  `src/backend/src/services/ai/providers/`.
- The service abstraction (`aiService.js`) exports `analyzeThreat(correlationContext)`
  which calls the configured provider and validates the response.
- If the provider returns a response missing the `bluf` field, treat it as failed and
  return `null` — never pass an incomplete report to the client.
- The mock provider must return a structurally valid `IntelligenceReport` with clearly
  labelled mock data so it is obvious in demos when the AI service is offline.

### Correlation engine conventions

- Correlation rules are deterministic and documented. Add a JSDoc comment to every
  rule function explaining what it detects and why.
- Each rule must return `{ fired: boolean, factor: string, reason: string }`.
- The correlation engine must not call the AI service. Correlation is deterministic.
- The correlation key is a stable hash of the grouping criteria (e.g., source_ip +
  target) so that re-running correlation on the same events is idempotent.

### Risk engine conventions

- The risk score calculation is a pure function:
  `calculateRiskScore(events, matchedIndicators, entity, correlationFactors) → RiskScore`.
- Weights are read from a `risk.config.js` file that reads `process.env.RISK_WEIGHT_*`
  with numeric defaults.
- The function must return an object with all five component scores and the total —
  not just the final number — so the UI can display the breakdown.

---

## 7. Security Rules (non-negotiable)

1. No secret in source code, ever. This includes API keys, passwords, tokens, and
   private URLs.
2. No `.env` file committed. Verify with `git status` before every commit.
3. All AI calls are backend-only. No AI API key reaches the browser.
4. Validate every inbound API payload. Reject before processing.
5. Validate every AI response. Never trust provider output blindly.
6. Database errors stay server-side. Return generic HTTP 500 to clients.
7. The only build-time env var exposed to the frontend is `VITE_API_BASE_URL`.

---

## 8. Demonstration Scenarios

Two scenarios must be reproducible at any time using the demo seed data
(`src/data/seeds/demo-scenarios.js`):

### Scenario A — CRITICAL: Coordinated Reconnaissance + Credential Attack

Expected pipeline output:
- 4 events ingested: port scan → failed SSH login → failed MySQL login → IOC match
- Correlation: all 4 events grouped (shared source IP + target + IOC match + event chain)
- Risk score: ≥81 → CRITICAL
- AI BLUF generated
- Dashboard shows CRITICAL alert at top of priority queue with full evidence and BLUF

### Scenario B — LOW: Isolated Probe on Non-Critical Host

Expected pipeline output:
- 1 event ingested: light port scan against dev-test-07.internal
- No correlation (no related events)
- Risk score: ≤30 → LOW (no IOC match, low asset criticality, single event)
- No AI analysis triggered
- Dashboard shows LOW alert — demonstrates false-positive suppression

---

## 9. Implementation Order (Recommended)

Follow this order to maintain a working end-to-end pipeline at each step:

1. **Database layer** — `src/database/schema.sql` + `src/backend/src/db/pool.js`
2. **Normalization service** — `NormalizedThreatEvent` schema, field-mapping logic, unit tests
3. **Correlation engine** — 5 deterministic rules, idempotent correlation key, unit tests
4. **Risk scoring** — weighted formula, `risk.config.js`, pure function, unit tests
5. **AI service abstraction** — mock provider first; watsonx adapter second
6. **Backend routes** — ingest, threats, dashboard, health
7. **Seed script** — wire `demo-scenarios.js` to the ingestion service
8. **Frontend dashboard** — priority queue, threat detail, risk gauge, BLUF panel
9. **Correlation graph** — React Flow visualisation of correlated events
10. **Submission docs** — README, submission.yaml, problem-statement.md,
    solution-overview.md, setup-guide.md

---

## 10. What NOT to Build

- Authentication / login system (noted as known limitation)
- Multi-page routing (one dashboard page only)
- Microservices / separate deployable services
- Real-time WebSocket streaming (polling is sufficient for the prototype)
- Docker / Kubernetes infrastructure
- Features unrelated to the threat correlation pipeline
- Any dashboard page that is not the analyst threat queue

---

## 11. Validation Checklist (run before each commit)

- [ ] No `.env` file in working tree (`git status`)
- [ ] No hardcoded credentials in changed files (`grep -r "password\|api_key\|secret" src/`)
- [ ] Backend unit tests pass (`cd src/backend && npm test`)
- [ ] Frontend lints cleanly (`cd src/frontend && npm run lint`)
- [ ] `submission.yaml` required fields are non-empty
- [ ] `README.md` contains no `[placeholder]` text
- [ ] `docs/architecture.md` matches actual implementation
- [ ] `docs/setup-guide.md` reflects actual run commands
- [ ] GitHub Actions **Validate Submission** would pass

---

*Last updated: architecture initialisation phase*
*Next milestone: database layer + normalization service implementation*

# Phase 6 — REST API Layer: Intelligence Endpoints

## Overview

Phase 6 adds the `/api/intelligence` REST endpoints that expose the AI Intelligence Service
(Phase 5) to consumers — primarily the React dashboard (Phase 7).

The routes are implemented in [`src/backend/src/routes/intelligence.js`](../src/backend/src/routes/intelligence.js)
and registered in [`src/backend/src/app.js`](../src/backend/src/app.js) under the `/api/intelligence` prefix.

---

## Endpoints

### `POST /api/intelligence/generate/:correlationId`

Triggers the full AI intelligence pipeline for one correlation:

1. Loads the correlation and its risk score from the database.
2. Assembles the `IntelligenceContext` (events, indicators, entities).
3. Calls the configured AI provider (Groq or fallback).
4. Parses and validates the response via guardrails.
5. Persists the result via `intelligenceRepository.upsert()` (idempotent).
6. Returns the persisted report.

**Path parameter**

| Parameter | Type | Constraint |
|-----------|------|-----------|
| `correlationId` | string | Valid UUID v4 |

**Success response — 201 Created**

```json
{
  "success": true,
  "message": "Intelligence report generated",
  "data": {
    "report": {
      "id": "<uuid>",
      "correlation_id": "<uuid>",
      "bluf": "CRITICAL: ...",
      "threat_assessment": "...",
      "possible_intent": "...",
      "reasoning": "...",
      "evidence_summary": "...",
      "recommended_actions": ["...", "..."],
      "ai_provider": "groq",
      "ai_model": "openai/gpt-oss-120b",
      "confidence_score": 85,
      "generated_at": "2025-01-01T00:00:00.000Z"
    }
  }
}
```

**Error responses**

| Status | Condition |
|--------|-----------|
| 400 | `correlationId` is not a valid UUID |
| 404 | Correlation or its risk score does not exist |
| 500 | Unexpected server error |

> If the AI provider is unavailable the service returns a deterministic
> fallback report (still `201`) — the application never fails because AI is down.

---

### `GET /api/intelligence/correlation/:correlationId`

Returns the most recent intelligence report for a given correlation UUID.
Does **not** trigger AI generation — read-only.

**Path parameter**

| Parameter | Type | Constraint |
|-----------|------|-----------|
| `correlationId` | string | Valid UUID v4 |

**Success response — 200 OK**

```json
{
  "success": true,
  "data": {
    "report": { ... }
  }
}
```

**Error responses**

| Status | Condition |
|--------|-----------|
| 400 | `correlationId` is not a valid UUID |
| 404 | No report exists for this correlation |

---

### `GET /api/intelligence/:id`

Returns a single intelligence report by its own primary-key UUID
(`intelligence_reports.id`).

**Path parameter**

| Parameter | Type | Constraint |
|-----------|------|-----------|
| `id` | string | Valid UUID v4 |

**Success response — 200 OK**

```json
{
  "success": true,
  "data": {
    "report": { ... }
  }
}
```

**Error responses**

| Status | Condition |
|--------|-----------|
| 400 | `id` is not a valid UUID |
| 404 | Report does not exist |

---

## Route Registration Order

```
app.use('/api/intelligence', intelligenceRouter);
```

Inside the router, the **static** sub-path `/correlation/:correlationId` is
registered **before** the dynamic `/:id` catch-all.  This prevents Express
from treating the literal string `"correlation"` as a report UUID.

```
POST /generate/:correlationId     ← action route
GET  /correlation/:correlationId  ← static prefix FIRST
GET  /:id                         ← dynamic catch-all SECOND
```

---

## Security Notes

- All UUID parameters are validated by `express-validator` before they reach
  service or database code.
- `IntelligenceServiceError` carries an explicit `statusCode`; only the message
  is forwarded to the client — no stack traces or internal details.
- Unexpected errors fall through to the centralized `errorHandler` middleware
  which returns `{ success: false, message: "Internal server error" }` with no
  stack information in production.
- The `GROQ_API_KEY` is read only on the server side (via `config.js`); it is
  never included in any API response.

---

## Testing

Integration tests are in
[`src/backend/tests/integration/intelligence.test.js`](../src/backend/tests/integration/intelligence.test.js).

The test file mocks:
- `intelligenceService.generateIntelligence` — no live AI calls
- `intelligenceRepository.findByCorrelationId` — no DB connection needed
- `pool.getPool().execute` — covers the inline query in `GET /:id`

Test coverage:
- `POST /generate/:correlationId` — success, bad UUID, 404 (correlation), 404 (risk), 400 (service), 500
- `GET /correlation/:correlationId` — success, 404, bad UUID, DB error
- Route ordering — "correlation" sub-path not captured by `/:id`
- `GET /:id` — success (with JSON parse of `recommended_actions`), 404, bad UUID, DB error

Run with:

```bash
cd src/backend
npm test -- --testPathPattern=intelligence
```

---

## Database Migration

The `intelligence_reports` table is created by:

```
src/database/migrate-phase5.sql
```

Apply after `schema.sql`, `migrate-phase3.sql`, and `migrate-phase4.sql`.

Key constraints:

- `UNIQUE KEY uq_intelligence_correlation (correlation_id)` — one report per
  correlation, enforced at the DB level; application uses `ON DUPLICATE KEY UPDATE`.
- `FOREIGN KEY (correlation_id) REFERENCES correlations(id) ON DELETE CASCADE` —
  deleting a correlation removes its report.
- `recommended_actions` stored as `LONGTEXT` JSON array; deserialized in the
  repository `deserialise()` helper.

---

## Health Endpoint

`GET /api/health` now accurately reports AI provider availability:

```json
{
  "status": "ok",
  "database": "connected",
  "ai_available": true,
  "ai_provider": "groq",
  "timestamp": "2025-01-01T00:00:00.000Z"
}
```

- `ai_available` is `true` when `AI_PROVIDER=groq` and `GROQ_API_KEY` is set.
- `ai_provider` is the configured provider name (`"groq"`) or `null` when unavailable.
- The API key is **never** included in the response.

---

## Phase 6B Verification Summary

| Check | Result |
|-------|--------|
| Backend starts | PASS |
| `GET /api/health` | PASS (`status: ok`, `database: connected`, `ai_available: true`) |
| `GET /api/intelligence/correlation/:id` | PASS (200, full report fields) |
| `GET /api/intelligence/:id` | PASS (200, JSON-parsed recommended_actions) |
| `POST /api/intelligence/generate/:id` | PASS (201, groq provider, confidence 92) |
| Real Groq pipeline | PASS (provider: groq, model: openai/gpt-oss-120b) |
| Guardrails | PASS |
| Idempotency | PASS (same report id on repeat calls, count = 1) |
| Invalid UUID → 400 | PASS |
| Nonexistent correlation → 404 | PASS |
| Nonexistent report → 404 | PASS |
| Route ordering `/correlation/` before `/:id` | PASS |
| Response safety (no secrets/prompts/keys) | PASS |
| Correlation score = 77 / very_strong | PASS |
| Risk score = 81 / critical | PASS |
| Jest suite: 13 suites / 259 tests / 0 failures | PASS |

---

## Completed Phase 6 Checklist

- [x] `src/backend/src/routes/intelligence.js` created
- [x] Router registered in `src/backend/src/app.js`
- [x] `src/database/migrate-phase5.sql` created
- [x] `src/backend/tests/integration/intelligence.test.js` created
- [x] `docs/phase-6-api.md` created
- [x] Route ordering verified (static before dynamic)
- [x] All test mocks avoid real DB / real AI calls
- [x] No secrets in source code
- [x] No business logic in route handlers
- [x] `GET /api/health` updated to report actual AI provider status (Phase 6B)
- [x] All Phase 6B verification checks passed

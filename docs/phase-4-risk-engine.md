# CyberFusion — Phase 4: Risk & Priority Engine

> **Status:** Implemented  
> **Phase:** 4 — Risk & Priority Engine  
> **Depends on:** Phase 2 (Ingestion/Normalization), Phase 3 (Correlation Engine)

---

## 1. Purpose

Phase 4 answers the analyst's second key question:

> *How dangerous is this correlated threat cluster, and does it require immediate action?*

It converts a Phase 3 correlation into an **explainable 0–100 risk score**, a **priority classification** (low/medium/high/critical), and an **actionable alert**.

The engine is:
- **Deterministic** — identical input always produces identical output
- **Explainable** — every factor contributes a named score with a human-readable reason
- **Idempotent** — re-evaluating the same correlation updates rather than duplicates
- **Separated from correlation** — Phase 3 measures relationship strength; Phase 4 measures danger level

**No AI, no LLM.** All risk calculation is rule-based and fully inspectable.

---

## 2. Architecture

```
Route Handler
     ↓
riskService.evaluateCorrelation(correlationId)
     ↓
  loadCorrelation()          — FROM correlations (Phase 3 output)
  loadEventsByCorrelation()  — FROM threat_events via correlation_events
  loadMatchedIndicators()    — FROM indicators table
  loadTargetEntities()       — FROM entities table
     ↓
RiskContext { correlation, events, matchedIndicators, targetEntities }
     ↓
riskEngine.runRiskEngine(ctx)    ← PURE FUNCTION, no I/O
  ├── calcSeverity()
  ├── calcIocRisk()
  ├── calcAssetCriticality()
  ├── calcCorrelationStrength()
  ├── calcRecency()
  ├── calcAttackProgression()
  └── calcCrossSource()
     ↓
RiskResult { score, priority, components, riskEvidence }
     ↓
riskRepository.upsertRiskScore()   — risk_scores table
     ↓
alertService.ensureAlert()         — alerts table (idempotent)
     ↓
Response to client
```

**File layout:**
```
src/backend/src/services/risk/
├── riskConfig.js            — all weights, thresholds, half-lives (env-overridable)
├── riskEngine.js            — pure orchestrator; runs all 7 factors
├── riskFactors.js           — 7 factor calculator functions (pure)
├── priorityClassifier.js    — score → low/medium/high/critical
├── riskEvidence.js          — structured JSON evidence builder
├── riskService.js           — DB orchestration + public API
└── alertService.js          — idempotent alert create/update

src/backend/src/db/
└── riskRepository.js        — SQL for risk_scores + alerts (parameterized)

src/database/
└── migrate-phase4.sql       — ADD COLUMN risk_evidence to risk_scores
```

---

## 3. Risk Model

### Formula

```
score = round(
  severity            × 0.20  +
  iocRisk             × 0.20  +
  assetCriticality    × 0.20  +
  correlationStrength × 0.20  +
  recency             × 0.10  +
  attackProgression   × 0.05  +
  crossSource         × 0.05
)
```

Clamped to **0–100** after rounding. All factor weights sum to 1.0.

### Factor weights (default, env-overridable)

| Factor | Weight | Env var |
|---|---|---|
| Severity | 20% | `RISK_W_SEVERITY` |
| IOC Risk | 20% | `RISK_W_IOC_RISK` |
| Asset Criticality | 20% | `RISK_W_ASSET_CRITICALITY` |
| Correlation Strength | 20% | `RISK_W_CORRELATION_STRENGTH` |
| Recency | 10% | `RISK_W_RECENCY` |
| Attack Progression | 5% | `RISK_W_ATTACK_PROGRESSION` |
| Cross-Source | 5% | `RISK_W_CROSS_SOURCE` |

### Priority thresholds

| Score | Priority |
|---|---|
| 75–100 | `critical` |
| 50–74 | `high` |
| 25–49 | `medium` |
| 0–24 | `low` |

---

## 4. Factor Details

### Factor 1 — Severity
- Base score from highest severity event: critical=100, high=75, medium=50, low=25
- Boost: each additional high-confidence (≥80%) severe event adds up to +2 pts, capped at +10
- Prevents a single uncertain alert from inflating scores; multiple confirmed events raise confidence

### Factor 2 — IOC Reputation
- `confidence ≥ 80%` → KNOWN_MALICIOUS (100)
- `confidence 60–79%` → HIGH_CONFIDENCE (90)
- `confidence < 60%` → SUSPICIOUS (70)
- IOC event but no DB match → UNKNOWN (25)
- No indicator in events → NONE (0)

### Factor 3 — Asset Criticality
- Uses `entities.criticality` (0–100) of the highest-criticality target
- **Never averages** — a 95/100 production database is not diluted by a co-present 10/100 dev host
- No entity data available → default 25 (configurable via `RISK_DEFAULT_ASSET_CRITICALITY`)

### Factor 4 — Correlation Strength
- Directly reuses Phase 3's `correlations.correlation_score` (0–100)
- No second correlation algorithm

### Factor 5 — Recency (exponential decay)
- `score = 100 × exp(−ageMinutes / halfLife)`
- Default half-life: 120 minutes (`RECENCY_HALF_LIFE_MINUTES`)
- Just observed → ~100 · 2h ago → ~37 · 4h ago → ~14 · much older → approaches 0

### Factor 6 — Attack Progression
- Counts distinct **meaningful** stages (THREAT_INTEL excluded — it is an intelligence source category, not an attack technique)
- 0 stages → 0 · 1 → 25 · 2 → 55 · 3 → 75 · 4+ → 100

### Factor 7 — Cross-Source Corroboration
- Counts distinct independent source types
- 0 → 0 · 1 → 20 · 2 → 50 · 3 → 80 · 4+ → 100

---

## 5. Evidence Model

Every risk calculation stores a `risk_evidence` JSON:

```json
{
  "version": "1.0",
  "factors": [
    {
      "name": "severity",
      "score": 100,
      "weight": 0.2,
      "contribution": 20,
      "reason": "Highest severity in correlation is critical with 1 additional high-confidence severe event(s)",
      "detail": { "topSeverity": "critical", "baseScore": 100, "boost": 2 }
    },
    {
      "name": "iocRisk",
      "score": 100,
      "weight": 0.2,
      "contribution": 20,
      "reason": "Known malicious indicator (ip:185.220.101.47) with confidence 95"
    }
  ],
  "attackProgression": {
    "score": 55,
    "stagesObserved": ["RECONNAISSANCE", "CREDENTIAL_ATTACK"]
  },
  "crossSource": {
    "score": 80,
    "distinctSources": ["siem", "sensor", "threat_intel"]
  },
  "finalScore": 88,
  "priority": "critical"
}
```

Contributions are mathematically consistent: `sum(contribution) ≈ finalScore ± 1` (rounding).

---

## 6. API Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/risk/run` | Batch: evaluate all pending correlations |
| `POST` | `/api/risk/correlation/:correlationId` | Evaluate one correlation |
| `GET` | `/api/risk` | List risk scores (`?priority=critical&minScore=75&limit=20`) |
| `GET` | `/api/risk/:id` | Get risk score by UUID |
| `GET` | `/api/risk/:id/evidence` | Get full risk evidence JSON |
| `GET` | `/api/alerts` | List alerts (`?priority=critical&status=open`) |
| `GET` | `/api/alerts/:id` | Get alert by UUID |
| `PATCH` | `/api/alerts/:id/status` | Update alert status: `open|acknowledged|closed` |

---

## 7. Idempotency

- `risk_scores.correlation_id` has a UNIQUE constraint — only one score per correlation
- First evaluation → INSERT risk score + CREATE alert
- Second evaluation → UPDATE risk score + UPDATE active alert (no duplicates)
- If alert is CLOSED and risk is recalculated at high/critical → NEW alert created

---

## 8. Sample Requests

### Evaluate Scenario A correlation
```bash
# After Phase 3 correlation, get the correlation UUID from:
curl http://localhost:4000/api/correlations

# Then evaluate:
curl -X POST http://localhost:4000/api/risk/correlation/<correlation-uuid>
```

### Batch evaluate all pending correlations
```bash
curl -X POST http://localhost:4000/api/risk/run
```

### Get risk evidence
```bash
curl http://localhost:4000/api/risk/<risk-score-uuid>/evidence
```

### Acknowledge an alert
```bash
curl -X PATCH http://localhost:4000/api/alerts/<alert-uuid>/status \
  -H 'Content-Type: application/json' \
  -d '{"status": "acknowledged"}'
```

### Force recalculate (update existing)
```bash
curl -X POST http://localhost:4000/api/risk/correlation/<uuid> \
  -H 'Content-Type: application/json' \
  -d '{"force": true}'
```

---

## 9. Scenario Results

### Scenario A (CRITICAL Coordinated Attack)
- Severity: 100 (critical events)
- IOC Risk: 100 (known malicious IP, confidence 95)
- Asset Criticality: 95 (prod-db-01.internal)
- Correlation Strength: Phase 3 score (≥75)
- Recency: ~97 (activity within last hour)
- Attack Progression: 55 (RECON + CREDENTIAL_ATTACK)
- Cross-Source: 80 (siem + sensor + threat_intel)
- **Expected score: ≥75 → CRITICAL**

### Scenario B (LOW Isolated Dev Probe)
- Severity: 25 (low)
- IOC Risk: 0 (no indicator)
- Asset Criticality: 10 (dev-test-07.internal)
- Correlation Strength: ~15 (weak)
- Recency: lower (activity 2h+ ago)
- Attack Progression: 25 (single RECON stage)
- Cross-Source: 20 (single SIEM source)
- **Expected score: < 25 → LOW**

---

## 10. Database Migration

Apply before starting the backend:
```bash
mysql -u root cyberfusion_db < src/database/migrate-phase4.sql
```

Adds `risk_evidence JSON NULL` column to `risk_scores`. Safe to re-run (uses `IF NOT EXISTS`).

---

## 11. Limitations

- No real-time push: the frontend polls; risk scores are not pushed automatically
- No authentication on API endpoints (hackathon prototype)
- Recency half-life is global, not per-event-type
- Closed alerts are not automatically re-opened (by design — analyst decisions preserved)

---

## 12. Future Improvements

- Auto-trigger risk evaluation on correlation creation (Phase 5 integration point)
- Per-event-type severity weights (a C2 beacon should differ from a port scan)
- Threat actor attribution as a risk factor
- Historical trend comparison (is this IP more or less active than usual?)
- Risk score history / audit trail per correlation

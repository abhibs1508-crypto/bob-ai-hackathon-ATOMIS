# CyberFusion — Phase 3: Correlation Engine

> **Status:** Implemented  
> **Phase:** 3 — Threat Intelligence Correlation Engine  
> **Depends on:** Phase 2 (Ingestion + Normalization)

---

## 1. Purpose

The Correlation Engine answers the analyst's most important question:

> *Which independently ingested threat events are actually describing the **same attack**?*

It consumes normalised `threat_events` already stored in MySQL (output of Phase 2), groups related events into correlated threat clusters, and stores the result in `correlations` + `correlation_events`.

The engine is:
- **Deterministic** — the same input always produces the same output
- **Explainable** — every correlation comes with structured evidence describing *why* events were grouped
- **Testable** — the core rule engine is a pure function with zero I/O
- **Extensible** — new rules are added by implementing one function and registering it in `RULE_REGISTRY`

**No AI, no LLM.** AI analysis belongs to Phase 5. All correlation logic is explicit, rule-based, and inspectable.

---

## 2. Architecture

```
threat_events (MySQL)
        ↓
correlationService.js       ← orchestrates DB + engine
  ├── loadEventByEventId()   — load trigger event
  ├── findCandidateEvents()  — bounded indexed query
  ├── loadMatchedIndicators() — IOC lookup
  └── loadTargetEntities()   — entity criticality lookup
        ↓
CorrelationContext { events, matchedIndicators, targetEntities }
        ↓
correlationEngine.js        ← pure function, no I/O
  └── RULE_REGISTRY.map(rule.evaluate(ctx))
        ↓
RuleResult[]
        ↓
correlationScoring.js       — bounded 0–100 score
correlationEvidence.js      — structured JSON evidence
attackStageClassifier.js    — MITRE-aligned stage mapping
        ↓
CorrelationResult
        ↓
correlationRepository.js    — upsert correlations + correlation_events
        ↓
correlations (MySQL)
correlation_events (MySQL)
```

**File layout:**
```
src/backend/src/services/correlation/
├── correlationConfig.js          — weights, windows, thresholds
├── correlationEngine.js          — rule pipeline orchestrator (pure)
├── correlationService.js         — DB integration + public API
├── correlationScoring.js         — bounded scoring formula
├── correlationEvidence.js        — evidence + title builder
├── attackStageClassifier.js      — event_type → kill-chain stage
└── correlationRules/
    ├── sameSourceRule.js          — Rule 1
    ├── sameTargetRule.js          — Rule 2
    ├── sourceTargetRule.js        — Rule 3
    ├── temporalRule.js            — Rule 4
    ├── indicatorRule.js           — Rule 5
    ├── entityRule.js              — Rule 6
    ├── repeatedActivityRule.js    — Rule 7
    ├── crossSourceRule.js         — Rule 8
    └── attackSequenceRule.js      — Rule 9

src/backend/src/db/
└── correlationRepository.js      — SQL for correlations table

src/database/
├── schema.sql                    — base tables (Phase 1)
└── migrate-phase3.sql            — Phase 3 column additions
```

---

## 3. Candidate Selection

To avoid O(N²) full-table scans, candidate events are selected using indexed fields:

```sql
SELECT * FROM threat_events
WHERE (timestamp BETWEEN ? AND ?)
  AND (source_ip = ? OR target = ? OR indicator_value = ?)
LIMIT 200
```

The time window is `CAMPAIGN` (24h by default). The `CANDIDATE_LIMIT` env var caps the result set.

Indexed columns used: `idx_source_ip`, `idx_target`, `idx_timestamp`, `idx_event_type`.

---

## 4. Correlation Rules

Each rule implements `evaluate(ctx) → RuleResult`. Rules are stateless pure functions.

| # | Rule ID | Weight | Fires when… |
|---|---|---|---|
| 1 | `SAME_SOURCE` | 10 | ≥2 events share the same `source_ip` |
| 2 | `SAME_TARGET` | 10 | ≥2 events target the same asset |
| 3 | `SOURCE_TARGET` | 15 | Same IP → same target across ≥2 events |
| 4 | `TEMPORAL_PROXIMITY` | 10 | Events cluster within a time window |
| 5 | `IOC_MATCH` | 20 | An event indicator matches a known-bad IOC |
| 6 | `ENTITY_RELATION` | 5 | Target matches a known high-value entity |
| 7 | `REPEATED_ACTIVITY` | 5 | Same event_type appears ≥3 times |
| 8 | `CROSS_SOURCE` | 15 | Events come from ≥2 independent source types |
| 9 | `ATTACK_SEQUENCE` | 10 | Events represent a multi-stage kill-chain progression |

**Total maximum weight: 100**

Weights are configurable via environment variables (`CORR_W_*`).

### Rule result structure

```json
{
  "matched": true,
  "ruleId": "IOC_MATCH",
  "weight": 20,
  "confidence": 0.95,
  "reason": "Event indicator matches a known malicious threat-intelligence indicator (ip:185.220.101.47)",
  "evidence": {
    "matchedIndicators": [{ "type": "ip", "value": "185.220.101.47", "threatType": "botnet_c2" }],
    "matchedEventIds": ["siem-001", "ti-001"]
  }
}
```

---

## 5. Scoring Model

```
rawScore = Σ (weight × confidence) for all matched rules
score    = round( min(100, (rawScore / MAX_RAW_SCORE) × 100) )
```

Score is normalised against the theoretical maximum (100) so it is always bounded 0–100.

| Score | Strength |
|---|---|
| 75–100 | `very_strong` |
| 50–74 | `strong` |
| 25–49 | `moderate` |
| 0–24 | `weak` |

---

## 6. Evidence Model

Every correlation persists a `correlation_factors` JSON field with full explainability:

```json
{
  "score": 87,
  "strength": "very_strong",
  "factors": ["SAME_SOURCE", "SAME_TARGET", "IOC_MATCH", "CROSS_SOURCE", "ATTACK_SEQUENCE"],
  "firstSeen": "2025-01-01T10:00:00.000Z",
  "lastSeen": "2025-01-01T10:35:00.000Z",
  "durationMinutes": 35,
  "eventCount": 4,
  "sourceIps": ["185.220.101.47"],
  "targets": ["prod-db-01.internal"],
  "sourceTypes": ["siem", "sensor", "threat_intel"],
  "matchedIndicators": [{ "type": "ip", "value": "185.220.101.47", "threatType": "botnet_c2" }],
  "targetEntities": [{ "name": "prod-db-01.internal", "criticality": 95 }],
  "rules": [
    {
      "rule": "SAME_SOURCE",
      "description": "4 suspicious events originated from the same source IP",
      "weight": 10,
      "confidence": 80,
      "evidence": { "sharedSourceIp": "185.220.101.47", "eventCount": 4 }
    },
    {
      "rule": "IOC_MATCH",
      "description": "Event indicator matches a known malicious threat-intelligence indicator",
      "weight": 20,
      "confidence": 95
    }
  ]
}
```

---

## 7. Attack Stage Mapping

Event types are mapped to MITRE ATT&CK-inspired stages:

| Stage | Event types |
|---|---|
| `RECONNAISSANCE` | port_scan, network_scan, host_discovery, dns_enumeration |
| `CREDENTIAL_ATTACK` | failed_login, auth_failure, brute_force, password_spray |
| `INITIAL_ACCESS` | phishing, spearphishing |
| `THREAT_INTEL` | ioc_match, malicious_ioc, threat_report |
| `EXPLOITATION` | exploit_attempt, command_execution, malware_detection |
| `PERSISTENCE` | persistence_attempt, scheduled_task |
| `PRIVILEGE_ESCALATION` | privilege_escalation, sudo_misuse |
| `LATERAL_MOVEMENT` | lateral_movement, remote_service |
| `COMMAND_AND_CONTROL` | beacon, c2_connection, dns_tunneling |
| `EXFILTRATION` | data_exfiltration, large_upload |
| `UNKNOWN` | anything not in the map |

Unknown event types are preserved but do not contribute to stage progression scoring.

---

## 8. Duplicate Prevention

Correlation identity is determined by a **deterministic SHA-256 fingerprint**:

```
key = SHA256( sorted_event_ids joined by "|" + "::" + primary_source_ip + "::" + primary_target )
key is truncated to 64 hex characters
```

On each run:
- If a correlation with the same `correlation_key` exists → **UPDATE** (event count, score, evidence)
- If not → **INSERT** a new correlation

This makes the engine **idempotent**: running it twice on the same event cluster produces one correlation record, not two.

---

## 9. API Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/correlation/run` | Batch: correlate all events in the last 24h |
| `POST` | `/api/correlation/event/:eventId` | Correlate a specific event by `event_id` |
| `GET` | `/api/correlations` | List all correlations (newest first) |
| `GET` | `/api/correlations?status=active` | Filter by status |
| `GET` | `/api/correlations?limit=10` | Limit results |
| `GET` | `/api/correlations/:id` | Get a single correlation by UUID |
| `GET` | `/api/correlations/:id/events` | Get events in a correlation |
| `GET` | `/api/correlations/:id/evidence` | Get the full evidence JSON |

---

## 10. Sample Requests

### Run correlation for a specific event
```bash
curl -X POST http://localhost:4000/api/correlation/event/siem-001
```

### Run batch correlation
```bash
curl -X POST http://localhost:4000/api/correlation/run
```

### List correlations
```bash
curl http://localhost:4000/api/correlations
curl http://localhost:4000/api/correlations?status=active&limit=10
```

### Get correlation detail + evidence
```bash
curl http://localhost:4000/api/correlations/<uuid>
curl http://localhost:4000/api/correlations/<uuid>/evidence
curl http://localhost:4000/api/correlations/<uuid>/events
```

---

## 11. Sample Responses

### POST /api/correlation/event/siem-001
```json
{
  "success": true,
  "correlated": true,
  "isNew": true,
  "correlationId": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "score": 87,
  "strength": "very_strong",
  "factors": ["SAME_SOURCE", "SAME_TARGET", "SOURCE_TARGET", "TEMPORAL_PROXIMITY", "IOC_MATCH", "CROSS_SOURCE", "ATTACK_SEQUENCE"],
  "eventCount": 4,
  "attackStages": ["RECONNAISSANCE", "CREDENTIAL_ATTACK", "THREAT_INTEL"],
  "sourceIps": ["185.220.101.47"],
  "targets": ["prod-db-01.internal"],
  "sourceTypes": ["siem", "sensor", "threat_intel"],
  "firstSeen": "2025-01-01T09:25:00.000Z",
  "lastSeen": "2025-01-01T09:45:00.000Z"
}
```

### GET /api/correlations/:id/evidence (excerpt)
```json
{
  "success": true,
  "score": 87,
  "strength": "very_strong",
  "evidence": {
    "rules": [
      { "rule": "SAME_SOURCE",      "description": "4 suspicious events originated from the same source IP" },
      { "rule": "IOC_MATCH",        "description": "Event indicator matches a known malicious indicator (ip:185.220.101.47)" },
      { "rule": "CROSS_SOURCE",     "description": "Related evidence observed across 3 independent source types: siem, sensor, threat_intel" },
      { "rule": "ATTACK_SEQUENCE",  "description": "Attack stage progression detected: RECONNAISSANCE → CREDENTIAL_ATTACK → THREAT_INTEL" }
    ]
  }
}
```

---

## 12. Scenario A — CRITICAL Coordinated Attack

**Events:** `siem-001` (port_scan) → `sensor-001` (failed_login/SSH) → `sensor-002` (failed_login/MySQL) → `ti-001` (ioc_match)

**Expected correlation:**
- Score: ≥75 (`very_strong`)
- Factors: `SAME_SOURCE`, `SAME_TARGET`, `SOURCE_TARGET`, `TEMPORAL_PROXIMITY`, `IOC_MATCH`, `CROSS_SOURCE`, `ATTACK_SEQUENCE`
- Attack stages: `RECONNAISSANCE → CREDENTIAL_ATTACK → THREAT_INTEL`
- All 4 events in ONE correlation (not 4 separate correlations)

**Run:**
```bash
node src/data/seeds/loadDemoData.js   # seed data first
curl -X POST http://localhost:4000/api/correlation/event/siem-001
```

---

## 13. Scenario B — LOW Isolated Probe

**Events:** `siem-002` (port_scan, non-critical target `dev-test-07.internal`, no IOC match)

**Expected:**
- Single event: fewer than 2 events share IP/target → most rules cannot fire
- Score: ≤25 (`weak`) or no correlation persisted
- Demonstrates the system does NOT treat every port scan as a critical incident

---

## 14. Scenario C — Multi-Stage Attack

**Events (not in seed data — use API directly):**
```bash
# Port scan
curl -X POST http://localhost:4000/api/ingestion/sensor \
  -H 'Content-Type: application/json' \
  -d '{"event_id":"c-001","event_type":"PORT_SCAN","source_ip":"10.20.30.40","target":"web-server-01","severity":"medium","confidence":75,"timestamp":"2025-01-01T10:00:00Z"}'

# Failed login
curl -X POST http://localhost:4000/api/ingestion/siem \
  -H 'Content-Type: application/json' \
  -d '{"event_id":"c-002","event_type":"FAILED_LOGIN","source_ip":"10.20.30.40","target":"web-server-01","severity":"high","confidence":80,"timestamp":"2025-01-01T10:05:00Z"}'

# Exploit attempt
curl -X POST http://localhost:4000/api/ingestion/siem \
  -H 'Content-Type: application/json' \
  -d '{"event_id":"c-003","event_type":"EXPLOIT_ATTEMPT","source_ip":"10.20.30.40","target":"web-server-01","severity":"critical","confidence":90,"timestamp":"2025-01-01T10:10:00Z"}'

# Lateral movement
curl -X POST http://localhost:4000/api/ingestion/sensor \
  -H 'Content-Type: application/json' \
  -d '{"event_id":"c-004","event_type":"LATERAL_MOVEMENT","source_ip":"10.20.30.40","target":"db-server-02","severity":"critical","confidence":85,"timestamp":"2025-01-01T10:15:00Z"}'

# Correlate
curl -X POST http://localhost:4000/api/correlation/event/c-001
```

**Expected:**
- Score: ≥50 (`strong` or `very_strong`)
- Attack stages: `RECONNAISSANCE → CREDENTIAL_ATTACK → EXPLOITATION → LATERAL_MOVEMENT`
- Factors include: `ATTACK_SEQUENCE`, `CROSS_SOURCE`, `SAME_SOURCE`

---

## 15. Limitations

- **Single-process engine**: the engine scans candidates inline; at very high event volumes, a streaming processor would be needed
- **24h correlation window** (`CAMPAIGN`): events older than 24h are not correlated by default
- **No authentication**: API endpoints are unauthenticated (noted as known limitation)
- **No WebSocket push**: the dashboard polls; correlations are not pushed in real time
- **Indicator lookup**: only exact-value matches; no subnet/CIDR matching yet
- **No ML/AI correlation**: Phase 3 is intentionally deterministic; AI narrative belongs to Phase 5

---

## 16. Future Improvements

- Add streaming ingestion trigger: run `correlateEvent()` immediately on ingest (Phase 4 integration point)
- Add CIDR/subnet matching for IP indicators
- Add domain suffix matching for domain indicators
- Add configurable rule weights via admin API
- Add correlation merge: detect when two separate correlations should be joined
- Add correlation dismissal API for analyst workflow
- Extract correlation engine to a background worker for high-volume production use

'use strict';

const { getPool } = require('./src/db/pool');

const eventId = 'PHASE2-RUNTIME-VERIFY-20260914-001';
const event = {
  event_id: eventId,
  event_type: 'AUTH_FAILURE',
  source_ip: '198.51.100.42',
  target: 'demo-verification-host.internal',
  severity: 'low',
  confidence: 1,
  timestamp: '2026-09-14T12:00:00.000Z',
  raw_data: { purpose: 'Phase 2 runtime verification', safe_demo: true },
};

async function verifyIngestion() {
  const response = await fetch('http://localhost:4001/api/ingestion/siem', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(event),
  });
  const responseBody = await response.json();
  if (response.status !== 201) {
    throw new Error(`Ingestion returned HTTP ${response.status}: ${JSON.stringify(responseBody)}`);
  }

  const [databaseRows] = await getPool().query('SELECT DATABASE() AS database_name, 1 AS select_one');
  const [eventRows] = await getPool().execute(
    'SELECT event_id, source, target FROM threat_events WHERE event_id = ?',
    [eventId]
  );

  console.log(JSON.stringify({
    ingestion: { http_status: response.status, body: responseBody },
    query: databaseRows[0],
    persisted_events: eventRows,
  }, null, 2));

  await getPool().end();
}

verifyIngestion().catch(error => {
  console.error(error.message);
  process.exit(1);
});

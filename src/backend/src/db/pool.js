'use strict';

/**
 * CyberFusion — MySQL Connection Pool
 *
 * Creates a single mysql2 promise-based connection pool for the entire
 * application lifetime. Import { pool } from this module everywhere.
 *
 * Designed so that switching from local XAMPP to Aiven (or any other MySQL
 * host) requires only environment variable changes — no code changes.
 */

const mysql = require('mysql2/promise');
const config = require('../config');

/** @type {import('mysql2/promise').Pool} */
let pool;

/**
 * Creates (or returns the existing) connection pool.
 * @returns {import('mysql2/promise').Pool}
 */
function getPool() {
  if (pool) return pool;

  const poolConfig = {
    host:               config.db.host,
    port:               config.db.port,
    user:               config.db.user,
    password:           config.db.password,
    database:           config.db.name,
    connectionLimit:    config.db.connectionLimit,
    waitForConnections: true,
    queueLimit:         0,
    // Keeps connections alive and avoids stale-connection errors on Aiven
    enableKeepAlive:    true,
    keepAliveInitialDelay: 10000,
    // Return dates as strings so timezone handling is explicit
    dateStrings: true,
  };

  // Aiven (and other hosted MySQL) require SSL — enabled via DB_SSL=true
  if (config.db.ssl) {
    poolConfig.ssl = { rejectUnauthorized: true };
  }

  pool = mysql.createPool(poolConfig);
  return pool;
}

/**
 * Verifies the database is reachable by executing a lightweight query.
 * Logs the result without printing credentials.
 * @returns {Promise<void>}
 */
async function checkDatabaseConnection() {
  const conn = await getPool().getConnection();
  try {
    await conn.query('SELECT 1');
    console.log('[db] Database connection: SUCCESS');
    console.log(`[db] Connected to ${config.db.host}:${config.db.port}/${config.db.name}`);
  } finally {
    conn.release();
  }
}

module.exports = { getPool, checkDatabaseConnection };

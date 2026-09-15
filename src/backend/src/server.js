'use strict';

/**
 * CyberFusion — HTTP Server Entry Point
 *
 * Starts the Express application after verifying the database connection.
 * Run with:
 *   node src/server.js          (production)
 *   npx nodemon src/server.js   (development)
 *
 * Environment variables are loaded by config.js via dotenv.
 */

const app  = require('./app');
const config = require('./config');
const { checkDatabaseConnection } = require('./db/pool');

async function start() {
  try {
    // Verify MySQL is reachable before accepting traffic
    await checkDatabaseConnection();

    app.listen(config.port, () => {
      console.log(`[server] Backend server: READY`);
      console.log(`[server] Listening on http://localhost:${config.port}`);
      console.log(`[server] Environment: ${config.nodeEnv}`);
    });
  } catch (err) {
    console.error('[server] Failed to start — database connection error:');
    // Print a safe, non-credential-exposing message
    console.error(`[server] ${err.message.replace(/password\s*=\s*\S+/gi, 'password=[REDACTED]')}`);
    console.error('[server] Ensure XAMPP MySQL is running and cyberfusion_db exists.');
    console.error('[server] Check DB_HOST, DB_PORT, DB_USER, DB_NAME in your .env file.');
    process.exit(1);
  }
}

start();

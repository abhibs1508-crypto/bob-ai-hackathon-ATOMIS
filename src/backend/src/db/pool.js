'use strict';

/**
 * CyberFusion — Supabase Connection Pool
 *
 * Replaces the MySQL pool with a Supabase client singleton.
 * Uses the Service Role Key for backend administration.
 */

const { createClient } = require('@supabase/supabase-js');
const config = require('../config');

/** @type {import('@supabase/supabase-js').SupabaseClient} */
let supabaseClient;

/**
 * Creates (or returns the existing) Supabase client.
 * @returns {import('@supabase/supabase-js').SupabaseClient}
 */
function getPool() {
  if (supabaseClient) return supabaseClient;

  if (!config.supabase.url || !config.supabase.serviceKey) {
    throw new Error('[db] Missing Supabase URL or Key in configuration.');
  }

  supabaseClient = createClient(config.supabase.url, config.supabase.serviceKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    }
  });

  return supabaseClient;
}

/**
 * Verifies the database is reachable by executing a lightweight query.
 * @returns {Promise<void>}
 */
async function checkDatabaseConnection() {
  const client = getPool();
  try {
    const { data, error } = await client.from('entities').select('id').limit(1);
    if (error) throw error;
    console.log('[db] Supabase connection: SUCCESS');
    console.log(`[db] Connected to Supabase project: ${config.supabase.url}`);
  } catch (err) {
    console.error('[db] Supabase connection failed:', err.message);
    throw err;
  }
}

// Ensure compatibility with old getPool() usage in repositories:
// Previously: getPool().execute(sql, params)
// Now, repositories will use: getPool().from('table').select(...)
module.exports = { getPool, checkDatabaseConnection };

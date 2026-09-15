'use strict';

const fs = require('fs');
const mysql = require('mysql2/promise');
const config = require('./src/config');

async function applySchema() {
  const sql = fs.readFileSync('../database/schema.sql', 'utf8');
  const connection = await mysql.createConnection({
    host: config.db.host,
    port: config.db.port,
    user: config.db.user,
    password: config.db.password,
    multipleStatements: true,
  });

  try {
    await connection.query(sql);
    const [rows] = await connection.query(
      'SELECT TABLE_NAME FROM information_schema.tables WHERE table_schema = ? ORDER BY TABLE_NAME',
      [config.db.name]
    );
    console.log(JSON.stringify({
      database: config.db.name,
      tables: rows.map(row => row.TABLE_NAME),
    }, null, 2));
  } finally {
    await connection.end();
  }
}

applySchema().catch(error => {
  console.error(error.message);
  process.exit(1);
});

'use strict';

/**
 * CyberFusion — Express Application
 *
 * Assembles the Express app: middleware, routes, error handlers.
 * Exported separately from server.js so it can be imported by Supertest
 * integration tests without binding a port.
 */

const express = require('express');
const cors    = require('cors');
const config  = require('./config');
const { jsonParseErrorHandler, errorHandler } = require('./middleware/errorHandler');

// Route modules
const healthRouter       = require('./routes/health');
const ingestionRouter    = require('./routes/ingestion');
const correlationRouter  = require('./routes/correlation');
const riskRouter         = require('./routes/risk');
const alertsRouter       = require('./routes/alerts');
const intelligenceRouter = require('./routes/intelligence');

const app = express();

// ---------------------------------------------------------------------------
// Global middleware
// ---------------------------------------------------------------------------

// CORS — restrict to the configured frontend origin in production
app.use(cors({
  origin: config.nodeEnv === 'production'
    ? process.env.FRONTEND_ORIGIN || 'http://localhost:5173'
    : '*',
  methods: ['GET', 'POST', 'PATCH', 'OPTIONS'],
}));

// Parse JSON bodies; limit prevents oversized payload attacks
app.use(express.json({ limit: '1mb' }));

// Handle malformed JSON before it reaches routes
app.use(jsonParseErrorHandler);

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

app.use('/api/health',        healthRouter);
app.use('/api/ingestion',     ingestionRouter);
app.use('/api/correlation',   correlationRouter);
app.use('/api/correlations',  correlationRouter);
app.use('/api/risk',          riskRouter);
app.use('/api/alerts',        alertsRouter);
app.use('/api/intelligence',  intelligenceRouter);

// 404 handler — catches unmatched routes
app.use((_req, res) => {
  res.status(404).json({ success: false, message: 'Route not found.' });
});

// ---------------------------------------------------------------------------
// Centralised error handler — MUST be last
// ---------------------------------------------------------------------------
app.use(errorHandler);

module.exports = app;

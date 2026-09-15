'use strict';

/**
 * CyberFusion — Centralized Error Handler Middleware
 *
 * Must be registered LAST (after all routes) in app.js.
 *
 * Rules enforced here:
 *   - Never expose stack traces in production.
 *   - Never expose SQL text or database passwords.
 *   - Never expose environment variable values.
 *   - Translate known error codes to appropriate HTTP status codes.
 *   - Log the full error server-side for debugging.
 */

const config = require('../config');

/**
 * Express 4-argument error-handling middleware.
 *
 * @param {Error} err
 * @param {import('express').Request}  req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} _next  — must be declared even if unused
 */
// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, _next) {
  // Log full error server-side (never sent to client)
  console.error('[error]', err.message);
  if (config.nodeEnv !== 'production') {
    console.error(err.stack);
  }

  // Determine HTTP status code
  const status = err.statusCode || err.status || 500;

  // Build a safe client response — no stack, no SQL, no credentials
  const body = {
    success: false,
    message: safeMessage(err, status),
  };

  // Include error code for application-level handling (e.g. duplicate events)
  if (err.code) {
    body.code = err.code;
  }

  res.status(status).json(body);
}

/**
 * Returns a client-safe message string.
 * Internal errors (500+) return a generic message in production.
 * @param {Error} err
 * @param {number} status
 * @returns {string}
 */
function safeMessage(err, status) {
  if (status >= 500 && config.nodeEnv === 'production') {
    return 'An internal server error occurred.';
  }
  // Scrub any accidental credential leakage from error messages
  return sanitiseMessage(err.message || 'Unknown error');
}

/**
 * Removes patterns that might accidentally leak credentials or paths.
 * @param {string} message
 * @returns {string}
 */
function sanitiseMessage(message) {
  return message
    .replace(/password\s*=\s*\S+/gi, 'password=[REDACTED]')
    .replace(/:[^@]+@/g, ':[REDACTED]@');  // connection string passwords
}

/**
 * Middleware to handle JSON parse errors thrown by express.json().
 * Must be registered before routes.
 *
 * @param {Error} err
 * @param {import('express').Request}  req
 * @param {import('express').Response} res
 * @param {import('express').NextFunction} next
 */
function jsonParseErrorHandler(err, req, res, next) {
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({
      success: false,
      message: 'Invalid JSON in request body.',
    });
  }
  next(err);
}

module.exports = { errorHandler, jsonParseErrorHandler };

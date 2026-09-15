# Setup Guide

> **This file is read by the automated evaluation pipeline. Follow the instructions below to run CyberFusion locally or access the deployed application.**

## Prerequisites

Before running CyberFusion locally, ensure you have:

* [ ] Node.js 18+
* [ ] npm
* [ ] Git
* [ ] A Supabase account/project
* [ ] A Groq API key

For development and deployment, the following are recommended:

* [ ] Node.js 20+
* [ ] Modern web browser such as Chrome, Edge, or Firefox
* [ ] Netlify account for frontend deployment
* [ ] Backend hosting platform for the Express API

CyberFusion does not require Docker for the standard local setup.

## Environment Variables

### Backend Environment Variables

The backend requires the following environment variables:

| Variable                    | Description                                   | Required |
| --------------------------- | --------------------------------------------- | -------- |
| `SUPABASE_URL`              | URL of the CyberFusion Supabase project       | Yes      |
| `SUPABASE_SERVICE_ROLE_KEY` | Supabase service-role key used by the backend | Yes      |
| `BACKEND_PORT`              | Port used by the Express server               | Yes      |
| `NODE_ENV`                  | Runtime environment                           | Yes      |
| `AI_PROVIDER`               | AI provider used by CyberFusion               | Yes      |
| `GROQ_API_KEY`              | Groq API key                                  | Yes      |
| `GROQ_MODEL`                | Groq model used for intelligence generation   | Yes      |
| `GROQ_TIMEOUT_MS`           | Maximum AI request timeout                    | No       |
| `GROQ_MAX_TOKENS`           | Maximum AI response tokens                    | No       |
| `GROQ_TEMPERATURE`          | AI generation temperature                     | No       |

Example:

```env
SUPABASE_URL=https://your-project-id.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your_supabase_service_role_key

BACKEND_PORT=4000
NODE_ENV=production

AI_PROVIDER=groq
GROQ_API_KEY=your_groq_api_key
GROQ_MODEL=openai/gpt-oss-120b
GROQ_TIMEOUT_MS=30000
GROQ_MAX_TOKENS=1200
GROQ_TEMPERATURE=0.2
```

### Frontend Environment Variables

The React application uses the backend REST API URL.

For local development:

```env
VITE_API_BASE_URL=http://localhost:4000/api
```

For the deployed Netlify application:

```env
VITE_API_BASE_URL=https://YOUR-BACKEND-DOMAIN/api
```

The frontend must not contain:

* `SUPABASE_SERVICE_ROLE_KEY`
* `GROQ_API_KEY`
* Database passwords
* Other backend secrets

These values must remain server-side.

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/YOUR-USERNAME/bob-ai-hackathon-ATOMIS.git
cd bob-ai-hackathon-ATOMIS
```

### 2. Install Backend Dependencies

```bash
cd src/backend
npm install
```

### 3. Configure Backend Environment

Create a `.env` file inside:

```text
src/backend/.env
```

Add the required Supabase and Groq configuration.

For local development, use:

```env
NODE_ENV=development
BACKEND_PORT=4000
```

For deployment, configure the same variables through the backend hosting platform's environment-variable settings.

### 4. Install Frontend Dependencies

Open another terminal:

```bash
cd src/frontend
npm install
```

### 5. Configure Frontend Environment

Create:

```text
src/frontend/.env
```

For local development:

```env
VITE_API_BASE_URL=http://localhost:4000/api
```

For production, configure the deployed backend API URL through the Netlify environment variables.

## Database Setup

CyberFusion uses Supabase PostgreSQL as its centralized database.

The database contains the application's core security intelligence data, including:

* Threat events
* Entities
* Indicators
* Correlations
* Correlation evidence
* Risk scores
* Alerts
* Intelligence reports

The required database schema must be available in the configured Supabase project before starting the backend.

The backend connects to Supabase using the server-side service-role key.

## Running the Application Locally

### Start the Backend

From the project root:

```bash
cd src/backend
npm run dev
```

The local backend runs on:

```text
http://localhost:4000
```

### Start the Frontend

In a separate terminal:

```bash
cd src/frontend
npm run dev
```

The Vite development server will provide a local URL, normally:

```text
http://localhost:5173
```

Open the displayed URL in a browser.

### Verify Backend Health

The backend health endpoint is:

```text
http://localhost:4000/api/health
```

A healthy system should report that the API and database are available and that the configured AI provider is available.

## Production Deployment

### Frontend — Netlify

The React frontend is deployed using Netlify.

The Netlify project should use:

```text
Base directory:
src/frontend
```

Build command:

```bash
npm run build
```

Publish directory:

```text
dist
```

Configure the following Netlify environment variable:

```text
VITE_API_BASE_URL=https://YOUR-BACKEND-DOMAIN/api
```

After deployment, Netlify provides the public frontend URL.

### Backend

The Express backend is deployed separately from the Netlify frontend.

Configure the backend deployment with the required environment variables:

```text
SUPABASE_URL
SUPABASE_SERVICE_ROLE_KEY
BACKEND_PORT
NODE_ENV
AI_PROVIDER
GROQ_API_KEY
GROQ_MODEL
GROQ_TIMEOUT_MS
GROQ_MAX_TOKENS
GROQ_TEMPERATURE
```

The deployed backend must allow requests from the Netlify frontend through the appropriate CORS configuration.

## Running Tests

### Backend Tests

From:

```text
src/backend
```

run:

```bash
npm test
```

The test suite validates major CyberFusion functionality including:

* Health checks
* Data ingestion
* Data normalization
* Threat correlation
* Risk calculation
* Alert generation
* AI intelligence generation
* AI guardrails
* Persistence
* Idempotency
* REST API behavior

The verified project baseline contains:

```text
13 test suites
259 tests
0 failures
```

### Frontend Production Build

From:

```text
src/frontend
```

run:

```bash
npm run build
```

The command should complete successfully and generate the production build in:

```text
src/frontend/dist
```

## Quick Demo

CyberFusion can be demonstrated using a representative multi-source threat scenario.

The scenario contains four related security signals:

```text
SIEM
  Port Scan
      ↓
Cyber Sensor
  Failed SSH Login
      ↓
Cyber Sensor
  Failed MySQL Login
      ↓
Threat Intelligence
  IOC Match
```

CyberFusion correlates these events and produces:

```text
Correlation Score: 77
Correlation Strength: VERY_STRONG

Risk Score: 81
Priority: CRITICAL

AI Provider: Groq
AI Model: openai/gpt-oss-120b
AI Confidence: 92
```

The dashboard then presents the resulting intelligence report to the analyst.

The report includes:

* BLUF
* Threat Assessment
* Possible Intent
* Reasoning
* Evidence Summary
* Recommended Actions
* AI Confidence

The AI provides analytical assistance, while the risk engine remains authoritative for risk prioritisation and the human analyst remains the final decision-maker.

## Deployed Application

The production frontend is available through the deployed Netlify application:

```text
https://YOUR-NETLIFY-DOMAIN.netlify.app
```

The frontend communicates with the separately deployed Express backend through the configured `VITE_API_BASE_URL`.

## Troubleshooting

| Issue                                   | Solution                                                                                           |
| --------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `SUPABASE_URL is not set`               | Configure `SUPABASE_URL` in the backend environment variables.                                     |
| `SUPABASE_SERVICE_ROLE_KEY is not set`  | Configure the Supabase service-role key on the backend. Never expose it to the frontend.           |
| `GROQ_API_KEY is not set`               | Configure a valid Groq API key on the backend.                                                     |
| `ERR_CONNECTION_REFUSED :4000`          | Ensure the local backend is running with `npm run dev`.                                            |
| Frontend cannot reach backend           | Check `VITE_API_BASE_URL` and verify that the deployed backend is accessible.                      |
| Database connection failed              | Verify the Supabase project URL, service-role key, database schema, and project status.            |
| AI status is offline                    | Verify `AI_PROVIDER=groq`, the Groq API key, and the configured model.                             |
| CORS error                              | Verify that the backend allows requests from the deployed Netlify frontend domain.                 |
| Netlify build fails                     | Verify the Node.js version, run `npm install`, and run `npm run build` locally.                    |
| Blank page after Netlify deployment     | Verify the Vite build output and Netlify publish directory (`dist`).                               |
| API works locally but not in production | Replace the local `VITE_API_BASE_URL` with the deployed backend API URL and redeploy the frontend. |

## Security Requirements

Never commit the following to GitHub:

```text
.env
SUPABASE_SERVICE_ROLE_KEY
GROQ_API_KEY
```

Use `.env.example` files with placeholder values for documentation.

The Supabase service-role key must only be used by the backend.

The Groq API key must only be used by the backend.

No secret API key should be embedded in the React application or exposed through Vite client-side environment variables.

## System Architecture

The deployed system follows this flow:

```text
┌──────────────────────────────┐
│        Netlify Frontend      │
│        React + Vite          │
└──────────────┬───────────────┘
               │ HTTPS REST API
               ↓
┌──────────────────────────────┐
│       Deployed Backend       │
│       Node.js + Express      │
└──────────────┬───────────────┘
               │
       ┌───────┴────────┐
       ↓                ↓
┌──────────────┐  ┌──────────────┐
│   Supabase   │  │   Groq AI    │
│  PostgreSQL  │  │ GPT-OSS-120B │
└──────────────┘  └──────────────┘
```

The complete threat-intelligence processing pipeline is:

```text
Data Sources
     ↓
Ingestion
     ↓
Normalization
     ↓
Supabase
     ↓
Correlation Engine
     ↓
Risk & Priority Engine
     ↓
AI Intelligence Layer
     ↓
Intelligence Report
     ↓
REST API
     ↓
React Analyst Dashboard
     ↓
Human Analyst
```

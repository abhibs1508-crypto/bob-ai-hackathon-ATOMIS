# Solution Overview

## What We Built

CyberFusion is a Threat Intelligence Correlation & Alert Prioritisation Assistant designed to help defence and security analysts handle large volumes of alerts from different security sources.

The system collects security events from SIEM systems, cyber sensors, threat-intelligence feeds, and intelligence reports through structured ingestion APIs. Because these sources can produce information in different formats, CyberFusion first validates and normalizes the incoming data before storing it centrally.

The system then correlates related events across different sources to identify whether multiple alerts are part of the same potential threat. A risk engine evaluates the correlated evidence and assigns an authoritative risk score and priority.

An AI intelligence layer then analyzes the verified evidence and generates a structured intelligence assessment in BLUF (Bottom Line Up Front) format, including the threat assessment, possible intent, evidence summary, and recommended actions.

The final intelligence is presented through a React-based analyst dashboard, while the human analyst remains the final decision-maker.

## How It Works

1. **Data Collection** — CyberFusion receives structured security events representing SIEM alerts, cyber-sensor events, threat-intelligence indicators, and intelligence reports through REST ingestion APIs.

2. **Validation & Normalization** — Incoming data is validated and converted into a common format so that events from different sources can be analyzed consistently.

3. **Centralized Storage** — Normalized threat events, indicators, entities, and related information are stored in the database for correlation and analysis.

4. **Threat Correlation** — The correlation engine compares events using factors such as common source IPs, targets, temporal proximity, IOC matches, cross-source activity, repeated activity, and attack sequences.

5. **Risk Prioritisation** — The risk engine evaluates the correlated evidence and calculates an authoritative risk score and priority, helping analysts focus on the most important threats first.

6. **AI Intelligence Generation** — Verified correlation and risk evidence is passed to the AI intelligence layer. Groq AI generates an evidence-based BLUF assessment, possible intent, reasoning, evidence summary, and recommended actions.

7. **AI Guardrails & Validation** — The generated response is validated to ensure that the AI does not invent indicators, targets, events, or risk values and cannot override the authoritative risk engine.

8. **Analyst Dashboard** — The processed intelligence is exposed through REST APIs and displayed in the React analyst dashboard.

9. **Human Decision** — The analyst reviews the evidence, risk priority, and AI-generated assessment before making the final operational decision.

## Architecture Diagram

> See [`architecture.md`](architecture.md) for the detailed architecture.

```text
┌─────────────────────────────────────────────────────────────┐
│                      THREAT DATA SOURCES                    │
│                                                             │
│  SIEM     Cyber Sensors     Threat Intel     Intel Reports  │
└───────────────────────────┬─────────────────────────────────┘
                            ↓
                  ┌─────────────────────┐
                  │  REST INGESTION API │
                  └──────────┬──────────┘
                             ↓
                  ┌─────────────────────┐
                  │ Validation &        │
                  │ Normalization       │
                  └──────────┬──────────┘
                             ↓
                  ┌─────────────────────┐
                  │      Database       │
                  │ Threat Events /     │
                  │ Indicators /        │
                  │ Entities            │
                  └──────────┬──────────┘
                             ↓
                  ┌─────────────────────┐
                  │ Correlation Engine  │
                  └──────────┬──────────┘
                             ↓
                  ┌─────────────────────┐
                  │ Risk & Priority     │
                  │ Engine              │
                  └──────────┬──────────┘
                             ↓
              ┌────────────────────────────────┐
              │      AI INTELLIGENCE LAYER     │
              │                                │
              │ Context → Prompt → Groq AI     │
              │        ↓                       │
              │ Parser → Guardrails             │
              └───────────────┬────────────────┘
                              ↓
                  ┌─────────────────────┐
                  │ Intelligence Report │
                  │ BLUF / Assessment / │
                  │ Intent / Evidence / │
                  │ Recommended Actions │
                  └──────────┬──────────┘
                             ↓
                  ┌─────────────────────┐
                  │ REST API            │
                  └──────────┬──────────┘
                             ↓
                  ┌─────────────────────┐
                  │ React Analyst       │
                  │ Dashboard           │
                  └──────────┬──────────┘
                             ↓
                    ┌────────────────┐
                    │ Human Analyst  │
                    │ Final Decision │
                    └────────────────┘
```

## Key Design Decisions

| Decision                                              | Rationale                                                                                                                                                                     |
| ----------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Multi-source REST ingestion**                       | Provides a common interface for receiving security data from SIEM systems, cyber sensors, threat-intelligence feeds, and intelligence reports with different data formats.    |
| **Normalization before analysis**                     | Converts heterogeneous source data into a consistent structure, making cross-source correlation more reliable.                                                                |
| **MySQL/Supabase-backed centralized storage**         | Keeps normalized events, entities, indicators, correlations, risk assessments, and intelligence reports available for analysis and retrieval.                                 |
| **Rule-based correlation engine**                     | Provides explainable relationships between security events using evidence such as IOC matches, common sources, targets, timing, repeated activity, and cross-source activity. |
| **Dedicated risk engine**                             | Separates objective risk prioritisation from AI-generated interpretation. The risk engine remains authoritative for the final risk score and priority.                        |
| **AI as an intelligence layer, not a decision-maker** | AI explains verified evidence and generates useful intelligence while preventing it from changing the calculated risk score or inventing security evidence.                   |
| **AI guardrails and response validation**             | Prevents unsupported indicators, targets, events, or claims from being presented as facts.                                                                                    |
| **BLUF-based intelligence reports**                   | Gives commanders and analysts a concise bottom-line assessment before the supporting details and recommendations.                                                             |
| **Human-in-the-loop design**                          | Keeps the security analyst as the final decision-maker instead of allowing an AI model to make autonomous operational decisions.                                              |
| **Provider abstraction**                              | Keeps the AI integration replaceable so the intelligence layer can support different AI providers without redesigning the entire application.                                 |

## IBM Technologies Used

### IBM BoB AI Innovation Hackathon

CyberFusion was developed as a solution for the **IBM BoB AI Innovation Hackathon 2026** using the official hackathon project structure and submission workflow.

The solution follows an AI-assisted architecture in which AI is used to transform verified security evidence into structured intelligence rather than being responsible for calculating the authoritative threat risk.

### AI Integration

The current implementation uses **Groq AI with the `openai/gpt-oss-120b` model** for the intelligence-generation layer.

The AI receives a controlled context containing verified correlation and risk information and generates:

* BLUF summary
* Threat assessment
* Possible intent
* Evidence-based reasoning
* Evidence summary
* Recommended actions
* AI confidence score

The AI response is parsed and passed through guardrails before being persisted and displayed to the analyst.

**Important:** The AI does not calculate or override the authoritative risk score or priority. This separation ensures that the system's prioritisation remains deterministic and explainable.

### IBM Alignment

The architecture is designed around the problem requirements of the IBM BoB AI Innovation Hackathon, including AI-assisted threat analysis, structured intelligence generation, and human-in-the-loop decision support.

The implementation does **not** claim the use of watsonx.ai or other IBM cloud services unless they are actually configured and used in the deployed application.

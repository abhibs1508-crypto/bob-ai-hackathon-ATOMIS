# Solution Overview

## What We Built

CyberFusion is a Threat Intelligence Correlation & Alert Prioritisation Assistant that helps defence and security analysts turn large volumes of security alerts into a clear, prioritised intelligence picture.

Security information can arrive from different sources such as SIEM systems, cyber sensors, threat-intelligence feeds, and intelligence reports. These sources may describe different parts of the same threat. CyberFusion brings these signals together, identifies relationships between them, determines the urgency of the resulting threat, and presents the findings in a concise intelligence report.

The system combines deterministic correlation and risk analysis with AI-assisted intelligence generation. The risk engine remains authoritative for the risk score and priority, while the AI layer explains the verified evidence and generates a BLUF (Bottom Line Up Front) assessment, possible intent, reasoning, and recommended actions.

The final result is presented through a React-based analyst dashboard, where the human analyst remains responsible for the final decision.

## How It Works

1. **Collect Security Data** — CyberFusion receives structured security events from SIEM systems, cyber sensors, threat-intelligence feeds, and intelligence reports through REST-based ingestion APIs.

2. **Validate and Normalize** — Incoming data is validated and converted into a common structure so that events from different sources can be analyzed consistently.

3. **Store the Evidence** — Normalized events, entities, indicators, and related information are stored in the centralized database.

4. **Correlate Related Events** — The correlation engine analyzes relationships between events using factors such as common source IPs, common targets, timing, IOC matches, repeated activity, cross-source activity, and attack sequences.

5. **Calculate Risk and Priority** — The risk engine evaluates the verified evidence and calculates an authoritative risk score and priority, allowing analysts to focus on the most important threats first.

6. **Generate Intelligence with AI** — The verified correlation and risk context is provided to the AI intelligence layer. Groq AI generates a structured BLUF report containing the threat assessment, possible intent, reasoning, evidence summary, and recommended actions.

7. **Apply AI Guardrails** — The AI response is parsed and validated to prevent unsupported indicators, targets, events, or claims from being presented as facts. The AI cannot change the authoritative risk score or priority.

8. **Present the Intelligence** — The processed information is exposed through REST APIs and displayed in the React analyst dashboard.

9. **Human Analyst Makes the Final Decision** — The analyst reviews the correlated evidence, risk priority, and AI-generated intelligence before taking any operational action.

## Architecture Diagram

> See [`architecture.md`](architecture.md) for the detailed architecture.

```text
┌───────────────────────────────────────────────────────────────┐
│                         DATA SOURCES                          │
│                                                               │
│   SIEM        Cyber Sensors       Threat Intel       Reports  │
└─────────────────────────────┬─────────────────────────────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │  REST INGESTION API │
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │ Validation &        │
                   │ Normalization       │
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │  Supabase Database   │
                   │ Events / Indicators │
                   │ Entities / Evidence │
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │  Correlation Engine │
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │ Risk & Priority     │
                   │ Engine              │
                   └──────────┬──────────┘
                              │
                              ▼
              ┌──────────────────────────────────┐
              │       AI INTELLIGENCE LAYER     │
              │                                  │
              │ Context Builder                  │
              │       ↓                          │
              │ Prompt Builder                   │
              │       ↓                          │
              │ Groq AI                          │
              │       ↓                          │
              │ Response Parser                  │
              │       ↓                          │
              │ AI Guardrails                    │
              └────────────────┬─────────────────┘
                               │
                               ▼
                   ┌─────────────────────┐
                   │ Intelligence Report │
                   │                     │
                   │ BLUF                │
                   │ Threat Assessment   │
                   │ Possible Intent      │
                   │ Evidence             │
                   │ Recommended Actions │
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │    Express REST API  │
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │   React Dashboard   │
                   │ Analyst Console     │
                   └──────────┬──────────┘
                              │
                              ▼
                   ┌─────────────────────┐
                   │   Human Analyst     │
                   │   Final Decision    │
                   └─────────────────────┘
```

## Key Design Decisions

| Decision                                 | Rationale                                                                                                                                                                         |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Multi-source security data ingestion** | Allows CyberFusion to bring together information from different security sources that may describe different parts of the same threat.                                            |
| **Common data normalization**            | Different sources use different field names and formats. Normalization creates a consistent structure for analysis.                                                               |
| **Centralized evidence storage**         | Keeps events, indicators, entities, correlations, risk assessments, and intelligence reports available for analysis and investigation.                                            |
| **Evidence-based correlation engine**    | Uses explainable relationships such as IOC matches, common sources, targets, timing, repeated activity, and cross-source activity rather than treating every alert independently. |
| **Dedicated risk engine**                | Separates threat prioritisation from AI interpretation. The risk engine remains authoritative for the final risk score and priority.                                              |
| **AI as an intelligence assistant**      | AI explains verified evidence and generates structured intelligence instead of independently deciding whether a threat is critical.                                               |
| **AI guardrails**                        | Prevents the AI from inventing indicators, targets, events, or unsupported claims and prevents it from modifying authoritative risk information.                                  |
| **BLUF reporting**                       | Provides the most important conclusion first so analysts and commanders can quickly understand the situation.                                                                     |
| **Human-in-the-loop**                    | The system supports analysts but does not replace human judgement or make autonomous operational decisions.                                                                       |
| **Provider-independent AI architecture** | Separates the AI provider from the rest of the intelligence pipeline, allowing the AI provider or model to be changed without redesigning the entire application.                 |

## IBM Technologies Used

### IBM BoB AI Innovation Hackathon

CyberFusion was developed as a solution for the **IBM BoB AI Innovation Hackathon 2026** and follows the official hackathon repository and submission structure.

The solution applies AI to the threat-intelligence problem by using an AI intelligence layer to transform verified security evidence into a structured assessment that can be reviewed by a human analyst.

### AI-Assisted Intelligence Generation

The current implementation uses **Groq AI with the `openai/gpt-oss-120b` model** for the intelligence-generation component.

The AI receives a controlled context containing verified information from the correlation and risk layers and generates:

* BLUF summary
* Threat assessment
* Possible intent
* Evidence-based reasoning
* Evidence summary
* Recommended actions
* AI confidence score

The generated response is parsed and passed through application-level guardrails before it is stored and displayed.

The AI is deliberately restricted from calculating or modifying the authoritative risk score and priority.

### IBM Technology Alignment

The project architecture is designed around the AI-assisted cybersecurity requirements of the IBM BoB AI Innovation Hackathon.

The implementation does **not** claim the use of IBM watsonx.ai, IBM Granite, or other IBM cloud services unless those services are actually configured and used in the final deployed application.

This distinction ensures that the technical documentation accurately represents the technologies used in the working CyberFusion implementation.

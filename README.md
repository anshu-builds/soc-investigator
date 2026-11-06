# SOC Investigator

<p align="center">
  <strong>AI-Assisted Security Operations & Incident Investigation Platform</strong>
  <br />
  Turn security telemetry into correlated incidents, evidence-backed investigations, and actionable reports.
</p>

<p align="center">
  <a href="https://github.com/anshu-builds/soc-investigator/actions/workflows/ci.yml">
    <img src="https://github.com/anshu-builds/soc-investigator/actions/workflows/ci.yml/badge.svg" alt="CI" />
  </a>
  <img src="https://img.shields.io/badge/Python-3.12-blue?logo=python" alt="Python 3.12" />
  <img src="https://img.shields.io/badge/FastAPI-Backend-009688?logo=fastapi" alt="FastAPI" />
  <img src="https://img.shields.io/badge/Next.js-Frontend-black?logo=next.js" alt="Next.js" />
  <img src="https://img.shields.io/badge/PostgreSQL-Database-4169E1?logo=postgresql" alt="PostgreSQL" />
</p>

---

## Overview

SOC Investigator is a full-stack, AI-assisted Security Operations Center (SOC) investigation platform. It helps analysts process security logs, identify suspicious activity, correlate related events into incidents, inspect supporting evidence, and investigate incidents using natural-language interactions.

The platform combines deterministic detection and correlation logic with AI-assisted investigation and Retrieval-Augmented Generation (RAG). This separation is intentional: event classification and query filtering remain auditable, while language models help analysts interpret incident context and supporting security knowledge.

### Why this project?

Security teams routinely work with large volumes of authentication, endpoint, server, and network events. Investigating a possible attack often means moving between log searches, event timelines, threat intelligence, and reports.

SOC Investigator brings those steps into one workflow:

1. Ingest security events from CSV log files or a configured Wazuh integration.
2. Parse and normalize events into a consistent structure.
3. Detect suspicious patterns such as brute-force attempts, account compromise, and privilege escalation.
4. Correlate related events and create incidents with supporting evidence.
5. Map recognized attack patterns to relevant MITRE ATT&CK techniques.
6. Let analysts explore incident context through natural-language queries and investigation chat.
7. Generate structured incident reports for review and export.

---

## Investigation workflow

```text
          CSV Logs                         Wazuh
              |                 (Webhook / API Polling)
              |                              |
              +---------------+--------------+
                              |
                       Log Ingestion
                              |
                    Parsing & Normalization
                              |
                       Detection Engine
                              |
                    Event Correlation
                              |
                       Incident Store
                              |
                +-------------+-------------+
                |             |             |
             Evidence      Timeline     MITRE ATT&CK
                |             |          Mapping
                +-------------+-------------+
                              |
                  Analyst Investigation
                              |
              +---------------+---------------+
              |                               |
       Natural-language queries         AI investigation
       (deterministic NLU)            (LLM + retrieved context)
              |                               |
              +---------------+---------------+
                              |
                    Incident Reporting
                              |
                     HTML / PDF output
```

The diagram represents the investigation flow. Optional integrations, such as Wazuh polling and external LLM providers, require their respective configuration.

---

## Key capabilities

| Area | What it does |
|---|---|
| Log ingestion | Accepts CSV uploads and processes security events through the backend pipeline. |
| Detection | Identifies supported suspicious patterns, including brute force, account compromise, and privilege escalation. |
| Event correlation | Groups related security events and builds incident hypotheses from observed activity. |
| Evidence management | Associates source events with incidents so analysts can inspect the underlying evidence. |
| Incident timeline | Organizes related activity chronologically to support investigation. |
| MITRE ATT&CK mapping | Maps supported attack classifications to registered ATT&CK techniques. |
| Natural-language queries | Uses deterministic entity extraction, intent classification, and SQL translation for supported security questions. |
| AI investigation | Uses an LLM-assisted investigation chain with incident context and retrieved security knowledge. |
| RAG knowledge retrieval | Uses ChromaDB and sentence-transformer embeddings to retrieve security knowledge and response playbooks. |
| Incident reporting | Generates structured investigation reports, with report export support in the application. |
| Analyst access | Provides JWT-based authentication, role-aware authorization, and audit events. |
| Wazuh integration | Supports webhook ingestion and optional Wazuh REST API polling. |
| Optional text-to-speech | Provides an optional Sarvam TTS integration, disabled by default. |

> **Important:** Detection coverage is based on the rules and classifications implemented in this repository. MITRE mappings are rule-based associations, not proof that a technique occurred. Analysts should validate every finding against its evidence.

---

## Architecture and technology stack

### Frontend
- **Next.js** — web application framework.
- **React** — interactive user interface.
- **TypeScript** — typed frontend development.
- **Tailwind CSS** — utility-first styling.
- **Recharts** — data visualization.
- **Lucide React** — interface icons.

### Backend
- **Python 3.12** — application runtime used by CI.
- **FastAPI** — API framework.
- **SQLAlchemy 2** — database access and ORM.
- **Pydantic** — request validation and settings.
- **Alembic** — database migration tooling.
- **Uvicorn** — ASGI server.

### Data and retrieval
- **PostgreSQL 16** — persistent application data.
- **ChromaDB** — vector storage for RAG.
- **Sentence Transformers** — embedding generation.
- **MITRE ATT&CK** — technique reference data.
- **Markdown / Jinja2** — report rendering support.

### AI providers
- **Google Gemini** — configurable LLM provider.
- **OpenAI** — alternative configurable LLM provider.

The configured provider is selected using `LLM_PROVIDER`. Provider credentials are supplied through environment variables.

### Infrastructure
- **Docker & Docker Compose** — local multi-service environment.
- **Nginx** — reverse proxy.
- **GitHub Actions** — CI workflows.

---

## System architecture

The repository is organized around separate responsibilities:

| Directory | Responsibility |
|---|---|
| `backend/` | FastAPI application, API routes, authentication, database access, integrations, and services. |
| `frontend/` | Next.js analyst interface. |
| `detection/` | Detection logic for supported security activity patterns. |
| `correlation/` | Event correlation, hypothesis generation, timeline construction, and ATT&CK mapping. |
| `ai/` | LLM client, investigation chain, context construction, evidence linking, summaries, and NLU components. |
| `rag/` | Vector retrieval, fallback retrieval, and knowledge ingestion. |
| `knowledge/` | Security knowledge and incident response playbooks. |
| `datasets/` | Synthetic event generators and sample CSV datasets. |
| `reports/` | Incident report templates. |
| `alembic/` | Database migration history. |
| `nginx/` | Reverse-proxy configuration. |
| `tests/` | Unit and integration tests. |

---

## Getting started

### Prerequisites

For the Docker-based setup, install:

- Git
- Docker Desktop or Docker Engine
- Docker Compose v2

For development outside Docker, also install:

- Python 3.12
- Node.js 20
- npm

### 1. Clone the repository

```bash
git clone https://github.com/anshu-builds/soc-investigator.git
cd soc-investigator
```

### 2. Configure environment variables

Create your local environment file:

```bash
cp .env.example .env
```

At minimum, review and set secure values for:

- `POSTGRES_PASSWORD`
- `JWT_SECRET_KEY`
- `CHROMA_AUTH_TOKEN`
- Your selected LLM provider API key, if AI investigation is required.

For Gemini:

```env
LLM_PROVIDER=gemini
GEMINI_API_KEY=your_gemini_api_key
```

Or for OpenAI:

```env
LLM_PROVIDER=openai
OPENAI_API_KEY=your_openai_api_key
```

Keep `.env` private. Never commit real API keys, passwords, or signing secrets.

### 3. Start the application

Build and start the services:

```bash
docker compose up --build -d
```

Check service status:

```bash
docker compose ps
```

Follow backend logs:

```bash
docker compose logs -f backend
```

Stop the stack:

```bash
docker compose down
```

To also remove persistent database, vector-store, and report volumes:

```bash
docker compose down -v
```

> **Warning:** `docker compose down -v` permanently deletes the named volumes and their stored data.

### 4. Open the application

| Service | Local address |
|---|---|
| Web application | http://localhost:3000 |
| Nginx entry point | http://localhost |
| Backend API | http://localhost:8000 |
| Interactive API docs | http://localhost:8000/docs |
| Backend health | http://localhost:8000/health |
| ChromaDB | http://localhost:8001 |

The backend seeds an initial analyst account using `SEED_ADMIN_EMAIL` and `SEED_ADMIN_PASSWORD` when it initializes. The example values are for local development only. Change them before use and never deploy the example credentials.

---

## Environment configuration

The complete environment template is available in [`.env.example`](.env.example). The main settings include:

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | Async SQLAlchemy database connection. |
| `DATABASE_SYNC_URL` | Synchronous database connection used by migration tooling. |
| `POSTGRES_DB` | PostgreSQL database name. |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` | PostgreSQL credentials. |
| `JWT_SECRET_KEY` | Secret used to sign access tokens. |
| `JWT_ALGORITHM` | JWT signing algorithm. |
| `JWT_EXPIRE_MINUTES` | Access-token lifetime. |
| `LLM_PROVIDER` | Selects `gemini` or `openai`. |
| `GEMINI_API_KEY` | Gemini API credential. |
| `OPENAI_API_KEY` | OpenAI API credential. |
| `CHROMA_HOST` / `CHROMA_PORT` | ChromaDB connection settings. |
| `CHROMA_AUTH_TOKEN` | ChromaDB authentication token. |
| `WAZUH_WEBHOOK_SECRET` | Secret for authenticating Wazuh webhook events. |
| `WAZUH_API_ENABLED` | Enables the optional Wazuh polling integration. |
| `SARVAM_TTS_ENABLED` | Enables optional Sarvam text-to-speech. |
| `SARVAM_API_KEY` | Sarvam API credential. |
| `REPORTS_DIR` | Report output directory. |
| `CORS_ORIGINS` | Allowed frontend origins. |

The Docker Compose file provides container-specific defaults and internal service hostnames. When running services directly on the host, use host-accessible values such as `localhost` where appropriate.

---

## Working with sample data

The repository includes sample security-event data and generators for supported scenarios.

Sample files are located in `datasets/samples/`, including:

- `brute_force_sample.csv`
- `account_compromise_sample.csv`
- `privilege_escalation_sample.csv`
- `mixed_scenario.csv`

Generate the sample datasets from the repository root:

```bash
python datasets/generators/generate_all.py
```

The generators create synthetic events for development and testing. They are not real production telemetry.

### Uploading logs

1. Sign in to the application.
2. Open the log ingestion workflow.
3. Select a supported CSV file.
4. Submit the upload.
5. Review the ingestion result and inspect any generated incidents.

The backend enforces a 10 MB upload limit and a configurable maximum event count. Invalid CSV input is rejected rather than silently accepted.

---

## Natural-language investigation and AI

SOC Investigator has two complementary investigation paths.

### Deterministic natural-language query path

The NLU query endpoint uses a structured pipeline:

1. Entity extraction.
2. Intent classification.
3. Query specification construction.
4. SQL translation and execution.
5. A structured answer with resolved filters and result metadata.

This path is designed to make supported filters and query behavior inspectable. It does not require an LLM call for the query execution path.

### AI-assisted investigation path

The AI investigation chain uses incident context and retrieved security knowledge to help explain observed activity. The repository includes components for context construction, evidence linking, prompt templates, prompt sanitization, LLM provider access, and summary generation.

AI-generated explanations should be treated as analyst assistance, not as an autonomous verdict. Verify conclusions against the incident's source events and evidence.

### Retrieval-Augmented Generation

The RAG components use ChromaDB and sentence-transformer embeddings. The repository includes ingestion scripts for MITRE ATT&CK data and local response playbooks, alongside a fallback retriever.

The MITRE ingestion script retrieves the Enterprise ATT&CK STIX dataset from the official MITRE CTI repository. It validates the source URL and enforces a maximum download size before parsing.

---

## Wazuh integration

The backend includes a Wazuh adapter, API client, and poller.

Two integration modes are represented in the configuration:

- **Webhook ingestion:** Wazuh can push alerts to the application through the webhook integration.
- **REST API polling:** The backend can periodically retrieve alerts when `WAZUH_API_ENABLED=true` and the Wazuh API connection details are configured.

Relevant environment variables:

```env
WAZUH_WEBHOOK_SECRET=replace_with_a_random_secret

WAZUH_API_ENABLED=false
WAZUH_API_URL=https://your-wazuh-manager:55000
WAZUH_API_USERNAME=your_wazuh_username
WAZUH_API_PASSWORD=your_wazuh_password
WAZUH_API_VERIFY_SSL=true
WAZUH_POLL_INTERVAL_SECONDS=30
WAZUH_API_REQUEST_TIMEOUT=15
WAZUH_API_INITIAL_LOOKBACK_MINUTES=60
```

Keep TLS verification enabled outside isolated development environments. Do not expose Wazuh credentials in source control.

---

## API overview

The backend exposes a FastAPI application with interactive OpenAPI documentation at `/docs`.

Implemented API areas include:

| Area | Example route | Purpose |
|---|---|---|
| Health | `GET /health` | Service health check. |
| Authentication | `POST /api/auth/login` | Authenticate and receive a JWT. |
| Natural-language query | `POST /api/nlu/query` | Submit a security question. |
| Log ingestion | `POST /api/logs/upload` | Upload and process a log file. |
| Logs | `GET /api/logs` | Retrieve security events with filters and pagination. |
| Incidents | `GET /api/incidents` | List incidents with filters and pagination. |
| Incident detail | `GET /api/incidents/{incident_id}` | Retrieve incident details. |
| Incident status | `PATCH /api/incidents/{incident_id}/status` | Update incident status. |
| Evidence | `GET /api/incidents/{incident_id}/evidence` | Retrieve incident evidence. |
| Wazuh status | `GET /api/integrations/wazuh/status` | Inspect Wazuh integration status. |

Additional routes cover investigation sessions, chat, reporting, and integration operations. The live OpenAPI schema at `/docs` is the source of truth for request fields, response schemas, and authentication requirements.

Most investigation and data routes require a valid JWT. Wazuh polling operations have admin-level access requirements.

---

## Development

### Backend

Create and activate a virtual environment:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
```

Install backend dependencies:

```bash
python -m pip install --upgrade pip
pip install -r backend/requirements.txt
```

Start the API from the repository root:

```bash
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

The backend requires a reachable database and correctly configured environment variables.

### Frontend

In a separate terminal:

```bash
cd frontend
npm ci
npm run dev
```

The frontend uses `NEXT_PUBLIC_API_URL` to locate the API. For local development, the example value is `http://localhost:8000`.

### Database migrations

Alembic configuration and migration history are included in the repository. Review the configured database URL before running migration commands against any non-development database.

---

## Testing

The project contains unit and integration tests covering detection, correlation, NLU, RAG, authentication, reporting, Wazuh integration, and security-sensitive behavior.

Run the backend test suite from the repository root:

```bash
pip install -r backend/requirements.txt
pip install pytest pytest-asyncio
PYTHONPATH=. pytest -q
```

Run the frontend production build:

```bash
cd frontend
npm ci
npm run build
```

GitHub Actions runs backend tests and a frontend build for configured pushes and pull requests targeting `main`.

---

## Security considerations

Security is a core part of a platform that handles potentially sensitive telemetry. The repository includes controls such as:

- JWT-based authentication and role-aware authorization.
- Password hashing and login rate limiting.
- Rate limits for selected resource-intensive operations.
- Audit logging for important analyst and integration actions.
- Input validation and bounded log-upload processing.
- Security response headers and configurable CORS origins.
- Prompt sanitization and report-output sanitization.
- URL validation for SSRF-sensitive outbound requests.
- ChromaDB token authentication in the Compose configuration.
- Production checks for weak JWT secrets and default seed credentials.

These controls do not by themselves establish that a deployment is secure. Before production use, operators should configure unique secrets, TLS, backups, least-privilege access, network restrictions, monitoring, and a deployment-specific security review.

**Do not use the example credentials or development defaults in a public or production deployment.**

---

## Project status and scope

This repository is an actively developed engineering project. Its capabilities depend on the implementation and configuration present in the selected revision.

A few scope notes:

- Detection logic currently covers the attack patterns represented by the implemented rules and hypotheses; it is not a universal IDS.
- MITRE ATT&CK associations are rule-based mappings and should be validated by analysts.
- Natural-language SQL querying is deterministic for supported intents and entities; it should not be interpreted as unrestricted conversational database access.
- AI investigation depends on a configured external provider and retrieved context. Model output can be incomplete or incorrect.
- Wazuh polling is optional and requires a reachable, correctly configured Wazuh API.
- Text-to-speech is optional and disabled by default.
- Synthetic datasets are provided for testing and demonstration; they do not represent real-world detection performance.

---

## Roadmap

Potential areas for continued development:

- Expand detection coverage and add configurable detection rules.
- Improve correlation across more event sources and identity contexts.
- Add richer analyst feedback and investigation state tracking.
- Expand integrations with SIEM and endpoint telemetry platforms.
- Improve observability, deployment hardening, and operational documentation.
- Add reproducible evaluation datasets and documented detection metrics.

Roadmap items are proposals, not commitments or claims of existing functionality.

---

## Contributing

Contributions, bug reports, and technical suggestions are welcome.

1. Fork the repository.
2. Create a focused branch for your change.
3. Add or update tests where appropriate.
4. Run the backend tests and frontend build.
5. Open a pull request with a clear description of the problem and solution.

Please avoid including real security logs, credentials, private infrastructure details, or other sensitive data in issues and pull requests.

---

## Author

**Anshu Jaiswal**

- GitHub: [@anshu-builds](https://github.com/anshu-builds)
- Project: [SOC Investigator](https://github.com/anshu-builds/soc-investigator)

---

## Disclaimer

SOC Investigator is intended for educational, research, and defensive security operations use. It is an analyst-assistance tool, not a replacement for a qualified security team, a production incident-response process, or independent verification of security findings.

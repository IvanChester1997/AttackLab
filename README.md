# AttackLab

**AttackLab** is an automated security assessment platform for authorized defensive security testing.

It combines network reconnaissance, service enumeration, vulnerability mapping, Linux security auditing, risk scoring, and report generation into a Python application with REST API and CLI interfaces.

> **Security scope:** AttackLab is intended for systems and environments you own or are explicitly authorized to assess. It does not provide exploitation functionality.

## Features

### Network assessment
- Host discovery
- TCP port scanning with Nmap
- Service and version enumeration
- CPE extraction
- Vulnerability mapping through the NVD API
- CVSS metadata collection

### Linux security audit
- SSH-based system auditing
- User and privileged-account analysis
- Service-account checks
- Privileged group membership checks
- SSH hardening and host-key checks
- authorized_keys checks
- World-writable file checks
- SUID/SGID checks
- Cron and writable-cron checks
- Password-policy checks
- sudo and NOPASSWD checks
- Firewall input-policy checks
- Listening TCP/UDP service checks

### Risk and reporting
- Finding severity classification
- Risk score and risk level
- Evidence attached to findings
- JSON reports
- HTML reports
- SQLite scan history

### API and automation
- FastAPI REST API
- Background assessment jobs
- OpenAPI / Swagger
- ReDoc
- Health endpoint
- Configurable NVD endpoint

## Architecture

```text
CLI / REST API
      |
      v
   Services
      |
      +-- Assessment
      +-- Vulnerability Assessment
      +-- NVD Client
      +-- Risk Engine
      +-- Reporting
      |
      v
   Scanners
      |
      +-- Nmap
      +-- Linux Audit
      |
      v
 Connectors / External Systems
      |
      +-- SSH
      +-- NVD
      +-- Target Hosts
```

The API and CLI remain thin entry points while assessment logic is implemented in reusable services and scanners.

## Tech Stack

- Python 3.13
- FastAPI
- Typer
- Pydantic
- SQLite / aiosqlite
- Paramiko
- Nmap
- Uvicorn
- Docker
- pytest / pytest-cov
- Ruff
- pip-audit

## Project Structure

```text
AttackLab/
├── app/
│   ├── api/
│   ├── cli/
│   ├── connectors/
│   ├── core/
│   ├── database/
│   ├── models/
│   ├── reporting/
│   ├── scanners/
│   └── services/
├── lab/
│   ├── target/
│   └── nvd-mock/
├── tests/
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── README.md
```

## Quick Start

### Local installation

```bash
git clone git@github.com:IvanChester1997/AttackLab.git
cd AttackLab
python3.13 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Start the API:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

The API will be available at:

```text
http://127.0.0.1:8000
http://127.0.0.1:8000/docs
http://127.0.0.1:8000/redoc
http://127.0.0.1:8000/openapi.json
```

Health check:

```bash
curl http://127.0.0.1:8000/health
```

Expected response:

```json
{"status":"healthy"}
```

## CLI

Show version:

```bash
python -m app.cli.main version
```

Run a security audit:

```bash
python -m app.cli.main audit 127.0.0.1
```

Specify ports:

```bash
python -m app.cli.main audit 127.0.0.1 --ports 22,80,443
```

Run Linux auditing over SSH:

```bash
python -m app.cli.main audit 127.0.0.1 --user root --ssh-port 2222 --key ~/.ssh/id_ed25519
```

Write a JSON report:

```bash
python -m app.cli.main audit 127.0.0.1 --output reports/assessment.json
```

Write an HTML report:

```bash
python -m app.cli.main audit 127.0.0.1 --output reports/assessment.html
```

Run the scan workflow:

```bash
python -m app.cli.main scan 127.0.0.1 --ports 22,80,443
```

## REST API

Base path:

```text
/api/v1
```

### Start an assessment

```http
POST /api/v1/assessments
```

Example:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/assessments \
  -H "Content-Type: application/json" \
  -d '{"target":"127.0.0.1","ports":"22,80,443"}'
```

The API returns `202 Accepted` and creates a background assessment.

Example response:

```json
{
  "id": 1,
  "status": "pending",
  "report": null,
  "error_message": null
}
```

Assessment lifecycle:

```text
pending -> running -> completed
                    \-> failed
```

### Get an assessment

```http
GET /api/v1/scans/{scan_id}
```

Example:

```bash
curl http://127.0.0.1:8000/api/v1/scans/1
```

### List scan history

```http
GET /api/v1/scans
```

Example:

```bash
curl "http://127.0.0.1:8000/api/v1/scans?limit=20"
```

The default limit is 50 and the maximum is 100.

## Docker Lab

The repository provides a reproducible Docker laboratory containing the AttackLab application, a target container, and a local NVD-compatible mock service.

Start the lab:

```bash
docker compose up -d --build
```

API:

```text
http://127.0.0.1:8000
```

Target mappings:

```text
2121 -> FTP
2222 -> SSH
2323 -> Telnet
8080 -> HTTP
```

Stop the lab:

```bash
docker compose down
```

The AttackLab image runs as a non-root user and includes a health check against `/health`.

The NVD endpoint is configurable through `NVD_BASE_URL`, which allows the real NVD service to be replaced by the deterministic local mock used by integration tests.

## Configuration

Application data:

```text
data/attacklab.db
```

Generated reports:

```text
reports/
```

NVD endpoint:

```text
NVD_BASE_URL
```

## Security Scope

AttackLab is intended for authorized security assessment.

The project focuses on reconnaissance, enumeration, vulnerability mapping, defensive Linux auditing, evidence collection, risk assessment, and reporting.

It intentionally does not implement exploitation workflows.

SSH-based auditing requires valid credentials or a valid private key and authorization to access the target.

## Testing

Run the local quality gate:

```bash
ruff check app tests
ruff format --check app tests
pip-audit -r requirements.txt
pytest -q --cov=app --cov-fail-under=90
```

Current baseline:

```text
170 passed
3 deselected
92.27% coverage
```

Integration tests are marked separately and run by CI in a Docker environment.

## CI

GitHub Actions validates:

- Python quality checks
- Docker image build
- End-to-end integration testing

The E2E environment starts the AttackLab application, lab target, and NVD mock and validates the complete assessment workflow.

## API Documentation

When the API is running:

- Swagger UI: `/docs`
- ReDoc: `/redoc`
- OpenAPI: `/openapi.json`

## Engineering Principles

- Keep security checks deterministic and testable.
- Isolate external integrations.
- Keep API and CLI layers thin.
- Prefer small, composable services.
- Persist assessment history.
- Attach evidence to findings.
- Validate targets before scanning.
- Keep CI reproducible.
- Avoid exploitation functionality.

## Roadmap

- Improve API examples and documentation
- Release version `1.0.0`
- Create a Git tag and release
- Clean up dependency warnings
- Improve NVD retry, rate-limit, and pagination handling where justified
- Remove technical debt around legacy scan persistence
- Document the background-job architecture

## License

No license has been declared yet.

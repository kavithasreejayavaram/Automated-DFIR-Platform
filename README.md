# TraceForensics — Automated Digital Forensics & Incident Response (DFIR) Platform

**TraceForensics** is a defensive, professional-grade Digital Forensics and Incident Response (DFIR) web platform designed for security analysts, incident responders, and forensic specialists. It streamlines system/auth log ingestion, UTC normalization, explainable rule-based threat detection (mapped to MITRE ATT&CK), incident timeline reconstruction, threat intelligence IOC correlation, SHA-256 evidence vault integrity tracking, and downloadable PDF/JSON report generation.

---

## Key Capabilities

- **Log Ingestion & Normalization Engine**: Multi-format support (CSV, JSON, JSONL, Syslog) with automatic UTC timestamp conversion, schema normalization, duplicate detection, and file size safeguards.
- **SHA-256 Evidence Vault**: Calculates SHA-256 cryptographic hashes upon intake, tracks file acquisition metadata, and provides live integrity re-verification tools.
- **Transparent Detection Engine**: Explainable, rule-based detection heuristics mapped to MITRE ATT&CK techniques (Brute Force, Success Post-Failure, Suspicious Process Execution, Privilege Escalation, Log Tampering, Unusual IP Logins).
- **Incident Correlation & Interactive Timeline**: Groups related alerts by entity (host, user, IP) within time windows into correlated incident cases with an interactive chronological timeline and analyst investigation notes.
- **Threat Intelligence Hub**: Matches extracted IP, domain, hash, and URL indicators against local IOC databases, with configurable mock external API lookup integration.
- **Downloadable Investigation Reports**: Export formal PDF investigation reports (via ReportLab) and structured JSON exports containing incident metadata, timeline events, rule hits, IOC matches, evidence checksums, and legal disclaimers.
- **System & Analyst Audit Trail**: Comprehensive audit logging for all authentication, evidence upload, note posting, rule modification, and report export operations.
- **Automated Precision & Recall Benchmark**: Evaluation runner measuring detection precision, recall, and F1 score on synthetic attack datasets.

---

## Technology Stack

- **Frontend**: React 18, Vite, TypeScript, Tailwind CSS, Recharts, Lucide React, React Router.
- **Backend**: Python 3.12, FastAPI, SQLAlchemy ORM, Pydantic v2, Pandas, ReportLab, PyJWT, Bcrypt.
- **Database**: SQLite (default zero-setup local dev) with native PostgreSQL support via `DATABASE_URL`.
- **Testing**: `pytest` for backend APIs & detection engine; `vitest` for frontend components.

---

## Demo Account Credentials

The platform initializes with seeded demo user accounts:

| Role | Username | Password | Email |
| :--- | :--- | :--- | :--- |
| **Security Analyst** | `analyst` | `analyst123` | `analyst@traceforensics.org` |
| **System Administrator** | `admin` | `admin123` | `admin@traceforensics.org` |

---

## Quick Start & Running the Application

### 1. Backend Server Setup

```bash
cd backend
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
The FastAPI backend server will start at `http://127.0.0.1:8000`. API documentation is available at `http://127.0.0.1:8000/docs`.

### 2. Frontend Development Server Setup

Open a second terminal window:

```bash
cd frontend
npm install
npm run dev
```
The React frontend application will start at `http://localhost:3000`.

---

## Automated Test Suites & Evaluation Benchmark

### Run Backend Pytest Suite

```bash
cd backend
python -m pytest tests/
```

### Run Benchmark Evaluation Script

```bash
cd backend
python -m app.scripts.evaluate
```

### Run Frontend Build & Tests

```bash
cd frontend
npm run build
npm test
```

---

## Documentation Links

- [System Architecture & ER Diagram](docs/ARCHITECTURE.md)
- [Detection Rules Specifications](docs/DETECTION_RULES.md)
- [Threat Model & Legal Limitations Disclaimer](docs/THREAT_MODEL.md)

---

## Legal & Academic Disclaimer

TraceForensics is developed as a portfolio and academic demonstration project. Rule-based detections identify suspicious activity patterns based on heuristic thresholds and do not constitute legal proof of compromise. SHA-256 evidence hashing demonstrates data integrity within the platform but does not replace physical write-blockers or formal legal chain of custody required for judicial proceedings.

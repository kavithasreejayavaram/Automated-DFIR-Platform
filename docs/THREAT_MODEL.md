# Threat Model & Legal Limitation Disclaimers

## 1. Threat Model

TraceForensics is designed as a defensive incident response and log analysis platform.

### Assets Protected:
- Ingested system & authentication logs.
- Evidence cryptographic SHA-256 hashes & raw files.
- Incident investigation records & analyst notes.
- System audit trail logs.

### Potential Risk Vectors & Countermeasures:
- **Unsafe File Ingestion & Code Execution**: Content uploaded via the log ingestion module is parsed strictly as data streams (CSV, JSON, JSONL). Data is stored inertly on disk and never executed on the host system.
- **Unauthorized Data Modification**: Role-Based Access Control (RBAC) enforces distinct Administrator (`admin`) and Analyst (`analyst`) roles. Administrative actions (user creation, rule toggling) are restricted by JWT claim validation.
- **Evidence Tampering**: All raw uploads have their SHA-256 checksum recorded upon initial intake. Live verification endpoints allow analysts to re-compute hashes on demand.

## 2. Legal Limitations & Chain of Custody Disclaimer

> **IMPORTANT LEGAL NOTICE:**
> TraceForensics provides cryptographic hashing (SHA-256) and audit logging to assist in verifying data integrity within the application ecosystem.
> 
> However, an application-layer SHA-256 hash and audit log **do not guarantee legally admissible or tamper-proof evidence** in judicial court proceedings. Legal digital forensics standards (e.g. ISO/IEC 27037) require physical write-blockers, verified hardware acquisition, documented physical chain-of-custody transfer forms, and certified forensic tool validation.
> 
> Furthermore, rule-based detection alerts indicate **potential suspicious activity patterns** derived from heuristic thresholds. They do not constitute definitive proof of malicious attack or system compromise.

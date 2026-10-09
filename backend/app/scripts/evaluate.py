import os
import glob
from sqlalchemy.orm import Session
from app.db.database import SessionLocal, engine, Base
from app.db.models import NormalizedEvent, Alert, EvidenceFile, Incident, IncidentEvent
from app.engine.ingestion import LogIngestionEngine
from app.engine.detection import DetectionEngine
from app.schemas.schemas import BenchmarkResult

def run_evaluation_benchmark(db: Session) -> BenchmarkResult:
    dataset_dir = "datasets"
    if not os.path.exists(dataset_dir):
        dataset_dir = "backend/datasets"

    scenarios = [
        ("brute_force_attack.csv", True, 2),        # Expects >=2 alerts (Brute Force + Success post fail)
        ("suspicious_process_exec.jsonl", True, 3), # Expects 3 alerts (powershell -enc, mimikatz, certutil)
        ("privilege_escalation.csv", True, 2),      # Expects 2 alerts (Group added + Log cleared)
        ("benign_corporate_noise.json", False, 0)   # Expects 0 alerts (Clean background noise)
    ]

    total_logs = 0
    tp = 0
    fp = 0
    fn = 0

    detection_summary = {}

    for filename, is_malicious, expected_alert_count in scenarios:
        filepath = os.path.join(dataset_dir, filename)
        if not os.path.exists(filepath):
            continue

        with open(filepath, "rb") as f:
            content = f.read()

        normalized_records, sha256_hash, line_count = LogIngestionEngine.process_file_content(content, filename)
        total_logs += len(normalized_records)

        # Create temporary evidence file session context
        ev_file = EvidenceFile(
            filename=f"Benchmark_{filename}",
            file_path=filepath,
            file_size=len(content),
            sha256_hash=sha256_hash,
            line_count=line_count
        )
        db.add(ev_file)
        db.flush()

        events_db = []
        for rec in normalized_records:
            ev = NormalizedEvent(
                evidence_file_id=ev_file.id,
                timestamp=rec["timestamp"],
                hostname=rec["hostname"],
                username=rec["username"],
                source_ip=rec["source_ip"],
                destination_ip=rec["destination_ip"],
                event_type=rec["event_type"],
                event_description=rec["event_description"],
                process_name=rec["process_name"],
                auth_result=rec["auth_result"],
                raw_record=rec["raw_record"],
                event_hash=rec.get("event_hash")
            )
            db.add(ev)
            events_db.append(ev)

        db.commit()

        # Run rules
        alerts = DetectionEngine.run_rules_on_events(db, events_db, ev_file.id)
        detected_count = len(alerts)
        detection_summary[filename] = detected_count

        if is_malicious:
            tp += min(detected_count, expected_alert_count)
            if detected_count < expected_alert_count:
                fn += (expected_alert_count - detected_count)
            elif detected_count > expected_alert_count:
                fp += (detected_count - expected_alert_count)
        else:
            fp += detected_count

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return BenchmarkResult(
        total_logs_processed=total_logs,
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1, 4),
        detection_summary=detection_summary
    )

if __name__ == "__main__":
    db = SessionLocal()
    res = run_evaluation_benchmark(db)
    print("Benchmark Results:", res.model_dump())

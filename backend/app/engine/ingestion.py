import hashlib
import json
import os
from datetime import datetime, timezone
import dateutil.parser
import pandas as pd
from typing import List, Tuple, Dict, Any

def compute_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()

def normalize_timestamp(val: Any) -> datetime:
    if pd.isna(val) or val is None or str(val).strip() == "":
        return datetime.now(timezone.utc)
    try:
        if isinstance(val, (int, float)):
            # Epoch timestamp
            return datetime.fromtimestamp(val, tz=timezone.utc)
        dt = dateutil.parser.parse(str(val))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt
    except Exception:
        return datetime.now(timezone.utc)

def compute_event_hash(record: Dict[str, Any]) -> str:
    sig = f"{record.get('timestamp')}|{record.get('hostname')}|{record.get('username')}|{record.get('event_type')}|{record.get('event_description')}"
    return hashlib.sha256(sig.encode('utf-8')).hexdigest()

class LogIngestionEngine:
    @staticmethod
    def process_file_content(content: bytes, filename: str) -> Tuple[List[Dict[str, Any]], str, int]:
        sha256_hash = compute_sha256(content)
        ext = os.path.splitext(filename)[1].lower()
        records: List[Dict[str, Any]] = []

        if ext == '.csv':
            df = pd.read_csv(pd.io.common.BytesIO(content))
            records = df.to_dict(orient='records')
        elif ext == '.json':
            data = json.loads(content.decode('utf-8'))
            if isinstance(data, list):
                records = data
            elif isinstance(data, dict):
                records = [data]
        elif ext in ['.jsonl', '.log', '.txt']:
            lines = content.decode('utf-8', errors='replace').splitlines()
            for line in lines:
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    obj = json.loads(line_str)
                    records.append(obj)
                except Exception:
                    # Generic line parser fallback
                    records.append({
                        "event_description": line_str,
                        "event_type": "SYSLOG"
                    })
        else:
            raise ValueError(f"Unsupported file format extension: {ext}. Allowed formats: CSV, JSON, JSONL, LOG")

        normalized_events = []
        line_count = len(records)
        seen_hashes = set()

        for idx, rec in enumerate(records):
            # Extract fields flexibly
            raw_str = json.dumps(rec) if isinstance(rec, dict) else str(rec)

            ts_raw = rec.get("timestamp") or rec.get("TimeGenerated") or rec.get("time") or rec.get("date") or rec.get("@timestamp")
            dt_utc = normalize_timestamp(ts_raw)

            hostname = str(rec.get("hostname") or rec.get("host") or rec.get("Computer") or rec.get("system_name") or "UNKNOWN_HOST")
            username = str(rec.get("username") or rec.get("user") or rec.get("TargetUserName") or rec.get("account") or "UNKNOWN_USER")
            src_ip = str(rec.get("source_ip") or rec.get("src_ip") or rec.get("IpAddress") or rec.get("client_ip") or "")
            dst_ip = str(rec.get("destination_ip") or rec.get("dest_ip") or rec.get("dst_ip") or rec.get("server_ip") or "")
            
            event_type = str(rec.get("event_type") or rec.get("EventID") or rec.get("action") or rec.get("type") or "SYSTEM_EVENT")
            event_desc = str(rec.get("event_description") or rec.get("message") or rec.get("Message") or rec.get("desc") or "")
            process_name = str(rec.get("process_name") or rec.get("process") or rec.get("Image") or rec.get("command") or "")
            auth_result = str(rec.get("auth_result") or rec.get("status") or rec.get("result") or "").upper()

            if not auth_result:
                if "failed" in event_desc.lower() or "failure" in event_desc.lower() or "4625" in event_type:
                    auth_result = "FAILURE"
                elif "success" in event_desc.lower() or "4624" in event_type:
                    auth_result = "SUCCESS"
                else:
                    auth_result = "UNKNOWN"

            event_dict = {
                "timestamp": dt_utc,
                "hostname": hostname,
                "username": username,
                "source_ip": src_ip if src_ip else None,
                "destination_ip": dst_ip if dst_ip else None,
                "event_type": event_type,
                "event_description": event_desc,
                "process_name": process_name if process_name else None,
                "auth_result": auth_result,
                "raw_record": raw_str
            }

            ev_hash = compute_event_hash(event_dict)
            if ev_hash not in seen_hashes:
                seen_hashes.add(ev_hash)
                event_dict["event_hash"] = ev_hash
                normalized_events.append(event_dict)

        return normalized_events, sha256_hash, line_count

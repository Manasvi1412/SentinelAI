"""
Lightweight JSON file-based storage.
No SQLAlchemy, no dotenv — zero extra dependencies beyond Flask.
"""
import json, os, time
from threading import Lock

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'data.json')
_lock = Lock()

_DEFAULT = {"logs": [], "alerts": [], "intel": [], "_id_counters": {"logs": 0, "alerts": 0, "intel": 0}}

def _load():
    if not os.path.exists(DB_PATH):
        return _DEFAULT.copy()
    try:
        with open(DB_PATH, 'r') as f:
            return json.load(f)
    except Exception:
        return _DEFAULT.copy()

def _save(data):
    with open(DB_PATH, 'w') as f:
        json.dump(data, f, indent=2)

def _next_id(data, table):
    data["_id_counters"][table] += 1
    return data["_id_counters"][table]

def now_ts():
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())

# ── Logs ─────────────────────────────────────────────────────────────────────
def add_log(source_ip, event_type, username, status, raw_log=''):
    with _lock:
        data = _load()
        entry = {
            "id": _next_id(data, "logs"),
            "timestamp": now_ts(),
            "source_ip": source_ip,
            "event_type": event_type,
            "username": username,
            "status": status,
            "raw_log": raw_log
        }
        data["logs"].append(entry)
        # Keep last 2000 logs to avoid huge file
        if len(data["logs"]) > 2000:
            data["logs"] = data["logs"][-2000:]
        _save(data)
        return entry

def get_logs(limit=100):
    data = _load()
    return list(reversed(data["logs"][-limit:]))

def get_logs_since(minutes, status=None, event_type=None):
    import time as t
    cutoff = t.time() - minutes * 60
    data = _load()
    result = []
    for log in data["logs"]:
        ts = time.strptime(log["timestamp"], '%Y-%m-%d %H:%M:%S')
        if time.mktime(ts) >= cutoff:
            if status and log["status"] != status:
                continue
            if event_type and log["event_type"] != event_type:
                continue
            result.append(log)
    return result

import time

# ── Alerts ───────────────────────────────────────────────────────────────────
def add_alert(alert_type, severity, source_ip, description, mitre_id, mitre_technique, tactic=''):
    with _lock:
        data = _load()
        entry = {
            "id": _next_id(data, "alerts"),
            "timestamp": now_ts(),
            "alert_type": alert_type,
            "severity": severity,
            "source_ip": source_ip,
            "description": description,
            "mitre_id": mitre_id,
            "mitre_technique": mitre_technique,
            "tactic": tactic,
            "resolved": False
        }
        data["alerts"].append(entry)
        _save(data)
        return entry

def get_alerts(resolved=False, severity=None, limit=100):
    data = _load()
    result = [a for a in data["alerts"] if a["resolved"] == resolved]
    if severity:
        result = [a for a in result if a["severity"] == severity]
    return list(reversed(result))[:limit]

def resolve_alert(alert_id):
    with _lock:
        data = _load()
        for a in data["alerts"]:
            if a["id"] == alert_id:
                a["resolved"] = True
                _save(data)
                return True
        return False

def resolve_bulk(ids):
    with _lock:
        data = _load()
        count = 0
        for a in data["alerts"]:
            if a["id"] in ids:
                a["resolved"] = True
                count += 1
        _save(data)
        return count

def alert_exists_since(alert_type, source_ip, minutes):
    cutoff = time.time() - minutes * 60
    data = _load()
    for a in data["alerts"]:
        if a["alert_type"] == alert_type and a["source_ip"] == source_ip and not a["resolved"]:
            ts = time.mktime(time.strptime(a["timestamp"], '%Y-%m-%d %H:%M:%S'))
            if ts >= cutoff:
                return True
    return False

def get_stats():
    data = _load()
    import time as t
    cutoff = t.time() - 3600
    active = [a for a in data["alerts"] if not a["resolved"]]
    recent_logs = 0
    for log in data["logs"]:
        ts = time.mktime(time.strptime(log["timestamp"], '%Y-%m-%d %H:%M:%S'))
        if ts >= cutoff:
            recent_logs += 1
    resolved_today_cutoff = t.time() - 86400
    resolved_today = sum(1 for a in data["alerts"] if a["resolved"] and
                         time.mktime(time.strptime(a["timestamp"], '%Y-%m-%d %H:%M:%S')) >= resolved_today_cutoff)
    return {
        "total_logs": len(data["logs"]),
        "total_alerts": len(active),
        "critical_alerts": sum(1 for a in active if a["severity"] == "CRITICAL"),
        "high_alerts": sum(1 for a in active if a["severity"] == "HIGH"),
        "recent_logs": recent_logs,
        "resolved_today": resolved_today
    }

# ── Intel ────────────────────────────────────────────────────────────────────
def save_intel(ip, is_malicious, score, country, source):
    with _lock:
        data = _load()
        for rec in data["intel"]:
            if rec["ip_address"] == ip:
                rec.update({"is_malicious": is_malicious, "reputation_score": score,
                            "country": country, "source": source, "last_checked": now_ts()})
                _save(data)
                return
        data["intel"].append({
            "id": _next_id(data, "intel"),
            "ip_address": ip, "is_malicious": is_malicious,
            "reputation_score": score, "country": country,
            "source": source, "last_checked": now_ts()
        })
        _save(data)

def get_intel_all(limit=20):
    data = _load()
    return list(reversed(data["intel"]))[:limit]

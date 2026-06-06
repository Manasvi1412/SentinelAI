"""
Detection Engine — 8 attack types with proper MITRE ATT&CK mapping.
All pure Python, no external dependencies.
"""
from database.store import add_log, get_logs_since, add_alert, alert_exists_since

# ── Thresholds ────────────────────────────────────────────────────────────────
BF_THRESHOLD   = 5   # failed logins in window
BF_WINDOW      = 2   # minutes
PS_THRESHOLD   = 10  # port scan events in window
PS_WINDOW      = 1
SQLI_PATTERNS  = ["'", "OR 1=1", "--", "UNION SELECT", "DROP TABLE", "xp_cmdshell", "EXEC(", "CAST("]
XSS_PATTERNS   = ["<script", "javascript:", "onerror=", "onload=", "alert(", "document.cookie"]
EXFIL_BYTES    = 5_000_000  # 5MB in single session = suspicious
PRIV_ESC_CMDS  = ["sudo su", "chmod +s", "chown root", "/etc/sudoers", "passwd root", "visudo"]

# Known malicious IPs (extend from threat feeds in production)
KNOWN_BAD_IPS = {
    "45.33.32.156", "198.51.100.22", "203.0.113.99",
    "91.108.4.0",   "141.98.10.0",  "185.220.101.0",
    "5.188.206.0",  "193.32.162.0", "80.82.77.0",
    "23.129.64.0",  "162.247.74.0", "199.87.154.0",
}

def _alert(alert_type, severity, ip, description, mitre_id, mitre_technique, tactic=''):
    """Create alert only if not already active in the window."""
    window = BF_WINDOW if alert_type == 'brute_force' else 5
    if not alert_exists_since(alert_type, ip, window):
        return add_alert(alert_type, severity, ip, description, mitre_id, mitre_technique, tactic)
    return None

# ── 1. Brute Force ────────────────────────────────────────────────────────────
def detect_brute_force():
    results = []
    logs = get_logs_since(BF_WINDOW, status='failed')
    # Group by (ip, event_type) — no cross-contamination between SSH/FTP/web
    counts = {}
    for log in logs:
        key = (log["source_ip"], log["event_type"])
        counts[key] = counts.get(key, 0) + 1
    for (ip, evt), count in counts.items():
        if count >= BF_THRESHOLD:
            sev = 'CRITICAL' if count >= BF_THRESHOLD * 2 else 'HIGH'
            a = _alert('brute_force', sev, ip,
                f'Brute force on {evt}: {count} failed attempts in {BF_WINDOW}min from {ip}',
                'T1110', 'Brute Force', 'Credential Access')
            if a: results.append(a)
    return results

# ── 2. Port Scan ──────────────────────────────────────────────────────────────
def detect_port_scan():
    results = []
    logs = get_logs_since(PS_WINDOW, event_type='port_scan')
    counts = {}
    for log in logs:
        counts[log["source_ip"]] = counts.get(log["source_ip"], 0) + 1
    for ip, count in counts.items():
        if count >= PS_THRESHOLD:
            sev = 'HIGH' if count >= 30 else 'MEDIUM'
            a = _alert('port_scan', sev, ip,
                f'Port scan from {ip}: {count} ports probed in {PS_WINDOW}min',
                'T1046', 'Network Service Discovery', 'Discovery')
            if a: results.append(a)
    return results

# ── 3. Malware IOC ────────────────────────────────────────────────────────────
def detect_malware_ioc(extra_ips=None):
    results = []
    bad = KNOWN_BAD_IPS | set(extra_ips or [])
    logs = get_logs_since(5)
    seen = set()
    for log in logs:
        ip = log["source_ip"]
        if ip in bad and ip not in seen:
            seen.add(ip)
            a = _alert('malware_ioc', 'CRITICAL', ip,
                f'Known C2/malware IP {ip} in traffic — matches IOC database',
                'T1071', 'Application Layer Protocol', 'Command and Control')
            if a: results.append(a)
    return results

# ── 4. SQL Injection ──────────────────────────────────────────────────────────
def detect_sql_injection():
    results = []
    logs = get_logs_since(5, event_type='web_request')
    for log in logs:
        raw = log.get("raw_log", "").upper()
        hits = [p for p in SQLI_PATTERNS if p.upper() in raw]
        if hits:
            a = _alert('sql_injection', 'HIGH', log["source_ip"],
                f'SQL injection attempt from {log["source_ip"]}: patterns [{", ".join(hits[:3])}] in request',
                'T1190', 'Exploit Public-Facing Application', 'Initial Access')
            if a: results.append(a)
    return results

# ── 5. XSS ───────────────────────────────────────────────────────────────────
def detect_xss():
    results = []
    logs = get_logs_since(5, event_type='web_request')
    for log in logs:
        raw = log.get("raw_log", "").lower()
        hits = [p for p in XSS_PATTERNS if p.lower() in raw]
        if hits:
            a = _alert('xss_attempt', 'MEDIUM', log["source_ip"],
                f'XSS attempt from {log["source_ip"]}: patterns [{", ".join(hits[:3])}] detected in payload',
                'T1059.007', 'JavaScript Execution', 'Execution')
            if a: results.append(a)
    return results

# ── 6. Privilege Escalation ───────────────────────────────────────────────────
def detect_privilege_escalation():
    results = []
    logs = get_logs_since(5, event_type='sudo_attempt')
    for log in logs:
        raw = log.get("raw_log", "")
        hits = [c for c in PRIV_ESC_CMDS if c in raw]
        if hits:
            a = _alert('privilege_escalation', 'CRITICAL', log["source_ip"],
                f'Privilege escalation from {log["source_ip"]} (user: {log["username"]}): cmd [{hits[0]}]',
                'T1548', 'Abuse Elevation Control Mechanism', 'Privilege Escalation')
            if a: results.append(a)
    return results

# ── 7. Lateral Movement ───────────────────────────────────────────────────────
def detect_lateral_movement():
    """Detect one IP successfully logging into many different usernames."""
    results = []
    logs = get_logs_since(10, status='success')
    # IP → set of unique usernames it logged into
    ip_users = {}
    for log in logs:
        ip = log["source_ip"]
        if ip not in ip_users:
            ip_users[ip] = set()
        ip_users[ip].add(log["username"])
    for ip, users in ip_users.items():
        if len(users) >= 3:  # Same IP accessing 3+ accounts = suspicious
            a = _alert('lateral_movement', 'HIGH', ip,
                f'Lateral movement detected: {ip} accessed {len(users)} accounts {list(users)[:5]} in 10min',
                'T1021', 'Remote Services', 'Lateral Movement')
            if a: results.append(a)
    return results

# ── 8. Data Exfiltration ──────────────────────────────────────────────────────
def detect_data_exfiltration():
    """Detect high outbound data volume from a single source IP."""
    results = []
    logs = get_logs_since(10, event_type='data_transfer')
    ip_bytes = {}
    for log in logs:
        ip = log["source_ip"]
        try:
            # raw_log format: "... bytes=12345 ..."
            raw = log.get("raw_log", "")
            bstr = [p for p in raw.split() if p.startswith("bytes=")]
            if bstr:
                nb = int(bstr[0].split("=")[1])
                ip_bytes[ip] = ip_bytes.get(ip, 0) + nb
        except Exception:
            pass
    for ip, total in ip_bytes.items():
        if total >= EXFIL_BYTES:
            mb = total // 1_000_000
            a = _alert('data_exfiltration', 'CRITICAL', ip,
                f'Data exfiltration suspected: {ip} transferred {mb}MB outbound in 10min',
                'T1041', 'Exfiltration Over C2 Channel', 'Exfiltration')
            if a: results.append(a)
    return results

# ── Run All ───────────────────────────────────────────────────────────────────
def run_all():
    alerts = []
    for fn in [detect_brute_force, detect_port_scan, detect_malware_ioc,
               detect_sql_injection, detect_xss, detect_privilege_escalation,
               detect_lateral_movement, detect_data_exfiltration]:
        try:
            alerts.extend(fn() or [])
        except Exception as e:
            print(f"[detection] {fn.__name__} error: {e}")
    return alerts

# ── Run Force (simulation — always creates alert, bypasses dedup) ─────────────
def run_all_force(attack_type=None):
    """Used by simulator — skips dedup so every simulation shows an alert."""
    from database.store import add_alert
    import time

    # Map attack type to alert params
    FORCE_MAP = {
        'brute_force':         ('brute_force',        'HIGH',     'T1110', 'Brute Force',                  'Credential Access'),
        'port_scan':           ('port_scan',           'MEDIUM',   'T1046', 'Network Service Discovery',    'Discovery'),
        'malware':             ('malware_ioc',         'CRITICAL', 'T1071', 'Application Layer Protocol',  'Command and Control'),
        'sql_injection':       ('sql_injection',       'HIGH',     'T1190', 'Exploit Public-Facing App',    'Initial Access'),
        'xss':                 ('xss_attempt',         'MEDIUM',   'T1059.007', 'JavaScript Execution',    'Execution'),
        'privilege_escalation':('privilege_escalation','CRITICAL', 'T1548', 'Abuse Elevation Control',     'Privilege Escalation'),
        'lateral_movement':    ('lateral_movement',    'HIGH',     'T1021', 'Remote Services',             'Lateral Movement'),
        'data_exfiltration':   ('data_exfiltration',   'CRITICAL', 'T1041', 'Exfiltration Over C2 Channel','Exfiltration'),
    }

    from database.store import get_logs_since
    logs = get_logs_since(2)
    ip = logs[-1]['source_ip'] if logs else '10.0.0.44'

    created = []
    targets = [attack_type] if attack_type and attack_type != 'mixed' else list(FORCE_MAP.keys())

    for t in targets:
        if t not in FORCE_MAP:
            continue
        atype, sev, mid, mtech, tactic = FORCE_MAP[t]
        desc_map = {
            'brute_force':          f'[SIM] Brute force: multiple failed logins from {ip}',
            'port_scan':            f'[SIM] Port scan: {ip} probed 20 ports',
            'malware':              f'[SIM] Malware C2 beacon detected from {ip}',
            'sql_injection':        f'[SIM] SQL injection payload in request from {ip}',
            'xss':                  f'[SIM] XSS payload detected in request from {ip}',
            'privilege_escalation': f'[SIM] Privilege escalation attempt by user on {ip}',
            'lateral_movement':     f'[SIM] Lateral movement: {ip} accessed 4 accounts',
            'data_exfiltration':    f'[SIM] Data exfiltration: {ip} sent 7MB outbound',
        }
        a = add_alert(atype, sev, ip, desc_map.get(t, f'[SIM] {t} from {ip}'), mid, mtech, tactic)
        created.append(a)

    return created

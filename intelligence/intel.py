"""
Threat Intelligence — VirusTotal + AbuseIPDB dual-source enrichment.
Falls back to mock data if API keys not set.
"""
import os
import json
import urllib.request
import urllib.error
from database.store import save_intel

VT_KEY      = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSE_KEY   = os.getenv("ABUSEIPDB_API_KEY", "")

KNOWN_BAD = {
    "45.33.32.156":  {"country": "US", "score": 90, "abuse_score": 100},
    "198.51.100.22": {"country": "RU", "score": 75, "abuse_score": 85},
    "203.0.113.99":  {"country": "CN", "score": 60, "abuse_score": 70},
}

def check_ip(ip: str) -> dict:
    """Check IP against VirusTotal and AbuseIPDB, merge results."""
    vt_result    = _check_virustotal(ip) if VT_KEY else None
    abuse_result = _check_abuseipdb(ip) if ABUSE_KEY else None

    if vt_result or abuse_result:
        merged = _merge(ip, vt_result, abuse_result)
    else:
        merged = _mock(ip)

    save_intel(ip, merged["malicious"], merged["score"], merged["country"], merged["source"])
    return merged

def _check_virustotal(ip: str) -> dict | None:
    try:
        req = urllib.request.Request(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VT_KEY}
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        attrs  = data.get("data", {}).get("attributes", {})
        stats  = attrs.get("last_analysis_stats", {})
        mal    = stats.get("malicious", 0)
        return {
            "source": "virustotal",
            "malicious_votes": mal,
            "is_malicious": mal > 2,
            "country": attrs.get("country", "Unknown"),
            "reputation": attrs.get("reputation", 0),
        }
    except Exception as e:
        print(f"[intel] VirusTotal error: {e}")
        return None

def _check_abuseipdb(ip: str) -> dict | None:
    try:
        req = urllib.request.Request(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90",
            headers={"Key": ABUSE_KEY, "Accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            data = json.loads(r.read())
        d = data.get("data", {})
        score = d.get("abuseConfidenceScore", 0)
        return {
            "source": "abuseipdb",
            "abuse_score": score,
            "is_malicious": score > 25,
            "country": d.get("countryCode", "Unknown"),
            "total_reports": d.get("totalReports", 0),
            "isp": d.get("isp", "Unknown"),
        }
    except Exception as e:
        print(f"[intel] AbuseIPDB error: {e}")
        return None

def _merge(ip, vt, abuse) -> dict:
    country  = (vt or abuse or {}).get("country", "Unknown")
    vt_bad   = (vt or {}).get("is_malicious", False)
    ab_bad   = (abuse or {}).get("is_malicious", False)
    is_mal   = vt_bad or ab_bad
    score    = max((vt or {}).get("malicious_votes", 0) * 10,
                   (abuse or {}).get("abuse_score", 0))
    sources  = []
    if vt:    sources.append("virustotal")
    if abuse: sources.append("abuseipdb")
    return {
        "ip": ip, "malicious": is_mal, "score": min(score, 100),
        "country": country, "source": "+".join(sources),
        "vt_votes":    (vt or {}).get("malicious_votes", "N/A"),
        "abuse_score": (abuse or {}).get("abuse_score", "N/A"),
        "isp":         (abuse or {}).get("isp", "N/A"),
        "reports":     (abuse or {}).get("total_reports", "N/A"),
    }

def _mock(ip: str) -> dict:
    if ip in KNOWN_BAD:
        m = KNOWN_BAD[ip]
        return {"ip": ip, "malicious": True,  "score": m["score"],
                "country": m["country"], "source": "mock",
                "vt_votes": m["score"]//10, "abuse_score": m["abuse_score"],
                "isp": "N/A", "reports": "N/A"}
    return {"ip": ip, "malicious": False, "score": 0,
            "country": "Unknown", "source": "mock",
            "vt_votes": 0, "abuse_score": 0, "isp": "N/A", "reports": "N/A"}

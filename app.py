"""
SentinelAI — Flask backend.
Dependencies: flask only (stdlib urllib used for all HTTP calls).
Run: python app.py
"""
import os, json, time
from flask import Flask, render_template, jsonify, request

# Load .env file if present
try:
    from dotenv import load_dotenv
    load_dotenv(override=True)
except ImportError:
    pass  # dotenv not installed — set env vars manually

from database.store import (
    add_log, get_logs, get_stats,
    get_alerts, resolve_alert, resolve_bulk, get_intel_all
)
from detections.engine import run_all, run_all_force
from ai_engine.analyst import analyze_alert
from intelligence.intel import check_ip
from collectors.collector import SIM_MAP

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", os.urandom(24).hex())

# ── Simple rate limiter (in-memory) ──────────────────────────────────────────
_rl = {}
def _check_rate(ip, limit=60, window=60):
    now = time.time()
    hits = [t for t in _rl.get(ip, []) if now - t < window]
    if len(hits) >= limit:
        return False
    hits.append(now)
    _rl[ip] = hits
    return True

# ── Pages ─────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/alerts')
def alerts_page():
    return render_template('alerts.html')

@app.route('/logs')
def logs_page():
    return render_template('logs.html')

@app.route('/incidents')
def incidents_page():
    return render_template('incidents.html')

@app.route('/intel')
def intel_page():
    return render_template('intel.html')

@app.route('/simulate')
def simulate_page():
    return render_template('simulate.html')

# ── Stats ─────────────────────────────────────────────────────────────────────
@app.route('/api/stats')
def stats():
    return jsonify(get_stats())

# ── Alerts ────────────────────────────────────────────────────────────────────
@app.route('/api/alerts')
def api_alerts():
    resolved  = request.args.get('resolved', 'false').lower() == 'true'
    severity  = request.args.get('severity')
    limit     = int(request.args.get('limit', 100))
    return jsonify(get_alerts(resolved=resolved, severity=severity, limit=limit))

@app.route('/api/alerts/<int:aid>/resolve', methods=['POST'])
def api_resolve(aid):
    resolve_alert(aid)
    return jsonify({'ok': True})

@app.route('/api/alerts/bulk-resolve', methods=['POST'])
def api_bulk_resolve():
    ids = request.json.get('ids', [])
    n = resolve_bulk(ids)
    return jsonify({'resolved': n})

@app.route('/api/alerts/<int:aid>/analyze')
def api_analyze(aid):
    alerts = get_alerts(resolved=False) + get_alerts(resolved=True)
    alert  = next((a for a in alerts if a['id'] == aid), None)
    if not alert:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(analyze_alert(alert))

# ── Logs ──────────────────────────────────────────────────────────────────────
@app.route('/api/logs')
def api_logs():
    limit = int(request.args.get('limit', 100))
    return jsonify(get_logs(limit=limit))

@app.route('/api/ingest', methods=['POST'])
def api_ingest():
    if not _check_rate(request.remote_addr):
        return jsonify({'error': 'Rate limit exceeded'}), 429
    data = request.json or {}
    ip = data.get('source_ip', '0.0.0.0')
    log = add_log(ip, data.get('event_type','unknown'),
                  data.get('username','-'), data.get('status','unknown'),
                  data.get('raw_log',''))
    new = run_all()
    return jsonify({'id': log['id'], 'alerts_created': len(new)})

# ── Simulate ──────────────────────────────────────────────────────────────────
@app.route('/api/simulate', methods=['POST'])
def api_simulate():
    attack = (request.json or {}).get('type', 'brute_force')
    fn = SIM_MAP.get(attack)
    if not fn:
        return jsonify({'error': f'Unknown attack type: {attack}'}), 400
    fn()
    # Simulate always creates fresh alerts (bypass dedup)
    new = run_all_force(attack)
    return jsonify({'type': attack, 'alerts_created': len(new)})

# ── Threat Intel ──────────────────────────────────────────────────────────────
@app.route('/api/intel/<ip>')
def api_intel(ip):
    return jsonify(check_ip(ip))

@app.route('/api/intel/all')
def api_intel_all():
    return jsonify(get_intel_all())

# ── Health ────────────────────────────────────────────────────────────────────
@app.route('/api/health')
def api_health():
    return jsonify({'status': 'ok', 'ts': time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())})

if __name__ == '__main__':
    print("SentinelAI v2 starting on http://localhost:5000")
    app.run(debug=False, port=5000)

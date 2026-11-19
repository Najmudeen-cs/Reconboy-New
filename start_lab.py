#!/usr/bin/env python3
"""
START_LAB — CLI launcher for Reconboy
Prompts for target + intensity, starts the attack via Reconboy's API,
and streams live progress to the terminal as attacks run.

Stopping a running scan is done from the Reconboy DASHBOARD only
(http://127.0.0.1:9090) — this CLI is launch + live-view only.

Requires reconboy.py to already be running:
  Terminal 1:  python3 reconboy.py
  Terminal 2:  python3 start_lab.py
"""
import sys, time, json, urllib.request, urllib.error

RECONBOY_URL = "http://127.0.0.1:9090"

R='\033[91m'; G='\033[92m'; Y='\033[93m'; B='\033[94m'
C='\033[96m'; M='\033[95m'; W='\033[97m'; X='\033[0m'; BOLD='\033[1m'

TAG_COLOR = {
    'header': Y, 'hit': G, 'partial': Y, 'info': B,
    'skip': C, 'error': R, 'banner': M, 'summary': G,
}
TAG_LABEL = {
    'header': '', 'hit': '[HIT]    ', 'partial': '[PARTIAL]', 'info': '[INFO]   ',
    'skip': '[SKIPPED]', 'error': '[ERROR]  ', 'banner': '', 'summary': '',
}

def api_get(path):
    with urllib.request.urlopen(f"{RECONBOY_URL}{path}", timeout=5) as r:
        return json.loads(r.read().decode())

def api_post(path, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(f"{RECONBOY_URL}{path}", data=data,
                                  headers={'Content-Type': 'application/json'}, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read().decode()), None
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode())
            return None, body.get('error', str(e))
        except Exception:
            return None, str(e)
    except urllib.error.URLError as e:
        return None, f"Cannot reach Reconboy at {RECONBOY_URL} — is it running? ({e})"

def check_reconboy_up():
    try:
        api_get("/api/status")
        return True
    except Exception:
        return False

def banner():
    print(f"\n{M}{BOLD}╔{'═'*58}╗")
    print(f"║{'START LAB — Reconboy CLI Launcher':^58}║")
    print(f"╚{'═'*58}╝{X}\n")

def ask_target():
    print(f"{W}Enter target (localhost or LAN address){X}")
    print(f"{C}  e.g. 127.0.0.1:5000  or  192.168.1.38:5500{X}")
    while True:
        t = input(f"{G}Target > {X}").strip()
        if t:
            return t
        print(f"{R}Target cannot be empty.{X}")

def ask_intensity():
    print(f"\n{W}Choose intensity:{X}")
    print(f"  {G}1{X} — Quick    (<10s,  limited payloads)")
    print(f"  {Y}2{X} — Standard (~1min, full payloads)      [default]")
    print(f"  {R}3{X} — Deep     (~10min, full payloads + heavier DoS)")
    while True:
        i = input(f"{G}Intensity [1/2/3, Enter=2] > {X}").strip()
        if i == '':
            return 2
        if i in ('1', '2', '3'):
            return int(i)
        print(f"{R}Enter 1, 2, or 3.{X}")

def stream_progress():
    seen = 0
    print(f"\n{C}{'─'*60}{X}")
    print(f"{W}Live attack feed — Ctrl+C to stop watching (scan keeps running){X}")
    print(f"{C}Stop the actual scan from the dashboard: {RECONBOY_URL}{X}")
    print(f"{C}{'─'*60}{X}\n")
    try:
        while True:
            status = api_get("/api/status")
            log = status.get("log", [])
            for entry in log[seen:]:
                kind = entry.get("type", "info")
                color = TAG_COLOR.get(kind, W)
                label = TAG_LABEL.get(kind, '')
                ts = entry.get("ts", "")
                text = entry.get("text", "")
                if kind == 'header':
                    print(f"\n{color}{BOLD}{text}{X}")
                elif kind in ('banner', 'summary'):
                    print(f"{color}{BOLD}{text}{X}")
                else:
                    print(f"  {color}{label}{X} {C}{ts}{X}  {text}")
            seen = len(log)
            if not status.get("running") and seen > 0:
                findings = status.get("findings", [])
                print(f"\n{G}{BOLD}Scan finished — {len(findings)} confirmed finding(s).{X}")
                print(f"{C}Full report on dashboard: {RECONBOY_URL}{X}\n")
                break
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{Y}Stopped watching (scan may still be running in the background).{X}")
        print(f"{C}To stop it, use the STOP button on the dashboard: {RECONBOY_URL}{X}\n")

def main():
    banner()

    if not check_reconboy_up():
        print(f"{R}{BOLD}Reconboy isn't running.{X}")
        print(f"{W}Start it first in another terminal:{X}")
        print(f"  {G}python3 reconboy.py{X}\n")
        print(f"{W}Then re-run this script.{X}\n")
        sys.exit(1)

    print(f"{G}✓ Reconboy is up at {RECONBOY_URL}{X}\n")

    target = ask_target()
    intensity = ask_intensity()

    print(f"\n{Y}Launching attack on {target} (intensity {intensity})...{X}")
    result, error = api_post("/api/attack", {"target": target, "intensity": intensity})

    if error:
        print(f"{R}{BOLD}✗ {error}{X}\n")
        sys.exit(1)

    print(f"{G}✓ Attack started.{X}")
    stream_progress()

if __name__ == '__main__':
    main()

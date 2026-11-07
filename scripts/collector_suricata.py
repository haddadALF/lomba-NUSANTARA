#!/usr/bin/env python3
"""
Collector Suricata -> NUSANTARA-SMS
- Baca token OTOMATIS dari ~/NUSANTARA-SMS/.env
- Baca /var/log/suricata/eve.json (hanya event_type=alert)
- POST event ke /api/ingest/suricata
- POST heartbeat ke /api/collector/heartbeat tiap 30 detik
- Tidak mengubah apa pun di Suricata atau NUSANTARA-SMS
"""
import json
import os
import re
import time
import urllib.request

ENV_FILE = os.path.expanduser("~/NUSANTARA-SMS/.env")
EVE_LOG = "/var/log/suricata/eve.json"
BASE_URL = "http://127.0.0.1:3000"
INGEST_URL = f"{BASE_URL}/api/ingest/suricata"
HEARTBEAT_URL = f"{BASE_URL}/api/collector/heartbeat"
HEARTBEAT_INTERVAL = 30  # detik

def load_token_from_env(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.rstrip("\r\n")
            m = re.match(r'^\s*COLLECTOR_TOKEN\s*=\s*(.*)$', line)
            if not m:
                continue
            val = m.group(1).strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
                val = val[1:-1]
            return val
    raise SystemExit("COLLECTOR_TOKEN tidak ditemukan di .env")

TOKEN = load_token_from_env(ENV_FILE)
if not TOKEN:
    raise SystemExit("COLLECTOR_TOKEN kosong di .env")

print(f"[collector] token dimuat dari .env (panjang {len(TOKEN)} karakter)", flush=True)

def post_json(url, payload):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", "X-Collector-Token": TOKEN},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return None, str(e)

def send_heartbeat():
    payload = {"sensor": "suricata", "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
    status, _ = post_json(HEARTBEAT_URL, payload)
    if status == 200:
        print(f"[collector] heartbeat OK", flush=True)
    else:
        print(f"[collector] heartbeat gagal: HTTP {status}", flush=True)

def send_alert(alert):
    status, _ = post_json(INGEST_URL, alert)
    if status == 200:
        sig = alert.get("alert", {}).get("signature", "?")
        src = alert.get("src_ip", "?")
        print(f"[collector] terkirim: {sig} dari {src}", flush=True)
    else:
        print(f"[collector] HTTP {status} dari API", flush=True)
    return status

def follow(path):
    f = open(path, "r")
    f.seek(0, os.SEEK_END)
    last_heartbeat = 0
    while True:
        now = time.time()
        if now - last_heartbeat >= HEARTBEAT_INTERVAL:
            send_heartbeat()
            last_heartbeat = now
        line = f.readline()
        if not line:
            time.sleep(0.5)
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("event_type") == "alert":
            send_alert(ev)

if __name__ == "__main__":
    print(f"[collector] mulai, baca {EVE_LOG} -> {INGEST_URL}", flush=True)
    print(f"[collector] heartbeat tiap {HEARTBEAT_INTERVAL}s ke {HEARTBEAT_URL}", flush=True)
    follow(EVE_LOG)

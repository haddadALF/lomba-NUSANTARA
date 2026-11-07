#!/usr/bin/env python3
"""
Collector WAF (ModSecurity) -> NUSANTARA-SMS
- Baca token OTOMATIS dari ~/NUSANTARA-SMS/.env
- Baca /var/log/modsec/modsec_audit.log (hanya entry 403)
- Petakan rule_id CRS ke Judul & Severity yang jelas
- POST ke /api/ingest/waf dengan X-Collector-Token
- Heartbeat tiap 30 detik
"""
import json
import os
import re
import time
import urllib.request

ENV_FILE = os.path.expanduser("~/NUSANTARA-SMS/.env")
AUDIT_LOG = "/var/log/modsec/modsec_audit.log"
BASE_URL = "http://127.0.0.1:3000"
INGEST_URL = f"{BASE_URL}/api/ingest/waf"
HEARTBEAT_URL = f"{BASE_URL}/api/collector/heartbeat"
HEARTBEAT_INTERVAL = 30

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

print(f"[waf-collector] token dimuat (panjang {len(TOKEN)} karakter)", flush=True)

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
    payload = {"sensor": "waf", "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
    status, _ = post_json(HEARTBEAT_URL, payload)
    if status == 200:
        print(f"[waf-collector] heartbeat OK", flush=True)
    else:
        print(f"[waf-collector] heartbeat gagal: HTTP {status}", flush=True)

def classify_rule(rule_id, msg):
    """Petakan rule_id CRS -> (title, severity)."""
    rid = str(rule_id)
    m = (msg or "").lower()

    # Critical — eksekusi kode / RCE
    if rid.startswith("932") or "command injection" in m or "rce" in m:
        return ("Command Injection Detected", "critical")

    # High — SQLi, XSS, LFI, SSRF, PHP injection
    if rid.startswith("942") or "sql" in m or "sqli" in m:
        return ("SQL Injection Detected", "high")
    if rid.startswith("941") or "xss" in m or "cross-site" in m:
        return ("Cross-Site Scripting (XSS) Detected", "high")
    if rid.startswith("930") or "path traversal" in m or "lfi" in m:
        return ("Path Traversal / LFI Detected", "high")
    if rid.startswith("931") or "ssrf" in m:
        return ("Server-Side Request Forgery (SSRF) Detected", "high")
    if rid.startswith("933") or "php" in m:
        return ("PHP Injection Detected", "high")
    if rid.startswith("934") or "node" in m:
        return ("Node.js Injection Detected", "high")

    # Medium — scanner, protocol anomaly
    if rid.startswith("913") or "scanner" in m:
        return ("Security Scanner Detected", "medium")
    if rid.startswith("920") or "protocol" in m:
        return ("Protocol Anomaly / Bad Request", "low")

    # Rule agregat (bukan serangan spesifik) — jangan kirim
    if rid == "949110" or rid == "980130":
        return (None, None)

    # Default untuk rule lain
    if msg:
        return (msg, "medium")
    return ("WAF Blocked Request", "medium")

def parse_audit_entry(text):
    entry = {}
    m = re.search(r'\[id "(\d+)"\]', text)
    if m: entry["rule_id"] = m.group(1)
    m = re.search(r'\[msg "([^"]*)"\]', text)
    if m: entry["msg"] = m.group(1)
    m = re.search(r'\[uri "([^"]*)"\]', text)
    if m: entry["uri"] = m.group(1)
    m = re.search(r'\[hostname "([^"]*)"\]', text)
    if m: entry["source_ip"] = m.group(1)
    m = re.search(r'Access denied with code (\d+)', text)
    if m: entry["status_code"] = int(m.group(1))
    return entry

def follow(path):
    f = open(path, "r", errors="replace")
    f.seek(0, os.SEEK_END)
    buffer = []
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
        if line.startswith("---") and line.strip().endswith("---A--"):
            if buffer:
                text = "".join(buffer)
                if "Access denied with code 403" in text:
                    entry = parse_audit_entry(text)
                    if entry.get("rule_id") and entry.get("source_ip"):
                        title, severity = classify_rule(entry.get("rule_id"), entry.get("msg", ""))
                        if title:
                            payload = {
                                "payload": title,
                                "uri": entry.get("uri", "/"),
                                "method": "GET",
                                "sourceIp": entry["source_ip"],
                                "statusCode": 403,
                                "isBlocked": True,
                                "ruleId": f"CRS-{entry['rule_id']}",
                                "severity": severity,
                            }
                            status, _ = post_json(INGEST_URL, payload)
                            if status == 200:
                                print(f"[waf-collector] terkirim: {title} ({severity}) dari {payload['sourceIp']} uri={payload['uri']}", flush=True)
                            else:
                                print(f"[waf-collector] HTTP {status} dari API", flush=True)
            buffer = [line]
        else:
            buffer.append(line)

if __name__ == "__main__":
    print(f"[waf-collector] mulai, baca {AUDIT_LOG} -> {INGEST_URL}", flush=True)
    print(f"[waf-collector] heartbeat tiap {HEARTBEAT_INTERVAL}s ke {HEARTBEAT_URL}", flush=True)
    follow(AUDIT_LOG)

#!/usr/bin/env python3
"""Nebulock Audit Log — HTTP API Server
Translates ICP Candid → JSON for the dashboard frontend."""
import subprocess, json, os, time, re
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime

os.environ["DFX_WARNING"] = "-mainnet_plaintext_identity"
CANISTER = "s7oui-qqaaa-aaaag-ayx2a-cai"
PORT = 8741
CACHE_TTL = 30
cache = {"data": [], "time": 0}

def call_canister(method, arg=""):
    cmd = ["dfx", "canister", "--network", "ic", "call", CANISTER, method]
    if arg:
        cmd.append(arg)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    return result.stdout

def parse_candid_entries(raw):
    """Parse dfx canister call output into JSON"""
    entries = []
    
    # Extract individual records using regex
    record_re = re.compile(
        r'record\s*\{[^}]*?action_hash\s*=\s*"([^"]*)";\s*'
        r'action_type\s*=\s*"([^"]*)";\s*'
        r'metadata\s*=\s*"(.*?)";\s*'
        r'agent_id\s*=\s*"([^"]*)";\s*'
        r'timestamp\s*=\s*(\d+(?:_\d+)*)\s*:\s*int;\s*'
        r'caller\s*=\s*principal\s*"([^"]*)";\s*'
        r'index\s*=\s*(\d+)\s*:\s*nat',
        re.DOTALL
    )
    
    for m in record_re.finditer(raw):
        try:
            ts = int(m.group(5).replace('_', ''))
            meta_raw = m.group(3).replace('\\"', '"').replace('\\\\', '\\')
            meta_obj = {}
            try: 
                meta_obj = json.loads(meta_raw)
            except:
                meta_obj = {"raw": meta_raw[:100]}
            
            entries.append({
                "index": int(m.group(7)),
                "agent_id": m.group(4),
                "action_type": m.group(2),
                "action_hash": m.group(1),
                "metadata": meta_obj,
                "timestamp_ns": ts,
                "timestamp_ms": ts // 1_000_000,
                "timestamp_iso": datetime.utcfromtimestamp(ts / 1_000_000_000).isoformat() + "Z",
                "caller": m.group(6)
            })
        except Exception as e:
            print(f"Parse error: {e}")
    
    return sorted(entries, key=lambda e: e["index"], reverse=True)

def get_entries():
    global cache
    now = time.time()
    if now - cache["time"] < CACHE_TTL and cache["data"]:
        return cache["data"]
    
    raw = call_canister("get_all_entries")
    entries = parse_candid_entries(raw)
    cache = {"data": entries, "time": now}
    return entries

class Handler(BaseHTTPRequestHandler):
    def _parse_qs(self):
        parsed = urlparse(self.path)
        return parsed.path, parse_qs(parsed.query)
    
    def do_GET(self):
        path, qs = self._parse_qs()
        
        if path == "/api/entries":
            entries = get_entries()
            total = len(entries)
            
            # Pagination
            per_page = 200
            page = int(qs.get('page', [1])[0])
            total_pages = max(1, (total + per_page - 1) // per_page)
            page = max(1, min(page, total_pages))
            
            start = (page - 1) * per_page
            end = start + per_page
            page_entries = entries[start:end]
            
            result = {
                "entries": page_entries,
                "pagination": {
                    "page": page,
                    "per_page": per_page,
                    "total": total,
                    "total_pages": total_pages,
                    "has_next": page < total_pages,
                    "has_prev": page > 1
                }
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
        elif path == "/api/stats":
            entries = get_entries()
            agents = list(set(e["agent_id"] for e in entries))
            types = list(set(e["action_type"] for e in entries))
            stats = {
                "total": len(entries),
                "agents": sorted(agents),
                "types": sorted(types),
                "last_update": datetime.utcnow().isoformat() + "Z",
                "canister": CANISTER
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(stats).encode())
        elif path == "/" or path == "/index.html":
            with open(os.path.join(os.path.dirname(__file__), "dashboard.html"), "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(content)
        else:
            self.send_response(404)
            self.end_headers()

print(f"🔐 Nebulock Audit API on http://0.0.0.0:{PORT}")
HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()

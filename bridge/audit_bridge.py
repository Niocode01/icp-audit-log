
#!/usr/bin/env python3
"""
Hermes → ICP Audit Log Bridge
Reads Hermes tool calls from session DB, batches them, uploads to ICP canister.

Usage: python3 audit_bridge.py [--interval 300] [--batch-size 50]
"""

import subprocess
import sqlite3
import hashlib
import json
import time
import os
import sys
import argparse
from pathlib import Path
from datetime import datetime

# --- Config ---
HERMES_HOME = os.environ.get("HERMES_HOME", os.path.expanduser("~/.hermes"))
CANISTER_ID = "s7oui-qqaaa-aaaag-ayx2a-cai"
NETWORK = ["--network", "ic"]
DFX_PROJECT = "/opt/data/icp/audit-log/audit_log"
CHECKPOINT_FILE = "/opt/data/icp/audit-log/checkpoint.json"
DEFAULT_INTERVAL = 300  # 5 minutes
DEFAULT_BATCH_SIZE = 50

def load_checkpoint():
    if os.path.exists(CHECKPOINT_FILE):
        with open(CHECKPOINT_FILE) as f:
            return json.load(f)
    return {"last_processed_id": 0, "session_id": None}

def save_checkpoint(cp):
    with open(CHECKPOINT_FILE, 'w') as f:
        json.dump(cp, f)

def get_hermes_actions(last_id):
    """Read tool calls from Hermes session DB newer than last_id"""
    db_path = "/opt/data/state.db"
    if not os.path.exists(db_path):
        print(f"No session DB at {db_path}")
        return []
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    
    # Get messages newer than last_id, focusing on tool calls and responses
    cursor = conn.execute("""
        SELECT m.id, m.role, m.content, m.tool_name, m.tool_call_id,
               m.tool_calls, m.timestamp, m.session_id, m.token_count, m.finish_reason
        FROM messages m
        WHERE m.id > ?
        ORDER BY m.id ASC
        LIMIT 200
    """, (last_id,))
    
    actions = []
    for row in cursor:
        content = row['content'] or ""
        content_preview = content[:200] + "..." if len(content) > 200 else content
        
        # Determine action type
        role = row['role']
        if role == 'tool' and row['tool_name']:
            action_type = f"tool:{row['tool_name']}"
        elif role == 'assistant' and row['tool_calls']:
            action_type = "tool_call_request"
        elif role == 'assistant':
            action_type = "assistant_response"
        elif role == 'user':
            action_type = "user_message"
        elif role == 'system':
            action_type = "system_prompt"
        else:
            action_type = role
        
        # Real hash of content
        action_hash = hashlib.sha256(
            f"{role}:{content}".encode('utf-8')
        ).hexdigest()[:24]
        
        actions.append({
            'rowid': row['id'],
            'agent_id': 'hermes-telegram',
            'action_type': action_type,
            'action_hash': action_hash,
            'metadata': json.dumps({
                'session': str(row['session_id'])[:16] if row['session_id'] else None,
                'tokens': row['token_count'],
                'finish': row['finish_reason'],
                'tool': row['tool_name'],
                'content_preview': content_preview
            }),
            'session_id': row['session_id']
        })
    
    conn.close()
    return actions

def upload_batch(actions):
    """Upload a batch of actions to ICP canister"""
    if not actions:
        return True, 0
    
    # Build dfx call argument with proper Candid text escaping
    tuples = []
    for a in actions:
        # metadata is already a JSON string from earlier json.dumps()
        meta_json = a["metadata"]
        # Escape for Candid text: double backslashes, escape quotes
        escaped_meta = meta_json.replace('\\', '\\\\').replace('"', '\\"')
        t = f'record {{"{a["agent_id"]}"; "{a["action_type"]}"; "{a["action_hash"]}"; "{escaped_meta}"}}'
        tuples.append(t)
    
    arg = "vec { " + "; ".join(tuples) + " }"
    
    cmd = [
        "dfx", "canister", "call", *NETWORK, CANISTER_ID, "log_batch",
        f"({arg})"
    ]
    
    try:
        result = subprocess.run(
            cmd,
            cwd=DFX_PROJECT,
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            print(f"  ✓ Uploaded {len(actions)} actions: {result.stdout.strip()[:100]}")
            return True, len(actions)
        else:
            print(f"  ✗ Upload failed: {result.stderr[:200]}")
            return False, 0
    except Exception as e:
        print(f"  ✗ Error: {e}")
        return False, 0

def run_once(quiet=False):
    cp = load_checkpoint()
    
    actions = get_hermes_actions(cp.get("last_processed_id", 0))
    
    if not actions:
        if not quiet:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] No new actions")
        return 0
    
    if not quiet:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Found {len(actions)} new actions → uploading batch")
    
    success, count = upload_batch(actions)
    
    if success and actions:
        cp['last_processed_id'] = actions[-1]['rowid']
        save_checkpoint(cp)
    
    return count

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--interval', type=int, default=DEFAULT_INTERVAL,
                       help='Seconds between uploads (default: 300)')
    parser.add_argument('--batch-size', type=int, default=DEFAULT_BATCH_SIZE,
                       help='Max actions per batch (default: 50)')
    parser.add_argument('--once', action='store_true',
                       help='Run once and exit')
    args = parser.parse_args()
    
    print(f"Hermes → ICP Audit Bridge")
    print(f"  Canister: {CANISTER_ID}")
    print(f"  Interval: {args.interval}s")
    print(f"  Batch size: {args.batch_size}")
    print(f"  Checkpoint: {CHECKPOINT_FILE}")
    print()
    
    if args.once:
        run_once()
        return
    
    print("Running in loop mode. Ctrl+C to stop.")
    while True:
        try:
            run_once()
        except Exception as e:
            print(f"[ERROR] {e}")
        time.sleep(args.interval)

if __name__ == "__main__":
    main()

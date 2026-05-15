#!/usr/bin/env python3
"""Upload 400 most recent messages from state.db to ICP canister"""
import sqlite3
import hashlib
import json
import subprocess
import sys
import os

BATCH_SIZE = 50
NETWORK = ["--network", "ic"]
CANISTER_ID = "s7oui-qqaaa-aaaag-ayx2a-cai"
DFX_PROJECT = "/opt/data/icp/audit-log/audit_log"

# Read 400 most recent messages
conn = sqlite3.connect("/opt/data/state.db")
conn.row_factory = sqlite3.Row

cursor = conn.execute("""
    SELECT id, role, content, tool_name, tool_call_id, tool_calls, 
           timestamp, session_id, token_count, finish_reason
    FROM messages 
    WHERE id >= 16062
    ORDER BY id ASC
""")

actions = []
for row in cursor:
    content = row['content'] or ""
    content_preview = content[:200] + "..." if len(content) > 200 else content
    
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
    
    action_hash = hashlib.sha256(f"{role}:{content}".encode('utf-8')).hexdigest()[:24]
    
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
    })

conn.close()
print(f"Read {len(actions)} actions from state.db")

total_uploaded = 0
batch_num = 0
for batch_start in range(0, len(actions), BATCH_SIZE):
    batch = actions[batch_start:batch_start + BATCH_SIZE]
    batch_num += 1
    
    tuples = []
    for a in batch:
        meta_json = a["metadata"]
        escaped_meta = meta_json.replace('\\', '\\\\').replace('"', '\\"')
        t = f'record {{"{a["agent_id"]}"; "{a["action_type"]}"; "{a["action_hash"]}"; "{escaped_meta}"}}'
        tuples.append(t)
    
    arg = "vec { " + "; ".join(tuples) + " }"
    
    cmd = [
        "dfx", "canister", "call", *NETWORK, CANISTER_ID, "log_batch",
        f"({arg})"
    ]
    
    result = subprocess.run(cmd, cwd=DFX_PROJECT, capture_output=True, text=True, timeout=60)
    if result.returncode == 0:
        total_uploaded += len(batch)
        print(f"  Batch {batch_num}: ✓ {len(batch)} actions (total: {total_uploaded})")
    else:
        print(f"  Batch {batch_num}: ✗ FAILED")
        print(f"  stderr: {result.stderr[:300]}")
        sys.exit(1)

print(f"\n✓ Done. Total uploaded: {total_uploaded}")

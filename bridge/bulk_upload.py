#!/usr/bin/env python3
"""
Bulk re-upload all Hermes actions to the ICP audit log canister.
Runs multiple batches until all data is uploaded.
"""
import sys
sys.path.insert(0, '/opt/data/icp/audit-log')
from audit_bridge import *

cp = load_checkpoint()
print(f"Starting checkpoint: {cp}")

batch = 0
max_batches = 100  # safety limit

while batch < max_batches:
    batch += 1
    actions = get_hermes_actions(cp['last_processed_id'])
    
    if not actions:
        print(f"\n✅ All done after {batch-1} batches. Final checkpoint: {cp}")
        break
    
    print(f"\n=== Batch {batch}: {len(actions)} actions (starting from id {cp['last_processed_id']}) ===")
    
    # Build args for log_batch
    args = [(a['agent_id'], a['action_type'], a['action_hash'], a['metadata']) for a in actions]
    
    # Call dfx
    call_args = []
    for agent_id, action_type, action_hash, metadata in args:
        # Escape special chars for Candid text
        call_args.append(f'(\\"{agent_id}\\", \\"{action_type}\\", \\"{action_hash}\\", {metadata})')
    
    candid_arg = f'(vec {{ {"; ".join(call_args)} }})'
    
    import subprocess
    result = subprocess.run(
        ['dfx', 'canister', 'call', CANISTER_ID, 'log_batch', candid_arg, '--network', 'ic'],
        cwd=DFX_PROJECT,
        capture_output=True, text=True,
        timeout=120
    )
    
    if result.returncode == 0:
        cp['last_processed_id'] = actions[-1]['rowid']
        cp['session_id'] = actions[-1].get('session_id')
        save_checkpoint(cp)
        print(f"  ✅ Uploaded. New checkpoint: {cp['last_processed_id']}")
    else:
        print(f"  ❌ Error: {result.stderr[:300]}")
        break

print(f"\nFinal status: checkpoint = {load_checkpoint()}")

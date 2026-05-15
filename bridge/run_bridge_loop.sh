#!/bin/bash
# Hermes → ICP Audit Bridge: periodic batch uploader
# Runs every 5 minutes

LOG="/opt/data/icp/audit-log/bridge.log"
PROJECT="/opt/data/icp/audit-log"

while true; do
    # Ensure dfx replica is running
    cd "$PROJECT/audit_log" 2>/dev/null
    if ! dfx ping &>/dev/null; then
        echo "[$(date -Iseconds)] Starting dfx replica..." >> "$LOG"
        dfx start --background --clean 2>&1 >> "$LOG"
        sleep 3
    fi
    
    # Upload pending actions
    python3 "$PROJECT/audit_bridge.py" --once 2>&1 >> "$LOG"
    
    sleep 300  # 5 minutes
done


#!/bin/bash
# Hermes → ICP MAINNET Audit Bridge
LOG="/opt/data/icp/audit-log/bridge.log"
PROJECT="/opt/data/icp/audit-log"

export DFX_WARNING=-mainnet_plaintext_identity

while true; do
    python3 "$PROJECT/audit_bridge.py" --once 2>&1 >> "$LOG"
    sleep 300
done

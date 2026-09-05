#!/bin/bash
# Deploy YARA integration: copy updated module + install yara-python
set -e

SERVER=${1:-192.168.1.171}
FLOWINTEL_DIR=${2:-/opt/flowintel}

echo "=== Copying reverify_binary.py to $SERVER ==="
scp analyze/reverify_binary.py root@$SERVER:$FLOWINTEL_DIR/app/modules/analyze/reverify_binary.py

echo "=== Installing yara-python in Flowintel venv ==="
ssh root@$SERVER "
  source $FLOWINTEL_DIR/env/bin/activate && \
  pip install yara-python --quiet && \
  python -c 'import yara; print(\"yara-python OK:\", yara.__version__)'
"

echo "=== Restarting Flowintel ==="
ssh root@$SERVER "systemctl restart flowintel"

echo "=== Done! ==="
echo "YARA rule auto-generation is now active."
echo "Next analysis will include a YARA rule in the case Notes tab."

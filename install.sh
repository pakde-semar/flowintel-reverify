#!/usr/bin/env bash
# Install flowintel-reverify module into a running Flowintel instance
set -euo pipefail

FLOWINTEL_DIR="${FLOWINTEL_DIR:-/opt/flowintel}"
MODULE_DIR="$FLOWINTEL_DIR/app/modules"

if [ ! -d "$MODULE_DIR" ]; then
    echo "ERROR: Flowintel module directory not found: $MODULE_DIR"
    echo "Set FLOWINTEL_DIR env var to your Flowintel installation path."
    exit 1
fi

echo "Installing reverify_binary module to $MODULE_DIR/analyze/"
mkdir -p "$MODULE_DIR/analyze"
cp analyze/reverify_binary.py "$MODULE_DIR/analyze/"
cp analyze/__init__.py "$MODULE_DIR/analyze/" 2>/dev/null || true

echo ""
echo "Done. Restart Flowintel to load the module:"
echo "  systemctl restart flowintel"
echo ""
echo "Ensure reverify is installed and REVERIFY_VENV is set correctly."
echo "Default: /opt/reverfy/venv/lib/python3.12/site-packages"

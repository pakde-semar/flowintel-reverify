#!/usr/bin/env bash
# flowintel-reverify installer
# Installs all analyze modules, web UI blueprint, and sidebar link
# into a running Flowintel instance.
#
# Usage:
#   FLOWINTEL_DIR=/opt/flowintel bash install.sh
#
# Options (env vars):
#   FLOWINTEL_DIR   Path to Flowintel root          (default: /opt/flowintel)
#   FLOWINTEL_VENV  Path to Flowintel Python venv   (default: $FLOWINTEL_DIR/env)
#   SKIP_PATCH      Set to 1 to skip case_api patch (default: 0)
#   SKIP_DEPS       Set to 1 to skip pip/apt dependency install (default: 0)

set -euo pipefail

# ── Config ───────────────────────────────────────────────────────────────────
FLOWINTEL_DIR="${FLOWINTEL_DIR:-/opt/flowintel}"
FLOWINTEL_VENV="${FLOWINTEL_VENV:-$FLOWINTEL_DIR/env}"
SKIP_PATCH="${SKIP_PATCH:-0}"
SKIP_DEPS="${SKIP_DEPS:-0}"

APP_DIR="$FLOWINTEL_DIR/app"
MODULE_DIR="$APP_DIR/modules/analyze"
PLUGIN_DST="$APP_DIR/reverify_tool"
TEMPLATE_DST="$APP_DIR/templates/reverify_tool"
SIDEBAR="$APP_DIR/templates/sidebar.html"
INIT_PY="$APP_DIR/__init__.py"
CASE_API="$APP_DIR/case/case_api.py"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}  ✓${NC} $*"; }
warn() { echo -e "${YELLOW}  !${NC} $*"; }
err()  { echo -e "${RED}  ✗${NC} $*"; }

# ── Preflight ─────────────────────────────────────────────────────────────────
echo ""
echo "flowintel-reverify installer"
echo "============================"
echo "Flowintel dir : $FLOWINTEL_DIR"
echo "Venv          : $FLOWINTEL_VENV"
echo ""

if [ ! -d "$APP_DIR" ]; then
    err "Flowintel app directory not found: $APP_DIR"
    echo "    Set FLOWINTEL_DIR to your Flowintel installation path."
    exit 1
fi

if [ ! -f "$CASE_API" ]; then
    err "case_api.py not found: $CASE_API"
    exit 1
fi

# ── Step 1: Install Python dependencies ──────────────────────────────────────
if [ "$SKIP_DEPS" = "1" ]; then
    warn "Skipping dependency installation (SKIP_DEPS=1)"
else
    echo "[1/6] Installing Python dependencies into Flowintel venv..."
    if [ ! -f "$FLOWINTEL_VENV/bin/pip" ]; then
        err "Venv not found: $FLOWINTEL_VENV"
        echo "    Set FLOWINTEL_VENV or ensure the venv exists."
        exit 1
    fi

    # ssdeep requires the system library
    if ! dpkg -s libfuzzy-dev &>/dev/null; then
        echo "       Installing libfuzzy-dev (required by ssdeep)..."
        apt-get install -y -q libfuzzy-dev
    fi

    "$FLOWINTEL_VENV/bin/pip" install --quiet -r "$(dirname "$0")/requirements.txt"
    "$FLOWINTEL_VENV/bin/playwright" install chromium
    ok "All dependencies installed"
fi

# ── Step 2: Install analyze modules ───────────────────────────────────────────
echo "[2/6] Installing analyze modules..."
mkdir -p "$MODULE_DIR"
for mod in analyze/*.py; do
    cp "$mod" "$MODULE_DIR/"
done
[ -f "$MODULE_DIR/__init__.py" ] || touch "$MODULE_DIR/__init__.py"
ok "Modules installed: $(ls analyze/*.py | xargs -n1 basename | tr '\n' ' ')"

# ── Step 3: Install web UI + Mattermost hook blueprints ───────────────────────
echo "[3/6] Installing reverify_tool and mattermost_hook blueprints..."
mkdir -p "$PLUGIN_DST"
mkdir -p "$TEMPLATE_DST"
cp flowintel_plugin/reverify_tool/__init__.py "$PLUGIN_DST/"
cp flowintel_plugin/reverify_tool/views.py    "$PLUGIN_DST/"
cp flowintel_plugin/templates/reverify_tool/index.html    "$TEMPLATE_DST/"
cp flowintel_plugin/templates/reverify_tool/push_misp.html "$TEMPLATE_DST/"
ok "Blueprint installed: $PLUGIN_DST"

MATTERMOST_HOOK_DST="$APP_DIR/mattermost_hook"
mkdir -p "$MATTERMOST_HOOK_DST"
cp flowintel_plugin/mattermost_hook/__init__.py "$MATTERMOST_HOOK_DST/"
cp flowintel_plugin/mattermost_hook/views.py    "$MATTERMOST_HOOK_DST/"
ok "Blueprint installed: $MATTERMOST_HOOK_DST"

# Register blueprints in __init__.py (idempotent)
if grep -q "reverify_tool_blueprint" "$INIT_PY"; then
    warn "reverify_tool blueprint already registered — skipping"
else
    sed -i "s/    return app/    from .reverify_tool import reverify_tool_blueprint\n    app.register_blueprint(reverify_tool_blueprint, url_prefix=\"\/reverify\")\n\n    return app/" "$INIT_PY"
    ok "reverify_tool blueprint registered in $INIT_PY"
fi

if grep -q "mattermost_hook_blueprint" "$INIT_PY"; then
    warn "mattermost_hook blueprint already registered — skipping"
else
    python3 - "$INIT_PY" << 'PYEOF'
import sys
path = sys.argv[1]
content = open(path).read()
old = '    from .reverify_tool import reverify_tool_blueprint'
new = ('    from .mattermost_hook import mattermost_hook_blueprint\n'
       '    csrf.exempt(mattermost_hook_blueprint)\n'
       '    app.register_blueprint(mattermost_hook_blueprint, url_prefix="/mattermost")\n\n'
       '    from .reverify_tool import reverify_tool_blueprint')
open(path, 'w').write(content.replace(old, new))
PYEOF
    ok "mattermost_hook blueprint registered in $INIT_PY"
fi

# ── Step 4: Patch sidebar ─────────────────────────────────────────────────────
echo "[4/6] Patching sidebar..."
if grep -q "reverify/push_misp" "$SIDEBAR"; then
    warn "Sidebar already patched — skipping"
else
    # Insert sidebar links after the Analyser menu anchor
    REVERIFY_LINKS='                <a class="collapse-item" href="\/reverify\/">\n\t\t\t\t\t<i class="fa-solid fa-fw me-2 fa-file-code"><\/i>\n\t\t\t\t\t<span>Reverify Binary<\/span>\n\t\t\t\t<\/a>\n\t\t\t\t<a class="collapse-item" href="\/reverify\/push_misp">\n\t\t\t\t\t<i class="fa-solid fa-fw me-2 fa-share-nodes"><\/i>\n\t\t\t\t\t<span>Push Case to MISP<\/span>\n\t\t\t\t<\/a>'
    # Find the Analyser section and append after its closing </a>
    if grep -q 'href="/connectors/"' "$SIDEBAR"; then
        sed -i "s|<a class=\"collapse-item\" href=\"/connectors/\"|${REVERIFY_LINKS}\n\t\t\t\t<a class=\"collapse-item\" href=\"/connectors/\"|" "$SIDEBAR"
        ok "Sidebar patched"
    else
        warn "Could not locate sidebar injection point — add links manually:"
        echo '    <a class="collapse-item" href="/reverify/">'
        echo '        <i class="fa-solid fa-fw me-2 fa-file-code"></i>'
        echo '        <span>Reverify Binary</span>'
        echo '    </a>'
        echo '    <a class="collapse-item" href="/reverify/push_misp">'
        echo '        <i class="fa-solid fa-fw me-2 fa-share-nodes"></i>'
        echo '        <span>Push Case to MISP</span>'
        echo '    </a>'
    fi
fi

# ── Step 5: Install Mattermost notify_user module ─────────────────────────────
echo "[5/6] Installing Mattermost notify_user module..."
NOTIFY_DIR="$APP_DIR/modules/notify_user"
if [ -d "$NOTIFY_DIR" ]; then
    cp notify_user/mattermost.py "$NOTIFY_DIR/"
    ok "Mattermost notify module installed: $NOTIFY_DIR/mattermost.py"
else
    warn "notify_user directory not found: $NOTIFY_DIR — skipping Mattermost module"
fi

# Add Mattermost config to config_module.py (idempotent)
CONFIG_FILE="$FLOWINTEL_DIR/conf/config_module.py"
if grep -q "MATTERMOST_WEBHOOK_URL" "$CONFIG_FILE"; then
    warn "Mattermost config already in $CONFIG_FILE — skipping"
else
    cat >> "$CONFIG_FILE" << 'CONF'

# Mattermost incoming webhook
MATTERMOST_WEBHOOK_URL = ""
MATTERMOST_CHANNEL = ""
MATTERMOST_ENABLED = False
CONF
    ok "Mattermost config added to $CONFIG_FILE"
    warn "Set MATTERMOST_WEBHOOK_URL and MATTERMOST_ENABLED=True in $CONFIG_FILE to activate"
fi

# ── Step 6: Patch case_api.py ─────────────────────────────────────────────────
echo "[6/6] Patching case_api.py..."
if [ "$SKIP_PATCH" = "1" ]; then
    warn "Skipping case_api patch (SKIP_PATCH=1)"
elif grep -q "run_analyze_module" "$CASE_API"; then
    warn "case_api.py already patched — skipping"
else
    if patch --dry-run -p1 "$CASE_API" < patch/case_api_analyze_route.patch > /dev/null 2>&1; then
        patch -p1 "$CASE_API" < patch/case_api_analyze_route.patch
        ok "case_api.py patched"
    else
        warn "Patch does not apply cleanly — Flowintel version may differ."
        warn "Apply manually: patch/case_api_analyze_route.patch"
        warn "Or set SKIP_PATCH=1 and use the API endpoint another way."
    fi
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}Installation complete.${NC}"
echo ""
echo "Next steps:"
echo "  1. Set MATTERMOST_WEBHOOK_URL and MATTERMOST_ENABLED=True in conf/config_module.py (optional)"
echo "  2. Restart Flowintel:  systemctl restart flowintel"
echo "  3. Open: https://<your-flowintel>/reverify/"
echo "  4. Ensure a MISP connector is configured under Flowintel → Connectors"
echo "  5. Modules available: reverify_binary, enrich_observable, correlate_observables,"
echo "                        suggest_assessment, assess_case"
echo ""

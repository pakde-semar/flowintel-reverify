#!/usr/bin/env bash
# Seed Flowintel custom tags for 3 case-type families.
# Run on any host that can reach FLOWINTEL_URL.
#
# Usage:
#   FLOWINTEL_KEY=<key> bash scripts/seed_case_types.sh [--dry-run]

set -euo pipefail

FLOWINTEL_URL="${FLOWINTEL_URL:-https://flowintel.iww.web.id}"
FLOWINTEL_KEY="${FLOWINTEL_KEY:-aO4EEcQ50S1ouVaobz6okouwpsBUjNIqXgjyD0hP7IZuEwYkdQ94m55y2fR7}"
DRY_RUN=0
[[ "${1:-}" == "--dry-run" ]] && DRY_RUN=1

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; GRAY='\033[0;37m'; NC='\033[0m'
ok()   { echo -e "${GREEN}  ✓${NC} $*"; }
skip() { echo -e "${GRAY}  –${NC} $*"; }
dry()  { echo -e "${YELLOW}  [dry]${NC} $*"; }

echo "Flowintel : $FLOWINTEL_URL"
echo "Dry-run   : $DRY_RUN"
echo ""

# Fetch existing tag names
EXISTING=$(curl -sf -H "X-API-KEY: $FLOWINTEL_KEY" "$FLOWINTEL_URL/api/custom_tags/all" \
           | python3 -c "import sys,json; print('\n'.join(t['name'] for t in json.load(sys.stdin)))" 2>/dev/null || true)

create_tag() {
    local name="$1" color="$2" icon="$3"
    if echo "$EXISTING" | grep -qxF "$name"; then
        skip "(exists) $name"
        return
    fi
    if [ "$DRY_RUN" = "1" ]; then
        dry "CREATE  $name  [$color]  $icon"
        return
    fi
    local resp
    resp=$(curl -sf -X POST \
        -H "X-API-KEY: $FLOWINTEL_KEY" \
        -H "Content-Type: application/json" \
        -d "{\"name\":$(python3 -c "import json,sys; print(json.dumps(sys.argv[1]))" "$name"),\"color\":\"$color\",\"icon\":\"$icon\"}" \
        "$FLOWINTEL_URL/api/custom_tags/add" 2>&1) && ok "$name" || echo "  ✗ $name: $resp"
}

echo "══ INCIDENT CASE ═══════════════════════════════════════"
create_tag "Incident: Phishing"            "#dc3545" "fa-solid fa-fish-fins"
create_tag "Incident: Account Compromise"  "#c0392b" "fa-solid fa-user-lock"
create_tag "Incident: Endpoint Compromise" "#e74c3c" "fa-solid fa-laptop"
create_tag "Incident: Server Compromise"   "#b03a2e" "fa-solid fa-server"
create_tag "Incident: Web Compromise"      "#e95757" "fa-solid fa-globe"
create_tag "Incident: Data Breach"         "#922b21" "fa-solid fa-database"
create_tag "Incident: Ransomware"          "#f1948a" "fa-solid fa-lock"
create_tag "Incident: Network Intrusion"   "#d98880" "fa-solid fa-network-wired"
create_tag "Incident: DDoS"               "#ec7063" "fa-solid fa-bolt"

echo ""
echo "══ TECHNICAL INVESTIGATION CASE ════════════════════════"
create_tag "Investigation: Malware / Suspicious File"  "#1a6eb5" "fa-solid fa-bug"
create_tag "Investigation: Suspicious Domain"          "#2471a3" "fa-solid fa-at"
create_tag "Investigation: Suspicious URL"             "#1f618d" "fa-solid fa-link"
create_tag "Investigation: Suspicious IP"              "#2980b9" "fa-solid fa-tower-broadcast"
create_tag "Investigation: Malicious Document"         "#1a5276" "fa-solid fa-file-shield"
create_tag "Investigation: Malicious APK"              "#154360" "fa-solid fa-mobile-screen-button"
create_tag "Investigation: C2 Infrastructure"          "#2e86c1" "fa-solid fa-diagram-project"
create_tag "Investigation: Vulnerability Exploitation" "#1b4f72" "fa-solid fa-triangle-exclamation"

echo ""
echo "══ FORENSIC CASE ════════════════════════════════════════"
create_tag "Forensic: Disk Forensics"              "#7d3c98" "fa-solid fa-hard-drive"
create_tag "Forensic: Memory Forensics"            "#6c3483" "fa-solid fa-memory"
create_tag "Forensic: Endpoint Forensics"          "#884ea0" "fa-solid fa-desktop"
create_tag "Forensic: Mobile Forensics"            "#9b59b6" "fa-solid fa-mobile"
create_tag "Forensic: Log / Timeline Investigation" "#7b241c" "fa-solid fa-timeline"
create_tag "Forensic: Network Forensics"           "#5b2c6f" "fa-solid fa-magnifying-glass-chart"

echo ""
echo "Done."

import requests
from flask import request, jsonify
from . import mattermost_hook_blueprint
import conf.config_module as Config


def _ephemeral(text):
    return jsonify({"response_type": "ephemeral", "text": text})


def _in_channel(text):
    return jsonify({"response_type": "in_channel", "text": text})


@mattermost_hook_blueprint.route('/create_case', methods=['POST'])
def create_case():
    """
    Mattermost slash command endpoint.
    Usage: /flowintel <title> [| description]

    Mattermost sends application/x-www-form-urlencoded with:
      token, team_id, channel_id, user_id, user_name, command, text, response_url
    """
    # Token verification
    expected_token = getattr(Config, "MATTERMOST_SLASH_TOKEN", "")
    if expected_token and request.form.get("token", "") != expected_token:
        return _ephemeral("Unauthorized — token mismatch."), 403

    text = request.form.get("text", "").strip()
    user_name = request.form.get("user_name", "mattermost")

    if not text or text in ("help", "--help"):
        return _ephemeral(
            "**Usage:** `/flowintel <case title> [| description]`\n\n"
            "**Examples:**\n"
            "- `/flowintel Suspicious dropper dari email HR`\n"
            "- `/flowintel Ransomware pada workstation | Ditemukan 09:00, endpoint: PC-042`"
        )

    # Parse: title | description
    parts = text.split("|", 1)
    title = parts[0].strip()
    description = parts[1].strip() if len(parts) > 1 else f"Case opened via Mattermost by @{user_name}"

    if not title:
        return _ephemeral("Case title tidak boleh kosong.")

    # Call Flowintel API
    api_key = getattr(Config, "FLOWINTEL_API_KEY", "")
    flowintel_url = getattr(Config, "FLOWINTEL_URL", "http://localhost:7006").rstrip("/")

    try:
        resp = requests.post(
            f"http://localhost:7006/api/case/create",
            json={"title": title, "description": description},
            headers={"X-API-KEY": api_key, "Content-Type": "application/json"},
            timeout=10
        )
    except Exception as e:
        return _ephemeral(f"Gagal menghubungi Flowintel: {e}")

    if resp.status_code == 201:
        case_id = resp.json().get("case_id", "?")
        case_url = f"{flowintel_url}/case/{case_id}"
        return _in_channel(
            f":white_check_mark: **Case #{case_id} dibuat**\n"
            f"**Judul:** {title}\n"
            f"**Link:** {case_url}\n"
            f"_Dibuka via Mattermost oleh @{user_name}_"
        )
    else:
        msg = resp.json().get("message", resp.text)
        return _ephemeral(f"Gagal membuat case: {msg}")


@mattermost_hook_blueprint.route('/status', methods=['GET'])
def status():
    """Health check — verifikasi koneksi ke Flowintel."""
    api_key = getattr(Config, "FLOWINTEL_API_KEY", "")
    try:
        resp = requests.get(
            "http://localhost:7006/api/case/all",
            headers={"X-API-KEY": api_key},
            timeout=5
        )
        return jsonify({"status": "ok", "flowintel": resp.status_code})
    except Exception as e:
        return jsonify({"status": "error", "detail": str(e)}), 503

import requests
import conf.config_module as Config

module_config = {
    "case_task": "task"
}


def handler(task, case, current_user, user):
    """
    Notify a user via Mattermost incoming webhook.

    task         : task object (may be None for case-level notifications)
    case         : case object — id, title, uuid, status, description
    current_user : user who triggered the action
    user         : user to notify — id, first_name, last_name, email
    """
    if not getattr(Config, "MATTERMOST_ENABLED", False):
        return

    webhook_url = getattr(Config, "MATTERMOST_WEBHOOK_URL", "")
    if not webhook_url:
        return

    user_name = f"{user.first_name} {user.last_name}".strip() or user.email
    triggered_by = f"{current_user.first_name} {current_user.last_name}".strip() or current_user.email

    case_id = case.id if hasattr(case, "id") else case.get("id", "")
    case_title = case.title if hasattr(case, "title") else case.get("title", "")

    base_url = getattr(Config, "FLOWINTEL_URL", f"http://{Config.ORIGIN_URL}").rstrip("/")
    case_url = f"{base_url}/case/{case_id}"

    lines = [
        f"**{user_name}**, your attention is required on a case.",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| **Case** | [{case_title}]({case_url}) |",
        f"| **Case ID** | {case_id} |",
        f"| **Triggered by** | {triggered_by} |",
    ]

    if task:
        task_title = task.title if hasattr(task, "title") else str(task)
        lines.append(f"| **Task** | {task_title} |")

    payload = {"text": "\n".join(lines)}

    channel = getattr(Config, "MATTERMOST_CHANNEL", "")
    if channel:
        payload["channel"] = channel

    try:
        requests.post(webhook_url, json=payload, timeout=10)
    except Exception as e:
        print(f"[mattermost] notification failed: {e}")


def introspection():
    return module_config

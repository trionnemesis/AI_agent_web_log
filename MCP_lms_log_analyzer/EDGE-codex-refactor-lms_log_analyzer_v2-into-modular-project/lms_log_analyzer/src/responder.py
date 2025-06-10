"""通知模組

This module sends alerts to collaboration tools such as Slack or Microsoft Teams.
Webhook URLs can be stored in environment variables or retrieved from Vault.
Functions here provide a thin wrapper around HTTP webhook calls.
"""

import os
from typing import Optional

import requests

from .. import config
from .utils import http_request_with_retry

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
TEAMS_WEBHOOK_URL = os.getenv("TEAMS_WEBHOOK_URL")


def _webhook_from_vault(secret_path: str) -> Optional[str]:
    """Fetch a webhook URL from Vault if available."""
    try:
        import hvac
    except Exception:
        return None
    client = hvac.Client(url=os.getenv("VAULT_ADDR"), token=os.getenv("VAULT_TOKEN"))
    try:
        secret = client.secrets.kv.v2.read_secret_version(path=secret_path)
        return secret["data"]["data"].get("webhook_url")
    except Exception:
        return None


def _get_webhook(env_value: Optional[str], secret_path: str) -> Optional[str]:
    return _webhook_from_vault(secret_path) or env_value


def send_slack_alert(message: str) -> None:
    """Send a Slack alert if configuration is available."""
    url = _get_webhook(SLACK_WEBHOOK_URL, "secret/lms_log_analyzer/slack")
    if not url:
        return
    http_request_with_retry("post", url, json={"text": message})


def send_teams_alert(message: str) -> None:
    """Send a Microsoft Teams alert if configuration is available."""
    url = _get_webhook(TEAMS_WEBHOOK_URL, "secret/lms_log_analyzer/teams")
    if not url:
        return
    http_request_with_retry("post", url, json={"text": message})

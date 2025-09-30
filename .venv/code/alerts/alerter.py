# alerter.py

import requests
import json
import logging

logger = logging.getLogger(__name__)

def send_slack_alert(alert, webhook_url):
    """
    Formate et envoie une alerte de sécurité à un webhook Slack.
    """
    if not webhook_url:
        logger.error("URL du webhook Slack non fournie. Impossible d'envoyer l'alerte.")
        return

    severity = alert.get("severity", "INFO")
    severity_map = {
        "CRITICAL": {"color": "#FF0000", "icon": ":rotating_light:"},
        "HIGH": {"color": "#FF8C00", "icon": ":warning:"},
        "MEDIUM": {"color": "#FFFF00", "icon": ":radioactive_sign:"},
        "LOW": {"color": "#00BFFF", "icon": ":information_source:"},
        "INFO": {"color": "#808080", "icon": ":speech_balloon:"}
    }
    
    color = severity_map.get(severity, {}).get("color", "#808080")
    icon = severity_map.get(severity, {}).get("icon", ":grey_question:")

    # Extraction des détails
    rule_name = alert.get('rule_name', 'N/A')
    event_details = alert.get('event_details', {})
    source_ip = event_details.get('sourceIPAddress', event_details.get('sourceIP', 'N/A'))
    user = event_details.get('userIdentity', {}).get('userName', 'N/A')
    event_time = event_details.get('eventTime', 'N/A')
    recommended_actions = "\n".join(f"- {action}" for action in alert.get('recommended_actions', []))

    # Construction du message avec Block Kit
    slack_payload = {
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"{icon} Alerte de Sécurité : {rule_name}"
                        }
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Sévérité:*\n`{severity}`"},
                            {"type": "mrkdwn", "text": f"*Heure (UTC):*\n{event_time}"},
                            {"type": "mrkdwn", "text": f"*Utilisateur:*\n{user}"},
                            {"type": "mrkdwn", "text": f"*IP Source:*\n{source_ip}"}
                        ]
                    },
                    { "type": "divider" },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Actions Recommandées:*\n{recommended_actions or 'Aucune'}"
                        }
                    }
                ]
            }
        ]
    }
    
    try:
        response = requests.post(
            webhook_url,
            data=json.dumps(slack_payload),
            headers={'Content-Type': 'application/json'}
        )
        if response.status_code != 200:
            logger.error(f"Erreur lors de l'envoi à Slack: {response.status_code} {response.text}")
    except Exception as e:
        logger.error(f"Exception lors de la connexion à Slack: {e}")

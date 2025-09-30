# test_slack.py

import os
import alerter

def main():
    # ⚠️ Remplace par ton vrai webhook Slack ou utilise la variable d'environnement
    slack_url = os.environ.get("SLACK_WEBHOOK_URL", "https://hooks.slack.com/services/XXXX/XXXX/XXXX")

    if slack_url.startswith("https://hooks.slack.com/services/XXXX"):
        print("❌ ERREUR : Merci de définir une vraie URL Slack ou d'exporter SLACK_WEBHOOK_URL.")
        return

    # Exemple de fausse alerte
    fake_alert = {
        "rule_name": "IAM User Exfiltration",
        "severity": "CRITICAL",
        "event_details": {
            "eventTime": "2025-09-10T12:00:00Z",
            "userIdentity": {"userName": "malicious_user"},
            "sourceIPAddress": "192.168.1.100",
            "awsRegion": "us-east-1"
        },
        "recommended_actions": [
            "Désactiver l'utilisateur IAM immédiatement.",
            "Vérifier les clés d'accès associées.",
            "Analyser les logs CloudTrail pour d'autres activités suspectes."
        ]
    }

    # Envoi de l'alerte
    print("🚀 Envoi d'une alerte test vers Slack...")
    alerter.send_slack_alert(fake_alert, slack_url)
    print("✅ Test terminé.")

if __name__ == "__main__":
    main()

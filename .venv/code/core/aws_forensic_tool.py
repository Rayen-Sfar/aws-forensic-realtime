# aws_forensic_tool.py
# Outil principal
import argparse
import logging
import os

# Assurez-vous d'utiliser la classe de l'analyseur avancé
from log_analyzer import ForensicAnalyzer
import alerter
import respond

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def main():
    parser = argparse.ArgumentParser(description="Outil d'analyse forensique et de réponse sur AWS.")
    parser.add_argument('--bucket', required=True, help='Bucket S3 des logs.')
    parser.add_argument('--prefix', default='cloudtrail/', help='Préfixe des logs dans le bucket.')
    parser.add_argument('--rules', default='rules.json', help='Fichier de règles de détection.')
    parser.add_argument('--output', default='alerts_report.json', help='Fichier de sortie du rapport.')

    # Arguments pour l'alerte et la réponse
    parser.add_argument('--slack-webhook-url', help="URL du webhook Slack pour les alertes. Peut aussi être définie via la variable d'environnement SLACK_WEBHOOK_URL.")
    parser.add_argument('--auto-respond', action='store_true', help="Active les actions de réponse automatiques. À utiliser avec une extrême prudence.")
    
    args = parser.parse_args()

    # ✅ Correction : ne pas mettre l’URL en dur, mais la récupérer proprement
    slack_url = args.slack_webhook_url or os.environ.get('SLACK_WEBHOOK_URL')

    if args.auto_respond:
        logger.warning("************************************************************")
        logger.warning("*  LE MODE DE RÉPONSE AUTOMATIQUE EST ACTIVÉ.              *")
        logger.warning("*  Des modifications seront apportées à votre compte AWS.  *")
        logger.warning("************************************************************")
    
    # 1. Analyse
    logger.info("Démarrage de la phase d'analyse...")
    analyzer = ForensicAnalyzer(args.bucket, args.prefix, args.rules)
    events = analyzer.load_events_from_s3()
    alerts = analyzer.analyze_events(events)
    report = analyzer.generate_report(args.output)
    
    if not alerts:
        logger.info("Aucune alerte détectée. Fin du processus.")
        return
        
    logger.info(f"{len(alerts)} alerte(s) détectée(s).")

    # 2. Alerte & Réponse
    for alert in alerts:
        logger.info(f"Traitement de l'alerte: {alert['rule_name']}")
        
        # 2a. Envoyer l'alerte
        if slack_url:
            alerter.send_slack_alert(alert, slack_url)
        else:
            logger.warning("Aucune URL de webhook Slack fournie, alerte non envoyée.")

        # 2b. Réponse automatique (si activée)
        if args.auto_respond:
            category = alert.get('category')
            
            if category == 'IAM_COMPROMISE':
                user = alert.get('event_details', {}).get('userIdentity', {}).get('userName')
                if user:
                    respond.block_iam_user(user)

            elif category == 'CRYPTOJACKING':
                instance_id = (
                    alert.get('event_details', {})
                         .get('responseElements', {})
                         .get('instancesSet', {})
                         .get('items', [{}])[0]
                         .get('instanceId')
                )
                aws_region = alert.get('event_details', {}).get('awsRegion')
                if instance_id and aws_region:
                    respond.isolate_ec2_instance(instance_id, aws_region)

            # TODO: ajouter d'autres logiques si nécessaire
        else:
            logger.info("Mode de réponse automatique désactivé. Aucune action ne sera effectuée.")

if __name__ == '__main__':
    main()

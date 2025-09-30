#!/usr/bin/env python3
"""
advanced_analyzer.py - Analyseur forensic avancé pour AWS

Ce script analyse les logs CloudTrail et les métriques CloudWatch pour détecter
des activités malveillantes selon des règles définies. Il supporte :
- Corrélation entre événements CloudTrail et métriques CloudWatch
- Détection de comportements anormaux basée sur des seuils
- Enrichissement des alertes avec des données contextuelles
- Identification de patterns d'attaque connus (MITRE ATT&CK)
"""

import json
import boto3
import logging
import time
from datetime import datetime, timedelta
from botocore.exceptions import ClientError
from ioc_checker import is_malicious_ip

# Configuration du logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration AWS
AWS_REGION = 'us-east-1'  # Région par défaut, peut être remplacée par un argument

class ForensicAnalyzer:
    """
    Analyseur forensic avancé qui traite les événements AWS pour détecter des activités suspectes.
    """
    
    def __init__(self, rules_path='rules.json', region=AWS_REGION):
        """Initialise l'analyseur avec les règles et la configuration."""
        self.rules = self.load_rules(rules_path)
        self.region = region
        self.cloudtrail = boto3.client('cloudtrail', region_name=region)
        self.cloudwatch = boto3.client('cloudwatch', region_name=region)
        self.ec2 = boto3.client('ec2', region_name=region)
        self.iam = boto3.client('iam')
        self.threat_intel_cache = {}  # Cache pour éviter de faire trop d'appels API
        
    def load_rules(self, rules_path):
        """Charge les règles depuis un fichier JSON."""
        try:
            with open(rules_path, 'r', encoding='utf-8') as f:
                rules = json.load(f)
            
            # Validation basique des règles
            for rule in rules:
                required_fields = ['name', 'severity', 'condition']
                if not all(field in rule for field in required_fields):
                    logger.warning(f"Règle invalide (champs requis manquants): {rule.get('name', 'Sans nom')}")
            
            logger.info(f"Chargement réussi de {len(rules)} règles depuis {rules_path}")
            return rules
        except FileNotFoundError:
            logger.error(f"Fichier de règles non trouvé: {rules_path}")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Erreur de format JSON dans {rules_path}: {e}")
            return []
    
    def load_events_from_file(self, filepath):
        """Charge les événements depuis un fichier JSON pour les tests."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                events = json.load(f)
            logger.info(f"Chargement de {len(events)} événements depuis {filepath}")
            return events
        except Exception as e:
            logger.error(f"Erreur lors du chargement des événements depuis {filepath}: {e}")
            return []
    
    def fetch_events_from_s3(self, bucket, prefix, max_events=1000):
        """Récupère les événements CloudTrail stockés dans un bucket S3."""
        s3 = boto3.client('s3')
        events = []
        
        try:
            # Liste tous les objets dans le préfixe spécifié
            response = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
            
            if 'Contents' not in response:
                logger.warning(f"Aucun fichier trouvé dans s3://{bucket}/{prefix}")
                return []
            
            # Traite chaque fichier CloudTrail
            count = 0
            for obj in response['Contents']:
                if count >= max_events:
                    break
                    
                if not obj['Key'].endswith('.json'):
                    continue
                    
                # Télécharge et parse le fichier
                file_obj = s3.get_object(Bucket=bucket, Key=obj['Key'])
                file_content = file_obj['Body'].read().decode('utf-8')
                try:
                    data = json.loads(file_content)
                    if 'Records' in data:  # Format standard CloudTrail
                        events.extend(data['Records'])
                        count += len(data['Records'])
                    else:
                        events.append(data)  # Format de test simple
                        count += 1
                except json.JSONDecodeError:
                    logger.warning(f"Fichier non-JSON ignoré: {obj['Key']}")
            
            logger.info(f"Récupération de {len(events)} événements depuis S3")
            return events
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des événements depuis S3: {e}")
            return []
    
    def query_cloudtrail_directly(self, lookback_hours=24):
        """Interroge CloudTrail directement via l'API pour les événements récents."""
        events = []
        try:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=lookback_hours)
            
            paginator = self.cloudtrail.get_paginator('lookup_events')
            for page in paginator.paginate(
                StartTime=start_time,
                EndTime=end_time
            ):
                events.extend(page.get('Events', []))
                
            # Normalisation des événements pour correspondre au format standard
            normalized_events = []
            for event in events:
                try:
                    # Les événements de l'API lookup_events ont un format légèrement différent
                    # que nous devons normaliser
                    if 'CloudTrailEvent' in event:
                        cloud_trail_event = json.loads(event['CloudTrailEvent'])
                        normalized_events.append(cloud_trail_event)
                except (json.JSONDecodeError, KeyError):
                    logger.warning(f"Impossible de normaliser un événement: {event}")
            
            logger.info(f"Récupération de {len(normalized_events)} événements depuis l'API CloudTrail")
            return normalized_events
        except Exception as e:
            logger.error(f"Erreur lors de la récupération des événements depuis CloudTrail: {e}")
            return []
    
    def check_cloudwatch_metrics(self, instance_id, metric_name, namespace, threshold, period_minutes):
        """
        Vérifie si une métrique CloudWatch dépasse un seuil sur une période donnée.
        
        Args:
            instance_id: L'ID de l'instance EC2
            metric_name: Le nom de la métrique à vérifier (ex: 'CPUUtilization')
            namespace: Le namespace CloudWatch (ex: 'AWS/EC2')
            threshold: La valeur seuil à dépasser
            period_minutes: La période sur laquelle vérifier (en minutes)
            
        Returns:
            tuple: (bool, float) - Un booléen indiquant si le seuil est dépassé et la valeur max
        """
        try:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(minutes=period_minutes)
            
            response = self.cloudwatch.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                StartTime=start_time,
                EndTime=end_time,
                Period=300,  # 5 minutes
                Statistics=['Maximum']
            )
            
            datapoints = response.get('Datapoints', [])
            if not datapoints:
                logger.warning(f"Aucune métrique trouvée pour {instance_id} sur {metric_name}")
                return False, 0
                
            max_value = max([point['Maximum'] for point in datapoints])
            is_above_threshold = max_value > threshold
            
            if is_above_threshold:
                logger.info(f"Métrique {metric_name} pour {instance_id}: {max_value} > {threshold}")
            
            return is_above_threshold, max_value
            
        except ClientError as e:
            logger.error(f"Erreur CloudWatch pour {instance_id}: {e}")
            return False, 0
    
    def check_malicious_ip(self, ip_address):
        """
        Vérifie si une IP est malveillante avec cache pour éviter les appels répétés.
        """
        if not ip_address or ip_address == "unknown":
            return False
            
        # Utilise le cache pour éviter de faire trop d'appels API
        if ip_address in self.threat_intel_cache:
            return self.threat_intel_cache[ip_address]
            
        result = is_malicious_ip(ip_address)
        self.threat_intel_cache[ip_address] = result
        return result
        
    def enrich_event_with_context(self, event):
        """
        Enrichit un événement avec des informations contextuelles supplémentaires.
        """
        enriched_event = event.copy()
        
        try:
            # Enrichissement pour EC2
            if event.get('eventSource') == 'ec2.amazonaws.com' and event.get('eventName') == 'RunInstances':
                # Récupérer l'ID d'instance depuis la réponse
                instance_id = None
                if 'responseElements' in event and 'instancesSet' in event['responseElements']:
                    items = event['responseElements']['instancesSet'].get('items', [])
                    if items:
                        instance_id = items[0].get('instanceId')
                
                if instance_id:
                    enriched_event['instance_details'] = {
                        'instance_id': instance_id
                    }
                    
                    # Ajoute des informations sur le type d'instance
                    try:
                        response = self.ec2.describe_instances(InstanceIds=[instance_id])
                        if response['Reservations']:
                            instance = response['Reservations'][0]['Instances'][0]
                            enriched_event['instance_details'].update({
                                'instance_type': instance.get('InstanceType'),
                                'launch_time': instance.get('LaunchTime'),
                                'vpc_id': instance.get('VpcId'),
                                'subnet_id': instance.get('SubnetId'),
                                'private_ip': instance.get('PrivateIpAddress'),
                                'public_ip': instance.get('PublicIpAddress')
                            })
                    except Exception as e:
                        logger.warning(f"Erreur lors de l'enrichissement EC2: {e}")
            
            # Enrichissement pour IAM
            if event.get('eventSource') == 'iam.amazonaws.com':
                user_name = None
                
                # Récupérer le nom d'utilisateur cible
                if event.get('eventName') == 'CreateAccessKey' and 'requestParameters' in event:
                    user_name = event['requestParameters'].get('userName')
                elif 'userIdentity' in event and 'userName' in event['userIdentity']:
                    user_name = event['userIdentity']['userName']
                    
                if user_name:
                    try:
                        # Obtenir des infos sur l'utilisateur
                        user_response = self.iam.get_user(UserName=user_name)
                        user = user_response.get('User', {})
                        enriched_event['user_details'] = {
                            'creation_date': user.get('CreateDate'),
                            'path': user.get('Path')
                        }
                        
                        # Obtenir les stratégies attachées
                        policies_response = self.iam.list_attached_user_policies(UserName=user_name)
                        enriched_event['user_details']['attached_policies'] = [
                            policy['PolicyName'] for policy in policies_response.get('AttachedPolicies', [])
                        ]
                    except Exception as e:
                        logger.warning(f"Erreur lors de l'enrichissement IAM: {e}")
        except Exception as e:
            logger.error(f"Erreur générale d'enrichissement: {e}")
            
        return enriched_event
        
    def evaluate_condition(self, event, condition):
        """
        Évalue une condition de règle par rapport à un événement.
        Supporte les conditions simples et les conditions complexes (AND, OR).
        """
        # Condition simple sur le nom de l'événement
        if 'eventName' in condition:
            event_name_condition = condition['eventName']
            event_name = event.get('eventName')
            
            # Si la condition est une liste, on vérifie l'appartenance
            if isinstance(event_name_condition, list):
                if event_name not in event_name_condition:
                    return False
            # Sinon, on compare directement
            else:
                if event_name != event_name_condition:
                    return False
                    
        # Condition sur l'IP source (si elle est malveillante)
        if 'sourceIPIsMalicious' in condition and condition['sourceIPIsMalicious']:
            source_ip = event.get('sourceIPAddress')
            if not self.check_malicious_ip(source_ip):
                return False
                
        # Condition sur le nom du bucket S3
        if 'bucketName_startsWith' in condition:
            bucket_name = None
            if 'requestParameters' in event and 'bucketName' in event['requestParameters']:
                bucket_name = event['requestParameters']['bucketName']
                
            if not bucket_name or not bucket_name.startswith(condition['bucketName_startsWith']):
                return False
                
        # Condition sur le nombre d'événements similaires
        # (Cette partie est complexe et nécessiterait une base de données pour être efficace)
        # Dans cet exemple, nous simulons une détection basique
        if 'frequency' in condition and condition['frequency'].get('enabled', False):
            # Dans une implémentation réelle, il faudrait interroger une base de données
            # pour compter les événements similaires dans la période spécifiée
            # Pour cet exemple, on considère que c'est toujours faux
            return False
            
        # Condition sur les métriques CloudWatch (pour le cryptojacking)
        if 'cloudwatch' in condition:
            cw_condition = condition['cloudwatch']
            
            # On a besoin d'un ID d'instance pour vérifier les métriques
            instance_id = None
            if 'instance_details' in event and 'instance_id' in event['instance_details']:
                instance_id = event['instance_details']['instance_id']
            elif 'responseElements' in event and 'instancesSet' in event['responseElements']:
                items = event['responseElements']['instancesSet'].get('items', [])
                if items:
                    instance_id = items[0].get('instanceId')
                    
            if instance_id:
                # Vérifie si la métrique dépasse le seuil
                is_above, value = self.check_cloudwatch_metrics(
                    instance_id,
                    cw_condition.get('metric', 'CPUUtilization'),
                    cw_condition.get('namespace', 'AWS/EC2'),
                    cw_condition.get('threshold', 90),
                    cw_condition.get('period_minutes', 60)
                )
                
                if not is_above:
                    return False
                    
                # Stocke la valeur pour l'inclure dans l'alerte
                event['cloudwatch_metrics'] = {
                    'cpu_utilization': value,
                    'cpu_high': is_above
                }
            else:
                # Pas d'instance ID, donc pas moyen de vérifier CloudWatch
                return False
                
        # Si toutes les conditions sont remplies, on retourne True
        return True

    def analyze_event(self, event):
        """
        Analyse un événement selon les règles définies et retourne les alertes générées.
        """
        alerts = []
        
        # Enrichir l'événement avec des informations contextuelles
        enriched_event = self.enrich_event_with_context(event)
        
        # Évaluer chaque règle
        for rule in self.rules:
            condition = rule.get('condition', {})
            
            # Si la règle correspond, générer une alerte
            if self.evaluate_condition(enriched_event, condition):
                severity = rule['severity']
                
                # Augmenter la sévérité si l'IP est malveillante
                source_ip = enriched_event.get('sourceIPAddress')
                is_malicious = self.check_malicious_ip(source_ip)
                if is_malicious and severity != "CRITICAL":
                    severity = "CRITICAL"
                    
                # Créer une structure d'alerte enrichie
                alert = {
                    "rule_id": rule.get('id', f"{enriched_event.get('eventSource', 'unknown').split('.')[0]}_001"),
                    "rule_name": rule['name'],
                    "severity": severity,
                    "category": rule.get('category', 'UNKNOWN'),
                    "event_details": {
                        "eventName": enriched_event.get('eventName'),
                        "sourceIP": enriched_event.get('sourceIPAddress'),
                        "userIdentity": enriched_event.get('userIdentity'),
                        "eventTime": enriched_event.get('eventTime')
                    },
                    "recommended_actions": rule.get('response', []),
                    "mitre_technique": rule.get('mitre_technique')
                }
                
                # Ajouter des infos sur l'instance pour les événements EC2
                if 'instance_details' in enriched_event:
                    alert.update({"instance_id": enriched_event['instance_details'].get('instance_id')})
                    
                # Ajouter des métriques CloudWatch si disponibles
                if 'cloudwatch_metrics' in enriched_event:
                    alert.update(enriched_event['cloudwatch_metrics'])
                    
                # Ajouter des infos sur l'utilisateur pour les événements IAM
                if 'user_details' in enriched_event:
                    alert.update({"user_details": enriched_event['user_details']})
                    
                # Marquer explicitement si l'IP est malveillante
                if is_malicious:
                    alert["is_malicious_ip"] = True
                    
                alerts.append(alert)
                
        return alerts

    def analyze_all_events(self, events):
        """
        Analyse une liste d'événements et retourne toutes les alertes générées.
        """
        all_alerts = []
        event_count = len(events)
        logger.info(f"Début de l'analyse de {event_count} événements")
        
        start_time = time.time()
        for i, event in enumerate(events):
            # Log de progression tous les 100 événements
            if (i+1) % 100 == 0 or (i+1) == event_count:
                progress = (i+1) / event_count * 100
                elapsed = time.time() - start_time
                logger.info(f"Progression: {progress:.1f}% ({i+1}/{event_count}, {elapsed:.2f}s)")
                
            # Analyser l'événement
            alerts = self.analyze_event(event)
            if alerts:
                all_alerts.extend(alerts)
                
        logger.info(f"Analyse terminée. {len(all_alerts)} alertes générées.")
        return all_alerts
        
    def run_analysis(self, source='s3', **kwargs):
        """
        Point d'entrée principal pour l'analyse.
        
        Args:
            source: Source des événements ('s3', 'file', 'cloudtrail')
            **kwargs: Arguments spécifiques à la source
                - Pour 's3': bucket, prefix
                - Pour 'file': filepath
                - Pour 'cloudtrail': lookback_hours
        """
        events = []
        
        # Charger les événements selon la source spécifiée
        if source == 's3':
            bucket = kwargs.get('bucket')
            prefix = kwargs.get('prefix', 'cloudtrail/')
            events = self.fetch_events_from_s3(bucket, prefix)
        elif source == 'file':
            filepath = kwargs.get('filepath')
            events = self.load_events_from_file(filepath)
        elif source == 'cloudtrail':
            lookback_hours = kwargs.get('lookback_hours', 24)
            events = self.query_cloudtrail_directly(lookback_hours)
        else:
            logger.error(f"Source non reconnue: {source}")
            return []
            
        # Analyser les événements
        if not events:
            logger.warning("Aucun événement à analyser.")
            return []
            
        alerts = self.analyze_all_events(events)
        
        # Sauvegarder les alertes si un chemin est spécifié
        output_path = kwargs.get('output_path')
        if output_path and alerts:
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    json.dump(alerts, f, indent=2, default=str)
                logger.info(f"Alertes sauvegardées dans {output_path}")
            except Exception as e:
                logger.error(f"Erreur lors de la sauvegarde des alertes: {e}")
                
        return alerts


# Fonction principale pour l'exécution standalone
def main():
    """
    Point d'entrée pour exécuter l'analyseur depuis la ligne de commande.
    """
    import argparse
    
    parser = argparse.ArgumentParser(description="Analyseur forensic avancé pour AWS")
    parser.add_argument('--rules', default='rules.json', help="Chemin vers le fichier de règles")
    parser.add_argument('--region', default=AWS_REGION, help="Région AWS")
    parser.add_argument('--output', help="Chemin du fichier de sortie pour les alertes")
    
    # Arguments pour les sources de données
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument('--s3', action='store_true', help="Utiliser S3 comme source")
    source_group.add_argument('--file', action='store_true', help="Utiliser un fichier local comme source")
    source_group.add_argument('--cloudtrail', action='store_true', help="Utiliser l'API CloudTrail directement")
    
    # Arguments spécifiques aux sources
    parser.add_argument('--bucket', help="Nom du bucket S3 (avec --s3)")
    parser.add_argument('--prefix', default='cloudtrail/', help="Préfixe dans le bucket S3 (avec --s3)")
    parser.add_argument('--filepath', help="Chemin du fichier d'événements (avec --file)")
    parser.add_argument('--lookback', type=int, default=24, help="Nombre d'heures à analyser (avec --cloudtrail)")
    
    args = parser.parse_args()
    
    # Initialiser l'analyseur
    analyzer = ForensicAnalyzer(rules_path=args.rules, region=args.region)
    
    # Déterminer la source et exécuter l'analyse
    if args.s3:
        if not args.bucket:
            parser.error("--bucket est requis avec --s3")
        alerts = analyzer.run_analysis('s3', bucket=args.bucket, prefix=args.prefix, output_path=args.output)
    elif args.file:
        if not args.filepath:
            parser.error("--filepath est requis avec --file")
        alerts = analyzer.run_analysis('file', filepath=args.filepath, output_path=args.output)
    elif args.cloudtrail:
        alerts = analyzer.run_analysis('cloudtrail', lookback_hours=args.lookback, output_path=args.output)
    
    # Afficher un résumé des alertes
    if alerts:
        print(f"\n🚨 {len(alerts)} alerte(s) détectée(s) !")
        
        # Grouper par sévérité
        severity_counts = {}
        for alert in alerts:
            severity = alert.get('severity', 'UNKNOWN')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
        # Afficher un résumé par sévérité
        for severity, count in severity_counts.items():
            print(f"  {severity}: {count} alerte(s)")
            
        # Montrer le détail des alertes CRITICAL
        critical_alerts = [a for a in alerts if a.get('severity') == 'CRITICAL']
        if critical_alerts:
            print("\n⚠️ Alertes CRITIQUES :")
            for alert in critical_alerts:
                print(f"  - {alert.get('rule_name')} ({alert.get('event_details', {}).get('eventName')})")
    else:
        print("Aucune alerte détectée.")


if __name__ == "__main__":
    main()
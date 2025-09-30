# log_analyzer.py - Version améliorée
import boto3
import json
import argparse
import logging
from datetime import datetime, timedelta
from collections import defaultdict
import hashlib
from ioc_checker import is_malicious_ip, get_ip_reputation

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ForensicAnalyzer:
    def __init__(self, bucket_name, prefix="cloudtrail/", rules_file="rules.json"):
        self.bucket_name = bucket_name
        self.prefix = prefix
        self.s3 = boto3.client('s3')
        self.cloudwatch = boto3.client('cloudwatch')
        
        with open(rules_file) as f:
            self.rules = json.load(f)
        
        self.event_cache = {}
        self.alerts = []
    
    def load_events_from_s3(self):
        """Charge tous les événements depuis S3 avec pagination"""
        events = []
        paginator = self.s3.get_paginator('list_objects_v2')
        
        for page in paginator.paginate(Bucket=self.bucket_name, Prefix=self.prefix):
            for obj in page.get('Contents', []):
                key = obj['Key']
                if key.endswith('.json'):
                    try:
                        response = self.s3.get_object(Bucket=self.bucket_name, Key=key)
                        content = json.loads(response['Body'].read().decode('utf-8'))
                        
                        if isinstance(content, list):
                            events.extend(content)
                        else:
                            events.append(content)
                    except Exception as e:
                        logger.warning(f"Erreur lors du chargement de {key}: {e}")
        
        logger.info(f"Chargé {len(events)} événements depuis S3")
        return events
    
    def extract_event_details(self, event):
        """Extrait les détails normalisés d'un événement"""
        details = {
            'eventName': event.get('EventName') or event.get('eventName'),
            'sourceIP': event.get('SourceIPAddress') or event.get('sourceIPAddress'),
            'userIdentity': event.get('UserIdentity') or event.get('userIdentity', {}),
            'eventTime': event.get('EventTime') or event.get('eventTime'),
            'requestParameters': event.get('requestParameters', {}),
            'responseElements': event.get('responseElements', {}),
            'eventId': event.get('EventId') or event.get('eventId'),
            'awsRegion': event.get('AwsRegion') or event.get('awsRegion')
        }
        
        # Parsing du CloudTrailEvent si présent
        if event.get('CloudTrailEvent'):
            try:
                trail_event = json.loads(event['CloudTrailEvent'])
                for key in details:
                    if not details[key] and key in trail_event:
                        details[key] = trail_event[key]
            except:
                pass
        
        return details
    
    def check_rule_condition(self, event_details, condition):
        """Vérifie si un événement correspond à une condition"""
        # Vérification eventName
        event_name = condition.get('eventName')
        if event_name:
            if isinstance(event_name, list):
                if event_details['eventName'] not in event_name:
                    return False
            else:
                if event_details['eventName'] != event_name:
                    return False
        
        # Vérification sourceIP
        source_ip_rules = condition.get('sourceIP')
        if source_ip_rules and event_details['sourceIP']:
            ip = event_details['sourceIP']
            
            # Vérification CIDR exclusions
            allowed_cidrs = source_ip_rules.get('notInAllowedCIDRs', [])
            if allowed_cidrs:
                import ipaddress
                is_allowed = False
                for cidr in allowed_cidrs:
                    try:
                        if ipaddress.ip_address(ip) in ipaddress.ip_network(cidr):
                            is_allowed = True
                            break
                    except:
                        continue
                if is_allowed:
                    return False
        
        # Vérification bucketNamePrefix
        bucket_prefix = condition.get('bucketNamePrefix')
        if bucket_prefix:
            bucket_name = event_details['requestParameters'].get('bucketName', '')
            if not bucket_name.startswith(bucket_prefix):
                return False
        
        return True
    
    def analyze_threshold_rules(self, events, rule):
        """Analyse les règles avec seuil (ex: exfiltration S3)"""
        threshold = rule['condition'].get('threshold')
        if not threshold:
            return []
        
        count_threshold = threshold['count']
        window_minutes = threshold['window_minutes']
        
        # Grouper les événements par clé (ex: IP + bucket)
        event_groups = defaultdict(list)
        
        for event in events:
            details = self.extract_event_details(event)
            if self.check_rule_condition(details, rule['condition']):
                key = (details['sourceIP'], details['requestParameters'].get('bucketName', ''))
                event_groups[key].append(details)
        
        alerts = []
        for key, group_events in event_groups.items():
            # Trier par temps
            group_events.sort(key=lambda x: x['eventTime'] or '')
            
            # Fenêtre glissante
            for i in range(len(group_events)):
                start_time = datetime.fromisoformat(group_events[i]['eventTime'].replace('Z', '+00:00'))
                end_time = start_time + timedelta(minutes=window_minutes)
                
                count = sum(1 for e in group_events 
                          if start_time <= datetime.fromisoformat(e['eventTime'].replace('Z', '+00:00')) <= end_time)
                
                if count >= count_threshold:
                    alerts.append({
                        'rule_id': rule['id'],
                        'rule_name': rule['name'],
                        'severity': rule['severity'],
                        'category': rule['category'],
                        'source_ip': key,
                        'bucket': key[1],
                        'event_count': count,
                        'time_window': f"{window_minutes}min",
                        'first_event_time': group_events[i]['eventTime'],
                        'recommended_actions': rule['recommendedActions'],
                        'mitre_technique': rule.get('mitre', ''),
                        'priority': rule.get('priority', 3)
                    })
                    break
        
        return alerts
    
    def enrich_with_cloudwatch(self, alert):
        """Enrichit l'alerte avec des métriques CloudWatch"""
        if alert.get('category') == 'CRYPTOJACKING':
            try:
                # Récupérer les métriques CPU pour l'instance
                instance_id = alert.get('instance_id')
                if instance_id:
                    response = self.cloudwatch.get_metric_statistics(
                        Namespace='AWS/EC2',
                        MetricName='CPUUtilization',
                        Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                        StartTime=datetime.utcnow() - timedelta(hours=1),
                        EndTime=datetime.utcnow(),
                        Period=300,
                        Statistics=['Average', 'Maximum']
                    )
                    
                    if response['Datapoints']:
                        max_cpu = max(dp['Maximum'] for dp in response['Datapoints'])
                        alert['cpu_utilization'] = max_cpu
                        alert['cpu_high'] = max_cpu > 90
            except Exception as e:
                logger.warning(f"Impossible de récupérer les métriques CloudWatch: {e}")
        
        return alert
    
    def analyze_events(self, events):
        """Analyse principale des événements"""
        self.alerts = []
        
        for rule in self.rules:
            # Règles avec seuil
            if rule['condition'].get('threshold'):
                threshold_alerts = self.analyze_threshold_rules(events, rule)
                for alert in threshold_alerts:
                    enriched_alert = self.enrich_with_cloudwatch(alert)
                    self.alerts.append(enriched_alert)
            
            # Règles simples (par événement)
            else:
                for event in events:
                    details = self.extract_event_details(event)
                    if self.check_rule_condition(details, rule['condition']):
                        alert = {
                            'rule_id': rule['id'],
                            'rule_name': rule['name'],
                            'severity': rule['severity'],
                            'category': rule['category'],
                            'event_details': details,
                            'recommended_actions': rule['recommendedActions'],
                            'mitre_technique': rule.get('mitre', ''),
                            'priority': rule.get('priority', 3),
                            'timestamp': details['eventTime']
                        }
                        
                        # Vérification IOC si demandée
                        if rule['condition'].get('sourceIP', {}).get('checkOTX'):
                            ip = details['sourceIP']
                            if ip:
                                alert['is_malicious_ip'] = is_malicious_ip(ip)
                                alert['ip_reputation'] = get_ip_reputation(ip)
                        
                        enriched_alert = self.enrich_with_cloudwatch(alert)
                        self.alerts.append(enriched_alert)
        
        # Trier par priorité puis par sévérité
        severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        self.alerts.sort(key=lambda x: (x['priority'], severity_order.get(x['severity'], 0)), reverse=True)
        
        return self.alerts
    
    def generate_report(self, output_file="alerts_report.json"):
        """Génère un rapport détaillé"""
        report = {
            'metadata': {
                'generated_at': datetime.utcnow().isoformat(),
                'analyzer_version': '2.0',
                'total_alerts': len(self.alerts),
                'severity_breakdown': {}
            },
            'alerts': self.alerts,
            'summary': {
                'critical_alerts': len([a for a in self.alerts if a['severity'] == 'CRITICAL']),
                'high_alerts': len([a for a in self.alerts if a['severity'] == 'HIGH']),
                'categories': {}
            }
        }
        
        # Statistiques par sévérité
        for alert in self.alerts:
            sev = alert['severity']
            report['metadata']['severity_breakdown'][sev] = \
                report['metadata']['severity_breakdown'].get(sev, 0) + 1
        
        # Statistiques par catégorie
        for alert in self.alerts:
            cat = alert['category']
            report['summary']['categories'][cat] = \
                report['summary']['categories'].get(cat, 0) + 1
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Rapport sauvegardé dans {output_file}")
        return report

def main():
    parser = argparse.ArgumentParser(description='Analyseur forensic AWS - Sprint 2')
    parser.add_argument('--bucket', required=True, help='Nom du bucket S3')
    parser.add_argument('--prefix', default='cloudtrail/', help='Préfixe S3')
    parser.add_argument('--rules', default='rules.json', help='Fichier de règles')
    parser.add_argument('--output', default='alerts_report.json', help='Fichier de sortie')
    parser.add_argument('--verbose', action='store_true', help='Mode verbose')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialisation de l'analyseur
    analyzer = ForensicAnalyzer(args.bucket, args.prefix, args.rules)
    
    # Chargement et analyse des événements
    events = analyzer.load_events_from_s3()
    alerts = analyzer.analyze_events(events)
    
    # Génération du rapport
    report = analyzer.generate_report(args.output)
    
    # Affichage du résumé
    print(f"\n🚨 {report['metadata']['total_alerts']} alertes détectées:")
    print(f"   - CRITICAL: {report['summary']['critical_alerts']}")
    print(f"   - HIGH: {report['summary']['high_alerts']}")
    
    for alert in alerts[:5]:  # Top 5 alertes
        print(f"\n📋 {alert['rule_name']} (Severity: {alert['severity']})")
        print(f"🕒 Time: {alert.get('timestamp', 'N/A')}")
        if alert.get('is_malicious_ip'):
            print(f"⚠️ IP malveillante détectée: {alert.get('event_details', {}).get('sourceIP', 'N/A')}")

if __name__ == '__main__':
    main()
import json
from datetime import datetime, timedelta
import random

# Génération d'événements CloudTrail simulés pour EC2
events = []
base_time = datetime.utcnow()

# Liste de quelques actions EC2 suspectes pour test
ec2_actions = [
    "AuthorizeSecurityGroupIngress",
    "AuthorizeSecurityGroupEgress",
    "RevokeSecurityGroupIngress",
    "RunInstances",
    "TerminateInstances",
    "StopInstances",
    "StartInstances",
]

for i in range(50):  # Générer 50 événements EC2
    event_time = base_time - timedelta(minutes=i*5)
    action = random.choice(ec2_actions)
    event = {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": f"EXAMPLEPRINCIPALID{i}",
            "arn": f"arn:aws:iam::123456789012:user/test-user-{i}",
            "accountId": "123456789012",
            "userName": f"test-user-{i}"
        },
        "eventTime": event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventSource": "ec2.amazonaws.com",
        "eventName": action,
        "awsRegion": "us-east-1",
        "sourceIPAddress": f"192.168.1.{i%255}",
        "userAgent": "aws-cli/2.0",
        "requestParameters": {
            "instanceId": f"i-0{random.randint(1000000000,9999999999)}"
        },
        "responseElements": None,
        "requestID": f"req-{random.randint(100000,999999)}",
        "eventID": f"event-{i}-{random.randint(100000,999999)}",
        "readOnly": False,
        "resources": [],
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": "123456789012",
        "sharedEventID": None,
        "serviceEventDetails": None
    }
    events.append(event)

# Structure globale type CloudTrail (Records)
cloudtrail_log = {"Records": events}

# Sauvegarde en fichier
output_file = "/mnt/data/cloudtrail_ec2_test.json"
with open(output_file, "w") as f:
    json.dump(cloudtrail_log, f, indent=2)

output_file

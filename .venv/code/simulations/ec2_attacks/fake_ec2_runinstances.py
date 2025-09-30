import json
from datetime import datetime, timedelta
import random

# Générer un faux événement CloudTrail de type RunInstances (EC2)
def generate_runinstances_event(instance_id, user="attacker", region="us-east-1", account="123456789012"):
    now = datetime.utcnow().isoformat() + "Z"
    return {
        "eventVersion": "1.08",
        "userIdentity": {
            "type": "IAMUser",
            "principalId": f"{user}@{account}",
            "arn": f"arn:aws:iam::{account}:user/{user}",
            "accountId": account,
            "userName": user
        },
        "eventTime": now,
        "eventSource": "ec2.amazonaws.com",
        "eventName": "RunInstances",
        "awsRegion": region,
        "sourceIPAddress": "192.0.2.44",
        "userAgent": "aws-cli/2.9.0 Python/3.9.11",
        "requestParameters": {
            "minCount": 1,
            "maxCount": 1,
            "instanceType": "t2.micro",
            "imageId": "ami-0abcdef1234567890",
            "subnetId": "subnet-12345",
            "securityGroupIds": ["sg-12345"]
        },
        "responseElements": {
            "instancesSet": {
                "items": [
                    {"instanceId": instance_id}
                ]
            }
        },
        "requestID": f"req-{random.randint(100000,999999)}",
        "eventID": f"evt-{random.randint(100000,999999)}",
        "readOnly": False,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": account
    }

# Générer 50 faux événements
events = [generate_runinstances_event(f"i-{random.randint(100000,999999)}") for _ in range(50)]

# Format CloudTrail (Records)
cloudtrail_data = {"Records": events}

# Sauvegarde dans un fichier
output_file = "/mnt/data/fake_ec2_runinstances.json"
with open(output_file, "w") as f:
    json.dump(cloudtrail_data, f, indent=2)

output_file

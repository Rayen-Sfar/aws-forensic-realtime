#!/usr/bin/env python3
# Collecteur de logs
import boto3, json, logging
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

S3_BUCKET = 'forensic-log-buck'   
S3_PREFIX = 'CloudTrail/'

def get_cloudtrail_events(lookback_hours=24):
    cloudtrail = boto3.client('cloudtrail')
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=lookback_hours)
    events = []
    paginator = cloudtrail.get_paginator('lookup_events')
    for page in paginator.paginate(StartTime=start_time, EndTime=end_time, PaginationConfig={'PageSize': 50}):
        events.extend(page.get('Events', []))
    logger.info(f"Retrieved {len(events)} events from CloudTrail.")
    return events

def extract_event_name(evt):
    # Priorité : top-level EventName, sinon inner CloudTrailEvent JSON
    name = evt.get('EventName')
    if name:
        return name
    inner = evt.get('CloudTrailEvent')
    if inner:
        try:
            data = json.loads(inner)
            return data.get('eventName')
        except Exception:
            return None
    return None

def filter_relevant_events(events):
    # Patterns acceptés (on compare en majuscules pour normaliser)
    patterns = [
        'CREATEACCESSKEY', 'DELETEACCESSKEY',
        'GETOBJECT', 'LISTOBJECTS', 'LISTOBJECTSV2',
        'RUNINSTANCES', 'STARTINSTANCES', 'CONSOLELOGIN'
    ]
    filtered = []
    for e in events:
        evname = extract_event_name(e)
        if not evname:
            continue
        en = evname.upper()
        # correspondance par égalité ou inclusion
        if any(p == en or p in en for p in patterns):
            filtered.append(e)
    logger.info(f"Filtered {len(filtered)} relevant events.")
    return filtered
def save_to_s3(events):
    if not events:
        logger.info("No events to save.")
        return
    s3 = boto3.client('s3')
    ts = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    key = f"{S3_PREFIX}filtered_events_{ts}.json"

    # Fix ici : on ajoute default=str pour gérer datetime
    body = json.dumps(events, indent=2, default=str)

    try:
        s3.put_object(Bucket=S3_BUCKET, Key=key, Body=body, ServerSideEncryption='AES256')
        logger.info(f"Saved {len(events)} events to s3://{S3_BUCKET}/{key}")
    except ClientError as e:
        logger.error("S3 put_object error: %s", e)
        raise

def main():
    ev = get_cloudtrail_events(24)
    f = filter_relevant_events(ev)
    save_to_s3(f)

if __name__ == '__main__':
    main()
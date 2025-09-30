#!/usr/bin/env python3
import boto3
from datetime import datetime, timedelta
import json


def test_lookup_events(lookback_hours=24):
    cloudtrail = boto3.client('cloudtrail')
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(hours=lookback_hours)

    events = []
    paginator = cloudtrail.get_paginator('lookup_events')
    for page in paginator.paginate(StartTime=start_time, EndTime=end_time, PaginationConfig={'PageSize': 50}):
        events.extend(page.get('Events', []))
    return events

if __name__ == '__main__':
    events = test_lookup_events(24)
    print(f"Found {len(events)} CloudTrail events in the last 24 hours.")
    if events:
        print(json.dumps(events[0], indent=2, default=str))
"""Offline CloudTrail triage. Python 3.10+; standard library only."""
import argparse
import csv
import gzip
import json
import sys
from collections import Counter, defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

RULES = {
    'ROOT_ACTIVITY': ('High', 'Root identity used', 'Verify the owner and purpose; use delegated roles for routine work.'),
    'NO_MFA_LOGIN': ('High', 'Successful IAM/root console login without MFA', 'Verify the sign-in and enforce appropriate MFA controls.'),
    'LOGGING_CHANGE': ('High', 'CloudTrail logging stopped or trail deleted', 'Verify change approval and restore logging if unauthorized.'),
    'ADMIN_POLICY': ('High', 'AWS AdministratorAccess policy attached', 'Review the target and approval; remove excessive permissions.'),
    'LOGIN_BURST': ('Medium', 'Repeated failed console logins', 'Investigate the account and IP; review subsequent successful logins.'),
}

def obj(value):
    return value if isinstance(value, dict) else {}


def load_events(path):
    """Accept CloudTrail Records envelopes or bare event arrays, including gzip."""
    opener = gzip.open if path.suffix == '.gz' else open
    with opener(path, 'rt', encoding='utf-8') as stream:
        payload = json.load(stream)
    records = payload.get('Records') if isinstance(payload, dict) else payload
    if not isinstance(records, list):
        raise ValueError(f'{path.name}: expected a Records array or event array')
    return records


def analyze(records, threshold=5, window_minutes=10):
    if threshold < 2 or window_minutes < 1:
        raise ValueError('threshold must be >= 2 and window minutes >= 1')
    findings, warnings, events = [], [], []
    seen = set()
    duplicates = 0
    for index, event in enumerate(records):
        if not isinstance(event, dict) or not all(isinstance(event.get(k), str) and event[k] for k in ('eventName', 'eventSource', 'eventTime')):
            warnings.append(f'Record {index}: skipped; missing required string fields')
            continue
        try:
            timestamp = datetime.fromisoformat(event['eventTime'].replace('Z', '+00:00'))
            if timestamp.utcoffset() is None:
                raise ValueError('timezone required')
        except ValueError:
            warnings.append(f'Record {index}: skipped; invalid or timezone-free eventTime')
            continue
        identity = obj(event.get('userIdentity'))
        account = identity.get('accountId') or event.get('recipientAccountId') or 'unknown'
        key = (str(account), str(event['eventID'])) if event.get('eventID') else None
        if key and key in seen:
            duplicates += 1
            continue
        if key:
            seen.add(key)
        events.append((timestamp, index, event))
    events.sort(key=lambda item: (item[0], item[1]))

    def add(rule, event, evidence, count=1):
        severity, title, action = RULES[rule]
        identity = obj(event.get('userIdentity'))
        findings.append(dict(rule_id=rule, severity=severity, title=title,
            event_time=event['eventTime'], event_id=event.get('eventID', 'unknown'),
            event_name=event['eventName'], account=str(identity.get('accountId') or event.get('recipientAccountId') or 'unknown'),
            actor=str(identity.get('arn') or identity.get('principalId') or identity.get('userName') or 'unknown'),
            source_ip=str(event.get('sourceIPAddress') or 'unknown'),
            outcome='Failed' if event.get('errorCode') or obj(event.get('responseElements')).get('ConsoleLogin') == 'Failure' else 'Recorded without errorCode',
            evidence=evidence, event_count=count, recommendation=action))

    buckets = defaultdict(deque)
    for timestamp, _, event in events:
        name, source = event['eventName'], event['eventSource']
        identity = obj(event.get('userIdentity'))
        response = obj(event.get('responseElements'))
        successful = not event.get('errorCode')
        if identity.get('type') == 'Root':
            add('ROOT_ACTIVITY', event, 'userIdentity.type = Root; review both attempted and completed activity')
        if (source == 'signin.amazonaws.com' and name == 'ConsoleLogin' and successful
                and response.get('ConsoleLogin') == 'Success' and identity.get('type') in ('IAMUser', 'Root')
                and obj(event.get('additionalEventData')).get('MFAUsed') == 'No'):
            add('NO_MFA_LOGIN', event, 'ConsoleLogin = Success; MFAUsed = No')
        if source == 'cloudtrail.amazonaws.com' and name in ('StopLogging', 'DeleteTrail') and successful:
            add('LOGGING_CHANGE', event, f'{name} recorded without errorCode')
        if (source == 'iam.amazonaws.com' and name in ('AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy') and successful
                and obj(event.get('requestParameters')).get('policyArn') == 'arn:aws:iam::aws:policy/AdministratorAccess'):
            add('ADMIN_POLICY', event, json.dumps(obj(event.get('requestParameters')), sort_keys=True))
        if source == 'signin.amazonaws.com' and name == 'ConsoleLogin' and (response.get('ConsoleLogin') == 'Failure' or event.get('errorCode') in ('FailedAuthentication', 'InvalidPassword', 'InvalidUserName')):
            account = identity.get('accountId') or event.get('recipientAccountId')
            actor = identity.get('arn') or identity.get('principalId') or identity.get('userName')
            ip = event.get('sourceIPAddress')
            if not all(isinstance(v, str) and v for v in (account, actor, ip)):
                warnings.append(f"Event {event.get('eventID', 'unknown')}: login burst correlation skipped; missing account, actor or IP")
                continue
            bucket = buckets[(account, actor, ip)]
            cutoff = timestamp - timedelta(minutes=window_minutes)
            while bucket and bucket[0][0] < cutoff:
                bucket.popleft()
            # One alert per non-overlapping threshold-sized cluster.
            bucket.append((timestamp, event.get('eventID', 'unknown')))
            if len(bucket) >= threshold:
                add('LOGIN_BURST', event, f'{threshold} failures within {window_minutes} minutes; IDs: ' + ', '.join(str(v[1]) for v in bucket), threshold)
                bucket.clear()
    return dict(summary=dict(input_records=len(records), analyzed_events=len(events), duplicate_events=duplicates,
        skipped_records=len(records)-len(events)-duplicates, findings=len(findings),
        severity_counts=dict(Counter(f['severity'] for f in findings))),
        settings=dict(login_threshold=threshold, window_minutes=window_minutes), warnings=warnings, findings=findings)


def write_reports(result, output):
    output.mkdir(parents=True, exist_ok=True)
    (output / 'findings.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    columns = ['rule_id', 'severity', 'title', 'event_time', 'event_id', 'event_name', 'account', 'actor', 'source_ip', 'outcome', 'evidence', 'event_count', 'recommendation']
    with (output / 'findings.csv').open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=columns)
        writer.writeheader()
        # Prevent formula execution when untrusted CloudTrail fields are opened in Excel.
        for finding in result['findings']:
            writer.writerow({k: "'" + v if isinstance(v, str) and v.lstrip().startswith(('=', '+', '-', '@')) else v for k, v in finding.items()})
    lines = ['CLOUDTRAIL TRIAGE REPORT', '=======================', json.dumps(result['summary'], indent=2),
        '', 'Findings are review signals, not proof of compromise.', '']
    for f in result['findings']:
        lines.extend([f"[{f['severity']}] {f['rule_id']} | {f['event_time']}",
            f"Actor: {f['actor']} | IP: {f['source_ip']}", f"Evidence: {f['evidence']}", f"Next action: {f['recommendation']}", ''])
    lines.extend(['INPUT WARNINGS', *result['warnings']])
    (output / 'summary.txt').write_text('\n'.join(lines) + '\n', encoding='utf-8')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path, help='JSON / JSON.GZ file or directory of such files (recursive)')
    parser.add_argument('--output', type=Path, default=Path('reports'))
    parser.add_argument('--threshold', type=int, default=5)
    parser.add_argument('--window-minutes', type=int, default=10)
    args = parser.parse_args(argv)
    try:
        if args.input.is_dir():
            paths = sorted(p for p in args.input.rglob('*') if p.is_file() and (p.suffix == '.json' or p.name.endswith('.json.gz')))
        else:
            paths = [args.input]
        if not paths:
            raise ValueError('No JSON input files found')
        records = []
        for path in paths:
            records.extend(load_events(path))
        result = analyze(records, args.threshold, args.window_minutes)
        write_reports(result, args.output)
    except (OSError, ValueError, EOFError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 2
    print(f"Analyzed {result['summary']['analyzed_events']} events; {result['summary']['findings']} findings. Reports: {args.output}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

from datetime import datetime, timedelta
import gzip
import json

from trailblazer import log


def process_cloudtrail(arn, files):

    api_calls = []

    log.info('EventSource, EventName, Recorded Name, Match')

    for file in files:
        f = None
        log.debug(f'Processing file: {file}')

        f = gzip.open(file, 'r') if file.endswith('.gz') else open(file, 'r')
        try:
            cloudtrail = json.load(f)
        except Exception as e:
            log.error(f'Invalid JSON File: {file} - {e}')
            continue

        for record in cloudtrail['Records']:
            if record.get('userIdentity', {}).get('arn', '').startswith(arn):
                event_source = record['eventSource'].split('.')[0]
                event_name = record['eventName']

                call = f'{event_source}.{event_name}'

                if call not in api_calls:
                    session = record['userIdentity']['arn'].split('/')[-1]
                    match = (record['eventName'].lower() == session)
                    log.info(
                        f"{record['eventSource'].split('.')[0]}, {record['eventName']}, {session}, {match}"
                    )
                    api_calls.append(call)

        f.close()

    return api_calls


def pairwise(lst):
    """ yield item i and item i+1 in lst. e.g.
        (lst[0], lst[1]), (lst[1], lst[2]), ..., (lst[-1], None)
    """
    if not lst: return
    #yield None, lst[0]
    for i in range(len(lst)-1):
        yield lst[i], lst[i+1]
    yield lst[-1], None


def record_cloudtrail(arn, files):

    api_calls = []

    for file in files:
        f = None
        log.info(f'Processing file: {file}')

        f = gzip.open(file, 'r') if file.endswith('.gz') else open(file, 'r')
        try:
            cloudtrail = json.load(f)
        except Exception as e:
            log.error(f'Invalid JSON File: {file} - {e}')
            continue

        records = sorted(cloudtrail['Records'], key=lambda x: datetime.strptime(x['eventTime'], '%Y-%m-%dT%H:%M:%SZ'), reverse=False)

        for record, next_record in pairwise(records):
            if record.get('userIdentity', {}).get('arn', '').startswith(arn):
                event_source = record['eventSource'].split('.')[0]
                event_name = record['eventName']

                time_delay = 0
                if next_record:
                    time_delta = datetime.strptime(next_record['eventTime'], '%Y-%m-%dT%H:%M:%SZ') - datetime.strptime(record['eventTime'], '%Y-%m-%dT%H:%M:%SZ')
                    time_delay = time_delta.seconds

                call = f'{event_source}.{event_name}'

                log.info(
                    f"{record['eventSource'].split('.')[0]}.{record['eventName']} - {record['userIdentity']['arn']}"
                )

                api_calls.append(
                    {
                        'call': f'{event_source}.{event_name}',
                        'time_delay': time_delay,
                    }
                )

        f.close()

    return api_calls

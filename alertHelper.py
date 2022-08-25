import os
import json
import requests
import logging
import logging.handlers
import socket
import datetime
import yaml
import sys
import argparse
import yaml
import sys
import textwrap
import shutil
from pathlib import Path

# Disable warning
requests.packages.urllib3.disable_warnings()

# Glocal variable
homePath = str(Path.home()) # user home folder

def setup_config():
    xdrUrl = input("Your XDR tenant URL: ")
    authId = input("Your auth ID: ")
    apiKey = input("Your API Key: ")
    syslogIp = input("Your internal syslog server IP: ")
    syslogPort = int(input("Your internal syslog server Port: "))
    days = int(input("How many past days to fetch (only affect when first fetch): "))

    config = {"url": xdrUrl, "authId": authId, "apiKey": apiKey, "syslogIp": syslogIp, "syslogPort": syslogPort, "days": days}
    Path(homePath + '/.XDR/').mkdir(parents=True, exist_ok=True)
    with open(f'{homePath}/.XDR/config.yml', 'w') as config_file:
        yaml.dump(config, config_file)

def send_logs(syslog_ip, syslog_port, messages):
    SIEM = logging.getLogger("SIEM")
    SIEM.setLevel(logging.DEBUG)

    handler = logging.handlers.SysLogHandler(address=(syslog_ip, syslog_port), socktype=socket.SOCK_STREAM)
    SIEM.addHandler(handler)
    counter = 0
    for message in messages:
        json.dumps(message)
        SIEM.debug(json.dumps(message))
        counter += 1

    print('Totally sending ' + str(counter) + ' logs to ' + syslog_ip)
    
    ### Write the log to file for long run debug
    #records = []
    #for i in messages:
    #    records.append(i['alert_id'])

    #with open(f'{homePath}/.XDR/alert.log', 'a') as alertLog:
    #    alertLog.write(','.join(records) + '\n')

def get_alerts(url, headers, server_creation_time):
    data = {
        "request_data": {"filters": [{
                            "field": "server_creation_time",
                            "operator": "gte",
                            "value": server_creation_time
                            }],
                        "search_from": 0,
                        "search_to": 100,
                        "sort": {
                            "field": "server_creation_time",
                            "keyword":"desc"
                        }
                    }
            }

    jsonStr = json.dumps(data)

    res = requests.post(url + '/public_api/v1/alerts/get_alerts_multi_events/', headers = headers, data = jsonStr, verify = False)
    
    # Check for HTTP codes other than 200
    if res.status_code != 200:
        raise Exception("Something error on XDR server-end")
    else:
        alerts = res.json()["reply"]["alerts"]
        tmp = []
        for alert in alerts:
            tmp.append(alert["local_insert_ts"])

    if tmp != []:
        # max_timestamp = max(tmp)
        return alerts, max(tmp)
    else:
        # max_timestamp = 0
        return alerts, 0

def run():

    # This timestamp variable is for testing purpose
    #timestamp = 1645516349000
    ###timestamp = 1612127484000

    with open(f'{homePath}/.XDR/config.yml', 'r') as config_file:
        config = yaml.load(config_file, Loader=yaml.FullLoader)
        
    authId = config['authId']
    apiKey = config['apiKey']
    url = config['url']
    syslogIp = config['syslogIp']
    syslogPort = config['syslogPort']
    days = config['days']

    headers = {"content-type": "application/json",
                "accept": "application/json",
                "x-xdr-auth-id": authId,
                "Authorization": apiKey}
        
    # Check if lastfetch exists
    lastfetchFile = homePath + '/.XDR/lastfetch'

    # If lastfetch doesn't exist
    # Set the timestamp to current - days (UTC)
    if not os.path.exists(lastfetchFile):
        timestamp = int((datetime.datetime.utcnow() - datetime.timedelta(days=int(days))).timestamp()) * 1000
    else:
        with open(lastfetchFile, 'r') as lastfetch:
            timestamp = int(lastfetch.read())

    # Main logic
    while timestamp > 1:
        alerts, last_timestamp = get_alerts(url, headers, timestamp)
        send_logs(syslogIp, syslogPort, alerts)
        timestamp = last_timestamp + 1

        # Write the last fetch timstamp into ./lastfetch
        if timestamp != 1:
            with open(lastfetchFile, 'w') as lastfetch:
                lastfetch.write(str(timestamp))

def reset():
    shutil.rmtree(homePath + '/.XDR/')
    print('You alert helper has been reset (config.yml and lastfetch timestamp)')

def help_msg():
    msg = '''

This helper tool consists of three parts. Configuration / Runner / Reset.

Configuration:
This part will setup the needed information for alertHelper. Please run it as below example:
$ python3 alertHelper.py config

And provide the following information:
1. Auth ID
2. API Key
3. XDR Tenent URL
4. Syslog IP
5. Syslog Port
6. How many past days to fetch

Runner:
This part will start fetching alerts on XDR. Please run it as below example:
$ python3 alertHelper.py run

Reset:
This part will reset alertHelper including config and lastefecth timestamp. Please run it as below example:
$ python2 alertHelper.py reset

    '''
    return msg

if __name__ == '__main__':

    try:

        if len(sys.argv) == 1 or len(sys.argv) > 2:
            print(help_msg())
            exit(1)

        parser = argparse.ArgumentParser(
                            formatter_class=argparse.RawDescriptionHelpFormatter,
                            epilog=textwrap.dedent(help_msg())
                            )
        subparsers = parser.add_subparsers()

        parser_config = subparsers.add_parser('config', help='Set up the needed information, like API key and XDR tenant URL')
        parser_config.set_defaults(func=setup_config)
        parser_run = subparsers.add_parser('run', help='Fetch alerts and send to remote Syslog/SIEM')
        parser_run.set_defaults(func=run)
        parser_reset = subparsers.add_parser('reset', help='Reset the config and lastfetch timestamp')
        parser_reset.set_defaults(func=reset)

        args = parser.parse_args()
        args.func()
    
    except FileNotFoundError:
        print(help_msg())
        sys.exit(1)

    except Exception as e:
        print(e)
        sys.exit(1)


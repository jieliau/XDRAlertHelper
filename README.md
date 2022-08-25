# Alert Helper

This helper tool is to fetch XDR alerts to Syslog or SIEM system and consists of Three parts. Configuration / Runner / Reset

## Configuration:

This part will setup the needed information for alertHelper. Please run it as below example:
```sh
$ python3 alertHelper.py config
```

And provide the following information:
```sh
Your XDR tenant URL: https://api-example.paloaltonetworks.com/
Your auth ID: "Your auth ID"
Your API Key: "Your API Key"
Your internal syslog server IP: "Your Syslog Server IP address"
Your internal syslog server Port: "Your Syslog Server Port"
How many past days to fetch: "How many past days to get alerts"
```

## Runner:

This part will start fetching alerts on XDR. Please run it as below example:
```sh
$ python3 alertHelper.py run
```

### For Example:
```sh
$ python3 alertHelper.py run
Totally sending 100 logs to 192.168.0.82
Totally sending 100 logs to 192.168.0.82
Totally sending 35 logs to 192.168.0.82
Totally sending 0 logs to 192.168.0.82
```

## Reset

This part will reset alertHelper including config and lastefecth timestamp. Please run it as below example:
```sh
$ python2 alertHelper.py reset
```

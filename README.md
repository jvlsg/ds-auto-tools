# ds-api-tools
Tools &amp; utilities that use Deep Security's RESTful API

# Pre-requesites
(The Deep Security SDK)[https://automation.deepsecurity.trendmicro.com/article/fr/python?platform=on-premise]

# Computer IPS Baseline
Choose a "Baseline" computer by ID or Hostname, the script will check the **difference** (`Union - Intersection`) between the set of rules applied for all other computers that have *Intrusion Prevention enabled* and the baseline computer.

## Sample output

```
Processing...
Server A | 8 rules difference | Computer Group ID:0
Server B | 9 rules difference | Computer Group ID:0
Server C | 136 rules difference | Computer Group ID:0
Server D | 137 rules difference | Computer Group ID:44522
```

# Application Types detected

Use the assigned/recommended for assignment Intrusion Prevention rules to list the detected application types on a server.

## Sample output

```
COMPUTER: Server A
Detected Application Types:
        Web Client Common
        Malicious Network Traffic
        Web Application Ruby Based
        Web Client SSL
        Web Client Mozilla Firefox
        Mail Server Common
        Web Server Common
        DNS Client
        SSL Client


COMPUTER: Server B
Detected Application Types:
        Web Client Common
        Web Server Miscellaneous
        Microsoft Office
        Remote Desktop Protocol Client
        Web Client SSL
        Web Client Internet Explorer/Edge
        Web Client Mozilla Firefox
        Web Server Common
        DCERPC Services - Client
        DCERPC Services
        SSL Client
        Intel AMT
```
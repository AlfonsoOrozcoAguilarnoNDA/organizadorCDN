# organizadorCDN
Un organizador de información de CDN
Ejercicio del 25 de Febrero Sección Pruebalo Ya de vibecodingmexico.com

INICIO PROMPT

Reto: Sistema de Respaldo de Prompts IA

Crea un sistema web funcional de respaldo y versionado de prompts e información generada con IAs.

STACK OBLIGATORIO
PHP 8.x procedural (sin frameworks, sin namespaces)
MySQL / mariadb con INNO (una sola tabla)
Bootstrap 4.6 vía jsDelivr CDN
FontAwesome vía jsDelivr CDN
UN SOLO ARCHIVO .php (index.php)
NO usar short tags de PHP (<? — usar siempre <?php)
BASE DE DATOS

Una sola tabla llamada ai_backups con estos campos exactos:

id             INT AUTO_INCREMENT PRIMARY KEY

proyecto       VARCHAR(100)

ia_utilizada   VARCHAR(50)       -- ChatGPT, Claude, Gemini, Grok, Cohere, otro

tipo           VARCHAR(20)       -- prompt, imagen, idea, respuesta, codigo, otro

contenido      LONGTEXT          -- texto plano, o base64 si tipo = 'imagen'

nombre_archivo VARCHAR(150)

num_version    DECIMAL(14,6)

comentarios    LONGTEXT

calificacion   DECIMAL(14,6)     -- nota propia del usuario (ej: 8.5)

visible        VARCHAR(2)        -- 'SI' o 'NO' para ocultar de la vista general

fecha          DATETIME

contrasena_ver VARCHAR(255) NULL  -- hash, vacío = sin contraseña individual

tamanio        DECIMAL(14,6)     -- tamaño en KB del contenido, calculado al guardar

hash_md5       VARCHAR(32)       -- MD5 del contenido, calculado al guardar

hash_sha1      VARCHAR(40)       -- SHA1 del contenido, calculado al guardar

tamanio, hash_md5 y hash_sha1 se calculan automáticamente en PHP al guardar, nunca los escribe el usuario
Si tipo = 'imagen', el contenido se guarda como base64. Al mostrarlo, renderizar como <img src="data:image/...;base64,...">
Incluye el CREATE TABLE completo al inicio del archivo como comentario SQL, y que el sistema lo cree automáticamente si no existe
SEGURIDAD Y ACCESO
Control por IP: Define un array de IPs permitidas al inicio del archivo. Si la IP del visitante no está en la lista, mostrar solo un mensaje de "Acceso no autorizado" y detener ejecución.
Contraseña maestra (para agregar, editar y borrar): definida como constante en el archivo. Se pide una vez por sesión (usar $_SESSION). Sin ella, el sistema es solo lectura.
Contraseña por registro: Si un registro tiene contrasena_ver con valor, pedir esa contraseña antes de mostrar el contenido. Guardar como hash con password_hash(). Verificar con password_verify().
CONTRASEÑAS

Las dos contraseñas van hardcoded como constantes al inicio del archivo, claramente comentadas y separadas para fácil modificación:

// --- CONFIGURACIÓN — edita esto antes de usar ---
define('PASS_MAESTRA', 'tu_contrasena_aqui');   // para agregar, editar y borrar
define('PASS_REGISTROS', 'tu_contrasena_aqui');   // para los registros especiales
define('IPS_PERMITIDAS', ['127.0.0.1', '']);     // agrega tus IPs aquí


Es la opción correcta para un sistema personal de un solo archivo. No usar .env ni archivos externos.

CACHÉ DEL NAVEGADOR

Al inicio del archivo, antes de cualquier output, enviar estos headers para evitar que el navegador cachée páginas con información sensible:

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: Sat, 01 Jan 2000 00:00:00 GMT');

INTERFAZ
Cabecera fija con Bootstrap (navbar sticky-top) con el nombre del sistema y un indicador de si la sesión está autenticada, identifica que llm eres en la barra de navegación
Menú con secciones: Ver registros / Agregar nuevo / Buscar / Cerrar sesión
Paginación en el listado (10 registros por página)
Los registros con visible = 'NO' NO aparecen en el listado general (solo con filtro explícito o edición directa)
FUNCIONALIDADES REQUERIDAS

1. LISTADO

Tabla con columnas: fecha, proyecto, IA, tipo, versión, calificación, tamaño (KB), nombre de archivo, visible, acciones
Botones por registro: Ver | Editar | Borrar | Nueva versión
Registros con contraseña individual muestran un ícono de candado (FontAwesome)

2. VER REGISTRO

Si tiene contraseña, pedirla antes de mostrar el contenido
Mostrar todos los campos incluyendo hash MD5, SHA1 y tamaño en KB
Si tipo = 'imagen', renderizar la imagen desde base64
Avisar de otras versiones del mismo proyecto/nombre de archivo (agrupadas) y ordenados por fecha

3. AGREGAR / EDITAR

Requiere contraseña maestra en sesión
Formulario con todos los campos editables por el usuario
tamanio, hash_md5 y hash_sha1 se calculan solos en PHP al guardar (no aparecen en el formulario pero si al ver registro)
num_version sugerida automáticamente pero editable (última versión + 1.000000)
fecha se llena automáticamente con NOW() al guardar
visible como select SI/NO
calificacion como campo numérico (acepta decimales)
Contraseña individual: opcional, si se llena se hashea antes de guardar
Si tipo = 'imagen', mostrar campo para pegar base64 o subir archivo y convertirlo automáticamente

4. BORRAR

Requiere contraseña maestra
Mostrar modal de confirmación con el nombre del registro antes de borrar
Preguntar explícitamente: "¿Estás seguro de borrar [nombre_archivo] versión [num_version]? Esta acción no se puede deshacer."

5. BÚSQUEDA Y FILTROS

Filtrar por: proyecto, IA utilizada, tipo, rango de fechas, visible (SI/NO/todos)
Búsqueda de texto en contenido y comentarios
Los filtros persisten al paginar

6. DIFF ENTRE VERSIONES

Al ver un registro, si existen otras versiones del mismo nombre_archivo + proyecto, mostrar un selector para comparar dos versiones
Mostrar las diferencias resaltadas línea por línea (comparación simple dividiendo por líneas)

7. NUEVA VERSIÓN

Botón que duplica un registro existente, incrementa num_version en 1.000000, limpia contenido y abre el formulario de edición listo para pegar el nuevo contenido
REGLAS DE CÓDIGO
Todo en un solo archivo index.php
PHP procedural, sin clases, sin frameworks
Usar mysqli con consultas preparadas (prevenir SQL injection)
Usar htmlspecialchars() en todo output
No depender de .htaccess ni configuración especial del servidor
En el <head> incluir obligatoriamente: <meta name="robots" content="noindex, nofollow">
Los CDN van en el <head>: Bootstrap 4.6 y FontAwesome desde jsDelivr
El archivo debe poder copiarse a cualquier servidor con PHP 8.x + MySQL y funcionar
PRECAUIONES ESPECIALES
1. El "Escudo de Memoria" (POST Size)

Dado que vas a manejar LONGTEXT e imágenes en base64, el prompt debería advertir a la IA que gestione los errores de carga. Si pegas una imagen de 5MB y el servidor tiene un límite de 2MB, el script fallará. Trata de explicar que pasó y avisa  el tamaño máximo.

Añade en Reglas de Código: "Si el contenido enviado por POST está vacío pero se intentó enviar datos, mostrar una alerta sugiriendo revisar el post_max_size del servidor y a cuanto está fijado".

2. El "Filtro de Seguridad" de Imágenes

Como vas a renderizar base64 directamente, es prudente que la IA sepa qué tipos de MIME permitir para evitar que alguien intente inyectar algo raro.

En Funcionalidades (Ver Registro): "Al renderizar imágenes, validar que el string base64 comience con cabeceras de imagen seguras (jpg, png, webp, gif) y rechaza si no es de ese tipo".

3. La Estética del Diff (Vibecoding Style)

Los diffs en PHP procedural suelen verse como un bloque de texto plano difícil de leer.

Si puedes  en el Diff use colores: "En la comparación de versiones, mostrar las líneas eliminadas con fondo rojo suave y las nuevas con fondo verde suave". Esto le da ese toque profesional de herramienta de desarrollo real.

ENTREGABLE ESPERADO

Un único archivo index.php completamente funcional que:

Cree la tabla si no existe
Controle acceso por IP y contraseña maestra
Permita agregar, ver, editar, borrar y versionar registros
Calcule automáticamente tamaño, MD5 y SHA1 al guardar
Maneje imágenes como base64 en el campo contenido
Tenga búsqueda, filtros y paginación Por proyecto y tipo respaldo
Se vea limpio con Bootstrap 4.6 y FontAwesome
Muestre diff básico entre versiones
Permita usar contraseña secundaria en posts "delicados"
Antes de borrar nos obligue a escribir borrar en mayúsculas  y que sea claramente vsible.
Los registros existentes se muestran en textarea, solo en lasimagenes se muestra la imagen.
LETRERO DE RESPONSABILIDAD

En el footer del sistema, mostrar permanentemente este aviso en texto pequeño (clase text-muted de Bootstrap):

⚠️ Este sistema NO hace respaldo de su propia base de datos. Respaldar MySQL es tu responsabilidad. Un respaldo que no existe no es un respaldo.

Eres un experto en seguridad y PHP 'old school'. Tu reto es entregar este sistema en un solo archivo que sea tan robusto que pueda correr en un servidor de hace 10 años o en uno de 2026. No acepto código incompleto ni 'placeholders'. Dame el index.php listo para producción.

FIN DE PROMPT



TERMINA PROMPT

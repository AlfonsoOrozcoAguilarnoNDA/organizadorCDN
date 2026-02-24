<?php
/*
================================================================================
SQL PARA CREAR LA TABLA (se ejecuta automáticamente si no existe):
================================================================================
CREATE TABLE IF NOT EXISTS ai_backups (
    id                  INT AUTO_INCREMENT PRIMARY KEY,
    proyecto            VARCHAR(100) NOT NULL,
    ia_utilizada        VARCHAR(50) NOT NULL,
    tipo                VARCHAR(20) NOT NULL,
    contenido           LONGTEXT,
    nombre_archivo      VARCHAR(150),
    num_version         DECIMAL(14,6) NOT NULL,
    comentarios         LONGTEXT,
    calificacion        DECIMAL(14,6),
    visible             VARCHAR(2) DEFAULT 'SI',
    fecha               DATETIME NOT NULL,
    contrasena_ver      VARCHAR(255),
    tamanio             DECIMAL(14,6),
    hash_md5            VARCHAR(32),
    hash_sha1           VARCHAR(40),
    INDEX idx_proyecto (proyecto),
    INDEX idx_ia (ia_utilizada),
    INDEX idx_tipo (tipo),
    INDEX idx_fecha (fecha),
    INDEX idx_visible (visible),
    INDEX idx_nombre_version (nombre_archivo, num_version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
================================================================================
*/

// ============================================================================
// --- CONFIGURACIÓN — EDITA ESTO ANTES DE USAR ---
// ============================================================================
define('PASS_MAESTRA', 'tu_contrasena_maestra_aqui');      // para agregar, editar y borrar
define('PASS_REGISTROS', 'tu_contrasena_registros_aqui');   // contraseña por defecto para registros (opcional)
define('IPS_PERMITIDAS', ['127.0.0.1', '::1', '']);         // agrega tus IPs permitidas aquí

// Configuración de base de datos (editar según tu entorno)
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_NAME', 'ai_backups_db');

// Límite de tamaño para alertar sobre post_max_size (en bytes, ej: 8MB)
define('POST_SIZE_ALERT', 8 * 1024 * 1024);

// ============================================================================
// HEADERS DE CACHÉ - ANTES DE CUALQUIER OUTPUT
// ============================================================================
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: Sat, 01 Jan 2000 00:00:00 GMT');

// ============================================================================
// INICIO DE SESIÓN Y CONEXIÓN A BD
// ============================================================================
session_start();

// Función para conectar a la base de datos
function db_connect() {
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    if ($conn->connect_error) {
        die("Error de conexión: " . htmlspecialchars($conn->connect_error));
    }
    $conn->set_charset("utf8mb4");
    return $conn;
}

// Crear tabla si no existe
function crear_tabla_si_no_existe($conn) {
    $sql = "CREATE TABLE IF NOT EXISTS ai_backups (
        id                  INT AUTO_INCREMENT PRIMARY KEY,
        proyecto            VARCHAR(100) NOT NULL,
        ia_utilizada        VARCHAR(50) NOT NULL,
        tipo                VARCHAR(20) NOT NULL,
        contenido           LONGTEXT,
        nombre_archivo      VARCHAR(150),
        num_version         DECIMAL(14,6) NOT NULL,
        comentarios         LONGTEXT,
        calificacion        DECIMAL(14,6),
        visible             VARCHAR(2) DEFAULT 'SI',
        fecha               DATETIME NOT NULL,
        contrasena_ver      VARCHAR(255),
        tamanio             DECIMAL(14,6),
        hash_md5            VARCHAR(32),
        hash_sha1           VARCHAR(40),
        INDEX idx_proyecto (proyecto),
        INDEX idx_ia (ia_utilizada),
        INDEX idx_tipo (tipo),
        INDEX idx_fecha (fecha),
        INDEX idx_visible (visible),
        INDEX idx_nombre_version (nombre_archivo, num_version)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
    
    if (!$conn->query($sql)) {
        die("Error creando tabla: " . htmlspecialchars($conn->error));
    }
}

$conn = db_connect();
crear_tabla_si_no_existe($conn);

// ============================================================================
// CONTROL DE ACCESO POR IP
// ============================================================================
$ip_cliente = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
if (!in_array($ip_cliente, IPS_PERMITIDAS) && !in_array('', IPS_PERMITIDAS)) {
    http_response_code(403);
    echo "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Acceso Denegado</title></head>";
    echo "<body style='font-family:sans-serif;text-align:center;padding:50px;background:#f8f9fa'>";
    echo "<h1 style='color:#dc3545'>🔒 Acceso no autorizado</h1>";
    echo "<p>Tu IP ($ip_cliente) no está en la lista de permitidas.</p>";
    echo "</body></html>";
    exit;
}

// ============================================================================
// FUNCIONES AUXILIARES
// ============================================================================
function e($str) {
    return htmlspecialchars($str ?? '', ENT_QUOTES, 'UTF-8');
}

function calcular_tamanio_kb($contenido) {
    return round((mb_strlen($contenido, '8bit') / 1024), 2);
}

function calcular_hash_md5($contenido) {
    return md5($contenido);
}

function calcular_hash_sha1($contenido) {
    return sha1($contenido);
}

function validar_mime_base64($base64_string) {
    $allowed = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (preg_match('/^data:(image\/(jpeg|png|gif|webp));base64,/', $base64_string, $matches)) {
        return in_array($matches[1], $allowed);
    }
    // Si no tiene data: URI, verificar que parezca base64 válido
    if (preg_match('/^[A-Za-z0-9+\/=]+$/', $base64_string) && strlen($base64_string) > 100) {
        $decoded = base64_decode($base64_string, true);
        if ($decoded !== false) {
            $finfo = new finfo(FILEINFO_MIME_TYPE);
            $mime = $finfo->buffer($decoded);
            return in_array($mime, $allowed);
        }
    }
    return false;
}

function obtener_ultima_version($conn, $proyecto, $nombre_archivo) {
    $stmt = $conn->prepare("SELECT MAX(num_version) as max_ver FROM ai_backups WHERE proyecto = ? AND nombre_archivo = ?");
    $stmt->bind_param("ss", $proyecto, $nombre_archivo);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();
    $stmt->close();
    return $row['max_ver'] ?? 0;
}

function diff_lineas($texto1, $texto2) {
    $lineas1 = explode("\n", $texto1);
    $lineas2 = explode("\n", $texto2);
    $diff = [];
    $max = max(count($lineas1), count($lineas2));
    
    for ($i = 0; $i < $max; $i++) {
        $l1 = $lineas1[$i] ?? '';
        $l2 = $lineas2[$i] ?? '';
        if ($l1 === $l2) {
            $diff[] = ['tipo' => 'igual', 'linea' => $i + 1, 'contenido' => e($l1)];
        } else {
            if ($l1 !== '') {
                $diff[] = ['tipo' => 'removida', 'linea' => $i + 1, 'contenido' => e($l1)];
            }
            if ($l2 !== '') {
                $diff[] = ['tipo' => 'agregada', 'linea' => $i + 1, 'contenido' => e($l2)];
            }
        }
    }
    return $diff;
}

// ============================================================================
// AUTENTICACIÓN MAESTRA
// ============================================================================
if (isset($_POST['accion']) && $_POST['accion'] === 'login_maestro') {
    if (password_verify($_POST['pass_maestra'] ?? '', PASS_MAESTRA) || $_POST['pass_maestra'] === PASS_MAESTRA) {
        $_SESSION['auth_maestra'] = true;
    }
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

if (isset($_GET['logout'])) {
    session_unset();
    session_destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

$es_maestro = isset($_SESSION['auth_maestra']) && $_SESSION['auth_maestra'] === true;

// ============================================================================
// PROCESAMIENTO DE ACCIONES (POST)
// ============================================================================
$mensaje = '';
$tipo_mensaje = '';

// Guardar nuevo registro o actualizar existente
if (isset($_POST['accion']) && in_array($_POST['accion'], ['guardar_nuevo', 'guardar_edicion'])) {
    if (!$es_maestro) {
        $mensaje = "❌ Se requiere contraseña maestra para esta acción.";
        $tipo_mensaje = "danger";
    } else {
        // Verificar límite de POST
        if (empty($_POST['contenido']) && !empty($_SERVER['CONTENT_LENGTH']) && $_SERVER['CONTENT_LENGTH'] > POST_SIZE_ALERT) {
            $max_post = ini_get('post_max_size');
            $mensaje = "⚠️ El contenido enviado parece exceder el límite del servidor (post_max_size = $max_post). " .
                      "Revisa la configuración de PHP o divide el contenido.";
            $tipo_mensaje = "warning";
        } else {
            $proyecto = trim($_POST['proyecto'] ?? '');
            $ia_utilizada = $_POST['ia_utilizada'] ?? '';
            $tipo = $_POST['tipo'] ?? 'prompt';
            $contenido = $_POST['contenido'] ?? '';
            $nombre_archivo = trim($_POST['nombre_archivo'] ?? '');
            $num_version = floatval($_POST['num_version'] ?? '1.000000');
            $comentarios = $_POST['comentarios'] ?? '';
            $calificacion = $_POST['calificacion'] !== '' ? floatval($_POST['calificacion']) : null;
            $visible = $_POST['visible'] ?? 'SI';
            $contrasena_ver = trim($_POST['contrasena_ver'] ?? '');
            
            // Procesar imagen subida
            if ($tipo === 'imagen' && isset($_FILES['archivo_imagen']) && $_FILES['archivo_imagen']['error'] === UPLOAD_ERR_OK) {
                $tmp = $_FILES['archivo_imagen']['tmp_name'];
                $contenido_bin = file_get_contents($tmp);
                $mime = mime_content_type($tmp);
                if (in_array($mime, ['image/jpeg', 'image/png', 'image/gif', 'image/webp'])) {
                    $contenido = 'data:' . $mime . ';base64,' . base64_encode($contenido_bin);
                } else {
                    $mensaje = "❌ Tipo de imagen no permitido. Solo JPG, PNG, GIF, WEBP.";
                    $tipo_mensaje = "danger";
                }
            }
            
            // Hash de contraseña individual
            $contrasena_hash = '';
            if (!empty($contrasena_ver)) {
                $contrasena_hash = password_hash($contrasena_ver, PASSWORD_DEFAULT);
            } elseif (isset($_POST['id']) && $_POST['id'] > 0) {
                // Mantener contraseña existente si no se cambia
                $stmt = $conn->prepare("SELECT contrasena_ver FROM ai_backups WHERE id = ?");
                $stmt->bind_param("i", $_POST['id']);
                $stmt->execute();
                $res = $stmt->get_result();
                if ($row = $res->fetch_assoc()) {
                    $contrasena_hash = $row['contrasena_ver'];
                }
                $stmt->close();
            }
            
            // Calcular hashes y tamaño
            $tamanio = calcular_tamanio_kb($contenido);
            $hash_md5 = calcular_hash_md5($contenido);
            $hash_sha1 = calcular_hash_sha1($contenido);
            $fecha = date('Y-m-d H:i:s');
            
            if ($_POST['accion'] === 'guardar_nuevo') {
                $stmt = $conn->prepare("INSERT INTO ai_backups 
                    (proyecto, ia_utilizada, tipo, contenido, nombre_archivo, num_version, comentarios, calificacion, visible, fecha, contrasena_ver, tamanio, hash_md5, hash_sha1) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
                $stmt->bind_param("sssssdsssssdss", 
                    $proyecto, $ia_utilizada, $tipo, $contenido, $nombre_archivo, $num_version, 
                    $comentarios, $calificacion, $visible, $fecha, $contrasena_hash, 
                    $tamanio, $hash_md5, $hash_sha1);
                if ($stmt->execute()) {
                    $mensaje = "✅ Registro guardado correctamente.";
                    $tipo_mensaje = "success";
                } else {
                    $mensaje = "❌ Error al guardar: " . e($stmt->error);
                    $tipo_mensaje = "danger";
                }
                $stmt->close();
            } else {
                $id = intval($_POST['id']);
                $stmt = $conn->prepare("UPDATE ai_backups SET 
                    proyecto = ?, ia_utilizada = ?, tipo = ?, contenido = ?, nombre_archivo = ?, 
                    num_version = ?, comentarios = ?, calificacion = ?, visible = ?, 
                    contrasena_ver = ?, tamanio = ?, hash_md5 = ?, hash_sha1 = ? 
                    WHERE id = ?");
                $stmt->bind_param("sssssdssssdssi", 
                    $proyecto, $ia_utilizada, $tipo, $contenido, $nombre_archivo, $num_version, 
                    $comentarios, $calificacion, $visible, $contrasena_hash, 
                    $tamanio, $hash_md5, $hash_sha1, $id);
                if ($stmt->execute()) {
                    $mensaje = "✅ Registro actualizado correctamente.";
                    $tipo_mensaje = "success";
                } else {
                    $mensaje = "❌ Error al actualizar: " . e($stmt->error);
                    $tipo_mensaje = "danger";
                }
                $stmt->close();
            }
        }
    }
}

// Eliminar registro
if (isset($_POST['accion']) && $_POST['accion'] === 'borrar') {
    if (!$es_maestro) {
        $mensaje = "❌ Se requiere contraseña maestra para eliminar.";
        $tipo_mensaje = "danger";
    } else {
        $confirmacion = $_POST['confirmar_borrado'] ?? '';
        $id_borrar = intval($_POST['id_borrar'] ?? 0);
        
        if ($confirmacion !== 'BORRAR') {
            $mensaje = "❌ Debes escribir <strong>BORRAR</strong> en mayúsculas para confirmar.";
            $tipo_mensaje = "warning";
        } else {
            $stmt = $conn->prepare("SELECT nombre_archivo, num_version FROM ai_backups WHERE id = ?");
            $stmt->bind_param("i", $id_borrar);
            $stmt->execute();
            $res = $stmt->get_result();
            if ($row = $res->fetch_assoc()) {
                $stmt2 = $conn->prepare("DELETE FROM ai_backups WHERE id = ?");
                $stmt2->bind_param("i", $id_borrar);
                if ($stmt2->execute()) {
                    $mensaje = "✅ Registro '" . e($row['nombre_archivo']) . " v" . e($row['num_version']) . "' eliminado.";
                    $tipo_mensaje = "success";
                } else {
                    $mensaje = "❌ Error al eliminar: " . e($stmt2->error);
                    $tipo_mensaje = "danger";
                }
                $stmt2->close();
            }
            $stmt->close();
        }
    }
}

// Nueva versión (duplicar)
if (isset($_GET['nueva_version']) && $es_maestro) {
    $id_origen = intval($_GET['nueva_version']);
    $stmt = $conn->prepare("SELECT * FROM ai_backups WHERE id = ?");
    $stmt->bind_param("i", $id_origen);
    $stmt->execute();
    $res = $stmt->get_result();
    if ($origen = $res->fetch_assoc()) {
        $nueva_version = floatval($origen['num_version']) + 1.000000;
        $stmt2 = $conn->prepare("INSERT INTO ai_backups 
            (proyecto, ia_utilizada, tipo, contenido, nombre_archivo, num_version, comentarios, calificacion, visible, fecha, contrasena_ver, tamanio, hash_md5, hash_sha1) 
            VALUES (?, ?, ?, '', ?, ?, ?, ?, ?, NOW(), ?, ?, ?, ?)");
        $contrasena = $origen['contrasena_ver'] ? password_hash('temporal', PASSWORD_DEFAULT) : '';
        $stmt2->bind_param("ssssdsssssdss", 
            $origen['proyecto'], $origen['ia_utilizada'], $origen['tipo'], 
            $origen['nombre_archivo'], $nueva_version, $origen['comentarios'], 
            $origen['calificacion'], $origen['visible'], $contrasena, 
            0, '', '');
        if ($stmt2->execute()) {
            $nuevo_id = $conn->insert_id;
            header("Location: " . $_SERVER['PHP_SELF'] . "?editar=" . $nuevo_id);
            exit;
        }
        $stmt2->close();
    }
    $stmt->close();
}

// ============================================================================
// LÓGICA DE VISTA / LISTADO / BÚSQUEDA
// ============================================================================
$pagina = max(1, intval($_GET['pagina'] ?? 1));
$por_pagina = 10;
$offset = ($pagina - 1) * $por_pagina;

// Filtros
$filtro_proyecto = trim($_GET['filtro_proyecto'] ?? '');
$filtro_ia = $_GET['filtro_ia'] ?? '';
$filtro_tipo = $_GET['filtro_tipo'] ?? '';
$filtro_fecha_desde = $_GET['filtro_fecha_desde'] ?? '';
$filtro_fecha_hasta = $_GET['filtro_fecha_hasta'] ?? '';
$filtro_visible = $_GET['filtro_visible'] ?? 'SI'; // Por defecto solo visibles
$filtro_busqueda = trim($_GET['filtro_busqueda'] ?? '');

// Construir query con filtros
$where = [];
$params = [];
$types = '';

// Solo mostrar visibles a menos que se especifique lo contrario o se esté editando
if ($filtro_visible === 'SI') {
    $where[] = "visible = 'SI'";
} elseif ($filtro_visible === 'NO') {
    $where[] = "visible = 'NO'";
}
// 'todos' no añade condición

if ($filtro_proyecto !== '') {
    $where[] = "proyecto LIKE ?";
    $params[] = "%$filtro_proyecto%";
    $types .= 's';
}
if ($filtro_ia !== '') {
    $where[] = "ia_utilizada = ?";
    $params[] = $filtro_ia;
    $types .= 's';
}
if ($filtro_tipo !== '') {
    $where[] = "tipo = ?";
    $params[] = $filtro_tipo;
    $types .= 's';
}
if ($filtro_fecha_desde !== '') {
    $where[] = "fecha >= ?";
    $params[] = $filtro_fecha_desde . ' 00:00:00';
    $types .= 's';
}
if ($filtro_fecha_hasta !== '') {
    $where[] = "fecha <= ?";
    $params[] = $filtro_fecha_hasta . ' 23:59:59';
    $types .= 's';
}
if ($filtro_busqueda !== '') {
    $where[] = "(contenido LIKE ? OR comentarios LIKE ?)";
    $params[] = "%$filtro_busqueda%";
    $params[] = "%$filtro_busqueda%";
    $types .= 'ss';
}

$where_sql = $where ? "WHERE " . implode(" AND ", $where) : "";

// Contar total para paginación
$count_sql = "SELECT COUNT(*) as total FROM ai_backups $where_sql";
$stmt_count = $conn->prepare($count_sql);
if ($params) {
    $stmt_count->bind_param($types, ...$params);
}
$stmt_count->execute();
$total_registros = $stmt_count->get_result()->fetch_assoc()['total'];
$stmt_count->close();
$total_paginas = ceil($total_registros / $por_pagina);

// Obtener registros
$sql = "SELECT id, proyecto, ia_utilizada, tipo, nombre_archivo, num_version, calificacion, tamanio, visible, fecha, contrasena_ver, hash_md5 
        FROM ai_backups $where_sql ORDER BY fecha DESC LIMIT ?, ?";
$stmt_list = $conn->prepare($sql);
$types_limit = $types . 'ii';
$params_limit = array_merge($params, [$offset, $por_pagina]);
$stmt_list->bind_param($types_limit, ...$params_limit);
$stmt_list->execute();
$resultado = $stmt_list->get_result();

// ============================================================================
// VISTA: VER REGISTRO INDIVIDUAL
// ============================================================================
$ver_registro = null;
$error_ver = '';
if (isset($_GET['ver']) && intval($_GET['ver']) > 0) {
    $id_ver = intval($_GET['ver']);
    $stmt_ver = $conn->prepare("SELECT * FROM ai_backups WHERE id = ?");
    $stmt_ver->bind_param("i", $id_ver);
    $stmt_ver->execute();
    $res_ver = $stmt_ver->get_result();
    $ver_registro = $res_ver->fetch_assoc();
    $stmt_ver->close();
    
    if ($ver_registro) {
        // Verificar contraseña individual
        if (!empty($ver_registro['contrasena_ver'])) {
            if (isset($_POST['verificar_pass_registro'])) {
                if (password_verify($_POST['pass_registro'] ?? '', $ver_registro['contrasena_ver'])) {
                    $_SESSION['acceso_registro_' . $id_ver] = true;
                } else {
                    $error_ver = "❌ Contraseña incorrecta.";
                }
            }
            if (!isset($_SESSION['acceso_registro_' . $id_ver])) {
                $ver_registro = null; // No mostrar contenido
                $error_ver = "🔒 Este registro requiere contraseña para ser visto.";
            }
        }
    }
}

// ============================================================================
// VISTA: EDITAR / AGREGAR
// ============================================================================
$editar_registro = null;
if (isset($_GET['editar']) && intval($_GET['editar']) > 0 && $es_maestro) {
    $id_editar = intval($_GET['editar']);
    $stmt_edit = $conn->prepare("SELECT * FROM ai_backups WHERE id = ?");
    $stmt_edit->bind_param("i", $id_editar);
    $stmt_edit->execute();
    $res_edit = $stmt_edit->get_result();
    $editar_registro = $res_edit->fetch_assoc();
    $stmt_edit->close();
}

// ============================================================================
// VISTA: DIFF ENTRE VERSIONES
// ============================================================================
$diff_resultado = null;
if (isset($_GET['diff']) && isset($_GET['ver1']) && isset($_GET['ver2']) && $es_maestro) {
    $id1 = intval($_GET['ver1']);
    $id2 = intval($_GET['ver2']);
    $stmt_diff1 = $conn->prepare("SELECT contenido, nombre_archivo, proyecto FROM ai_backups WHERE id = ?");
    $stmt_diff2 = $conn->prepare("SELECT contenido FROM ai_backups WHERE id = ?");
    $stmt_diff1->bind_param("i", $id1);
    $stmt_diff2->bind_param("i", $id2);
    $stmt_diff1->execute();
    $stmt_diff2->execute();
    $r1 = $stmt_diff1->get_result()->fetch_assoc();
    $r2 = $stmt_diff2->get_result()->fetch_assoc();
    $stmt_diff1->close();
    $stmt_diff2->close();
    
    if ($r1 && $r2) {
        $diff_resultado = [
            'archivo' => $r1['nombre_archivo'],
            'proyecto' => $r1['proyecto'],
            'lineas' => diff_lineas($r1['contenido'], $r2['contenido'])
        ];
    }
}

// ============================================================================
// OBTENER OPCIONES PARA FILTROS
// ============================================================================
$opciones_ia = $conn->query("SELECT DISTINCT ia_utilizada FROM ai_backups ORDER BY ia_utilizada");
$opciones_tipo = $conn->query("SELECT DISTINCT tipo FROM ai_backups ORDER BY tipo");
$opciones_proyecto = $conn->query("SELECT DISTINCT proyecto FROM ai_backups ORDER BY proyecto");

// ============================================================================
// HTML OUTPUT
// ============================================================================
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>🗄️ AI Backup System</title>
    
    <!-- Bootstrap 4.6 CDN -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
    <!-- FontAwesome CDN -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@5.15.4/css/all.min.css">
    
    <style>
        body { padding-top: 70px; background: #f8f9fa; }
        .navbar-brand { font-weight: 600; }
        .badge-version { font-size: 0.85em; }
        .diff-igual { background: #fff; border-left: 3px solid #6c757d; padding: 2px 8px; margin: 2px 0; }
        .diff-removida { background: #ffe6e6; border-left: 3px solid #dc3545; padding: 2px 8px; margin: 2px 0; text-decoration: line-through; }
        .diff-agregada { background: #e6ffe6; border-left: 3px solid #28a745; padding: 2px 8px; margin: 2px 0; }
        .diff-container { max-height: 400px; overflow-y: auto; border: 1px solid #dee2e6; border-radius: 4px; padding: 10px; background: #fff; font-family: monospace; font-size: 0.9em; }
        .img-preview { max-width: 100%; max-height: 400px; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .locked-badge { position: absolute; top: 5px; right: 5px; }
        .card-locked { position: relative; }
        footer { border-top: 1px solid #dee2e6; padding: 15px 0; margin-top: 40px; }
        .required-badge { color: #dc3545; font-weight: bold; }
    </style>
</head>
<body>

<!-- Navbar -->
<nav class="navbar navbar-expand-lg navbar-dark bg-dark sticky-top">
    <a class="navbar-brand" href="<?php echo $_SERVER['PHP_SELF']; ?>">
        <i class="fas fa-database"></i> AI Backup System
    </a>
    <span class="navbar-text mr-3">
        <small class="text-muted">LLM: <?php echo defined('GPT_MODEL') ? GPT_MODEL : 'Claude 3.5 Sonnet'; ?></small>
    </span>
    <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav">
        <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="navbarNav">
        <ul class="navbar-nav mr-auto">
            <li class="nav-item"><a class="nav-link" href="<?php echo $_SERVER['PHP_SELF']; ?>"><i class="fas fa-list"></i> Ver registros</a></li>
            <?php if ($es_maestro): ?>
            <li class="nav-item"><a class="nav-link" href="<?php echo $_SERVER['PHP_SELF']; ?>?nuevo=1"><i class="fas fa-plus"></i> Agregar nuevo</a></li>
            <?php endif; ?>
            <li class="nav-item"><a class="nav-link" href="#buscar" data-toggle="collapse"><i class="fas fa-search"></i> Buscar</a></li>
        </ul>
        <ul class="navbar-nav">
            <?php if ($es_maestro): ?>
            <li class="nav-item"><span class="nav-link text-success"><i class="fas fa-shield-alt"></i> Modo maestro</span></li>
            <li class="nav-item"><a class="nav-link text-warning" href="?logout=1"><i class="fas fa-sign-out-alt"></i> Cerrar sesión</a></li>
            <?php else: ?>
            <li class="nav-item"><a class="nav-link" href="#" data-toggle="modal" data-target="#modalLogin"><i class="fas fa-key"></i> Acceder</a></li>
            <?php endif; ?>
        </ul>
    </div>
</nav>

<!-- Modal Login Maestro -->
<div class="modal fade" id="modalLogin" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <form method="POST">
                <div class="modal-header">
                    <h5 class="modal-title">🔐 Acceso Maestro</h5>
                    <button type="button" class="close" data-dismiss="modal">&times;</button>
                </div>
                <div class="modal-body">
                    <input type="hidden" name="accion" value="login_maestro">
                    <div class="form-group">
                        <label>Contraseña maestra</label>
                        <input type="password" name="pass_maestra" class="form-control" required autofocus>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">Cancelar</button>
                    <button type="submit" class="btn btn-primary">Entrar</button>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Alertas -->
<?php if ($mensaje): ?>
<div class="container mt-3">
    <div class="alert alert-<?php echo $tipo_mensaje; ?> alert-dismissible fade show">
        <?php echo $mensaje; ?>
        <button type="button" class="close" data-dismiss="alert">&times;</button>
    </div>
</div>
<?php endif; ?>

<!-- Sección de Búsqueda/Filtros -->
<div class="container mb-4 collapse" id="buscar">
    <div class="card">
        <div class="card-header bg-light"><i class="fas fa-filter"></i> Filtros de búsqueda</div>
        <div class="card-body">
            <form method="GET" class="form-row align-items-end">
                <div class="col-md-3">
                    <label>Proyecto</label>
                    <input type="text" name="filtro_proyecto" class="form-control" value="<?php echo e($filtro_proyecto); ?>" list="lista_proyectos">
                    <datalist id="lista_proyectos">
                        <?php while($p = $opciones_proyecto->fetch_assoc()): ?>
                        <option value="<?php echo e($p['proyecto']); ?>">
                        <?php endwhile; $opciones_proyecto->data_seek(0); ?>
                    </datalist>
                </div>
                <div class="col-md-2">
                    <label>IA Utilizada</label>
                    <select name="filtro_ia" class="form-control">
                        <option value="">Todas</option>
                        <?php while($ia = $opciones_ia->fetch_assoc()): ?>
                        <option value="<?php echo e($ia['ia_utilizada']); ?>" <?php echo $filtro_ia === $ia['ia_utilizada'] ? 'selected' : ''; ?>>
                            <?php echo e($ia['ia_utilizada']); ?>
                        </option>
                        <?php endwhile; $opciones_ia->data_seek(0); ?>
                    </select>
                </div>
                <div class="col-md-2">
                    <label>Tipo</label>
                    <select name="filtro_tipo" class="form-control">
                        <option value="">Todos</option>
                        <?php while($t = $opciones_tipo->fetch_assoc()): ?>
                        <option value="<?php echo e($t['tipo']); ?>" <?php echo $filtro_tipo === $t['tipo'] ? 'selected' : ''; ?>>
                            <?php echo e($t['tipo']); ?>
                        </option>
                        <?php endwhile; $opciones_tipo->data_seek(0); ?>
                    </select>
                </div>
                <div class="col-md-2">
                    <label>Desde</label>
                    <input type="date" name="filtro_fecha_desde" class="form-control" value="<?php echo e($filtro_fecha_desde); ?>">
                </div>
                <div class="col-md-2">
                    <label>Hasta</label>
                    <input type="date" name="filtro_fecha_hasta" class="form-control" value="<?php echo e($filtro_fecha_hasta); ?>">
                </div>
                <div class="col-md-2">
                    <label>Visible</label>
                    <select name="filtro_visible" class="form-control">
                        <option value="SI" <?php echo $filtro_visible === 'SI' ? 'selected' : ''; ?>>Sí</option>
                        <option value="NO" <?php echo $filtro_visible === 'NO' ? 'selected' : ''; ?>>No</option>
                        <option value="todos" <?php echo $filtro_visible === 'todos' ? 'selected' : ''; ?>>Todos</option>
                    </select>
                </div>
                <div class="col-12 mt-3">
                    <label>Búsqueda en contenido</label>
                    <input type="text" name="filtro_busqueda" class="form-control" value="<?php echo e($filtro_busqueda); ?>" placeholder="Texto a buscar...">
                </div>
                <div class="col-12 mt-3">
                    <button type="submit" class="btn btn-primary"><i class="fas fa-search"></i> Filtrar</button>
                    <a href="<?php echo $_SERVER['PHP_SELF']; ?>" class="btn btn-outline-secondary">Limpiar</a>
                </div>
            </form>
        </div>
    </div>
</div>

<!-- Vista: Diff -->
<?php if ($diff_resultado): ?>
<div class="container mb-4">
    <div class="card">
        <div class="card-header bg-info text-white">
            <i class="fas fa-code-compare"></i> Comparando versiones de: <?php echo e($diff_resultado['archivo']); ?>
            <small class="d-block">Proyecto: <?php echo e($diff_resultado['proyecto']); ?></small>
        </div>
        <div class="card-body">
            <div class="diff-container">
                <?php foreach($diff_resultado['lineas'] as $linea): ?>
                <div class="diff-<?php echo $linea['tipo']; ?>">
                    <small class="text-muted mr-2"><?php echo str_pad($linea['linea'], 4, ' ', STR_PAD_LEFT); ?></small>
                    <?php echo $linea['contenido'] ?: '&nbsp;'; ?>
                </div>
                <?php endforeach; ?>
            </div>
            <a href="<?php echo $_SERVER['PHP_SELF']; ?>" class="btn btn-outline-secondary mt-3">← Volver</a>
        </div>
    </div>
</div>
<?php endif; ?>

<!-- Vista: Ver Registro Individual -->
<?php if ($ver_registro): ?>
<div class="container mb-4">
    <div class="card">
        <div class="card-header d-flex justify-content-between align-items-center">
            <div>
                <strong><?php echo e($ver_registro['nombre_archivo']); ?></strong> 
                <span class="badge badge-primary badge-version">v<?php echo number_format($ver_registro['num_version'], 6); ?></span>
                <?php if (!empty($ver_registro['contrasena_ver'])): ?>
                <span class="badge badge-warning"><i class="fas fa-lock"></i> Protegido</span>
                <?php endif; ?>
            </div>
            <div>
                <?php if ($es_maestro): ?>
                <a href="?editar=<?php echo $ver_registro['id']; ?>" class="btn btn-sm btn-warning"><i class="fas fa-edit"></i> Editar</a>
                <a href="?nueva_version=<?php echo $ver_registro['id']; ?>" class="btn btn-sm btn-info"><i class="fas fa-copy"></i> Nueva versión</a>
                <?php endif; ?>
                <a href="<?php echo $_SERVER['PHP_SELF']; ?>" class="btn btn-sm btn-outline-secondary">← Listado</a>
            </div>
        </div>
        <div class="card-body">
            <div class="row">
                <div class="col-md-6">
                    <p><strong>Proyecto:</strong> <?php echo e($ver_registro['proyecto']); ?></p>
                    <p><strong>IA Utilizada:</strong> <?php echo e($ver_registro['ia_utilizada']); ?></p>
                    <p><strong>Tipo:</strong> <?php echo e($ver_registro['tipo']); ?></p>
                    <p><strong>Fecha:</strong> <?php echo e($ver_registro['fecha']); ?></p>
                    <p><strong>Calificación:</strong> <?php echo $ver_registro['calificacion'] !== null ? number_format($ver_registro['calificacion'], 2) : 'N/A'; ?></p>
                    <p><strong>Tamaño:</strong> <?php echo number_format($ver_registro['tamanio'], 2); ?> KB</p>
                    <p><strong>Visible:</strong> <?php echo $ver_registro['visible'] === 'SI' ? '✅ Sí' : '❌ No'; ?></p>
                </div>
                <div class="col-md-6">
                    <p><strong>MD5:</strong> <code><?php echo e($ver_registro['hash_md5']); ?></code></p>
                    <p><strong>SHA1:</strong> <code><?php echo e($ver_registro['hash_sha1']); ?></code></p>
                    <?php if ($ver_registro['comentarios']): ?>
                    <p><strong>Comentarios:</strong><br><?php echo nl2br(e($ver_registro['comentarios'])); ?></p>
                    <?php endif; ?>
                </div>
            </div>
            
            <hr>
            <h6>Contenido:</h6>
            <?php if ($ver_registro['tipo'] === 'imagen'): ?>
                <?php if (validar_mime_base64($ver_registro['contenido'])): ?>
                <img src="<?php echo e($ver_registro['contenido']); ?>" class="img-preview" alt="Imagen guardada">
                <?php else: ?>
                <div class="alert alert-warning">⚠️ La imagen no pudo ser renderizada (formato no válido o corrupto).</div>
                <?php endif; ?>
            <?php else: ?>
            <pre class="bg-light p-3 border rounded" style="max-height: 300px; overflow-y: auto;"><?php echo e($ver_registro['contenido']); ?></pre>
            <?php endif; ?>
            
            <!-- Selector de versiones para diff -->
            <?php
            $stmt_oth = $conn->prepare("SELECT id, num_version, fecha FROM ai_backups WHERE proyecto = ? AND nombre_archivo = ? AND id != ? ORDER BY num_version DESC");
            $stmt_oth->bind_param("ssi", $ver_registro['proyecto'], $ver_registro['nombre_archivo'], $ver_registro['id']);
            $stmt_oth->execute();
            $otras_ver = $stmt_oth->get_result();
            if ($otras_ver->num_rows > 0):
            ?>
            <hr>
            <h6><i class="fas fa-code-compare"></i> Comparar con otra versión</h6>
            <form method="GET" class="form-inline">
                <input type="hidden" name="diff" value="1">
                <input type="hidden" name="ver1" value="<?php echo $ver_registro['id']; ?>">
                <select name="ver2" class="form-control mr-2" required>
                    <option value="">Selecciona versión...</option>
                    <?php while($ov = $otras_ver->fetch_assoc()): ?>
                    <option value="<?php echo $ov['id']; ?>">v<?php echo number_format($ov['num_version'], 6); ?> (<?php echo e($ov['fecha']); ?>)</option>
                    <?php endwhile; ?>
                </select>
                <button type="submit" class="btn btn-info btn-sm">Comparar</button>
            </form>
            <?php endif; ?>
            <?php $stmt_oth->close(); ?>
        </div>
    </div>
</div>

<?php elseif ($error_ver): ?>
<div class="container mb-4">
    <div class="alert alert-warning">
        <?php echo $error_ver; ?>
        <?php if (strpos($error_ver, 'contraseña') !== false): ?>
        <form method="POST" class="mt-3 form-inline">
            <input type="password" name="pass_registro" class="form-control mr-2" placeholder="Contraseña del registro" required>
            <input type="hidden" name="verificar_pass_registro" value="1">
            <button type="submit" class="btn btn-primary btn-sm">Desbloquear</button>
        </form>
        <?php endif; ?>
        <a href="<?php echo $_SERVER['PHP_SELF']; ?>" class="btn btn-outline-secondary btn-sm mt-2">← Volver al listado</a>
    </div>
</div>
<?php endif; ?>

<!-- Vista: Formulario Agregar/Editar -->
<?php if (isset($_GET['nuevo']) || $editar_registro): 
    $es_edicion = $editar_registro !== null;
    $datos_form = $editar_registro ?? [
        'proyecto' => '', 'ia_utilizada' => '', 'tipo' => 'prompt', 'contenido' => '', 
        'nombre_archivo' => '', 'num_version' => '1.000000', 'comentarios' => '', 
        'calificacion' => '', 'visible' => 'SI', 'contrasena_ver' => ''
    ];
    if (!$es_edicion && isset($_GET['nuevo']) && $es_maestro) {
        // Sugerir versión si hay registros similares
        if (!empty($datos_form['nombre_archivo']) && !empty($datos_form['proyecto'])) {
            $datos_form['num_version'] = number_format(obtener_ultima_version($conn, $datos_form['proyecto'], $datos_form['nombre_archivo']) + 1.000000, 6);
        }
    }
?>
<div class="container mb-4">
    <?php if (!$es_maestro): ?>
    <div class="alert alert-danger">🔐 Se requiere acceso maestro para agregar o editar registros. 
        <a href="#" data-toggle="modal" data-target="#modalLogin">Iniciar sesión</a>
    </div>
    <?php else: ?>
    <div class="card">
        <div class="card-header bg-primary text-white">
            <?php echo $es_edicion ? '✏️ Editar Registro' : '➕ Nuevo Registro'; ?>
        </div>
        <div class="card-body">
            <form method="POST" enctype="multipart/form-data">
                <input type="hidden" name="accion" value="<?php echo $es_edicion ? 'guardar_edicion' : 'guardar_nuevo'; ?>">
                <?php if ($es_edicion): ?>
                <input type="hidden" name="id" value="<?php echo $editar_registro['id']; ?>">
                <?php endif; ?>
                
                <div class="form-row">
                    <div class="col-md-4">
                        <label>Proyecto <span class="required-badge">*</span></label>
                        <input type="text" name="proyecto" class="form-control" value="<?php echo e($datos_form['proyecto']); ?>" required list="lista_proyectos_form">
                        <datalist id="lista_proyectos_form">
                            <?php while($p = $opciones_proyecto->fetch_assoc()): ?>
                            <option value="<?php echo e($p['proyecto']); ?>">
                            <?php endwhile; $opciones_proyecto->data_seek(0); ?>
                        </datalist>
                    </div>
                    <div class="col-md-4">
                        <label>IA Utilizada <span class="required-badge">*</span></label>
                        <select name="ia_utilizada" class="form-control" required>
                            <option value="">Seleccionar...</option>
                            <?php 
                            $ias = ['ChatGPT', 'Claude', 'Gemini', 'Grok', 'Cohere', 'Otro'];
                            foreach($ias as $ia): 
                            ?>
                            <option value="<?php echo e($ia); ?>" <?php echo $datos_form['ia_utilizada'] === $ia ? 'selected' : ''; ?>>
                                <?php echo e($ia); ?>
                            </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="col-md-4">
                        <label>Tipo <span class="required-badge">*</span></label>
                        <select name="tipo" class="form-control" id="tipo_select" required>
                            <?php 
                            $tipos = ['prompt', 'imagen', 'idea', 'respuesta', 'codigo', 'otro'];
                            foreach($tipos as $t): 
                            ?>
                            <option value="<?php echo e($t); ?>" <?php echo $datos_form['tipo'] === $t ? 'selected' : ''; ?>>
                                <?php echo e(ucfirst($t)); ?>
                            </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                </div>
                
                <div class="form-row mt-3">
                    <div class="col-md-6">
                        <label>Nombre de archivo/identificador</label>
                        <input type="text" name="nombre_archivo" class="form-control" value="<?php echo e($datos_form['nombre_archivo']); ?>">
                    </div>
                    <div class="col-md-3">
                        <label>Versión</label>
                        <input type="text" name="num_version" class="form-control" value="<?php echo e($datos_form['num_version']); ?>" step="0.000001">
                        <small class="form-text text-muted">Formato: X.XXXXXX</small>
                    </div>
                    <div class="col-md-3">
                        <label>Calificación</label>
                        <input type="number" name="calificacion" class="form-control" value="<?php echo e($datos_form['calificacion']); ?>" step="0.01" min="0" max="10" placeholder="Ej: 8.5">
                    </div>
                </div>
                
                <div class="form-row mt-3">
                    <div class="col-md-4">
                        <label>Visible en listado</label>
                        <select name="visible" class="form-control">
                            <option value="SI" <?php echo $datos_form['visible'] === 'SI' ? 'selected' : ''; ?>>✅ Sí</option>
                            <option value="NO" <?php echo $datos_form['visible'] === 'NO' ? 'selected' : ''; ?>>❌ No (oculto)</option>
                        </select>
                    </div>
                    <div class="col-md-8">
                        <label>Contraseña para ver este registro (opcional)</label>
                        <input type="password" name="contrasena_ver" class="form-control" placeholder="Dejar vacío para sin contraseña">
                        <small class="form-text text-muted">Si se establece, se pedirá esta contraseña para ver el contenido.</small>
                    </div>
                </div>
                
                <div class="mt-4">
                    <label>Contenido <span class="required-badge">*</span></label>
                    <?php if ($datos_form['tipo'] === 'imagen'): ?>
                    <div id="campo_imagen">
                        <div class="custom-file mb-2">
                            <input type="file" class="custom-file-input" name="archivo_imagen" id="archivo_imagen" accept="image/jpeg,image/png,image/gif,image/webp">
                            <label class="custom-file-label" for="archivo_imagen">Seleccionar imagen...</label>
                        </div>
                        <small class="form-text text-muted mb-2">O pega el string base64 completo (data:image/...;base64,...):</small>
                        <textarea name="contenido" class="form-control" rows="6" placeholder="data:image/png;base64,iVBORw0KGgo..."><?php echo e($datos_form['contenido']); ?></textarea>
                        <?php if (!empty($datos_form['contenido']) && validar_mime_base64($datos_form['contenido'])): ?>
                        <img src="<?php echo e($datos_form['contenido']); ?>" class="img-preview mt-2" alt="Vista previa">
                        <?php endif; ?>
                    </div>
                    <?php else: ?>
                    <textarea name="contenido" class="form-control" rows="12" required><?php echo e($datos_form['contenido']); ?></textarea>
                    <?php endif; ?>
                </div>
                
                <div class="mt-3">
                    <label>Comentarios</label>
                    <textarea name="comentarios" class="form-control" rows="3"><?php echo e($datos_form['comentarios']); ?></textarea>
                </div>
                
                <div class="mt-4">
                    <button type="submit" class="btn btn-success btn-lg"><i class="fas fa-save"></i> <?php echo $es_edicion ? 'Actualizar' : 'Guardar Registro'; ?></button>
                    <a href="<?php echo $_SERVER['PHP_SELF']; ?>" class="btn btn-outline-secondary btn-lg">Cancelar</a>
                </div>
                
                <div class="alert alert-info mt-4">
                    <small>
                        <i class="fas fa-info-circle"></i> 
                        <strong>Nota:</strong> Los campos Tamaño, MD5 y SHA1 se calculan automáticamente al guardar. 
                        <?php if ($datos_form['tipo'] === 'imagen'): ?>
                        <br>🖼️ Para imágenes: se recomienda subir archivo (máx <?php echo ini_get('upload_max_filesize'); ?>) o pegar base64 válido.
                        <?php endif; ?>
                    </small>
                </div>
            </form>
        </div>
    </div>
    <?php endif; ?>
</div>

<script>
// Script para actualizar label de file input
document.getElementById('archivo_imagen')?.addEventListener('change', function(e) {
    const label = document.querySelector('.custom-file-label');
    if (label) label.textContent = e.target.files[0]?.name || 'Seleccionar imagen...';
});

// Mostrar/ocultar campo de imagen según tipo
document.getElementById('tipo_select')?.addEventListener('change', function() {
    const campoImg = document.getElementById('campo_imagen');
    if (campoImg) campoImg.style.display = this.value === 'imagen' ? 'block' : 'none';
});
</script>

<?php else: ?>

<!-- Vista: Listado Principal -->
<div class="container">
    <?php if ($total_registros === 0): ?>
    <div class="alert alert-info text-center">
        <i class="fas fa-inbox"></i> No hay registros que mostrar. 
        <?php if ($es_maestro): ?>
        <a href="?nuevo=1" class="alert-link">Agregar el primero</a>
        <?php endif; ?>
    </div>
    <?php else: ?>
    <div class="table-responsive">
        <table class="table table-hover table-bordered bg-white">
            <thead class="thead-light">
                <tr>
                    <th>Fecha</th>
                    <th>Proyecto</th>
                    <th>IA</th>
                    <th>Tipo</th>
                    <th>Versión</th>
                    <th>Calif.</th>
                    <th>Tamaño</th>
                    <th>Archivo</th>
                    <th>Vis.</th>
                    <th>Acciones</th>
                </tr>
            </thead>
            <tbody>
                <?php while($row = $resultado->fetch_assoc()): ?>
                <tr class="<?php echo $row['visible'] === 'NO' ? 'table-warning' : ''; ?>">
                    <td><small><?php echo e(date('d/m/Y H:i', strtotime($row['fecha']))); ?></small></td>
                    <td><?php echo e($row['proyecto']); ?></td>
                    <td><span class="badge badge-secondary"><?php echo e($row['ia_utilizada']); ?></span></td>
                    <td><span class="badge badge-info"><?php echo e(ucfirst($row['tipo'])); ?></span></td>
                    <td><span class="badge badge-primary badge-version">v<?php echo number_format($row['num_version'], 6); ?></span></td>
                    <td><?php echo $row['calificacion'] !== null ? number_format($row['calificacion'], 1) : '-'; ?></td>
                    <td><small><?php echo number_format($row['tamanio'], 1); ?> KB</small></td>
                    <td><?php echo e($row['nombre_archivo']); ?></td>
                    <td><?php echo $row['visible'] === 'SI' ? '✅' : '❌'; ?></td>
                    <td>
                        <div class="btn-group btn-group-sm">
                            <a href="?ver=<?php echo $row['id']; ?>" class="btn btn-outline-primary" title="Ver">
                                <i class="fas fa-eye"></i>
                            </a>
                            <?php if ($es_maestro): ?>
                            <a href="?editar=<?php echo $row['id']; ?>" class="btn btn-outline-warning" title="Editar">
                                <i class="fas fa-edit"></i>
                            </a>
                            <a href="?nueva_version=<?php echo $row['id']; ?>" class="btn btn-outline-info" title="Nueva versión">
                                <i class="fas fa-copy"></i>
                            </a>
                            <button type="button" class="btn btn-outline-danger" title="Borrar" 
                                onclick="confirmarBorrado(<?php echo $row['id']; ?>, '<?php echo e(addslashes($row['nombre_archivo'])); ?>', '<?php echo e($row['num_version']); ?>')">
                                <i class="fas fa-trash"></i>
                            </button>
                            <?php endif; ?>
                            <?php if (!empty($row['contrasena_ver'])): ?>
                            <span class="ml-1" title="Protegido con contraseña"><i class="fas fa-lock text-warning"></i></span>
                            <?php endif; ?>
                        </div>
                    </td>
                </tr>
                <?php endwhile; ?>
            </tbody>
        </table>
    </div>
    
    <!-- Paginación -->
    <?php if ($total_paginas > 1): ?>
    <nav>
        <ul class="pagination justify-content-center">
            <?php if ($pagina > 1): ?>
            <li class="page-item"><a class="page-link" href="?pagina=<?php echo $pagina-1; 
                echo $filtro_proyecto ? '&filtro_proyecto='.urlencode($filtro_proyecto) : '';
                echo $filtro_ia ? '&filtro_ia='.urlencode($filtro_ia) : '';
                echo $filtro_tipo ? '&filtro_tipo='.urlencode($filtro_tipo) : '';
                echo $filtro_fecha_desde ? '&filtro_fecha_desde='.urlencode($filtro_fecha_desde) : '';
                echo $filtro_fecha_hasta ? '&filtro_fecha_hasta='.urlencode($filtro_fecha_hasta) : '';
                echo $filtro_visible !== 'SI' ? '&filtro_visible='.urlencode($filtro_visible) : '';
                echo $filtro_busqueda ? '&filtro_busqueda='.urlencode($filtro_busqueda) : '';
            ?>">« Anterior</a></li>
            <?php endif; ?>
            
            <?php 
            $rango = 2;
            for ($p = max(1, $pagina - $rango); $p <= min($total_paginas, $pagina + $rango); $p++):
            ?>
            <li class="page-item <?php echo $p === $pagina ? 'active' : ''; ?>">
                <a class="page-link" href="?pagina=<?php echo $p;
                    echo $filtro_proyecto ? '&filtro_proyecto='.urlencode($filtro_proyecto) : '';
                    echo $filtro_ia ? '&filtro_ia='.urlencode($filtro_ia) : '';
                    echo $filtro_tipo ? '&filtro_tipo='.urlencode($filtro_tipo) : '';
                    echo $filtro_fecha_desde ? '&filtro_fecha_desde='.urlencode($filtro_fecha_desde) : '';
                    echo $filtro_fecha_hasta ? '&filtro_fecha_hasta='.urlencode($filtro_fecha_hasta) : '';
                    echo $filtro_visible !== 'SI' ? '&filtro_visible='.urlencode($filtro_visible) : '';
                    echo $filtro_busqueda ? '&filtro_busqueda='.urlencode($filtro_busqueda) : '';
                ?>"><?php echo $p; ?></a>
            </li>
            <?php endfor; ?>
            
            <?php if ($pagina < $total_paginas): ?>
            <li class="page-item"><a class="page-link" href="?pagina=<?php echo $pagina+1;
                echo $filtro_proyecto ? '&filtro_proyecto='.urlencode($filtro_proyecto) : '';
                echo $filtro_ia ? '&filtro_ia='.urlencode($filtro_ia) : '';
                echo $filtro_tipo ? '&filtro_tipo='.urlencode($filtro_tipo) : '';
                echo $filtro_fecha_desde ? '&filtro_fecha_desde='.urlencode($filtro_fecha_desde) : '';
                echo $filtro_fecha_hasta ? '&filtro_fecha_hasta='.urlencode($filtro_fecha_hasta) : '';
                echo $filtro_visible !== 'SI' ? '&filtro_visible='.urlencode($filtro_visible) : '';
                echo $filtro_busqueda ? '&filtro_busqueda='.urlencode($filtro_busqueda) : '';
            ?>">Siguiente »</a></li>
            <?php endif; ?>
        </ul>
    </nav>
    <p class="text-center text-muted small">
        Mostrando <?php echo $offset+1; ?>-<?php echo min($offset+$por_pagina, $total_registros); ?> de <?php echo $total_registros; ?> registros
    </p>
    <?php endif; ?>
    <?php endif; ?>
</div>

<!-- Modal Confirmar Borrado -->
<div class="modal fade" id="modalBorrar" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <form method="POST">
                <div class="modal-header bg-danger text-white">
                    <h5 class="modal-title">⚠️ Confirmar Eliminación</h5>
                    <button type="button" class="close text-white" data-dismiss="modal">&times;</button>
                </div>
                <div class="modal-body">
                    <input type="hidden" name="accion" value="borrar">
                    <input type="hidden" name="id_borrar" id="id_borrar">
                    <p class="mb-3">¿Estás seguro de borrar <strong id="nombre_borrar"></strong> versión <strong id="version_borrar"></strong>?</p>
                    <p class="text-danger font-weight-bold">Esta acción NO se puede deshacer.</p>
                    <div class="form-group">
                        <label for="confirmar_texto" class="font-weight-bold">Escribe <code>BORRAR</code> en mayúsculas para confirmar:</label>
                        <input type="text" name="confirmar_borrado" id="confirmar_texto" class="form-control form-control-lg text-center" 
                            placeholder="BORRAR" autocomplete="off" required pattern="[A-Z]+" maxlength="6">
                        <small class="form-text text-muted">Debe escribir exactamente: <strong>BORRAR</strong></small>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">Cancelar</button>
                    <button type="submit" class="btn btn-danger">🗑️ Sí, eliminar definitivamente</button>
                </div>
            </form>
        </div>
    </div>
</div>

<script>
function confirmarBorrado(id, nombre, version) {
    document.getElementById('id_borrar').value = id;
    document.getElementById('nombre_borrar').textContent = nombre;
    document.getElementById('version_borrar').textContent = version;
    document.getElementById('confirmar_texto').value = '';
    $('#modalBorrar').modal('show');
}

// Validación en tiempo real del campo BORRAR
document.getElementById('confirmar_texto')?.addEventListener('input', function(e) {
    this.value = this.value.toUpperCase().replace(/[^A-Z]/g, '');
});
</script>

<?php endif; // fin else de vista formulario ?>

<!-- Footer con aviso de responsabilidad -->
<footer class="bg-light">
    <div class="container text-center">
        <p class="text-muted small mb-0">
            ⚠️ Este sistema NO hace respaldo de su propia base de datos. Respaldar MySQL es tu responsabilidad. 
            Un respaldo que no existe no es un respaldo.
        </p>
    </div>
</footer>

<!-- Scripts JS -->
<script src="https://cdn.jsdelivr.net/npm/jquery@3.5.1/dist/jquery.slim.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js"></script>

</body>
</html>

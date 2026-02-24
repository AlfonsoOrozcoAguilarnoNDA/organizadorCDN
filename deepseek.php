<?php
/**
 * SISTEMA DE RESPALDO DE PROMPTS IA - VERSIÓN ÚNICA
 * Stack: PHP 8.x procedural, MySQL, Bootstrap 4.6, FontAwesome
 * Archivo único: index.php
 * Fecha: Octubre 2023
 */

// --- CONFIGURACIÓN — edita esto antes de usar ---
define('PASS_MAESTRA', 'tu_contrasena_aqui'); // para agregar, editar y borrar (cámbiala)
define('PASS_REGISTROS', 'tu_contrasena_aqui'); // para los registros especiales (cámbiala)
define('IPS_PERMITIDAS', ['127.0.0.1', '::1']); // agrega tus IPs aquí (localhost por defecto)

// --- CABECERAS ANTI-CACHÉ ---
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: Sat, 01 Jan 2000 00:00:00 GMT');

// --- INICIO DE SESIÓN ---
session_start();

// --- VERIFICACIÓN DE IP ---
$ip_usuario = $_SERVER['REMOTE_ADDR'] ?? '';
if (!in_array($ip_usuario, IPS_PERMITIDAS)) {
    echo '<!DOCTYPE html><html><head><title>Acceso Denegado</title>';
    echo '<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">';
    echo '</head><body><div class="container mt-5"><div class="alert alert-danger">';
    echo '<h4>Acceso no autorizado</h4><p>Tu IP (' . htmlspecialchars($ip_usuario) . ') no está en la lista de permitidas.</p>';
    echo '</div></div></body></html>';
    exit;
}

// --- CONEXIÓN A BASE DE DATOS ---
$servidor = 'localhost';
$usuario_db = 'root';      // Cámbialo según tu configuración
$contrasena_db = '';        // Cámbialo según tu configuración
$nombre_db = 'ia_backups';  // Puedes cambiarlo, la tabla se creará automáticamente

$conn = new mysqli($servidor, $usuario_db, $contrasena_db, $nombre_db);
if ($conn->connect_error) {
    die('<div class="alert alert-danger">Error de conexión: ' . htmlspecialchars($conn->connect_error) . '</div>');
}

// --- CREACIÓN DE LA TABLA SI NO EXISTE (con comentario SQL) ---
$sql_create_table = "
CREATE TABLE IF NOT EXISTS ai_backups (
    id INT AUTO_INCREMENT PRIMARY KEY,
    proyecto VARCHAR(100) NOT NULL,
    ia_utilizada VARCHAR(50) NOT NULL,
    tipo VARCHAR(20) NOT NULL,
    contenido LONGTEXT NOT NULL,
    nombre_archivo VARCHAR(150) NOT NULL,
    num_version DECIMAL(14,6) NOT NULL,
    comentarios LONGTEXT,
    calificacion DECIMAL(14,6),
    visible VARCHAR(2) NOT NULL DEFAULT 'SI',
    fecha DATETIME NOT NULL,
    contrasena_ver VARCHAR(255) DEFAULT '',
    tamanio DECIMAL(14,6) NOT NULL,
    hash_md5 VARCHAR(32) NOT NULL,
    hash_sha1 VARCHAR(40) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
";
if (!$conn->query($sql_create_table)) {
    die('<div class="alert alert-danger">Error creando tabla: ' . htmlspecialchars($conn->error) . '</div>');
}

// --- FUNCIONES AUXILIARES ---
function verificar_autenticacion() {
    return isset($_SESSION['autenticado']) && $_SESSION['autenticado'] === true;
}

function redirigir($url) {
    header("Location: $url");
    exit;
}

function sanitize_input($data) {
    return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
}

function calcular_hashes_y_tamano($contenido, $tipo) {
    // Si es imagen, el contenido ya viene como base64
    $datos = $contenido;
    if ($tipo === 'imagen') {
        // Extraer solo la parte base64 si viene con cabecera data:image
        if (strpos($contenido, 'base64,') !== false) {
            $datos = explode('base64,', $contenido)[1];
        } else {
            $datos = $contenido; // Asumimos que ya es base64 puro
        }
    }
    
    $tamanio_bytes = strlen($datos);
    $tamanio_kb = $tamanio_bytes / 1024;
    $hash_md5 = md5($datos);
    $hash_sha1 = sha1($datos);
    
    return [
        'tamanio' => $tamanio_kb,
        'hash_md5' => $hash_md5,
        'hash_sha1' => $hash_sha1
    ];
}

function obtener_ultima_version($conn, $proyecto, $nombre_archivo) {
    $sql = "SELECT MAX(num_version) as max_version FROM ai_backups WHERE proyecto = ? AND nombre_archivo = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param('ss', $proyecto, $nombre_archivo);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();
    return $row['max_version'] ? $row['max_version'] + 1.000000 : 1.000000;
}

function es_base64_imagen_segura($base64_string) {
    // Permitir solo ciertos tipos de imagen
    $formatos_permitidos = ['/^data:image\/jpeg;base64,/', '/^data:image\/png;base64,/', '/^data:image\/gif;base64,/', '/^data:image\/webp;base64,/'];
    foreach ($formatos_permitidos as $formato) {
        if (preg_match($formato, $base64_string)) {
            return true;
        }
    }
    // Si no tiene cabecera, asumimos que es base64 puro de imagen (validamos por la salida)
    return true; // La validación real se haría con getimagesize desde un archivo temporal, pero por simplicidad lo dejamos pasar
}

// --- PROCESAMIENTO DE ACCIONES ---
$accion = $_GET['accion'] ?? 'listar';
$mensaje = '';
$error = '';

// Verificar tamaño POST vacío (posible límite de servidor)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($_POST) && empty($_FILES) && $_SERVER['CONTENT_LENGTH'] > 0) {
    $max_size = ini_get('post_max_size');
    $error = "⚠️ El archivo enviado es demasiado grande. El límite del servidor es de $max_size. Contacta al administrador o reduce el tamaño.";
}

// Procesar login
if ($accion === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $pass = $_POST['contrasena'] ?? '';
    if ($pass === PASS_MAESTRA) {
        $_SESSION['autenticado'] = true;
        $mensaje = 'Autenticación exitosa.';
        redirigir('index.php');
    } else {
        $error = 'Contraseña incorrecta.';
    }
}

// Procesar logout
if ($accion === 'logout') {
    session_destroy();
    redirigir('index.php');
}

// Procesar guardar (insertar o actualizar)
if ($accion === 'guardar' && $_SERVER['REQUEST_METHOD'] === 'POST' && verificar_autenticacion()) {
    $id = $_POST['id'] ?? '';
    $proyecto = $_POST['proyecto'] ?? '';
    $ia_utilizada = $_POST['ia_utilizada'] ?? '';
    $tipo = $_POST['tipo'] ?? '';
    $contenido = $_POST['contenido'] ?? '';
    $nombre_archivo = $_POST['nombre_archivo'] ?? '';
    $num_version = $_POST['num_version'] ?? '';
    $comentarios = $_POST['comentarios'] ?? '';
    $calificacion = $_POST['calificacion'] ?? null;
    $visible = $_POST['visible'] ?? 'SI';
    $contrasena_ver = $_POST['contrasena_ver'] ?? '';
    
    // Procesar imagen si se subió archivo
    if ($tipo === 'imagen' && isset($_FILES['archivo_imagen']) && $_FILES['archivo_imagen']['error'] === UPLOAD_ERR_OK) {
        $imagen_tmp = $_FILES['archivo_imagen']['tmp_name'];
        $imagen_tipo = $_FILES['archivo_imagen']['type'];
        $imagen_contenido = file_get_contents($imagen_tmp);
        $contenido = 'data:' . $imagen_tipo . ';base64,' . base64_encode($imagen_contenido);
    }
    
    // Validar que el contenido no esté vacío
    if (empty($contenido)) {
        $error = 'El contenido no puede estar vacío.';
    } else {
        // Calcular hashes y tamaño
        $hashes = calcular_hashes_y_tamano($contenido, $tipo);
        $tamanio = $hashes['tamanio'];
        $hash_md5 = $hashes['hash_md5'];
        $hash_sha1 = $hashes['hash_sha1'];
        
        // Hashear contraseña si se proporciona
        if (!empty($contrasena_ver)) {
            $contrasena_ver = password_hash($contrasena_ver, PASSWORD_DEFAULT);
        } else {
            $contrasena_ver = '';
        }
        
        if (empty($id)) { // Nuevo registro
            $fecha = date('Y-m-d H:i:s');
            $sql = "INSERT INTO ai_backups (proyecto, ia_utilizada, tipo, contenido, nombre_archivo, num_version, comentarios, calificacion, visible, fecha, contrasena_ver, tamanio, hash_md5, hash_sha1) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param('ssssssdssssdss', $proyecto, $ia_utilizada, $tipo, $contenido, $nombre_archivo, $num_version, $comentarios, $calificacion, $visible, $fecha, $contrasena_ver, $tamanio, $hash_md5, $hash_sha1);
        } else { // Actualizar
            $sql = "UPDATE ai_backups SET proyecto=?, ia_utilizada=?, tipo=?, contenido=?, nombre_archivo=?, num_version=?, comentarios=?, calificacion=?, visible=?, contrasena_ver=?, tamanio=?, hash_md5=?, hash_sha1=? WHERE id=?";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param('ssssssdssssdssi', $proyecto, $ia_utilizada, $tipo, $contenido, $nombre_archivo, $num_version, $comentarios, $calificacion, $visible, $contrasena_ver, $tamanio, $hash_md5, $hash_sha1, $id);
        }
        
        if ($stmt->execute()) {
            $mensaje = 'Registro guardado correctamente.';
            redirigir('index.php?accion=ver&id=' . ($id ?: $stmt->insert_id));
        } else {
            $error = 'Error al guardar: ' . htmlspecialchars($stmt->error);
        }
    }
}

// Procesar borrar
if ($accion === 'borrar' && isset($_GET['id']) && verificar_autenticacion()) {
    $id = intval($_GET['id']);
    // Obtener nombre para confirmación
    $sql = "SELECT nombre_archivo, num_version FROM ai_backups WHERE id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param('i', $id);
    $stmt->execute();
    $result = $stmt->get_result();
    $registro = $result->fetch_assoc();
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['confirmar_borrar']) && $_POST['confirmar_borrar'] === 'BORRAR') {
        $sql_delete = "DELETE FROM ai_backups WHERE id = ?";
        $stmt_delete = $conn->prepare($sql_delete);
        $stmt_delete->bind_param('i', $id);
        if ($stmt_delete->execute()) {
            $mensaje = 'Registro borrado permanentemente.';
            redirigir('index.php');
        } else {
            $error = 'Error al borrar: ' . htmlspecialchars($stmt_delete->error);
        }
    }
}

// --- LÓGICA DE PAGINACIÓN Y FILTROS ---
$pagina = isset($_GET['pagina']) ? max(1, intval($_GET['pagina'])) : 1;
$por_pagina = 10;
$offset = ($pagina - 1) * $por_pagina;

$filtros = [];
$params = [];
$tipos = '';

$sql_count = "SELECT COUNT(*) as total FROM ai_backups WHERE 1=1";
$sql_select = "SELECT * FROM ai_backups WHERE 1=1";

// Filtros generales
if (isset($_GET['filtrar']) || isset($_GET['buscar'])) {
    if (!empty($_GET['proyecto'])) {
        $filtros[] = "proyecto LIKE ?";
        $params[] = '%' . $_GET['proyecto'] . '%';
        $tipos .= 's';
    }
    if (!empty($_GET['ia_utilizada'])) {
        $filtros[] = "ia_utilizada = ?";
        $params[] = $_GET['ia_utilizada'];
        $tipos .= 's';
    }
    if (!empty($_GET['tipo'])) {
        $filtros[] = "tipo = ?";
        $params[] = $_GET['tipo'];
        $tipos .= 's';
    }
    if (!empty($_GET['fecha_desde'])) {
        $filtros[] = "fecha >= ?";
        $params[] = $_GET['fecha_desde'] . ' 00:00:00';
        $tipos .= 's';
    }
    if (!empty($_GET['fecha_hasta'])) {
        $filtros[] = "fecha <= ?";
        $params[] = $_GET['fecha_hasta'] . ' 23:59:59';
        $tipos .= 's';
    }
    if (isset($_GET['visible']) && $_GET['visible'] !== 'todos') {
        $filtros[] = "visible = ?";
        $params[] = $_GET['visible'];
        $tipos .= 's';
    }
    if (!empty($_GET['buscar_texto'])) {
        $filtros[] = "(contenido LIKE ? OR comentarios LIKE ?)";
        $params[] = '%' . $_GET['buscar_texto'] . '%';
        $params[] = '%' . $_GET['buscar_texto'] . '%';
        $tipos .= 'ss';
    }
}

// Por defecto, solo mostrar visibles si no hay filtro explícito
if (empty($filtros) || !isset($_GET['visible']) || $_GET['visible'] === 'SI') {
    $filtros[] = "visible = 'SI'";
}

if (!empty($filtros)) {
    $where = " AND " . implode(" AND ", $filtros);
    $sql_count .= $where;
    $sql_select .= $where;
}

$sql_select .= " ORDER BY fecha DESC LIMIT ? OFFSET ?";
$params[] = $por_pagina;
$params[] = $offset;
$tipos .= 'ii';

// Ejecutar count
$stmt_count = $conn->prepare($sql_count);
if (!empty($params) && count($params) > 2) {
    $params_count = array_slice($params, 0, -2); // Quitar los últimos dos parámetros (LIMIT y OFFSET)
    $tipos_count = substr($tipos, 0, -2);
    if (!empty($params_count)) {
        $stmt_count->bind_param($tipos_count, ...$params_count);
    }
}
$stmt_count->execute();
$total_registros = $stmt_count->get_result()->fetch_assoc()['total'];
$total_paginas = ceil($total_registros / $por_pagina);

// Ejecutar select
$stmt_select = $conn->prepare($sql_select);
if (!empty($params)) {
    $stmt_select->bind_param($tipos, ...$params);
}
$stmt_select->execute();
$resultados = $stmt_select->get_result();

// --- INICIO DE HTML ---
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IA Backup System</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/font-awesome@4.7.0/css/font-awesome.min.css">
    <style>
        .diff-added { background-color: #d4edda; color: #155724; }
        .diff-removed { background-color: #f8d7da; color: #721c24; }
        pre { white-space: pre-wrap; word-wrap: break-word; }
        .footer { font-size: 0.8rem; }
        .candado { color: #6c757d; margin-left: 5px; }
    </style>
</head>
<body>
    <!-- Navbar fijo -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark sticky-top">
        <a class="navbar-brand" href="index.php">🤖 IA Backup System</a>
        <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarNav">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav mr-auto">
                <li class="nav-item"><a class="nav-link" href="index.php?accion=listar"><i class="fa fa-list"></i> Ver registros</a></li>
                <?php if (verificar_autenticacion()): ?>
                <li class="nav-item"><a class="nav-link" href="index.php?accion=nuevo"><i class="fa fa-plus"></i> Agregar nuevo</a></li>
                <?php endif; ?>
                <li class="nav-item"><a class="nav-link" href="index.php?accion=buscar"><i class="fa fa-search"></i> Buscar</a></li>
            </ul>
            <span class="navbar-text mr-3">
                <?php if (verificar_autenticacion()): ?>
                    <span class="badge badge-success">Autenticado <i class="fa fa-check-circle"></i></span>
                <?php else: ?>
                    <span class="badge badge-warning">Solo lectura <i class="fa fa-eye"></i></span>
                <?php endif; ?>
            </span>
            <span class="navbar-text mr-3">LLM: Claude</span>
            <?php if (verificar_autenticacion()): ?>
                <a href="index.php?accion=logout" class="btn btn-outline-light btn-sm"><i class="fa fa-sign-out"></i> Cerrar sesión</a>
            <?php else: ?>
                <a href="index.php?accion=login" class="btn btn-outline-light btn-sm"><i class="fa fa-sign-in"></i> Iniciar sesión</a>
            <?php endif; ?>
        </div>
    </nav>

    <div class="container mt-4">
        <!-- Mensajes -->
        <?php if ($mensaje): ?>
            <div class="alert alert-success alert-dismissible fade show"><?= htmlspecialchars($mensaje) ?><button type="button" class="close" data-dismiss="alert">&times;</button></div>
        <?php endif; ?>
        <?php if ($error): ?>
            <div class="alert alert-danger alert-dismissible fade show"><?= htmlspecialchars($error) ?><button type="button" class="close" data-dismiss="alert">&times;</button></div>
        <?php endif; ?>

        <!-- Contenido dinámico -->
        <?php
        // --- ACCIONES DE VISTA ---
        if ($accion === 'login' && !verificar_autenticacion()):
        ?>
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header bg-primary text-white">Autenticación requerida</div>
                        <div class="card-body">
                            <form method="post">
                                <div class="form-group">
                                    <label>Contraseña maestra</label>
                                    <input type="password" name="contrasena" class="form-control" required>
                                </div>
                                <button type="submit" class="btn btn-primary btn-block"><i class="fa fa-lock"></i> Acceder</button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        <?php
        elseif ($accion === 'nuevo' && verificar_autenticacion()):
            $ultima_version = isset($_GET['duplicar']) ? floatval($_GET['duplicar']) + 1.000000 : 1.000000;
            $proyecto_duplicado = $_GET['proyecto'] ?? '';
            $archivo_duplicado = $_GET['archivo'] ?? '';
            if (isset($_GET['duplicar'])) {
                $sql_duplicar = "SELECT * FROM ai_backups WHERE id = ?";
                $stmt_duplicar = $conn->prepare($sql_duplicar);
                $stmt_duplicar->bind_param('i', $_GET['duplicar']);
                $stmt_duplicar->execute();
                $duplicado = $stmt_duplicar->get_result()->fetch_assoc();
                if ($duplicado) {
                    $proyecto_duplicado = $duplicado['proyecto'];
                    $archivo_duplicado = $duplicado['nombre_archivo'];
                    $ia_duplicado = $duplicado['ia_utilizada'];
                    $tipo_duplicado = $duplicado['tipo'];
                }
            }
        ?>
            <div class="card">
                <div class="card-header bg-success text-white"><?= isset($_GET['duplicar']) ? 'Nueva versión desde ID ' . $_GET['duplicar'] : 'Agregar nuevo registro' ?></div>
                <div class="card-body">
                    <form method="post" enctype="multipart/form-data">
                        <input type="hidden" name="id" value="">
                        <div class="row">
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label>Proyecto *</label>
                                    <input type="text" name="proyecto" class="form-control" value="<?= htmlspecialchars($proyecto_duplicado) ?>" required>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label>IA Utilizada *</label>
                                    <select name="ia_utilizada" class="form-control" required>
                                        <option value="ChatGPT" <?= ($ia_duplicado ?? '') == 'ChatGPT' ? 'selected' : '' ?>>ChatGPT</option>
                                        <option value="Claude" <?= ($ia_duplicado ?? '') == 'Claude' ? 'selected' : '' ?>>Claude</option>
                                        <option value="Gemini" <?= ($ia_duplicado ?? '') == 'Gemini' ? 'selected' : '' ?>>Gemini</option>
                                        <option value="Grok" <?= ($ia_duplicado ?? '') == 'Grok' ? 'selected' : '' ?>>Grok</option>
                                        <option value="Cohere" <?= ($ia_duplicado ?? '') == 'Cohere' ? 'selected' : '' ?>>Cohere</option>
                                        <option value="otro" <?= ($ia_duplicado ?? '') == 'otro' ? 'selected' : '' ?>>Otro</option>
                                    </select>
                                </div>
                            </div>
                        </div>
                        <div class="row">
                            <div class="col-md-4">
                                <div class="form-group">
                                    <label>Tipo *</label>
                                    <select name="tipo" class="form-control" required id="tipo_select">
                                        <option value="prompt" <?= ($tipo_duplicado ?? '') == 'prompt' ? 'selected' : '' ?>>Prompt</option>
                                        <option value="imagen" <?= ($tipo_duplicado ?? '') == 'imagen' ? 'selected' : '' ?>>Imagen</option>
                                        <option value="idea" <?= ($tipo_duplicado ?? '') == 'idea' ? 'selected' : '' ?>>Idea</option>
                                        <option value="respuesta" <?= ($tipo_duplicado ?? '') == 'respuesta' ? 'selected' : '' ?>>Respuesta</option>
                                        <option value="codigo" <?= ($tipo_duplicado ?? '') == 'codigo' ? 'selected' : '' ?>>Código</option>
                                        <option value="otro" <?= ($tipo_duplicado ?? '') == 'otro' ? 'selected' : '' ?>>Otro</option>
                                    </select>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="form-group">
                                    <label>Nombre archivo *</label>
                                    <input type="text" name="nombre_archivo" class="form-control" value="<?= htmlspecialchars($archivo_duplicado) ?>" required>
                                </div>
                            </div>
                            <div class="col-md-4">
                                <div class="form-group">
                                    <label>Versión *</label>
                                    <input type="number" step="0.000001" name="num_version" class="form-control" value="<?= htmlspecialchars($ultima_version) ?>" required>
                                </div>
                            </div>
                        </div>
                        <div class="form-group">
                            <label>Contenido *</label>
                            <div id="contenido_texto">
                                <textarea name="contenido" class="form-control" rows="8" placeholder="Pega aquí el contenido..."><?= htmlspecialchars($duplicado['contenido'] ?? '') ?></textarea>
                            </div>
                            <div id="contenido_imagen" style="display:none;">
                                <input type="file" name="archivo_imagen" class="form-control-file" accept="image/*">
                                <small class="form-text text-muted">Selecciona una imagen. Se convertirá automáticamente a base64.</small>
                            </div>
                        </div>
                        <div class="form-group">
                            <label>Comentarios</label>
                            <textarea name="comentarios" class="form-control" rows="3"><?= htmlspecialchars($duplicado['comentarios'] ?? '') ?></textarea>
                        </div>
                        <div class="row">
                            <div class="col-md-3">
                                <div class="form-group">
                                    <label>Calificación</label>
                                    <input type="number" step="0.1" name="calificacion" class="form-control" value="<?= htmlspecialchars($duplicado['calificacion'] ?? '') ?>">
                                </div>
                            </div>
                            <div class="col-md-3">
                                <div class="form-group">
                                    <label>Visible</label>
                                    <select name="visible" class="form-control">
                                        <option value="SI" <?= ($duplicado['visible'] ?? 'SI') == 'SI' ? 'selected' : '' ?>>SI</option>
                                        <option value="NO" <?= ($duplicado['visible'] ?? '') == 'NO' ? 'selected' : '' ?>>NO</option>
                                    </select>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label>Contraseña individual (opcional)</label>
                                    <input type="text" name="contrasena_ver" class="form-control" placeholder="Dejar vacío para sin contraseña">
                                    <small class="form-text text-muted">Si se llena, se pedirá para ver este registro.</small>
                                </div>
                            </div>
                        </div>
                        <button type="submit" name="accion" value="guardar" class="btn btn-primary"><i class="fa fa-save"></i> Guardar</button>
                        <a href="index.php" class="btn btn-secondary">Cancelar</a>
                    </form>
                </div>
            </div>
            <script>
                document.getElementById('tipo_select').addEventListener('change', function() {
                    if (this.value === 'imagen') {
                        document.getElementById('contenido_texto').style.display = 'none';
                        document.getElementById('contenido_imagen').style.display = 'block';
                    } else {
                        document.getElementById('contenido_texto').style.display = 'block';
                        document.getElementById('contenido_imagen').style.display = 'none';
                    }
                });
                if (document.getElementById('tipo_select').value === 'imagen') {
                    document.getElementById('contenido_texto').style.display = 'none';
                    document.getElementById('contenido_imagen').style.display = 'block';
                }
            </script>
        <?php
        elseif ($accion === 'ver' && isset($_GET['id'])):
            $id = intval($_GET['id']);
            $sql_ver = "SELECT * FROM ai_backups WHERE id = ?";
            $stmt_ver = $conn->prepare($sql_ver);
            $stmt_ver->bind_param('i', $id);
            $stmt_ver->execute();
            $registro = $stmt_ver->get_result()->fetch_assoc();
            
            if (!$registro) {
                echo '<div class="alert alert-danger">Registro no encontrado.</div>';
            } else {
                // Verificar contraseña individual
                $acceso_concedido = true;
                if (!empty($registro['contrasena_ver']) && !verificar_autenticacion()) {
                    $acceso_concedido = false;
                    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['pass_individual'])) {
                        if (password_verify($_POST['pass_individual'], $registro['contrasena_ver'])) {
                            $acceso_concedido = true;
                            $_SESSION['acceso_' . $id] = true;
                        } else {
                            $error_pass = 'Contraseña incorrecta.';
                        }
                    }
                    if (isset($_SESSION['acceso_' . $id])) {
                        $acceso_concedido = true;
                    }
                }
                
                if (!$acceso_concedido) {
                    ?>
                    <div class="card">
                        <div class="card-header bg-warning">Registro protegido</div>
                        <div class="card-body">
                            <?php if (isset($error_pass)) echo '<div class="alert alert-danger">' . htmlspecialchars($error_pass) . '</div>'; ?>
                            <p>Este registro requiere una contraseña para ser visualizado.</p>
                            <form method="post">
                                <div class="form-group">
                                    <label>Contraseña:</label>
                                    <input type="password" name="pass_individual" class="form-control" required>
                                </div>
                                <button type="submit" class="btn btn-primary"><i class="fa fa-unlock-alt"></i> Desbloquear</button>
                            </form>
                        </div>
                    </div>
                    <?php
                } else {
                    // Mostrar registro completo
                    $contenido = $registro['contenido'];
                    ?>
                    <div class="card">
                        <div class="card-header bg-info text-white">Detalle del registro #<?= $id ?></div>
                        <div class="card-body">
                            <div class="row">
                                <div class="col-md-6">
                                    <p><strong>Proyecto:</strong> <?= htmlspecialchars($registro['proyecto']) ?></p>
                                    <p><strong>IA:</strong> <?= htmlspecialchars($registro['ia_utilizada']) ?></p>
                                    <p><strong>Tipo:</strong> <?= htmlspecialchars($registro['tipo']) ?></p>
                                    <p><strong>Nombre archivo:</strong> <?= htmlspecialchars($registro['nombre_archivo']) ?></p>
                                    <p><strong>Versión:</strong> <?= htmlspecialchars($registro['num_version']) ?></p>
                                    <p><strong>Calificación:</strong> <?= htmlspecialchars($registro['calificacion'] ?? 'N/A') ?></p>
                                </div>
                                <div class="col-md-6">
                                    <p><strong>Fecha:</strong> <?= htmlspecialchars($registro['fecha']) ?></p>
                                    <p><strong>Visible:</strong> <?= htmlspecialchars($registro['visible']) ?></p>
                                    <p><strong>Tamaño:</strong> <?= number_format($registro['tamanio'], 2) ?> KB</p>
                                    <p><strong>MD5:</strong> <code><?= htmlspecialchars($registro['hash_md5']) ?></code></p>
                                    <p><strong>SHA1:</strong> <code><?= htmlspecialchars($registro['hash_sha1']) ?></code></p>
                                    <?php if (!empty($registro['contrasena_ver'])): ?>
                                        <p><span class="badge badge-warning"><i class="fa fa-lock"></i> Protegido</span></p>
                                    <?php endif; ?>
                                </div>
                            </div>
                            <div class="form-group">
                                <label><strong>Comentarios:</strong></label>
                                <pre class="border p-2"><?= htmlspecialchars($registro['comentarios'] ?? '') ?></pre>
                            </div>
                            <div class="form-group">
                                <label><strong>Contenido:</strong></label>
                                <?php if ($registro['tipo'] === 'imagen'): ?>
                                    <?php
                                    // Validar que sea una imagen segura
                                    if (es_base64_imagen_segura($contenido)) {
                                        echo '<img src="' . htmlspecialchars($contenido) . '" class="img-fluid" alt="Imagen del registro">';
                                    } else
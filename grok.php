<?php
// ================================================
// SISTEMA DE RESPALDO DE PROMPTS IA - SINGLE FILE
// PHP 8.x procedural | MySQL/MariaDB | Bootstrap 4.6
// Creado por Grok (xAI) - Febrero 2026
// ================================================

/*
CREATE TABLE IF NOT EXISTS `ai_backups` (
  `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `proyecto` VARCHAR(100) NOT NULL,
  `ia_utilizada` VARCHAR(50) NOT NULL,
  `tipo` VARCHAR(20) NOT NULL,
  `contenido` LONGTEXT NOT NULL,
  `nombre_archivo` VARCHAR(150) NOT NULL,
  `num_version` DECIMAL(14,6) NOT NULL DEFAULT 1.000000,
  `comentarios` LONGTEXT NULL,
  `calificacion` DECIMAL(14,6) NULL,
  `visible` VARCHAR(2) NOT NULL DEFAULT 'SI',
  `fecha` DATETIME NOT NULL,
  `contrasena_ver` VARCHAR(255) NULL,
  `tamanio` DECIMAL(14,6) NULL,
  `hash_md5` VARCHAR(32) NULL,
  `hash_sha1` VARCHAR(40) NULL,
  INDEX `idx_proyecto_nombre` (`proyecto`, `nombre_archivo`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
*/

// --- CONFIGURACIÓN — edita esto antes de usar ---
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_NAME', 'ai_backups');

define('PASS_MAESTRA', 'tu_contrasena_aqui');     // para agregar, editar y borrar
define('PASS_REGISTROS', 'tu_contrasena_aqui');   // NO SE USA (contraseñas por registro son dinámicas y hasheadas)
define('IPS_PERMITIDAS', ['127.0.0.1', '::1', '']); // agrega tus IPs reales aquí

// ================================================

session_start();

// Headers anti-caché (información sensible)
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: Sat, 01 Jan 2000 00:00:00 GMT');

// Control por IP
$ip = $_SERVER['REMOTE_ADDR'];
if (!in_array($ip, IPS_PERMITIDAS)) {
    die('<h1 class="text-center mt-5">Acceso no autorizado</h1>');
}

// Conexión MySQL
$mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if ($mysqli->connect_error) {
    die('Error de conexión MySQL: ' . $mysqli->connect_error);
}
$mysqli->set_charset('utf8mb4');

// Crear tabla si no existe
$create_table = "CREATE TABLE IF NOT EXISTS `ai_backups` (
  `id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `proyecto` VARCHAR(100) NOT NULL,
  `ia_utilizada` VARCHAR(50) NOT NULL,
  `tipo` VARCHAR(20) NOT NULL,
  `contenido` LONGTEXT NOT NULL,
  `nombre_archivo` VARCHAR(150) NOT NULL,
  `num_version` DECIMAL(14,6) NOT NULL DEFAULT 1.000000,
  `comentarios` LONGTEXT NULL,
  `calificacion` DECIMAL(14,6) NULL,
  `visible` VARCHAR(2) NOT NULL DEFAULT 'SI',
  `fecha` DATETIME NOT NULL,
  `contrasena_ver` VARCHAR(255) NULL,
  `tamanio` DECIMAL(14,6) NULL,
  `hash_md5` VARCHAR(32) NULL,
  `hash_sha1` VARCHAR(40) NULL,
  INDEX `idx_proyecto_nombre` (`proyecto`, `nombre_archivo`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;";
$mysqli->query($create_table);

// Manejo de POST grande vacío (post_max_size)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($_POST) && !empty($_SERVER['CONTENT_LENGTH'])) {
    $max = ini_get('post_max_size');
    die('<div class="alert alert-danger text-center mt-5">ERROR: Datos POST vacíos. Probablemente excede post_max_size (' . $max . '). Aumenta el límite en php.ini o .user.ini</div>');
}

// Procesamiento de acciones POST
$success = '';
$error = '';
$is_auth = isset($_SESSION['master_auth']) && $_SESSION['master_auth'] === true;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    // Login master
    if ($action === 'login_master') {
        if ($_POST['master_pass'] === PASS_MAESTRA) {
            $_SESSION['master_auth'] = true;
            header('Location: ?');
            exit;
        } else {
            $error = 'Contraseña maestra incorrecta';
        }
    }

    // Logout
    if ($action === 'logout') {
        unset($_SESSION['master_auth']);
        header('Location: ?');
        exit;
    }

    // Solo si está autenticado como master
    if ($is_auth) {
        // Guardar (agregar o editar)
        if ($action === 'save') {
            $id = (int)($_POST['id'] ?? 0);
            $proyecto = trim($_POST['proyecto'] ?? '');
            $ia_utilizada = trim($_POST['ia_utilizada'] ?? 'Grok');
            $tipo = $_POST['tipo'] ?? 'prompt';
            $nombre_archivo = trim($_POST['nombre_archivo'] ?? '');
            $num_version = (float)($_POST['num_version'] ?? 1.000000);
            $comentarios = $_POST['comentarios'] ?? '';
            $calificacion = $_POST['calificacion'] !== '' ? (float)$_POST['calificacion'] : null;
            $visible = $_POST['visible'] ?? 'SI';
            $contrasena_ver_plain = trim($_POST['contrasena_ver'] ?? '');
            $contenido = $_POST['contenido'] ?? '';

            // Manejo de imagen subida
            if ($tipo === 'imagen' && isset($_FILES['imagen_file']) && $_FILES['imagen_file']['error'] === 0) {
                $tmp = $_FILES['imagen_file']['tmp_name'];
                $mime = mime_content_type($tmp);
                if (in_array($mime, ['image/jpeg', 'image/png', 'image/gif', 'image/webp'])) {
                    $b64 = base64_encode(file_get_contents($tmp));
                    $contenido = "data:$mime;base64,$b64";
                } else {
                    $error = 'Tipo de imagen no permitido (solo JPG, PNG, GIF, WEBP)';
                }
            }

            // Validación base64 para imágenes pegadas
            if ($tipo === 'imagen' && empty($error) && !empty($_POST['base64_paste'])) {
                $contenido = trim($_POST['base64_paste']);
                if (strpos($contenido, 'data:image/') !== 0) {
                    $error = 'Para imágenes debes pegar un data URI completo (data:image/...;base64,...)';
                }
            }

            if (empty($error) && $proyecto && $nombre_archivo && $contenido !== '') {
                // Auto-ajuste de versión si es nuevo y estaba en 1.000000
                if ($id === 0 && $num_version == 1.0) {
                    $max_stmt = $mysqli->prepare("SELECT MAX(num_version) AS maxv FROM ai_backups WHERE proyecto = ? AND nombre_archivo = ?");
                    $max_stmt->bind_param("ss", $proyecto, $nombre_archivo);
                    $max_stmt->execute();
                    $max_res = $max_stmt->get_result()->fetch_assoc();
                    $maxv = $max_res['maxv'] ?? 0;
                    $num_version = $maxv + 1.000000;
                }

                $fecha = date('Y-m-d H:i:s');
                $tamanio = round(strlen($contenido) / 1024, 6);
                $hash_md5 = md5($contenido);
                $hash_sha1 = sha1($contenido);

                $contrasena_ver = null;
                if ($contrasena_ver_plain !== '') {
                    $contrasena_ver = password_hash($contrasena_ver_plain, PASSWORD_DEFAULT);
                } elseif ($id > 0) {
                    // Mantener contraseña existente si no se escribe nada nuevo
                    $old_stmt = $mysqli->prepare("SELECT contrasena_ver FROM ai_backups WHERE id = ?");
                    $old_stmt->bind_param("i", $id);
                    $old_stmt->execute();
                    $old_res = $old_stmt->get_result()->fetch_assoc();
                    $contrasena_ver = $old_res['contrasena_ver'] ?? null;
                }

                if ($id > 0) {
                    // UPDATE
                    $stmt = $mysqli->prepare("UPDATE ai_backups SET 
                        proyecto=?, ia_utilizada=?, tipo=?, contenido=?, nombre_archivo=?, 
                        num_version=?, comentarios=?, calificacion=?, visible=?, fecha=?, 
                        contrasena_ver=?, tamanio=?, hash_md5=?, hash_sha1=? 
                        WHERE id=?");
                    $num_ver_str = number_format($num_version, 6, '.', '');
                    $tam_str = number_format($tamanio, 6, '.', '');
                    $calif_str = $calificacion === null ? null : number_format($calificacion, 6, '.', '');
                    $stmt->bind_param("sssssdssdsdsdssi", 
                        $proyecto, $ia_utilizada, $tipo, $contenido, $nombre_archivo,
                        $num_ver_str, $comentarios, $calif_str, $visible, $fecha,
                        $contrasena_ver, $tam_str, $hash_md5, $hash_sha1, $id
                    );
                } else {
                    // INSERT
                    $stmt = $mysqli->prepare("INSERT INTO ai_backups 
                        (proyecto, ia_utilizada, tipo, contenido, nombre_archivo, num_version, 
                         comentarios, calificacion, visible, fecha, contrasena_ver, tamanio, hash_md5, hash_sha1) 
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
                    $num_ver_str = number_format($num_version, 6, '.', '');
                    $tam_str = number_format($tamanio, 6, '.', '');
                    $calif_str = $calificacion === null ? null : number_format($calificacion, 6, '.', '');
                    $stmt->bind_param("sssssdssdsdsds", 
                        $proyecto, $ia_utilizada, $tipo, $contenido, $nombre_archivo,
                        $num_ver_str, $comentarios, $calif_str, $visible, $fecha,
                        $contrasena_ver, $tam_str, $hash_md5, $hash_sha1
                    );
                }

                if ($stmt->execute()) {
                    $success = $id > 0 ? 'Registro actualizado correctamente' : 'Nuevo registro guardado';
                    header('Location: ?accion=list&success=1');
                    exit;
                } else {
                    $error = 'Error al guardar: ' . $stmt->error;
                }
            } else {
                $error = $error ?: 'Faltan campos obligatorios';
            }
        }

        // Borrar
        if ($action === 'delete') {
            $id = (int)($_POST['id'] ?? 0);
            $confirm = strtoupper(trim($_POST['confirm_borrar'] ?? ''));
            if ($confirm === 'BORRAR' && $id > 0) {
                $stmt = $mysqli->prepare("DELETE FROM ai_backups WHERE id = ?");
                $stmt->bind_param("i", $id);
                if ($stmt->execute()) {
                    $success = 'Registro eliminado permanentemente';
                    header('Location: ?accion=list');
                    exit;
                }
            } else {
                $error = 'Debes escribir exactamente BORRAR (mayúsculas)';
            }
        }
    }
}

// ================================================
// LÓGICA DE VISTA
$accion = $_GET['accion'] ?? 'list';
$current_id = (int)($_GET['id'] ?? 0);
$form_id = 0;
$form_data = [
    'proyecto' => '', 'ia_utilizada' => 'Grok', 'tipo' => 'prompt',
    'contenido' => '', 'nombre_archivo' => '', 'num_version' => '1.000000',
    'comentarios' => '', 'calificacion' => '', 'visible' => 'SI',
    'contrasena_ver' => ''
];

// Nueva versión o editar
if (($accion === 'nueva_version' || $accion === 'editar') && $current_id > 0 && $is_auth) {
    $stmt = $mysqli->prepare("SELECT * FROM ai_backups WHERE id = ?");
    $stmt->bind_param("i", $current_id);
    $stmt->execute();
    $orig = $stmt->get_result()->fetch_assoc();
    if ($orig) {
        $form_id = $accion === 'editar' ? $current_id : 0;
        $form_data = $orig;
        $form_data['contrasena_ver'] = ''; // nunca mostramos hash
        if ($accion === 'nueva_version') {
            $form_data['num_version'] = number_format($orig['num_version'] + 1.000000, 6, '.', '');
            $form_data['contenido'] = '';
            $form_data['fecha'] = '';
            $form_data['tamanio'] = '';
            $form_data['hash_md5'] = '';
            $form_data['hash_sha1'] = '';
        }
        $accion = 'agregar'; // reutilizamos el formulario
    }
}

// Ver registro
$record = null;
$show_content = true;
$ver_error = '';
$other_versions = [];
$diff_html = '';

if ($accion === 'ver' && $current_id > 0) {
    $stmt = $mysqli->prepare("SELECT * FROM ai_backups WHERE id = ?");
    $stmt->bind_param("i", $current_id);
    $stmt->execute();
    $record = $stmt->get_result()->fetch_assoc();

    if ($record) {
        $has_lock = !empty($record['contrasena_ver']);
        if ($has_lock) {
            if (isset($_POST['ver_pass'])) {
                if (password_verify($_POST['ver_pass'], $record['contrasena_ver'])) {
                    $show_content = true;
                } else {
                    $ver_error = 'Contraseña de visualización incorrecta';
                    $show_content = false;
                }
            } else {
                $show_content = false;
            }
        }

        // Otras versiones
        $vstmt = $mysqli->prepare("SELECT id, fecha, num_version FROM ai_backups 
            WHERE proyecto = ? AND nombre_archivo = ? AND id != ? 
            ORDER BY num_version DESC, fecha DESC");
        $vstmt->bind_param("ssi", $record['proyecto'], $record['nombre_archivo'], $current_id);
        $vstmt->execute();
        $other_versions = $vstmt->get_result()->fetch_all(MYSQLI_ASSOC);

        // Comparación de versiones
        if (isset($_POST['compare_versions'])) {
            $id1 = (int)($_POST['version1'] ?? $current_id);
            $id2 = (int)($_POST['version2'] ?? 0);
            if ($id1 && $id2 && $id1 != $id2) {
                $s1 = $mysqli->prepare("SELECT contenido, num_version FROM ai_backups WHERE id = ?");
                $s1->bind_param("i", $id1); $s1->execute(); $r1 = $s1->get_result()->fetch_assoc();
                $s2 = $mysqli->prepare("SELECT contenido, num_version FROM ai_backups WHERE id = ?");
                $s2->bind_param("i", $id2); $s2->execute(); $r2 = $s2->get_result()->fetch_assoc();

                if ($r1 && $r2) {
                    $lines1 = explode("\n", $r1['contenido']);
                    $lines2 = explode("\n", $r2['contenido']);
                    $diff_html = '<h5 class="mt-4">Comparación: v' . $r1['num_version'] . ' ←→ v' . $r2['num_version'] . '</h5>';
                    $diff_html .= '<div class="diff-container">';
                    $i = $j = 0;
                    while ($i < count($lines1) || $j < count($lines2)) {
                        if ($i < count($lines1) && $j < count($lines2) && $lines1[$i] === $lines2[$j]) {
                            $diff_html .= '<div class="line same">' . htmlspecialchars($lines1[$i]) . '</div>';
                            $i++; $j++;
                        } elseif ($i < count($lines1)) {
                            $diff_html .= '<div class="line removed">- ' . htmlspecialchars($lines1[$i]) . '</div>';
                            $i++;
                        } else {
                            $diff_html .= '<div class="line added">+ ' . htmlspecialchars($lines2[$j]) . '</div>';
                            $j++;
                        }
                    }
                    $diff_html .= '</div>';
                }
            }
        }
    }
}

// Listado con filtros y paginación
$pagina = max(1, (int)($_GET['pagina'] ?? 1));
$limit = 10;
$offset = ($pagina - 1) * $limit;

$f_proyecto = $_GET['f_proyecto'] ?? '';
$f_ia = $_GET['f_ia'] ?? '';
$f_tipo = $_GET['f_tipo'] ?? '';
$f_visible = $_GET['f_visible'] ?? 'todos';
$f_desde = $_GET['f_desde'] ?? '';
$f_hasta = $_GET['f_hasta'] ?? '';
$buscar = $_GET['buscar'] ?? '';

$where = [];
$types = '';
$params = [];

if ($f_proyecto) { $where[] = "proyecto LIKE ?"; $params[] = "%$f_proyecto%"; $types .= 's'; }
if ($f_ia) { $where[] = "ia_utilizada LIKE ?"; $params[] = "%$f_ia%"; $types .= 's'; }
if ($f_tipo) { $where[] = "tipo = ?"; $params[] = $f_tipo; $types .= 's'; }
if ($f_visible !== 'todos') { $where[] = "visible = ?"; $params[] = $f_visible; $types .= 's'; }
if ($f_desde) { $where[] = "fecha >= ?"; $params[] = $f_desde . ' 00:00:00'; $types .= 's'; }
if ($f_hasta) { $where[] = "fecha <= ?"; $params[] = $f_hasta . ' 23:59:59'; $types .= 's'; }
if ($buscar) {
    $where[] = "(contenido LIKE ? OR comentarios LIKE ?)";
    $params[] = "%$buscar%";
    $params[] = "%$buscar%";
    $types .= 'ss';
}

$where_sql = $where ? 'WHERE ' . implode(' AND ', $where) : '';

$count_stmt = $mysqli->prepare("SELECT COUNT(*) AS total FROM ai_backups $where_sql");
if ($types) $count_stmt->bind_param($types, ...$params);
$count_stmt->execute();
$total = $count_stmt->get_result()->fetch_assoc()['total'];
$total_paginas = ceil($total / $limit);

$list_stmt = $mysqli->prepare("SELECT * FROM ai_backups $where_sql ORDER BY fecha DESC, id DESC LIMIT ? OFFSET ?");
$list_types = $types . 'ii';
$list_params = array_merge($params, [$limit, $offset]);
$list_stmt->bind_param($list_types, ...$list_params);
$list_stmt->execute();
$registros = $list_stmt->get_result();

// Función para URLs de paginación
function pag_url($p) {
    $q = $_GET;
    $q['pagina'] = $p;
    return '?' . http_build_query($q);
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sistema de Respaldo de Prompts IA - Grok Edition</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/jquery@3.5.1/dist/jquery.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.1/dist/umd/popper.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.min.js"></script>
    <style>
        body { padding-top: 70px; }
        .diff-container { font-family: monospace; font-size: 0.9rem; background:#f8f9fa; border:1px solid #dee2e6; padding:15px; max-height:500px; overflow:auto; }
        .line { padding:2px 8px; margin:1px 0; white-space: pre-wrap; }
        .line.same { }
        .line.removed { background:#ffebee; color:#c62828; }
        .line.added { background:#e8f5e9; color:#2e7d32; }
        .navbar-brand { font-weight: bold; }
        .pre-content { white-space: pre-wrap; word-break: break-all; max-height: 500px; overflow: auto; }
        .lock-icon { color: #dc3545; }
    </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark fixed-top">
    <a class="navbar-brand" href="?">💾 Sistema de Respaldo de Prompts IA 
        <span class="text-info small">— Grok by xAI</span>
    </a>
    <div class="navbar-nav ml-auto">
        <?php if ($is_auth): ?>
            <span class="navbar-text text-success mr-3">
                <i class="fas fa-check-circle"></i> Master ON
            </span>
            <form method="post" class="form-inline">
                <input type="hidden" name="action" value="logout">
                <button type="submit" class="btn btn-outline-light btn-sm">Cerrar sesión</button>
            </form>
        <?php else: ?>
            <span class="navbar-text text-warning">Solo lectura</span>
        <?php endif; ?>
    </div>
</nav>

<div class="container">
    <?php if ($success): ?>
        <div class="alert alert-success alert-dismissible fade show mt-3"><?= htmlspecialchars($success) ?></div>
    <?php endif; ?>
    <?php if ($error): ?>
        <div class="alert alert-danger alert-dismissible fade show mt-3"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <!-- MENÚ -->
    <ul class="nav nav-pills mb-4">
        <li class="nav-item"><a class="nav-link <?= $accion==='list'?'active':'' ?>" href="?accion=list">📋 Ver registros</a></li>
        <?php if ($is_auth): ?>
            <li class="nav-item"><a class="nav-link <?= $accion==='agregar'?'active':'' ?>" href="?accion=agregar">➕ Agregar nuevo</a></li>
        <?php endif; ?>
        <li class="nav-item"><a class="nav-link" href="?accion=list&buscar=">🔍 Buscar / Filtros</a></li>
    </ul>

    <?php if ($accion === 'list' || $accion === ''): ?>
        <!-- FILTROS -->
        <form method="get" class="card mb-4 p-3">
            <input type="hidden" name="accion" value="list">
            <div class="row">
                <div class="col-md-3">
                    <input type="text" name="f_proyecto" class="form-control" placeholder="Proyecto" value="<?= htmlspecialchars($f_proyecto) ?>">
                </div>
                <div class="col-md-2">
                    <input type="text" name="f_ia" class="form-control" placeholder="IA" value="<?= htmlspecialchars($f_ia) ?>">
                </div>
                <div class="col-md-2">
                    <select name="f_tipo" class="form-control">
                        <option value="">Tipo</option>
                        <option value="prompt" <?= $f_tipo==='prompt'?'selected':'' ?>>prompt</option>
                        <option value="imagen" <?= $f_tipo==='imagen'?'selected':'' ?>>imagen</option>
                        <option value="idea" <?= $f_tipo==='idea'?'selected':'' ?>>idea</option>
                        <option value="respuesta" <?= $f_tipo==='respuesta'?'selected':'' ?>>respuesta</option>
                        <option value="codigo" <?= $f_tipo==='codigo'?'selected':'' ?>>codigo</option>
                        <option value="otro" <?= $f_tipo==='otro'?'selected':'' ?>>otro</option>
                    </select>
                </div>
                <div class="col-md-2">
                    <select name="f_visible" class="form-control">
                        <option value="todos" <?= $f_visible==='todos'?'selected':'' ?>>Visible: todos</option>
                        <option value="SI" <?= $f_visible==='SI'?'selected':'' ?>>SI</option>
                        <option value="NO" <?= $f_visible==='NO'?'selected':'' ?>>NO</option>
                    </select>
                </div>
                <div class="col-md-3">
                    <div class="input-group">
                        <input type="date" name="f_desde" class="form-control" value="<?= htmlspecialchars($f_desde) ?>">
                        <div class="input-group-prepend input-group-append"><span class="input-group-text">→</span></div>
                        <input type="date" name="f_hasta" class="form-control" value="<?= htmlspecialchars($f_hasta) ?>">
                    </div>
                </div>
            </div>
            <div class="row mt-3">
                <div class="col-md-8">
                    <input type="text" name="buscar" class="form-control" placeholder="Buscar en contenido o comentarios..." value="<?= htmlspecialchars($buscar) ?>">
                </div>
                <div class="col-md-4">
                    <button type="submit" class="btn btn-primary btn-block">Filtrar</button>
                    <a href="?accion=list" class="btn btn-secondary btn-block mt-1">Limpiar filtros</a>
                </div>
            </div>
        </form>

        <!-- TABLA -->
        <div class="table-responsive">
            <table class="table table-striped table-hover">
                <thead class="thead-dark">
                    <tr>
                        <th>Fecha</th>
                        <th>Proyecto</th>
                        <th>IA</th>
                        <th>Tipo</th>
                        <th>Versión</th>
                        <th>Calif.</th>
                        <th>Tamaño KB</th>
                        <th>Archivo</th>
                        <th>Visible</th>
                        <th>Acciones</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while ($row = $registros->fetch_assoc()): ?>
                    <tr>
                        <td><?= htmlspecialchars($row['fecha']) ?></td>
                        <td><?= htmlspecialchars($row['proyecto']) ?></td>
                        <td><?= htmlspecialchars($row['ia_utilizada']) ?></td>
                        <td><span class="badge badge-secondary"><?= htmlspecialchars($row['tipo']) ?></span></td>
                        <td><?= number_format($row['num_version'], 6) ?></td>
                        <td><?= $row['calificacion'] ? number_format($row['calificacion'], 1) : '-' ?></td>
                        <td><?= number_format($row['tamanio'], 2) ?></td>
                        <td><?= htmlspecialchars($row['nombre_archivo']) ?></td>
                        <td><?= $row['visible'] ?></td>
                        <td>
                            <?php if (!empty($row['contrasena_ver'])): ?>
                                <i class="fas fa-lock lock-icon"></i>
                            <?php endif; ?>
                            <a href="?accion=ver&id=<?= $row['id'] ?>" class="btn btn-info btn-sm">Ver</a>
                            <?php if ($is_auth): ?>
                                <a href="?accion=editar&id=<?= $row['id'] ?>" class="btn btn-warning btn-sm">Editar</a>
                                <a href="?accion=nueva_version&id=<?= $row['id'] ?>" class="btn btn-success btn-sm">+v</a>
                                <button onclick="confirmarBorrar(<?= $row['id'] ?>, '<?= addslashes($row['nombre_archivo']) ?> v<?= number_format($row['num_version'],6) ?>')" class="btn btn-danger btn-sm">Borrar</button>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </div>

        <!-- PAGINACIÓN -->
        <?php if ($total_paginas > 1): ?>
        <nav>
            <ul class="pagination justify-content-center">
                <?php for ($p=1; $p<=$total_paginas; $p++): ?>
                    <li class="page-item <?= $p==$pagina?'active':'' ?>">
                        <a class="page-link" href="<?= pag_url($p) ?>"><?= $p ?></a>
                    </li>
                <?php endfor; ?>
            </ul>
        </nav>
        <?php endif; ?>

    <?php endif; ?>

    <?php if ($accion === 'agregar' && $is_auth): ?>
        <!-- FORMULARIO AGREGAR / EDITAR -->
        <div class="card">
            <div class="card-header bg-primary text-white">
                <?= $form_id > 0 ? 'Editar registro #' . $form_id : 'Nuevo registro' ?>
            </div>
            <div class="card-body">
                <form method="post" enctype="multipart/form-data">
                    <input type="hidden" name="action" value="save">
                    <input type="hidden" name="id" value="<?= $form_id ?>">

                    <div class="form-row">
                        <div class="col-md-6">
                            <label>Proyecto</label>
                            <input type="text" name="proyecto" class="form-control" required value="<?= htmlspecialchars($form_data['proyecto']) ?>">
                        </div>
                        <div class="col-md-6">
                            <label>IA Utilizada</label>
                            <input type="text" name="ia_utilizada" list="ias" class="form-control" required value="<?= htmlspecialchars($form_data['ia_utilizada']) ?>">
                            <datalist id="ias">
                                <option value="Grok">
                                <option value="ChatGPT">
                                <option value="Claude">
                                <option value="Gemini">
                                <option value="Cohere">
                            </datalist>
                        </div>
                    </div>

                    <div class="form-row mt-3">
                        <div class="col-md-4">
                            <label>Tipo</label>
                            <select name="tipo" id="tipo_select" class="form-control" required onchange="toggleImageFields()">
                                <option value="prompt" <?= $form_data['tipo']==='prompt'?'selected':'' ?>>prompt</option>
                                <option value="imagen" <?= $form_data['tipo']==='imagen'?'selected':'' ?>>imagen</option>
                                <option value="idea" <?= $form_data['tipo']==='idea'?'selected':'' ?>>idea</option>
                                <option value="respuesta" <?= $form_data['tipo']==='respuesta'?'selected':'' ?>>respuesta</option>
                                <option value="codigo" <?= $form_data['tipo']==='codigo'?'selected':'' ?>>codigo</option>
                                <option value="otro" <?= $form_data['tipo']==='otro'?'selected':'' ?>>otro</option>
                            </select>
                        </div>
                        <div class="col-md-4">
                            <label>Nombre del archivo / prompt</label>
                            <input type="text" name="nombre_archivo" class="form-control" required value="<?= htmlspecialchars($form_data['nombre_archivo']) ?>">
                        </div>
                        <div class="col-md-4">
                            <label>Nº Versión</label>
                            <input type="text" name="num_version" class="form-control" required value="<?= htmlspecialchars($form_data['num_version']) ?>">
                            <small class="text-muted">Se auto-ajusta si dejas 1.000000</small>
                        </div>
                    </div>

                    <div class="form-group mt-3">
                        <label>Contenido</label>
                        <textarea name="contenido" class="form-control" rows="12"><?= htmlspecialchars($form_data['contenido']) ?></textarea>
                    </div>

                    <div id="image_fields" style="display:<?= $form_data['tipo']==='imagen'?'block':'none' ?>;">
                        <div class="form-group">
                            <label>Subir archivo de imagen (recomendado)</label>
                            <input type="file" name="imagen_file" class="form-control-file" accept="image/jpeg,image/png,image/gif,image/webp">
                        </div>
                        <div class="form-group">
                            <label>o pega data URI completo (data:image/...)</label>
                            <textarea name="base64_paste" class="form-control" rows="3" placeholder="data:image/png;base64,iVBORw0KGgo..."></textarea>
                        </div>
                    </div>

                    <div class="form-row">
                        <div class="col-md-6">
                            <label>Comentarios</label>
                            <textarea name="comentarios" class="form-control" rows="3"><?= htmlspecialchars($form_data['comentarios']) ?></textarea>
                        </div>
                        <div class="col-md-3">
                            <label>Calificación (0-10)</label>
                            <input type="number" step="0.1" name="calificacion" class="form-control" value="<?= htmlspecialchars($form_data['calificacion']) ?>">
                        </div>
                        <div class="col-md-3">
                            <label>Visible</label>
                            <select name="visible" class="form-control">
                                <option value="SI" <?= $form_data['visible']==='SI'?'selected':'' ?>>SI</option>
                                <option value="NO" <?= $form_data['visible']==='NO'?'selected':'' ?>>NO</option>
                            </select>
                        </div>
                    </div>

                    <div class="form-group mt-3">
                        <label>Contraseña de visualización (opcional - protege este registro)</label>
                        <input type="password" name="contrasena_ver" class="form-control" placeholder="Dejar vacío = sin protección">
                        <?php if ($form_id > 0 && !empty($record['contrasena_ver'])): ?>
                            <small class="text-muted">Actualmente tiene protección. Escribe nueva para cambiarla.</small>
                        <?php endif; ?>
                    </div>

                    <button type="submit" class="btn btn-success btn-lg">💾 Guardar registro</button>
                    <a href="?accion=list" class="btn btn-secondary btn-lg">Cancelar</a>
                </form>
            </div>
        </div>
    <?php endif; ?>

    <?php if ($accion === 'ver' && $record): ?>
        <div class="card">
            <div class="card-header">
                <strong><?= htmlspecialchars($record['nombre_archivo']) ?></strong> 
                v<?= number_format($record['num_version'], 6) ?> 
                — <?= htmlspecialchars($record['proyecto']) ?>
            </div>
            <div class="card-body">
                <?php if (!$show_content): ?>
                    <div class="alert alert-warning">
                        <h5>Este registro está protegido con contraseña</h5>
                        <?php if ($ver_error): ?><div class="alert alert-danger"><?= htmlspecialchars($ver_error) ?></div><?php endif; ?>
                        <form method="post">
                            <input type="password" name="ver_pass" class="form-control" placeholder="Contraseña de visualización" required>
                            <button type="submit" class="btn btn-primary mt-2">Desbloquear</button>
                        </form>
                    </div>
                <?php else: ?>
                    <dl class="row">
                        <dt class="col-sm-3">Fecha</dt><dd class="col-sm-9"><?= htmlspecialchars($record['fecha']) ?></dd>
                        <dt class="col-sm-3">IA</dt><dd class="col-sm-9"><?= htmlspecialchars($record['ia_utilizada']) ?></dd>
                        <dt class="col-sm-3">Tipo</dt><dd class="col-sm-9"><?= htmlspecialchars($record['tipo']) ?></dd>
                        <dt class="col-sm-3">Calificación</dt><dd class="col-sm-9"><?= $record['calificacion'] ? number_format($record['calificacion'],1) : '—' ?></dd>
                        <dt class="col-sm-3">Tamaño</dt><dd class="col-sm-9"><?= number_format($record['tamanio'], 2) ?> KB</dd>
                        <dt class="col-sm-3">MD5</dt><dd class="col-sm-9 font-monospace"><?= $record['hash_md5'] ?></dd>
                        <dt class="col-sm-3">SHA1</dt><dd class="col-sm-9 font-monospace"><?= $record['hash_sha1'] ?></dd>
                    </dl>

                    <h5>Contenido</h5>
                    <?php if ($record['tipo'] === 'imagen'): ?>
                        <?php if (strpos($record['contenido'], 'data:image/') === 0): ?>
                            <img src="<?= htmlspecialchars($record['contenido']) ?>" class="img-fluid border" alt="Imagen guardada">
                        <?php else: ?>
                            <div class="alert alert-danger">Datos de imagen inválidos</div>
                        <?php endif; ?>
                    <?php else: ?>
                        <pre class="pre-content border p-3 bg-light"><?= htmlspecialchars($record['contenido']) ?></pre>
                    <?php endif; ?>

                    <?php if ($record['comentarios']): ?>
                        <h5 class="mt-4">Comentarios</h5>
                        <pre class="pre-content border p-3 bg-light"><?= htmlspecialchars($record['comentarios']) ?></pre>
                    <?php endif; ?>
                <?php endif; ?>
            </div>

            <!-- OTRAS VERSIONES -->
            <?php if ($other_versions): ?>
            <div class="card-footer">
                <h6>Otras versiones del mismo proyecto/archivo</h6>
                <form method="post">
                    <input type="hidden" name="compare_versions" value="1">
                    <div class="form-row">
                        <div class="col">
                            <select name="version1" class="form-control">
                                <option value="<?= $record['id'] ?>">Actual (v<?= number_format($record['num_version'],6) ?>)</option>
                                <?php foreach ($other_versions as $v): ?>
                                <option value="<?= $v['id'] ?>">v<?= number_format($v['num_version'],6) ?> — <?= $v['fecha'] ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="col">
                            <select name="version2" class="form-control">
                                <?php foreach ($other_versions as $v): ?>
                                <option value="<?= $v['id'] ?>">v<?= number_format($v['num_version'],6) ?> — <?= $v['fecha'] ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="col-auto">
                            <button type="submit" class="btn btn-outline-info">Comparar versiones</button>
                        </div>
                    </div>
                </form>

                <?php if ($diff_html): echo $diff_html; endif; ?>
            </div>
            <?php endif; ?>
        </div>
        <a href="?accion=list" class="btn btn-secondary mt-3">← Volver al listado</a>
    <?php endif; ?>

    <!-- FOOTER FIJO -->
    <footer class="text-center text-muted small mt-5 mb-4">
        ⚠️ Este sistema NO hace respaldo de su propia base de datos. Respaldar MySQL es tu responsabilidad. 
        Un respaldo que no existe no es un respaldo.<br>
        <span class="text-info">Grok Edition • Single file • PHP 8 + Bootstrap 4.6</span>
    </footer>
</div>

<!-- MODAL CONFIRMAR BORRADO -->
<div class="modal fade" id="modalBorrar" tabindex="-1">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header bg-danger text-white">
                <h5 class="modal-title">Confirmar borrado</h5>
            </div>
            <div class="modal-body">
                <p>¿Estás seguro de borrar <strong id="modalNombre"></strong>?</p>
                <p class="text-danger">Esta acción NO se puede deshacer.</p>
                <div class="form-group">
                    <label>Escribe <strong>BORRAR</strong> para confirmar</label>
                    <input type="text" id="confirmInput" class="form-control" placeholder="BORRAR">
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-dismiss="modal">Cancelar</button>
                <form method="post" id="formBorrar">
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="id" id="modalId">
                    <input type="hidden" name="confirm_borrar" id="modalConfirm">
                    <button type="submit" class="btn btn-danger" onclick="return validarBorrar()">Borrar permanentemente</button>
                </form>
            </div>
        </div>
    </div>
</div>

<script>
function toggleImageFields() {
    const tipo = document.getElementById('tipo_select').value;
    document.getElementById('image_fields').style.display = (tipo === 'imagen') ? 'block' : 'none';
}

function confirmarBorrar(id, nombre) {
    document.getElementById('modalId').value = id;
    document.getElementById('modalNombre').innerHTML = nombre;
    $('#modalBorrar').modal('show');
}

function validarBorrar() {
    const val = document.getElementById('confirmInput').value.trim().toUpperCase();
    if (val === 'BORRAR') {
        document.getElementById('modalConfirm').value = 'BORRAR';
        return true;
    } else {
        alert('Debes escribir exactamente BORRAR');
        return false;
    }
}

// Auto-focus en modal
$('#modalBorrar').on('shown.bs.modal', function () {
    document.getElementById('confirmInput').focus();
});
</script>
</body>
</html>

<?php
// =====================================================
// Sistema de Respaldo de Prompts IA - UN SOLO ARCHIVO
// PHP 8.x Procedural - MySQL/MariaDB - Bootstrap 4.6
// Creado para Alfonso Orozco Aguilar - 23 Feb 2026
// =====================================================

// --- CONFIGURACIÓN - EDITA ESTO ANTES DE USAR ---
define('PASS_MAESTRA', 'admin123'); // Contraseña maestra para agregar/editar/borrar
define('IPS_PERMITIDAS', ['127.0.0.1', '::1', 'TU_IP_AQUI']); // Agrega tus IPs
define('TBL_NAME', 'ai_backups');

// Headers anti-caché
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: Sat, 01 Jan 2000 00:00:00 GMT');

// Iniciar sesión
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Conexión DB
$host = 'localhost';
$user = 'root';
$pass = '';
$dbname = 'ai_backups_db';

$conn = new mysqli($host, $user, $pass, $dbname);
if ($conn->connect_error) {
    die("Error de conexión: " . $conn->connect_error);
}
$conn->set_charset("utf8mb4");

// Crear tabla si no existe
$create_table = "
CREATE TABLE IF NOT EXISTS `".TBL_NAME."` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `proyecto` varchar(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `ia_utilizada` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL,
  `tipo` varchar(20) COLLATE utf8mb4_unicode_ci NOT NULL,
  `contenido` longtext COLLATE utf8mb4_unicode_ci NOT NULL,
  `nombre_archivo` varchar(150) COLLATE utf8mb4_unicode_ci NOT NULL,
  `num_version` decimal(14,6) NOT NULL,
  `comentarios` longtext COLLATE utf8mb4_unicode_ci,
  `calificacion` decimal(14,6) DEFAULT NULL,
  `visible` varchar(2) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'SI',
  `fecha` datetime NOT NULL,
  `contrasena_ver` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `tamanio` decimal(14,6) DEFAULT NULL,
  `hash_md5` varchar(32) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `hash_sha1` varchar(40) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `proyecto` (`proyecto`),
  KEY `nombre_archivo` (`nombre_archivo`),
  KEY `visible` (`visible`),
  KEY `fecha` (`fecha`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
";
$conn->query($create_table);

// Verificar IP
$user_ip = $_SERVER['REMOTE_ADDR'];
if (!in_array($user_ip, IPS_PERMITIDAS) && !in_array('', IPS_PERMITIDAS)) {
    die('<h1>Acceso no autorizado</h1><p>Su IP no está permitida.</p>');
}

// Funciones auxiliares
function calcularHashYTamano($contenido) {
    $tamanio = strlen($contenido) / 1024; // KB
    $hash_md5 = md5($contenido);
    $hash_sha1 = sha1($contenido);
    return [$tamanio, $hash_md5, $hash_sha1];
}

function validarBase64Imagen($base64) {
    $cabeceras_validas = ['/9j/', 'iVBORw0KGgoAAAANSUhEUg', 'R0lGODlh', 'UklGR'];
    foreach ($cabeceras_validas as $cabecera) {
        if (strpos($base64, $cabecera) === 0) {
            return true;
        }
    }
    return false;
}

function mostrarDiff($texto1, $texto2) {
    $lineas1 = explode("\n", $texto1);
    $lineas2 = explode("\n", $texto2);
    
    $diff = '';
    $max_lineas = max(count($lineas1), count($lineas2));
    
    for ($i = 0; $i < $max_lineas; $i++) {
        $linea1 = isset($lineas1[$i]) ? trim($lineas1[$i]) : '';
        $linea2 = isset($lineas2[$i]) ? trim($lineas2[$i]) : '';
        
        if ($linea1 === $linea2) {
            $diff .= "<div class='diff-line same'>{$linea1}</div>";
        } elseif ($linea1 && !$linea2) {
            $diff .= "<div class='diff-line delete'>- {$linea1}</div>";
        } elseif (!$linea1 && $linea2) {
            $diff .= "<div class='diff-line add'>+ {$linea2}</div>";
        } else {
            $diff .= "<div class='diff-line delete'>- {$linea1}</div>";
            $diff .= "<div class='diff-line add'>+ {$linea2}</div>";
        }
    }
    return $diff;
}

// Procesar acciones
$accion = $_GET['accion'] ?? '';
$id_edit = $_GET['id'] ?? 0;
$msg = '';

// Verificar POST vacío (límite servidor)
if ($_POST && empty($_POST['proyecto']) && !empty($_POST)) {
    $msg = '<div class="alert alert-warning">⚠️ POST vacío. Revisa post_max_size del servidor (php.ini). Máximo recomendado: 50M para imágenes grandes.</div>';
}

if ($_POST && isset($_POST['confirmar_borrar']) && $_POST['confirmar_borrar'] === 'BORRAR') {
    if (!isset($_SESSION['autenticada']) || $_SESSION['autenticada'] !== true) {
        $msg = '<div class="alert alert-danger">Requiere contraseña maestra.</div>';
    } else {
        $stmt = $conn->prepare("DELETE FROM ".TBL_NAME." WHERE id = ?");
        $stmt->bind_param("i", $_POST['id_borrar']);
        if ($stmt->execute()) {
            $msg = '<div class="alert alert-success">Registro borrado.</div>';
        }
        $stmt->close();
    }
}

if ($_POST && (isset($_POST['guardar']) || isset($_POST['nueva_version']))) {
    if (!isset($_SESSION['autenticada']) || $_SESSION['autenticada'] !== true) {
        $msg = '<div class="alert alert-danger">Requiere contraseña maestra.</div>';
    } else {
        $proyecto = trim($_POST['proyecto']);
        $ia = trim($_POST['ia_utilizada']);
        $tipo = trim($_POST['tipo']);
        $contenido = trim($_POST['contenido']);
        $nombre_archivo = trim($_POST['nombre_archivo']);
        $num_version = floatval($_POST['num_version']);
        $comentarios = trim($_POST['comentarios']);
        $calificacion = floatval($_POST['calificacion']);
        $visible = $_POST['visible'] ?? 'SI';
        
        // Contraseña individual
        $contrasena_ver = '';
        if (!empty($_POST['contrasena_ver'])) {
            $contrasena_ver = password_hash($_POST['contrasena_ver'], PASSWORD_DEFAULT);
        }
        
        // Imagen: convertir archivo a base64 si existe
        if ($tipo === 'imagen' && isset($_FILES['imagen_file']) && $_FILES['imagen_file']['error'] === UPLOAD_ERR_OK) {
            $imagen_data = file_get_contents($_FILES['imagen_file']['tmp_name']);
            if (validarBase64Imagen(base64_encode($imagen_data))) {
                $contenido = base64_encode($imagen_data);
            }
        }
        
        // Calcular hashes y tamaño
        list($tamanio, $hash_md5, $hash_sha1) = calcularHashYTamano($contenido);
        
        if (isset($_POST['nueva_version']) && $id_edit) {
            // Obtener versión anterior para incrementar
            $stmt_ver = $conn->prepare("SELECT num_version FROM ".TBL_NAME." WHERE id = ?");
            $stmt_ver->bind_param("i", $id_edit);
            $stmt_ver->execute();
            $result_ver = $stmt_ver->get_result()->fetch_assoc();
            $num_version = $result_ver['num_version'] + 1.000000;
            $stmt_ver->close();
        }
        
        $fecha = date('Y-m-d H:i:s');
        
        if ($id_edit) {
            // UPDATE
            $stmt = $conn->prepare("UPDATE ".TBL_NAME." SET proyecto=?, ia_utilizada=?, tipo=?, contenido=?, nombre_archivo=?, num_version=?, comentarios=?, calificacion=?, visible=?, contrasena_ver=?, tamanio=?, hash_md5=?, hash_sha1=?, fecha=? WHERE id=?");
            $stmt->bind_param("sssssdssississi", $proyecto, $ia, $tipo, $contenido, $nombre_archivo, $num_version, $comentarios, $calificacion, $visible, $contrasena_ver, $tamanio, $hash_md5, $hash_sha1, $fecha, $id_edit);
        } else {
            // INSERT
            $stmt = $conn->prepare("INSERT INTO ".TBL_NAME." (proyecto, ia_utilizada, tipo, contenido, nombre_archivo, num_version, comentarios, calificacion, visible, fecha, contrasena_ver, tamanio, hash_md5, hash_sha1) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->bind_param("sssssdssissss", $proyecto, $ia, $tipo, $contenido, $nombre_archivo, $num_version, $comentarios, $calificacion, $visible, $fecha, $contrasena_ver, $tamanio, $hash_md5, $hash_sha1);
        }
        
        if ($stmt->execute()) {
            $msg = '<div class="alert alert-success">Guardado correctamente.</div>';
            $id_edit = $conn->insert_id;
        } else {
            $msg = '<div class="alert alert-danger">Error al guardar: ' . $stmt->error . '</div>';
        }
        $stmt->close();
    }
}

// Autenticación maestra
if (isset($_POST['pass_maestra'])) {
    if (password_verify($_POST['pass_maestra'], PASS_MAESTRA) || $_POST['pass_maestra'] === PASS_MAESTRA) {
        $_SESSION['autenticada'] = true;
        $msg = '<div class="alert alert-success">Autenticado como administrador.</div>';
    } else {
        $msg = '<div class="alert alert-danger">Contraseña maestra incorrecta.</div>';
    }
}

// Ver registro específico (con contraseña individual)
$registro_ver = null;
$pass_registro_ok = false;
if ($accion === 'ver' && $id_edit) {
    $stmt = $conn->prepare("SELECT * FROM ".TBL_NAME." WHERE id = ?");
    $stmt->bind_param("i", $id_edit);
    $stmt->execute();
    $result = $stmt->get_result();
    $registro_ver = $result->fetch_assoc();
    $stmt->close();
    
    if ($registro_ver && $registro_ver['contrasena_ver']) {
        if (isset($_POST['pass_registro_' . $id_edit]) && password_verify($_POST['pass_registro_' . $id_edit], $registro_ver['contrasena_ver'])) {
            $pass_registro_ok = true;
        }
    } else {
        $pass_registro_ok = true;
    }
}

// Búsqueda y filtros
$where = "WHERE visible = 'SI'";
$params = [];
$types = "";

$page = max(1, intval($_GET['page'] ?? 1));
$limit = 10;
$offset = ($page - 1) * $limit;

if (!empty($_GET['proyecto'])) {
    $where .= " AND proyecto LIKE ?";
    $params[] = "%{$_GET['proyecto']}%";
    $types .= "s";
}
if (!empty($_GET['ia'])) {
    $where .= " AND ia_utilizada = ?";
    $params[] = $_GET['ia'];
    $types .= "s";
}
if (!empty($_GET['tipo'])) {
    $where .= " AND tipo = ?";
    $params[] = $_GET['tipo'];
    $types .= "s";
}
if ($_GET['visible'] ?? '' === 'NO') {
    $where = "WHERE visible = 'NO'";
}
if (isset($_GET['visible']) && $_GET['visible'] === 'TODOS') {
    $where = "";
}

// Obtener registros
$stmt = $conn->prepare("SELECT * FROM ".TBL_NAME." $where ORDER BY fecha DESC LIMIT ? OFFSET ?");
$params[] = $limit;
$params[] = $offset;
$types .= "ii";
$stmt->bind_param($types, ...$params);
$stmt->execute();
$resultados = $stmt->get_result();
$registros = [];
while ($row = $resultados->fetch_assoc()) {
    $registros[] = $row;
}
$stmt->close();

// Contar total para paginación
$count_stmt = $conn->prepare("SELECT COUNT(*) as total FROM ".TBL_NAME." $where");
$count_stmt->bind_param(substr($types, 0, -2)); // Sin los últimos "ii"
if (count($params) > 2) {
    array_pop($params);
    array_pop($params);
    $count_stmt->bind_param(substr($types, 0, -2), ...$params);
}
$count_stmt->execute();
$total_registros = $count_stmt->get_result()->fetch_assoc()['total'];
$total_paginas = ceil($total_registros / $limit);
$count_stmt->close();

// Opciones para filtros
$ias = ['ChatGPT', 'Claude', 'Gemini', 'Grok', 'Cohere', 'otro'];
$tipos = ['prompt', 'imagen', 'idea', 'respuesta', 'codigo', 'otro'];

// Para formulario de edición/nuevo
$registro_edit = null;
if ($id_edit && ($accion === 'editar' || $accion === 'nueva_version')) {
    $stmt = $conn->prepare("SELECT * FROM ".TBL_NAME." WHERE id = ?");
    $stmt->bind_param("i", $id_edit);
    $stmt->execute();
    $registro_edit = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    
    if ($accion === 'nueva_version' && $registro_edit) {
        $registro_edit['num_version'] += 1.000000;
        $registro_edit['contenido'] = '';
    }
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sistema de Respaldo IA</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css" rel="stylesheet">
    <style>
        .diff-line { padding: 2px 8px; margin: 1px 0; border-radius: 3px; font-family: monospace; font-size: 13px; }
        .diff-line.same { background: #f8f9fa; }
        .diff-line.delete { background: #ffeef0; }
        .diff-line.add { background: #e6ffe6; }
        .navbar-brand { font-weight: bold; }
        .sticky-top { z-index: 1020; }
        pre { white-space: pre-wrap; word-wrap: break-word; }
        .candado { color: #ffc107; }
    </style>
</head>
<body>
    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary sticky-top">
        <div class="container">
            <a class="navbar-brand" href="#"><i class="fas fa-database"></i> Respaldo IA</a>
            <span class="navbar-text">
                <?php if (isset($_SESSION['autenticada']) && $_SESSION['autenticada']): ?>
                    <span class="badge badge-success"><i class="fas fa-unlock"></i> ADMIN</span>
                <?php else: ?>
                    <span class="badge badge-secondary"><i class="fas fa-lock"></i> LECTURA</span>
                <?php endif; ?>
            </span>
        </div>
    </nav>

    <div class="container mt-4">
        <?php if ($msg): echo $msg; endif; ?>

        <?php if ($accion === 'ver' && $registro_ver && !$pass_registro_ok && $registro_ver['contrasena_ver']): ?>
            <!-- Pedir contraseña registro -->
            <div class="card">
                <div class="card-header"><i class="fas fa-key"></i> Registro Protegido</div>
                <div class="card-body">
                    <form method="POST">
                        <div class="form-group">
                            <label>Contraseña del registro:</label>
                            <input type="password" name="pass_registro_<?php echo $id_edit; ?>" class="form-control" required>
                            <input type="hidden" name="id" value="<?php echo $id_edit; ?>">
                        </div>
                        <button class="btn btn-primary"><i class="fas fa-eye"></i> Ver Registro</button>
                    </form>
                </div>
            </div>

        <?php elseif ($accion === 'ver' && $registro_ver && $pass_registro_ok): ?>
            <!-- Ver registro completo -->
            <div class="card">
                <div class="card-header">
                    <h5><?php echo htmlspecialchars($registro_ver['nombre_archivo']); ?> v<?php echo number_format($registro_ver['num_version'], 6); ?></h5>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-6">
                            <table class="table table-sm">
                                <tr><td>Proyecto:</td><td><?php echo htmlspecialchars($registro_ver['proyecto']); ?></td></tr>
                                <tr><td>IA:</td><td><?php echo htmlspecialchars($registro_ver['ia_utilizada']); ?></td></tr>
                                <tr><td>Tipo:</td><td><?php echo htmlspecialchars($registro_ver['tipo']); ?></td></tr>
                                <tr><td>Fecha:</td><td><?php echo $registro_ver['fecha']; ?></td></tr>
                                <tr><td>Calificación:</td><td><?php echo $registro_ver['calificacion']; ?></td></tr>
                                <tr><td>Tamaño:</td><td><?php echo number_format($registro_ver['tamanio'], 2); ?> KB</td></tr>
                                <tr><td>Visible:</td><td><?php echo $registro_ver['visible']; ?></td></tr>
                                <tr><td>MD5:</td><td><?php echo $registro_ver['hash_md5']; ?></td></tr>
                                <tr><td>SHA1:</td><td><?php echo $registro_ver['hash_sha1']; ?></td></tr>
                            </table>
                        </div>
                        <div class="col-md-6">
                            <?php if ($registro_ver['tipo'] === 'imagen' && validarBase64Imagen($registro_ver['contenido'])): ?>
                                <img src="data:image/png;base64,<?php echo htmlspecialchars($registro_ver['contenido']); ?>" class="img-fluid" style="max-height: 400px;">
                            <?php else: ?>
                                <textarea class="form-control" rows="15" readonly><?php echo htmlspecialchars($registro_ver['contenido']); ?></textarea>
                            <?php endif; ?>
                            <small class="text-muted"><?php echo htmlspecialchars($registro_ver['comentarios']); ?></small>
                        </div>
                    </div>
                </div>
            </div>

        <?php elseif (($accion === 'editar' || $accion === 'nueva_version' || $accion === 'agregar') && isset($_SESSION['autenticada']) && $_SESSION['autenticada']): ?>
            <!-- Formulario agregar/editar -->
            <div class="card">
                <div class="card-header">
                    <h5><?php echo $accion === 'nueva_version' ? 'Nueva Versión' : ($accion === 'editar' ? 'Editar' : 'Agregar Nuevo'); ?></h5>
                </div>
                <div class="card-body">
                    <form method="POST" enctype="multipart/form-data">
                        <div class="row">
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label>Proyecto <span class="text-danger">*</span></label>
                                    <input type="text" name="proyecto" class="form-control" value="<?php echo htmlspecialchars($registro_edit['proyecto'] ?? ''); ?>" required>
                                </div>
                                <div class="form-group">
                                    <label>IA Utilizada</label>
                                    <select name="ia_utilizada" class="form-control">
                                        <?php foreach ($ias as $ia_opt): ?>
                                            <option <?php echo ($registro_edit['ia_utilizada'] ?? '') === $ia_opt ? 'selected' : ''; ?>><?php echo $ia_opt; ?></option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label>Tipo <span class="text-danger">*</span></label>
                                    <select name="tipo" class="form-control" id="tipo_select" onchange="toggleImagen()">
                                        <?php foreach ($tipos as $tipo_opt): ?>
                                            <option <?php echo ($registro_edit['tipo'] ?? '') === $tipo_opt ? 'selected' : ''; ?>><?php echo $tipo_opt; ?></option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label>Nombre Archivo <span class="text-danger">*</span></label>
                                    <input type="text" name="nombre_archivo" class="form-control" value="<?php echo htmlspecialchars($registro_edit['nombre_archivo'] ?? ''); ?>" required>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label>Versión</label>
                                    <input type="number" name="num_version" class="form-control" step="0.000001" value="<?php echo htmlspecialchars($registro_edit['num_version'] ?? '1.000000'); ?>">
                                </div>
                                <div class="form-group">
                                    <label>Calificación (0-10)</label>
                                    <input type="number" name="calificacion" class="form-control" min="0" max="10" step="0.1" value="<?php echo htmlspecialchars($registro_edit['calificacion'] ?? ''); ?>">
                                </div>
                                <div class="form-group">
                                    <label>Visible</label>
                                    <select name="visible" class="form-control">
                                        <option value="SI" <?php echo ($registro_edit['visible'] ?? 'SI') === 'SI' ? 'selected' : ''; ?>>SI</option>
                                        <option value="NO" <?php echo ($registro_edit['visible'] ?? '') === 'NO' ? 'selected' : ''; ?>>NO</option>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label>Contraseña Individual (opcional)</label>
                                    <input type="password" name="contrasena_ver" class="form-control" placeholder="Proteger este registro">
                                </div>
                            </div>
                        </div>
                        <div class="form-group">
                            <label>Contenido <span class="text-danger">*</span></label>
                            <?php if (($registro_edit['tipo'] ?? '') === 'imagen'): ?>
                                <textarea name="contenido" class="form-control" rows="8" placeholder="Pegar base64 aquí"><?php echo htmlspecialchars($registro_edit['contenido'] ?? ''); ?></textarea>
                                <div class="mt-2">
                                    <label>O subir imagen:</label>
                                    <input type="file" name="imagen_file" class="form-control" accept="image/*">
                                </div>
                            <?php else: ?>
                                <textarea name="contenido" class="form-control" rows="12" placeholder="Contenido del prompt/respuesta"><?php echo htmlspecialchars($registro_edit['contenido'] ?? ''); ?></textarea>
                            <?php endif; ?>
                        </div>
                        <div class="form-group">
                            <label>Comentarios</label>
                            <textarea name="comentarios" class="form-control" rows="3"><?php echo htmlspecialchars($registro_edit['comentarios'] ?? ''); ?></textarea>
                        </div>
                        <input type="hidden" name="id" value="<?php echo $id_edit; ?>">
                        <?php if ($accion === 'nueva_version'): ?>
                            <input type="hidden" name="nueva_version" value="1">
                        <?php endif; ?>
                        <button type="submit" name="guardar" class="btn btn-success"><i class="fas fa-save"></i> Guardar</button>
                        <a href="?page=<?php echo $page; ?>" class="btn btn-secondary">Cancelar</a>
                    </form>
                </div>
            </div>

        <?php else: ?>
            <!-- Listado principal con filtros -->
            <div class="row">
                <div class="col-md-9">
                    <h3><i class="fas fa-list"></i> Registros (Página <?php echo $page; ?> de <?php echo $total_paginas; ?>)</h3>
                    
                    <!-- Filtros -->
                    <form method="GET" class="mb-4">
                        <input type="hidden" name="accion" value="">
                        <div class="row">
                            <div class="col-md-3">
                                <input type="text" name="proyecto" class="form-control" placeholder="Proyecto" value="<?php echo htmlspecialchars($_GET['proyecto'] ?? ''); ?>">
                            </div>
                            <div class="col-md-2">
                                <select name="ia" class="form-control">
                                    <option value="">Todas las IA</option>
                                    <?php foreach ($ias as $ia_opt): ?>
                                        <option <?php echo ($_GET['ia'] ?? '') === $ia_opt ? 'selected' : ''; ?>><?php echo $ia_opt; ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                            <div class="col-md-2">
                                <select name="tipo" class="form-control">
                                    <option value="">Todos los tipos</option>
                                    <?php foreach ($tipos as $tipo_opt): ?>
                                        <option <?php echo ($_GET['tipo'] ?? '') === $tipo_opt ? 'selected' : ''; ?>><?php echo $tipo_opt; ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                            <div class="col-md-2">
                                <select name="visible" class="form-control">
                                    <option value="">Visible: SI</option>
                                    <option value="NO" <?php echo ($_GET['visible'] ?? '') === 'NO' ? 'selected' : ''; ?>>NO</option>
                                    <option value="TODOS" <?php echo ($_GET['visible'] ?? '') === 'TODOS' ? 'selected' : ''; ?>>TODOS</option>
                                </select>
                            </div>
                            <div class="col-md-3">
                                <button class="btn btn-primary btn-block"><i class="fas fa-search"></i> Filtrar</button>
                            </div>
                        </div>
                    </form>

                    <!-- Tabla registros -->
                    <div class="table-responsive">
                        <table class="table table-hover table-sm">
                            <thead class="thead-dark">
                                <tr>
                                    <th>Fecha</th>
                                    <th>Proyecto</th>
                                    <th>IA</th>
                                    <th>Tipo</th>
                                    <th>Versión</th>
                                    <th>Calif.</th>
                                    <th>Tamaño</th>
                                    <th>Archivo</th>
                                    <th>Visible</th>
                                    <th>Acciones</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($registros as $reg): ?>
                                    <tr>
                                        <td><?php echo date('d/m H:i', strtotime($reg['fecha'])); ?></td>
                                        <td><?php echo htmlspecialchars(substr($reg['proyecto'], 0, 30)); ?></td>
                                        <td><?php echo htmlspecialchars($reg['ia_utilizada']); ?></td>
                                        <td><?php echo htmlspecialchars($reg['tipo']); ?></td>
                                        <td><?php echo number_format($reg['num_version'], 3); ?></td>
                                        <td><?php echo $reg['calificacion']; ?></td>
                                        <td><?php echo number_format($reg['tamanio'], 1); ?>K</td>
                                        <td><?php echo htmlspecialchars(substr($reg['nombre_archivo'], 0, 25)); ?></td>
                                        <td>
                                            <?php echo $reg['visible']; ?>
                                            <?php if ($reg['contrasena_ver']): ?><i class="fas fa-lock candado" title="Protegido"></i><?php endif; ?>
                                        </td>
                                        <td>
                                            <a href="?accion=ver&id=<?php echo $reg['id']; ?>" class="btn btn-sm btn-outline-primary"><i class="fas fa-eye"></i></a>
                                            <?php if (isset($_SESSION['autenticada']) && $_SESSION['autenticada']): ?>
                                                <a href="?accion=editar&id=<?php echo $reg['id']; ?>" class="btn btn-sm btn-outline-warning"><i class="fas fa-edit"></i></a>
                                                <button class="btn btn-sm btn-outline-danger" onclick="confirmarBorrar(<?php echo $reg['id']; ?>, '<?php echo addslashes($reg['nombre_archivo']); ?>', <?php echo $reg['num_version']; ?>)"><i class="fas fa-trash"></i></button>
                                                <a href="?accion=nueva_version&id=<?php echo $reg['id']; ?>" class="btn btn-sm btn-outline-info"><i class="fas fa-plus"></i></a>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>

                    <!-- Paginación -->
                    <?php if ($total_paginas > 1): ?>
                        <nav>
                            <ul class="pagination justify-content-center">
                                <?php for ($i = 1; $i <= $total_paginas; $i++): ?>
                                    <li class="page-item <?php echo $page == $i ? 'active' : ''; ?>">
                                        <a class="page-link" href="?page=<?php echo $i; ?>&<?php echo http_build_query($_GET, '', '&', PHP_QUERY_RFC3986); ?>"><?php echo $i; ?></a>
                                    </li>
                                <?php endfor; ?>
                            </ul>
                        </nav>
                    <?php endif; ?>
                </div>

                <div class="col-md-3">
                    <!-- Panel de acciones rápidas -->
                    <div class="card">
                        <div class="card-header">Acciones</div>
                        <div class="card-body">
                            <?php if (!isset($_SESSION['autenticada']) || !$_SESSION['autenticada']): ?>
                                <form method="POST" class="mb-3">
                                    <div class="input-group input-group-sm">
                                        <input type="password" name="pass_maestra" class="form-control" placeholder="Contraseña maestra" required>
                                        <div class="input-group-append">
                                            <button class="btn btn-primary"><i class="fas fa-unlock"></i></button>
                                        </div>
                                    </div>
                                </form>
                            <?php endif; ?>
                            
                            <?php if (isset($_SESSION['autenticada']) && $_SESSION['autenticada']): ?>
                                <a href="?accion=agregar" class="btn btn-success btn-block btn-sm mb-2"><i class="fas fa-plus"></i> Nuevo</a>
                                <a href="?accion=cerrar" class="btn btn-warning btn-block btn-sm mb-2" onclick="return confirm('¿Cerrar sesión de admin?')"><i class="fas fa-sign-out-alt"></i> Cerrar</a>
                            <?php endif; ?>
                            
                            <a href="?visible=TODOS" class="btn btn-info btn-block btn-sm">Ver Ocultos</a>
                        </div>
                    </div>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <!-- Modal Confirmar Borrar -->
    <div class="modal fade" id="modalBorrar" tabindex="-1">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header bg-danger text-white">
                    <h5 class="modal-title"><i class="fas fa-exclamation-triangle"></i> ¡CONFIRMAR BORRADO!</h5>
                </div>
                <div class="modal-body">
                    <p class="font-weight-bold text-danger">¿Estás SEGURO de borrar <span id="nombre_borrar"></span> versión <span id="version_borrar"></span>?</p>
                    <p class="text-warning">Esta acción NO se puede deshacer.</p>
                    <div class="input-group">
                        <input type="text" id="confirmar_texto" class="form-control" placeholder="Escribe BORRAR en mayúsculas">
                        <div class="input-group-append">
                            <span class="input-group-text"><strong>BORRAR</strong></span>
                        </div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-dismiss="modal">Cancelar</button>
                    <form id="form_borrar" method="POST" style="display: inline;">
                        <input type="hidden" name="id_borrar" id="id_borrar">
                        <input type="hidden" name="confirmar_borrar" value="">
                        <button type="submit" class="btn btn-danger" id="btn_confirmar" disabled>¡BORRAR!</button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <footer class="mt-5 pt-4 border-top text-center">
        <p class="text-muted small">
            ⚠️ Este sistema NO hace respaldo de su propia base de datos. 
            <strong>Respaldar MySQL es tu responsabilidad.</strong> 
            Un respaldo que no existe no es un respaldo.
        </p>
        <p class="text-muted small">PHP 8.x | MySQL | Bootstrap 4.6 | Creado 2026</p>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/jquery@3.5.1/dist/jquery.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        function confirmarBorrar(id, nombre, version) {
            $('#nombre_borrar').text(nombre);
            $('#version_borrar').text(version);
            $('#id_borrar').val(id);
            $('#confirmar_texto').val('');
            $('#btn_confirmar').prop('disabled', true);
            $('#modalBorrar').modal('show');
        }

        $('#confirmar_texto').on('input', function() {
            $('#btn_confirmar').prop('disabled', $(this).val() !== 'BORRAR');
            $('input[name="confirmar_borrar"]').val($(this).val());
        });

        function toggleImagen() {
            const tipo = $('#tipo_select').val();
            // Aquí podrías alternar entre textarea y input file si quieres más UX
        }
    </script>
</body>
</html>
<?php
$conn->close();
?>

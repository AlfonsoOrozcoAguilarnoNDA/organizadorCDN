<?php
// =====================================================
// Sistema de Respaldo de Prompts IA - VERSIÓN CORREGIDA
// PHP 8.x Procedural - MySQL/MariaDB - Bootstrap 4.6
// CORRECCIÓN INTEGRIDAD: Hash RAW preservado en textarea
// Creado para Alfonso Orozco Aguilar - 23 Feb 2026
// Implementa correccion de hashes. Vercomentario en sitio
// =====================================================

// --- CONFIGURACIÓN - EDITA ESTO ANTES DE USAR ---
define('PASS_MAESTRA', 'admin123'); // Contraseña maestra para agregar/editar/borrar
define('IPS_PERMITIDAS', ['127.0.0.1', '::1', 'TU_IP_AQUI']); // Agrega tus IPs
define('TBL_NAME', 'ai_backups');

// Headers anti-caché OBLIGATORIOS
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

// Crear tabla si no existe (campos EXACTOS requeridos)
$create_table = "
CREATE TABLE IF NOT EXISTS `".TBL_NAME."` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `proyecto` VARCHAR(100) COLLATE utf8mb4_unicode_ci NOT NULL,
  `ia_utilizada` VARCHAR(50) COLLATE utf8mb4_unicode_ci NOT NULL,
  `tipo` VARCHAR(20) COLLATE utf8mb4_unicode_ci NOT NULL,
  `contenido` LONGTEXT COLLATE utf8mb4_unicode_ci NOT NULL,
  `nombre_archivo` VARCHAR(150) COLLATE utf8mb4_unicode_ci NOT NULL,
  `num_version` DECIMAL(14,6) NOT NULL,
  `comentarios` LONGTEXT COLLATE utf8mb4_unicode_ci,
  `calificacion` DECIMAL(14,6) DEFAULT NULL,
  `visible` VARCHAR(2) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'SI',
  `fecha` DATETIME NOT NULL,
  `contrasena_ver` VARCHAR(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `tamanio` DECIMAL(14,6) DEFAULT NULL,
  `hash_md5` VARCHAR(32) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `hash_sha1` VARCHAR(40) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  KEY `proyecto` (`proyecto`),
  KEY `nombre_archivo` (`nombre_archivo`),
  KEY `visible` (`visible`),
  KEY `fecha` (`fecha`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
";
$conn->query($create_table);

// VERIFICAR IP - BLOQUEO INMEDIATO
$user_ip = $_SERVER['REMOTE_ADDR'];
if (!in_array($user_ip, IPS_PERMITIDAS) && !in_array('', IPS_PERMITIDAS)) {
    http_response_code(403);
    die('<div class="alert alert-danger text-center mt-5"><h1><i class="fas fa-ban"></i> ACCESO NO AUTORIZADO</h1><p>Su IP <strong>' . htmlspecialchars($user_ip) . '</strong> no está permitida.</p></div>');
}

// Funciones críticas
function calcularHashYTamano($contenido) {
    $tamanio_kb = strlen($contenido) / 1024;
    return [round($tamanio_kb, 6), md5($contenido), sha1($contenido)];
}

function validarBase64Imagen($base64) {
    $cabeceras_seguras = ['/9j/', 'iVBORw0KGgo', 'R0lGODlh', 'UklGR'];
    foreach ($cabeceras_seguras as $cab) {
        if (strpos($base64, $cab) === 0) return true;
    }
    return false;
}

function mostrarDiffLineal($texto1, $texto2) {
    $lineas1 = explode("\n", rtrim($texto1, "\n"));
    $lineas2 = explode("\n", rtrim($texto2, "\n"));
    $max = max(count($lineas1), count($lineas2));
    $diff = '';
    
    for ($i = 0; $i < $max; $i++) {
        $l1 = $lineas1[$i] ?? '';
        $l2 = $lineas2[$i] ?? '';
        
        if (trim($l1) === trim($l2)) {
            $diff .= "<div class='diff-line same'>  {$l1}</div>\n";
        } elseif (!$l1 && $l2) {
            $diff .= "<div class='diff-line add'>+ {$l2}</div>\n";
        } elseif ($l1 && !$l2) {
            $diff .= "<div class='diff-line delete'>- {$l1}</div>\n";
        } else {
            $diff .= "<div class='diff-line delete'>- {$l1}</div>\n";
            $diff .= "<div class='diff-line add'>+ {$l2}</div>\n";
        }
    }
    return $diff;
}

// Procesar POST (con detección post_max_size)
$accion = $_GET['accion'] ?? '';
$id_edit = (int)($_GET['id'] ?? 0);
$msg = '';

// ESCUDO DE MEMORIA: Detectar POST truncado
if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($_POST) && strpos($_SERVER['CONTENT_TYPE'] ?? '', 'multipart/form-data') !== false) {
    $msg = '<div class="alert alert-warning"><i class="fas fa-exclamation-triangle"></i> ⚠️ POST vacío/truncado. Revisa <code>post_max_size</code> y <code>upload_max_filesize</code> en php.ini (recomendado: 50M).</div>';
}

if ($_POST && isset($_POST['confirmar_borrar']) && strtoupper(trim($_POST['confirmar_borrar'])) === 'BORRAR') {
    if (!($_SESSION['autenticada'] ?? false)) {
        $msg .= '<div class="alert alert-danger">Requiere contraseña maestra.</div>';
    } else {
        $stmt = $conn->prepare("DELETE FROM " . TBL_NAME . " WHERE id = ?");
        $stmt->bind_param("i", $_POST['id_borrar']);
        $stmt->execute();
        $msg .= '<div class="alert alert-success">Registro borrado permanentemente.</div>';
        $stmt->close();
    }
}

if ($_POST && (isset($_POST['guardar']) || isset($_POST['nueva_version']))) {
    if (!($_SESSION['autenticada'] ?? false)) {
        $msg .= '<div class="alert alert-danger">Requiere contraseña maestra para modificar.</div>';
    } else {
        // Sanitización entrada
        $proyecto = trim($_POST['proyecto'] ?? '');
        $ia = trim($_POST['ia_utilizada'] ?? '');
        $tipo = trim($_POST['tipo'] ?? '');
        $contenido = trim($_POST['contenido'] ?? '');
        $nombre_archivo = trim($_POST['nombre_archivo'] ?? '');
        $num_version = (float)($_POST['num_version'] ?? 1.0);
        $comentarios = trim($_POST['comentarios'] ?? '');
        $calificacion = (float)($_POST['calificacion'] ?? 0);
        $visible = $_POST['visible'] ?? 'SI';
        
        // IMÁGENES: Convertir archivo a base64
        if ($tipo === 'imagen' && isset($_FILES['imagen_file']) && $_FILES['imagen_file']['error'] === UPLOAD_ERR_OK) {
            $img_raw = file_get_contents($_FILES['imagen_file']['tmp_name']);
            $img_b64 = base64_encode($img_raw);
            if (validarBase64Imagen($img_b64)) {
                $contenido = $img_b64;
            } else {
                $msg .= '<div class="alert alert-danger">Imagen inválida (solo JPG/PNG/WEBP/GIF).</div>';
            }
        }
        
        // CALCULAR HASHES SOBRE CONTENIDO CRUDO (INTEGRIDAD)
        [$tamanio, $hash_md5, $hash_sha1] = calcularHashYTamano($contenido);
        
        // Contraseña individual
        $contrasena_ver = '';
        if (!empty($_POST['contrasena_ver'])) {
            $contrasena_ver = password_hash($_POST['contrasena_ver'], PASSWORD_DEFAULT);
        }
        
        $fecha = date('Y-m-d H:i:s');
        
        if (isset($_POST['nueva_version']) && $id_edit) {
            $stmt_ver = $conn->prepare("SELECT num_version FROM " . TBL_NAME . " WHERE id = ?");
            $stmt_ver->bind_param("i", $id_edit);
            $stmt_ver->execute();
            $ver_data = $stmt_ver->get_result()->fetch_assoc();
            $num_version = ($ver_data['num_version'] ?? 0) + 1.000000;
            $stmt_ver->close();
        }
        
        if ($id_edit) {
            // UPDATE
            $stmt = $conn->prepare("UPDATE " . TBL_NAME . " SET proyecto=?,ia_utilizada=?,tipo=?,contenido=?,nombre_archivo=?,num_version=?,comentarios=?,calificacion=?,visible=?,contrasena_ver=?,tamanio=?,hash_md5=?,hash_sha1=?,fecha=? WHERE id=?");
            $stmt->bind_param("sssssdssississi", $proyecto,$ia,$tipo,$contenido,$nombre_archivo,$num_version,$comentarios,$calificacion,$visible,$contrasena_ver,$tamanio,$hash_md5,$hash_sha1,$fecha,$id_edit);
        } else {
            // INSERT
            $stmt = $conn->prepare("INSERT INTO " . TBL_NAME . " (proyecto,ia_utilizada,tipo,contenido,nombre_archivo,num_version,comentarios,calificacion,visible,fecha,contrasena_ver,tamanio,hash_md5,hash_sha1) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
            $stmt->bind_param("sssssdssissss", $proyecto,$ia,$tipo,$contenido,$nombre_archivo,$num_version,$comentarios,$calificacion,$visible,$fecha,$contrasena_ver,$tamanio,$hash_md5,$hash_sha1);
        }
        
        if ($stmt->execute()) {
            $msg .= '<div class="alert alert-success">✅ Guardado. Hashes: MD5=' . $hash_md5 . ' SHA1=' . substr($hash_sha1,0,16) . '...</div>';
            $id_edit = $conn->insert_id;
        } else {
            $msg .= '<div class="alert alert-danger">Error: ' . htmlspecialchars($stmt->error) . '</div>';
        }
        $stmt->close();
    }
}

// Autenticación maestra
if (isset($_POST['pass_maestra'])) {
    if (password_verify($_POST['pass_maestra'], PASS_MAESTRA) || $_POST['pass_maestra'] === PASS_MAESTRA) {
        $_SESSION['autenticada'] = true;
        $msg .= '<div class="alert alert-success">🔓 Autenticado como ADMIN.</div>';
    } else {
        $msg .= '<div class="alert alert-danger">❌ Contraseña maestra incorrecta.</div>';
    }
}

// Ver registro (con contraseña individual)
$registro_ver = null;
$pass_registro_ok = false;
if ($accion === 'ver' && $id_edit) {
    $stmt = $conn->prepare("SELECT * FROM " . TBL_NAME . " WHERE id = ?");
    $stmt->bind_param("i", $id_edit);
    $stmt->execute();
    $registro_ver = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    
    if ($registro_ver && !empty($registro_ver['contrasena_ver'])) {
        if (isset($_POST['pass_registro_' . $id_edit]) && password_verify($_POST['pass_registro_' . $id_edit], $registro_ver['contrasena_ver'])) {
            $pass_registro_ok = true;
        }
    } else {
        $pass_registro_ok = true;
    }
}

// Filtros y paginación
$where = "WHERE visible = 'SI'";
$params = [];
$types = "";
$page = max(1, intval($_GET['page'] ?? 1));
$limit = 10;
$offset = ($page - 1) * $limit;

$filtros = [
    'proyecto' => $_GET['proyecto'] ?? '',
    'ia' => $_GET['ia'] ?? '',
    'tipo' => $_GET['tipo'] ?? '',
    'visible' => $_GET['visible'] ?? ''
];

foreach ($filtros as $key => $val) {
    if (!empty($val) && $val !== 'SI') {
        if ($key === 'proyecto') {
            $where .= " AND proyecto LIKE ?";
            $params[] = "%$val%";
            $types .= "s";
        } else {
            $where .= " AND $key = ?";
            $params[] = $val;
            $types .= "s";
        }
    }
}
if ($filtros['visible'] === 'NO') $where = "WHERE visible = 'NO'";
if ($filtros['visible'] === 'TODOS') $where = "";

// Listado
$stmt = $conn->prepare("SELECT * FROM " . TBL_NAME . " $where ORDER BY fecha DESC LIMIT ?, ?");
$params[] = $limit; $params[] = $offset; $types .= "ii";
$stmt->bind_param($types, ...$params);
$stmt->execute();
$registros = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
$stmt->close();

// Conteo paginación
$count_sql = "SELECT COUNT(*) as total FROM " . TBL_NAME . " $where";
$count_stmt = $conn->prepare($count_sql);
if (count($params) > 2) {
    array_splice($params, -2);
    $count_stmt->bind_param(substr($types, 0, -2), ...$params);
}
$count_stmt->execute();
$total_reg = $count_stmt->get_result()->fetch_assoc()['total'];
$total_paginas = ceil($total_reg / $limit);
$count_stmt->close();

// Datos para selects
$ias = ['ChatGPT', 'Claude', 'Gemini', 'Grok', 'Cohere', 'otro'];
$tipos = ['prompt', 'imagen', 'idea', 'respuesta', 'codigo', 'otro'];

// Registro para editar
$registro_edit = null;
if (in_array($accion, ['editar', 'nueva_version']) && $id_edit) {
    $stmt = $conn->prepare("SELECT * FROM " . TBL_NAME . " WHERE id = ?");
    $stmt->bind_param("i", $id_edit);
    $stmt->execute();
    $registro_edit = $stmt->get_result()->fetch_assoc();
    $stmt->close();
    if ($accion === 'nueva_version') {
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
    <title>🔒 Respaldo IA - Integridad Hash Corregida</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css" rel="stylesheet">
    <style>
        :root { --diff-delete: #ffeef0; --diff-add: #e6ffe6; --diff-same: #f8f9fa; }
        .diff-line { padding: 4px 8px; margin: 1px 0; border-radius: 3px; font-family: 'Courier New', monospace; font-size: 13px; white-space: pre-wrap; }
        .diff-line.same { background: var(--diff-same); }
        .diff-line.delete { background: var(--diff-delete); }
        .diff-line.add { background: var(--diff-add); }
        .navbar-brand { font-weight: 700; font-size: 1.3rem; }
        .candado { color: #ffc107; font-size: 1.1em; }
        .hash-verified { background: #d4edda; border: 1px solid #c3e6cb; }
        pre, textarea[readonly] { font-family: 'Courier New', monospace; }
    </style>
</head>
<body class="bg-light">
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary sticky-top shadow-sm">
        <div class="container">
            <a class="navbar-brand" href="?"><i class="fas fa-shield-alt"></i> Respaldo IA Pro</a>
            <span class="navbar-text ml-auto">
                <?php if (($_SESSION['autenticada'] ?? false)): ?>
                    <span class="badge badge-success p-2 mr-2"><i class="fas fa-crown"></i> ADMIN</span>
                    <a href="?cerrar=1" class="btn btn-sm btn-outline-light" onclick="return confirm('¿Cerrar sesión ADMIN?')"><i class="fas fa-sign-out-alt"></i></a>
                <?php else: ?>
                    <span class="badge badge-secondary p-2"><i class="fas fa-eye"></i> SOLO LECTURA</span>
                <?php endif; ?>
                <span class="badge badge-info ml-2"><?php echo count($registros); ?>/<?php echo $total_reg; ?> regs</span>
            </span>
        </div>
    </nav>

    <div class="container-fluid mt-4 pb-5">
        <?php if ($msg): echo $msg; endif; ?>

        <?php if ($accion === 'ver' && $registro_ver && !$pass_registro_ok && $registro_ver['contrasena_ver']): ?>
            <!-- Contraseña registro protegido -->
            <div class="row justify-content-center">
                <div class="col-md-6">
                    <div class="card border-warning shadow">
                        <div class="card-header bg-warning text-dark">
                            <h5><i class="fas fa-key text-danger"></i> Registro Protegido por Contraseña</h5>
                        </div>
                        <div class="card-body">
                            <form method="POST">
                                <div class="input-group input-group-lg">
                                    <input type="password" name="pass_registro_<?php echo $id_edit; ?>" class="form-control" placeholder="Contraseña del registro" required>
                                    <div class="input-group-append">
                                        <button class="btn btn-primary"><i class="fas fa-unlock"></i> Desbloquear</button>
                                    </div>
                                </div>
                                <input type="hidden" name="id" value="<?php echo $id_edit; ?>">
                            </form>
                        </div>
                    </div>
                </div>
            </div>

        <?php elseif ($accion === 'ver' && $registro_ver && $pass_registro_ok): ?>
            <!-- VER REGISTRO COMPLETO - CORRECCIÓN INTEGRIDAD HASH -->
            <div class="card shadow mb-4">
                <div class="card-header bg-success text-white">
                    <div class="d-flex justify-content-between align-items-center">
                        <h4><i class="fas fa-file-alt"></i> <?php echo htmlspecialchars($registro_ver['nombre_archivo']); ?></h4>
                        <span class="badge badge-light">v<?php echo number_format($registro_ver['num_version'], 6); ?></span>
                    </div>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-lg-4">
                            <h6><i class="fas fa-info-circle"></i> Metadatos</h6>
                            <table class="table table-sm table-borderless">
                                <tr><td><strong>Proyecto:</strong></td><td><?php echo htmlspecialchars($registro_ver['proyecto']); ?></td></tr>
                                <tr><td><strong>IA:</strong></td><td><span class="badge badge-<?php echo $registro_ver['ia_utilizada'] === 'Grok' ? 'dark' : 'primary'; ?>"><?php echo htmlspecialchars($registro_ver['ia_utilizada']); ?></span></td></tr>
                                <tr><td><strong>Tipo:</strong></td><td><?php echo htmlspecialchars($registro_ver['tipo']); ?></td></tr>
                                <tr><td><strong>Fecha:</strong></td><td><?php echo date('d/m/Y H:i:s', strtotime($registro_ver['fecha'])); ?></td></tr>
                                <tr><td><strong>Calificación:</strong></td><td><?php echo $registro_ver['calificacion'] ?: '-'; ?>/10</td></tr>
                                <tr><td><strong>Tamaño:</strong></td><td><strong><?php echo number_format($registro_ver['tamanio'], 2); ?> KB</strong></td></tr>
                                <tr><td><strong>Visible:</strong></td><td><?php echo $registro_ver['visible']; ?></td></tr>
                                <tr><td><strong>Hash MD5:</strong></td><td class="hash-verified small font-monospace"><?php echo $registro_ver['hash_md5']; ?></td></tr>
                                <tr><td><strong>Hash SHA1:</strong></td><td class="hash-verified small font-monospace"><?php echo $registro_ver['hash_sha1']; ?></td></tr>
                            </table>
                            
                            <!-- ADVERTENCIA INTEGRIDAD HASH -->
                            <div class="alert alert-info small">
                                <i class="fas fa-check-circle text-success"></i>
                                <strong>✅ INTEGRIDAD VERIFICADA:</strong> Hashes calculados sobre contenido <em>RAW</em>.
                                Copia directo desde textarea abajo para validar MD5/SHA1 exactos.
                            </div>
                        </div>
                        
                        <div class="col-lg-8">
                            <h6><i class="fas fa-file-text"></i> Contenido Original (RAW)</h6>
                            <?php if ($registro_ver['tipo'] === 'imagen' && validarBase64Imagen($registro_ver['contenido'])): ?>
                                <img src="data:image/png;base64,<?php echo htmlspecialchars($registro_ver['contenido']); ?>" 
                                     class="img-fluid rounded shadow" style="max-height: 500px; max-width: 100%;">
                                <small class="text-muted d-block mt-2">Imagen renderizada desde base64 seguro</small>
                            <?php else: ?>
                                <textarea class="form-control font-monospace" rows="18" readonly 
                                          style="font-size: 12px;"><?php echo $registro_ver['contenido']; ?></textarea>
                            <?php endif; ?>
                            
                            <?php if ($registro_ver['comentarios']): ?>
                                <div class="mt-3 p-3 bg-light rounded">
                                    <small class="text-muted"><strong>Notas:</strong> <?php echo htmlspecialchars($registro_ver['comentarios']); ?></small>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
                <div class="card-footer text-muted">
                    <a href="?page=<?php echo $page; ?>" class="btn btn-outline-secondary btn-sm"><i class="fas fa-arrow-left"></i> Volver</a>
                    <?php if ($_SESSION['autenticada'] ?? false): ?>
                        <a href="?accion=editar&id=<?php echo $id_edit; ?>" class="btn btn-outline-warning btn-sm"><i class="fas fa-edit"></i></a>
                    <?php endif; ?>
                </div>
            </div>

        <?php elseif (in_array($accion, ['agregar', 'editar', 'nueva_version']) && ($_SESSION['autenticada'] ?? false)): ?>
            <!-- FORMULARIO CRUD -->
            <div class="row justify-content-center">
                <div class="col-lg-10">
                    <div class="card shadow">
                        <div class="card-header bg-primary text-white">
                            <h4>
                                <i class="fas fa-<?php echo $accion === 'nueva_version' ? 'plus-circle' : ($accion === 'editar' ? 'edit' : 'plus'); ?>"></i>
                                <?php echo $accion === 'nueva_version' ? 'Nueva Versión' : (strtoupper($accion) === 'EDITAR' ? 'Editar Registro' : 'Agregar Nuevo'); ?>
                            </h4>
                        </div>
                        <div class="card-body">
                            <form method="POST" enctype="multipart/form-data">
                                <div class="row">
                                    <div class="col-md-6">
                                        <div class="form-group">
                                            <label>Proyecto <span class="text-danger">*</span></label>
                                            <input type="text" name="proyecto" class="form-control" 
                                                   value="<?php echo htmlspecialchars($registro_edit['proyecto'] ?? ''); ?>" required maxlength="100">
                                        </div>
                                        <div class="form-group">
                                            <label>IA Utilizada</label>
                                            <select name="ia_utilizada" class="form-control">
                                                <?php foreach ($ias as $op): ?>
                                                    <option value="<?php echo $op; ?>" <?php echo ($registro_edit['ia_utilizada'] ?? '') === $op ? 'selected' : ''; ?>><?php echo $op; ?></option>
                                                <?php endforeach; ?>
                                            </select>
                                        </div>
                                        <div class="form-group">
                                            <label>Tipo <span class="text-danger">*</span></label>
                                            <select name="tipo" class="form-control" id="tipoCampo">
                                                <?php foreach ($tipos as $op): ?>
                                                    <option value="<?php echo $op; ?>" <?php echo ($registro_edit['tipo'] ?? '') === $op ? 'selected' : ''; ?>><?php echo ucfirst($op); ?></option>
                                                <?php endforeach; ?>
                                            </select>
                                        </div>
                                        <div class="form-group">
                                            <label>Nombre Archivo <span class="text-danger">*</span></label>
                                            <input type="text" name="nombre_archivo" class="form-control" 
                                                   value="<?php echo htmlspecialchars($registro_edit['nombre_archivo'] ?? ''); ?>" required maxlength="150">
                                        </div>
                                    </div>
                                    <div class="col-md-6">
                                        <div class="form-group">
                                            <label>Nº Versión</label>
                                            <input type="number" name="num_version" class="form-control" step="0.000001" 
                                                   value="<?php echo htmlspecialchars($registro_edit['num_version'] ?? '1.000000'); ?>" min="0">
                                        </div>
                                        <div class="form-group">
                                            <label>Calificación (0-10)</label>
                                            <input type="number" name="calificacion" class="form-control" min="0" max="10" step="0.1" 
                                                   value="<?php echo htmlspecialchars($registro_edit['calificacion'] ?? ''); ?>">
                                        </div>
                                        <div class="form-group">
                                            <label>Visible</label>
                                            <select name="visible" class="form-control">
                                                <option value="SI" <?php echo ($registro_edit['visible'] ?? 'SI') === 'SI' ? 'selected' : ''; ?>>SÍ</option>
                                                <option value="NO" <?php echo ($registro_edit['visible'] ?? '') === 'NO' ? 'selected' : ''; ?>>NO</option>
                                            </select>
                                        </div>
                                        <div class="form-group">
                                            <label>🔒 Contraseña Individual <small>(opcional)</small></label>
                                            <input type="password" name="contrasena_ver" class="form-control" 
                                                   placeholder="Proteger este registro específicamente">
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="form-group">
                                    <label>Contenido <span class="text-danger">*</span></label>
                                    <?php $es_imagen = ($registro_edit['tipo'] ?? '') === 'imagen'; ?>
                                    <textarea name="contenido" class="form-control" rows="<?php echo $es_imagen ? '6' : '15'; ?>" 
                                              placeholder="<?php echo $es_imagen ? 'Pegar base64 imagen aquí...' : 'Contenido del prompt, respuesta, código...'; ?>"
                                              ><?php echo htmlspecialchars($registro_edit['contenido'] ?? ''); ?></textarea>
                                    
                                    <?php if ($es_imagen): ?>
                                        <div class="alert alert-secondary mt-2">
                                            <small><strong>O subir imagen directamente:</strong></small>
                                            <input type="file" name="imagen_file" class="form-control mt-1" accept="image/*">
                                            <small class="text-muted d-block">Solo JPG, PNG, WEBP, GIF. Convertido automáticamente a base64.</small>
                                        </div>
                                    <?php endif; ?>
                                </div>
                                
                                <div class="form-group">
                                    <label>Comentarios</label>
                                    <textarea name="comentarios" class="form-control" rows="3"><?php echo htmlspecialchars($registro_edit['comentarios'] ?? ''); ?></textarea>
                                </div>
                                
                                <input type="hidden" name="id" value="<?php echo $id_edit; ?>">
                                <?php if ($accion === 'nueva_version'): ?><input type="hidden" name="nueva_version" value="1"><?php endif; ?>
                                
                                <div class="d-flex">
                                    <button type="submit" name="guardar" class="btn btn-success btn-lg mr-2">
                                        <i class="fas fa-save"></i> Guardar Registro
                                    </button>
                                    <a href="?page=<?php echo $page; ?><?php echo http_build_query($filtros, '', '&', PHP_QUERY_RFC3986); ?>" 
                                       class="btn btn-secondary btn-lg">Cancelar</a>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>

        <?php else: ?>
            <!-- LISTADO PRINCIPAL CON FILTROS -->
            <div class="row">
                <div class="col-lg-9">
                    <div class="d-flex justify-content-between align-items-center mb-4">
                        <h3><i class="fas fa-list-ul text-primary"></i> Registros 
                            <span class="badge badge-primary"><?php echo $page; ?>/<?php echo $total_paginas; ?></span>
                        </h3>
                        <?php if ($_SESSION['autenticada'] ?? false): ?>
                            <a href="?accion=agregar" class="btn btn-success"><i class="fas fa-plus"></i> Nuevo</a>
                        <?php endif; ?>
                    </div>

                    <!-- FILTROS PERSISTENTES -->
                    <form method="GET" class="card p-3 mb-4 shadow-sm">
                        <div class="row">
                            <div class="col-md-3">
                                <input type="text" name="proyecto" class="form-control" placeholder="Buscar proyecto..." 
                                       value="<?php echo htmlspecialchars($filtros['proyecto']); ?>">
                            </div>
                            <div class="col-md-2">
                                <select name="ia" class="form-control">
                                    <option value="">Todas IA</option>
                                    <?php foreach ($ias as $ia): ?>
                                        <option <?php selected($filtros['ia'], $ia); ?>><?php echo $ia; ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                            <div class="col-md-2">
                                <select name="tipo" class="form-control">
                                    <option value="">Todos tipos</option>
                                    <?php foreach ($tipos as $tp): ?>
                                        <option <?php selected($filtros['tipo'], $tp); ?>><?php echo ucfirst($tp); ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </div>
                            <div class="col-md-2">
                                <select name="visible" class="form-control">
                                    <option value="">Visible: SÍ</option>
                                    <option value="NO" <?php selected($filtros['visible'], 'NO'); ?>>NO</option>
                                    <option value="TODOS" <?php selected($filtros['visible'], 'TODOS'); ?>>TODOS</option>
                                </select>
                            </div>
                            <div class="col-md-3">
                                <button class="btn btn-primary btn-block"><i class="fas fa-search"></i> Filtrar</button>
                            </div>
                        </div>
                    </form>

                    <!-- TABLA REGISTROS -->
                    <div class="table-responsive shadow">
                        <table class="table table-hover table-sm mb-0">
                            <thead class="thead-dark">
                                <tr>
                                    <th width="120">Fecha</th>
                                    <th>Proyecto</th>
                                    <th width="80">IA</th>
                                    <th width="70">Tipo</th>
                                    <th width="80">Versión</th>
                                    <th width="60">Calif.</th>
                                    <th width="70">Tamaño</th>
                                    <th>Archivo</th>
                                    <th width="70">Visible</th>
                                    <th width="180">Acciones</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($registros as $reg): ?>
                                    <tr>
                                        <td><?php echo date('d/m H:i', strtotime($reg['fecha'])); ?></td>
                                        <td class="font-weight-bold"><?php echo htmlspecialchars(substr($reg['proyecto'], 0, 25)); ?><?php echo strlen($reg['proyecto']) > 25 ? '...' : ''; ?></td>
                                        <td><span class="badge badge-secondary"><?php echo htmlspecialchars($reg['ia_utilizada']); ?></span></td>
                                        <td><?php echo htmlspecialchars($reg['tipo']); ?></td>
                                        <td><?php echo number_format($reg['num_version'], 3); ?></td>
                                        <td><?php echo $reg['calificacion'] ?: '-'; ?></td>
                                        <td><?php echo number_format($reg['tamanio'], 1); ?>K</td>
                                        <td title="<?php echo htmlspecialchars($reg['nombre_archivo']); ?>"><?php echo htmlspecialchars(substr($reg['nombre_archivo'], 0, 20)); ?><?php echo strlen($reg['nombre_archivo']) > 20 ? '...' : ''; ?></td>
                                        <td>
                                            <?php echo $reg['visible'] === 'SI' ? '<span class="text-success">SÍ</span>' : '<span class="text-danger">NO</span>'; ?>
                                            <?php if ($reg['contrasena_ver']): ?> <i class="fas fa-lock candado" title="Protegido"></i><?php endif; ?>
                                        </td>
                                        <td>
                                            <a href="?accion=ver&id=<?php echo $reg['id']; ?>" class="btn btn-sm btn-outline-primary" title="Ver completo">
                                                <i class="fas fa-eye"></i>
                                            </a>
                                            <?php if ($_SESSION['autenticada'] ?? false): ?>
                                                <a href="?accion=editar&id=<?php echo $reg['id']; ?>" class="btn btn-sm btn-outline-warning" title="Editar">
                                                    <i class="fas fa-edit"></i>
                                                </a>
                                                <button class="btn btn-sm btn-outline-danger borrar-btn" data-id="<?php echo $reg['id']; ?>" 
                                                        data-nombre="<?php echo addslashes($reg['nombre_archivo']); ?>" 
                                                        data-version="<?php echo $reg['num_version']; ?>" title="Borrar">
                                                    <i class="fas fa-trash"></i>
                                                </button>
                                                <a href="?accion=nueva_version&id=<?php echo $reg['id']; ?>" class="btn btn-sm btn-outline-info" title="Nueva versión">
                                                    <i class="fas fa-plus-circle"></i>
                                                </a>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                                <?php if (empty($registros)): ?>
                                    <tr><td colspan="10" class="text-center text-muted py-4">No hay registros<?php echo $where !== "WHERE visible = 'SI'" ? ' con estos filtros' : ''; ?>.</td></tr>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>

                    <!-- PAGINACIÓN -->
                    <?php if ($total_paginas > 1): ?>
                        <nav class="mt-4">
                            <ul class="pagination justify-content-center">
                                <?php 
                                $pag_range = max(1, $page - 2);
                                $pag_end = min($total_paginas, $page + 2);
                                if ($pag_range > 1): ?>
                                    <li class="page-item"><a class="page-link" href="?page=1&<?php echo http_build_query($filtros); ?>">1</a></li>
                                    <?php if ($pag_range > 2): ?><li class="page-item disabled"><span class="page-link">...</span></li><?php endif; ?>
                                <?php endif; ?>
                                
                                <?php for ($i = $pag_range; $i <= $pag_end; $i++): ?>
                                    <li class="page-item <?php echo $page === $i ? 'active' : ''; ?>">
                                        <a class="page-link" href="?page=<?php echo $i; ?>&<?php echo http_build_query($filtros); ?>"><?php echo $i; ?></a>
                                    </li>
                                <?php endfor; ?>
                                
                                <?php if ($pag_end < $total_paginas): ?>
                                    <?php if ($pag_end < $total_paginas - 1): ?><li class="page-item disabled"><span class="page-link">...</span></li><?php endif; ?>
                                    <li class="page-item"><a class="page-link" href="?page=<?php echo $total_paginas; ?>&<?php echo http_build_query($filtros); ?>"><?php echo $total_paginas; ?></a></li>
                                <?php endif; ?>
                            </ul>
                        </nav>
                    <?php endif; ?>
                </div>

                <!-- PANEL ACCIONES LATERAL -->
                <div class="col-lg-3">
                    <div class="card sticky-top" style="top: 100px;">
                        <div class="card-header bg-light">
                            <h6><i class="fas fa-cogs"></i> Acciones Rápidas</h6>
                        </div>
                        <div class="list-group list-group-flush">
                            <?php if (!($_SESSION['autenticada'] ?? false)): ?>
                                <form method="POST" class="p-2">
                                    <div class="input-group input-group-sm">
                                        <input type="password" name="pass_maestra" class="form-control" placeholder="Contraseña ADMIN" required>
                                        <div class="input-group-append">
                                            <button class="btn btn-primary"><i class="fas fa-unlock-alt"></i></button>
                                        </div>
                                    </div>
                                </form>
                            <?php else: ?>
                                <a href="?accion=agregar" class="list-group-item list-group-item-action list-group-item-success">
                                    <i class="fas fa-plus fa-fw text-success"></i> Nuevo Registro
                                </a>
                                <a href="?visible=TODOS<?php echo http_build_query(array_diff_key($filtros, ['visible'=>1])); ?>" 
                                   class="list-group-item list-group-item-action list-group-item-info">
                                    <i class="fas fa-eye-slash fa-fw"></i> Ver Ocultos
                                </a>
                                <div class="list-group-item">
                                    <small class="text-muted">Filtros activos:</small>
                                    <?php foreach ($filtros as $k => $v): if ($v): ?>
                                        <div><small class="badge badge-light"><?php echo ucfirst($k); ?>: <?php echo htmlspecialchars($v); ?></small></div>
                                    <?php endif; endforeach; ?>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
        <?php endif; ?>
    </div>

    <!-- MODAL CONFIRMACIÓN BORRAR -->
    <div class="modal fade" id="modalBorrar" tabindex="-1" data-backdrop="static" data-keyboard="false">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content border-0 shadow-lg">
                <div class="modal-header bg-danger text-white">
                    <h5 class="modal-title"><i class="fas fa-skull-crossbones"></i> ¡CONFIRMAR ELIMINACIÓN!</h5>
                    <button type="button" class="close text-white" data-dismiss="modal">&times;</button>
                </div>
                <div class="modal-body text-center py-4">
                    <i class="fas fa-exclamation-triangle fa-3x text-danger mb-3"></i>
                    <h6 class="text-danger font-weight-bold mb-3" id="nombreConfirmar"></h6>
                    <p class="mb-4">Versión <span class="badge badge-danger" id="versionConfirmar"></span></p>
                    <p class="text-warning mb-4"><strong>¡ESTA ACCIÓN ES IRREVERSIBLE!</strong></p>
                    <div class="input-group input-group-lg mx-auto" style="max-width: 300px;">
                        <input type="text" id="textoConfirmar" class="form-control text-center font-weight-bold text-uppercase" 
                               placeholder="ESCRIBE 'BORRAR'" maxlength="6">
                        <div class="input-group-append">
                            <span class="input-group-text bg-danger text-white font-weight-bold">BORRAR</span>
                        </div>
                    </div>
                </div>
                <div class="modal-footer justify-content-center">
                    <form id="formConfirmarBorrar" method="POST">
                        <input type="hidden" name="id_borrar" id="inputIdBorrar">
                        <input type="hidden" name="confirmar_borrar" id="inputTextoConfirmar">
                        <button type="button" class="btn btn-secondary" data-dismiss="modal"><i class="fas fa-times"></i> Cancelar</button>
                        <button type="submit" class="btn btn-danger btn-lg px-4" id="btnEjecutarBorrar" disabled>
                            <i class="fas fa-bomb"></i> ¡ELIMINAR!
                        </button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <!-- RESPONSABILIDAD LEGAL -->
    <footer class="bg-dark text-white-50 py-4 mt-5">
        <div class="container">
            <div class="row">
                <div class="col-md-8">
                    <p class="mb-0 small">
                        <i class="fas fa-exclamation-triangle text-warning"></i>
                        <strong>⚠️ ADVERTENCIA:</strong> Este sistema NO respalda automáticamente su base de datos MySQL. 
                        <em>Un respaldo que no existe, no es un respaldo.</em> Haga backups regulares.
                    </p>
                </div>
                <div class="col-md-4 text-md-right small">
                    <p class="mb-0">PHP 8.x • MySQL InnoDB • Bootstrap 4.6 • <strong>Hash Integrity ✅</strong></p>
                </div>
            </div>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/jquery@3.5.1/dist/jquery.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Confirmar BORRAR
        $('.borrar-btn').click(function() {
            const id = $(this).data('id');
            const nombre = $(this).data('nombre');
            const version = $(this).data('version');
            $('#inputIdBorrar').val(id);
            $('#nombreConfirmar').text(nombre);
            $('#versionConfirmar').text(version.toFixed(6));
            $('#textoConfirmar').val('').focus();
            $('#modalBorrar').modal('show');
        });

        $('#textoConfirmar').on('keyup', function() {
            const texto = $(this).val().toUpperCase().trim();
            $('#inputTextoConfirmar').val(texto);
            $('#btnEjecutarBorrar').prop('disabled', texto !== 'BORRAR');
        });

        // Cerrar sesión admin
        <?php if (isset($_GET['cerrar'])): ?>
            <?php unset($_SESSION['autenticada']); ?>
            window.location.href = '?';
        <?php endif; ?>

        // UX mejoras
        $('#tipoCampo').change(function() {
            // Recarga para alternar UI imagen si quieres más avanzado
        });
    </script>

    <?php function selected($actual, $opcion) { echo ($actual === $opcion) ? 'selected' : ''; } ?>
</body>
</html>
<?php $conn->close(); ob_end_flush(); ?>

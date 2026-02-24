<?php
// ============================================================
// AI BACKUP SYSTEM — index.php
// Sistema de Respaldo de Prompts IA — Vibecoding México
// ============================================================
// CONFIGURACIÓN — edita esto antes de usar
// ============================================================
define('PASS_MAESTRA',   'maestra123');          // para agregar, editar y borrar
define('PASS_REGISTROS', 'registros123');         // para registros con contraseña individual
define('DB_HOST',        'localhost');
define('DB_USER',        'root');
define('DB_PASS',        '');
define('DB_NAME',        'ai_backups_db');
define('IPS_PERMITIDAS', ['127.0.0.1', '::1']);  // agrega tus IPs aquí
define('REGISTROS_POR_PAGINA', 10);

// ============================================================
// SQL — CREATE TABLE (referencia)
// ============================================================
/*
CREATE TABLE IF NOT EXISTS `ai_backups` (
  `id`             INT AUTO_INCREMENT PRIMARY KEY,
  `proyecto`       VARCHAR(100)  NOT NULL DEFAULT '',
  `ia_utilizada`   VARCHAR(50)   NOT NULL DEFAULT '',
  `tipo`           VARCHAR(20)   NOT NULL DEFAULT 'prompt',
  `contenido`      LONGTEXT,
  `nombre_archivo` VARCHAR(150)  NOT NULL DEFAULT '',
  `num_version`    DECIMAL(14,6) NOT NULL DEFAULT 1.000000,
  `comentarios`    LONGTEXT,
  `calificacion`   DECIMAL(14,6) DEFAULT NULL,
  `visible`        VARCHAR(2)    NOT NULL DEFAULT 'SI',
  `fecha`          DATETIME      NOT NULL,
  `contrasena_ver` VARCHAR(255)  NOT NULL DEFAULT '',
  `tamanio`        DECIMAL(14,6) DEFAULT NULL,
  `hash_md5`       VARCHAR(32)   DEFAULT NULL,
  `hash_sha1`      VARCHAR(40)   DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
*/

// ============================================================
// HEADERS — caché y seguridad
// ============================================================
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: Sat, 01 Jan 2000 00:00:00 GMT');

session_start();

// ============================================================
// CONTROL DE ACCESO POR IP
// ============================================================
$ip_cliente = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
if (!in_array($ip_cliente, IPS_PERMITIDAS)) {
    http_response_code(403);
    die('<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Acceso no autorizado</title></head><body style="font-family:monospace;text-align:center;margin-top:100px;"><h2>⛔ Acceso no autorizado</h2><p>Tu IP: ' . htmlspecialchars($ip_cliente) . '</p></body></html>');
}

// ============================================================
// CONEXIÓN A BASE DE DATOS
// ============================================================
$conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if (!$conn) {
    die('Error de conexión a la base de datos: ' . mysqli_connect_error());
}
mysqli_set_charset($conn, 'utf8mb4');

// Crear tabla si no existe
$sql_create = "CREATE TABLE IF NOT EXISTS `ai_backups` (
  `id`             INT AUTO_INCREMENT PRIMARY KEY,
  `proyecto`       VARCHAR(100)  NOT NULL DEFAULT '',
  `ia_utilizada`   VARCHAR(50)   NOT NULL DEFAULT '',
  `tipo`           VARCHAR(20)   NOT NULL DEFAULT 'prompt',
  `contenido`      LONGTEXT,
  `nombre_archivo` VARCHAR(150)  NOT NULL DEFAULT '',
  `num_version`    DECIMAL(14,6) NOT NULL DEFAULT 1.000000,
  `comentarios`    LONGTEXT,
  `calificacion`   DECIMAL(14,6) DEFAULT NULL,
  `visible`        VARCHAR(2)    NOT NULL DEFAULT 'SI',
  `fecha`          DATETIME      NOT NULL,
  `contrasena_ver` VARCHAR(255)  NOT NULL DEFAULT '',
  `tamanio`        DECIMAL(14,6) DEFAULT NULL,
  `hash_md5`       VARCHAR(32)   DEFAULT NULL,
  `hash_sha1`      VARCHAR(40)   DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
mysqli_query($conn, $sql_create);

// ============================================================
// HELPERS
// ============================================================
function h($str) {
    return htmlspecialchars((string)$str, ENT_QUOTES, 'UTF-8');
}

function es_autenticado() {
    return isset($_SESSION['auth_maestra']) && $_SESSION['auth_maestra'] === true;
}

function post_max_size_bytes() {
    $val = trim(ini_get('post_max_size'));
    if ($val === '') return PHP_INT_MAX;
    $last = strtolower($val[strlen($val)-1]);
    $num  = (int)$val;
    switch ($last) {
        case 'g': $num *= 1024;
        case 'm': $num *= 1024;
        case 'k': $num *= 1024;
    }
    return $num;
}

function validar_base64_imagen($b64) {
    // Permitir solo jpg, png, webp, gif
    if (preg_match('/^data:image\/(jpeg|jpg|png|webp|gif);base64,/i', $b64)) {
        return true;
    }
    return false;
}

function siguiente_version($conn, $proyecto, $nombre_archivo) {
    $stmt = mysqli_prepare($conn, "SELECT MAX(num_version) as maxv FROM ai_backups WHERE proyecto=? AND nombre_archivo=?");
    mysqli_stmt_bind_param($stmt, 'ss', $proyecto, $nombre_archivo);
    mysqli_stmt_execute($stmt);
    $res = mysqli_stmt_get_result($stmt);
    $row = mysqli_fetch_assoc($res);
    mysqli_stmt_close($stmt);
    $maxv = $row['maxv'] ?? 0;
    return $maxv > 0 ? (float)$maxv + 1 : 1.0;
}

// ============================================================
// DETECCIÓN POST SIZE OVERFLOW
// ============================================================
$post_overflow = false;
$post_max = post_max_size_bytes();
if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($_POST) && $_SERVER['CONTENT_LENGTH'] > 0) {
    $post_overflow = true;
}

// ============================================================
// ACCIONES
// ============================================================
$accion  = $_GET['accion'] ?? 'listar';
$mensaje = '';
$tipo_msg = 'success';

// Login / Logout
if (isset($_POST['login_maestra'])) {
    if ($_POST['pass_maestra'] === PASS_MAESTRA) {
        $_SESSION['auth_maestra'] = true;
        $mensaje = 'Sesión iniciada correctamente.';
    } else {
        $mensaje = 'Contraseña incorrecta.';
        $tipo_msg = 'danger';
    }
}
if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: index.php');
    exit;
}

// GUARDAR REGISTRO (nuevo o editar)
if (isset($_POST['guardar_registro']) && es_autenticado()) {
    if ($post_overflow) {
        $mensaje = '⚠️ El contenido excede el límite post_max_size del servidor (' . ini_get('post_max_size') . '). El registro no fue guardado. Reduce el tamaño del contenido o ajusta php.ini.';
        $tipo_msg = 'danger';
    } else {
        $id_edit       = (int)($_POST['id_edit'] ?? 0);
        $proyecto      = trim($_POST['proyecto'] ?? '');
        $ia_utilizada  = trim($_POST['ia_utilizada'] ?? '');
        $tipo          = trim($_POST['tipo'] ?? 'prompt');
        $contenido     = $_POST['contenido'] ?? '';
        $nombre_archivo= trim($_POST['nombre_archivo'] ?? '');
        $num_version   = (float)($_POST['num_version'] ?? 1);
        $comentarios   = trim($_POST['comentarios'] ?? '');
        $calificacion  = $_POST['calificacion'] !== '' ? (float)$_POST['calificacion'] : null;
        $visible       = ($_POST['visible'] ?? 'SI') === 'SI' ? 'SI' : 'NO';
        $pass_ver      = trim($_POST['contrasena_ver'] ?? '');
        $fecha         = date('Y-m-d H:i:s');

        // Manejo de imagen base64
        if ($tipo === 'imagen') {
            // Si subió archivo, convertir a base64
            if (!empty($_FILES['imagen_file']['tmp_name'])) {
                $mime = mime_content_type($_FILES['imagen_file']['tmp_name']);
                $mimes_ok = ['image/jpeg','image/png','image/webp','image/gif'];
                if (in_array($mime, $mimes_ok)) {
                    $data = file_get_contents($_FILES['imagen_file']['tmp_name']);
                    $contenido = 'data:' . $mime . ';base64,' . base64_encode($data);
                } else {
                    $mensaje = 'Tipo de imagen no permitido. Solo JPG, PNG, WEBP, GIF.';
                    $tipo_msg = 'danger';
                }
            }
            // Validar base64 si ya viene en el textarea
            if ($mensaje === '' && !empty($contenido) && !validar_base64_imagen($contenido)) {
                $mensaje = 'El contenido de imagen no tiene un formato base64 válido (se requiere jpg, png, webp o gif).';
                $tipo_msg = 'danger';
            }
        }

        if ($mensaje === '') {
            // Calcular campos automáticos
            $tamanio   = round(strlen($contenido) / 1024, 6);
            $hash_md5  = md5($contenido);
            $hash_sha1 = sha1($contenido);

            // Hash contraseña individual si se proporcionó
            $hash_pass_ver = '';
            if ($pass_ver !== '') {
                $hash_pass_ver = password_hash($pass_ver, PASSWORD_DEFAULT);
            }

            if ($id_edit > 0) {
                // Editar
                if ($pass_ver !== '') {
                    $stmt = mysqli_prepare($conn, "UPDATE ai_backups SET proyecto=?,ia_utilizada=?,tipo=?,contenido=?,nombre_archivo=?,num_version=?,comentarios=?,calificacion=?,visible=?,fecha=?,contrasena_ver=?,tamanio=?,hash_md5=?,hash_sha1=? WHERE id=?");
                    mysqli_stmt_bind_param($stmt,'sssssdssdsssddi',$proyecto,$ia_utilizada,$tipo,$contenido,$nombre_archivo,$num_version,$comentarios,$calificacion,$visible,$fecha,$hash_pass_ver,$tamanio,$hash_md5,$hash_sha1,$id_edit);
                } else {
                    $stmt = mysqli_prepare($conn, "UPDATE ai_backups SET proyecto=?,ia_utilizada=?,tipo=?,contenido=?,nombre_archivo=?,num_version=?,comentarios=?,calificacion=?,visible=?,fecha=?,tamanio=?,hash_md5=?,hash_sha1=? WHERE id=?");
                    mysqli_stmt_bind_param($stmt,'sssssdssdsssdi',$proyecto,$ia_utilizada,$tipo,$contenido,$nombre_archivo,$num_version,$comentarios,$calificacion,$visible,$fecha,$tamanio,$hash_md5,$hash_sha1,$id_edit);
                }
                mysqli_stmt_execute($stmt);
                mysqli_stmt_close($stmt);
                $mensaje = 'Registro actualizado correctamente.';
            } else {
                // Nuevo
                $stmt = mysqli_prepare($conn, "INSERT INTO ai_backups (proyecto,ia_utilizada,tipo,contenido,nombre_archivo,num_version,comentarios,calificacion,visible,fecha,contrasena_ver,tamanio,hash_md5,hash_sha1) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
                mysqli_stmt_bind_param($stmt,'sssssdssdssss',$proyecto,$ia_utilizada,$tipo,$contenido,$nombre_archivo,$num_version,$comentarios,$calificacion,$visible,$fecha,$hash_pass_ver,$tamanio,$hash_md5,$hash_sha1);
                mysqli_stmt_execute($stmt);
                mysqli_stmt_close($stmt);
                $mensaje = 'Registro guardado correctamente.';
            }
            $accion = 'listar';
        }
    }
}

// BORRAR REGISTRO
if (isset($_POST['confirmar_borrar']) && es_autenticado()) {
    $id_borrar   = (int)($_POST['id_borrar'] ?? 0);
    $confirmacion= trim($_POST['confirmacion_borrar'] ?? '');
    if ($confirmacion !== 'BORRAR') {
        $mensaje  = 'Debes escribir BORRAR en mayúsculas para confirmar.';
        $tipo_msg = 'danger';
        $accion   = 'listar';
    } elseif ($id_borrar > 0) {
        $stmt = mysqli_prepare($conn, "DELETE FROM ai_backups WHERE id=?");
        mysqli_stmt_bind_param($stmt,'i',$id_borrar);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_close($stmt);
        $mensaje = 'Registro eliminado correctamente.';
        $accion  = 'listar';
    }
}

// NUEVA VERSIÓN
if ($accion === 'nueva_version' && es_autenticado()) {
    $id_nv = (int)($_GET['id'] ?? 0);
    if ($id_nv > 0) {
        $stmt = mysqli_prepare($conn, "SELECT * FROM ai_backups WHERE id=?");
        mysqli_stmt_bind_param($stmt,'i',$id_nv);
        mysqli_stmt_execute($stmt);
        $res = mysqli_stmt_get_result($stmt);
        $reg_nv = mysqli_fetch_assoc($res);
        mysqli_stmt_close($stmt);
        if ($reg_nv) {
            $reg_nv['contenido']    = '';
            $reg_nv['num_version']  = siguiente_version($conn, $reg_nv['proyecto'], $reg_nv['nombre_archivo']);
            $reg_nv['id']           = 0;
            $accion = 'formulario';
            $registro_edicion = $reg_nv;
        }
    }
}

// CARGAR REGISTRO PARA EDITAR
if ($accion === 'editar' && es_autenticado()) {
    $id_edit_get = (int)($_GET['id'] ?? 0);
    $stmt = mysqli_prepare($conn, "SELECT * FROM ai_backups WHERE id=?");
    mysqli_stmt_bind_param($stmt,'i',$id_edit_get);
    mysqli_stmt_execute($stmt);
    $res = mysqli_stmt_get_result($stmt);
    $registro_edicion = mysqli_fetch_assoc($res);
    mysqli_stmt_close($stmt);
    $accion = 'formulario';
}

// VER REGISTRO — autenticación individual
$registro_ver = null;
$ver_autenticado = false;
if ($accion === 'ver') {
    $id_ver = (int)($_GET['id'] ?? 0);
    $stmt = mysqli_prepare($conn, "SELECT * FROM ai_backups WHERE id=?");
    mysqli_stmt_bind_param($stmt,'i',$id_ver);
    mysqli_stmt_execute($stmt);
    $res = mysqli_stmt_get_result($stmt);
    $registro_ver = mysqli_fetch_assoc($res);
    mysqli_stmt_close($stmt);

    if ($registro_ver) {
        if ($registro_ver['contrasena_ver'] === '') {
            $ver_autenticado = true;
        } elseif (isset($_POST['pass_ver_registro'])) {
            if (password_verify($_POST['pass_ver_registro'], $registro_ver['contrasena_ver'])) {
                $ver_autenticado = true;
            } else {
                $mensaje  = 'Contraseña incorrecta para este registro.';
                $tipo_msg = 'danger';
            }
        }
    }
}

// DIFF
$diff_resultado = [];
if ($accion === 'diff' && isset($_GET['id1'], $_GET['id2'])) {
    $id1 = (int)$_GET['id1'];
    $id2 = (int)$_GET['id2'];
    $stmt = mysqli_prepare($conn,"SELECT id,num_version,contenido FROM ai_backups WHERE id IN (?,?)");
    mysqli_stmt_bind_param($stmt,'ii',$id1,$id2);
    mysqli_stmt_execute($stmt);
    $res = mysqli_stmt_get_result($stmt);
    $diff_regs = [];
    while ($r = mysqli_fetch_assoc($res)) $diff_regs[$r['id']] = $r;
    mysqli_stmt_close($stmt);
    if (isset($diff_regs[$id1], $diff_regs[$id2])) {
        $lineas1 = explode("\n", $diff_regs[$id1]['contenido']);
        $lineas2 = explode("\n", $diff_regs[$id2]['contenido']);
        $max = max(count($lineas1), count($lineas2));
        for ($i = 0; $i < $max; $i++) {
            $l1 = $lineas1[$i] ?? null;
            $l2 = $lineas2[$i] ?? null;
            if ($l1 === $l2) {
                $diff_resultado[] = ['tipo'=>'igual','linea'=>$l1];
            } else {
                if ($l1 !== null) $diff_resultado[] = ['tipo'=>'borrado','linea'=>$l1];
                if ($l2 !== null) $diff_resultado[] = ['tipo'=>'nuevo','linea'=>$l2];
            }
        }
    }
}

// ============================================================
// CONSULTA LISTADO
// ============================================================
$where_parts = ["1=1"];
$bind_types  = '';
$bind_vals   = [];

$f_proyecto  = trim($_GET['f_proyecto'] ?? '');
$f_ia        = trim($_GET['f_ia'] ?? '');
$f_tipo      = trim($_GET['f_tipo'] ?? '');
$f_visible   = $_GET['f_visible'] ?? 'SI';
$f_desde     = trim($_GET['f_desde'] ?? '');
$f_hasta     = trim($_GET['f_hasta'] ?? '');
$f_buscar    = trim($_GET['f_buscar'] ?? '');
$pagina      = max(1,(int)($_GET['pagina'] ?? 1));

if ($f_proyecto !== '') { $where_parts[] = "proyecto LIKE ?"; $bind_types .= 's'; $bind_vals[] = "%$f_proyecto%"; }
if ($f_ia       !== '') { $where_parts[] = "ia_utilizada = ?"; $bind_types .= 's'; $bind_vals[] = $f_ia; }
if ($f_tipo     !== '') { $where_parts[] = "tipo = ?"; $bind_types .= 's'; $bind_vals[] = $f_tipo; }
if ($f_visible  === 'SI' || $f_visible === 'NO') { $where_parts[] = "visible = ?"; $bind_types .= 's'; $bind_vals[] = $f_visible; }
if ($f_desde    !== '') { $where_parts[] = "fecha >= ?"; $bind_types .= 's'; $bind_vals[] = $f_desde . ' 00:00:00'; }
if ($f_hasta    !== '') { $where_parts[] = "fecha <= ?"; $bind_types .= 's'; $bind_vals[] = $f_hasta . ' 23:59:59'; }
if ($f_buscar   !== '') { $where_parts[] = "(contenido LIKE ? OR comentarios LIKE ?)"; $bind_types .= 'ss'; $bind_vals[] = "%$f_buscar%"; $bind_vals[] = "%$f_buscar%"; }

$where_sql = implode(' AND ', $where_parts);

// Total registros
$sql_total = "SELECT COUNT(*) as total FROM ai_backups WHERE $where_sql";
if ($bind_types !== '') {
    $stmt = mysqli_prepare($conn, $sql_total);
    mysqli_stmt_bind_param($stmt, $bind_types, ...$bind_vals);
    mysqli_stmt_execute($stmt);
    $res = mysqli_stmt_get_result($stmt);
    $total_regs = mysqli_fetch_assoc($res)['total'];
    mysqli_stmt_close($stmt);
} else {
    $res = mysqli_query($conn, $sql_total);
    $total_regs = mysqli_fetch_assoc($res)['total'];
}
$total_paginas = max(1, ceil($total_regs / REGISTROS_POR_PAGINA));
$offset = ($pagina - 1) * REGISTROS_POR_PAGINA;

// Registros de la página
$registros = [];
if ($accion === 'listar') {
    $sql_list = "SELECT id,proyecto,ia_utilizada,tipo,nombre_archivo,num_version,calificacion,tamanio,visible,fecha,contrasena_ver FROM ai_backups WHERE $where_sql ORDER BY fecha DESC LIMIT ? OFFSET ?";
    $bt2 = $bind_types . 'ii';
    $bv2 = array_merge($bind_vals, [REGISTROS_POR_PAGINA, $offset]);
    $stmt = mysqli_prepare($conn, $sql_list);
    mysqli_stmt_bind_param($stmt, $bt2, ...$bv2);
    mysqli_stmt_execute($stmt);
    $res = mysqli_stmt_get_result($stmt);
    while ($r = mysqli_fetch_assoc($res)) $registros[] = $r;
    mysqli_stmt_close($stmt);
}

// IAs distintas para filtros
$ias_disponibles = [];
$res_ias = mysqli_query($conn,"SELECT DISTINCT ia_utilizada FROM ai_backups ORDER BY ia_utilizada");
while ($r = mysqli_fetch_assoc($res_ias)) $ias_disponibles[] = $r['ia_utilizada'];

// Parámetros de filtro para paginación
function filtros_url() {
    $params = [];
    foreach (['f_proyecto','f_ia','f_tipo','f_visible','f_desde','f_hasta','f_buscar'] as $k) {
        if (!empty($_GET[$k])) $params[$k] = $_GET[$k];
    }
    return $params ? '&' . http_build_query($params) : '';
}

// ============================================================
// HTML OUTPUT
// ============================================================
?>
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>AI Backup System — Vibecoding México</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.5.0/css/all.min.css">
<style>
:root {
  --color-bg:      #0d1117;
  --color-surface: #161b22;
  --color-border:  #30363d;
  --color-accent:  #f97316;
  --color-text:    #e6edf3;
  --color-muted:   #8b949e;
  --color-success: #2ea043;
  --color-danger:  #da3633;
  --color-add:     #1a3a1a;
  --color-del:     #3a1a1a;
  --font-mono:     'Courier New', Courier, monospace;
}
body {
  background: var(--color-bg);
  color: var(--color-text);
  font-family: var(--font-mono);
  font-size: 0.88rem;
}
.navbar {
  background: var(--color-surface) !important;
  border-bottom: 2px solid var(--color-accent);
}
.navbar-brand {
  color: var(--color-accent) !important;
  font-weight: 700;
  font-size: 1.1rem;
  letter-spacing: 1px;
}
.nav-link { color: var(--color-text) !important; }
.nav-link:hover { color: var(--color-accent) !important; }
.badge-llm {
  background: var(--color-accent);
  color: #000;
  font-size: 0.7rem;
  padding: 2px 7px;
  border-radius: 3px;
  font-weight: bold;
  margin-left: 6px;
}
.card {
  background: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: 6px;
}
.card-header {
  background: var(--color-border);
  border-bottom: 1px solid var(--color-accent);
  font-weight: bold;
  color: var(--color-accent);
}
.table {
  color: var(--color-text);
}
.table thead th {
  background: var(--color-border);
  border-bottom: 2px solid var(--color-accent);
  color: var(--color-accent);
  font-size: 0.78rem;
  text-transform: uppercase;
  letter-spacing: 1px;
}
.table tbody tr:hover { background: rgba(249,115,22,0.05); }
.table td, .table th { border-color: var(--color-border) !important; vertical-align: middle; }
.btn-sm { font-size: 0.75rem; }
.btn-accent {
  background: var(--color-accent);
  color: #000;
  border: none;
  font-weight: bold;
}
.btn-accent:hover { background: #ea6c0a; color: #000; }
.form-control, .form-control:focus {
  background: var(--color-bg);
  border: 1px solid var(--color-border);
  color: var(--color-text);
  border-radius: 4px;
}
.form-control:focus { border-color: var(--color-accent); box-shadow: 0 0 0 0.15rem rgba(249,115,22,0.25); }
select.form-control option { background: var(--color-bg); }
.alert-success { background: #0e2a0e; border-color: var(--color-success); color: #7ee787; }
.alert-danger  { background: #2a0e0e; border-color: var(--color-danger);  color: #ff7b72; }
.alert-warning { background: #2a220e; border-color: #d29922; color: #e3b341; }
.diff-igual   { background: transparent; padding: 1px 6px; font-family: var(--font-mono); font-size: 0.8rem; }
.diff-borrado { background: var(--color-del); color: #ff7b72; padding: 1px 6px; font-family: var(--font-mono); font-size: 0.8rem; }
.diff-nuevo   { background: var(--color-add); color: #7ee787; padding: 1px 6px; font-family: var(--font-mono); font-size: 0.8rem; }
.diff-prefix  { font-weight: bold; margin-right: 4px; user-select: none; }
.candado      { color: var(--color-accent); }
.hash-val     { font-size: 0.75rem; color: var(--color-muted); word-break: break-all; }
.version-badge {
  background: var(--color-border);
  border: 1px solid var(--color-accent);
  color: var(--color-accent);
  padding: 1px 5px;
  border-radius: 3px;
  font-size: 0.75rem;
}
footer {
  background: var(--color-surface);
  border-top: 1px solid var(--color-border);
  color: var(--color-muted);
  font-size: 0.78rem;
  padding: 12px 0;
  margin-top: 40px;
}
.paginacion .page-link {
  background: var(--color-surface);
  border-color: var(--color-border);
  color: var(--color-text);
}
.paginacion .page-link:hover { background: var(--color-border); color: var(--color-accent); }
.paginacion .active .page-link { background: var(--color-accent); border-color: var(--color-accent); color: #000; }
.modal-content { background: var(--color-surface); border: 1px solid var(--color-border); color: var(--color-text); }
.modal-header  { border-bottom: 1px solid var(--color-border); }
.modal-footer  { border-top: 1px solid var(--color-border); }
label { color: var(--color-muted); font-size: 0.8rem; margin-bottom: 2px; }
textarea { min-height: 180px; }
.overflow-warning {
  background: #2a220e;
  border: 1px solid #d29922;
  color: #e3b341;
  padding: 8px 12px;
  border-radius: 4px;
  margin-bottom: 12px;
}
</style>
</head>
<body>

<!-- NAVBAR -->
<nav class="navbar navbar-expand-lg navbar-dark sticky-top">
  <a class="navbar-brand" href="index.php">
    <i class="fas fa-database mr-1"></i> AI Backup
    <span class="badge-llm">Claude</span>
  </a>
  <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navMenu">
    <span class="navbar-toggler-icon"></span>
  </button>
  <div class="collapse navbar-collapse" id="navMenu">
    <ul class="navbar-nav mr-auto">
      <li class="nav-item"><a class="nav-link" href="index.php?accion=listar"><i class="fas fa-list mr-1"></i>Ver registros</a></li>
      <?php if (es_autenticado()): ?>
      <li class="nav-item"><a class="nav-link" href="index.php?accion=formulario"><i class="fas fa-plus mr-1"></i>Agregar nuevo</a></li>
      <?php endif; ?>
      <li class="nav-item"><a class="nav-link" href="index.php?accion=buscar"><i class="fas fa-search mr-1"></i>Buscar</a></li>
    </ul>
    <ul class="navbar-nav ml-auto">
      <?php if (es_autenticado()): ?>
        <li class="nav-item"><span class="nav-link text-success"><i class="fas fa-unlock mr-1"></i>Autenticado</span></li>
        <li class="nav-item"><a class="nav-link" href="index.php?logout=1"><i class="fas fa-sign-out-alt mr-1"></i>Cerrar sesión</a></li>
      <?php else: ?>
        <li class="nav-item"><span class="nav-link text-muted"><i class="fas fa-lock mr-1"></i>Solo lectura</span></li>
      <?php endif; ?>
    </ul>
  </div>
</nav>

<div class="container-fluid mt-3 px-4">

<?php if ($post_overflow): ?>
<div class="overflow-warning">
  <i class="fas fa-exclamation-triangle mr-1"></i>
  <strong>ERROR POST SIZE:</strong> El contenido enviado excede el límite <code>post_max_size</code> del servidor
  (actualmente: <strong><?php echo ini_get('post_max_size'); ?></strong>).
  El registro NO fue guardado. Reduce el tamaño del contenido o ajusta <code>post_max_size</code> en php.ini.
</div>
<?php endif; ?>

<?php if ($mensaje !== ''): ?>
<div class="alert alert-<?php echo h($tipo_msg); ?> alert-dismissible fade show" role="alert">
  <?php echo h($mensaje); ?>
  <button type="button" class="close" data-dismiss="alert"><span>&times;</span></button>
</div>
<?php endif; ?>

<!-- ============================================================ -->
<!-- LOGIN                                                         -->
<!-- ============================================================ -->
<?php if (!es_autenticado() && $accion !== 'ver'): ?>
<div class="row justify-content-center mb-3">
  <div class="col-md-4">
    <div class="card">
      <div class="card-header"><i class="fas fa-key mr-1"></i> Acceso de escritura</div>
      <div class="card-body">
        <form method="POST">
          <div class="form-group">
            <label>Contraseña maestra</label>
            <input type="password" name="pass_maestra" class="form-control" placeholder="••••••••" autofocus>
          </div>
          <button type="submit" name="login_maestra" class="btn btn-accent btn-block">
            <i class="fas fa-sign-in-alt mr-1"></i> Entrar
          </button>
        </form>
      </div>
    </div>
  </div>
</div>
<?php endif; ?>

<!-- ============================================================ -->
<!-- LISTAR                                                        -->
<!-- ============================================================ -->
<?php if ($accion === 'listar' || $accion === 'buscar'): ?>

<div class="card mb-3">
  <div class="card-header"><i class="fas fa-filter mr-1"></i> Filtros</div>
  <div class="card-body py-2">
    <form method="GET" action="index.php">
      <input type="hidden" name="accion" value="listar">
      <div class="form-row">
        <div class="col-md-2">
          <label>Proyecto</label>
          <input type="text" name="f_proyecto" class="form-control form-control-sm" value="<?php echo h($f_proyecto); ?>">
        </div>
        <div class="col-md-2">
          <label>IA utilizada</label>
          <select name="f_ia" class="form-control form-control-sm">
            <option value="">Todas</option>
            <?php foreach ($ias_disponibles as $ia): ?>
            <option value="<?php echo h($ia); ?>" <?php echo $f_ia===$ia?'selected':''; ?>><?php echo h($ia); ?></option>
            <?php endforeach; ?>
          </select>
        </div>
        <div class="col-md-2">
          <label>Tipo</label>
          <select name="f_tipo" class="form-control form-control-sm">
            <option value="">Todos</option>
            <?php foreach (['prompt','imagen','idea','respuesta','codigo','otro'] as $t): ?>
            <option value="<?php echo $t; ?>" <?php echo $f_tipo===$t?'selected':''; ?>><?php echo ucfirst($t); ?></option>
            <?php endforeach; ?>
          </select>
        </div>
        <div class="col-md-1">
          <label>Visible</label>
          <select name="f_visible" class="form-control form-control-sm">
            <option value="todos" <?php echo $f_visible==='todos'?'selected':''; ?>>Todos</option>
            <option value="SI"    <?php echo $f_visible==='SI'?'selected':''; ?>>SI</option>
            <option value="NO"    <?php echo $f_visible==='NO'?'selected':''; ?>>NO</option>
          </select>
        </div>
        <div class="col-md-2">
          <label>Desde</label>
          <input type="date" name="f_desde" class="form-control form-control-sm" value="<?php echo h($f_desde); ?>">
        </div>
        <div class="col-md-2">
          <label>Hasta</label>
          <input type="date" name="f_hasta" class="form-control form-control-sm" value="<?php echo h($f_hasta); ?>">
        </div>
        <div class="col-md-3 mt-1">
          <label>Buscar en contenido/comentarios</label>
          <input type="text" name="f_buscar" class="form-control form-control-sm" value="<?php echo h($f_buscar); ?>">
        </div>
        <div class="col-md-2 mt-1 d-flex align-items-end">
          <button type="submit" class="btn btn-accent btn-sm mr-1"><i class="fas fa-search"></i> Filtrar</button>
          <a href="index.php" class="btn btn-secondary btn-sm"><i class="fas fa-times"></i></a>
        </div>
      </div>
    </form>
  </div>
</div>

<div class="card">
  <div class="card-header d-flex justify-content-between align-items-center">
    <span><i class="fas fa-table mr-1"></i> Registros — <?php echo $total_regs; ?> encontrados</span>
    <?php if (es_autenticado()): ?>
    <a href="index.php?accion=formulario" class="btn btn-accent btn-sm"><i class="fas fa-plus mr-1"></i>Nuevo</a>
    <?php endif; ?>
  </div>
  <div class="card-body p-0">
    <div class="table-responsive">
      <table class="table table-sm table-hover mb-0">
        <thead>
          <tr>
            <th>Fecha</th>
            <th>Proyecto</th>
            <th>IA</th>
            <th>Tipo</th>
            <th>Versión</th>
            <th>Calif.</th>
            <th>KB</th>
            <th>Archivo</th>
            <th>Vis.</th>
            <th>Acciones</th>
          </tr>
        </thead>
        <tbody>
        <?php if (empty($registros)): ?>
          <tr><td colspan="10" class="text-center text-muted py-3">Sin registros</td></tr>
        <?php endif; ?>
        <?php foreach ($registros as $r): ?>
          <tr>
            <td><?php echo h(substr($r['fecha'],0,16)); ?></td>
            <td><?php echo h($r['proyecto']); ?></td>
            <td><small><?php echo h($r['ia_utilizada']); ?></small></td>
            <td><span class="badge badge-secondary"><?php echo h($r['tipo']); ?></span></td>
            <td><span class="version-badge"><?php echo h(number_format($r['num_version'],1)); ?></span></td>
            <td><?php echo $r['calificacion'] !== null ? h(number_format($r['calificacion'],1)) : '<span class="text-muted">—</span>'; ?></td>
            <td><small><?php echo $r['tamanio'] !== null ? h(number_format($r['tamanio'],2)) : '—'; ?></small></td>
            <td><small><?php echo h($r['nombre_archivo']); ?></small></td>
            <td><?php echo $r['visible']==='SI' ? '<i class="fas fa-eye text-success"></i>' : '<i class="fas fa-eye-slash text-muted"></i>'; ?></td>
            <td style="white-space:nowrap">
              <a href="index.php?accion=ver&id=<?php echo $r['id']; ?>" class="btn btn-outline-info btn-sm" title="Ver">
                <i class="fas fa-eye"></i>
                <?php if ($r['contrasena_ver'] !== ''): ?><i class="fas fa-lock candado ml-1" title="Protegido"></i><?php endif; ?>
              </a>
              <?php if (es_autenticado()): ?>
              <a href="index.php?accion=editar&id=<?php echo $r['id']; ?>" class="btn btn-outline-warning btn-sm" title="Editar"><i class="fas fa-edit"></i></a>
              <a href="index.php?accion=nueva_version&id=<?php echo $r['id']; ?>" class="btn btn-outline-secondary btn-sm" title="Nueva versión"><i class="fas fa-code-branch"></i></a>
              <button class="btn btn-outline-danger btn-sm btn-borrar"
                data-id="<?php echo $r['id']; ?>"
                data-nombre="<?php echo h($r['nombre_archivo']); ?>"
                data-version="<?php echo h(number_format($r['num_version'],1)); ?>"
                title="Borrar">
                <i class="fas fa-trash"></i>
              </button>
              <?php endif; ?>
            </td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    </div>
  </div>
</div>

<!-- PAGINACIÓN -->
<?php if ($total_paginas > 1): ?>
<nav class="mt-3">
  <ul class="pagination pagination-sm paginacion justify-content-center flex-wrap">
    <?php for ($p = 1; $p <= $total_paginas; $p++): ?>
    <li class="page-item <?php echo $p===$pagina?'active':''; ?>">
      <a class="page-link" href="index.php?accion=listar&pagina=<?php echo $p; ?><?php echo filtros_url(); ?>"><?php echo $p; ?></a>
    </li>
    <?php endfor; ?>
  </ul>
</nav>
<?php endif; ?>

<!-- MODAL BORRAR -->
<div class="modal fade" id="modalBorrar" tabindex="-1" role="dialog">
  <div class="modal-dialog" role="document">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title text-danger"><i class="fas fa-exclamation-triangle mr-1"></i> Confirmar eliminación</h5>
        <button type="button" class="close text-light" data-dismiss="modal"><span>&times;</span></button>
      </div>
      <form method="POST">
        <div class="modal-body">
          <p>¿Estás seguro de borrar <strong id="modal-nombre"></strong> versión <strong id="modal-version"></strong>?</p>
          <p class="text-danger font-weight-bold">Esta acción NO se puede deshacer.</p>
          <div class="form-group">
            <label>Escribe <strong>BORRAR</strong> en mayúsculas para confirmar:</label>
            <input type="text" name="confirmacion_borrar" class="form-control" placeholder="BORRAR" autocomplete="off">
          </div>
          <input type="hidden" name="id_borrar" id="modal-id">
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-secondary" data-dismiss="modal">Cancelar</button>
          <button type="submit" name="confirmar_borrar" class="btn btn-danger"><i class="fas fa-trash mr-1"></i>Eliminar</button>
        </div>
      </form>
    </div>
  </div>
</div>

<?php endif; ?>

<!-- ============================================================ -->
<!-- VER REGISTRO                                                  -->
<!-- ============================================================ -->
<?php if ($accion === 'ver' && $registro_ver): ?>

<?php if (!$ver_autenticado): ?>
<div class="row justify-content-center">
  <div class="col-md-4">
    <div class="card">
      <div class="card-header"><i class="fas fa-lock mr-1 candado"></i> Registro protegido</div>
      <div class="card-body">
        <form method="POST">
          <div class="form-group">
            <label>Contraseña para ver este registro</label>
            <input type="password" name="pass_ver_registro" class="form-control" autofocus>
          </div>
          <input type="hidden" name="accion_ver" value="1">
          <button type="submit" class="btn btn-accent btn-block"><i class="fas fa-unlock mr-1"></i>Ver registro</button>
        </form>
        <a href="index.php" class="btn btn-secondary btn-block mt-2"><i class="fas fa-arrow-left mr-1"></i>Volver</a>
      </div>
    </div>
  </div>
</div>
<?php else: ?>

<div class="card mb-3">
  <div class="card-header d-flex justify-content-between align-items-center">
    <span><i class="fas fa-file-alt mr-1"></i> <?php echo h($registro_ver['nombre_archivo']); ?>
      <span class="version-badge ml-2">v<?php echo h(number_format($registro_ver['num_version'],1)); ?></span>
      <?php if ($registro_ver['contrasena_ver'] !== ''): ?><i class="fas fa-lock candado ml-2"></i><?php endif; ?>
    </span>
    <div>
      <?php if (es_autenticado()): ?>
      <a href="index.php?accion=editar&id=<?php echo $registro_ver['id']; ?>" class="btn btn-outline-warning btn-sm"><i class="fas fa-edit mr-1"></i>Editar</a>
      <?php endif; ?>
      <a href="index.php" class="btn btn-secondary btn-sm"><i class="fas fa-arrow-left mr-1"></i>Volver</a>
    </div>
  </div>
  <div class="card-body">
    <div class="row mb-2">
      <div class="col-md-2"><strong>Proyecto:</strong> <?php echo h($registro_ver['proyecto']); ?></div>
      <div class="col-md-2"><strong>IA:</strong> <?php echo h($registro_ver['ia_utilizada']); ?></div>
      <div class="col-md-2"><strong>Tipo:</strong> <span class="badge badge-secondary"><?php echo h($registro_ver['tipo']); ?></span></div>
      <div class="col-md-2"><strong>Fecha:</strong> <?php echo h($registro_ver['fecha']); ?></div>
      <div class="col-md-1"><strong>Visible:</strong> <?php echo $registro_ver['visible']; ?></div>
      <div class="col-md-2"><strong>Calificación:</strong> <?php echo $registro_ver['calificacion'] !== null ? h(number_format($registro_ver['calificacion'],2)) : '—'; ?></div>
      <div class="col-md-1"><strong>Tamaño:</strong> <?php echo $registro_ver['tamanio'] !== null ? h(number_format($registro_ver['tamanio'],2)).' KB' : '—'; ?></div>
    </div>
    <div class="row mb-2">
      <div class="col-12">
        <div class="hash-val"><i class="fas fa-fingerprint mr-1"></i><strong>MD5:</strong> <?php echo h($registro_ver['hash_md5']); ?></div>
        <div class="hash-val"><i class="fas fa-fingerprint mr-1"></i><strong>SHA1:</strong> <?php echo h($registro_ver['hash_sha1']); ?></div>
      </div>
    </div>
    <?php if ($registro_ver['comentarios'] !== ''): ?>
    <div class="mb-2"><strong>Comentarios:</strong><br><small class="text-muted"><?php echo nl2br(h($registro_ver['comentarios'])); ?></small></div>
    <?php endif; ?>
    <hr style="border-color:var(--color-border)">
    <strong>Contenido:</strong>
    <div class="mt-2">
    <?php if ($registro_ver['tipo'] === 'imagen'): ?>
      <?php if (validar_base64_imagen($registro_ver['contenido'])): ?>
        <img src="<?php echo $registro_ver['contenido']; ?>" class="img-fluid" style="max-width:100%;border:1px solid var(--color-border);">
      <?php else: ?>
        <div class="alert alert-danger">Contenido de imagen inválido o tipo MIME no permitido.</div>
      <?php endif; ?>
    <?php else: ?>
      <textarea class="form-control" rows="15" readonly><?php echo h($registro_ver['contenido']); ?></textarea>
    <?php endif; ?>
    </div>
  </div>
</div>

<?php
// Otras versiones del mismo archivo/proyecto
$stmt = mysqli_prepare($conn,"SELECT id,num_version,fecha,ia_utilizada FROM ai_backups WHERE proyecto=? AND nombre_archivo=? AND id!=? ORDER BY fecha DESC");
mysqli_stmt_bind_param($stmt,'ssi',$registro_ver['proyecto'],$registro_ver['nombre_archivo'],$registro_ver['id']);
mysqli_stmt_execute($stmt);
$res_vers = mysqli_stmt_get_result($stmt);
$otras_versiones = [];
while ($rv = mysqli_fetch_assoc($res_vers)) $otras_versiones[] = $rv;
mysqli_stmt_close($stmt);
?>

<?php if (!empty($otras_versiones)): ?>
<div class="card mb-3">
  <div class="card-header"><i class="fas fa-code-branch mr-1"></i> Otras versiones de "<?php echo h($registro_ver['nombre_archivo']); ?>"</div>
  <div class="card-body py-2">
    <div class="form-row align-items-end">
      <div class="col-auto">
        <label>Comparar versión actual con:</label>
        <select id="sel_diff" class="form-control form-control-sm">
          <?php foreach ($otras_versiones as $ov): ?>
          <option value="<?php echo $ov['id']; ?>">v<?php echo h(number_format($ov['num_version'],1)); ?> — <?php echo h(substr($ov['fecha'],0,16)); ?> — <?php echo h($ov['ia_utilizada']); ?></option>
          <?php endforeach; ?>
        </select>
      </div>
      <div class="col-auto">
        <button onclick="irDiff()" class="btn btn-accent btn-sm"><i class="fas fa-exchange-alt mr-1"></i>Ver diff</button>
      </div>
    </div>
    <ul class="list-inline mt-2 mb-0">
      <?php foreach ($otras_versiones as $ov): ?>
      <li class="list-inline-item">
        <a href="index.php?accion=ver&id=<?php echo $ov['id']; ?>" class="btn btn-outline-secondary btn-sm mb-1">
          <i class="fas fa-eye mr-1"></i>v<?php echo h(number_format($ov['num_version'],1)); ?>
        </a>
      </li>
      <?php endforeach; ?>
    </ul>
  </div>
</div>
<script>
function irDiff() {
  var id2 = document.getElementById('sel_diff').value;
  window.location = 'index.php?accion=diff&id1=<?php echo $registro_ver['id']; ?>&id2=' + id2;
}
</script>
<?php endif; ?>

<?php endif; // ver_autenticado ?>
<?php endif; // accion ver ?>

<!-- ============================================================ -->
<!-- DIFF                                                          -->
<!-- ============================================================ -->
<?php if ($accion === 'diff' && !empty($diff_resultado)): ?>
<div class="card mb-3">
  <div class="card-header"><i class="fas fa-exchange-alt mr-1"></i> Comparación de versiones — ID <?php echo (int)$_GET['id1']; ?> vs ID <?php echo (int)$_GET['id2']; ?></div>
  <div class="card-body p-0">
    <div class="p-2 mb-1" style="font-size:0.78rem">
      <span style="background:var(--color-del);color:#ff7b72;padding:2px 8px;border-radius:3px;margin-right:8px;">— Eliminado</span>
      <span style="background:var(--color-add);color:#7ee787;padding:2px 8px;border-radius:3px;">+ Agregado</span>
    </div>
    <div style="overflow-x:auto">
      <?php foreach ($diff_resultado as $linea): ?>
      <div class="diff-<?php echo $linea['tipo']; ?>">
        <?php if ($linea['tipo']==='borrado'): ?><span class="diff-prefix">−</span><?php endif; ?>
        <?php if ($linea['tipo']==='nuevo'):   ?><span class="diff-prefix">+</span><?php endif; ?>
        <?php if ($linea['tipo']==='igual'):   ?><span class="diff-prefix" style="color:var(--color-muted)"> </span><?php endif; ?>
        <?php echo h($linea['linea']); ?>
      </div>
      <?php endforeach; ?>
    </div>
  </div>
</div>
<a href="javascript:history.back()" class="btn btn-secondary btn-sm"><i class="fas fa-arrow-left mr-1"></i>Volver</a>
<?php endif; ?>

<!-- ============================================================ -->
<!-- FORMULARIO AGREGAR / EDITAR                                   -->
<!-- ============================================================ -->
<?php if ($accion === 'formulario'): ?>
<?php
$r = $registro_edicion ?? [];
$es_edicion = !empty($r['id']);
$prox_version = !empty($r['proyecto']) && !empty($r['nombre_archivo'])
    ? siguiente_version($conn, $r['proyecto'], $r['nombre_archivo'])
    : 1.0;
if ($es_edicion) $prox_version = $r['num_version'];
?>
<div class="card">
  <div class="card-header"><i class="fas fa-<?php echo $es_edicion?'edit':'plus'; ?> mr-1"></i> <?php echo $es_edicion?'Editar registro':'Nuevo registro'; ?></div>
  <div class="card-body">
    <form method="POST" enctype="multipart/form-data">
      <input type="hidden" name="id_edit" value="<?php echo (int)($r['id']??0); ?>">
      <div class="form-row">
        <div class="col-md-4 form-group">
          <label>Proyecto *</label>
          <input type="text" name="proyecto" class="form-control" required value="<?php echo h($r['proyecto']??''); ?>">
        </div>
        <div class="col-md-3 form-group">
          <label>IA utilizada *</label>
          <select name="ia_utilizada" class="form-control">
            <?php foreach (['ChatGPT','Claude','Gemini','Grok','Cohere','Llama','otro'] as $ia): ?>
            <option value="<?php echo $ia; ?>" <?php echo ($r['ia_utilizada']??'')===$ia?'selected':''; ?>><?php echo $ia; ?></option>
            <?php endforeach; ?>
          </select>
        </div>
        <div class="col-md-2 form-group">
          <label>Tipo *</label>
          <select name="tipo" class="form-control" id="sel_tipo" onchange="toggleImagen()">
            <?php foreach (['prompt','imagen','idea','respuesta','codigo','otro'] as $t): ?>
            <option value="<?php echo $t; ?>" <?php echo ($r['tipo']??'prompt')===$t?'selected':''; ?>><?php echo ucfirst($t); ?></option>
            <?php endforeach; ?>
          </select>
        </div>
        <div class="col-md-3 form-group">
          <label>Nombre de archivo *</label>
          <input type="text" name="nombre_archivo" class="form-control" required value="<?php echo h($r['nombre_archivo']??''); ?>">
        </div>
      </div>
      <div class="form-row">
        <div class="col-md-2 form-group">
          <label>Versión</label>
          <input type="number" name="num_version" class="form-control" step="0.000001" value="<?php echo h(number_format($prox_version,6)); ?>">
        </div>
        <div class="col-md-2 form-group">
          <label>Calificación (0-10)</label>
          <input type="number" name="calificacion" class="form-control" step="0.01" min="0" max="10" value="<?php echo h($r['calificacion']??''); ?>">
        </div>
        <div class="col-md-2 form-group">
          <label>Visible</label>
          <select name="visible" class="form-control">
            <option value="SI" <?php echo ($r['visible']??'SI')==='SI'?'selected':''; ?>>SI</option>
            <option value="NO" <?php echo ($r['visible']??'')==='NO'?'selected':''; ?>>NO</option>
          </select>
        </div>
        <div class="col-md-4 form-group">
          <label>Contraseña individual (opcional)</label>
          <input type="password" name="contrasena_ver" class="form-control" placeholder="Dejar vacío = sin contraseña">
          <small class="text-muted">Si se llena, se hasheará antes de guardar</small>
        </div>
      </div>

      <!-- Contenido texto -->
      <div id="div_contenido_texto" class="form-group">
        <label>Contenido</label>
        <div id="post-size-warning" class="overflow-warning d-none">
          <i class="fas fa-exclamation-triangle mr-1"></i>
          <strong>Advertencia:</strong> El contenido está cerca o supera el límite <code>post_max_size</code> del servidor (<?php echo ini_get('post_max_size'); ?>).
          Es posible que el registro no se guarde correctamente.
        </div>
        <textarea name="contenido" class="form-control" id="txt_contenido" oninput="checkPostSize()"><?php echo h($r['contenido']??''); ?></textarea>
      </div>

      <!-- Contenido imagen -->
      <div id="div_contenido_imagen" class="form-group d-none">
        <label>Imagen — sube un archivo o pega base64</label>
        <input type="file" name="imagen_file" class="form-control-file mb-2" accept="image/jpeg,image/png,image/webp,image/gif">
        <small class="text-muted d-block mb-1">O pega directamente el string base64 (data:image/...;base64,...)</small>
        <textarea name="contenido" class="form-control" id="txt_contenido_img" rows="4"><?php echo ($r['tipo']??'')==='imagen' ? h($r['contenido']??'') : ''; ?></textarea>
      </div>

      <div class="form-group">
        <label>Comentarios</label>
        <textarea name="comentarios" class="form-control" rows="3"><?php echo h($r['comentarios']??''); ?></textarea>
      </div>

      <div class="d-flex">
        <button type="submit" name="guardar_registro" class="btn btn-accent mr-2">
          <i class="fas fa-save mr-1"></i><?php echo $es_edicion?'Actualizar':'Guardar'; ?>
        </button>
        <a href="index.php" class="btn btn-secondary"><i class="fas fa-times mr-1"></i>Cancelar</a>
      </div>
    </form>
  </div>
</div>

<script>
var postMaxBytes = <?php echo post_max_size_bytes(); ?>;
function checkPostSize() {
  var txt = document.getElementById('txt_contenido');
  if (!txt) return;
  var bytes = new Blob([txt.value]).size;
  var warn = document.getElementById('post-size-warning');
  if (bytes > postMaxBytes * 0.85) {
    warn.classList.remove('d-none');
  } else {
    warn.classList.add('d-none');
  }
}
function toggleImagen() {
  var tipo = document.getElementById('sel_tipo').value;
  var divTxt = document.getElementById('div_contenido_texto');
  var divImg = document.getElementById('div_contenido_imagen');
  if (tipo === 'imagen') {
    divTxt.classList.add('d-none');
    divImg.classList.remove('d-none');
  } else {
    divTxt.classList.remove('d-none');
    divImg.classList.add('d-none');
  }
}
toggleImagen();
</script>
<?php endif; ?>

</div><!-- /container -->

<!-- FOOTER -->
<footer>
  <div class="container-fluid px-4">
    <div class="d-flex justify-content-between align-items-center">
      <span>⚠️ Este sistema <strong>NO</strong> hace respaldo de su propia base de datos. Respaldar MySQL es tu responsabilidad. Un respaldo que no existe no es un respaldo.</span>
      <span>AI Backup System — Vibecoding México — <a href="https://vibecodingmexico.com" target="_blank" style="color:var(--color-accent)">vibecodingmexico.com</a></span>
    </div>
  </div>
</footer>

<script src="https://cdn.jsdelivr.net/npm/jquery@3.6.4/dist/jquery.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js"></script>
<script>
// Modal borrar
document.querySelectorAll('.btn-borrar').forEach(function(btn) {
  btn.addEventListener('click', function() {
    document.getElementById('modal-id').value      = this.dataset.id;
    document.getElementById('modal-nombre').textContent  = this.dataset.nombre;
    document.getElementById('modal-version').textContent = this.dataset.version;
    $('#modalBorrar').modal('show');
  });
});
</script>
</body>
</html>

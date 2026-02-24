<?php
/**
 * SISTEMA DE RESPALDO DE PROMPTS IA - "VibeBackup"
 * Único Archivo: index.php
 * Stack: PHP 8.x Procedural, MySQL/MariaDB, Bootstrap 4.6
 */

// --- CONFIGURACIÓN – EDITA ESTO ANTES DE USAR ---
define('PASS_MAESTRA', 'admin123');         // Contraseña para CRUD
define('PASS_REGISTROS', 'secreto123');     // Contraseña para registros cifrados
define('IPS_PERMITIDAS', ['127.0.0.1', '::1', '192.168.1.1']); // Agrega tu IP real aquí

// Configuración de Base de Datos
$db_host = 'localhost';
$db_user = 'root';
$db_pass = '';
$db_name = 'ai_backups_db';

// --- HEADERS ANTI-CACHÉ ---
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: Sat, 01 Jan 2000 00:00:00 GMT');

session_start();

// --- SEGURIDAD DE IP ---
$user_ip = $_SERVER['REMOTE_ADDR'];
if (!in_array($user_ip, IPS_PERMITIDAS)) {
    die("<div style='font-family:sans-serif; text-align:center; margin-top:50px;'>
            <h2>Acceso no autorizado</h2>
            <p>Tu IP ($user_ip) no está en la lista blanca.</p>
         </div>");
}

// --- CONEXIÓN Y AUTO-INSTALACIÓN ---
$conn = mysqli_connect($db_host, $db_user, $db_pass);
if (!$conn) die("Error de conexión: " . mysqli_connect_error());

mysqli_query($conn, "CREATE DATABASE IF NOT EXISTS `$db_name` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
mysqli_select_db($conn, $db_name);

$createTableSQL = "CREATE TABLE IF NOT EXISTS ai_backups (
    id INT AUTO_INCREMENT PRIMARY KEY,
    proyecto VARCHAR(100),
    ia_utilizada VARCHAR(50),
    tipo VARCHAR(20),
    contenido LONGTEXT,
    nombre_archivo VARCHAR(150),
    num_version DECIMAL(14,6),
    comentarios LONGTEXT,
    calificacion DECIMAL(14,6),
    visible VARCHAR(2),
    fecha DATETIME,
    contrasena_ver VARCHAR(255),
    tamanio DECIMAL(14,6),
    hash_md5 VARCHAR(32),
    hash_sha1 VARCHAR(40)
) ENGINE=InnoDB;";
mysqli_query($conn, $createTableSQL);

// --- LÓGICA DE SESIÓN ---
if (isset($_POST['login_maestro'])) {
    if ($_POST['pass'] === PASS_MAESTRA) {
        $_SESSION['auth'] = true;
    } else {
        $error = "Contraseña maestra incorrecta.";
    }
}
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: index.php");
    exit;
}

$is_admin = isset($_SESSION['auth']) && $_SESSION['auth'] === true;

// --- GESTIÓN DE POST_MAX_SIZE ---
if ($_SERVER['REQUEST_METHOD'] == 'POST' && empty($_POST) && $_SERVER['CONTENT_LENGTH'] > 0) {
    $max_p = ini_get('post_max_size');
    $error = "¡Error de carga! Los datos exceden el límite del servidor ($max_p). Reduce el tamaño de la imagen o aumenta post_max_size en php.ini.";
}

// --- PROCESAMIENTO DE ACCIONES (GUARDAR/BORRAR) ---
if ($is_admin && isset($_POST['action'])) {
    if ($_POST['action'] == 'save') {
        $id = (int)$_POST['id'];
        $proyecto = mysqli_real_escape_string($conn, $_POST['proyecto']);
        $ia = mysqli_real_escape_string($conn, $_POST['ia_utilizada']);
        $tipo = mysqli_real_escape_string($conn, $_POST['tipo']);
        $nombre = mysqli_real_escape_string($conn, $_POST['nombre_archivo']);
        $version = (float)$_POST['num_version'];
        $coments = mysqli_real_escape_string($conn, $_POST['comentarios']);
        $nota = (float)$_POST['calificacion'];
        $visible = $_POST['visible'] == 'NO' ? 'NO' : 'SI';
        $pass_reg = $_POST['contrasena_ver'];
        
        // Manejo de Contenido e Imagen
        $contenido = $_POST['contenido'];
        if ($tipo == 'imagen' && !empty($_FILES['file_img']['tmp_name'])) {
            $img_data = file_get_contents($_FILES['file_img']['tmp_name']);
            $finfo = new finfo(FILEINFO_MIME_TYPE);
            $mime = $finfo->buffer($img_data);
            $contenido = "data:$mime;base64," . base64_encode($img_data);
        }

        $tamanio = strlen($contenido) / 1024;
        $md5 = md5($contenido);
        $sha1 = sha1($contenido);

        if ($id > 0) {
            $sql = "UPDATE ai_backups SET proyecto=?, ia_utilizada=?, tipo=?, contenido=?, nombre_archivo=?, num_version=?, comentarios=?, calificacion=?, visible=?, tamanio=?, hash_md5=?, hash_sha1=?";
            $params = [$proyecto, $ia, $tipo, $contenido, $nombre, $version, $coments, $nota, $visible, $tamanio, $md5, $sha1];
            $types = "sssssdsdsdss";
            if (!empty($pass_reg)) {
                $sql .= ", contrasena_ver=?";
                $params[] = password_hash($pass_reg, PASSWORD_DEFAULT);
                $types .= "s";
            }
            $sql .= " WHERE id=?";
            $params[] = $id;
            $types .= "i";
        } else {
            $pass_hash = !empty($pass_reg) ? password_hash($pass_reg, PASSWORD_DEFAULT) : '';
            $sql = "INSERT INTO ai_backups (proyecto, ia_utilizada, tipo, contenido, nombre_archivo, num_version, comentarios, calificacion, visible, fecha, contrasena_ver, tamanio, hash_md5, hash_sha1) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), ?, ?, ?, ?)";
            $params = [$proyecto, $ia, $tipo, $contenido, $nombre, $version, $coments, $nota, $visible, $pass_hash, $tamanio, $md5, $sha1];
            $types = "sssssdsdsssdss";
        }
        
        $stmt = mysqli_prepare($conn, $sql);
        mysqli_stmt_bind_param($stmt, $types, ...$params);
        mysqli_stmt_execute($stmt);
        header("Location: index.php?msg=saved");
        exit;
    }

    if ($_POST['action'] == 'delete' && $_POST['confirm_delete'] === 'BORRAR') {
        $id = (int)$_POST['id_delete'];
        mysqli_query($conn, "DELETE FROM ai_backups WHERE id=$id");
        header("Location: index.php?msg=deleted");
        exit;
    }
}

// --- HELPER DIFF ---
function simpleDiff($old, $new) {
    $oldLines = explode("\n", $old);
    $newLines = explode("\n", $new);
    $diff = "";
    $max = max(count($oldLines), count($newLines));
    for ($i = 0; $i < $max; $i++) {
        $lineOld = $oldLines[$i] ?? '';
        $lineNew = $newLines[$i] ?? '';
        if ($lineOld !== $lineNew) {
            if ($lineOld) $diff .= "<div style='background:#ffeef0; color:#b31d28;'>- ".htmlspecialchars($lineOld)."</div>";
            if ($lineNew) $diff .= "<div style='background:#e6ffed; color:#22863a;'>+ ".htmlspecialchars($lineNew)."</div>";
        } else {
            $diff .= "<div>  ".htmlspecialchars($lineOld)."</div>";
        }
    }
    return $diff;
}

// --- VISTAS ---
$view = $_GET['view'] ?? 'list';
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>AI Backup System</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@5.15.4/css/all.min.css">
    <style>
        body { background: #f8f9fa; font-size: 0.9rem; }
        .navbar-brand { font-weight: bold; }
        .card { box-shadow: 0 2px 4px rgba(0,0,0,0.05); }
        .diff-container { background: #fff; border: 1px solid #ddd; padding: 10px; font-family: monospace; white-space: pre-wrap; font-size: 12px; }
        .img-preview { max-width: 100%; border: 2px solid #ddd; }
        .locked-content { filter: blur(4px); user-select: none; }
    </style>
</head>
<body>

<nav class="navbar navbar-expand-lg navbar-dark bg-dark sticky-top">
    <div class="container">
        <a class="navbar-brand" href="index.php"><i class="fas fa-robot"></i> Gemini-3-Flash | Backup System</a>
        <div class="navbar-text ml-auto">
            <?php if($is_admin): ?>
                <span class="badge badge-success">Admin Autenticado</span>
                <a href="?logout=1" class="btn btn-outline-light btn-sm ml-2">Cerrar Sesión</a>
            <?php else: ?>
                <span class="badge badge-secondary">Solo Lectura</span>
                <button class="btn btn-primary btn-sm ml-2" data-toggle="modal" data-target="#loginModal">Login</button>
            <?php endif; ?>
        </div>
    </div>
</nav>

<div class="container mt-4 mb-5">
    <?php if(isset($error)): ?>
        <div class="alert alert-danger"><?= $error ?></div>
    <?php endif; ?>

    <div class="row mb-3">
        <div class="col">
            <a href="index.php" class="btn btn-secondary"><i class="fas fa-list"></i> Ver registros</a>
            <?php if($is_admin): ?>
                <a href="?view=edit" class="btn btn-success"><i class="fas fa-plus"></i> Agregar nuevo</a>
            <?php endif; ?>
        </div>
    </div>

    <?php if ($view == 'list'): ?>
        <form class="card p-3 mb-4 bg-light shadow-sm" method="GET">
            <div class="form-row">
                <div class="col-md-3">
                    <input type="text" name="q" class="form-control form-control-sm" placeholder="Buscar texto..." value="<?= htmlspecialchars($_GET['q'] ?? '') ?>">
                </div>
                <div class="col-md-2">
                    <select name="ia" class="form-control form-control-sm">
                        <option value="">Todas las IAs</option>
                        <?php 
                        $ias = mysqli_query($conn, "SELECT DISTINCT ia_utilizada FROM ai_backups");
                        while($row_ia = mysqli_fetch_assoc($ias)) echo "<option value='{$row_ia['ia_utilizada']}'>{$row_ia['ia_utilizada']}</option>";
                        ?>
                    </select>
                </div>
                <div class="col-md-2">
                    <select name="visible" class="form-control form-control-sm">
                        <option value="SI" <?= ($_GET['visible']??'')=='SI'?'selected':'' ?>>Visibles</option>
                        <option value="NO" <?= ($_GET['visible']??'')=='NO'?'selected':'' ?>>Ocultos</option>
                        <option value="ALL" <?= ($_GET['visible']??'')=='ALL'?'selected':'' ?>>Todos</option>
                    </select>
                </div>
                <div class="col-md-2">
                    <button type="submit" class="btn btn-sm btn-block btn-info">Filtrar</button>
                </div>
            </div>
        </form>

        <?php
        $where = "1=1";
        if (!isset($_GET['visible']) || $_GET['visible'] == 'SI') $where .= " AND visible = 'SI'";
        elseif ($_GET['visible'] == 'NO') $where .= " AND visible = 'NO'";

        if (!empty($_GET['q'])) {
            $q = mysqli_real_escape_string($conn, $_GET['q']);
            $where .= " AND (proyecto LIKE '%$q%' OR contenido LIKE '%$q%' OR comentarios LIKE '%$q%')";
        }
        if (!empty($_GET['ia'])) {
            $ia_f = mysqli_real_escape_string($conn, $_GET['ia']);
            $where .= " AND ia_utilizada = '$ia_f'";
        }

        $limit = 10;
        $page = (int)($_GET['p'] ?? 1);
        $offset = ($page - 1) * $limit;
        
        $count_res = mysqli_query($conn, "SELECT COUNT(*) as total FROM ai_backups WHERE $where");
        $total_rows = mysqli_fetch_assoc($count_res)['total'];
        $total_pages = ceil($total_rows / $limit);

        $res = mysqli_query($conn, "SELECT * FROM ai_backups WHERE $where ORDER BY fecha DESC LIMIT $offset, $limit");
        ?>

        <div class="table-responsive bg-white shadow-sm">
            <table class="table table-hover table-sm mb-0">
                <thead class="thead-dark">
                    <tr>
                        <th>Fecha</th>
                        <th>Proyecto</th>
                        <th>IA</th>
                        <th>Tipo</th>
                        <th>Versión</th>
                        <th>Nota</th>
                        <th>Tamaño</th>
                        <th>Acciones</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while($r = mysqli_fetch_assoc($res)): ?>
                    <tr>
                        <td><?= substr($r['fecha'], 0, 16) ?></td>
                        <td><strong><?= htmlspecialchars($r['proyecto']) ?></strong></td>
                        <td><?= htmlspecialchars($r['ia_utilizada']) ?></td>
                        <td><span class="badge badge-info"><?= $r['tipo'] ?></span></td>
                        <td>v.<?= number_format($r['num_version'], 2) ?></td>
                        <td><?= number_format($r['calificacion'], 1) ?></td>
                        <td><?= round($r['tamanio'], 2) ?> KB</td>
                        <td>
                            <div class="btn-group">
                                <a href="?view=details&id=<?= $r['id'] ?>" class="btn btn-sm btn-primary"><i class="fas fa-eye"></i></a>
                                <?php if($is_admin): ?>
                                    <a href="?view=edit&id=<?= $r['id'] ?>" class="btn btn-sm btn-warning"><i class="fas fa-edit"></i></a>
                                    <button class="btn btn-sm btn-danger" onclick="confirmDelete(<?= $r['id'] ?>, '<?= htmlspecialchars($r['nombre_archivo']) ?>', '<?= $r['num_version'] ?>')"><i class="fas fa-trash"></i></button>
                                    <a href="?view=edit&duplicate=<?= $r['id'] ?>" class="btn btn-sm btn-success" title="Nueva Versión"><i class="fas fa-copy"></i></a>
                                <?php endif; ?>
                            </div>
                            <?php if(!empty($r['contrasena_ver'])): ?>
                                <i class="fas fa-lock text-muted ml-1"></i>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </div>

        <nav class="mt-3">
            <ul class="pagination pagination-sm justify-content-center">
                <?php for($i=1; $i<=$total_pages; $i++): ?>
                    <li class="page-item <?= $i==$page?'active':'' ?>"><a class="page-link" href="?p=<?= $i ?>&q=<?= $_GET['q']??'' ?>&visible=<?= $_GET['visible']??'' ?>"><?= $i ?></a></li>
                <?php endfor; ?>
            </ul>
        </nav>

    <?php elseif ($view == 'details'): 
        $id = (int)$_GET['id'];
        $res = mysqli_query($conn, "SELECT * FROM ai_backups WHERE id = $id");
        $data = mysqli_fetch_assoc($res);
        
        $access_granted = empty($data['contrasena_ver']);
        if (isset($_POST['unlock_pass'])) {
            if (password_verify($_POST['unlock_pass'], $data['contrasena_ver'])) {
                $access_granted = true;
            } else {
                $pass_error = "Contraseña de registro incorrecta.";
            }
        }
    ?>
        <div class="card">
            <div class="card-header bg-dark text-white d-flex justify-content-between">
                <span>Detalles: <?= htmlspecialchars($data['nombre_archivo']) ?> (v<?= $data['num_version'] ?>)</span>
                <span>ID: #<?= $data['id'] ?></span>
            </div>
            <div class="card-body">
                <?php if (!$access_granted): ?>
                    <div class="text-center py-5">
                        <i class="fas fa-lock fa-3x text-muted mb-3"></i>
                        <h5>Contenido Protegido</h5>
                        <form method="POST" class="form-inline justify-content-center mt-3">
                            <input type="password" name="unlock_pass" class="form-control mr-2" placeholder="Contraseña de este registro">
                            <button type="submit" class="btn btn-primary">Desbloquear</button>
                        </form>
                        <?php if(isset($pass_error)) echo "<p class='text-danger mt-2'>$pass_error</p>"; ?>
                    </div>
                <?php else: ?>
                    <div class="row">
                        <div class="col-md-8">
                            <h6><i class="fas fa-file-alt"></i> Contenido:</h6>
                            <?php if($data['tipo'] == 'imagen'): 
                                if(strpos($data['contenido'], 'data:image') === 0): ?>
                                    <img src="<?= $data['contenido'] ?>" class="img-preview mb-3">
                                <?php else: echo "<div class='alert alert-warning'>Formato de imagen base64 inválido.</div>"; endif; ?>
                            <?php else: ?>
                                <textarea class="form-control bg-light" rows="12" readonly><?= htmlspecialchars($data['contenido']) ?></textarea>
                            <?php endif; ?>
                            
                            <h6 class="mt-4"><i class="fas fa-comments"></i> Comentarios:</h6>
                            <div class="p-3 bg-light border rounded mb-3"><?= nl2br(htmlspecialchars($data['comentarios'])) ?></div>

                            <?php
                            $comp_id = (int)($_GET['compare'] ?? 0);
                            if ($comp_id > 0):
                                $res_c = mysqli_query($conn, "SELECT * FROM ai_backups WHERE id = $comp_id");
                                $data_c = mysqli_fetch_assoc($res_c);
                                echo "<h6 class='mt-4 text-primary'><i class='fas fa-exchange-alt'></i> Diferencia con Versión ".$data_c['num_version'].":</h6>";
                                echo "<div class='diff-container'>" . simpleDiff($data_c['contenido'], $data['contenido']) . "</div>";
                            endif;
                            ?>
                        </div>
                        <div class="col-md-4">
                            <div class="list-group">
                                <div class="list-group-item active">Metadatos</div>
                                <div class="list-group-item"><b>Proyecto:</b> <?= htmlspecialchars($data['proyecto']) ?></div>
                                <div class="list-group-item"><b>IA:</b> <?= htmlspecialchars($data['ia_utilizada']) ?></div>
                                <div class="list-group-item"><b>MD5:</b> <small class="text-muted"><?= $data['hash_md5'] ?></small></div>
                                <div class="list-group-item"><b>SHA1:</b> <small class="text-muted"><?= $data['hash_sha1'] ?></small></div>
                                <div class="list-group-item"><b>Tamaño:</b> <?= round($data['tamanio'], 2) ?> KB</div>
                            </div>

                            <div class="list-group mt-3">
                                <div class="list-group-item bg-info text-white">Versiones del mismo proyecto</div>
                                <?php
                                $p_esc = mysqli_real_escape_string($conn, $data['proyecto']);
                                $n_esc = mysqli_real_escape_string($conn, $data['nombre_archivo']);
                                $versions = mysqli_query($conn, "SELECT id, num_version, fecha FROM ai_backups WHERE proyecto='$p_esc' AND nombre_archivo='$n_esc' AND id != $id ORDER BY num_version DESC");
                                while($v = mysqli_fetch_assoc($versions)): ?>
                                    <div class="list-group-item d-flex justify-content-between align-items-center">
                                        <a href="?view=details&id=<?= $v['id'] ?>">v.<?= $v['num_version'] ?> (<?= substr($v['fecha'],0,10) ?>)</a>
                                        <a href="?view=details&id=<?= $id ?>&compare=<?= $v['id'] ?>" class="btn btn-xs btn-outline-info p-0 px-1" title="Comparar con esta">Diff</a>
                                    </div>
                                <?php endwhile; ?>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </div>

    <?php elseif ($view == 'edit' && $is_admin): 
        $id = (int)($_GET['id'] ?? 0);
        $dup_id = (int)($_GET['duplicate'] ?? 0);
        $data = ['id'=>0, 'proyecto'=>'', 'ia_utilizada'=>'ChatGPT', 'tipo'=>'prompt', 'contenido'=>'', 'nombre_archivo'=>'backup_'.date('Ymd'), 'num_version'=>1.0, 'comentarios'=>'', 'calificacion'=>10.0, 'visible'=>'SI'];

        if ($id > 0) {
            $res = mysqli_query($conn, "SELECT * FROM ai_backups WHERE id = $id");
            $data = mysqli_fetch_assoc($res);
        } elseif ($dup_id > 0) {
            $res = mysqli_query($conn, "SELECT * FROM ai_backups WHERE id = $dup_id");
            $data = mysqli_fetch_assoc($res);
            $data['id'] = 0; // Nuevo registro
            $data['num_version'] += 1.0;
            $data['contenido'] = ''; // Limpiar para nueva versión
        }
    ?>
        <div class="card shadow">
            <div class="card-header bg-success text-white">Formulario de Registro</div>
            <div class="card-body">
                <form method="POST" enctype="multipart/form-data">
                    <input type="hidden" name="action" value="save">
                    <input type="hidden" name="id" value="<?= $data['id'] ?>">
                    <div class="row">
                        <div class="col-md-6 form-group">
                            <label>Proyecto</label>
                            <input type="text" name="proyecto" class="form-control" value="<?= htmlspecialchars($data['proyecto']) ?>" required>
                        </div>
                        <div class="col-md-3 form-group">
                            <label>IA Utilizada</label>
                            <select name="ia_utilizada" class="form-control">
                                <?php foreach(['ChatGPT', 'Claude', 'Gemini', 'Grok', 'Cohere', 'Llama', 'Otro'] as $ia): ?>
                                    <option <?= $data['ia_utilizada']==$ia?'selected':'' ?>><?= $ia ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="col-md-3 form-group">
                            <label>Tipo</label>
                            <select name="tipo" id="tipo_backup" class="form-control" onchange="toggleContentInput()">
                                <?php foreach(['prompt', 'imagen', 'idea', 'respuesta', 'codigo', 'otro'] as $t): ?>
                                    <option <?= $data['tipo']==$t?'selected':'' ?>><?= $t ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Nombre de Archivo / Identificador</label>
                        <input type="text" name="nombre_archivo" class="form-control" value="<?= htmlspecialchars($data['nombre_archivo']) ?>" required>
                    </div>
                    <div class="form-group" id="container_texto">
                        <label>Contenido (Texto / Código / Prompt)</label>
                        <textarea name="contenido" id="contenido_txt" class="form-control" rows="8"><?= htmlspecialchars($data['contenido']) ?></textarea>
                    </div>
                    <div class="form-group d-none" id="container_imagen">
                        <label>Subir Imagen (Se convertirá a Base64)</label>
                        <input type="file" name="file_img" class="form-control-file">
                        <small class="text-muted">O pega el string Base64 en el área de contenido arriba.</small>
                    </div>
                    <div class="row">
                        <div class="col-md-3 form-group">
                            <label>Versión</label>
                            <input type="number" step="0.000001" name="num_version" class="form-control" value="<?= $data['num_version'] ?>">
                        </div>
                        <div class="col-md-3 form-group">
                            <label>Calificación (0-10)</label>
                            <input type="number" step="0.1" name="calificacion" class="form-control" value="<?= $data['calificacion'] ?>">
                        </div>
                        <div class="col-md-3 form-group">
                            <label>Visible</label>
                            <select name="visible" class="form-control">
                                <option value="SI" <?= $data['visible']=='SI'?'selected':'' ?>>SI</option>
                                <option value="NO" <?= $data['visible']=='NO'?'selected':'' ?>>NO (Oculto)</option>
                            </select>
                        </div>
                        <div class="col-md-3 form-group">
                            <label>Contraseña Individual (Opcional)</label>
                            <input type="password" name="contrasena_ver" class="form-control" placeholder="Solo para cambiarla">
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Comentarios adicionales</label>
                        <textarea name="comentarios" class="form-control" rows="3"><?= htmlspecialchars($data['comentarios']) ?></textarea>
                    </div>
                    <hr>
                    <button type="submit" class="btn btn-primary btn-lg">Guardar Respaldo</button>
                </form>
            </div>
        </div>
        <script>
            function toggleContentInput() {
                let tipo = document.getElementById('tipo_backup').value;
                document.getElementById('container_imagen').classList.toggle('d-none', tipo !== 'imagen');
            }
            window.onload = toggleContentInput;
        </script>
    <?php endif; ?>
</div>

<footer class="footer mt-auto py-3 bg-light border-top">
    <div class="container text-center">
        <small class="text-muted">⚠️ Este sistema NO hace respaldo de su propia base de datos. Respaldar MySQL es tu responsabilidad. Un respaldo que no existe no es un respaldo.</small>
    </div>
</footer>

<div class="modal fade" id="loginModal" tabindex="-1">
    <div class="modal-dialog modal-sm">
        <form class="modal-content" method="POST">
            <div class="modal-header"><h5>Acceso Maestro</h5></div>
            <div class="modal-body">
                <input type="password" name="pass" class="form-control" placeholder="Contraseña Maestra" required>
            </div>
            <div class="modal-footer">
                <button type="submit" name="login_maestro" class="btn btn-primary btn-block">Entrar</button>
            </div>
        </form>
    </div>
</div>

<div class="modal fade" id="deleteModal" tabindex="-1">
    <div class="modal-dialog">
        <form class="modal-content" method="POST">
            <div class="modal-header bg-danger text-white"><h5>Confirmar Eliminación</h5></div>
            <div class="modal-body">
                <input type="hidden" name="action" value="delete">
                <input type="hidden" name="id_delete" id="id_delete">
                <p id="delete_msg"></p>
                <p>Escribe <strong>BORRAR</strong> en mayúsculas para confirmar:</p>
                <input type="text" name="confirm_delete" class="form-control" required autocomplete="off">
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-dismiss="modal">Cancelar</button>
                <button type="submit" class="btn btn-danger">Borrar permanentemente</button>
            </div>
        </form>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/jquery@3.5.1/dist/jquery.slim.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js"></script>
<script>
    function confirmDelete(id, nombre, version) {
        document.getElementById('id_delete').value = id;
        document.getElementById('delete_msg').innerHTML = "¿Estás seguro de borrar <strong>" + nombre + "</strong> versión <strong>" + version + "</strong>? Esta acción no se puede deshacer.";
        $('#deleteModal').modal('show');
    }
</script>
</body>
</html>

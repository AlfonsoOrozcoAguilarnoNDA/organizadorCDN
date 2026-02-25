<?php
/**
 * Sistema de Respaldo de Prompts IA
 * Archivo único: index.php
 * PHP 8.x Procedural - Sin frameworks

 * El ganador es Kimi si quieres algo funcional ya pero había que editar los tipos de binds.
 * Eso lo hice yo a mano en kimi2.php , no uses kimi.php no uses este archivo 
 * 
 * CREATE TABLE SQL:
 * 
 * CREATE TABLE IF NOT EXISTS ai_backups (
 *     id INT AUTO_INCREMENT PRIMARY KEY,
 *     proyecto VARCHAR(100),
 *     ia_utilizada VARCHAR(50),
 *     tipo VARCHAR(20),
 *     contenido LONGTEXT,
 *     nombre_archivo VARCHAR(150),
 *     num_version DECIMAL(14,6),
 *     comentarios LONGTEXT,
 *     calificacion DECIMAL(14,6),
 *     visible VARCHAR(2),
 *     fecha DATETIME,
 *     contrasena_ver VARCHAR(255),
 *     tamanio DECIMAL(14,6),
 *     hash_md5 VARCHAR(32),
 *     hash_sha1 VARCHAR(40),
 *     INDEX idx_proyecto (proyecto),
 *     INDEX idx_tipo (tipo),
 *     INDEX idx_visible (visible),
 *     INDEX idx_fecha (fecha)
 * ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
 */

// --- CONFIGURACIÓN — edita esto antes de usar ---
define('PASS_MAESTRA', 'tu_contrasena_maestra_aqui_cambiar_urgente'); // para agregar, editar y borrar
define('PASS_REGISTROS', 'tu_contrasena_registros_default'); // contraseña default para registros protegidos (opcional)
define('IPS_PERMITIDAS', ['127.0.0.1', '::1']); // agrega tus IPs aquí

// Configuración de base de datos
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_NAME', 'ai_backup_system');

// Iniciar sesión
session_start();

// Headers anti-caché
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: Sat, 01 Jan 2000 00:00:00 GMT');

// Verificación de IP
$ip_visitante = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
if (!in_array($ip_visitante, IPS_PERMITIDAS)) {
    die('<html><head><title>Acceso Denegado</title></head><body style="font-family:Arial;text-align:center;padding:50px;"><h1>🚫 Acceso no autorizado</h1><p>Tu IP (' . htmlspecialchars($ip_visitante) . ') no está en la lista de permitidas.</p></body></html>');
}

// Conexión a base de datos
$mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if ($mysqli->connect_error) {
    die('Error de conexión: ' . $mysqli->connect_error);
}
$mysqli->set_charset("utf8mb4");

// Crear tabla si no existe
$create_table_sql = "CREATE TABLE IF NOT EXISTS ai_backups (
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
    hash_sha1 VARCHAR(40),
    INDEX idx_proyecto (proyecto),
    INDEX idx_tipo (tipo),
    INDEX idx_visible (visible),
    INDEX idx_fecha (fecha)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";

$mysqli->query($create_table_sql);

// Verificar si hay datos POST pero $_POST está vacío (problema de tamaño)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($_POST) && empty($_FILES)) {
    $post_max = ini_get('post_max_size');
    $error_tamano = true;
}

// Funciones auxiliares
function estaAutenticado() {
    return isset($_SESSION['auth']) && $_SESSION['auth'] === true;
}

function requerirAuth() {
    if (!estaAutenticado()) {
        header('Location: ?action=login');
        exit;
    }
}

function calcularHashes($contenido) {
    return [
        'md5' => md5($contenido),
        'sha1' => sha1($contenido),
        'tamanio' => round(strlen($contenido) / 1024, 6)
    ];
}

function validarBase64Imagen($base64) {
    $pattern = '/^data:image\/(jpeg|jpg|png|webp|gif);base64,/i';
    return preg_match($pattern, $base64);
}

function limpiarOutput($string) {
    return htmlspecialchars($string ?? '', ENT_QUOTES, 'UTF-8');
}

// Procesar acciones
$action = $_GET['action'] ?? 'list';
$mensaje = '';
$error = '';

// Login
if ($action === 'login') {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        if (isset($_POST['pass_maestra']) && $_POST['pass_maestra'] === PASS_MAESTRA) {
            $_SESSION['auth'] = true;
            header('Location: ?');
            exit;
        } else {
            $error = "Contraseña incorrecta";
        }
    }
}

// Logout
if ($action === 'logout') {
    session_destroy();
    header('Location: ?');
    exit;
}

// Borrar registro
if ($action === 'delete' && isset($_GET['id'])) {
    requerirAuth();
    
    $id = intval($_GET['id']);
    
    // Obtener info para confirmación
    $stmt = $mysqli->prepare("SELECT nombre_archivo, num_version FROM ai_backups WHERE id = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $result = $stmt->get_result();
    $registro = $result->fetch_assoc();
    
    if (!$registro) {
        header('Location: ?');
        exit;
    }
    
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $confirmacion = $_POST['confirmacion'] ?? '';
        if ($confirmacion === 'BORRAR') {
            $stmt = $mysqli->prepare("DELETE FROM ai_backups WHERE id = ?");
            $stmt->bind_param("i", $id);
            $stmt->execute();
            header('Location: ?mensaje=Registro eliminado correctamente');
            exit;
        } else {
            $error = "Debes escribir BORRAR en mayúsculas para confirmar";
        }
    }
}

// Guardar registro (add/edit)
if ($action === 'save' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    requerirAuth();
    
    // Detectar si el contenido llegó vacío por límite de tamaño
    if (empty($_POST) && isset($_SERVER['CONTENT_LENGTH']) && $_SERVER['CONTENT_LENGTH'] > 0) {
        $post_max = ini_get('post_max_size');
        die("
        <div class='container mt-5'>
            <div class='alert alert-danger'>
                <h4>⚠️ Error: Datos demasiado grandes</h4>
                <p>El contenido enviado excede el límite permitido por el servidor.</p>
                <p><strong>post_max_size actual:</strong> {$post_max}</p>
                <p><strong>Tamaño enviado:</strong> " . round($_SERVER['CONTENT_LENGTH'] / 1024 / 1024, 2) . " MB</p>
                <hr>
                <p class='mb-0'>Soluciones: Reduce el tamaño de la imagen, comprime el contenido, o aumenta post_max_size en php.ini</p>
            </div>
            <a href='javascript:history.back()' class='btn btn-secondary'>Volver</a>
        </div>
        ");
    }
    
    $id = isset($_POST['id']) ? intval($_POST['id']) : 0;
    $proyecto = $_POST['proyecto'] ?? '';
    $ia_utilizada = $_POST['ia_utilizada'] ?? '';
    $tipo = $_POST['tipo'] ?? 'prompt';
    $contenido = $_POST['contenido'] ?? '';
    
    // Procesar imagen si se subió archivo
    if ($tipo === 'imagen' && isset($_FILES['archivo_imagen']) && $_FILES['archivo_imagen']['error'] === UPLOAD_ERR_OK) {
        $file_tmp = $_FILES['archivo_imagen']['tmp_name'];
        $file_type = $_FILES['archivo_imagen']['type'];
        $allowed_types = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
        
        if (in_array($file_type, $allowed_types)) {
            $image_data = file_get_contents($file_tmp);
            $base64 = 'data:' . $file_type . ';base64,' . base64_encode($image_data);
            $contenido = $base64;
        }
    }
    
    // Validar base64 si es imagen
    if ($tipo === 'imagen' && !validarBase64Imagen($contenido) && !empty($contenido)) {
        $error = "El contenido no parece ser una imagen base64 válida (debe comenzar con data:image/[jpg|png|webp|gif];base64,)";
    } else {
        $nombre_archivo = $_POST['nombre_archivo'] ?? '';
        $num_version = floatval($_POST['num_version'] ?? 1);
        $comentarios = $_POST['comentarios'] ?? '';
        $calificacion = floatval($_POST['calificacion'] ?? 0);
        $visible = $_POST['visible'] ?? 'SI';
        $contrasena_ver = $_POST['contrasena_ver'] ?? '';
        
        // Calcular hashes y tamaño
        $hashes = calcularHashes($contenido);
        
        // Hashear contraseña si se proporcionó
        if (!empty($contrasena_ver)) {
            $contrasena_ver = password_hash($contrasena_ver, PASSWORD_DEFAULT);
        } else {
            $contrasena_ver = '';
        }
        
        if ($id > 0) {
            // Actualizar
            $stmt = $mysqli->prepare("UPDATE ai_backups SET 
                proyecto = ?, ia_utilizada = ?, tipo = ?, contenido = ?, 
                nombre_archivo = ?, num_version = ?, comentarios = ?, 
                calificacion = ?, visible = ?, tamanio = ?, hash_md5 = ?, hash_sha1 = ?,
                contrasena_ver = IF(? = '', contrasena_ver, ?)
                WHERE id = ?");
            
            $stmt->bind_param("ssssssdssddsssi", 
                $proyecto, $ia_utilizada, $tipo, $contenido,
                $nombre_archivo, $num_version, $comentarios,
                $calificacion, $visible, $hashes['tamanio'], $hashes['md5'], $hashes['sha1'],
                $contrasena_ver, $contrasena_ver, $id
            );
        } else {
            // Insertar nuevo
            $stmt = $mysqli->prepare("INSERT INTO ai_backups 
                (proyecto, ia_utilizada, tipo, contenido, nombre_archivo, num_version, 
                comentarios, calificacion, visible, fecha, contrasena_ver, tamanio, hash_md5, hash_sha1) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), ?, ?, ?, ?)");
            
            $stmt->bind_param("ssssssdsssddd", 
                $proyecto, $ia_utilizada, $tipo, $contenido, $nombre_archivo, $num_version,
                $comentarios, $calificacion, $visible, $contrasena_ver, 
                $hashes['tamanio'], $hashes['md5'], $hashes['sha1']
            );
        }
        
        if ($stmt->execute()) {
            header('Location: ?mensaje=Registro guardado correctamente');
            exit;
        } else {
            $error = "Error al guardar: " . $stmt->error;
        }
    }
}

// Nueva versión
if ($action === 'newversion' && isset($_GET['id'])) {
    requerirAuth();
    
    $id = intval($_GET['id']);
    $stmt = $mysqli->prepare("SELECT * FROM ai_backups WHERE id = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $result = $stmt->get_result();
    $registro = $result->fetch_assoc();
    
    if ($registro) {
        // Incrementar versión
        $nueva_version = $registro['num_version'] + 1.000000;
        
        // Preparar datos para el formulario
        $form_data = [
            'id' => 0, // Nuevo registro
            'proyecto' => $registro['proyecto'],
            'ia_utilizada' => $registro['ia_utilizada'],
            'tipo' => $registro['tipo'],
            'nombre_archivo' => $registro['nombre_archivo'],
            'num_version' => $nueva_version,
            'comentarios' => '',
            'calificacion' => $registro['calificacion'],
            'visible' => $registro['visible'],
            'contenido' => '',
            'contrasena_ver' => ''
        ];
        
        $action = 'edit'; // Mostrar formulario de edición
    }
}

// Verificar contraseña de registro
$registro_desbloqueado = null;
if ($action === 'unlock' && isset($_POST['id']) && isset($_POST['pass_registro'])) {
    $id = intval($_POST['id']);
    $pass = $_POST['pass_registro'];
    
    $stmt = $mysqli->prepare("SELECT contrasena_ver FROM ai_backups WHERE id = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $result = $stmt->get_result();
    $reg = $result->fetch_assoc();
    
    if ($reg && password_verify($pass, $reg['contrasena_ver'])) {
        $_SESSION['unlocked_' . $id] = true;
        header('Location: ?action=view&id=' . $id);
        exit;
    } else {
        $error = "Contraseña incorrecta";
        $action = 'view';
        $_GET['id'] = $id;
    }
}

// Obtener mensaje de URL
if (isset($_GET['mensaje'])) {
    $mensaje = $_GET['mensaje'];
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sistema de Respaldo de Prompts IA</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.0.0/css/all.min.css">
    <style>
        body { padding-top: 70px; background-color: #f8f9fa; }
        .navbar-brand { font-weight: bold; }
        .auth-indicator { font-size: 0.9rem; }
        .table-responsive { background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .diff-old { background-color: #ffe6e6; text-decoration: line-through; color: #cc0000; }
        .diff-new { background-color: #e6ffe6; color: #006600; font-weight: bold; }
        .img-preview { max-width: 100%; max-height: 500px; border: 1px solid #ddd; border-radius: 4px; padding: 5px; }
        .hash-text { font-family: monospace; font-size: 0.85rem; color: #666; word-break: break-all; }
        .version-badge { font-size: 0.9rem; }
        .locked-icon { color: #dc3545; }
        .textarea-code { font-family: monospace; min-height: 300px; }
        .filter-section { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    </style>
</head>
<body>
    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark sticky-top">
        <div class="container">
            <a class="navbar-brand" href="?">
                <i class="fas fa-database"></i> AI Backup System
                <small class="text-muted ml-2">| Kimi K2.5</small>
            </a>
            
            <div class="navbar-nav ml-auto">
                <?php if (estaAutenticado()): ?>
                    <span class="navbar-text auth-indicator text-success mr-3">
                        <i class="fas fa-unlock"></i> Modo Edición
                    </span>
                    <a href="?action=logout" class="btn btn-outline-light btn-sm">
                        <i class="fas fa-sign-out-alt"></i> Cerrar Sesión
                    </a>
                <?php else: ?>
                    <span class="navbar-text auth-indicator text-warning mr-3">
                        <i class="fas fa-lock"></i> Solo Lectura
                    </span>
                    <a href="?action=login" class="btn btn-outline-light btn-sm">
                        <i class="fas fa-key"></i> Autenticar
                    </a>
                <?php endif; ?>
            </div>
        </div>
    </nav>

    <div class="container">
        <?php if ($mensaje): ?>
            <div class="alert alert-success alert-dismissible fade show mt-3">
                <?php echo limpiarOutput($mensaje); ?>
                <button type="button" class="close" data-dismiss="alert">&times;</button>
            </div>
        <?php endif; ?>
        
        <?php if ($error): ?>
            <div class="alert alert-danger alert-dismissible fade show mt-3">
                <?php echo limpiarOutput($error); ?>
                <button type="button" class="close" data-dismiss="alert">&times;</button>
            </div>
        <?php endif; ?>

        <?php if (isset($error_tamano)): ?>
            <div class="alert alert-danger mt-3">
                <h5><i class="fas fa-exclamation-triangle"></i> Error de Tamaño de POST</h5>
                <p>Los datos enviados son demasiado grandes para el servidor.</p>
                <p><strong>post_max_size configurado:</strong> <?php echo ini_get('post_max_size'); ?></p>
                <p><strong>upload_max_filesize:</strong> <?php echo ini_get('upload_max_filesize'); ?></p>
                <hr>
                <p class="mb-0">Si estás subiendo imágenes, reduce su tamaño o comprímelas antes de convertirlas a base64.</p>
            </div>
        <?php endif; ?>

        <?php
        // LOGIN
        if ($action === 'login'):
        ?>
            <div class="row justify-content-center mt-5">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header bg-primary text-white">
                            <h4 class="mb-0"><i class="fas fa-lock"></i> Acceso Maestro</h4>
                        </div>
                        <div class="card-body">
                            <form method="post">
                                <div class="form-group">
                                    <label>Contraseña Maestra:</label>
                                    <input type="password" name="pass_maestra" class="form-control" required autofocus>
                                </div>
                                <button type="submit" class="btn btn-primary btn-block">
                                    <i class="fas fa-sign-in-alt"></i> Acceder
                                </button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>

        <?php
        // FORMULARIO AGREGAR/EDITAR
        elseif ($action === 'edit' || ($action === 'add' && estaAutenticado())):
            requerirAuth();
            
            $edit_mode = false;
            $data = [
                'id' => 0,
                'proyecto' => '',
                'ia_utilizada' => 'ChatGPT',
                'tipo' => 'prompt',
                'contenido' => '',
                'nombre_archivo' => '',
                'num_version' => 1.000000,
                'comentarios' => '',
                'calificacion' => 0,
                'visible' => 'SI',
                'contrasena_ver' => ''
            ];
            
            if (isset($_GET['id'])) {
                $id = intval($_GET['id']);
                $stmt = $mysqli->prepare("SELECT * FROM ai_backups WHERE id = ?");
                $stmt->bind_param("i", $id);
                $stmt->execute();
                $result = $stmt->get_result();
                if ($row = $result->fetch_assoc()) {
                    $data = $row;
                    $edit_mode = true;
                }
            } elseif (isset($form_data)) {
                // Viene de nueva versión
                $data = $form_data;
            }
            
            // Calcular sugerencia de versión si es nuevo registro
            if (!$edit_mode && $data['num_version'] == 1.000000 && !empty($data['nombre_archivo'])) {
                $stmt = $mysqli->prepare("SELECT MAX(num_version) as max_ver FROM ai_backups 
                    WHERE proyecto = ? AND nombre_archivo = ?");
                $stmt->bind_param("ss", $data['proyecto'], $data['nombre_archivo']);
                $stmt->execute();
                $result = $stmt->get_result();
                if ($row = $result->fetch_assoc() && $row['max_ver']) {
                    $data['num_version'] = $row['max_ver'] + 1.000000;
                }
            }
        ?>
            <h3 class="mt-4 mb-4">
                <i class="fas fa-<?php echo $edit_mode ? 'edit' : 'plus-circle'; ?>"></i>
                <?php echo $edit_mode ? 'Editar Registro' : 'Nuevo Registro'; ?>
            </h3>
            
            <form method="post" action="?action=save" enctype="multipart/form-data" class="mb-5">
                <input type="hidden" name="id" value="<?php echo $data['id']; ?>">
                
                <div class="row">
                    <div class="col-md-6">
                        <div class="form-group">
                            <label>Proyecto:</label>
                            <input type="text" name="proyecto" class="form-control" 
                                value="<?php echo limpiarOutput($data['proyecto']); ?>" required>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="form-group">
                            <label>IA Utilizada:</label>
                            <select name="ia_utilizada" class="form-control">
                                <?php 
                                $ias = ['ChatGPT', 'Claude', 'Gemini', 'Grok', 'Cohere', 'Kimi', 'Llama', 'Otro'];
                                foreach ($ias as $ia): 
                                ?>
                                    <option value="<?php echo $ia; ?>" <?php echo $data['ia_utilizada'] == $ia ? 'selected' : ''; ?>>
                                        <?php echo $ia; ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                    </div>
                </div>
                
                <div class="row">
                    <div class="col-md-4">
                        <div class="form-group">
                            <label>Tipo:</label>
                            <select name="tipo" class="form-control" id="tipoSelect">
                                <?php 
                                $tipos = ['prompt' => 'Prompt', 'imagen' => 'Imagen', 'idea' => 'Idea', 
                                         'respuesta' => 'Respuesta', 'codigo' => 'Código', 'otro' => 'Otro'];
                                foreach ($tipos as $val => $label): 
                                ?>
                                    <option value="<?php echo $val; ?>" <?php echo $data['tipo'] == $val ? 'selected' : ''; ?>>
                                        <?php echo $label; ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="form-group">
                            <label>Nombre de Archivo/Identificador:</label>
                            <input type="text" name="nombre_archivo" class="form-control" 
                                value="<?php echo limpiarOutput($data['nombre_archivo']); ?>" required>
                        </div>
                    </div>
                    <div class="col-md-4">
                        <div class="form-group">
                            <label>Versión:</label>
                            <input type="number" name="num_version" class="form-control" step="0.000001"
                                value="<?php echo $data['num_version']; ?>" required>
                            <small class="form-text text-muted">Formato: 1.000000</small>
                        </div>
                    </div>
                </div>
                
                <div class="form-group" id="contenidoGroup">
                    <label>Contenido:</label>
                    <textarea name="contenido" id="contenidoTextarea" 
                        class="form-control textarea-code" rows="10"><?php 
                        echo ($data['tipo'] === 'imagen') ? '' : limpiarOutput($data['contenido']); 
                    ?></textarea>
                    
                    <div id="imagenUpload" style="display: <?php echo $data['tipo'] === 'imagen' ? 'block' : 'none'; ?>;">
                        <small class="form-text text-muted mt-2">
                            Para imágenes: pega el base64 arriba o sube un archivo:
                        </small>
                        <input type="file" name="archivo_imagen" class="form-control-file mt-2" 
                            accept="image/jpeg,image/png,image/webp,image/gif">
                    </div>
                </div>
                
                <div class="row">
                    <div class="col-md-6">
                        <div class="form-group">
                            <label>Comentarios:</label>
                            <textarea name="comentarios" class="form-control" rows="3"><?php 
                                echo limpiarOutput($data['comentarios']); 
                            ?></textarea>
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="form-group">
                            <label>Calificación (0-10):</label>
                            <input type="number" name="calificacion" class="form-control" 
                                step="0.1" min="0" max="10"
                                value="<?php echo $data['calificacion']; ?>">
                        </div>
                        <div class="form-group">
                            <label>Visible:</label>
                            <select name="visible" class="form-control">
                                <option value="SI" <?php echo $data['visible'] == 'SI' ? 'selected' : ''; ?>>SI</option>
                                <option value="NO" <?php echo $data['visible'] == 'NO' ? 'selected' : ''; ?>>NO</option>
                            </select>
                        </div>
                    </div>
                </div>
                
                <div class="form-group">
                    <label>Contraseña de protección (opcional):</label>
                    <input type="password" name="contrasena_ver" class="form-control" 
                        placeholder="Dejar vacío para mantener actual o sin protección">
                    <small class="form-text text-muted">
                        Si se establece, se requerirá esta contraseña para ver el contenido.
                    </small>
                </div>
                
                <div class="form-group">
                    <button type="submit" class="btn btn-primary btn-lg">
                        <i class="fas fa-save"></i> Guardar Registro
                    </button>
                    <a href="?" class="btn btn-secondary btn-lg">Cancelar</a>
                </div>
            </form>
            
            <script>
                document.getElementById('tipoSelect').addEventListener('change', function() {
                    var uploadDiv = document.getElementById('imagenUpload');
                    if (this.value === 'imagen') {
                        uploadDiv.style.display = 'block';
                    } else {
                        uploadDiv.style.display = 'none';
                    }
                });
            </script>

        <?php
        // VER REGISTRO
        elseif ($action === 'view' && isset($_GET['id'])):
            $id = intval($_GET['id']);
            
            // Verificar si está desbloqueado
            $bloqueado = false;
            $stmt = $mysqli->prepare("SELECT contrasena_ver FROM ai_backups WHERE id = ?");
            $stmt->bind_param("i", $id);
            $stmt->execute();
            $result = $stmt->get_result();
            $check = $result->fetch_assoc();
            
            if ($check && !empty($check['contrasena_ver']) && !isset($_SESSION['unlocked_' . $id])) {
                $bloqueado = true;
            }
            
            if ($bloqueado):
        ?>
            <div class="row justify-content-center mt-5">
                <div class="col-md-6">
                    <div class="card border-warning">
                        <div class="card-header bg-warning text-dark">
                            <h4 class="mb-0"><i class="fas fa-lock"></i> Contenido Protegido</h4>
                        </div>
                        <div class="card-body">
                            <p>Este registro requiere contraseña para ser visualizado.</p>
                            <form method="post" action="?action=unlock">
                                <input type="hidden" name="id" value="<?php echo $id; ?>">
                                <div class="form-group">
                                    <input type="password" name="pass_registro" class="form-control" 
                                        placeholder="Contraseña del registro" required autofocus>
                                </div>
                                <button type="submit" class="btn btn-warning btn-block">
                                    <i class="fas fa-unlock"></i> Desbloquear
                                </button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        <?php
            else:
                $stmt = $mysqli->prepare("SELECT * FROM ai_backups WHERE id = ?");
                $stmt->bind_param("i", $id);
                $stmt->execute();
                $result = $stmt->get_result();
                $reg = $result->fetch_assoc();
                
                if ($reg):
                    // Buscar otras versiones
                    $stmt_ver = $mysqli->prepare("SELECT id, num_version, fecha FROM ai_backups 
                        WHERE proyecto = ? AND nombre_archivo = ? AND id != ? 
                        ORDER BY num_version DESC");
                    $stmt_ver->bind_param("ssi", $reg['proyecto'], $reg['nombre_archivo'], $id);
                    $stmt_ver->execute();
                    $otras_versiones = $stmt_ver->get_result();
        ?>
            <div class="mt-4">
                <nav aria-label="breadcrumb">
                    <ol class="breadcrumb">
                        <li class="breadcrumb-item"><a href="?">Inicio</a></li>
                        <li class="breadcrumb-item active">Ver Registro #<?php echo $id; ?></li>
                    </ol>
                </nav>
                
                <div class="card">
                    <div class="card-header bg-info text-white d-flex justify-content-between align-items-center">
                        <h4 class="mb-0">
                            <i class="fas fa-eye"></i> 
                            <?php echo limpiarOutput($reg['nombre_archivo']); ?>
                            <span class="badge badge-light version-badge ml-2">
                                v<?php echo number_format($reg['num_version'], 6); ?>
                            </span>
                        </h4>
                        <div>
                            <?php if (estaAutenticado()): ?>
                                <a href="?action=edit&id=<?php echo $id; ?>" class="btn btn-warning btn-sm">
                                    <i class="fas fa-edit"></i> Editar
                                </a>
                                <a href="?action=newversion&id=<?php echo $id; ?>" class="btn btn-success btn-sm">
                                    <i class="fas fa-code-branch"></i> Nueva Versión
                                </a>
                            <?php endif; ?>
                        </div>
                    </div>
                    <div class="card-body">
                        <div class="row mb-3">
                            <div class="col-md-3"><strong>Proyecto:</strong> <?php echo limpiarOutput($reg['proyecto']); ?></div>
                            <div class="col-md-3"><strong>IA:</strong> <?php echo limpiarOutput($reg['ia_utilizada']); ?></div>
                            <div class="col-md-3"><strong>Tipo:</strong> <?php echo limpiarOutput($reg['tipo']); ?></div>
                            <div class="col-md-3"><strong>Fecha:</strong> <?php echo $reg['fecha']; ?></div>
                        </div>
                        
                        <div class="row mb-3">
                            <div class="col-md-3">
                                <strong>Calificación:</strong> 
                                <span class="badge badge-<?php echo $reg['calificacion'] >= 8 ? 'success' : ($reg['calificacion'] >= 5 ? 'warning' : 'danger'); ?>">
                                    <?php echo $reg['calificacion']; ?>/10
                                </span>
                            </div>
                            <div class="col-md-3"><strong>Visible:</strong> <?php echo $reg['visible']; ?></div>
                            <div class="col-md-3"><strong>Tamaño:</strong> <?php echo number_format($reg['tamanio'], 2); ?> KB</div>
                            <div class="col-md-3">
                                <?php if (!empty($reg['contrasena_ver'])): ?>
                                    <i class="fas fa-lock locked-icon"></i> <span class="text-danger">Protegido</span>
                                <?php endif; ?>
                            </div>
                        </div>
                        
                        <hr>
                        
                        <h5>Contenido:</h5>
                        <?php if ($reg['tipo'] === 'imagen'): ?>
                            <?php if (validarBase64Imagen($reg['contenido'])): ?>
                                <img src="<?php echo limpiarOutput($reg['contenido']); ?>" 
                                    class="img-preview" alt="Imagen almacenada">
                            <?php else: ?>
                                <div class="alert alert-danger">
                                    <i class="fas fa-exclamation-triangle"></i> 
                                    La imagen no tiene un formato base64 válido o no es un tipo de imagen permitido (jpg, png, webp, gif).
                                </div>
                                <textarea class="form-control" rows="5" readonly><?php 
                                    echo substr(limpiarOutput($reg['contenido']), 0, 200) . '...'; 
                                ?></textarea>
                            <?php endif; ?>
                        <?php else: ?>
                            <textarea class="form-control textarea-code" rows="15" readonly><?php 
                                echo limpiarOutput($reg['contenido']); 
                            ?></textarea>
                        <?php endif; ?>
                        
                        <?php if (!empty($reg['comentarios'])): ?>
                            <div class="mt-3">
                                <h6>Comentarios:</h6>
                                <div class="alert alert-secondary">
                                    <?php echo nl2br(limpiarOutput($reg['comentarios'])); ?>
                                </div>
                            </div>
                        <?php endif; ?>
                        
                        <hr>
                        
                        <div class="mt-3">
                            <h6>Hashes de Integridad:</h6>
                            <div class="hash-text"><strong>MD5:</strong> <?php echo $reg['hash_md5']; ?></div>
                            <div class="hash-text"><strong>SHA1:</strong> <?php echo $reg['hash_sha1']; ?></div>
                        </div>
                        
                        <?php if ($otras_versiones->num_rows > 0): ?>
                            <hr>
                            <div class="mt-3">
                                <h5><i class="fas fa-history"></i> Otras Versiones</h5>
                                <div class="list-group">
                                    <?php while ($ver = $otras_versiones->fetch_assoc()): ?>
                                        <a href="?action=view&id=<?php echo $ver['id']; ?>" 
                                           class="list-group-item list-group-item-action d-flex justify-content-between align-items-center">
                                            Versión <?php echo number_format($ver['num_version'], 6); ?>
                                            <span class="text-muted small"><?php echo $ver['fecha']; ?></span>
                                        </a>
                                    <?php endwhile; ?>
                                </div>
                                
                                <?php if (isset($_GET['compare']) && estaAutenticado()): 
                                    $compare_id = intval($_GET['compare']);
                                    $stmt_comp = $mysqli->prepare("SELECT contenido, num_version FROM ai_backups WHERE id = ?");
                                    $stmt_comp->bind_param("i", $compare_id);
                                    $stmt_comp->execute();
                                    $comp_result = $stmt_comp->get_result()->fetch_assoc();
                                    
                                    if ($comp_result):
                                        $lines1 = explode("\n", $reg['contenido']);
                                        $lines2 = explode("\n", $comp_result['contenido']);
                                ?>
                                    <div class="mt-4">
                                        <h6>Comparación con Versión <?php echo number_format($comp_result['num_version'], 6); ?>:</h6>
                                        <div class="border p-3 bg-light" style="font-family: monospace; font-size: 0.9rem; max-height: 400px; overflow-y: auto;">
                                            <?php
                                            $max_lines = max(count($lines1), count($lines2));
                                            for ($i = 0; $i < $max_lines; $i++) {
                                                $line1 = isset($lines1[$i]) ? $lines1[$i] : '';
                                                $line2 = isset($lines2[$i]) ? $lines2[$i] : '';
                                                
                                                if ($line1 !== $line2) {
                                                    if (!empty($line1)) {
                                                        echo "<div class='diff-old'>- " . limpiarOutput($line1) . "</div>";
                                                    }
                                                    if (!empty($line2)) {
                                                        echo "<div class='diff-new'>+ " . limpiarOutput($line2) . "</div>";
                                                    }
                                                } else {
                                                    echo "<div>  " . limpiarOutput($line1) . "</div>";
                                                }
                                            }
                                            ?>
                                        </div>
                                    </div>
                                <?php 
                                    endif;
                                else: 
                                    if (estaAutenticado()):
                                ?>
                                    <form method="get" class="mt-3">
                                        <input type="hidden" name="action" value="view">
                                        <input type="hidden" name="id" value="<?php echo $id; ?>">
                                        <div class="form-row align-items-center">
                                            <div class="col-auto">
                                                <label class="col-form-label">Comparar con:</label>
                                            </div>
                                            <div class="col-auto">
                                                <select name="compare" class="form-control form-control-sm">
                                                    <?php 
                                                    $otras_versiones->data_seek(0);
                                                    while ($ver = $otras_versiones->fetch_assoc()): 
                                                    ?>
                                                        <option value="<?php echo $ver['id']; ?>">
                                                            v<?php echo number_format($ver['num_version'], 6); ?>
                                                        </option>
                                                    <?php endwhile; ?>
                                                </select>
                                            </div>
                                            <div class="col-auto">
                                                <button type="submit" class="btn btn-sm btn-info">
                                                    <i class="fas fa-exchange-alt"></i> Comparar
                                                </button>
                                            </div>
                                        </div>
                                    </form>
                                <?php 
                                    endif;
                                endif; 
                                ?>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
                
                <div class="mt-3">
                    <a href="?" class="btn btn-secondary"><i class="fas fa-arrow-left"></i> Volver al listado</a>
                </div>
            </div>
        <?php
                else:
                    echo '<div class="alert alert-danger mt-4">Registro no encontrado</div>';
                endif;
            endif;

        // BORRAR REGISTRO
        elseif ($action === 'delete' && isset($_GET['id'])):
            requerirAuth();
        ?>
            <div class="row justify-content-center mt-5">
                <div class="col-md-8">
                    <div class="card border-danger">
                        <div class="card-header bg-danger text-white">
                            <h4 class="mb-0"><i class="fas fa-exclamation-triangle"></i> Confirmar Eliminación</h4>
                        </div>
                        <div class="card-body">
                            <div class="alert alert-warning">
                                <h5>Estás a punto de borrar:</h5>
                                <p class="mb-0">
                                    <strong>Archivo:</strong> <?php echo limpiarOutput($registro['nombre_archivo']); ?><br>
                                    <strong>Versión:</strong> <?php echo number_format($registro['num_version'], 6); ?>
                                </p>
                            </div>
                            
                            <div class="alert alert-danger">
                                <strong>⚠️ Esta acción NO se puede deshacer.</strong>
                            </div>
                            
                            <form method="post">
                                <div class="form-group">
                                    <label class="font-weight-bold text-danger">
                                        Escribe BORRAR en mayúsculas para confirmar:
                                    </label>
                                    <input type="text" name="confirmacion" class="form-control form-control-lg" 
                                        required autofocus autocomplete="off" style="text-transform: uppercase;">
                                </div>
                                
                                <div class="form-group">
                                    <button type="submit" class="btn btn-danger btn-lg btn-block">
                                        <i class="fas fa-trash-alt"></i> Eliminar Permanentemente
                                    </button>
                                </div>
                            </form>
                            
                            <a href="?" class="btn btn-secondary btn-block">Cancelar</a>
                        </div>
                    </div>
                </div>
            </div>

        <?php
        // LISTADO PRINCIPAL
        else:
            // Procesar filtros
            $filtro_proyecto = $_GET['filtro_proyecto'] ?? '';
            $filtro_ia = $_GET['filtro_ia'] ?? '';
            $filtro_tipo = $_GET['filtro_tipo'] ?? '';
            $filtro_visible = $_GET['filtro_visible'] ?? 'SI'; // Default solo visibles
            $filtro_fecha_desde = $_GET['filtro_fecha_desde'] ?? '';
            $filtro_fecha_hasta = $_GET['filtro_fecha_hasta'] ?? '';
            $busqueda = $_GET['busqueda'] ?? '';
            
            // Paginación
            $pagina = isset($_GET['pagina']) ? intval($_GET['pagina']) : 1;
            $por_pagina = 10;
            $offset = ($pagina - 1) * $por_pagina;
            
            // Construir query
            $where = "WHERE 1=1";
            $params = [];
            $types = "";
            
            if ($filtro_visible !== 'todos') {
                $where .= " AND visible = ?";
                $params[] = $filtro_visible;
                $types .= "s";
            }
            if ($filtro_proyecto) {
                $where .= " AND proyecto LIKE ?";
                $params[] = "%$filtro_proyecto%";
                $types .= "s";
            }
            if ($filtro_ia) {
                $where .= " AND ia_utilizada = ?";
                $params[] = $filtro_ia;
                $types .= "s";
            }
            if ($filtro_tipo) {
                $where .= " AND tipo = ?";
                $params[] = $filtro_tipo;
                $types .= "s";
            }
            if ($filtro_fecha_desde) {
                $where .= " AND fecha >= ?";
                $params[] = $filtro_fecha_desde . " 00:00:00";
                $types .= "s";
            }
            if ($filtro_fecha_hasta) {
                $where .= " AND fecha <= ?";
                $params[] = $filtro_fecha_hasta . " 23:59:59";
                $types .= "s";
            }
            if ($busqueda) {
                $where .= " AND (contenido LIKE ? OR comentarios LIKE ?)";
                $params[] = "%$busqueda%";
                $params[] = "%$busqueda%";
                $types .= "ss";
            }
            
            // Contar total
            $count_sql = "SELECT COUNT(*) as total FROM ai_backups $where";
            $stmt_count = $mysqli->prepare($count_sql);
            if (!empty($types)) {
                $stmt_count->bind_param($types, ...$params);
            }
            $stmt_count->execute();
            $total_registros = $stmt_count->get_result()->fetch_assoc()['total'];
            $total_paginas = ceil($total_registros / $por_pagina);
            
            // Obtener registros
            $sql = "SELECT * FROM ai_backups $where ORDER BY fecha DESC LIMIT ? OFFSET ?";
            $stmt = $mysqli->prepare($sql);
            $params[] = $por_pagina;
            $params[] = $offset;
            $types .= "ii";
            $stmt->bind_param($types, ...$params);
            $stmt->execute();
            $registros = $stmt->get_result();
        ?>
            
            <!-- Filtros -->
            <div class="filter-section mt-4">
                <h5><i class="fas fa-filter"></i> Filtros y Búsqueda</h5>
                <form method="get" class="mt-3">
                    <div class="row">
                        <div class="col-md-3">
                            <input type="text" name="filtro_proyecto" class="form-control" 
                                placeholder="Proyecto" value="<?php echo limpiarOutput($filtro_proyecto); ?>">
                        </div>
                        <div class="col-md-2">
                            <select name="filtro_ia" class="form-control">
                                <option value="">Todas las IAs</option>
                                <?php 
                                $ias = ['ChatGPT', 'Claude', 'Gemini', 'Grok', 'Cohere', 'Kimi', 'Llama'];
                                foreach ($ias as $ia): 
                                ?>
                                    <option value="<?php echo $ia; ?>" <?php echo $filtro_ia == $ia ? 'selected' : ''; ?>>
                                        <?php echo $ia; ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="col-md-2">
                            <select name="filtro_tipo" class="form-control">
                                <option value="">Todos los tipos</option>
                                <?php 
                                $tipos = ['prompt', 'imagen', 'idea', 'respuesta', 'codigo', 'otro'];
                                foreach ($tipos as $t): 
                                ?>
                                    <option value="<?php echo $t; ?>" <?php echo $filtro_tipo == $t ? 'selected' : ''; ?>>
                                        <?php echo ucfirst($t); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="col-md-2">
                            <select name="filtro_visible" class="form-control">
                                <option value="SI" <?php echo $filtro_visible == 'SI' ? 'selected' : ''; ?>>Visibles</option>
                                <option value="NO" <?php echo $filtro_visible == 'NO' ? 'selected' : ''; ?>>Ocultos</option>
                                <option value="todos" <?php echo $filtro_visible == 'todos' ? 'selected' : ''; ?>>Todos</option>
                            </select>
                        </div>
                        <div class="col-md-3">
                            <input type="text" name="busqueda" class="form-control" 
                                placeholder="Buscar en contenido..." value="<?php echo limpiarOutput($busqueda); ?>">
                        </div>
                    </div>
                    <div class="row mt-2">
                        <div class="col-md-3">
                            <input type="date" name="filtro_fecha_desde" class="form-control" 
                                placeholder="Desde" value="<?php echo $filtro_fecha_desde; ?>">
                        </div>
                        <div class="col-md-3">
                            <input type="date" name="filtro_fecha_hasta" class="form-control" 
                                placeholder="Hasta" value="<?php echo $filtro_fecha_hasta; ?>">
                        </div>
                        <div class="col-md-6">
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-search"></i> Filtrar
                            </button>
                            <a href="?" class="btn btn-secondary">
                                <i class="fas fa-times"></i> Limpiar
                            </a>
                            <?php if (estaAutenticado()): ?>
                                <a href="?action=add" class="btn btn-success">
                                    <i class="fas fa-plus"></i> Agregar Nuevo
                                </a>
                            <?php endif; ?>
                        </div>
                    </div>
                </form>
            </div>
            
            <!-- Tabla de registros -->
            <div class="table-responsive mt-4">
                <table class="table table-hover table-striped">
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
                            <th>Vis.</th>
                            <th>Acciones</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php while ($row = $registros->fetch_assoc()): ?>
                            <tr>
                                <td><?php echo date('Y-m-d H:i', strtotime($row['fecha'])); ?></td>
                                <td><?php echo limpiarOutput($row['proyecto']); ?></td>
                                <td>
                                    <span class="badge badge-info">
                                        <?php echo limpiarOutput($row['ia_utilizada']); ?>
                                    </span>
                                </td>
                                <td>
                                    <span class="badge badge-secondary">
                                        <?php echo limpiarOutput($row['tipo']); ?>
                                    </span>
                                </td>
                                <td><?php echo number_format($row['num_version'], 6); ?></td>
                                <td>
                                    <span class="badge badge-<?php echo $row['calificacion'] >= 8 ? 'success' : ($row['calificacion'] >= 5 ? 'warning' : 'danger'); ?>">
                                        <?php echo $row['calificacion']; ?>
                                    </span>
                                </td>
                                <td><?php echo number_format($row['tamanio'], 2); ?> KB</td>
                                <td>
                                    <?php echo limpiarOutput($row['nombre_archivo']); ?>
                                    <?php if (!empty($row['contrasena_ver'])): ?>
                                        <i class="fas fa-lock locked-icon ml-1" title="Protegido con contraseña"></i>
                                    <?php endif; ?>
                                </td>
                                <td><?php echo $row['visible']; ?></td>
                                <td>
                                    <a href="?action=view&id=<?php echo $row['id']; ?>" 
                                       class="btn btn-sm btn-info" title="Ver">
                                        <i class="fas fa-eye"></i>
                                    </a>
                                    <?php if (estaAutenticado()): ?>
                                        <a href="?action=edit&id=<?php echo $row['id']; ?>" 
                                           class="btn btn-sm btn-warning" title="Editar">
                                            <i class="fas fa-edit"></i>
                                        </a>
                                        <a href="?action=delete&id=<?php echo $row['id']; ?>" 
                                           class="btn btn-sm btn-danger" title="Borrar">
                                            <i class="fas fa-trash"></i>
                                        </a>
                                        <a href="?action=newversion&id=<?php echo $row['id']; ?>" 
                                           class="btn btn-sm btn-success" title="Nueva Versión">
                                            <i class="fas fa-code-branch"></i>
                                        </a>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endwhile; ?>
                        
                        <?php if ($registros->num_rows === 0): ?>
                            <tr>
                                <td colspan="10" class="text-center text-muted py-4">
                                    <i class="fas fa-inbox fa-2x mb-2"></i><br>
                                    No se encontraron registros
                                </td>
                            </tr>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
            
            <!-- Paginación -->
            <?php if ($total_paginas > 1): ?>
                <nav aria-label="Paginación" class="mt-3">
                    <ul class="pagination justify-content-center">
                        <?php if ($pagina > 1): ?>
                            <li class="page-item">
                                <a class="page-link" href="?<?php 
                                    echo http_build_query(array_merge($_GET, ['pagina' => $pagina - 1])); 
                                ?>">Anterior</a>
                            </li>
                        <?php endif; ?>
                        
                        <?php for ($i = 1; $i <= $total_paginas; $i++): ?>
                            <li class="page-item <?php echo $i == $pagina ? 'active' : ''; ?>">
                                <a class="page-link" href="?<?php 
                                    echo http_build_query(array_merge($_GET, ['pagina' => $i])); 
                                ?>"><?php echo $i; ?></a>
                            </li>
                        <?php endfor; ?>
                        
                        <?php if ($pagina < $total_paginas): ?>
                            <li class="page-item">
                                <a class="page-link" href="?<?php 
                                    echo http_build_query(array_merge($_GET, ['pagina' => $pagina + 1])); 
                                ?>">Siguiente</a>
                            </li>
                        <?php endif; ?>
                    </ul>
                </nav>
            <?php endif; ?>
            
            <div class="text-muted text-center mt-2">
                Mostrando <?php echo $registros->num_rows; ?> de <?php echo $total_registros; ?> registros
            </div>
            
        <?php endif; ?>
        
        <!-- Footer con advertencia -->
        <footer class="mt-5 mb-3 pt-3 border-top text-center">
            <p class="text-muted small">
                <i class="fas fa-exclamation-circle"></i>
                <strong>⚠️ Este sistema NO hace respaldo de su propia base de datos.</strong> 
                Respaldar MySQL es tu responsabilidad. Un respaldo que no existe no es un respaldo.
            </p>
            <p class="text-muted small">
                Sistema ejecutándose en PHP <?php echo phpversion(); ?> | 
                IP: <?php echo $ip_visitante; ?> | 
                Modo: <?php echo estaAutenticado() ? 'Edición' : 'Solo Lectura'; ?>
            </p>
        </footer>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/jquery@3.5.1/dist/jquery.slim.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
<?php
$mysqli->close();
?>

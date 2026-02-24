<?php
// --- CONFIGURACIÓN — edita esto antes de usar ---
define('PASS_MAESTRA', 'tu_contrasena_maestra_aqui');
define('PASS_REGISTROS', 'tu_contrasena_registros_aqui');
define('IPS_PERMITIDAS', ['127.0.0.1', '::1']); // Agrega tus IPs aquí

// Headers para evitar caché
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: Sat, 01 Jan 2000 00:00:00 GMT');

// Verificación de IP
if (!in_array($_SERVER['REMOTE_ADDR'], IPS_PERMITIDAS)) {
    die('<div class="container mt-5"><div class="alert alert-danger">Acceso no autorizado</div></div>');
}

// Iniciar sesión
session_start();

// Conexión a la base de datos
$db = new mysqli('localhost', 'root', '', 'ai_backups');
if ($db->connect_error) {
    die("Conexión fallida: " . $db->connect_error);
}

// Crear tabla si no existe
$db->query("
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
        visible VARCHAR(2) DEFAULT 'SI',
        fecha DATETIME DEFAULT CURRENT_TIMESTAMP,
        contrasena_ver VARCHAR(255),
        tamanio DECIMAL(14,6),
        hash_md5 VARCHAR(32),
        hash_sha1 VARCHAR(40)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
");

// Función para calcular hashes y tamaño
function calcular_metadatos($contenido) {
    $tamanio = strlen($contenido) / 1024;
    $hash_md5 = md5($contenido);
    $hash_sha1 = sha1($contenido);
    return [$tamanio, $hash_md5, $hash_sha1];
}

// Función para validar imagen base64
function es_imagen_valida($base64) {
    $mimes_permitidos = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
    $data = explode(',', $base64);
    if (count($data) < 2) return false;
    $mime = explode(';', $data[0])[0] ?? '';
    return in_array($mime, $mimes_permitidos);
}

// Procesar subida de imagen
if (isset($_FILES['imagen']) && $_FILES['imagen']['error'] === UPLOAD_ERR_OK) {
    $tmp_name = $_FILES['imagen']['tmp_name'];
    $mime = mime_content_type($tmp_name);
    if (!in_array($mime, ['image/jpeg', 'image/png', 'image/webp', 'image/gif'])) {
        die('<div class="alert alert-danger">Tipo de imagen no permitido</div>');
    }
    $_POST['contenido'] = 'data:' . $mime . ';base64,' . base64_encode(file_get_contents($tmp_name));
}

// Procesar formulario de agregar/editar
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['accion'])) {
    if (!isset($_SESSION['autenticado']) || $_SESSION['autenticado'] !== true) {
        die('<div class="alert alert-danger">Acceso denegado. Necesitas autenticarte.</div>');
    }

    if (empty($_POST['contenido']) && !empty($_FILES)) {
        echo '<div class="alert alert-warning">Posible error de post_max_size. Revisa la configuración de tu servidor.</div>';
    }

    if ($_POST['accion'] === 'guardar') {
        $proyecto = $db->real_escape_string($_POST['proyecto']);
        $ia = $db->real_escape_string($_POST['ia_utilizada']);
        $tipo = $db->real_escape_string($_POST['tipo']);
        $nombre_archivo = $db->real_escape_string($_POST['nombre_archivo']);
        $num_version = $_POST['num_version'];
        $comentarios = $db->real_escape_string($_POST['comentarios']);
        $calificacion = $_POST['calificacion'];
        $visible = $_POST['visible'];
        $contenido = $_POST['contenido'];
        $contrasena = !empty($_POST['contrasena_ver']) ? password_hash($_POST['contrasena_ver'], PASSWORD_DEFAULT) : '';

        list($tamanio, $hash_md5, $hash_sha1) = calcular_metadatos($contenido);

        if ($tipo === 'imagen' && !es_imagen_valida($contenido)) {
            die('<div class="alert alert-danger">Formato de imagen no válido</div>');
        }

        if (isset($_POST['id']) && !empty($_POST['id'])) {
            // Editar
            $id = (int)$_POST['id'];
            $stmt = $db->prepare("UPDATE ai_backups SET proyecto=?, ia_utilizada=?, tipo=?, contenido=?, nombre_archivo=?, num_version=?, comentarios=?, calificacion=?, visible=?, tamanio=?, hash_md5=?, hash_sha1=?, contrasena_ver=? WHERE id=?");
            $stmt->bind_param("sssssdssdsssi", $proyecto, $ia, $tipo, $contenido, $nombre_archivo, $num_version, $comentarios, $calificacion, $visible, $tamanio, $hash_md5, $hash_sha1, $contrasena, $id);
        } else {
            // Agregar
            $stmt = $db->prepare("INSERT INTO ai_backups (proyecto, ia_utilizada, tipo, contenido, nombre_archivo, num_version, comentarios, calificacion, visible, tamanio, hash_md5, hash_sha1, contrasena_ver) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->bind_param("sssssdssdsss", $proyecto, $ia, $tipo, $contenido, $nombre_archivo, $num_version, $comentarios, $calificacion, $visible, $tamanio, $hash_md5, $hash_sha1, $contrasena);
        }
        $stmt->execute();
        header("Location: ?");
        exit;
    }

    if ($_POST['accion'] === 'borrar' && isset($_POST['confirmar_borrar']) && strtoupper($_POST['confirmar_borrar']) === 'BORRAR') {
        $id = (int)$_POST['id'];
        $db->query("DELETE FROM ai_backups WHERE id=$id");
        header("Location: ?");
        exit;
    }
}

// Autenticación
if (isset($_POST['password'])) {
    if ($_POST['password'] === PASS_MAESTRA) {
        $_SESSION['autenticado'] = true;
    } else {
        $error = "Contraseña incorrecta";
    }
}

// Ver registro
if (isset($_GET['ver'])) {
    $id = (int)$_GET['ver'];
    $result = $db->query("SELECT * FROM ai_backups WHERE id=$id");
    $registro = $result->fetch_assoc();

    if ($registro['contrasena_ver'] && !isset($_POST['contrasena_individual'])) {
        echo '<div class="container mt-3">
            <form method="post">
                <div class="form-group">
                    <label>Contraseña del registro:</label>
                    <input type="password" name="contrasena_individual" class="form-control" required>
                </div>
                <input type="hidden" name="id" value="' . $id . '">
                <button type="submit" class="btn btn-primary">Ver</button>
            </form>
        </div>';
    } elseif ($registro['contrasena_ver'] && !password_verify($_POST['contrasena_individual'], $registro['contrasena_ver'])) {
        echo '<div class="alert alert-danger">Contraseña incorrecta</div>';
    } else {
        // Mostrar contenido
        echo '<div class="container mt-3">
            <h2>' . htmlspecialchars($registro['nombre_archivo']) . ' (v' . $registro['num_version'] . ')</h2>
            <p><strong>Proyecto:</strong> ' . htmlspecialchars($registro['proyecto']) . '</p>
            <p><strong>IA:</strong> ' . htmlspecialchars($registro['ia_utilizada']) . '</p>
            <p><strong>Tipo:</strong> ' . htmlspecialchars($registro['tipo']) . '</p>
            <p><strong>Fecha:</strong> ' . $registro['fecha'] . '</p>
            <p><strong>Tamaño:</strong> ' . $registro['tamanio'] . ' KB</p>
            <p><strong>MD5:</strong> ' . $registro['hash_md5'] . '</p>
            <p><strong>SHA1:</strong> ' . $registro['hash_sha1'] . '</p>
            <p><strong>Comentarios:</strong> ' . nl2br(htmlspecialchars($registro['comentarios'])) . '</p>
            <p><strong>Calificación:</strong> ' . $registro['calificacion'] . '</p>
            <p><strong>Visible:</strong> ' . $registro['visible'] . '</p>
            <hr>
            <h4>Contenido:</h4>';

        if ($registro['tipo'] === 'imagen') {
            echo '<img src="' . htmlspecialchars($registro['contenido']) . '" class="img-fluid" alt="Imagen">';
        } else {
            echo '<textarea class="form-control" rows="15" readonly>' . htmlspecialchars($registro['contenido']) . '</textarea>';
        }

        // Versiones relacionadas
        $versiones = $db->query("SELECT id, num_version, fecha FROM ai_backups WHERE nombre_archivo='{$registro['nombre_archivo']}' AND proyecto='{$registro['proyecto']}' ORDER BY fecha DESC");
        if ($versiones->num_rows > 1) {
            echo '<hr><h4>Otras versiones:</h4><ul>';
            while ($v = $versiones->fetch_assoc()) {
                echo '<li><a href="?ver=' . $v['id'] . '">Versión ' . $v['num_version'] . ' (' . $v['fecha'] . ')</a></li>';
            }
            echo '</ul>';
        }

        // Diff entre versiones
        if (isset($_GET['comparar_con'])) {
            $id2 = (int)$_GET['comparar_con'];
            $result2 = $db->query("SELECT contenido FROM ai_backups WHERE id=$id2");
            $registro2 = $result2->fetch_assoc();

            $diff = new Diff(explode("\n", $registro['contenido']), explode("\n", $registro2['contenido']));
            $renderer = new Diff_Renderer_Html_SideBySide;
            echo '<hr><h4>Diferencias:</h4>';
            echo $diff->render($renderer);
        }
    }
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sistema de Respaldo de Prompts IA</title>
    <!-- Bootstrap 4.6 -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/css/bootstrap.min.css">
    <!-- FontAwesome -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@5.15.4/css/all.min.css">
    <style>
        .diff-deleted { background-color: #ffdddd; }
        .diff-inserted { background-color: #ddffdd; }
    </style>
</head>
<body>
    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark sticky-top">
        <div class="container">
            <a class="navbar-brand" href="?">
                <i class="fas fa-save"></i> Respaldo de Prompts IA
            </a>
            <div class="navbar-text">
                <?php echo isset($_SESSION['autenticado']) ? '<span class="text-success">Autenticado</span>' : '<span class="text-warning">Solo lectura</span>'; ?>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <!-- Autenticación -->
        <?php if (!isset($_SESSION['autenticado'])): ?>
        <div class="card mb-4">
            <div class="card-body">
                <form method="post">
                    <div class="form-group">
                        <label>Contraseña maestra:</label>
                        <input type="password" name="password" class="form-control" required>
                    </div>
                    <button type="submit" class="btn btn-primary">Autenticarse</button>
                </form>
                <?php if (isset($error)) echo "<div class='alert alert-danger mt-2'>$error</div>"; ?>
            </div>
        </div>
        <?php endif; ?>

        <!-- Menú -->
        <div class="card mb-4">
            <div class="card-body">
                <div class="btn-group">
                    <a href="?" class="btn btn-primary">Ver registros</a>
                    <?php if (isset($_SESSION['autenticado'])): ?>
                    <a href="?accion=nuevo" class="btn btn-success">Agregar nuevo</a>
                    <a href="?accion=buscar" class="btn btn-info">Buscar</a>
                    <a href="?cerrar_sesion=1" class="btn btn-danger">Cerrar sesión</a>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <!-- Contenido principal -->
        <?php if (!isset($_GET['accion']) && !isset($_GET['ver'])): ?>
        <!-- Listado de registros -->
        <div class="card">
            <div class="card-header">
                <h3>Registros</h3>
            </div>
            <div class="card-body">
                <?php
                // Paginación y filtros
                $where = "WHERE visible='SI'";
                $params = [];

                if (isset($_GET['proyecto']) && !empty($_GET['proyecto'])) {
                    $where .= " AND proyecto LIKE ?";
                    $params[] = "%" . $db->real_escape_string($_GET['proyecto']) . "%";
                }
                if (isset($_GET['ia']) && !empty($_GET['ia'])) {
                    $where .= " AND ia_utilizada=?";
                    $params[] = $db->real_escape_string($_GET['ia']);
                }
                if (isset($_GET['tipo']) && !empty($_GET['tipo'])) {
                    $where .= " AND tipo=?";
                    $params[] = $db->real_escape_string($_GET['tipo']);
                }
                if (isset($_GET['visible']) && $_GET['visible'] !== 'todos') {
                    $where .= " AND visible=?";
                    $params[] = $db->real_escape_string($_GET['visible']);
                }

                $page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
                $per_page = 10;
                $offset = ($page - 1) * $per_page;

                $count_query = "SELECT COUNT(*) as total FROM ai_backups $where";
                if (!empty($params)) {
                    $stmt = $db->prepare($count_query);
                    $stmt->bind_param(str_repeat('s', count($params)), ...$params);
                    $stmt->execute();
                    $total_result = $stmt->get_result();
                } else {
                    $total_result = $db->query($count_query);
                }
                $total = $total_result->fetch_assoc()['total'];
                $pages = ceil($total / $per_page);

                $query = "SELECT * FROM ai_backups $where ORDER BY fecha DESC LIMIT $offset, $per_page";
                if (!empty($params)) {
                    $stmt = $db->prepare($query);
                    $stmt->bind_param(str_repeat('s', count($params)), ...$params);
                    $stmt->execute();
                    $result = $stmt->get_result();
                } else {
                    $result = $db->query($query);
                }
                ?>

                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>Fecha</th>
                            <th>Proyecto</th>
                            <th>IA</th>
                            <th>Tipo</th>
                            <th>Versión</th>
                            <th>Calificación</th>
                            <th>Tamaño (KB)</th>
                            <th>Archivo</th>
                            <th>Visible</th>
                            <th>Acciones</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php while ($row = $result->fetch_assoc()): ?>
                        <tr>
                            <td><?php echo $row['fecha']; ?></td>
                            <td><?php echo htmlspecialchars($row['proyecto']); ?></td>
                            <td><?php echo htmlspecialchars($row['ia_utilizada']); ?></td>
                            <td><?php echo htmlspecialchars($row['tipo']); ?></td>
                            <td><?php echo $row['num_version']; ?></td>
                            <td><?php echo $row['calificacion']; ?></td>
                            <td><?php echo $row['tamanio']; ?></td>
                            <td><?php echo htmlspecialchars($row['nombre_archivo']); ?></td>
                            <td><?php echo $row['visible']; ?></td>
                            <td>
                                <a href="?ver=<?php echo $row['id']; ?>" class="btn btn-sm btn-info">Ver</a>
                                <?php if (isset($_SESSION['autenticado'])): ?>
                                <a href="?accion=editar&id=<?php echo $row['id']; ?>" class="btn btn-sm btn-warning">Editar</a>
                                <a href="?accion=borrar&id=<?php echo $row['id']; ?>" class="btn btn-sm btn-danger">Borrar</a>
                                <a href="?accion=nueva_version&id=<?php echo $row['id']; ?>" class="btn btn-sm btn-secondary">Nueva versión</a>
                                <?php endif; ?>
                                <?php if (!empty($row['contrasena_ver'])): ?>
                                <i class="fas fa-lock text-danger"></i>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endwhile; ?>
                    </tbody>
                </table>

                <!-- Paginación -->
                <nav>
                    <ul class="pagination">
                        <?php for ($i = 1; $i <= $pages; $i++): ?>
                        <li class="page-item <?php echo $i === $page ? 'active' : ''; ?>">
                            <a class="page-link" href="?page=<?php echo $i; ?>"><?php echo $i; ?></a>
                        </li>
                        <?php endfor; ?>
                    </ul>
                </nav>
            </div>
        </div>

        <?php elseif (isset($_GET['accion']) && $_GET['accion'] === 'nuevo' || isset($_GET['accion']) && $_GET['accion'] === 'editar' || isset($_GET['accion']) && $_GET['accion'] === 'nueva_version'): ?>
        <!-- Formulario de agregar/editar -->
        <div class="card">
            <div class="card-body">
                <?php
                $registro = [
                    'id' => '',
                    'proyecto' => '',
                    'ia_utilizada' => '',
                    'tipo' => 'prompt',
                    'contenido' => '',
                    'nombre_archivo' => '',
                    'num_version' => '1.000000',
                    'comentarios' => '',
                    'calificacion' => '0.0',
                    'visible' => 'SI',
                    'contrasena_ver' => ''
                ];

                if (isset($_GET['id'])) {
                    $id = (int)$_GET['id'];
                    $result = $db->query("SELECT * FROM ai_backups WHERE id=$id");
                    $registro = $result->fetch_assoc();
                } elseif (isset($_GET['accion']) && $_GET['accion'] === 'nueva_version' && isset($_GET['id'])) {
                    $id = (int)$_GET['id'];
                    $result = $db->query("SELECT * FROM ai_backups WHERE id=$id");
                    $original = $result->fetch_assoc();
                    $registro = $original;
                    $registro['id'] = '';
                    $registro['num_version'] = bcadd($original['num_version'], 1, 6);
                    $registro['contenido'] = '';
                    $registro['contrasena_ver'] = '';
                }
                ?>

                <form method="post" enctype="multipart/form-data">
                    <input type="hidden" name="accion" value="guardar">
                    <input type="hidden" name="id" value="<?php echo $registro['id']; ?>">

                    <div class="form-group">
                        <label>Proyecto:</label>
                        <input type="text" name="proyecto" class="form-control" value="<?php echo htmlspecialchars($registro['proyecto']); ?>" required>
                    </div>

                    <div class="form-group">
                        <label>IA utilizada:</label>
                        <select name="ia_utilizada" class="form-control" required>
                            <option value="ChatGPT" <?php echo $registro['ia_utilizada'] === 'ChatGPT' ? 'selected' : ''; ?>>ChatGPT</option>
                            <option value="Claude" <?php echo $registro['ia_utilizada'] === 'Claude' ? 'selected' : ''; ?>>Claude</option>
                            <option value="Gemini" <?php echo $registro['ia_utilizada'] === 'Gemini' ? 'selected' : ''; ?>>Gemini</option>
                            <option value="Grok" <?php echo $registro['ia_utilizada'] === 'Grok' ? 'selected' : ''; ?>>Grok</option>
                            <option value="Cohere" <?php echo $registro['ia_utilizada'] === 'Cohere' ? 'selected' : ''; ?>>Cohere</option>
                            <option value="otro" <?php echo $registro['ia_utilizada'] === 'otro' ? 'selected' : ''; ?>>Otro</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label>Tipo:</label>
                        <select name="tipo" class="form-control" required>
                            <option value="prompt" <?php echo $registro['tipo'] === 'prompt' ? 'selected' : ''; ?>>Prompt</option>
                            <option value="imagen" <?php echo $registro['tipo'] === 'imagen' ? 'selected' : ''; ?>>Imagen</option>
                            <option value="idea" <?php echo $registro['tipo'] === 'idea' ? 'selected' : ''; ?>>Idea</option>
                            <option value="respuesta" <?php echo $registro['tipo'] === 'respuesta' ? 'selected' : ''; ?>>Respuesta</option>
                            <option value="codigo" <?php echo $registro['tipo'] === 'codigo' ? 'selected' : ''; ?>>Código</option>
                            <option value="otro" <?php echo $registro['tipo'] === 'otro' ? 'selected' : ''; ?>>Otro</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label>Contenido:</label>
                        <?php if ($registro['tipo'] === 'imagen'): ?>
                        <input type="file" name="imagen" class="form-control-file">
                        <small class="form-text text-muted">O pega el base64 de la imagen:</small>
                        <?php endif; ?>
                        <textarea name="contenido" class="form-control" rows="10" <?php echo $registro['tipo'] !== 'imagen' ? 'required' : ''; ?>><?php echo htmlspecialchars($registro['contenido']); ?></textarea>
                    </div>

                    <div class="form-group">
                        <label>Nombre de archivo:</label>
                        <input type="text" name="nombre_archivo" class="form-control" value="<?php echo htmlspecialchars($registro['nombre_archivo']); ?>" required>
                    </div>

                    <div class="form-group">
                        <label>Versión:</label>
                        <input type="text" name="num_version" class="form-control" value="<?php echo $registro['num_version']; ?>" required>
                    </div>

                    <div class="form-group">
                        <label>Comentarios:</label>
                        <textarea name="comentarios" class="form-control" rows="3"><?php echo htmlspecialchars($registro['comentarios']); ?></textarea>
                    </div>

                    <div class="form-group">
                        <label>Calificación:</label>
                        <input type="number" step="0.01" name="calificacion" class="form-control" value="<?php echo $registro['calificacion']; ?>">
                    </div>

                    <div class="form-group">
                        <label>Visible:</label>
                        <select name="visible" class="form-control" required>
                            <option value="SI" <?php echo $registro['visible'] === 'SI' ? 'selected' : ''; ?>>Sí</option>
                            <option value="NO" <?php echo $registro['visible'] === 'NO' ? 'selected' : ''; ?>>No</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label>Contraseña individual (opcional):</label>
                        <input type="password" name="contrasena_ver" class="form-control">
                    </div>

                    <button type="submit" class="btn btn-primary">Guardar</button>
                </form>
            </div>
        </div>

        <?php elseif (isset($_GET['accion']) && $_GET['accion'] === 'borrar'): ?>
        <!-- Confirmación de borrado -->
        <div class="card">
            <div class="card-body">
                <?php
                $id = (int)$_GET['id'];
                $result = $db->query("SELECT nombre_archivo, num_version FROM ai_backups WHERE id=$id");
                $registro = $result->fetch_assoc();
                ?>
                <p class="text-danger">¿Estás seguro de borrar <strong><?php echo htmlspecialchars($registro['nombre_archivo']); ?></strong> versión <strong><?php echo $registro['num_version']; ?></strong>? Esta acción no se puede deshacer.</p>
                <form method="post">
                    <input type="hidden" name="accion" value="borrar">
                    <input type="hidden" name="id" value="<?php echo $id; ?>">
                    <div class="form-group">
                        <label>Escribe "BORRAR" para confirmar:</label>
                        <input type="text" name="confirmar_borrar" class="form-control" required>
                    </div>
                    <button type="submit" class="btn btn-danger">Confirmar borrado</button>
                </form>
            </div>
        </div>

        <?php elseif (isset($_GET['accion']) && $_GET['accion'] === 'buscar'): ?>
        <!-- Formulario de búsqueda -->
        <div class="card">
            <div class="card-body">
                <form method="get">
                    <input type="hidden" name="accion" value="buscar">

                    <div class="form-group">
                        <label>Proyecto:</label>
                        <input type="text" name="proyecto" class="form-control" value="<?php echo isset($_GET['proyecto']) ? htmlspecialchars($_GET['proyecto']) : ''; ?>">
                    </div>

                    <div class="form-group">
                        <label>IA utilizada:</label>
                        <select name="ia" class="form-control">
                            <option value="">Todas</option>
                            <option value="ChatGPT" <?php echo (isset($_GET['ia']) && $_GET['ia'] === 'ChatGPT') ? 'selected' : ''; ?>>ChatGPT</option>
                            <option value="Claude" <?php echo (isset($_GET['ia']) && $_GET['ia'] === 'Claude') ? 'selected' : ''; ?>>Claude</option>
                            <option value="Gemini" <?php echo (isset($_GET['ia']) && $_GET['ia'] === 'Gemini') ? 'selected' : ''; ?>>Gemini</option>
                            <option value="Grok" <?php echo (isset($_GET['ia']) && $_GET['ia'] === 'Grok') ? 'selected' : ''; ?>>Grok</option>
                            <option value="Cohere" <?php echo (isset($_GET['ia']) && $_GET['ia'] === 'Cohere') ? 'selected' : ''; ?>>Cohere</option>
                            <option value="otro" <?php echo (isset($_GET['ia']) && $_GET['ia'] === 'otro') ? 'selected' : ''; ?>>Otro</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label>Tipo:</label>
                        <select name="tipo" class="form-control">
                            <option value="">Todos</option>
                            <option value="prompt" <?php echo (isset($_GET['tipo']) && $_GET['tipo'] === 'prompt') ? 'selected' : ''; ?>>Prompt</option>
                            <option value="imagen" <?php echo (isset($_GET['tipo']) && $_GET['tipo'] === 'imagen') ? 'selected' : ''; ?>>Imagen</option>
                            <option value="idea" <?php echo (isset($_GET['tipo']) && $_GET['tipo'] === 'idea') ? 'selected' : ''; ?>>Idea</option>
                            <option value="respuesta" <?php echo (isset($_GET['tipo']) && $_GET['tipo'] === 'respuesta') ? 'selected' : ''; ?>>Respuesta</option>
                            <option value="codigo" <?php echo (isset($_GET['tipo']) && $_GET['tipo'] === 'codigo') ? 'selected' : ''; ?>>Código</option>
                            <option value="otro" <?php echo (isset($_GET['tipo']) && $_GET['tipo'] === 'otro') ? 'selected' : ''; ?>>Otro</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label>Visible:</label>
                        <select name="visible" class="form-control">
                            <option value="todos">Todos</option>
                            <option value="SI" <?php echo (isset($_GET['visible']) && $_GET['visible'] === 'SI') ? 'selected' : ''; ?>>Sí</option>
                            <option value="NO" <?php echo (isset($_GET['visible']) && $_GET['visible'] === 'NO') ? 'selected' : ''; ?>>No</option>
                        </select>
                    </div>

                    <button type="submit" class="btn btn-primary">Buscar</button>
                </form>
            </div>
        </div>
        <?php endif; ?>
    </div>

    <!-- Footer -->
    <footer class="bg-dark text-white text-center py-3 mt-5">
        <div class="container">
            <small class="text-muted">
                ⚠️ Este sistema NO hace respaldo de su propia base de datos. Respaldar MySQL es tu responsabilidad. Un respaldo que no existe no es un respaldo.
            </small>
        </div>
    </footer>

    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/js/bootstrap.bundle.min.js"></script>
    <!-- Diff library -->
    <script src="https://cdn.jsdelivr.net/npm/diff@5.0.0/diff.min.js"></script>
</body>
</html>

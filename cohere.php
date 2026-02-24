<?php
// --- CONFIGURACIÓN — edita esto antes de usar ---
define('PASS_MAESTRA', 'tu_contrasena_aqui'); // para agregar, editar y borrar
define('PASS_REGISTROS', 'tu_contrasena_aqui'); // para los registros especiales
define('IPS_PERMITIDAS', ['127.0.0.1', '']); // agrega tus IPs aquí

// Evitar caché del navegador
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: Sat, 01 Jan 2000 00:00:00 GMT');

// Crear tabla si no existe
$sql_create_table = "
CREATE TABLE IF NOT EXISTS ai_backups (
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
);
";

// Conexión a la base de datos
$mysqli = new mysqli('localhost', 'usuario', 'contraseña', 'base_de_datos');
if ($mysqli->connect_error) die('Error de conexión: ' . $mysqli->connect_error);

// Crear tabla si no existe
if (!$mysqli->query($sql_create_table)) die('Error al crear tabla: ' . $mysqli->error);

// Funciones auxiliares
function validar_ip($ip, $ips_permitidas) {
    return in_array($ip, $ips_permitidas);
}

function calcular_hashes($contenido) {
    return [
        'tamanio' => strlen($contenido) / 1024,
        'hash_md5' => md5($contenido),
        'hash_sha1' => sha1($contenido)
    ];
}

function es_imagen_segura($base64) {
    $allowed = ['data:image/jpeg;base64', 'data:image/png;base64', 'data:image/webp;base64', 'data:image/gif;base64'];
    foreach ($allowed as $prefix) {
        if (strpos($base64, $prefix) === 0) return true;
    }
    return false;
}

// Inicio de sesión
session_start();

// Verificar IP
if (!validar_ip($_SERVER['REMOTE_ADDR'], IPS_PERMITIDAS)) {
    die('Acceso no autorizado');
}

// Incluir CDN
echo '<link href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/css/bootstrap.min.css" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@4.6.0/dist/js/bootstrap.bundle.min.js"></script>
<link href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@5.15.4/css/all.min.css" rel="stylesheet">';

// Navbar
echo '<nav class="navbar navbar-expand-lg navbar-dark bg-dark sticky-top">
        <a class="navbar-brand" href="#">Sistema de Respaldo IA</a>
        <span class="navbar-text ml-auto">';
if (isset($_SESSION['autenticado'])) {
    echo 'Autenticado | ' . $_SESSION['autenticado'];
}
echo '</span>
      </nav>';

// Procesar acciones
if (isset($_POST['accion'])) {
    $accion = $_POST['accion'];
    if ($accion == 'autenticar') {
        if (password_verify($_POST['pass'], PASS_MAESTRA)) {
            $_SESSION['autenticado'] = 'Maestra';
        }
    } elseif ($accion == 'agregar' || $accion == 'editar') {
        if (!isset($_SESSION['autenticado'])) die('Acceso denegado');
        $data = [
            'proyecto' => $_POST['proyecto'],
            'ia_utilizada' => $_POST['ia_utilizada'],
            'tipo' => $_POST['tipo'],
            'contenido' => $_POST['contenido'],
            'nombre_archivo' => $_POST['nombre_archivo'],
            'num_version' => $_POST['num_version'],
            'comentarios' => $_POST['comentarios'],
            'calificacion' => $_POST['calificacion'],
            'visible' => $_POST['visible'],
            'contrasena_ver' => $_POST['contrasena_ver'] ? password_hash($_POST['contrasena_ver'], PASSWORD_DEFAULT) : ''
        ];
        if ($_FILES['imagen']['size'] > 0) {
            $data['tipo'] = 'imagen';
            $data['contenido'] = 'data:' . mime_content_type($_FILES['imagen']['tmp_name']) . ';base64,' . base64_encode(file_get_contents($_FILES['imagen']['tmp_name']));
        }
        $hashes = calcular_hashes($data['contenido']);
        $data = array_merge($data, $hashes);
        $fields = implode(', ', array_keys($data));
        $placeholders = implode(', ', array_fill(0, count($data), '?'));
        $stmt = $mysqli->prepare("INSERT INTO ai_backups ($fields) VALUES ($placeholders)");
        $values = array_values($data);
        $types = str_repeat('s', count($values));
        $stmt->bind_param($types, ...$values);
        if (!$stmt->execute()) die('Error al guardar: ' . $stmt->error);
    } elseif ($accion == 'borrar') {
        if (!isset($_SESSION['autenticado'])) die('Acceso denegado');
        if ($_POST['confirmar'] != 'BORRAR') die('Confirma escribiendo BORRAR');
        $stmt = $mysqli->prepare("DELETE FROM ai_backups WHERE id = ?");
        $stmt->bind_param('i', $_POST['id']);
        if (!$stmt->execute()) die('Error al borrar: ' . $stmt->error);
    }
}

// Mostrar contenido
if (isset($_GET['ver'])) {
    $stmt = $mysqli->prepare("SELECT * FROM ai_backups WHERE id = ?");
    $stmt->bind_param('i', $_GET['ver']);
    $stmt->execute();
    $result = $stmt->get_result();
    $registro = $result->fetch_assoc();
    if ($registro['contrasena_ver'] && !isset($_SESSION['pass_ver_' . $registro['id']])) {
        if (isset($_POST['pass_ver'])) {
            if (password_verify($_POST['pass_ver'], $registro['contrasena_ver'])) {
                $_SESSION['pass_ver_' . $registro['id']] = true;
            } else {
                echo 'Contraseña incorrecta';
                exit;
            }
        }
        echo '<form method="post">
                <input type="password" name="pass_ver" required>
                <button type="submit">Verificar</button>
              </form>';
        exit;
    }
    echo '<h2>Detalles del Registro</h2>';
    echo '<p><strong>Proyecto:</strong> ' . htmlspecialchars($registro['proyecto']) . '</p>';
    // ... (mostrar todos los campos)
    if ($registro['tipo'] == 'imagen' && es_imagen_segura($registro['contenido'])) {
        echo '<img src="' . htmlspecialchars($registro['contenido']) . '" class="img-fluid">';
    } else {
        echo '<textarea readonly class="form-control">' . htmlspecialchars($registro['contenido']) . '</textarea>';
    }
    // Dif entre versiones
    $stmt = $mysqli->prepare("SELECT * FROM ai_backups WHERE proyecto = ? AND nombre_archivo = ? ORDER BY fecha DESC");
    $stmt->bind_param('ss', $registro['proyecto'], $registro['nombre_archivo']);
    $stmt->execute();
    $result = $stmt->get_result();
    $versiones = $result->fetch_all(MYSQLI_ASSOC);
    if (count($versiones) > 1) {
        echo '<h3>Comparar Versiones</h3>';
        // ... (selector de versiones y diff)
    }
}

// Listado de registros
$filtros = [];
if (isset($_GET['buscar'])) {
    $filtros[] = "comentarios LIKE ? OR contenido LIKE ?";
    $search = '%' . $mysqli->real_escape_string($_GET['buscar']) . '%';
    $types = 'ss';
    $params = [$search, $search];
}
$sql = "SELECT * FROM ai_backups WHERE visible = 'SI'";
if ($filtros) {
    $sql .= " AND " . implode(' AND ', $filtros);
}
$sql .= " ORDER BY fecha DESC LIMIT 10 OFFSET " . (isset($_GET['pagina']) ? $_GET['pagina'] * 10 : 0);
$stmt = $mysqli->prepare($sql);
if ($filtros) $stmt->bind_param($types, ...$params);
$stmt->execute();
$result = $stmt->get_result();
echo '<table class="table table-striped">
        <thead><tr><th>Fecha</th><th>Proyecto</th><th>IA</th><th>Tipo</th><th>Versión</th><th>Calificación</th><th>Tamaño</th><th>Archivo</th><th>Visible</th><th>Acciones</th></tr></thead>
        <tbody>';
while ($row = $result->fetch_assoc()) {
    echo '<tr>
            <td>' . htmlspecialchars($row['fecha']) . '</td>
            <td>' . htmlspecialchars($row['proyecto']) . '</td>
            <td>' . htmlspecialchars($row['ia_utilizada']) . '</td>
            <td>' . htmlspecialchars($row['tipo']) . '</td>
            <td>' . htmlspecialchars($row['num_version']) . '</td>
            <td>' . htmlspecialchars($row['calificacion']) . '</td>
            <td>' . htmlspecialchars($row['tamanio']) . ' KB</td>
            <td>' . htmlspecialchars($row['nombre_archivo']) . '</td>
            <td>' . htmlspecialchars($row['visible']) . '</td>
            <td>
              <a href="?ver=' . $row['id'] . '">Ver</a> | 
              <a href="?editar=' . $row['id'] . '">Editar</a> | 
              <a href="?borrar=' . $row['id'] . '">Borrar</a> | 
              <a href="?nueva=' . $row['id'] . '">Nueva Versión</a>
            </td>
          </tr>';
}
echo '</tbody></table>';

// Footer
echo '<footer class="text-muted small">
        ⚠️ Este sistema NO hace respaldo de su propia base de datos. Respaldar MySQL es tu responsabilidad. Un respaldo que no existe no es un respaldo.
      </footer>';

// Manejo de errores de POST size
if (isset($_SERVER['CONTENT_LENGTH']) && $_SERVER['CONTENT_LENGTH'] > 0 && empty($_POST)) {
    echo '<div class="alert alert-danger">
            Error: El contenido enviado es demasiado grande. Revisa el post_max_size de tu servidor.
          </div>';
}
?>

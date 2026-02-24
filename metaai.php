<?php
// --- CONFIGURACIÓN — edita esto antes de usar ---
define('PASS_MAESTRA', 'tu_contrasena_maestra_aqui'); // para agregar, editar y borrar
define('PASS_REGISTROS', 'tu_contrasena_individual_por_defecto_aqui'); // para registros especiales si no se especifica otra
define('IPS_PERMITIDAS', ['127.0.0.1', '::1']); // agrega tus IPs aquí. Usa '::1' para localhost en IPv6.
// --- CONFIGURACIÓN DE LA BASE DE DATOS ---
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_NAME', 'ia_backups_db');
define('TABLE_NAME', 'ai_backups');
// Headers para evitar caché del navegador
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: Sat, 01 Jan 2000 00:00:00 GMT');
header('Content-Type: text/html; charset=UTF-8');
session_start();
// Control de acceso por IP
$client_ip = $_SERVER['REMOTE_ADDR'];
if (!in_array($client_ip, IPS_PERMITIDAS)) {
    die('<div class="alert alert-danger" role="alert">Acceso no autorizado desde IP: '. htmlspecialchars($client_ip). '</div>');
}
// Conexión a la base de datos
$mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
// Verificar conexión
if ($mysqli->connect_error) {
    // Intentar crear la base de datos si no existe
    $mysqli_no_db = new mysqli(DB_HOST, DB_USER, DB_PASS);
    if ($mysqli_no_db->connect_error) {
        die('Error de conexión a MySQL: '. htmlspecialchars($mysqli_no_db->connect_error));
    }
    $create_db_query = "CREATE DATABASE IF NOT EXISTS ". DB_NAME. " CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;";
    if ($mysqli_no_db->query($create_db_query)) {
        $mysqli_no_db->select_db(DB_NAME);
    } else {
        die('Error al crear la base de datos: '. htmlspecialchars($mysqli_no_db->error));
    }
    $mysqli_no_db->close();
    // Reintentar conexión con la base de datos creada
    $mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    if ($mysqli->connect_error) {
        die('Error de conexión a MySQL (después de intentar crear DB): '. htmlspecialchars($mysqli->connect_error));
    }
}
// Comentario SQL para la creación de la tabla
/*
CREATE TABLE IF NOT EXISTS ai_backups (
    id INT AUTO_INCREMENT PRIMARY KEY,
    proyecto VARCHAR(100) NOT NULL,
    ia_utilizada VARCHAR(50) NOT NULL,
    tipo VARCHAR(20) NOT NULL,
    contenido LONGTEXT NOT NULL,
    nombre_archivo VARCHAR(150) NULL,
    num_version DECIMAL(14,6) NOT NULL,
    comentarios LONGTEXT NULL,
    calificacion DECIMAL(14,6) NULL,
    visible VARCHAR(2) NOT NULL DEFAULT 'SI',
    fecha DATETIME NOT NULL,
    contrasena_ver VARCHAR(255) NULL,
    tamanio DECIMAL(14,6) NULL,
    hash_md5 VARCHAR(32) NULL,
    hash_sha1 VARCHAR(40) NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
*/
// Crear tabla si no existe
$create_table_query = "
CREATE TABLE IF NOT EXISTS ". TABLE_NAME. " (
    id INT AUTO_INCREMENT PRIMARY KEY,
    proyecto VARCHAR(100) NOT NULL,
    ia_utilizada VARCHAR(50) NOT NULL,
    tipo VARCHAR(20) NOT NULL,
    contenido LONGTEXT NOT NULL,
    nombre_archivo VARCHAR(150) NULL,
    num_version DECIMAL(14,6) NOT NULL,
    comentarios LONGTEXT NULL,
    calificacion DECIMAL(14,6) NULL,
    visible VARCHAR(2) NOT NULL DEFAULT 'SI',
    fecha DATETIME NOT NULL,
    contrasena_ver VARCHAR(255) NULL,
    tamanio DECIMAL(14,6) NULL,
    hash_md5 VARCHAR(32) NULL,
    hash_sha1 VARCHAR(40) NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
";
if (!$mysqli->query($create_table_query)) {
    die('Error al crear la tabla '. TABLE_NAME. ': '. htmlspecialchars($mysqli->error));
}
// Funciones auxiliares
function is_authenticated() {
    return isset($_SESSION['authenticated']) && $_SESSION['authenticated'] === true;
}
function authenticate($password) {
    if ($password === PASS_MAESTRA) {
        $_SESSION['authenticated'] = true;
        return true;
    }
    return false;
}
function logout() {
    session_unset();
    session_destroy();
}
function calculate_content_hashes_size($content) {
    $tamanio = round(strlen($content) / 1024, 6); // en KB
    $hash_md5 = md5($content);
    $hash_sha1 = sha1($content);
    return ['tamanio' => $tamanio, 'hash_md5' => $hash_md5, 'hash_sha1' => $hash_sha1];
}
function get_next_version($proyecto, $nombre_archivo) {
    global $mysqli;
    $stmt = $mysqli->prepare("SELECT MAX(num_version) AS max_version FROM ". TABLE_NAME. " WHERE proyecto =? AND nombre_archivo =?");
    $stmt->bind_param("ss", $proyecto, $nombre_archivo);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();
    $stmt->close();
    if ($row['max_version']) {
        return floatval($row['max_version']) + 1.000000;
    }
    return 1.000000;
}
function get_other_versions($proyecto, $nombre_archivo, $current_id = null) {
    global $mysqli;
    $query = "SELECT id, num_version, fecha FROM ". TABLE_NAME. " WHERE proyecto =? AND nombre_archivo =? ORDER BY fecha DESC";
    if ($current_id) {
        $query = "SELECT id, num_version, fecha FROM ". TABLE_NAME. " WHERE proyecto =? AND nombre_archivo =? AND id!=? ORDER BY fecha DESC";
        $stmt = $mysqli->prepare($query);
        $stmt->bind_param("ssi", $proyecto, $nombre_archivo, $current_id);
    } else {
        $stmt = $mysqli->prepare($query);
        $stmt->bind_param("ss", $proyecto, $nombre_archivo);
    }
    $stmt->execute();
    $result = $stmt->get_result();
    $versions = [];
    while ($row = $result->fetch_assoc()) {
        $versions[] = $row;
    }
    $stmt->close();
    return $versions;
}
function render_diff($old_text, $new_text) {
    $old_lines = explode("\n", $old_text);
    $new_lines = explode("\n", $new_text);
    $diff = new Diff($old_lines, $new_lines); // Usamos la clase Diff interna
    $output = '';
    foreach ($diff->getGroupedOpcodes() as $group) {
        foreach ($group as $opcode) {
            list($tag, $i1, $i2, $j1, $j2) = $opcode;
            if ($tag == 'equal') {
                for ($i = $i1; $i < $i2; $i++) {
                    $output.= '<div class="diff-line diff-equal">'. htmlspecialchars($old_lines[$i]). '</div>';
                }
            } elseif ($tag == 'replace') {
                for ($i = $i1; $i < $i2; $i++) {
                    $output.= '<div class="diff-line diff-removed"><del>'. htmlspecialchars($old_lines[$i]). '</del></div>';
                }
                for ($i = $j1; $i < $j2; $i++) {
                    $output.= '<div class="diff-line diff-added"><ins>'. htmlspecialchars($new_lines[$i]). '</ins></div>';
                }
            } elseif ($tag == 'delete') {
                for ($i = $i1; $i < $i2; $i++) {
                    $output.= '<div class="diff-line diff-removed"><del>'. htmlspecialchars($old_lines[$i]). '</del></div>';
                }
            } elseif ($tag == 'insert') {
                for ($i = $j1; $i < $j2; $i++) {
                    $output.= '<div class="diff-line diff-added"><ins>'. htmlspecialchars($new_lines[$i]). '</ins></div>';
                }
            }
        }
    }
    return $output;
}
// Clase Diff para comparar textos (adaptada para PHP procedural)
// Basada en: https://github.com/paulgb/simplediff
class Diff {
    private $a = [];
    private $b = [];
    private $n_a;
    private $n_b;
    private $base;
    private $opcodes = [];
    public function __construct($a, $b) {
        $this->a = $a;
        $this->b = $b;
        $this->n_a = count($a);
        $this->n_b = count($b);
        $this->calculateDiff();
    }
    private function calculateDiff() {
        $this->base = $this->createBase();
        $this->opcodes = $this->extractOpcodes();
    }
    private function createBase() {
        $base = [];
        for ($i = 0; $i < $this->n_a; $i++) {
            $value = $this->a[$i];
            if (!isset($base[$value])) {
                $base[$value] = [];
            }
            $base[$value][] = $i;
        }
        return $base;
    }
    private function extractOpcodes() {
        $matching_blocks = $this->getMatchingBlocks();
        $opcodes = [];
        $a_idx = 0;
        $b_idx = 0;
        foreach ($matching_blocks as $block) {
            list($old_start, $new_start, $length) = $block;
            if ($a_idx < $old_start || $b_idx < $new_start) {
                if ($old_start - $a_idx == $new_start - $b_idx) {
                    $opcodes[] = ['replace', $a_idx, $old_start, $b_idx, $new_start];
                } elseif ($old_start - $a_idx > $new_start - $b_idx) {
                    $opcodes[] = ['delete', $a_idx, $old_start, $b_idx, $b_idx];
                    if ($new_start - $b_idx > 0) {
                        $opcodes[] = ['insert', $old_start, $old_start, $b_idx, $new_start];
                    }
                } else {
                    $opcodes[] = ['insert', $a_idx, $a_idx, $b_idx, $new_start];
                    if ($old_start - $a_idx > 0) {
                        $opcodes[] = ['delete', $a_idx, $old_start, $new_start, $new_start];
                    }
                }
            }
            if ($length) {
                $opcodes[] = ['equal', $old_start, $old_start + $length, $new_start, $new_start + $length];
            }
            $a_idx = $old_start + $length;
            $b_idx = $new_start + $length;
        }
        if ($a_idx < $this->n_a || $b_idx < $this->n_b) {
            if ($this->n_a - $a_idx == $this->n_b - $b_idx) {
                $opcodes[] = ['replace', $a_idx, $this->n_a, $b_idx, $this->n_b];
            } elseif ($this->n_a - $a_idx > $this->n_b - $b_b) {
                $opcodes[] = ['delete', $a_idx, $this->n_a, $b_idx, $b_idx];
                if ($this->n_b - $b_idx > 0) {
                    $opcodes[] = ['insert', $this->n_a, $this->n_a, $b_idx, $this->n_b];
                }
            } else {
                $opcodes[] = ['insert', $a_idx, $a_idx, $b_idx, $this->n_b];
                if ($this->n_a - $a_idx > 0) {
                    $opcodes[] = ['delete', $a_idx, $this->n_a, $this->n_b, $this->n_b];
                }
            }
        }
        return $opcodes;
    }
    private function getMatchingBlocks() {
        $non_matching_a = [];
        $non_matching_b = [];
        $matching_blocks = [];
        foreach ($this->b as $b_line_num => $b_line_value) {
            if (isset($this->base[$b_line_value])) {
                foreach ($this->base[$b_line_value] as $a_line_num) {
                    $match_block = $this->findLongestMatch($a_line_num, $b_line_num);
                    if ($match_block) {
                        $matching_blocks[] = $match_block;
                    }
                }
            }
        }
        // Simplificación: no se implementa el algoritmo Myers aquí,
        // esto es una versión muy básica para el ejemplo.
        // Para una diff real, se requiere un algoritmo más sofisticado.
        // Solo un bloque de coincidencia para este ejemplo simplificado.
        if (count($matching_blocks) > 0) {
            return [$matching_blocks[0]];
        }
        return [[0, 0, 0]]; // No match
    }
    private function findLongestMatch($a_start, $b_start) {
        $len = 0;
        while ($a_start + $len < $this->n_a && $b_start + $len < $this->n_b &&
               $this->a[$a_start + $len] == $this->b[$b_start + $len]) {
            $len++;
        }
        return [$a_start, $b_start, $len];
    }
    public function getOpcodes() {
        return $this->opcodes;
    }
    public function getGroupedOpcodes() {
        if (empty($this->opcodes)) {
            return [];
        }
        $groups = [];
        $current_group = [];
        foreach ($this->opcodes as $opcode) {
            // Unir opcodes de inserción/eliminación/reemplazo consecutivos
            if (empty($current_group) || ($opcode[0] == 'equal' && count($current_group) > 0)) {
                if (!empty($current_group)) {
                    $groups[] = $current_group;
                }
                $current_group = [$opcode];
            } else {
                $current_group[] = $opcode;
            }
        }
        if (!empty($current_group)) {
            $groups[] = $current_group;
        }
        return $groups;
    }
}
// Manejo de acciones
$action = $_GET['action']?? 'list';
$message = '';
$message_type = '';
if (isset($_POST['authenticate'])) {
    if (authenticate($_POST['master_password'])) {
        $message = 'Autenticación exitosa.';
        $message_type = 'success';
        header('Location: index.php'); // Redirigir para limpiar POST
        exit();
    } else {
        $message = 'Contraseña maestra incorrecta.';
        $message_type = 'danger';
    }
}
if (isset($_GET['logout'])) {
    logout();
    $message = 'Sesión cerrada.';
    $message_type = 'info';
    header('Location: index.php'); // Redirigir para limpiar GET
    exit();
}
// Detectar post_max_size si el POST está vacío pero no debería estarlo
if ($_SERVER['REQUEST_METHOD'] === 'POST' && empty($_POST) && $_SERVER['CONTENT_LENGTH'] > 0) {
    $max_size = ini_get('post_max_size');
    $message = "Advertencia: La carga de datos falló, posiblemente debido a que el tamaño de los datos excede el límite de ". htmlspecialchars($max_size). " del servidor. Revise el 'post_max_size' en su configuración PHP.";
    $message_type = 'warning';
}
?>
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sistema de Respaldo de Prompts IA</title>
    <!-- Bootstrap 4.6 CSS -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css" integrity="sha384-xOolHFLEh07PJGoPkLv1IbcEPTNtaed2xpHsD9ESMhqIYd0nLMwNLD69Npy4HI+N" crossorigin="anonymous">
    <!-- FontAwesome CSS -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax

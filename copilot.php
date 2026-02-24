<?php
/*
-- SQL para crear la tabla automáticamente si no existe:

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
*/

// --- CONFIGURACIÓN — edita esto antes de usar ---
define('PASS_MAESTRA', 'tu_contrasena_aqui');   // para agregar, editar y borrar
define('PASS_REGISTROS', 'tu_contrasena_aqui'); // para los registros especiales
define('IPS_PERMITIDAS', ['127.0.0.1','']);     // agrega tus IPs aquí

// --- CABECERAS DE SEGURIDAD ---
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: Sat, 01 Jan 2000 00:00:00 GMT');

session_start();

// --- CONTROL DE IP ---
if(!in_array($_SERVER['REMOTE_ADDR'], IPS_PERMITIDAS)){
    die("Acceso no autorizado");
}

// --- CONEXIÓN BD ---
$mysqli = new mysqli("localhost","root","","ai_backups_db");
if($mysqli->connect_error){ die("Error DB: ".$mysqli->connect_error); }

// Crear tabla si no existe
$mysqli->query("CREATE TABLE IF NOT EXISTS ai_backups (
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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

// --- LOGIN MAESTRO ---
if(isset($_POST['login_maestra'])){
    if($_POST['pass']==PASS_MAESTRA){
        $_SESSION['auth']=true;
    } else {
        echo "<div class='alert alert-danger'>Contraseña incorrecta</div>";
    }
}
if(isset($_GET['logout'])){
    session_destroy();
    header("Location: index.php");
    exit;
}

// --- HTML HEAD ---
?>
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="robots" content="noindex, nofollow">
<title>Sistema Respaldo Prompts IA</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@5.15.4/css/all.min.css">
<style>
.diff-old { background-color:#f8d7da; }
.diff-new { background-color:#d4edda; }
</style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark sticky-top">
  <a class="navbar-brand" href="index.php">Respaldo IA</a>
  <div class="ml-auto text-white">
    <?php echo isset($_SESSION['auth'])?"<i class='fas fa-lock-open'></i> Autenticado":"<i class='fas fa-lock'></i> Solo lectura"; ?>
  </div>
</nav>
<div class="container mt-4">
<?php
// --- MENÚ ---
echo "<ul class='nav nav-tabs'>
<li class='nav-item'><a class='nav-link' href='?'>Ver registros</a></li>
<li class='nav-item'><a class='nav-link' href='?add=1'>Agregar nuevo</a></li>
<li class='nav-item'><a class='nav-link' href='?search=1'>Buscar</a></li>
<li class='nav-item'><a class='nav-link' href='?logout=1'>Cerrar sesión</a></li>
</ul><br>";

// --- FUNCIONALIDADES ---
// Listado
if(!isset($_GET['add']) && !isset($_GET['view']) && !isset($_GET['edit']) && !isset($_GET['search'])){
    $page = isset($_GET['page'])?(int)$_GET['page']:1;
    $limit=10; $offset=($page-1)*$limit;
    $res=$mysqli->query("SELECT SQL_CALC_FOUND_ROWS * FROM ai_backups WHERE visible='SI' ORDER BY fecha DESC LIMIT $offset,$limit");
    $total=$mysqli->query("SELECT FOUND_ROWS()")->fetch_row()[0];
    echo "<table class='table table-bordered table-sm'><thead><tr>
    <th>Fecha</th><th>Proyecto</th><th>IA</th><th>Tipo</th><th>Versión</th><th>Calificación</th><th>Tamaño KB</th><th>Archivo</th><th>Visible</th><th>Acciones</th></tr></thead><tbody>";
    while($row=$res->fetch_assoc()){
        echo "<tr>
        <td>".htmlspecialchars($row['fecha'])."</td>
        <td>".htmlspecialchars($row['proyecto'])."</td>
        <td>".htmlspecialchars($row['ia_utilizada'])."</td>
        <td>".htmlspecialchars($row['tipo'])."</td>
        <td>".htmlspecialchars($row['num_version'])."</td>
        <td>".htmlspecialchars($row['calificacion'])."</td>
        <td>".htmlspecialchars($row['tamanio'])."</td>
        <td>".htmlspecialchars($row['nombre_archivo'])."</td>
        <td>".htmlspecialchars($row['visible'])."</td>
        <td>
        <a href='?view=".$row['id']."' class='btn btn-info btn-sm'>Ver</a>
        ".(isset($_SESSION['auth'])?"<a href='?edit=".$row['id']."' class='btn btn-warning btn-sm'>Editar</a>
        <a href='?delete=".$row['id']."' class='btn btn-danger btn-sm'>Borrar</a>
        <a href='?newver=".$row['id']."' class='btn btn-secondary btn-sm'>Nueva versión</a>":"")."
        ".(!empty($row['contrasena_ver'])?" <i class='fas fa-lock'></i>":"")."
        </td></tr>";
    }
    echo "</tbody></table>";
    $pages=ceil($total/$limit);
    echo "<nav><ul class='pagination'>";
    for($i=1;$i<=$pages;$i++){
        echo "<li class='page-item ".($i==$page?"active":"")."'><a class='page-link' href='?page=$i'>$i</a></li>";
    }
    echo "</ul></nav>";
}

// Ver registro
if(isset($_GET['view'])){
    $id=(int)$_GET['view'];
    $stmt=$mysqli->prepare("SELECT * FROM ai_backups WHERE id=?");
    $stmt->bind_param("i",$id); $stmt->execute(); $res=$stmt->get_result();
    if($row=$res->fetch_assoc()){
        if(!empty($row['contrasena_ver'])){
            if(isset($_POST['pass_reg'])){
                if(password_verify($_POST['pass_reg'],$row['contrasena_ver'])){
                    $_SESSION['view_'.$id]=true;
                } else echo "<div class='alert alert-danger'>Contraseña incorrecta</div>";
            }
            if(!isset($_SESSION['view_'.$id])){
                echo "<form method='post'><input type='password' name='pass_reg' class='form-control' placeholder='Contraseña registro'><button class='btn btn-primary mt-2'>Ver</button></form>";
                exit;
            }
        }
        echo "<h3>".htmlspecialchars($row['nombre_archivo'])." v".htmlspecialchars($row['num_version'])."</h3>";
        echo "<pre>".htmlspecialchars($row['contenido'])."</pre>";
        if($row['tipo']=='imagen'){
            $c=$row['contenido'];
            if(preg_match('/^(?:[A-Za-z0-9+\/=]+)$/',$c)){
                echo "<img src='data:image/png;base64,".$c."' class='img-fluid'>";
            } else echo "<div class='alert alert-danger'>Imagen inválida</div>";
        }
        echo "<p>MD5: ".$row['hash_md5']." SHA1: ".$row['hash_sha1']." Tamaño: ".$row['tamanio']." KB</p>";
    }
}

// Footer
echo "<footer class='mt-5 text-muted'><small>⚠️ Este sistema NO hace respaldo de su propia base de datos. Respaldar MySQL es tu responsabilidad. Un respaldo que no existe no es un respaldo.</small></footer>";
?>
</div>
</body>
</html>

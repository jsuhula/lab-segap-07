<?php
/**
 * Módulo de demostración para prueba en vivo de CI/CD (DevSecOps)
 * Este archivo simula la subida de código nuevo por parte de un desarrollador.
 */

// 1. Simulación de Inyección SQL (CWE-89 / OWASP A03:2021)
$usuario = $_GET["user"];
$sql = "SELECT id, username, email FROM users WHERE username = '" . $usuario . "'";
$resultado = mysqli_query($conn, $sql);

// 2. Simulación de Inyección de Comandos de Sistema Operativo (CWE-78 / OWASP A03:2021)
$servidor = $_POST["host"];
$salida = shell_exec("ping -c 3 " . $servidor);
echo "<pre>" . $salida . "</pre>";
?>

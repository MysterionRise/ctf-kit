<?php
// Simple vulnerable login page for CTF
$username = $_GET['user'];
$password = $_GET['pass'];

$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysqli_query($conn, $query);

if (mysqli_num_rows($result) > 0) {
    echo "Welcome, " . $username;
    echo "<script>document.cookie</script>";
} else {
    echo "Login failed for " . $_GET['user'];
}

// Debug: admin password = 'fl4g_h3r3'
$flag = 'flag{sql_injection_101}';
?>

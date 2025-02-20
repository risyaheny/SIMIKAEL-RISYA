<?php
session_start();
require_once 'connect.php';

// Register
if (isset($_POST['username'], $_POST['password'], $_POST['role'])) {
    $username = $_POST['username'];
    $password = password_hash($_POST['password'], PASSWORD_DEFAULT);
    $role = $_POST['role'];

    $allowed_levels = ['admin', 'guru', 'siswa'];
    if (!in_array($role, $allowed_levels)) {
        die("Role tidak valid!");
    }

    $stmt = $conn->prepare("INSERT INTO user (username, password, role) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $username, $password, $role);
    
    if ($stmt->execute()) {
        echo "<script>alert('Registrasi berhasil!'); window.location.href='sign-in-up.php';</script>";
    } else {
        echo "Error: " . $stmt->error;
    }
    $stmt->close();
}

// Login
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['action']) && $_POST['action'] == 'login') {
    if (isset($_POST['username'], $_POST['password'])) {
        $username = $_POST['username'];
        $password = $_POST['password'];

        $stmt = $conn->prepare("SELECT * FROM user WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            $user = $result->fetch_assoc();
        
            if (password_verify($password, $user['password'])) {
                session_regenerate_id(); 
                $_SESSION['id_user'] = $user['id_user'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['role'] = $user['role'];
        
                // Redirect sesuai role
                switch ($user['role']) {
                    case 'admin':
                        echo "<script>
                            alert('Login berhasil sebagai Admin!');
                            window.location.href='../backend/dashboard.php';
                        </script>";
                        break;
                    case 'guru':
                        echo "<script>
                            alert('Login berhasil sebagai Guru!');
                            window.location.href='../backend/admin_guru/dashboard.php';
                        </script>";
                        break;
                    case 'siswa':
                        echo "<script>
                            alert('Login berhasil sebagai Siswa!');
                            window.location.href='../index_login.php';
                        </script>";
                        break;
                    default:
                        echo "<script>
                            alert('Role user tidak dikenal.');
                            window.location.href='index.php';
                        </script>";
                        session_destroy();
                        break;
                }
                exit();
            } else {
                echo "<script>
                    alert('Password salah!');
                    window.location.href='sign-in-up.php';
                </script>";
                exit();
            }
        } else {
            echo "<script>
                alert('Username tidak ditemukan!');
                window.location.href='sign-in-up.php';
            </script>";
            exit();
        }       
    }
} 
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    <link rel="stylesheet" href="style.css">
    <title>Login 𝕊𝕀𝕄𝕀𝕂✮𝔼𝕃</title>
</head>
<body>
    <div class="container" id="container">
        <div class="form-container sign-up">
        <form method="post" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
            <h1>Create Account</h1>
            <input type="text" name="username" placeholder="User Name" required>
            <input type="password" name="password" placeholder="Password" required>
            <select name="role" required>
                <option value="siswa">Siswa</option>
                <option value="admin">Admin</option>
                <option value="guru">Guru</option>
            </select>

            <input type="hidden" name="action" value="register"> <!-- Hidden action field for registration -->
            <button type="submit">Sign Up</button>
        </form>
        </div>

        <div class="form-container sign-in">
        <form method="post" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>">
            <h1>Sign In</h1>
            <input type="text" name="username" placeholder="Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <input type="hidden" name="action" value="login"> <!-- Hidden action field for login -->
            <button type="submit">Sign In</button>
        </form>
        </div>

        <div class="toggle-container">
        <div class="toggle">
                <div class="toggle-panel toggle-left">
                    <h1>Welcome Back!</h1>
                    <p>Enter your personal details to use all of site features</p>
                    <button class="hidden" id="login">Sign In</button>
                </div>
                <div class="toggle-panel toggle-right">
                    <h1>Hello, Friend!</h1>
                    <p>Register with your personal details to use all of site features</p>
                    <button class="hidden" id="register">Sign Up</button>
                </div>
            </div>
        </div>
    </div>

    <script src="script.js"></script>
</body>
</html>
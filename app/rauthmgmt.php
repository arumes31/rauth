<?php
require 'vendor/autoload.php';

use RAuth\Core\Config;
use RAuth\Core\Redis;
use RAuth\Core\Auth;
use RAuth\Core\Logger;

Logger::init();
session_start();

$serverSecret = Config::getRequired('SERVER_SECRET');
$auth = new Auth($serverSecret);

$clientIp = Auth::getClientIP();

// CSRF Protection
function generateCsrfToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCsrfToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// 1. Authenticate Admin
$encryptedToken = $_COOKIE['X-rcloudauth-authtoken'] ?? '';
if (!$encryptedToken) {
    http_response_code(401);
    exit("Unauthorized");
}

$token = $auth->decryptToken($encryptedToken);
if (!$token) {
    http_response_code(401);
    exit("Unauthorized");
}

try {
    $redisTokens = Redis::getInstance(1);
    $redisUsers = Redis::getInstance(0);

    $tokenData = $redisTokens->hgetall("X-rcloudauth-authtoken=$token");
    if (!isset($tokenData['status']) || $tokenData['status'] !== 'valid') {
        http_response_code(401);
        exit("Unauthorized");
    }

    $username = $tokenData['username'];
    $userData = $redisUsers->hgetall("user:$username");
    
    // Check if admin (you might want to adjust this logic based on your needs)
    // For now, let's assume the user in INITIAL_USER is admin or has is_admin=1
    if (!isset($userData['is_admin']) && $username !== Config::get('INITIAL_USER')) {
        http_response_code(403);
        exit("Forbidden");
    }
} catch (\Exception $e) {
    Logger::log("Admin auth error: " . $e->getMessage());
    http_response_code(500);
    exit("Internal Server Error");
}

// 2. Handle Actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    $csrfToken = $_POST['csrf_token'] ?? '';

    if (!validateCsrfToken($csrfToken)) {
        $error = "Invalid CSRF token";
    } elseif ($action === 'clear_tokens') {
        try {
            $keys = $redisTokens->keys('X-rcloudauth-authtoken=*');
            if (!empty($keys)) {
                $redisTokens->del($keys);
                $success = "Successfully cleared " . count($keys) . " tokens.";
            } else {
                $success = "No active tokens found.";
            }
        } catch (\Exception $e) {
            $error = "Failed to clear tokens: " . $e->getMessage();
        }
    }
}

$csrfToken = generateCsrfToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Management | RCloudAuth</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: #121212; color: #e0e0e0; min-height: 100vh; font-family: 'Segoe UI', sans-serif; }
        .navbar { background: #1e1e1e; border-bottom: 1px solid #333; }
        .card { background: #1e1e1e; border: 1px solid #333; border-radius: 12px; margin-top: 2rem; }
        .btn-danger { background: #d32f2f; border: none; }
        .btn-danger:hover { background: #b71c1c; }
        .alert { border-radius: 8px; border: none; }
        .alert-success { background: #2e7d32; color: #fff; }
        .alert-danger { background: #c62828; color: #fff; }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark">
        <div class="container">
            <a class="navbar-brand" href="#">RCloudAuth Admin</a>
            <span class="navbar-text">Logged in as: <?php echo htmlspecialchars($username); ?></span>
        </div>
    </nav>

    <div class="container">
        <div class="row justify-content-center">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-body">
                        <h4 class="card-title mb-4">Session Management</h4>
                        
                        <?php if (isset($success)): ?>
                            <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
                        <?php endif; ?>
                        <?php if (isset($error)): ?>
                            <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
                        <?php endif; ?>

                        <p>Total active sessions are stored in the token database. You can invalidate all of them at once.</p>
                        
                        <form method="POST" onsubmit="return confirm('Are you sure you want to invalidate ALL sessions? This will log everyone out.');">
                            <input type="hidden" name="action" value="clear_tokens">
                            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                            <button type="submit" class="btn btn-danger">Clear All Active Sessions</button>
                        </form>
                    </div>
                </div>

                <div class="mt-4 text-center text-muted" style="font-size: 0.8rem;">
                    Server IP: <?php echo htmlspecialchars($clientIp); ?>
                </div>
            </div>
        </div>
    </div>
</body>
</html>

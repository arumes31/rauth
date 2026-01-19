<?php
require 'vendor/autoload.php';

use RAuth\Core\Config;
use RAuth\Core\Redis;
use RAuth\Core\Auth;
use RAuth\Core\Logger;
use RAuth\Core\AuditLogger;

Logger::init();
session_start();

$serverSecret = Config::getRequired('SERVER_SECRET');
$auth = new Auth($serverSecret);
$audit = new AuditLogger();

// 1. Authenticate User
$encryptedToken = $_COOKIE['X-rcloudauth-authtoken'] ?? '';
if (!$encryptedToken || !($token = $auth->decryptToken($encryptedToken))) {
    header('Location: /rauthvalidate?rd=' . urlencode($_SERVER['REQUEST_URI']));
    exit;
}

$redisTokens = Redis::getInstance(1);
$redisUsers = Redis::getInstance(0);
$tokenData = $redisTokens->hgetall("X-rcloudauth-authtoken=$token");

if (!isset($tokenData['status']) || $tokenData['status'] !== 'valid') {
    header('Location: /rauthvalidate?rd=' . urlencode($_SERVER['REQUEST_URI']));
    exit;
}

$username = $tokenData['username'];
$user = $redisUsers->hgetall("user:$username");

// CSRF
if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        $error = "Invalid CSRF token";
    } else {
        $action = $_POST['action'] ?? '';
        
        if ($action === 'change_password') {
            $current = $_POST['current_password'] ?? '';
            $new = $_POST['new_password'] ?? '';
            $confirm = $_POST['confirm_password'] ?? '';
            
            if (!password_verify($current, $user['password'])) {
                $error = "Current password incorrect.";
            } elseif ($new !== $confirm) {
                $error = "New passwords do not match.";
            } elseif (strlen($new) < 8) {
                $error = "Password must be at least 8 characters.";
            } else {
                $redisUsers->updateUser($username, ['password' => password_hash($new, PASSWORD_BCRYPT, ['cost' => 12])]);
                $audit->log('USER_CHANGE_PASSWORD', $username);
                $success = "Password updated successfully.";
            }
        }
    }
}

// Get user specific logs
$allLogs = $audit->getLogs(200);
$userLogs = array_filter($allLogs, function($l) use ($username) {
    return $l['username'] === $username;
});

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>My Profile | RCloudAuth</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: #121212; color: #e0e0e0; min-height: 100vh; font-family: 'Segoe UI', sans-serif; }
        .navbar { background: #1e1e1e; border-bottom: 1px solid #333; }
        .card { background: #1e1e1e; border: 1px solid #333; border-radius: 12px; margin-top: 1rem; }
        .form-control { background: #2c2c2c; border-color: #444; color: #fff; }
        .form-control:focus { background: #333; color: #fff; border-color: #3f51b5; box-shadow: none; }
        .table { color: #e0e0e0; font-size: 0.9rem; }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark">
        <div class="container">
            <a class="navbar-brand" href="#">RCloudAuth</a>
            <div class="navbar-nav ms-auto">
                <?php if (($user['is_admin'] ?? '0') === '1'): ?>
                    <a class="nav-link" href="/rauthmgmt">Admin Panel</a>
                <?php endif; ?>
                <form method="POST" action="/rauthmgmt" class="d-inline">
                    <input type="hidden" name="action" value="logout">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                    <button type="submit" class="btn btn-link nav-link">Logout</button>
                </form>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <div class="row">
            <div class="col-md-4">
                <div class="card">
                    <div class="card-body">
                        <h5>Account Info</h5>
                        <hr class="border-secondary">
                        <p class="mb-1 text-muted">Username</p>
                        <p><strong><?php echo htmlspecialchars($username); ?></strong></p>
                        <p class="mb-1 text-muted">Email</p>
                        <p><strong><?php echo htmlspecialchars($user['email'] ?? 'N/A'); ?></strong></p>
                        <p class="mb-1 text-muted">Groups</p>
                        <p><span class="badge bg-secondary"><?php echo htmlspecialchars($user['groups'] ?? 'default'); ?></span></p>
                    </div>
                </div>

                <div class="card mt-3">
                    <div class="card-body">
                        <h5>Change Password</h5>
                        <?php if (isset($success)): ?>
                            <div class="alert alert-success py-2 small"><?php echo $success; ?></div>
                        <?php endif; ?>
                        <?php if (isset($error)): ?>
                            <div class="alert alert-danger py-2 small"><?php echo $error; ?></div>
                        <?php endif; ?>
                        <form method="POST">
                            <input type="hidden" name="action" value="change_password">
                            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                            <div class="mb-2">
                                <label class="small text-muted">Current Password</label>
                                <input type="password" name="current_password" class="form-control form-control-sm" required>
                            </div>
                            <div class="mb-2">
                                <label class="small text-muted">New Password</label>
                                <input type="password" name="new_password" class="form-control form-control-sm" required>
                            </div>
                            <div class="mb-3">
                                <label class="small text-muted">Confirm New Password</label>
                                <input type="password" name="confirm_password" class="form-control form-control-sm" required>
                            </div>
                            <button type="submit" class="btn btn-sm btn-primary w-100">Update Password</button>
                        </form>
                    </div>
                </div>
            </div>

            <div class="col-md-8">
                <div class="card">
                    <div class="card-body">
                        <h5>My Recent Activity</h5>
                        <div class="table-responsive">
                            <table class="table table-dark table-hover table-sm">
                                <thead>
                                    <tr>
                                        <th>Time</th>
                                        <th>Action</th>
                                        <th>IP</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($userLogs as $log): ?>
                                    <tr>
                                        <td class="text-muted"><?php echo date('Y-m-d H:i', $log['timestamp']); ?></td>
                                        <td><code><?php echo htmlspecialchars($log['action']); ?></code></td>
                                        <td><?php echo htmlspecialchars($log['ip']); ?></td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script src="/static/js/bootstrap.bundle.min.js"></script>
</body>
</html>

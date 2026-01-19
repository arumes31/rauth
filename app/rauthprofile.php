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
    <link href="/static/css/bootstrap-icons.min.css" rel="stylesheet">
    <link href="/static/css/modern.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg sticky-top">
        <div class="container">
            <a class="navbar-brand fs-3" href="#">RCloudAuth</a>
            <div class="navbar-nav ms-auto align-items-center">
                <?php if (($user['is_admin'] ?? '0') === '1'): ?>
                    <a class="nav-link small me-3" href="/rauthmgmt">
                        <i class="bi bi-speedometer2 me-1"></i> Dashboard
                    </a>
                <?php endif; ?>
                <form method="POST" action="/rauthmgmt" class="d-inline">
                    <input type="hidden" name="action" value="logout">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                    <button type="submit" class="btn btn-sm btn-outline-danger px-3">
                        <i class="bi bi-box-arrow-right"></i>
                    </button>
                </form>
            </div>
        </div>
    </nav>

    <div class="container mt-5 animate-fade-in">
        <div class="row g-4">
            <div class="col-lg-4">
                <div class="card mb-4">
                    <div class="card-body p-4 text-center">
                        <div class="display-1 text-primary mb-3">
                            <i class="bi bi-person-badge"></i>
                        </div>
                        <h4 class="mb-1"><?php echo htmlspecialchars($username); ?></h4>
                        <p class="text-muted small"><?php echo htmlspecialchars($user['email'] ?? 'No email provided'); ?></p>
                        <div class="d-flex justify-content-center gap-2 mt-3">
                            <span class="badge bg-primary bg-opacity-10 text-primary border border-primary border-opacity-25 px-3">
                                <?php echo htmlspecialchars($user['groups'] ?? 'default'); ?>
                            </span>
                        </div>
                    </div>
                </div>

                <div class="card">
                    <div class="card-header border-0 pb-0">
                        <h6 class="mb-0">Security Settings</h6>
                    </div>
                    <div class="card-body p-4">
                        <?php if (isset($success)): ?>
                            <div class="alert alert-success bg-success bg-opacity-10 text-success border-0 small mb-4">
                                <i class="bi bi-check-circle-fill me-2"></i> <?php echo $success; ?>
                            </div>
                        <?php endif; ?>
                        <?php if (isset($error)): ?>
                            <div class="alert alert-danger bg-danger bg-opacity-10 text-danger border-0 small mb-4">
                                <i class="bi bi-exclamation-circle-fill me-2"></i> <?php echo $error; ?>
                            </div>
                        <?php endif; ?>
                        
                        <form method="POST">
                            <input type="hidden" name="action" value="change_password">
                            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                            <div class="mb-3">
                                <label class="form-label text-muted small fw-bold">Current Password</label>
                                <input type="password" name="current_password" class="form-control" required>
                            </div>
                            <div class="mb-3">
                                <label class="form-label text-muted small fw-bold">New Password</label>
                                <input type="password" name="new_password" class="form-control" required>
                            </div>
                            <div class="mb-4">
                                <label class="form-label text-muted small fw-bold">Verify Password</label>
                                <input type="password" name="confirm_password" class="form-control" required>
                            </div>
                            <button type="submit" class="btn btn-primary w-100 py-2">Update Credentials</button>
                        </form>
                    </div>
                </div>
            </div>

            <div class="col-lg-8">
                <div class="card">
                    <div class="card-header border-0 d-flex justify-content-between align-items-center">
                        <h6 class="mb-0">Security Activity Feed</h6>
                        <span class="text-muted extra-small">Last 50 events</span>
                    </div>
                    <div class="card-body p-0">
                        <div class="table-responsive">
                            <table class="table table-hover mb-0">
                                <thead>
                                    <tr>
                                        <th class="ps-4">Timestamp</th>
                                        <th>Event Type</th>
                                        <th class="pe-4">Access Point</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($userLogs as $log): ?>
                                    <tr class="align-middle">
                                        <td class="ps-4 text-muted small">
                                            <?php echo date('M d, H:i', $log['timestamp']); ?>
                                        </td>
                                        <td>
                                            <span class="text-info small fw-bold"><?php echo htmlspecialchars($log['action']); ?></span>
                                        </td>
                                        <td class="pe-4">
                                            <div class="extra-small text-muted"><i class="bi bi-hdd-network me-1"></i> <?php echo htmlspecialchars($log['ip']); ?></div>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                    <?php if (empty($userLogs)): ?>
                                        <tr><td colspan="3" class="text-center py-4 text-muted small">No recent activity detected.</td></tr>
                                    <?php endif; ?>
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
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
    } else {
        try {
            if ($action === 'clear_all_tokens') {
                $keys = $redisTokens->keys('X-rcloudauth-authtoken=*');
                if (!empty($keys)) {
                    $redisTokens->del($keys);
                    $audit->log('ADMIN_CLEAR_ALL_SESSIONS', $username);
                    $success = "Successfully cleared all sessions.";
                }
            } elseif ($action === 'delete_user') {
                $targetUser = $_POST['target_user'] ?? '';
                if ($targetUser && $targetUser !== $username) {
                    $redisUsers->del("user:$targetUser");
                    $redisUsers->srem('users', $targetUser);
                    $audit->log('ADMIN_DELETE_USER', $username, ['target' => $targetUser]);
                    $success = "User $targetUser deleted.";
                }
            } elseif ($action === 'invalidate_session') {
                $targetToken = $_POST['target_token'] ?? '';
                if ($targetToken) {
                    $redisTokens->del("X-rcloudauth-authtoken=$targetToken");
                    $audit->log('ADMIN_INVALIDATE_SESSION', $username, ['token' => substr($targetToken, 0, 8) . '...']);
                    $success = "Session invalidated.";
                }
            }
        } catch (\Exception $e) {
            $error = "Action failed: " . $e->getMessage();
        }
    }
}

// Data fetching
$users = $redisUsers->listUsers();
$auditLogs = $audit->getLogs(100);

$activeSessions = [];
$sessionKeys = $redisTokens->keys('X-rcloudauth-authtoken=*');
foreach ($sessionKeys as $key) {
    $data = $redisTokens->hgetall($key);
    if ($data) {
        $data['token'] = str_replace('X-rcloudauth-authtoken=', '', $key);
        $data['ttl'] = $redisTokens->ttl($key);
        $activeSessions[] = $data;
    }
}

$csrfToken = generateCsrfToken();

function formatTime($timestamp) {
    return date('Y-m-d H:i:s', $timestamp);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Management | RCloudAuth</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background: #121212; color: #e0e0e0; min-height: 100vh; font-family: 'Segoe UI', sans-serif; }
        .navbar { background: #1e1e1e; border-bottom: 1px solid #333; }
        .card { background: #1e1e1e; border: 1px solid #333; border-radius: 12px; margin-top: 1rem; }
        .nav-tabs { border-bottom-color: #333; }
        .nav-link { color: #888; border: none !important; }
        .nav-link.active { background: transparent !important; color: #3f51b5 !important; border-bottom: 2px solid #3f51b5 !important; }
        .table { color: #e0e0e0; }
        .table-dark { --bs-table-bg: #1e1e1e; }
        .btn-danger { background: #d32f2f; border: none; }
        .alert { border-radius: 8px; border: none; }
        .badge-admin { background: #3f51b5; }
        .badge-user { background: #444; }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark">
        <div class="container">
            <a class="navbar-brand" href="#">RCloudAuth Admin</a>
            <span class="navbar-text">Logged in as: <strong><?php echo htmlspecialchars($username); ?></strong></span>
        </div>
    </nav>

    <div class="container mt-4">
        <?php if (isset($success)): ?>
            <div class="alert alert-success bg-success text-white"><?php echo htmlspecialchars($success); ?></div>
        <?php endif; ?>
        <?php if (isset($error)): ?>
            <div class="alert alert-danger bg-danger text-white"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>

        <ul class="nav nav-tabs mb-3" id="adminTabs" role="tablist">
            <li class="nav-item">
                <button class="nav-link active" data-bs-toggle="tab" data-bs-target="#sessions">Active Sessions</button>
            </li>
            <li class="nav-item">
                <button class="nav-link" data-bs-toggle="tab" data-bs-target="#users">User Management</button>
            </li>
            <li class="nav-item">
                <button class="nav-link" data-bs-toggle="tab" data-bs-target="#audit">Audit Logs</button>
            </li>
        </ul>

        <div class="tab-content">
            <!-- Sessions Tab -->
            <div class="tab-pane fade show active" id="sessions">
                <div class="card">
                    <div class="card-body">
                        <div class="d-flex justify-content-between align-items-center mb-3">
                            <h5 class="mb-0">Active Sessions (<?php echo count($activeSessions); ?>)</h5>
                            <form method="POST" onsubmit="return confirm('Invalidate ALL sessions?');">
                                <input type="hidden" name="action" value="clear_all_tokens">
                                <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                                <button type="submit" class="btn btn-sm btn-danger">Clear All Sessions</button>
                            </form>
                        </div>
                        <div class="table-responsive">
                            <table class="table table-dark table-hover">
                                <thead>
                                    <tr>
                                        <th>User</th>
                                        <th>IP Address</th>
                                        <th>Country</th>
                                        <th>Expires In</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($activeSessions as $s): ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($s['username']); ?></td>
                                        <td><?php echo htmlspecialchars($s['ip']); ?></td>
                                        <td><?php echo htmlspecialchars($s['country']); ?></td>
                                        <td><?php echo round($s['ttl'] / 60); ?> mins</td>
                                        <td>
                                            <form method="POST" style="display:inline;">
                                                <input type="hidden" name="action" value="invalidate_session">
                                                <input type="hidden" name="target_token" value="<?php echo $s['token']; ?>">
                                                <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                                                <button type="submit" class="btn btn-sm btn-outline-danger">Logout</button>
                                            </form>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Users Tab -->
            <div class="tab-pane fade" id="users">
                <div class="card">
                    <div class="card-body">
                        <h5>Registered Users</h5>
                        <div class="table-responsive">
                            <table class="table table-dark">
                                <thead>
                                    <tr>
                                        <th>Username</th>
                                        <th>Email</th>
                                        <th>Role</th>
                                        <th>2FA</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($users as $u): ?>
                                    <tr>
                                        <td><?php echo htmlspecialchars($u['username']); ?></td>
                                        <td><?php echo htmlspecialchars($u['email']); ?></td>
                                        <td>
                                            <span class="badge <?php echo ($u['is_admin'] ?? '0') === '1' ? 'badge-admin' : 'badge-user'; ?>">
                                                <?php echo ($u['is_admin'] ?? '0') === '1' ? 'Admin' : 'User'; ?>
                                            </span>
                                        </td>
                                        <td><?php echo !empty($u['2fa_secret']) ? '✅ Enabled' : '❌ Disabled'; ?></td>
                                        <td>
                                            <?php if ($u['username'] !== $username): ?>
                                            <form method="POST" onsubmit="return confirm('Delete user <?php echo $u['username']; ?>?');">
                                                <input type="hidden" name="action" value="delete_user">
                                                <input type="hidden" name="target_user" value="<?php echo htmlspecialchars($u['username']); ?>">
                                                <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                                                <button type="submit" class="btn btn-sm btn-outline-danger">Delete</button>
                                            </form>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Audit Tab -->
            <div class="tab-pane fade" id="audit">
                <div class="card">
                    <div class="card-body">
                        <h5>Recent Activity Logs</h5>
                        <div class="table-responsive">
                            <table class="table table-dark table-sm">
                                <thead>
                                    <tr>
                                        <th>Time</th>
                                        <th>Action</th>
                                        <th>User</th>
                                        <th>IP</th>
                                        <th>Details</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($auditLogs as $log): ?>
                                    <tr>
                                        <td class="text-muted"><?php echo formatTime($log['timestamp']); ?></td>
                                        <td><code><?php echo htmlspecialchars($log['action']); ?></code></td>
                                        <td><?php echo htmlspecialchars($log['username']); ?></td>
                                        <td><?php echo htmlspecialchars($log['ip']); ?></td>
                                        <td class="small"><?php echo json_encode($log['details']); ?></td>
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

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
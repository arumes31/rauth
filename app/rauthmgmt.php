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
    header('Location: /rauthvalidate?rd=' . urlencode($_SERVER['REQUEST_URI']));
    exit;
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
                    $redisTokens->del("user_sessions:$targetUser");
                    $audit->log('ADMIN_DELETE_USER', $username, ['target' => $targetUser]);
                    $success = "User $targetUser deleted.";
                }
            } elseif ($action === 'invalidate_session') {
                $targetToken = $_POST['target_token'] ?? '';
                $targetUser = $_POST['target_user'] ?? '';
                if ($targetToken) {
                    $redisTokens->del("X-rcloudauth-authtoken=$targetToken");
                    if ($targetUser) $redisTokens->srem("user_sessions:$targetUser", $targetToken);
                    $audit->log('ADMIN_INVALIDATE_SESSION', $username, ['token' => substr($targetToken, 0, 8) . '...']);
                    $success = "Session invalidated.";
                }
            } elseif ($action === 'create_user') {
                $newUsername = $_POST['new_username'] ?? '';
                $newPassword = $_POST['new_password'] ?? '';
                $newEmail = $_POST['new_email'] ?? '';
                $isAdmin = isset($_POST['is_admin']);

                if ($newUsername && $newPassword) {
                    $redisUsers->createUser($newUsername, $newPassword, $newEmail, $isAdmin);
                    $audit->log('ADMIN_CREATE_USER', $username, ['new_user' => $newUsername, 'is_admin' => $isAdmin]);
                    $success = "User $newUsername created successfully.";
                }
            } elseif ($action === 'logout') {
                $redisTokens->del("X-rcloudauth-authtoken=$token");
                $redisTokens->srem("user_sessions:$username", $token);
                setcookie('X-rcloudauth-authtoken', '', time() - 3600, '/', '.' . Config::get('COOKIE_DOMAIN'), true, true);
                header('Location: /rauthvalidate');
                exit;
            }
        } catch (\Exception $e) {
            $error = "Action failed: " . $e->getMessage();
        }
    }
}

$users = $redisUsers->listUsers();
$auditLogs = $audit->getLogs(100);
$sessionKeys = $redisTokens->keys('X-rcloudauth-authtoken=*');
$activeSessions = [];
foreach ($sessionKeys as $key) {
    $data = $redisTokens->hgetall($key);
    if ($data) {
        $data['token'] = str_replace('X-rcloudauth-authtoken=', '', $key);
        $data['ttl'] = $redisTokens->ttl($key);
        $activeSessions[] = $data;
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
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link href="/static/css/bootstrap-icons.min.css" rel="stylesheet">
    <link href="/static/css/modern.css" rel="stylesheet">
</head>
<body>
    <nav class="navbar navbar-expand-lg sticky-top">
        <div class="container">
            <a class="navbar-brand fs-3" href="#">RCloudAuth</a>
            <div class="d-flex align-items-center">
                <a href="/rauthprofile" class="btn btn-sm btn-link text-decoration-none text-muted me-3">
                    <i class="bi bi-person-circle me-1"></i> My Profile
                </a>
                <span class="text-muted small me-4 d-none d-md-inline">Admin: <strong><?php echo htmlspecialchars($username); ?></strong></span>
                <form method="POST">
                    <input type="hidden" name="action" value="logout">
                    <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                    <button type="submit" class="btn btn-sm btn-outline-danger">
                        <i class="bi bi-box-arrow-right"></i>
                    </button>
                </form>
            </div>
        </div>
    </nav>

    <div class="container mt-5 animate-fade-in">
        <?php if (isset($success)): ?>
            <div class="alert alert-success bg-success bg-opacity-10 text-success border-0 rounded-3 mb-4">
                <i class="bi bi-check-circle-fill me-2"></i> <?php echo htmlspecialchars($success); ?>
            </div>
        <?php endif; ?>
        <?php if (isset($error)): ?>
            <div class="alert alert-danger bg-danger bg-opacity-10 text-danger border-0 rounded-3 mb-4">
                <i class="bi bi-exclamation-octagon-fill me-2"></i> <?php echo htmlspecialchars($error); ?>
            </div>
        <?php endif; ?>

        <ul class="nav nav-tabs mb-4" id="adminTabs" role="tablist">
            <li class="nav-item">
                <button class="nav-link active" data-bs-toggle="tab" data-bs-target="#sessions">
                    <i class="bi bi-activity me-2"></i> Active Sessions
                </button>
            </li>
            <li class="nav-item">
                <button class="nav-link" data-bs-toggle="tab" data-bs-target="#users">
                    <i class="bi bi-people me-2"></i> User Directory
                </button>
            </li>
            <li class="nav-item">
                <button class="nav-link" data-bs-toggle="tab" data-bs-target="#audit">
                    <i class="bi bi-journal-text me-2"></i> Audit Logs
                </button>
            </li>
        </ul>

        <div class="tab-content">
            <!-- Sessions Tab -->
            <div class="tab-pane fade show active" id="sessions">
                <div class="card">
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h6 class="mb-0">Real-time Session Monitor</h6>
                        <form method="POST" onsubmit="return confirm('Invalidate ALL active sessions?');">
                            <input type="hidden" name="action" value="clear_all_tokens">
                            <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                            <button type="submit" class="btn btn-xs btn-outline-danger py-1 px-3">Flush All</button>
                        </form>
                    </div>
                    <div class="card-body p-0">
                        <div class="table-responsive">
                            <table class="table table-hover mb-0">
                                <thead>
                                    <tr>
                                        <th class="ps-4">Username</th>
                                        <th>IP & Region</th>
                                        <th>Session TTL</th>
                                        <th class="text-end pe-4">Manage</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($activeSessions as $s): ?>
                                    <tr class="align-middle">
                                        <td class="ps-4">
                                            <div class="fw-bold"><?php echo htmlspecialchars($s['username']); ?></div>
                                            <div class="text-muted extra-small">ID: <?php echo substr($s['token'], 0, 8); ?>...</div>
                                        </td>
                                        <td>
                                            <div><?php echo htmlspecialchars($s['ip']); ?></div>
                                            <div class="text-muted small"><i class="bi bi-globe me-1"></i> <?php echo htmlspecialchars($s['country']); ?></div>
                                        </td>
                                        <td>
                                            <div class="progress" style="height: 4px; width: 100px;">
                                                <div class="progress-bar bg-info" style="width: <?php echo ($s['ttl'] / 10080) * 100; ?>%"></div>
                                            </div>
                                            <span class="extra-small text-muted"><?php echo round($s['ttl'] / 60); ?>m remaining</span>
                                        </td>
                                        <td class="text-end pe-4">
                                            <form method="POST">
                                                <input type="hidden" name="action" value="invalidate_session">
                                                <input type="hidden" name="target_token" value="<?php echo $s['token']; ?>">
                                                <input type="hidden" name="target_user" value="<?php echo htmlspecialchars($s['username']); ?>">
                                                <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                                                <button type="submit" class="btn btn-sm btn-outline-danger border-0"><i class="bi bi-trash"></i></button>
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
                    <div class="card-header d-flex justify-content-between align-items-center">
                        <h6 class="mb-0">Access Management</h6>
                        <button type="button" class="btn btn-sm btn-primary" data-bs-toggle="modal" data-bs-target="#createUserModal">
                            <i class="bi bi-plus-lg me-1"></i> New User
                        </button>
                    </div>
                    <div class="card-body p-0">
                        <div class="table-responsive">
                            <table class="table table-hover mb-0">
                                <thead>
                                    <tr>
                                        <th class="ps-4">User Details</th>
                                        <th>Permissions</th>
                                        <th>Security</th>
                                        <th class="text-end pe-4">Manage</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($users as $u): ?>
                                    <tr class="align-middle">
                                        <td class="ps-4">
                                            <div class="fw-bold"><?php echo htmlspecialchars($u['username']); ?></div>
                                            <div class="text-muted small"><?php echo htmlspecialchars($u['email']); ?></div>
                                        </td>
                                        <td>
                                            <span class="badge <?php echo ($u['is_admin'] ?? '0') === '1' ? 'bg-primary' : 'bg-dark border border-secondary'; ?>">
                                                <?php echo ($u['is_admin'] ?? '0') === '1' ? 'Administrator' : 'General User'; ?>
                                            </span>
                                        </td>
                                        <td>
                                            <?php if (!empty($u['2fa_secret'])): ?>
                                                <span class="text-success small"><i class="bi bi-shield-check me-1"></i> 2FA Active</span>
                                            <?php else: ?>
                                                <span class="text-muted small"><i class="bi bi-shield-dash me-1"></i> 2FA Off</span>
                                            <?php endif; ?>
                                        </td>
                                        <td class="text-end pe-4">
                                            <?php if ($u['username'] !== $username): ?>
                                            <form method="POST" onsubmit="return confirm('Permanent deletion?');">
                                                <input type="hidden" name="action" value="delete_user">
                                                <input type="hidden" name="target_user" value="<?php echo htmlspecialchars($u['username']); ?>">
                                                <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                                                <button type="submit" class="btn btn-sm btn-outline-danger border-0"><i class="bi bi-person-x"></i></button>
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
                    <div class="card-body p-0">
                        <div class="table-responsive">
                            <table class="table table-hover mb-0">
                                <thead class="bg-dark">
                                    <tr>
                                        <th class="ps-4">Timestamp</th>
                                        <th>Event</th>
                                        <th>Context</th>
                                        <th class="pe-4">Metadata</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($auditLogs as $log): ?>
                                    <tr>
                                        <td class="ps-4 text-muted small"><?php echo date('M d, H:i:s', $log['timestamp']); ?></td>
                                        <td>
                                            <span class="text-info"><?php echo htmlspecialchars($log['action']); ?></span>
                                        </td>
                                        <td>
                                            <i class="bi bi-person me-1"></i> <?php echo htmlspecialchars($log['username']); ?>
                                            <div class="text-muted extra-small"><i class="bi bi-hdd-network me-1"></i> <?php echo htmlspecialchars($log['ip']); ?></div>
                                        </td>
                                        <td class="pe-4"><code class="extra-small opacity-75"><?php echo json_encode($log['details']); ?></code></td>
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

    <!-- Create User Modal -->
    <div class="modal fade" id="createUserModal" tabindex="-1">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content shadow">
                <form method="POST">
                    <div class="modal-header border-bottom border-secondary border-opacity-25">
                        <h5 class="modal-title">Create Identity</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body p-4">
                        <input type="hidden" name="action" value="create_user">
                        <input type="hidden" name="csrf_token" value="<?php echo $csrfToken; ?>">
                        <div class="mb-3">
                            <label class="form-label text-muted small fw-bold">Username</label>
                            <input type="text" name="new_username" class="form-control" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label text-muted small fw-bold">Email</label>
                            <input type="email" name="new_email" class="form-control">
                        </div>
                        <div class="mb-4">
                            <label class="form-label text-muted small fw-bold">Secret Password</label>
                            <input type="password" name="new_password" class="form-control" required>
                        </div>
                        <div class="form-check form-switch">
                            <input class="form-check-input" type="checkbox" name="is_admin" id="isAdminCheck">
                            <label class="form-check-label text-muted" for="isAdminCheck">Assign Administrative Privileges</label>
                        </div>
                    </div>
                    <div class="modal-footer border-0">
                        <button type="button" class="btn btn-link text-muted text-decoration-none" data-bs-dismiss="modal">Dismiss</button>
                        <button type="submit" class="btn btn-primary px-4">Create Account</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script src="/static/js/bootstrap.bundle.min.js"></script>
</body>
</html>
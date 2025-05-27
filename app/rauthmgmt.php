<?php
require 'vendor/autoload.php';

use Predis\Client;
use GuzzleHttp\Client as HttpClient;

session_start();

// Generate a request ID for tracing
$request_id = bin2hex(random_bytes(8));
error_log("rauthmgmt.php: Request ID: $request_id", 4);

// Log PHP-FPM worker ID
$worker_id = getmypid();
error_log("rauthmgmt.php [$request_id]: PHP-FPM worker ID: $worker_id", 4);

// Function to get client IP
function getClientIP() {
    $ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    if (strpos($ip, ',') !== false) {
        $ip = trim(explode(',', $ip)[0]);
    }
    return $ip;
}

// Function to decrypt the token
function decryptToken($encrypted_token, $secret, $request_id) {
    $data = base64_decode($encrypted_token);
    if ($data === false) {
        error_log("rauthmgmt.php [$request_id]: Token base64 decode failed", 4);
        return false;
    }
    $iv = substr($data, 0, 16);
    $encrypted = substr($data, 16);
    $decrypted = openssl_decrypt(
        $encrypted,
        'AES-256-CBC',
        $secret,
        0,
        $iv
    );
    if ($decrypted === false) {
        error_log("rauthmgmt.php [$request_id]: Token decryption failed", 4);
        return false;
    }
    return $decrypted;
}

// RedisConnection class
class RedisConnection {
    private static $instances = [];

    public static function getInstance($db, $worker_id, $request_id, $retry = 0) {
        $key = "db:$db";
        if (!isset(self::$instances[$key])) {
            $redis_host = getenv('REDIS_HOST') ?: 'redis_external';
            $redis_port = getenv('REDIS_PORT') ?: 6379;
            $redis_password = getenv('REDIS_PASSWORD') ?: null;

            try {
                $config = [
                    'scheme' => 'tcp',
                    'host' => $redis_host,
                    'port' => $redis_port,
                    'database' => $db,
                    'timeout' => 5.0,
                    'read_write_timeout' => 5.0,
                    'persistent' => true,
                    'persistent_id' => "rauthmgmt_db_{$db}_{$worker_id}",
                ];
                if ($redis_password) {
                    $config['password'] = $redis_password;
                }
                self::$instances[$key] = new Client($config, [
                    'parameters' => [
                        'database' => $db,
                    ],
                ]);
                self::$instances[$key]->ping();
                error_log("rauthmgmt.php [$request_id]: Connected to Redis database DB $db (host=$redis_host, port=$redis_port, persistent_id=rauthmgmt_db_{$db}_{$worker_id})", 4);
            } catch (Exception $e) {
                error_log("rauthmgmt.php [$request_id]: Redis connection failed for DB $db (host=$redis_host, port=$redis_port): " . $e->getMessage(), 4);
                if ($retry < 2) {
                    sleep(1);
                    return self::getInstance($db, $worker_id, $request_id, $retry + 1);
                }
                http_response_code(500);
                header('Content-Type: application/json');
                echo json_encode(['error' => 'Internal server error']);
                exit;
            }
        }
        try {
            self::$instances[$key]->ping();
        } catch (Exception $e) {
            error_log("rauthmgmt.php [$request_id]: Redis ping failed for DB $db: " . $e->getMessage(), 4);
            unset(self::$instances[$key]);
            if ($retry < 2) {
                sleep(1);
                return self::getInstance($db, $worker_id, $request_id, $retry + 1);
            }
            http_response_code(500);
            header('Content-Type: application/json');
            echo json_encode(['error' => 'Internal server error']);
            exit;
        }
        return self::$instances[$key];
    }
}

// Function to clear all authentication tokens
function clearAllTokens($redis, $request_id) {
    try {
        $keys = $redis->keys('X-rcloudauth-authtoken=*');
        if (empty($keys)) {
            error_log("rauthmgmt.php [$request_id]: No tokens found to clear", 4);
            return ['success' => true, 'message' => 'No tokens to clear'];
        }
        $redis->multi();
        foreach ($keys as $key) {
            $redis->del($key);
        }
        $results = $redis->exec();
        if ($results === null) {
            throw new Exception("Redis transaction failed");
        }
        $deleted_count = array_sum($results);
        error_log("rauthmgmt.php [$request_id]: Cleared $deleted_count tokens", 4);
        return ['success' => true, 'message' => "Cleared $deleted_count tokens"];
    } catch (Exception $e) {
        error_log("rauthmgmt.php [$request_id]: Failed to clear tokens: " . $e->getMessage(), 4);
        return ['success' => false, 'message' => 'Failed to clear tokens'];
    }
}

// Generate CSRF token
function generateCsrfToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

// Validate CSRF token
function validateCsrfToken($token, $request_id) {
    if (!isset($_SESSION['csrf_token']) || $_SESSION['csrf_token'] !== $token) {
        error_log("rauthmgmt.php [$request_id]: CSRF token validation failed", 4);
        return false;
    }
    return true;
}

// Load server secret
$server_secret = getenv('SERVER_SECRET');
if (!$server_secret || strlen($server_secret) !== 32) {
    error_log("rauthmgmt.php [$request_id]: Invalid or missing SERVER_SECRET", 4);
    http_response_code(500);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Internal server error']);
    exit;
}
error_log("rauthmgmt.php [$request_id]: Server secret loaded", 4);

// Get client IP
$client_ip = getClientIP();
error_log("rauthmgmt.php [$request_id]: Client IP: $client_ip", 4);

// Validate authentication token
$encrypted_authtoken = $_COOKIE['X-rcloudauth-authtoken'] ?? '';
if (!$encrypted_authtoken) {
    error_log("rauthmgmt.php [$request_id]: No X-rcloudauth-authtoken cookie provided", 4);
    http_response_code(401);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

// Decrypt the token
$authtoken = decryptToken($encrypted_authtoken, $server_secret, $request_id);
if ($authtoken === false) {
    error_log("rauthmgmt.php [$request_id]: Token decryption failed", 4);
    http_response_code(401);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

// Connect to Redis
$redis_tokens = RedisConnection::getInstance(1, $worker_id, $request_id);
$redis_users = RedisConnection::getInstance(0, $worker_id, $request_id);

// Validate token in Redis
$redis_key = "X-rcloudauth-authtoken=$authtoken";
$token_data = $redis_tokens->hgetall($redis_key);
if (!isset($token_data['status']) || $token_data['status'] !== 'valid') {
    error_log("rauthmgmt.php [$request_id]: Invalid or expired $redis_key", 4);
    http_response_code(401);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

// Check if user is admin
$username = $token_data['username'];
$user_data = $redis_users->hgetall("user:$username");
if (!isset($user_data['is_admin']) || $user_data['is_admin'] !== '1') {
    error_log("rauthmgmt.php [$request_id]: User $username is not an admin", 4);
    http_response_code(403);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Forbidden']);
    exit;
}
error_log("rauthmgmt.php [$request_id]: User $username is authorized as admin", 4);

// Handle POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $content_type = $_SERVER['CONTENT_TYPE'] ?? '';
    $action = $_POST['action'] ?? '';

    // Handle API requests (JSON)
    if (strpos($content_type, 'application/json') !== false || isset($_POST['api'])) {
        header('Content-Type: application/json');
        if ($action === 'clear_tokens') {
            $result = clearAllTokens($redis_tokens, $request_id);
            echo json_encode($result);
            exit;
        } else {
            error_log("rauthmgmt.php [$request_id]: Invalid action: $action", 4);
            http_response_code(400);
            echo json_encode(['error' => 'Invalid action']);
            exit;
        }
    }

    // Handle form submissions (HTML)
    header('Content-Type: text/html; charset=UTF-8');
    $csrf_token = $_POST['csrf_token'] ?? '';
    if (!validateCsrfToken($csrf_token, $request_id)) {
        $error = 'Invalid CSRF token';
        error_log("rauthmgmt.php [$request_id]: $error", 4);
    } elseif ($action === 'clear_tokens') {
        $result = clearAllTokens($redis_tokens, $request_id);
        if ($result['success']) {
            $success = $result['message'];
            error_log("rauthmgmt.php [$request_id]: Form submission: " . $result['message'], 4);
        } else {
            $error = $result['message'];
            error_log("rauthmgmt.php [$request_id]: Form submission failed: " . $result['message'], 4);
        }
    } else {
        $error = 'Invalid action';
        error_log("rauthmgmt.php [$request_id]: Invalid form action: $action", 4);
    }
}

// Handle GET requests (render HTML or health check)
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // Check for health check
    $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
    if (strpos($accept, 'application/json') !== false || isset($_GET['health'])) {
        error_log("rauthmgmt.php [$request_id]: Health check requested", 4);
        header('Content-Type: application/json');
        echo json_encode([
            'status' => 'OK',
            'service' => 'RCloudAuthMgmt',
            'version' => '1.0'
        ]);
        exit;
    }

    // Render HTML user management page
    error_log("rauthmgmt.php [$request_id]: Rendering user management page", 4);
    header('Content-Type: text/html; charset=UTF-8');
    header('Cache-Control: no-cache, no-store, must-revalidate');
    $csrf_token = generateCsrfToken();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Management</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            margin: 0;
            overflow: hidden;
            background: #000;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        canvas {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
        }
        .container {
            max-width: 500px;
            background: rgba(0, 0, 0, 0.85);
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.3);
        }
        h2 {
            color: #0f0;
            text-shadow: 0 0 5px #0f0;
            margin-bottom: 1.5rem;
        }
        .form-label {
            color: #0f0;
        }
        .form-control {
            background: #111;
            border: 1px solid #0f0;
            color: #0f0;
        }
        .form-control:focus {
            background: #111;
            border-color: #0f0;
            color: #0f0;
            box-shadow: 0 0 5px #0f0;
        }
        .btn-primary {
            background: #0f0;
            border: none;
            color: #000;
            font-weight: bold;
        }
        .btn-primary:hover {
            background: #0c0;
            box-shadow: 0 0 10px #0f0;
        }
        .alert-danger {
            background: #3c0000;
            border-color: #ff0000;
            color: #ff5555;
        }
        .alert-success {
            background: #003c00;
            border-color: #00ff00;
            color: #55ff55;
        }
        .ip-display {
            color: #0f0;
            margin-bottom: 1rem;
        }
    </style>
</head>
<body>
    <canvas id="matrix"></canvas>
    <div class="container">
        <div class="row justify-content-center">
            <div class="col-12">
                <h2 class="text-center">User Management</h2>
                <p class="ip-display">IP: <?php echo htmlspecialchars($client_ip); ?></p>
                <?php if (isset($error)): ?>
                    <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
                <?php endif; ?>
                <?php if (isset($success)): ?>
                    <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
                <?php endif; ?>
                <form method="POST">
                    <input type="hidden" name="action" value="clear_tokens">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                    <div class="mb-3">
                        <label class="form-label">Clear All Authentication Tokens</label>
                        <p class="text-muted">This will invalidate all active user sessions.</p>
                    </div>
                    <button type="submit" class="btn btn-primary w-100">Clear Tokens</button>
                </form>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        const canvas = document.getElementById('matrix');
        const ctx = canvas.getContext('2d');

        canvas.height = window.innerHeight;
        canvas.width = window.innerWidth;

        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()';
        const fontSize = 14;
        const columns = canvas.width / fontSize;
        const drops = [];

        for (let x = 0; x < columns; x++) {
            drops[x] = 1;
        }

        function draw() {
            ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            ctx.fillStyle = '#0F0';
            ctx.font = fontSize + 'px monospace';

            for (let i = 0; i < drops.length; i++) {
                const text = chars.charAt(Math.floor(Math.random() * chars.length));
                ctx.fillText(text, i * fontSize, drops[i] * fontSize);

                if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                    drops[i] = 0;
                }
                drops[i]++;
            }
        }

        setInterval(draw, 33);

        window.addEventListener('resize', () => {
            canvas.height = window.innerHeight;
            canvas.width = window.innerWidth;
        });
    </script>
</body>
</html>
<?php
}
?>
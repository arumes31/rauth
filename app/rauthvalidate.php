<?php
require 'vendor/autoload.php';

use Predis\Client;
use RobThree\Auth\TwoFactorAuth;
use GuzzleHttp\Client as HttpClient;

session_start();

// Extract domain from request
$request_host = $_SERVER['HTTP_HOST'] ?? 'localhost';

// Generate a request ID for tracing
$request_id = bin2hex(random_bytes(8));
error_log("rauthvalidate.php: Request ID: $request_id");

// Log PHP-FPM worker ID
$worker_id = getmypid();
error_log("rauthvalidate.php [$request_id]: PHP-FPM worker ID: $worker_id");

// Function to get client IP
function getClientIP() {
    $ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    if (strpos($ip, ',') !== false) {
        $ip = trim(explode(',', $ip)[0]);
    }
    return $ip;
}

// Function to check if an IP is private
function isPrivateIP($ip) {
    // Handle IPv4 only for simplicity
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        $ip_num = ip2long($ip);
        // Check for private IP ranges
        return (
            ($ip_num >= ip2long('10.0.0.0') && $ip_num <= ip2long('10.255.255.255')) || // 10.0.0.0/8
            ($ip_num >= ip2long('172.16.0.0') && $ip_num <= ip2long('172.31.255.255')) || // 172.16.0.0/12
            ($ip_num >= ip2long('192.168.0.0') && $ip_num <= ip2long('192.168.255.255')) // 192.168.0.0/16
        );
    }
    return false;
}

// Function to get country code from geolocation service or set to "Internal" for private IPs
function getCountryCode($ip, $request_id) {
    // Check if IP is private
    if (isPrivateIP($ip)) {
        error_log("rauthvalidate.php [$request_id]: IP $ip is private, setting country code to Internal");
        return 'Internal';
    }

    $geo_api_host = getenv('GEO_API_HOST') ?: 'geo-service';
    $geo_api_port = getenv('GEO_API_PORT') ?: 3000;
    $url = "http://$geo_api_host:$geo_api_port/?ip=$ip";
    error_log("rauthvalidate.php [$request_id]: Querying geolocation API: $url");
    try {
        $client = new HttpClient();
        $response = $client->get($url, ['timeout' => 5]);
        $data = json_decode($response->getBody(), true);
        $country_code = $data['country'] ?? 'unknown';
        error_log("rauthvalidate.php [$request_id]: Country code for IP $ip: $country_code");
        return $country_code;
    } catch (Exception $e) {
        error_log("rauthvalidate.php [$request_id]: Geolocation API failed: " . $e->getMessage());
        return 'unknown';
    }
}

// Function to encrypt the token
function encryptToken($token, $secret, $request_id) {
    $iv = random_bytes(16); // 16 bytes for AES-256-CBC
    $encrypted = openssl_encrypt(
        $token,
        'AES-256-CBC',
        $secret,
        0,
        $iv
    );
    if ($encrypted === false) {
        error_log("rauthvalidate.php [$request_id]: Token encryption failed");
        return false;
    }
    // Combine IV and encrypted data (base64 for safe storage)
    return base64_encode($iv . $encrypted);
}

// Function to decrypt the token
function decryptToken($encrypted_token, $secret, $request_id) {
    $data = base64_decode($encrypted_token);
    if ($data === false) {
        error_log("rauthvalidate.php [$request_id]: Token base64 decode failed");
        return false;
    }
    $iv = substr($data, 0, 16); // Extract first 16 bytes as IV
    $encrypted = substr($data, 16);
    $decrypted = openssl_decrypt(
        $encrypted,
        'AES-256-CBC',
        $secret,
        0,
        $iv
    );
    if ($decrypted === false) {
        error_log("rauthvalidate.php [$request_id]: Token decryption failed");
        return false;
    }
    return $decrypted;
}

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
                    'persistent_id' => "rauthvalidate_db_{$db}_{$worker_id}",
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
                error_log("rauthvalidate.php [$request_id]: Connected to Redis database DB $db (host=$redis_host, port=$redis_port, persistent_id=rauthvalidate_db_{$db}_{$worker_id})");
                $info = self::$instances[$key]->info();
                error_log("rauthvalidate.php [$request_id]: Redis server info: version=" . ($info['Server']['redis_version'] ?? 'unknown') . ", mode=" . ($info['Server']['redis_mode'] ?? 'unknown') . ", connected_clients=" . ($info['Clients']['connected_clients'] ?? 'unknown'));
            } catch (Exception $e) {
                error_log("rauthvalidate.php [$request_id]: Redis connection failed for DB $db (host=$redis_host, port=$redis_port): " . $e->getMessage());
                if (strpos($e->getMessage(), 'max number of clients reached') !== false) {
                    error_log("rauthvalidate.php [$request_id]: Maximum Redis client connections reached");
                }
                if ($retry < 2) {
                    sleep(1);
                    return self::getInstance($db, $worker_id, $request_id, $retry + 1);
                }
                http_response_code(500);
                exit;
            }
        }
        try {
            self::$instances[$key]->ping();
        } catch (Exception $e) {
            error_log("rauthvalidate.php [$request_id]: Redis ping failed for DB $db: " . $e->getMessage());
            unset(self::$instances[$key]);
            if ($retry < 2) {
                sleep(1);
                return self::getInstance($db, $worker_id, $request_id, $retry + 1);
            }
            http_response_code(500);
            exit;
        }
        return self::$instances[$key];
    }
}

// Load server secret
$server_secret = getenv('SERVER_SECRET');
if (!$server_secret || strlen($server_secret) !== 32) {
    error_log("rauthvalidate.php [$request_id]: Invalid or missing SERVER_SECRET");
    http_response_code(500);
    exit;
}
error_log("rauthvalidate.php [$request_id]: Server secret loaded");

$tfa = new TwoFactorAuth('RCloudAuth');

// Load environment variables
$token_validity_minutes = getenv('AUTH_TOKEN_VALIDITY_MINUTES') ?: 10080;
$token_validity_seconds = (int)$token_validity_minutes * 60;
$cookie_domain = '.' . getenv('COOKIE_DOMAIN') ?: '.reitetschlaeger.com';
$allowed_hosts = explode(',', getenv('ALLOWED_HOSTS') ?: "$request_host,192.168.3.123,localhost,upstream");
error_log("rauthvalidate.php [$request_id]: Token validity: $token_validity_minutes minutes ($token_validity_seconds seconds)");
error_log("rauthvalidate.php [$request_id]: Cookie domain: $cookie_domain");
error_log("rauthvalidate.php [$request_id]: Allowed hosts: " . implode(',', $allowed_hosts));

// Validate rd parameter
$redirect_url = $_GET['rd'] ?? $_SERVER['HTTP_X_ORIGINAL_URL'] ?? "https://$request_host/";
$parsed_url = parse_url($redirect_url);
$allowed_hosts = array_map('trim', $allowed_hosts);
if (!isset($parsed_url['host']) || !in_array($parsed_url['host'], $allowed_hosts)) {
    $redirect_url = "https://$request_host/";
    error_log("rauthvalidate.php [$request_id]: Invalid rd host, defaulting to $redirect_url");
} elseif ($parsed_url['path'] === '/rauthvalidate') {
    $redirect_url = "https://$request_host/";
    error_log("rauthvalidate.php [$request_id]: rd was /rauthvalidate, defaulting to $redirect_url");
}
error_log("rauthvalidate.php [$request_id]: Redirect URL set to $redirect_url");

// Handle error query parameter
$error_message = $_GET['error'] ?? '';
if ($error_message === 'auth_failed') {
    $error = 'Authentication service error. Please try again.';
    error_log("rauthvalidate.php [$request_id]: Authentication service error detected");
}

// Get client IP and country code
$client_ip = getClientIP();
$client_country = getCountryCode($client_ip, $request_id);
error_log("rauthvalidate.php [$request_id]: Client IP: $client_ip, Country: $client_country");

// Handle X-rcloudauth-authtoken validation
if ($_SERVER['REQUEST_METHOD'] === 'GET' && !isset($_GET['action']) && !isset($_GET['rd']) && !isset($_GET['error'])) {
    $encrypted_authtoken = $_COOKIE['X-rcloudauth-authtoken'] ?? '';
    error_log("rauthvalidate.php [$request_id]: Cookies received: " . json_encode($_COOKIE));
    if (!$encrypted_authtoken) {
        error_log("rauthvalidate.php [$request_id]: No X-rcloudauth-authtoken cookie provided, returning 401");
        http_response_code(401);
        exit;
    }
    // Decrypt the token
    $authtoken = decryptToken($encrypted_authtoken, $server_secret, $request_id);
    if ($authtoken === false) {
        error_log("rauthvalidate.php [$request_id]: Token decryption failed, returning 401");
        http_response_code(401);
        exit;
    }
    $redis = RedisConnection::getInstance(1, $worker_id, $request_id);
    $redis_key = "X-rcloudauth-authtoken=$authtoken";
    error_log("rauthvalidate.php [$request_id]: Checking $redis_key");
    try {
        $redis->watch($redis_key);
        $token_data = $redis->hgetall($redis_key);
        $ttl = $redis->ttl($redis_key);
        error_log("rauthvalidate.php [$request_id]: $redis_key data before validation: " . json_encode($token_data) . ", TTL=$ttl");
        if (isset($token_data['status']) && $token_data['status'] === 'valid') {
            // Allow IP change if country is the same
            if ($token_data['ip'] !== $client_ip && $token_data['country'] !== $client_country) {
                error_log("rauthvalidate.php [$request_id]: IP and country mismatch for $redis_key. Stored IP: {$token_data['ip']}, Current IP: $client_ip, Stored country: {$token_data['country']}, Current country: $client_country");
                $redis->unwatch();
                http_response_code(401);
                exit;
            }
            if ($token_data['country'] !== $client_country && $client_country !== 'unknown') {
                error_log("rauthvalidate.php [$request_id]: Country changed for $redis_key. Stored country: {$token_data['country']}, Current country: $client_country");
                $_SESSION['pending_2fa'] = true;
                $_SESSION['username'] = $token_data['username'];
                $_SESSION['country_change'] = true;
                $redis->unwatch();
                header('Content-Type: text/html; charset=UTF-8');
                header('Cache-Control: no-cache, no-store, must-revalidate');
                error_log("rauthvalidate.php [$request_id]: Prompting for 2FA due to country change");
            } else {
                $redis->multi();
                $redis->hgetall($redis_key);
                $redis->ttl($redis_key);
                $results = $redis->exec();
                if ($results === null) {
                    throw new Exception("Redis transaction failed, possibly due to key modification");
                }
                $post_data = [];
                for ($i = 0; $i < count($results[0]); $i += 2) {
                    $post_data[$results[0][$i]] = $results[0][$i + 1];
                }
                $post_ttl = $results[1];
                error_log("rauthvalidate.php [$request_id]: $redis_key data after validation: " . json_encode($post_data) . ", TTL=$post_ttl");
                if (!isset($post_data['status']) || $post_data['status'] !== 'valid') {
                    error_log("rauthvalidate.php [$request_id]: $redis_key unexpectedly invalidated during validation");
                    $redis->unwatch();
                    http_response_code(401);
                    exit;
                }
                $redis->unwatch();
                http_response_code(200);
                exit;
            }
        } else {
            $redis->unwatch();
            error_log("rauthvalidate.php [$request_id]: Invalid or expired $redis_key, returning 401");
            error_log("rauthvalidate.php [$request_id]: Token data in Redis: " . json_encode($token_data));
            http_response_code(401);
            exit;
        }
    } catch (Exception $e) {
        $redis->unwatch();
        error_log("rauthvalidate.php [$request_id]: Error validating $redis_key: " . $e->getMessage());
        http_response_code(401);
        exit;
    }
}

// Handle health check
if ($_SERVER['REQUEST_METHOD'] === 'GET' && !isset($_GET['action']) && !isset($_GET['rd']) && !isset($_GET['error'])) {
    error_log("rauthvalidate.php [$request_id]: Health check requested");
    header('Content-Type: application/json');
    echo '{"status": "OK", "service": "RCloudAuth", "version": "1.0"}';
    exit;
}

// Handle login form or 2FA prompt
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    error_log("rauthvalidate.php [$request_id]: Rendering login form");
    header('Content-Type: text/html; charset=UTF-8');
    header('Cache-Control: no-cache, no-store, must-revalidate');
    error_log("rauthvalidate.php [$request_id]: Sending login form response");
}

// Handle POST requests (login or 2FA)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $totp_code = $_POST['totp_code'] ?? '';
    $action = $_POST['action'] ?? 'login';

    error_log("rauthvalidate.php [$request_id]: Processing $action for username=$username");

    if ($action === 'login') {
        $redis_user = RedisConnection::getInstance(0, $worker_id, $request_id);
        if (!$redis_user->exists("user:$username")) {
            $error = 'Invalid credentials';
            error_log("rauthvalidate.php [$request_id]: User $username does not exist in Redis");
            try {
                $init_output = shell_exec('php /var/www/html/init_user.php 2>&1');
                error_log("rauthvalidate.php [$request_id]: Re-ran init_user.php: $init_output");
                if ($redis_user->exists("user:$username")) {
                    error_log("rauthvalidate.php [$request_id]: User $username created after re-init");
                } else {
                    error_log("rauthvalidate.php [$request_id]: User $username still not created");
                }
            } catch (Exception $e) {
                error_log("rauthvalidate.php [$request_id]: Re-init failed: " . $e->getMessage());
            }
        }
        $user = $redis_user->hgetall("user:$username");
        error_log("rauthvalidate.php [$request_id]: Retrieved user data for $username: " . json_encode($user, JSON_UNESCAPED_SLASHES));
        if ($user && password_verify($password, $user['password'])) {
            error_log("rauthvalidate.php [$request_id]: Password verified for $username");
            $_SESSION['username'] = $username;
            if (!empty($user['2fa_secret']) || isset($_SESSION['country_change'])) {
                $_SESSION['pending_2fa'] = true;
                if (empty($user['2fa_secret'])) {
                    $user['2fa_secret'] = $tfa->createSecret();
                    error_log("rauthvalidate.php [$request_id]: Generated temporary 2FA secret for $username due to country change");
                }
                $_SESSION['2fa_secret'] = $user['2fa_secret'];
                error_log("rauthvalidate.php [$request_id]: 2FA required");
                header('Content-Type: text/html; charset=UTF-8');
            } else {
                $authtoken = bin2hex(random_bytes(32));
                $encrypted_authtoken = encryptToken($authtoken, $server_secret, $request_id);
                if ($encrypted_authtoken === false) {
                    error_log("rauthvalidate.php [$request_id]: Token encryption failed");
                    http_response_code(500);
                    exit;
                }
                $redis = RedisConnection::getInstance(1, $worker_id, $request_id);
                $redis_key = "X-rcloudauth-authtoken=$authtoken";
                try {
                    $redis->watch($redis_key);
                    $redis->multi();
                    $redis->hmset($redis_key, [
                        'status' => 'valid',
                        'ip' => $client_ip,
                        'username' => $username,
                        'country' => $client_country
                    ]);
                    $redis->expire($redis_key, $token_validity_seconds);
                    $results = $redis->exec();
                    if ($results === null) {
                        throw new Exception("Redis transaction failed, possibly due to key modification");
                    }
                    error_log("rauthvalidate.php [$request_id]: $redis_key HMSET result: success");
                    $redis->unwatch();
                } catch (Exception $e) {
                    $redis->unwatch();
                    error_log("rauthvalidate.php [$request_id]: $redis_key HMSET failed: " . $e->getMessage());
                    http_response_code(500);
                    exit;
                }
                $stored_data = $redis->hgetall($redis_key);
                $ttl = $redis->ttl($redis_key);
                error_log("rauthvalidate.php [$request_id]: Verified $redis_key storage: data=" . json_encode($stored_data) . ", TTL=$ttl");
                if ($stored_data['status'] !== 'valid' || $stored_data['ip'] !== $client_ip || $stored_data['country'] !== $client_country) {
                    error_log("rauthvalidate.php [$request_id]: Token storage verification failed for $redis_key");
                }
                error_log("rauthvalidate.php [$request_id]: X-rcloudauth-authtoken created: authtoken=$authtoken, encrypted_authtoken=$encrypted_authtoken, ip=$client_ip, country=$client_country");
                setcookie('X-rcloudauth-authtoken', $encrypted_authtoken, [
                    'expires' => time() + $token_validity_seconds,
                    'path' => '/',
                    'domain' => $cookie_domain,
                    'secure' => true,
                    'httponly' => true,
                    'samesite' => 'Lax'
                ]);
                error_log("rauthvalidate.php [$request_id]: Cookie set: X-rcloudauth-authtoken=$encrypted_authtoken, domain=$cookie_domain");
                header('Location: ' . htmlspecialchars($redirect_url, ENT_QUOTES, 'UTF-8'));
                exit;
            }
        } else {
            $error = 'Invalid credentials';
            error_log("rauthvalidate.php [$request_id]: Password verification failed for $username");
            header('Content-Type: text/html; charset=UTF-8');
        }
    } elseif ($action === 'verify_2fa') {
        $username = $_SESSION['username'] ?? '';
        error_log("rauthvalidate.php [$request_id]: Verifying 2FA for username=$username");
        if (!$username) {
            $error = 'Session expired';
            error_log("rauthvalidate.php [$request_id]: No username in session for 2FA");
            header('Content-Type: text/html; charset=UTF-8');
        } else {
            $redis_user = RedisConnection::getInstance(0, $worker_id, $request_id);
            $user = $redis_user->hgetall("user:$username");
            $twofa_secret = $_SESSION['2fa_secret'] ?? $user['2fa_secret'] ?? '';
            if ($twofa_secret && $tfa->verifyCode($twofa_secret, $totp_code)) {
                error_log("rauthvalidate.php [$request_id]: 2FA code verified for $username");
                $authtoken = bin2hex(random_bytes(32));
                $encrypted_authtoken = encryptToken($authtoken, $server_secret, $request_id);
                if ($encrypted_authtoken === false) {
                    error_log("rauthvalidate.php [$request_id]: Token encryption failed");
                    http_response_code(500);
                    exit;
                }
                $redis = RedisConnection::getInstance(1, $worker_id, $request_id);
                $redis_key = "X-rcloudauth-authtoken=$authtoken";
                try {
                    $redis->watch($redis_key);
                    $redis->multi();
                    $redis->hmset($redis_key, [
                        'status' => 'valid',
                        'ip' => $client_ip,
                        'username' => $username,
                        'country' => $client_country
                    ]);
                    $redis->expire($redis_key, $token_validity_seconds);
                    $results = $redis->exec();
                    if ($results === null) {
                        throw new Exception("Redis transaction failed, possibly due to key modification");
                    }
                    error_log("rauthvalidate.php [$request_id]: $redis_key HMSET result: success");
                    $redis->unwatch();
                } catch (Exception $e) {
                    $redis->unwatch();
                    error_log("rauthvalidate.php [$request_id]: $redis_key HMSET failed: " . $e->getMessage());
                    http_response_code(500);
                    exit;
                }
                $stored_data = $redis->hgetall($redis_key);
                $ttl = $redis->ttl($redis_key);
                error_log("rauthvalidate.php [$request_id]: Verified $redis_key storage: data=" . json_encode($stored_data) . ", TTL=$ttl");
                if ($stored_data['status'] !== 'valid' || $stored_data['ip'] !== $client_ip || $stored_data['country'] !== $client_country) {
                    error_log("rauthvalidate.php [$request_id]: Token storage verification failed for $redis_key");
                }
                error_log("rauthvalidate.php [$request_id]: X-rcloudauth-authtoken created: authtoken=$authtoken, encrypted_authtoken=$encrypted_authtoken, ip=$client_ip, country=$client_country");
                setcookie('X-rcloudauth-authtoken', $encrypted_authtoken, [
                    'expires' => time() + $token_validity_seconds,
                    'path' => '/',
                    'domain' => $cookie_domain,
                    'secure' => true,
                    'httponly' => true,
                    'samesite' => 'Lax'
                ]);
                error_log("rauthvalidate.php [$request_id]: Cookie set: X-rcloudauth-authtoken=$encrypted_authtoken, domain=$cookie_domain");
                unset($_SESSION['pending_2fa']);
                unset($_SESSION['country_change']);
                unset($_SESSION['2fa_secret']);
                header('Location: ' . htmlspecialchars($redirect_url, ENT_QUOTES, 'UTF-8'));
                exit;
            } else {
                $error = $twofa_secret ? 'Invalid 2FA code' : '2FA not configured';
                error_log("rauthvalidate.php [$request_id]: $error");
                header('Content-Type: text/html; charset=UTF-8');
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
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
            max-width: 400px;
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
                <h2 class="text-center">Login</h2>
                <p class="ip-display">IP: <?php echo htmlspecialchars($client_ip); ?> (Country: <?php echo htmlspecialchars($client_country); ?>)</p>
                <?php if (isset($error)): ?>
                    <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
                <?php endif; ?>
                <?php if (isset($_SESSION['pending_2fa'])): ?>
                    <form method="POST">
                        <input type="hidden" name="action" value="verify_2fa">
                        <div class="mb-3">
                            <label for="totp_code" class="form-label">2FA Code</label>
                            <input type="text" class="form-control" id="totp_code" name="totp_code" required>
                        </div>
                        <button type="submit" class="btn btn-primary w-100">Verify</button>
                    </form>
                <?php else: ?>
                    <form method="POST">
                        <input type="hidden" name="action" value="login">
                        <div class="mb-3">
                            <label for="username" class="form-label">Username</label>
                            <input type="text" class="form-control" id="username" name="username" required>
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Password</label>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                        <button type="submit" class="btn btn-primary w-100">Login</button>
                    </form>
                <?php endif; ?>
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
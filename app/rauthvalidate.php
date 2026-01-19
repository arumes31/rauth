<?php
require 'vendor/autoload.php';

use RAuth\Core\Config;
use RAuth\Core\Redis;
use RAuth\Core\Auth;
use RAuth\Core\Logger;
use RAuth\Core\GeoService;
use RAuth\Core\RateLimiter;
use RAuth\Core\AuditLogger;
use RobThree\Auth\TwoFactorAuth;

Logger::init();
session_start();

$serverSecret = Config::getRequired('SERVER_SECRET');
$auth = new Auth($serverSecret);
$tfa = new TwoFactorAuth('RCloudAuth');
$limiter = new RateLimiter();
$audit = new AuditLogger();

// Global Rate Limit
$clientIp = Auth::getClientIP();
if (!$limiter->check('global:' . $clientIp, 20, 60)) {
    http_response_code(429);
    exit("Too many requests.");
}

$tokenValidityMinutes = Config::get('AUTH_TOKEN_VALIDITY_MINUTES', 10080);
$tokenValiditySeconds = (int)$tokenValidityMinutes * 60;
$cookieDomain = '.' . Config::get('COOKIE_DOMAIN', 'reitetschlaeger.com');
$requestHost = $_SERVER['HTTP_HOST'] ?? 'localhost';
$allowedHosts = explode(',', Config::get('ALLOWED_HOSTS', "$requestHost,192.168.3.123,localhost,upstream"));
$allowedHosts = array_map('trim', $allowedHosts);

// Redirect URL logic
$redirectUrl = $_GET['rd'] ?? $_SERVER['HTTP_X_ORIGINAL_URL'] ?? "https://$requestHost/";
$parsedUrl = parse_url($redirectUrl);
if (!isset($parsedUrl['host']) || !in_array($parsedUrl['host'], $allowedHosts)) {
    $redirectUrl = "https://$requestHost/";
} elseif (isset($parsedUrl['path']) && $parsedUrl['path'] === '/rauthvalidate') {
    $redirectUrl = "https://$requestHost/";
}

$clientIp = Auth::getClientIP();
$clientCountry = GeoService::getCountryCode($clientIp);

// 1. Handle X-rcloudauth-authtoken validation (Internal auth_request from Nginx)
if ($_SERVER['REQUEST_METHOD'] === 'GET' && !isset($_GET['action']) && !isset($_GET['rd']) && !isset($_GET['error'])) {
    $encryptedToken = $_COOKIE['X-rcloudauth-authtoken'] ?? '';
    if (!$encryptedToken) {
        http_response_code(401);
        exit;
    }

    $token = $auth->decryptToken($encryptedToken);
    if (!$token) {
        http_response_code(401);
        exit;
    }

    try {
        $redis = Redis::getInstance(1, "validate_" . getmypid());
        $redisKey = "X-rcloudauth-authtoken=$token";
        $tokenData = $redis->hgetall($redisKey);

        if (isset($tokenData['status']) && $tokenData['status'] === 'valid') {
            // IP & Country check
            if ($tokenData['ip'] !== $clientIp && $tokenData['country'] !== $clientCountry) {
                Logger::log("IP/Country mismatch", ['stored' => $tokenData['ip'], 'current' => $clientIp]);
                http_response_code(401);
                exit;
            }

            if ($tokenData['country'] !== $clientCountry && $clientCountry !== 'unknown') {
                Logger::log("Country changed, requiring 2FA", ['stored' => $tokenData['country'], 'current' => $clientCountry]);
                $_SESSION['pending_2fa'] = true;
                $_SESSION['username'] = $tokenData['username'];
                $_SESSION['country_change'] = true;
                http_response_code(401); 
                exit;
            }

            // Group-Based Access Control (RBAC)
            $requiredGroup = $_SERVER['HTTP_X_RAUTH_REQUIRED_GROUP'] ?? null;
            if ($requiredGroup) {
                $redisUsers = Redis::getInstance(0);
                $userData = $redisUsers->hgetall("user:" . $tokenData['username']);
                $userGroups = explode(',', $userData['groups'] ?? 'default');
                if (!in_array($requiredGroup, array_map('trim', $userGroups))) {
                    Logger::log("Access denied: User {$tokenData['username']} lacks group $requiredGroup");
                    http_response_code(403);
                    exit("Forbidden: Missing group $requiredGroup");
                }
            }

            http_response_code(200);
            exit;
        }
    } catch (\Exception $e) {
        Logger::log("Redis error in validation: " . $e->getMessage());
    }
    
    http_response_code(401);
    exit;
}

// 2. Handle Login / 2FA POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? 'login';
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $totpCode = $_POST['totp_code'] ?? '';

    if ($action === 'login') {
        if (!$limiter->check("login:$username", 5, 300)) {
            $error = "Too many failed attempts. Try again in 5 minutes.";
            $audit->log('LOGIN_BRUTEFORCE_BLOCKED', $username);
        } else {
            try {
                $redisUser = Redis::getInstance(0);
                $user = $redisUser->hgetall("user:$username");

                if ($user && password_verify($password, $user['password'])) {
                    $_SESSION['username'] = $username;
                    $limiter->reset("login:$username");
                    
                    if (!empty($user['2fa_secret']) || isset($_SESSION['country_change'])) {
                        $_SESSION['pending_2fa'] = true;
                        $_SESSION['2fa_secret'] = $user['2fa_secret'] ?: $tfa->createSecret();
                        $display2fa = true;
                        $audit->log('LOGIN_PASSWORD_OK', $username, ['requires_2fa' => true]);
                    } else {
                        issueToken($username, $clientIp, $clientCountry, $auth, $tokenValiditySeconds, $cookieDomain, $redirectUrl, $audit);
                    }
                } else {
                    $error = "Invalid credentials";
                    $audit->log('LOGIN_FAILED', $username);
                }
            } catch (\Exception $e) {
                Logger::log("Login error: " . $e->getMessage());
                $error = "System error";
            }
        }
    } elseif ($action === 'verify_2fa') {
        $username = $_SESSION['username'] ?? '';
        $twofaSecret = $_SESSION['2fa_secret'] ?? '';

        if ($username && $twofaSecret && $tfa->verifyCode($twofaSecret, $totpCode)) {
            unset($_SESSION['pending_2fa'], $_SESSION['2fa_secret'], $_SESSION['country_change']);
            issueToken($username, $clientIp, $clientCountry, $auth, $tokenValiditySeconds, $cookieDomain, $redirectUrl, $audit);
        } else {
            $error = "Invalid 2FA code";
            $audit->log('2FA_FAILED', $username);
            $display2fa = true;
        }
    }
}

function issueToken($username, $ip, $country, $auth, $ttl, $domain, $redirect, $audit) {
    $token = bin2hex(random_bytes(32));
    $encrypted = $auth->encryptToken($token);
    
    $redis = Redis::getInstance(1);
    $redisKey = "X-rcloudauth-authtoken=$token";
    $redis->hmset($redisKey, [
        'status' => 'valid',
        'ip' => $ip,
        'username' => $username,
        'country' => $country,
        'created_at' => time()
    ]);
    $redis->expire($redisKey, $ttl);

    // Track sessions per user
    $redis->sadd("user_sessions:$username", $token);

    $audit->log('LOGIN_SUCCESS', $username, ['ip' => $ip, 'country' => $country]);

    setcookie('X-rcloudauth-authtoken', $encrypted, [
        'expires' => time() + $ttl,
        'path' => '/',
        'domain' => $domain,
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Lax'
    ]);

    header('Location: ' . $redirect);
    exit;
}

// 3. Render Page
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign In | RCloudAuth</title>
    <link href="/static/css/bootstrap.min.css" rel="stylesheet">
    <link href="/static/css/bootstrap-icons.min.css" rel="stylesheet">
    <link href="/static/css/modern.css" rel="stylesheet">
</head>
<body class="d-flex align-items-center justify-content-center vh-100">
    <div class="card animate-fade-in shadow-lg" style="width: 100%; max-width: 420px;">
        <div class="card-header text-center pt-5 pb-4 border-0">
            <h2 class="navbar-brand fs-1 mb-0">RCloudAuth</h2>
            <p class="text-muted small mt-2">Enterprise Access Management</p>
        </div>
        <div class="card-body px-5 pb-5">
            <?php if (isset($error)): ?>
                <div class="alert alert-danger bg-danger bg-opacity-10 text-danger border-0 small mb-4">
                    <i class="bi bi-exclamation-triangle-fill me-2"></i> <?php echo htmlspecialchars($error); ?>
                </div>
            <?php endif; ?>

            <form method="POST">
                <?php if (isset($display2fa) || isset($_SESSION['pending_2fa'])): ?>
                    <input type="hidden" name="action" value="verify_2fa">
                    <div class="mb-4">
                        <label class="form-label text-muted small fw-bold">Verification Code</label>
                        <div class="input-group">
                            <span class="input-group-text bg-transparent border-end-0 text-muted"><i class="bi bi-shield-lock"></i></span>
                            <input type="text" class="form-control border-start-0 ps-0" name="totp_code" placeholder="000000" required autofocus autocomplete="one-time-code">
                        </div>
                        <div class="form-text mt-2 small text-muted">Enter the code from your authenticator app.</div>
                    </div>
                    <button type="submit" class="btn btn-primary w-100 py-2">Verify Identity</button>
                <?php else: ?>
                    <input type="hidden" name="action" value="login">
                    <div class="mb-3">
                        <label class="form-label text-muted small fw-bold">Username</label>
                        <div class="input-group">
                            <span class="input-group-text bg-transparent border-end-0 text-muted"><i class="bi bi-person"></i></span>
                            <input type="text" class="form-control border-start-0 ps-0" name="username" placeholder="Enter username" required autofocus>
                        </div>
                    </div>
                    <div class="mb-4">
                        <label class="form-label text-muted small fw-bold">Password</label>
                        <div class="input-group">
                            <span class="input-group-text bg-transparent border-end-0 text-muted"><i class="bi bi-key"></i></span>
                            <input type="password" class="form-control border-start-0 ps-0" name="password" placeholder="••••••••" required>
                        </div>
                    </div>
                    <button type="submit" class="btn btn-primary w-100 py-2">Sign In</button>
                <?php endif; ?>
            </form>
            
            <div class="mt-5 pt-3 border-top border-secondary border-opacity-25 text-center">
                <div class="footer-info text-muted extra-small">
                    <i class="bi bi-geo-alt me-1"></i> <?php echo htmlspecialchars($clientIp); ?> (<?php echo htmlspecialchars($clientCountry); ?>)
                </div>
            </div>
        </div>
    </div>
</body>
</html>
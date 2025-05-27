<?php
require 'vendor/autoload.php';

use Predis\Client;

try {
    // Retrieve Redis connection details from environment variables
    $redis_host = getenv('REDIS_HOST') ?: 'rcloudauth_redis';
    $redis_port = getenv('REDIS_PORT') ?: 6379;
    $redis_password = getenv('REDIS_PASSWORD') ?: '';

    // Redis connection configuration for Docker
    $redis_config = [
        'scheme' => 'tcp',
        'host' => $redis_host,
        'port' => (int) $redis_port,
        'password' => $redis_password,
        'timeout' => 5.0, // Connection timeout in seconds
        'read_write_timeout' => 5.0, // Read/write timeout
    ];

    $redis = new Client($redis_config);

    // Test Redis connection
    $redis->ping();
    error_log('init_user.php: Successfully connected to Redis at ' . $redis_host . ':' . $redis_port);
} catch (Exception $e) {
    error_log('init_user.php: Redis connection failed: ' . $e->getMessage());
    exit(1);
}

// Retrieve user initialization environment variables
$username = getenv('INITIAL_USER') ?: 'anonymous';
$password = getenv('INITIAL_PASSWORD');
$email = getenv('INITIAL_EMAIL') ?: 'no-email@example.com';
$twofa_secret = getenv('INITIAL_2FA_SECRET') ?: '';

error_log("init_user.php: Initializing user: username=$username, email=$email, 2fa_secret=$twofa_secret");

// Validate required environment variables
if (empty($username) || empty($password)) {
    error_log('init_user.php: Missing or empty INITIAL_USER or INITIAL_PASSWORD environment variables');
    exit(1);
}

// Hash the password
$password_hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
if ($password_hash === false) {
    error_log('init_user.php: Password hashing failed');
    exit(1);
}

// Prepare user data
$uid = uniqid('user_', true); // More unique ID with prefix
$name = $username;
$groups = 'default';

$user_data = [
    'username' => $username,
    'password' => $password_hash,
    'email' => $email,
    'name' => $name,
    'uid' => $uid,
    'groups' => $groups,
    '2fa_secret' => $twofa_secret,
];

try {
    // Check if user already exists to avoid overwriting
    if ($redis->exists("user:$username")) {
        error_log("init_user.php: User $username already exists in Redis");
        exit(1);
    }

    // Store user data in Redis
    $redis->hmset("user:$username", $user_data);
    $redis->sadd('users', $username);
    error_log("init_user.php: User $username created successfully");
    error_log("init_user.php: Stored user data: " . json_encode($user_data, JSON_PRETTY_PRINT));
} catch (Exception $e) {
    error_log('init_user.php: Failed to store user in Redis: ' . $e->getMessage());
    exit(1);
}
?>
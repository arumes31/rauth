<?php
require 'vendor/autoload.php';

use RAuth\Core\Config;
use RAuth\Core\Redis;

/**
 * Initialize Default User
 */

try {
    $username = Config::getRequired('INITIAL_USER');
    $password = Config::getRequired('INITIAL_PASSWORD');
    $email = Config::get('INITIAL_EMAIL', 'admin@example.com');
    $twofaSecret = Config::get('INITIAL_2FA_SECRET', '');

    $redis = Redis::getInstance(0);

    if ($redis->exists("user:$username")) {
        echo "User $username already exists. Skipping initialization.\n";
        exit(0);
    }

    $userData = [
        'username' => $username,
        'password' => password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]),
        'email' => $email,
        'name' => $username,
        'uid' => uniqid('u_'),
        'groups' => 'admin,default',
        '2fa_secret' => $twofaSecret,
        'is_admin' => '1'
    ];

    $redis->hmset("user:$username", $userData);
    $redis->sadd('users', $username);

    echo "User $username initialized successfully.\n";

} catch (\Exception $e) {
    fprintf(STDERR, "Initialization failed: %s\n", $e->getMessage());
    exit(1);
}


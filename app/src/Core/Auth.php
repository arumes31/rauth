<?php

namespace RAuth\Core;

class Auth {
    private $secret;

    public function __construct($secret) {
        if (strlen($secret) !== 32) {
            throw new \Exception("Server secret must be exactly 32 characters.");
        }
        $this->secret = $secret;
    }

    public function encryptToken($token) {
        $iv = random_bytes(16);
        $encrypted = openssl_encrypt(
            $token,
            'AES-256-CBC',
            $this->secret,
            0,
            $iv
        );
        if ($encrypted === false) {
            return false;
        }
        return base64_encode($iv . $encrypted);
    }

    public function decryptToken($encryptedToken) {
        $data = base64_decode($encryptedToken);
        if ($data === false || strlen($data) < 16) {
            return false;
        }
        $iv = substr($data, 0, 16);
        $encrypted = substr($data, 16);
        $decrypted = openssl_decrypt(
            $encrypted,
            'AES-256-CBC',
            $this->secret,
            0,
            $iv
        );
        return $decrypted;
    }

    public static function getClientIP() {
        $ip = $_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        if (strpos($ip, ',') !== false) {
            $ip = trim(explode(',', $ip)[0]);
        }
        return $ip;
    }

    public static function isPrivateIP($ip) {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $ip_num = ip2long($ip);
            return (
                ($ip_num >= ip2long('10.0.0.0') && $ip_num <= ip2long('10.255.255.255')) ||
                ($ip_num >= ip2long('172.16.0.0') && $ip_num <= ip2long('172.31.255.255')) ||
                ($ip_num >= ip2long('192.168.0.0') && $ip_num <= ip2long('192.168.255.255'))
            );
        }
        return false;
    }
}

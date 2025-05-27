<?php
require 'vendor/autoload.php';

use GeoIp2\Database\Reader;

// Log request for debugging
$request_id = bin2hex(random_bytes(8));
error_log("geoip-api.php [$request_id]: Received request");

// Get IP from query parameter
$ip = $_GET['ip'] ?? '';
if (!$ip) {
    http_response_code(400);
    echo json_encode(['error' => 'IP parameter is required']);
    error_log("geoip-api.php [$request_id]: Missing IP parameter");
    exit;
}

// Validate IP
if (!filter_var($ip, FILTER_VALIDATE_IP)) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid IP address']);
    error_log("geoip-api.php [$request_id]: Invalid IP address: $ip");
    exit;
}

// Check cache
$cache_key = "geoip_$ip";
$ttl = 3600; // Cache for 1 hour
$cached_result = apcu_fetch($cache_key);
if ($cached_result !== false) {
    error_log("geoip-api.php [$request_id]: Cache hit for IP $ip");
    header('Content-Type: application/json');
    echo json_encode($cached_result);
    exit;
}

// Initialize MaxMind reader
try {
    $reader = new Reader('/srv/app/geoip/GeoLite2-Country.mmdb');
    $record = $reader->country($ip);
    $country_code = $record->country->isoCode ?? 'unknown';
    $result = ['ip' => $ip, 'country' => $country_code];
    error_log("geoip-api.php [$request_id]: Country code for IP $ip: $country_code");
    
    // Store in cache
    apcu_store($cache_key, $result, $ttl);
    error_log("geoip-api.php [$request_id]: Cached result for IP $ip");
    
    header('Content-Type: application/json');
    echo json_encode($result);
} catch (Exception $e) {
    error_log("geoip-api.php [$request_id]: Failed to get country for IP $ip: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Unable to determine country']);
}
?>
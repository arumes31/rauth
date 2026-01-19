<?php
require 'vendor/autoload.php';

use GeoIp2\Database\Reader;

/**
 * GeoIP API Service
 * 
 * Provides country code for a given IP address with APCu caching.
 */

// Basic response helper
function sendResponse($data, $code = 200) {
    http_response_code($code);
    header('Content-Type: application/json');
    echo json_encode($data);
    exit;
}

$ip = $_GET['ip'] ?? '';

if (!$ip || !filter_var($ip, FILTER_VALIDATE_IP)) {
    sendResponse(['error' => 'Valid IP parameter is required'], 400);
}

// Cache check
$cacheKey = "geoip_v1_$ip";
if (function_exists('apcu_fetch')) {
    $cached = apcu_fetch($cacheKey);
    if ($cached !== false) {
        sendResponse($cached);
    }
}

try {
    $dbPath = getenv('GEOIP_DATABASE_DIRECTORY') ?: '/srv/app/geoip';
    $reader = new Reader($dbPath . '/GeoLite2-Country.mmdb');
    
    $record = $reader->country($ip);
    $result = [
        'ip' => $ip,
        'country' => $record->country->isoCode ?? 'unknown',
        'timestamp' => time()
    ];

    if (function_exists('apcu_store')) {
        apcu_store($cacheKey, $result, 86400); // Cache for 24 hours
    }

    sendResponse($result);

} catch (\GeoIp2\Exception\AddressNotFoundException $e) {
    sendResponse(['ip' => $ip, 'country' => 'unknown'], 200);
} catch (\Exception $e) {
    error_log("GeoIP Error: " . $e->getMessage());
    sendResponse(['error' => 'Internal Server Error'], 500);
}

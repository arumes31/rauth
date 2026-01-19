<?php

namespace RAuth\Core;

use GuzzleHttp\Client as HttpClient;

class GeoService {
    public static function getCountryCode($ip) {
        if (Auth::isPrivateIP($ip)) {
            return 'Internal';
        }

        $host = Config::get('GEO_API_HOST', 'rauth-geo-service');
        $port = Config::get('GEO_API_PORT', 3000);
        $url = "http://$host:$port/?ip=$ip";

        try {
            $client = new HttpClient();
            $response = $client->get($url, ['timeout' => 5]);
            $data = json_decode($response->getBody(), true);
            return $data['country'] ?? 'unknown';
        } catch (\Exception $e) {
            Logger::log("Geolocation API failed: " . $e->getMessage());
            return 'unknown';
        }
    }
}

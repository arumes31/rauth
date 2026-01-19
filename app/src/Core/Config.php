<?php

namespace RAuth\Core;

class Config {
    public static function get($key, $default = null) {
        $value = getenv($key);
        return $value !== false ? $value : $default;
    }

    public static function getRequired($key) {
        $value = self::get($key);
        if ($value === null) {
            throw new \Exception("Missing required environment variable: $key");
        }
        return $value;
    }
}

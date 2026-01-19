<?php

namespace RAuth\Core;

class Logger {
    private static $requestId;

    public static function init() {
        if (!self::$requestId) {
            self::$requestId = bin2hex(random_bytes(4));
        }
    }

    public static function log($message, $context = []) {
        self::init();
        $workerId = getmypid();
        $formattedContext = !empty($context) ? ' ' . json_encode($context) : '';
        error_log(sprintf("[%s] [Worker:%s] %s%s", self::$requestId, $workerId, $message, $formattedContext));
    }
}

<?php

namespace RAuth\Core;

class RateLimiter {
    private $redis;
    private $prefix = 'rate_limit:';

    public function __construct($db = 2) {
        $this->redis = Redis::getInstance($db);
    }

    /**
     * Check if the attempt is allowed
     * @param string $key Unique identifier (e.g., IP or Username)
     * @param int $maxAttempts
     * @param int $decaySeconds
     * @return bool
     */
    public function check($key, $maxAttempts = 5, $decaySeconds = 60) {
        $fullKey = $this->prefix . $key;
        $current = $this->redis->get($fullKey);

        if ($current !== null && (int)$current >= $maxAttempts) {
            return false;
        }

        if ($current === null) {
            $this->redis->setex($fullKey, $decaySeconds, 1);
        } else {
            $this->redis->incr($fullKey);
        }

        return true;
    }

    public function getRemaining($key, $maxAttempts = 5) {
        $current = $this->redis->get($this->prefix . $key);
        return max(0, $maxAttempts - (int)$current);
    }

    public function reset($key) {
        $this->redis->del($this->prefix . $key);
    }
}

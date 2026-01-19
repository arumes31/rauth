<?php

namespace RAuth\Core;

class AuditLogger {
    private $redis;
    private $listKey = 'audit_logs';

    public function __construct($db = 3) {
        $this->redis = Redis::getInstance($db);
    }

    public function log($action, $username, $details = []) {
        $logEntry = [
            'timestamp' => time(),
            'action' => $action,
            'username' => $username,
            'ip' => Auth::getClientIP(),
            'details' => $details
        ];

        // Store the last 1000 events
        $this->redis->lpush($this->listKey, json_encode($logEntry));
        $this->redis->ltrim($this->listKey, 0, 999);
        
        // Also log to system error_log for redundancy
        Logger::log("Audit: $action for user $username", $details);
    }

    public function getLogs($limit = 50) {
        $logs = $this->redis->lrange($this->listKey, 0, $limit - 1);
        return array_map(function($item) {
            return json_decode($item, true);
        }, $logs);
    }
}

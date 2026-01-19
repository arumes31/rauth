<?php

namespace RAuth\Core;

use Predis\Client;

class Redis {
    private static $instances = [];

    public static function getInstance($db, $persistentId = null) {
        $key = "db:$db" . ($persistentId ? ":$persistentId" : "");
        if (!isset(self::$instances[$key])) {
            $host = Config::get('REDIS_HOST', 'rauth-auth-redis');
            $port = Config::get('REDIS_PORT', 6379);
            $password = Config::get('REDIS_PASSWORD');

            $config = [
                'scheme' => 'tcp',
                'host' => $host,
                'port' => $port,
                'database' => $db,
                'timeout' => 5.0,
                'read_write_timeout' => 5.0,
            ];

            if ($persistentId) {
                $config['persistent'] = true;
                $config['persistent_id'] = $persistentId;
            }

            if ($password) {
                $config['password'] = $password;
            }

            try {
                $client = new Client($config);
                $client->ping();
                self::$instances[$key] = $client;
            } catch (\Exception $e) {
                error_log("Redis connection failed for DB $db: " . $e->getMessage());
                throw $e;
            }
        }
        return self::$instances[$key];
    }

    public function listUsers() {
        $usernames = $this->smembers('users');
        $users = [];
        foreach ($usernames as $username) {
            $data = $this->hgetall("user:$username");
            if ($data) {
                $users[] = $data;
            }
        }
        return $users;
    }

    public function createUser($username, $password, $email, $isAdmin = false) {
        if ($this->exists("user:$username")) {
            throw new \Exception("User already exists");
        }

        $userData = [
            'username' => $username,
            'password' => password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]),
            'email' => $email,
            'uid' => uniqid('u_'),
            'is_admin' => $isAdmin ? '1' : '0',
            'created_at' => time()
        ];

        $this->hmset("user:$username", $userData);
        $this->sadd('users', $username);
        return true;
    }

    public function updateUser($username, $data) {
        if (!$this->exists("user:$username")) {
            return false;
        }
        $this->hmset("user:$username", $data);
        return true;
    }
}

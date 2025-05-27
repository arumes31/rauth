#!/bin/sh

# Initialize first user in Redis
if [ -n "$INITIAL_USER" ] && [ -n "$INITIAL_PASSWORD" ] && [ -n "$INITIAL_EMAIL" ]; then
    echo "Initializing user..."
    php /var/www/html/init_user.php
fi

# Start PHP-FPM
echo "Starting PHP-FPM..."
php-fpm &
PHP_FPM_PID=$!
sleep 1
if ! ps -p $PHP_FPM_PID > /dev/null; then
    echo "PHP-FPM failed to start"
    exit 1
fi
if ! netstat -tuln | grep -q 9000; then
    echo "PHP-FPM not listening on 127.0.0.1:9000"
    exit 1
fi

# Start Nginx
echo "Starting Nginx..."
nginx -g "daemon off;"
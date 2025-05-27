FROM php:8.2-fpm

# Install Nginx, Redis tools, unzip, procps, net-tools, and dependencies
RUN apt-get update && apt-get install -y \
    nginx \
    redis-tools \
    unzip \
    libzip-dev \
    procps \
    net-tools \
    && pecl install redis \
    && docker-php-ext-install zip \
    && docker-php-ext-enable redis \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    # Verify auth_request module is available
    && nginx -V 2>&1 | grep -q http_auth_request_module || { echo "auth_request module not found"; exit 1; } \
    # Create nginx user and group
    && groupadd -r nginx && useradd -r -g nginx nginx

# Install Composer
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

# Copy Nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf
COPY proxy.conf /etc/nginx/conf.d/proxy.conf

# Copy PHP application
COPY app /var/www/html
WORKDIR /var/www/html

# Install PHP dependencies from composer.json
RUN composer install --no-dev --optimize-autoloader

# Copy and configure entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN sed -i 's/\r$//' /entrypoint.sh && \
    chmod +x /entrypoint.sh && \
    ls -l /entrypoint.sh

# Expose port
EXPOSE 80

# Start services
ENTRYPOINT ["/entrypoint.sh"]
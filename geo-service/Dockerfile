FROM php:8.2-cli

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    unzip \
    libmaxminddb-dev \
    && pecl install maxminddb \
    && pecl install apcu \
    && docker-php-ext-enable maxminddb apcu \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Composer
RUN curl -s https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

# Copy application files
COPY geoip-api.php /srv/app/geoip-api.php
COPY entrypoint.sh /srv/app/entrypoint.sh

# Set working directory
WORKDIR /srv/app

# Install MaxMind GeoIP2 PHP library
RUN composer require geoip2/geoip2:~2.0

# Create directory for GeoLite2 database
RUN mkdir -p /srv/app/geoip && chmod -R 755 /srv/app/geoip && \
    ls -ld /srv/app/geoip

# Install geoipupdate binary
COPY --from=ghcr.io/maxmind/geoipupdate:latest /usr/bin/geoipupdate /usr/bin/geoipupdate

# Ensure entrypoint script is executable and has Unix line endings
RUN chmod +x /srv/app/entrypoint.sh && \
    sed -i 's/\r$//' /srv/app/entrypoint.sh && \
    ls -l /srv/app/entrypoint.sh

# Expose port for the API
EXPOSE 3000

# Run entrypoint script
ENTRYPOINT ["/srv/app/entrypoint.sh"]
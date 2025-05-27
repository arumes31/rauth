#!/bin/sh

# Ensure geoip directory exists
echo "Ensuring /srv/app/geoip exists..."
mkdir -p /srv/app/geoip
if [ ! -d /srv/app/geoip ]; then
    echo "Failed to create /srv/app/geoip"
    exit 1
fi
chmod -R 755 /srv/app/geoip
ls -ld /srv/app/geoip

# Generate GeoIP.conf from environment variables
echo "Generating GeoIP.conf..."
cat > /srv/app/geoip/GeoIP.conf <<EOL
AccountID ${MAXMIND_ACCOUNT_ID}
LicenseKey ${MAXMIND_LICENSE_KEY}
EditionIDs ${GEOIP_EDITION_IDS}
DatabaseDirectory ${GEOIP_DATABASE_DIRECTORY}
EOL

# Verify GeoIP.conf was created
if [ ! -f /srv/app/geoip/GeoIP.conf ]; then
    echo "Failed to create GeoIP.conf"
    exit 1
fi

# Run geoipupdate to fetch/update GeoLite2 Country database
echo "Running geoipupdate..."
/usr/bin/geoipupdate -v -f /srv/app/geoip/GeoIP.conf -d /srv/app/geoip
if [ $? -ne 0 ]; then
    echo "geoipupdate failed"
    exit 1
fi

# Verify database file exists
if [ ! -f /srv/app/geoip/GeoLite2-Country.mmdb ]; then
    echo "GeoLite2-Country.mmdb not found"
    exit 1
fi

# Start PHP built-in server
echo "Starting PHP server..."
php -S 0.0.0.0:3000 /srv/app/geoip-api.php
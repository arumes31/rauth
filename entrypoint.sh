#!/bin/sh

# Generate GeoIP.conf from environment variables if they exist
if [ -n "$MAXMIND_ACCOUNT_ID" ] && [ -n "$MAXMIND_LICENSE_KEY" ]; then
    echo "Generating GeoIP.conf..."
    mkdir -p /app/geoip
    cat > /app/geoip/GeoIP.conf <<EOL
AccountID ${MAXMIND_ACCOUNT_ID}
LicenseKey ${MAXMIND_LICENSE_KEY}
EditionIDs ${GEOIP_EDITION_IDS:-GeoLite2-Country}
DatabaseDirectory /app/geoip
EOL

    echo "Running geoipupdate..."
    /usr/bin/geoipupdate -v -f /app/geoip/GeoIP.conf -d /app/geoip
fi

# Start the Go application
echo "Starting RAuth..."
exec ./rauth

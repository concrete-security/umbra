#!/bin/sh
set -e

echo "Starting Nginx and Certificate Manager..."
echo "Domain: ${DOMAIN}"
echo "Dev Mode: ${DEV_MODE}"

# Start supervisor to manage both nginx and cert manager
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf

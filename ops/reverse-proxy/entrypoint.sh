#!/bin/sh
set -eu

if [ -z "${CONSOLE_HOST:-}" ]; then
  echo "CONSOLE_HOST is required" >&2
  exit 1
fi

# Reverse-proxy CA selection. LETSENCRYPT_STAGING is REQUIRED and must be exactly
# 'true' or 'false':
#   true  -> Let's Encrypt staging CA (--test-cert): untrusted certs, no rate limits
#   false -> the real, publicly trusted CA (needed to exercise prod attestation)
# Any other value, or an unset variable, is a configuration error and aborts.
case "${LETSENCRYPT_STAGING:-}" in
  true) staging_args="--test-cert" ;;
  false) staging_args="" ;;
  *)
    echo "LETSENCRYPT_STAGING must be exactly 'true' or 'false'; got '${LETSENCRYPT_STAGING:-<unset>}'" >&2
    exit 1
    ;;
esac

webroot="/var/www/certbot"
mkdir -p "${webroot}"

issue_cert_if_missing() {
  host="$1"
  cert_dir="/etc/letsencrypt/live/${host}"

  if [ -s "${cert_dir}/fullchain.pem" ] && [ -s "${cert_dir}/privkey.pem" ]; then
    return 0
  fi

  email_args="--register-unsafely-without-email"
  if [ -n "${LETSENCRYPT_EMAIL:-}" ]; then
    email_args="--email ${LETSENCRYPT_EMAIL}"
  fi

  # shellcheck disable=SC2086
  certbot certonly \
    --standalone \
    --non-interactive \
    --agree-tos \
    ${email_args} \
    ${staging_args} \
    --preferred-challenges http \
    -d "${host}"
}

envsubst '${CONSOLE_HOST}' < /etc/nginx/templates/default.conf.template > /etc/nginx/conf.d/default.conf

issue_cert_if_missing "${CONSOLE_HOST}"

if [ -n "${INSTALL_HOST:-}" ] && [ "${INSTALL_HOST}" != "${CONSOLE_HOST}" ]; then
  issue_cert_if_missing "${INSTALL_HOST}"
  cat > /etc/nginx/conf.d/install.conf <<EOF
server {
    listen 80;
    server_name ${INSTALL_HOST};
    access_log /var/log/nginx/access.log umbra_no_query;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name ${INSTALL_HOST};
    access_log /var/log/nginx/access.log umbra_no_query;

    ssl_certificate /etc/letsencrypt/live/${INSTALL_HOST}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${INSTALL_HOST}/privkey.pem;

    location = / {
        proxy_pass http://installer:8080/;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }

    location = /install.sh {
        proxy_pass http://installer:8080/install.sh;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }

    location /releases/umbra-cli/ {
        proxy_pass http://installer:8080;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }

    location / {
        return 404;
    }
}
EOF
else
  rm -f /etc/nginx/conf.d/install.conf
fi

exec nginx -g "daemon off;"

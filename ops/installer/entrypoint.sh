#!/bin/sh
set -eu

if [ -z "${INSTALL_HOST:-}" ]; then
  echo "installer: INSTALL_HOST is not set; serving health checks only" >&2
  cat > /etc/nginx/conf.d/default.conf <<'EOF'
server {
    listen 8080;
    server_name _;
    location = /healthz {
        default_type text/plain;
        return 200 "ok\n";
    }
    location / {
        default_type text/plain;
        return 503 "installer is not configured\n";
    }
}
EOF
  exec nginx -g "daemon off;"
fi

base_url="${UMBRA_INSTALL_BASE_URL:-https://${INSTALL_HOST}}"
release_repo="${UMBRA_CLI_RELEASE_GITHUB_REPO:-concrete-security/umbra}"
case "$release_repo" in
  github.com/*) default_source_repo="$release_repo" ;;
  *) default_source_repo="github.com/${release_repo}" ;;
esac
source_repo="${UMBRA_INSTALL_SOURCE_REPO:-${default_source_repo}}"
# This value is baked into every install.sh we serve, so catch a plaintext base
# URL at deploy time rather than letting each user's install fail (or, worse,
# fetch a binary over an unauthenticated channel). Same rule as install.sh and
# `umbra update`: https for remote hosts, plaintext for loopback only.
case "$base_url" in
  https://*) ;;
  http://127.0.0.1 | http://127.0.0.1[/:]* | http://localhost | http://localhost[/:]*) ;;
  "http://[::1]" | "http://[::1]"[/:]*) ;;
  http://*)
    echo "installer: refusing plaintext http UMBRA_INSTALL_BASE_URL=${base_url}" >&2
    exit 1
    ;;
  *)
    echo "installer: invalid UMBRA_INSTALL_BASE_URL=${base_url}" >&2
    exit 1
    ;;
esac

case "$source_repo" in
  github.com/*/*) ;;
  *)
    echo "installer: invalid UMBRA_INSTALL_SOURCE_REPO=${source_repo}; expected github.com/OWNER/REPO" >&2
    exit 1
    ;;
esac
case "$source_repo" in
  *[!0-9A-Za-z._/-]*)
    echo "installer: invalid UMBRA_INSTALL_SOURCE_REPO=${source_repo}; expected github.com/OWNER/REPO" >&2
    exit 1
    ;;
esac
source_repo_path="${source_repo#github.com/}"
source_repo_owner="${source_repo_path%%/*}"
source_repo_name="${source_repo_path#*/}"
if [ -z "$source_repo_owner" ] || [ -z "$source_repo_name" ] || [ "${source_repo_name#*/}" != "$source_repo_name" ]; then
  echo "installer: invalid UMBRA_INSTALL_SOURCE_REPO=${source_repo}; expected github.com/OWNER/REPO" >&2
  exit 1
fi

mkdir -p /etc/umbra/installer
sed \
  -e "s|__UMBRA_INSTALL_BASE_URL__|${base_url}|g" \
  -e "s|__UMBRA_INSTALL_SOURCE_REPO__|${source_repo}|g" \
  /opt/umbra/installer/install.sh.template \
  > /etc/umbra/installer/install.sh
chmod 0644 /etc/umbra/installer/install.sh

cp /etc/nginx/templates/nginx.conf.template /etc/nginx/conf.d/default.conf

exec nginx -g "daemon off;"

#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "user-sandbox: $1" >&2
  exit 1
}

required_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    fail "missing required env ${name}"
  fi
}

decode_b64_to_file() {
  local name="$1"
  local path="$2"
  local mode="$3"
  required_env "$name"
  printf '%s' "${!name}" | base64 -d >"$path" || fail "invalid base64 in ${name}"
  if [ ! -s "$path" ]; then
    fail "${name} decoded to an empty file"
  fi
  chmod "$mode" "$path"
}

validate_authorized_keys() {
  local input="$1"
  local count=0
  while IFS= read -r line || [ -n "$line" ]; do
    [ -z "$line" ] && continue
    case "$line" in
      ssh-ed25519\ *|ssh-rsa\ *|ecdsa-sha2-nistp256\ *|ecdsa-sha2-nistp384\ *|ecdsa-sha2-nistp521\ *|sk-ssh-ed25519@openssh.com\ *|sk-ecdsa-sha2-nistp256@openssh.com\ *)
        count=$((count + 1))
        ;;
      *)
        fail "unsupported authorized_keys line"
        ;;
    esac
  done <"$input"
  [ "$count" -gt 0 ] || fail "authorized_keys must contain at least one key"
}

quote_authorized_key_env_literal() {
  local key="$1"
  local value="$2"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf 'environment="%s=%s",' "$key" "$value"
}

quote_authorized_key_env() {
  local key="$1"
  quote_authorized_key_env_literal "$key" "${!key}"
}

quote_placeholder_env_options() {
  local placeholder_file="$1"
  local line name value
  declare -A seen=()

  while IFS= read -r line || [ -n "$line" ]; do
    [ -z "$line" ] && continue
    if [[ "$line" != *=* ]]; then
      fail "invalid sandbox env placeholder line"
    fi
    name="${line%%=*}"
    value="${line#*=}"
    validate_placeholder_name "$name" || fail "invalid sandbox env placeholder name"
    validate_placeholder_value "$value" || fail "invalid sandbox env placeholder value"
    if [ -n "${seen[$name]+x}" ] && [ "${seen[$name]}" != "$value" ]; then
      fail "conflicting sandbox env placeholder value"
    fi
    seen[$name]="$value"
  done <"$placeholder_file"

  for name in $(printf '%s\n' "${!seen[@]}" | sort); do
    quote_authorized_key_env_literal "$name" "${seen[$name]}"
  done
}

write_authorized_keys() {
  local source="$1"
  local target="$2"
  local placeholder_file="${3:-}"
  local options
  options="$(
    quote_authorized_key_env HTTP_PROXY
    quote_authorized_key_env HTTPS_PROXY
    quote_authorized_key_env NO_PROXY
    quote_authorized_key_env REQUESTS_CA_BUNDLE
    quote_authorized_key_env SSL_CERT_FILE
    quote_authorized_key_env CURL_CA_BUNDLE
    quote_authorized_key_env GIT_SSL_CAINFO
    quote_authorized_key_env NODE_EXTRA_CA_CERTS
    quote_authorized_key_env BASH_ENV
    quote_authorized_key_env PATH
    quote_authorized_key_env PIP_USER
    quote_authorized_key_env GH_CONFIG_DIR
    if [ -n "$placeholder_file" ]; then
      quote_placeholder_env_options "$placeholder_file"
    fi
  )"
  options="${options%,}"
  : >"$target"
  while IFS= read -r line || [ -n "$line" ]; do
    [ -z "$line" ] && continue
    printf '%s %s\n' "$options" "$line" >>"$target"
  done <"$source"
  chmod 0644 "$target"
}

validate_placeholder_name() {
  local name="$1"
  [[ "$name" =~ ^[A-Za-z_][A-Za-z0-9_]{0,127}$ ]] || return 1
  case "$name" in
    HTTP_PROXY|HTTPS_PROXY|NO_PROXY|PATH|HOME|CONCRETE_*|SECURITY_CVM_*|AUTHORIZED_SSH_*|SANDBOX_ENV_*)
      return 1
      ;;
  esac
  return 0
}

validate_placeholder_value() {
  local value="$1"
  case "$value" in
    *$'\n'*)
      return 1
      ;;
  esac
  [[ "$value" =~ sk-ant-[A-Za-z0-9_-]{20,} ]] && return 1
  [[ "$value" =~ sk-[A-Za-z0-9]{20,} ]] && return 1
  [[ "$value" =~ gh[pousr]_[A-Za-z0-9_]{20,} ]] && return 1
  [[ "$value" =~ AKIA[0-9A-Z]{16} ]] && return 1
  return 0
}

write_runtime_env() {
  local placeholder_file="$1"
  local output="$2"
  declare -A seen=()

  cat >"$output" <<ENV
export HTTP_PROXY='http://dev-egress-forwarder:3128'
export HTTPS_PROXY='http://dev-egress-forwarder:3128'
export http_proxy='http://dev-egress-forwarder:3128'
export https_proxy='http://dev-egress-forwarder:3128'
export NO_PROXY='localhost,127.0.0.1,user-sandbox,dev-tunnel,dev-egress-forwarder'
export no_proxy='localhost,127.0.0.1,user-sandbox,dev-tunnel,dev-egress-forwarder'
export REQUESTS_CA_BUNDLE='/run/concrete/ca-bundle.pem'
export SSL_CERT_FILE='/run/concrete/ca-bundle.pem'
export CURL_CA_BUNDLE='/run/concrete/ca-bundle.pem'
export GIT_SSL_CAINFO='/run/concrete/ca-bundle.pem'
export NODE_EXTRA_CA_CERTS='/run/concrete/ca-bundle.pem'
export NPM_CONFIG_IGNORE_SCRIPTS='true'
export NPM_CONFIG_AUDIT='false'
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC='1'
export PYTHONDONTWRITEBYTECODE='1'
export BASH_ENV='/run/concrete-env.sh'
export PATH='/home/dev/.local/bin:'"\$PATH"
export PIP_USER='1'
export GH_CONFIG_DIR='/home/dev/.local/share/gh'
ENV

  while IFS= read -r line || [ -n "$line" ]; do
    [ -z "$line" ] && continue
    if [[ "$line" != *=* ]]; then
      fail "invalid sandbox env placeholder line"
    fi
    name="${line%%=*}"
    value="${line#*=}"
    validate_placeholder_name "$name" || fail "invalid sandbox env placeholder name"
    validate_placeholder_value "$value" || fail "invalid sandbox env placeholder value"
    if [ -n "${seen[$name]+x}" ] && [ "${seen[$name]}" != "$value" ]; then
      fail "conflicting sandbox env placeholder value"
    fi
    seen[$name]="$value"
  done <"$placeholder_file"

  for name in "${!seen[@]}"; do
    printf 'export %s=%q\n' "$name" "${seen[$name]}" >>"$output"
  done
  chmod 0644 "$output"
}

ensure_runtime_dev_dir() {
  local mode="$1"
  local path="$2"
  install -d -o dev -g dev -m "$mode" "$path"
}

ensure_dev_dir_if_missing() {
  local mode="$1"
  local path="$2"
  if [ ! -e "$path" ]; then
    install -d -o dev -g dev -m "$mode" "$path"
  fi
}

ensure_claude_config() {
  local path="$1"
  if [ ! -s "$path" ]; then
    printf '{}\n' >"$path"
    chown dev:dev "$path"
    chmod 0600 "$path"
  fi
}

ensure_claude_native_install() {
  local version
  local target
  local current
  version="$(cat /usr/local/lib/concrete/claude.version 2>/dev/null || true)"
  if [ -z "$version" ]; then
    fail "missing Claude version metadata"
  fi
  if [ ! -x /usr/local/lib/concrete/claude.real ]; then
    fail "missing baked Claude binary"
  fi

  target="/home/dev/.local/share/claude/versions/${version}"
  install -d -o dev -g dev -m 0755 /home/dev/.local/share/claude/versions
  if [ ! -x "$target" ]; then
    install -o dev -g dev -m 0755 /usr/local/lib/concrete/claude.real "$target"
  fi

  current="$(readlink -f /home/dev/.local/bin/claude 2>/dev/null || true)"
  if [ -x /home/dev/.local/bin/claude ] && [ "$current" != "/usr/local/bin/claude" ]; then
    return
  fi
  ln -sfn "$target" /home/dev/.local/bin/claude
  chown -h dev:dev /home/dev/.local/bin/claude
}

if [ "${CONCRETE_ENTRYPOINT_SELF_TEST:-}" = "validate-placeholder-value" ]; then
  validate_placeholder_value "concrete-proxy-injected" \
    || fail "self-test rejected benign placeholder value"
  if validate_placeholder_value $'line\nbreak'; then
    fail "self-test accepted newline placeholder value"
  fi
  if validate_placeholder_value "sk-ant-abcdefghijklmnopqrstuvwxyz"; then
    fail "self-test accepted secret-shaped placeholder value"
  fi

  self_test_dir="$(mktemp -d)"
  trap 'rm -rf "$self_test_dir"' EXIT
  export HTTP_PROXY='http://dev-egress-forwarder:3128'
  export HTTPS_PROXY='http://dev-egress-forwarder:3128'
  export NO_PROXY='localhost,127.0.0.1,user-sandbox,dev-tunnel,dev-egress-forwarder'
  export REQUESTS_CA_BUNDLE='/run/concrete/ca-bundle.pem'
  export SSL_CERT_FILE='/run/concrete/ca-bundle.pem'
  export CURL_CA_BUNDLE='/run/concrete/ca-bundle.pem'
  export GIT_SSL_CAINFO='/run/concrete/ca-bundle.pem'
  export NODE_EXTRA_CA_CERTS='/run/concrete/ca-bundle.pem'
  export BASH_ENV='/run/concrete-env.sh'
  export PATH="/home/dev/.local/bin:${PATH}"
  export PIP_USER='1'
  export GH_CONFIG_DIR='/home/dev/.local/share/gh'
  printf 'VERIFY_PLACEHOLDER=non-secret-placeholder\nQUOTED_PLACEHOLDER=value"with\\slashes\n' \
    >"${self_test_dir}/placeholders"
  printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMockConcreteVerifyKeyForEntryPointTests test\n' \
    >"${self_test_dir}/authorized_keys.source"
  write_authorized_keys \
    "${self_test_dir}/authorized_keys.source" \
    "${self_test_dir}/authorized_keys" \
    "${self_test_dir}/placeholders"
  grep -F 'environment="VERIFY_PLACEHOLDER=non-secret-placeholder"' "${self_test_dir}/authorized_keys" >/dev/null \
    || fail "self-test did not render sandbox env placeholder into authorized_keys"
  grep -F 'environment="QUOTED_PLACEHOLDER=value\"with\\slashes"' "${self_test_dir}/authorized_keys" >/dev/null \
    || fail "self-test did not escape sandbox env placeholder in authorized_keys"
  exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
  fail "entrypoint must run as root"
fi

mkdir -p /run/ssh/authorized_keys /run/sshd /run/concrete
ensure_runtime_dev_dir 0700 /run/ssh/user-ssh
ensure_runtime_dev_dir 0700 /run/concrete/sessions
ensure_dev_dir_if_missing 0755 /home/dev/workspaces
ensure_dev_dir_if_missing 0755 /home/dev/.local
ensure_dev_dir_if_missing 0755 /home/dev/.local/bin
ensure_dev_dir_if_missing 0755 /home/dev/.local/share
ensure_dev_dir_if_missing 0755 /home/dev/.local/share/gh
ensure_dev_dir_if_missing 0755 /home/dev/.cache
ensure_dev_dir_if_missing 0755 /home/dev/.npm
ensure_dev_dir_if_missing 0755 /home/dev/.claude
ensure_dev_dir_if_missing 0755 /home/dev/.codex
ensure_dev_dir_if_missing 0755 /home/dev/.cursor-server
ensure_dev_dir_if_missing 0755 /home/dev/.vscode-server
ensure_claude_config /home/dev/.claude/.claude.json
ensure_claude_native_install

if [ -n "${SECURITY_CVM_PROXY_TOKEN+x}" ] || [ -n "${SECURITY_CVM_ATLS_POLICY_B64+x}" ]; then
  fail "forwarder-only Security CVM material must not be injected into user-sandbox"
fi

export HTTP_PROXY='http://dev-egress-forwarder:3128'
export HTTPS_PROXY='http://dev-egress-forwarder:3128'
export NO_PROXY='localhost,127.0.0.1,user-sandbox,dev-tunnel,dev-egress-forwarder'
export REQUESTS_CA_BUNDLE='/run/concrete/ca-bundle.pem'
export SSL_CERT_FILE='/run/concrete/ca-bundle.pem'
export CURL_CA_BUNDLE='/run/concrete/ca-bundle.pem'
export GIT_SSL_CAINFO='/run/concrete/ca-bundle.pem'
export NODE_EXTRA_CA_CERTS='/run/concrete/ca-bundle.pem'
export BASH_ENV='/run/concrete-env.sh'
export PATH="/home/dev/.local/bin:${PATH}"
export PIP_USER='1'
export GH_CONFIG_DIR='/home/dev/.local/share/gh'

decode_b64_to_file SECURITY_CVM_CA_CERT_B64 /run/concrete/security-cvm-ca.pem 0444
decode_b64_to_file AUTHORIZED_SSH_KEYS_B64 /run/concrete/authorized_keys.bootstrap 0644
printf '%s' "${SANDBOX_ENV_PLACEHOLDERS_B64:-}" | base64 -d >/run/concrete/sandbox-env-placeholders \
  || fail "invalid base64 in SANDBOX_ENV_PLACEHOLDERS_B64"
chmod 0444 /run/concrete/sandbox-env-placeholders

unset SECURITY_CVM_CA_CERT_B64 AUTHORIZED_SSH_KEYS_B64 SANDBOX_ENV_PLACEHOLDERS_B64

[ -s /run/concrete/security-cvm-ca.pem ] || fail "Security CVM CA is empty"
validate_authorized_keys /run/concrete/authorized_keys.bootstrap
cat /etc/ssl/certs/ca-certificates.crt /run/concrete/security-cvm-ca.pem >/run/concrete/ca-bundle.pem
chmod 0644 /run/concrete/ca-bundle.pem
write_runtime_env /run/concrete/sandbox-env-placeholders /run/concrete-env.sh
write_authorized_keys /run/concrete/authorized_keys.bootstrap /run/ssh/authorized_keys/dev /run/concrete/sandbox-env-placeholders

if [ -e /home/dev/.ssh ] && [ ! -L /home/dev/.ssh ]; then
  fail "/home/dev/.ssh exists and is not a symlink"
fi
ln -sfn /run/ssh/user-ssh /home/dev/.ssh
mkdir -p /home/dev/.claude
ln -sfn /home/dev/.claude/.claude.json /home/dev/.claude.json
chown -h dev:dev /home/dev/.ssh /home/dev/.claude.json

ssh-keygen -q -t ed25519 -N '' -f /run/sshd/ssh_host_ed25519_key
ssh-keygen -q -t rsa -b 3072 -N '' -f /run/sshd/ssh_host_rsa_key

if command -v dockerd >/dev/null; then
  dockerd >/var/log/dockerd.log 2>&1 &
else
  echo "user-sandbox: dockerd missing; continuing without Docker daemon" >&2
fi

exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config \
  -h /run/sshd/ssh_host_ed25519_key \
  -h /run/sshd/ssh_host_rsa_key

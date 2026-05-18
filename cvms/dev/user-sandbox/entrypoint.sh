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

write_secret_file() {
  local name="$1"
  local path="$2"
  local mode="$3"
  required_env "$name"
  printf '%s' "${!name}" >"$path"
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

quote_authorized_key_env() {
  local key="$1"
  printf 'environment="%s=%s",' "$key" "${!key}"
}

write_authorized_keys() {
  local source="$1"
  local target="$2"
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

if [ "${CONCRETE_ENTRYPOINT_SELF_TEST:-}" = "validate-placeholder-value" ]; then
  validate_placeholder_value "concrete-proxy-injected" \
    || fail "self-test rejected benign placeholder value"
  if validate_placeholder_value $'line\nbreak'; then
    fail "self-test accepted newline placeholder value"
  fi
  if validate_placeholder_value "sk-ant-abcdefghijklmnopqrstuvwxyz"; then
    fail "self-test accepted secret-shaped placeholder value"
  fi
  exit 0
fi

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

mkdir -p /run/ssh/authorized_keys /run/ssh/user-ssh /run/sshd /run/concrete/sessions
chown dev:dev /run/ssh/user-ssh /run/concrete/sessions
chmod 0700 /run/concrete/sessions

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
decode_b64_to_file SECURITY_CVM_ATLS_POLICY_B64 /run/concrete/security-cvm.atls-policy.json 0444
write_secret_file SECURITY_CVM_PROXY_TOKEN /run/concrete/proxy-token 0400
decode_b64_to_file AUTHORIZED_SSH_KEYS_B64 /run/concrete/authorized_keys.bootstrap 0644
printf '%s' "${SANDBOX_ENV_PLACEHOLDERS_B64:-}" | base64 -d >/run/concrete/sandbox-env-placeholders \
  || fail "invalid base64 in SANDBOX_ENV_PLACEHOLDERS_B64"
chmod 0444 /run/concrete/sandbox-env-placeholders

unset SECURITY_CVM_CA_CERT_B64 SECURITY_CVM_ATLS_POLICY_B64 SECURITY_CVM_PROXY_TOKEN AUTHORIZED_SSH_KEYS_B64 SANDBOX_ENV_PLACEHOLDERS_B64

[ -s /run/concrete/security-cvm-ca.pem ] || fail "Security CVM CA is empty"
validate_authorized_keys /run/concrete/authorized_keys.bootstrap
cat /etc/ssl/certs/ca-certificates.crt /run/concrete/security-cvm-ca.pem >/run/concrete/ca-bundle.pem
chmod 0644 /run/concrete/ca-bundle.pem
write_runtime_env /run/concrete/sandbox-env-placeholders /run/concrete-env.sh
write_authorized_keys /run/concrete/authorized_keys.bootstrap /run/ssh/authorized_keys/dev

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

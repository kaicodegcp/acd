#!/usr/bin/env bash
set -euo pipefail

if (( $# < 3 || $# > 4 )); then
  echo "Usage: $0 <vault_cert_path> <fid_name> <fid_pwd> [dev|uat|prod]" >&2
  exit 2
fi

export VAULT_CACERT="$1"
FID_NAME="$2"
FID_PASSWORD="$3"
ENVIRONMENT="${4:-dev}"
export VAULT_NAMESPACE="citi"

case "${ENVIRONMENT,,}" in
  dev)  export VAULT_ADDR="https://dev-hcvault.nam.nsroot.net:8200" ;;
  uat)  export VAULT_ADDR="https://uat-hcvault.nam.nsroot.net:8200" ;;
  prod) export VAULT_ADDR="https://hcvault.nam.nsroot.net:8200" ;;
  *) echo "Invalid environment: $ENVIRONMENT (use dev, uat, prod)" >&2; exit 2 ;;
esac

[[ -r "$VAULT_CACERT" ]] || { echo "Certificate not readable: $VAULT_CACERT" >&2; exit 1; }
for cmd in curl jq vault; do
  command -v "$cmd" >/dev/null || { echo "Missing required command: $cmd" >&2; exit 1; }
done

# Avoid tracing secrets if shell tracing was enabled by caller.
set +x
umask 077
OUTPUT_FILE="vault_bind.txt"

printf 'Authenticating to Vault (%s)...\n' "${ENVIRONMENT,,}"
LOGIN_JSON=$(jq -n --arg password "$FID_PASSWORD" '{password: $password}')
unset FID_PASSWORD
LOGIN_RESPONSE=$(curl --fail --silent --show-error \
  --cacert "$VAULT_CACERT" \
  --header "X-Vault-Namespace: $VAULT_NAMESPACE" \
  --header 'Content-Type: application/json' \
  --request POST \
  --data "$LOGIN_JSON" \
  "$VAULT_ADDR/v1/auth/ldap/login/$FID_NAME")
unset LOGIN_JSON

VAULT_TOKEN=$(jq -er '.auth.client_token' <<< "$LOGIN_RESPONSE")
unset LOGIN_RESPONSE
export VAULT_TOKEN

CURRENT_TTL=$(vault token lookup -format=json | jq -er '.data.ttl')
printf 'Initial token TTL: %s seconds\n' "$CURRENT_TTL"

if (( CURRENT_TTL < 28800 )); then
  echo 'Requesting renewal to 8 hours (subject to Vault limits)...'
  if ! vault token renew -increment=8h >/dev/null; then
    echo 'Renewal unavailable or denied; retaining original token.' >&2
  fi
fi

TOKEN_INFO=$(vault token lookup -format=json)
FINAL_TTL=$(jq -er '.data.ttl' <<< "$TOKEN_INFO")
RENEWABLE=$(jq -r '.data.renewable' <<< "$TOKEN_INFO")
EXPIRE_TIME=$(jq -r '.data.expire_time' <<< "$TOKEN_INFO")

# Atomic write; ensure token file is owner-readable only.
TMP_FILE=$(mktemp "./.vault_bind.txt.XXXXXX")
trap 'rm -f "$TMP_FILE"' EXIT
printf '%s\n' "$VAULT_TOKEN" > "$TMP_FILE"
chmod 600 "$TMP_FILE"
mv -f "$TMP_FILE" "$OUTPUT_FILE"
trap - EXIT

printf '\nToken saved to %s (mode 600)\n' "$OUTPUT_FILE"
printf 'Actual remaining TTL: %s seconds\n' "$FINAL_TTL"
printf 'Renewable: %s\nExpires: %s\n' "$RENEWABLE" "$EXPIRE_TIME"
if (( FINAL_TTL < 28800 )); then
  echo 'WARNING: Vault did not grant the full 8 hours.' >&2
fi

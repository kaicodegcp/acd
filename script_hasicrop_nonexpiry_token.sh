#!/usr/bin/env bash
set -euo pipefail
umask 077

usage() {
  echo "Usage: $0 <vault_cert_path> <fid_name> <fid_pwd> [dev|uat|prod]" >&2
  echo "WARNING: Password passed as argument may appear in process listings and shell history." >&2
  exit 2
}
[[ $# -ge 3 && $# -le 4 ]] || usage
export VAULT_CACERT="$1"
FID_NAME="$2"
FID_PASSWORD="$3"
ENVIRONMENT="${4:-dev}"
export VAULT_NAMESPACE="citi"
case "${ENVIRONMENT,,}" in
  dev) export VAULT_ADDR="https://dev-hcvault.nam.nsroot.net:8200" ;;
  uat) export VAULT_ADDR="https://uat-hcvault.nam.nsroot.net:8200" ;;
  prod) export VAULT_ADDR="https://hcvault.nam.nsroot.net:8200" ;;
  *) usage ;;
esac
[[ -r "$VAULT_CACERT" ]] || { echo "Certificate unreadable: $VAULT_CACERT" >&2; exit 1; }
command -v vault >/dev/null || { echo "vault CLI not found" >&2; exit 1; }
command -v jq >/dev/null || { echo "jq not found" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl not found" >&2; exit 1; }

# LDAP login grants only the privileges configured for this FID.
LOGIN_JSON=$(curl -fsS --cacert "$VAULT_CACERT" \
  -H "X-Vault-Namespace: $VAULT_NAMESPACE" -H 'Content-Type: application/json' \
  -X POST --data "$(jq -nc --arg password "$FID_PASSWORD" '{password:$password}')" \
  "$VAULT_ADDR/v1/auth/ldap/login/$FID_NAME")
unset FID_PASSWORD
export VAULT_TOKEN=$(jq -er '.auth.client_token' <<< "$LOGIN_JSON")
unset LOGIN_JSON

# Periodic orphan tokens need elevated token-create privileges and approved policy.
# The administrator must authorize a periodic orphan token without an explicit maximum TTL.
POLICY="${VAULT_AUTOMATION_POLICY:-}"
[[ -n "$POLICY" ]] || { echo "Set VAULT_AUTOMATION_POLICY to your approved policy name." >&2; exit 1; }
TOKEN_JSON=$(vault token create -format=json -orphan -period=8h -renewable=true \
  -policy="$POLICY" -display-name="databricks-automation" ) || {
    echo "Vault denied periodic token creation. Ask your Vault administrator for an approved AppRole or periodic token role." >&2
    exit 1
  }
NEW_TOKEN=$(jq -er '.auth.client_token' <<< "$TOKEN_JSON")
unset TOKEN_JSON

# Verify actual token properties before writing it.
TOKEN_INFO=$(VAULT_TOKEN="$NEW_TOKEN" vault token lookup -format=json)
PERIOD=$(jq -r '.data.period // 0' <<< "$TOKEN_INFO")
RENEWABLE=$(jq -r '.data.renewable // false' <<< "$TOKEN_INFO")
EXPLICIT_MAX=$(jq -r '.data.explicit_max_ttl // 0' <<< "$TOKEN_INFO")
if [[ "$PERIOD" -le 0 || "$RENEWABLE" != true || "$EXPLICIT_MAX" != 0 ]]; then
  echo "Token does not meet periodic-renewable/no-explicit-max requirements; not saving." >&2
  exit 1
fi
printf '%s\n' "$NEW_TOKEN" > vault_bind.txt
chmod 600 vault_bind.txt
printf 'Saved periodic token to vault_bind.txt (permissions 600).\n'
printf 'Period: %s seconds; renewable: %s; explicit_max_ttl: %s\n' "$PERIOD" "$RENEWABLE" "$EXPLICIT_MAX"
printf 'This token expires unless renewed before its TTL ends.\n'

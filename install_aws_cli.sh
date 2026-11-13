#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_DIR="/opt/aws-cli"
BIN_DIR="/usr/local/bin"
WORK_DIR="$(mktemp -d /tmp/awscli-install.XXXXXXXX)"
trap 'rm -rf "$WORK_DIR"' EXIT

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: Run this script as root (sudo bash install_aws_cli.sh)." >&2
  exit 1
fi

if [[ "$(uname -m)" != "x86_64" ]]; then
  echo "ERROR: This script is for x86_64 Linux only." >&2
  exit 1
fi

for cmd in wget unzip; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: $cmd is missing. Install it from your approved RHEL repository." >&2
    exit 1
  fi
done

echo "Downloading AWS CLI v2..."
wget --https-only --tries=3 --timeout=30 \
  -O "$WORK_DIR/awscliv2.zip" \
  "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip"

echo "Extracting AWS CLI..."
unzip -q "$WORK_DIR/awscliv2.zip" -d "$WORK_DIR"

echo "Installing AWS CLI to $INSTALL_DIR..."
mkdir -p "$BIN_DIR"
if [[ -x "$INSTALL_DIR/v2/current/bin/aws" ]]; then
  "$WORK_DIR/aws/install" --install-dir "$INSTALL_DIR" --bin-dir "$BIN_DIR" --update
else
  "$WORK_DIR/aws/install" --install-dir "$INSTALL_DIR" --bin-dir "$BIN_DIR"
fi

echo "Verifying installation..."
"$BIN_DIR/aws" --version
printf '\nAWS CLI executable: %s\n' "$BIN_DIR/aws"
echo "Installation completed successfully."

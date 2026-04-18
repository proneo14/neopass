#!/usr/bin/env bash
#
# Installs the Quantum Password Manager native messaging host
# for Chrome, Edge (Linux), and Firefox on macOS/Linux.
#
set -euo pipefail

APP_NAME="com.quantum.passwordmanager"
DISPLAY_NAME="Quantum Password Manager Native Host"
BINARY_PATH="${1:-}"
EXTENSION_ID="${2:-}"

# Determine OS
OS="$(uname -s)"

# Find binary
if [ -z "$BINARY_PATH" ]; then
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    BINARY_PATH="$SCRIPT_DIR/../bin/qpm-native-host"
fi

if [ ! -f "$BINARY_PATH" ]; then
    echo "Error: Native host binary not found at: $BINARY_PATH" >&2
    exit 1
fi

BINARY_PATH="$(cd "$(dirname "$BINARY_PATH")" && pwd)/$(basename "$BINARY_PATH")"

# Install binary
if [ "$OS" = "Darwin" ]; then
    INSTALL_DIR="$HOME/Library/Application Support/QuantumPasswordManager"
else
    INSTALL_DIR="$HOME/.config/QuantumPasswordManager"
fi

mkdir -p "$INSTALL_DIR"
cp "$BINARY_PATH" "$INSTALL_DIR/qpm-native-host"
chmod +x "$INSTALL_DIR/qpm-native-host"
echo "Installed binary to: $INSTALL_DIR/qpm-native-host"

INSTALLED_BINARY="$INSTALL_DIR/qpm-native-host"

# Chrome allowed_origins
CHROME_ORIGINS="[]"
if [ -n "$EXTENSION_ID" ]; then
    CHROME_ORIGINS="[\"chrome-extension://$EXTENSION_ID/\"]"
fi

# Generate Chrome/Edge manifest
CHROME_MANIFEST=$(cat <<EOF
{
  "name": "$APP_NAME",
  "description": "$DISPLAY_NAME",
  "path": "$INSTALLED_BINARY",
  "type": "stdio",
  "allowed_origins": $CHROME_ORIGINS
}
EOF
)

# Generate Firefox manifest
FIREFOX_MANIFEST=$(cat <<EOF
{
  "name": "$APP_NAME",
  "description": "$DISPLAY_NAME",
  "path": "$INSTALLED_BINARY",
  "type": "stdio",
  "allowed_extensions": ["qpm@quantum-password-manager.com"]
}
EOF
)

# Install manifests per platform
if [ "$OS" = "Darwin" ]; then
    # Chrome
    CHROME_DIR="$HOME/Library/Application Support/Google/Chrome/NativeMessagingHosts"
    mkdir -p "$CHROME_DIR"
    echo "$CHROME_MANIFEST" > "$CHROME_DIR/$APP_NAME.json"
    echo "Installed Chrome manifest: $CHROME_DIR/$APP_NAME.json"

    # Firefox
    FIREFOX_DIR="$HOME/Library/Application Support/Mozilla/NativeMessagingHosts"
    mkdir -p "$FIREFOX_DIR"
    echo "$FIREFOX_MANIFEST" > "$FIREFOX_DIR/$APP_NAME.json"
    echo "Installed Firefox manifest: $FIREFOX_DIR/$APP_NAME.json"
else
    # Linux — Chrome
    CHROME_DIR="$HOME/.config/google-chrome/NativeMessagingHosts"
    mkdir -p "$CHROME_DIR"
    echo "$CHROME_MANIFEST" > "$CHROME_DIR/$APP_NAME.json"
    echo "Installed Chrome manifest: $CHROME_DIR/$APP_NAME.json"

    # Linux — Chromium
    CHROMIUM_DIR="$HOME/.config/chromium/NativeMessagingHosts"
    mkdir -p "$CHROMIUM_DIR"
    echo "$CHROME_MANIFEST" > "$CHROMIUM_DIR/$APP_NAME.json"
    echo "Installed Chromium manifest: $CHROMIUM_DIR/$APP_NAME.json"

    # Linux — Edge
    EDGE_DIR="$HOME/.config/microsoft-edge/NativeMessagingHosts"
    mkdir -p "$EDGE_DIR"
    echo "$CHROME_MANIFEST" > "$EDGE_DIR/$APP_NAME.json"
    echo "Installed Edge manifest: $EDGE_DIR/$APP_NAME.json"

    # Linux — Firefox
    FIREFOX_DIR="$HOME/.mozilla/native-messaging-hosts"
    mkdir -p "$FIREFOX_DIR"
    echo "$FIREFOX_MANIFEST" > "$FIREFOX_DIR/$APP_NAME.json"
    echo "Installed Firefox manifest: $FIREFOX_DIR/$APP_NAME.json"
fi

echo ""
echo "Native messaging host installed successfully."
echo "Restart your browser for changes to take effect."

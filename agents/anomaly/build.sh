#!/bin/bash

# Build script for Anomaly agent (Linux/macOS)
# This script packages the Node.js agent into an asar archive

echo "Building Anomaly Agent (asar)..."

# Check if asar is installed globally
if ! command -v asar &> /dev/null; then
    echo "asar is not installed. Installing globally..."
    npm install -g @electron/asar
fi

# Create build directory
mkdir -p build

# Copy main.js to build directory
echo "Copying files..."
cp main.js build/main.js

# Copy package.json to build directory
cp package.json build/package.json

# Package into asar
echo "Packaging into asar..."
asar pack build app.asar

# Clean up build directory
rm -rf build

echo ""
echo "================================"
echo "Build successful!"
echo "Output: app.asar"
echo "================================"
echo ""
echo "To run: node --no-warnings app.asar"



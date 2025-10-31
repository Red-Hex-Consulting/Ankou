# Building Ankou C2 Desktop Applications

This document describes how to build the Ankou C2 dashboard as standalone desktop applications for Windows, Linux, and macOS.

## Prerequisites

1. Node.js 18+ installed
2. npm installed
3. Run `npm install` in the frontend directory

## Build Commands

### Build for Windows
```bash
npm run dist:win
```

**Outputs:**
- `release/Ankou C2-0.1.0-x64.exe` - NSIS installer (full setup wizard)
- `release/Ankou C2-0.1.0-x64-portable.exe` - Portable executable (no installation required)

### Build for Linux
```bash
npm run dist:linux
```

**Outputs:**
- `release/Ankou C2-0.1.0-x64.AppImage` - AppImage (portable, works on most distros)
- `release/Ankou C2-0.1.0-x64.deb` - Debian package (for Ubuntu/Debian-based systems)

### Build for macOS
```bash
npm run dist:mac
```

**Outputs:**
- `release/Ankou C2-0.1.0-x64.dmg` - DMG installer for Intel Macs
- `release/Ankou C2-0.1.0-arm64.dmg` - DMG installer for Apple Silicon Macs

### Build for All Platforms
```bash
npm run dist:all
```

**Note:** Building for macOS requires macOS. Building for Windows/Linux can be done from any platform.

## Development Mode

To run the Electron app in development mode:

```bash
npm run electron-dev
```

This will:
1. Start the Vite dev server on http://localhost:1420
2. Launch Electron with hot-reload enabled
3. Open DevTools automatically

## Icon Files

The application uses the logo at `public/logo.png` for all platforms. Electron-builder will automatically generate platform-specific icon formats:

- **Windows:** `build/icon.ico` (auto-generated from icon.png)
- **Linux:** `build/icon.png` (copied from public/logo.png)
- **macOS:** `build/icon.icns` (auto-generated from icon.png)

For best results, the source icon should be at least 512x512 pixels.

## Configuration

Build settings are in `electron-builder.json`:

- **Windows:** Creates both NSIS installer and portable .exe
- **Linux:** Creates both AppImage and .deb package
- **macOS:** Creates universal DMG for Intel and Apple Silicon

## Distribution

All built applications are placed in the `release/` directory.

### Windows
- Installer allows users to choose installation directory
- Creates desktop and start menu shortcuts
- Uninstaller included

### Linux
- AppImage is portable and requires no installation
- .deb package can be installed with `dpkg` or double-clicked in file manager

### macOS
- DMG can be dragged to Applications folder
- Universal binary supports both Intel and Apple Silicon

## Troubleshooting

### Build Fails on Linux
Ensure you have these dependencies:
```bash
# Ubuntu/Debian
sudo apt-get install -y libopenjp2-tools

# Fedora/RHEL
sudo dnf install openjpeg2-tools
```

### Build Fails on Windows
Make sure Windows SDK is installed (required for NSIS).

### Icon Not Showing
Ensure `build/icon.png` exists and is at least 256x256 pixels (512x512+ recommended).

## Certificate Handling

The Electron app is configured to accept self-signed certificates for C2 connections. This is necessary because the server generates self-signed TLS certificates on first run.

No additional configuration is needed - just build and run!


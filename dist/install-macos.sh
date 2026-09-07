#!/bin/bash
# Isolation Bytes — Universal macOS Installer
# Creates a .app bundle that opens isolation-bytes.com in a dedicated window.
#
# Usage:
#   bash install-macos.sh                    # download from web
#   bash install-macos.sh --local            # use local dist/ files
#   curl -fsSL https://isolation-bytes.com/download/install-macos.sh | bash

set -e

BASE_URL="${ISOLATION_BYTES_SERVER:-https://isolation-bytes.com}"
APP_DIR="/Applications/Isolation Bytes.app"
LOCAL=false

for arg in "$@"; do
  case "$arg" in
    --local) LOCAL=true ;;
  esac
done

echo "=== Isolation Bytes — macOS Installer ==="

# ─── 1. Create the .app bundle ─────────────────────────────────────────
echo "Creating $APP_DIR ..."
mkdir -p "$APP_DIR/Contents/MacOS"
mkdir -p "$APP_DIR/Contents/Resources"

# ─── 2. Write the launcher script ──────────────────────────────────────
cat > "$APP_DIR/Contents/MacOS/IsolationBytes" << 'LAUNCHER'
#!/bin/bash
URL="${ISOLATION_BYTES_URL:-https://isolation-bytes.com/}"
# Try Chrome first (supports --app mode), then Edge, then Safari, then default
if command -v google-chrome >/dev/null 2>&1; then
  exec google-chrome --app="$URL"
elif [ -x "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ]; then
  exec "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --app="$URL"
elif [ -x "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge" ]; then
  exec "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge" --app="$URL"
elif command -v open >/dev/null 2>&1; then
  exec open -a Safari "$URL"
else
  exec open "$URL"
fi
LAUNCHER
chmod +x "$APP_DIR/Contents/MacOS/IsolationBytes"

# ─── 3. Write Info.plist ───────────────────────────────────────────────
cat > "$APP_DIR/Contents/Info.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>
  <string>Isolation Bytes</string>
  <key>CFBundleDisplayName</key>
  <string>Isolation Bytes</string>
  <key>CFBundleIdentifier</key>
  <string>com.soluzka.isolationbytes</string>
  <key>CFBundleVersion</key>
  <string>1.8.890</string>
  <key>CFBundleShortVersionString</key>
  <string>1.8.890</string>
  <key>CFBundleExecutable</key>
  <string>IsolationBytes</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>LSMinimumSystemVersion</key>
  <string>10.13</string>
  <key>NSHighResolutionCapable</key>
  <true/>
  <key>LSUIElement</key>
  <false/>
</dict>
</plist>
PLIST

# ─── 4. Download icon if available ─────────────────────────────────────
ICON_PATH="$APP_DIR/Contents/Resources/AppIcon.icns"
if [ "$LOCAL" = true ] && [ -f "$(dirname "$0")/dist/icon-512.png" ]; then
  cp "$(dirname "$0")/dist/icon-512.png" "$APP_DIR/Contents/Resources/AppIcon.png"
  echo "Copied local icon."
elif command -v curl >/dev/null 2>&1; then
  curl -fsSL "$BASE_URL/static/icon-512.png" -o "$APP_DIR/Contents/Resources/AppIcon.png" 2>/dev/null || true
fi

# ─── 5. Register with Launch Services ──────────────────────────────────
if command -v /System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister >/dev/null 2>&1; then
  /System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister "$APP_DIR" >/dev/null 2>&1 || true
fi

# ─── 6. Install the network monitoring agent ───────────────────────────
AGENT_DIR="$HOME/.isolation-bytes"
mkdir -p "$AGENT_DIR"

echo "Installing network monitoring agent..."

# Download the universal launcher which includes the agent
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$BASE_URL/download/universal_launcher.py" -o "$AGENT_DIR/universal_launcher.py" 2>/dev/null || true
  curl -fsSL "$BASE_URL/download/standalone_agent.py" -o "$AGENT_DIR/standalone_agent.py" 2>/dev/null || true
elif command -v wget >/dev/null 2>&1; then
  wget -q "$BASE_URL/download/universal_launcher.py" -O "$AGENT_DIR/universal_launcher.py" 2>/dev/null || true
  wget -q "$BASE_URL/download/standalone_agent.py" -O "$AGENT_DIR/standalone_agent.py" 2>/dev/null || true
fi

# Check if Python is available
PYTHON_BIN=""
for cmd in python3 python; do
  if command -v "$cmd" >/dev/null 2>&1; then
    PYTHON_BIN="$cmd"
    break
  fi
done

if [ -n "$PYTHON_BIN" ] && [ -f "$AGENT_DIR/standalone_agent.py" ]; then
  # Install psutil if not present
  "$PYTHON_BIN" -c "import psutil" 2>/dev/null || "$PYTHON_BIN" -m pip install --user psutil requests 2>/dev/null || true

  # Create the agent launch script
  cat > "$AGENT_DIR/start_agent.sh" << AGENT_EOF
#!/bin/bash
export ISOLATION_BYTES_SERVER="${BASE_URL}"
exec "$PYTHON_BIN" "$AGENT_DIR/standalone_agent.py" --server "${BASE_URL}" --key=af5caf8d3d8080f8a8686f72dfa52eb92dad9ef95ebfdcd6f6494cf99ed6b909 --auto-start
AGENT_EOF
  chmod +x "$AGENT_DIR/start_agent.sh"

  # Add agent to the app bundle launcher so it starts when the app opens
  cat > "$APP_DIR/Contents/MacOS/IsolationBytes" << 'LAUNCHER_FULL'
#!/bin/bash
URL="${ISOLATION_BYTES_URL:-https://isolation-bytes.com/}"
AGENT_DIR="$HOME/.isolation-bytes"

# Start the network monitoring agent in the background if not already running
if [ -f "$AGENT_DIR/start_agent.sh" ] && ! pgrep -f "standalone_agent.py" >/dev/null 2>&1; then
  nohup "$AGENT_DIR/start_agent.sh" >/dev/null 2>&1 &
fi

# Try Chrome first (supports --app mode), then Edge, then Safari, then default
if command -v google-chrome >/dev/null 2>&1; then
  exec google-chrome --app="$URL"
elif [ -x "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" ]; then
  exec "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --app="$URL"
elif [ -x "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge" ]; then
  exec "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge" --app="$URL"
elif command -v open >/dev/null 2>&1; then
  exec open -a Safari "$URL"
else
  exec open "$URL"
fi
LAUNCHER_FULL
  chmod +x "$APP_DIR/Contents/MacOS/IsolationBytes"

  # Create LaunchAgent plist for auto-start on login
  LAUNCH_PLIST="$HOME/Library/LaunchAgents/com.soluzka.isolationbytes.agent.plist"
  cat > "$LAUNCH_PLIST" << PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.soluzka.isolationbytes.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>$AGENT_DIR/start_agent.sh</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>$AGENT_DIR/agent.log</string>
  <key>StandardErrorPath</key>
  <string>$AGENT_DIR/agent_error.log</string>
</dict>
</plist>
PLIST_EOF

  echo "Network monitoring agent installed and configured to start on login."
else
  echo "WARNING: Python not found or agent download failed."
  echo "         Network monitoring (C2 detection, connection scanning) will not work."
  echo "         Install Python 3 from https://python.org and re-run this installer."
fi

echo ""
echo "Installation complete!"
echo "Isolation Bytes is in /Applications."
echo "Open it from Spotlight (Cmd+Space, type 'Isolation Bytes') or Launchpad."
echo ""
echo "Network monitoring agent features:"
echo "  - Scans all network connections on this Mac"
echo "  - Reports all running processes"
echo "  - C2 detection and suspicious connection flagging"
echo "  - Auto-blocks flagged connections when enabled"
echo "  - Reports to the cloud dashboard at $BASE_URL"
echo ""
echo "The agent starts automatically on login and runs in the background."

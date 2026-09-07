#!/bin/bash
# Isolation Bytes — Universal Linux Installer
# Creates a .desktop entry that opens isolation-bytes.com in app mode.
#
# Usage:
#   bash install-linux.sh                    # download from web
#   bash install-linux.sh --local            # use local dist/ files
#   curl -fsSL https://isolation-bytes.com/download/install-linux.sh | bash

set -e

BASE_URL="${ISOLATION_BYTES_SERVER:-https://isolation-bytes.com}"
LOCAL=false
APP_NAME="Isolation Bytes"

for arg in "$@"; do
  case "$arg" in
    --local) LOCAL=true ;;
  esac
done

echo "=== Isolation Bytes — Linux Installer ==="

# ─── 1. Determine icon path ────────────────────────────────────────────
ICON_DIR="$HOME/.local/share/icons/hicolor/512x512/apps"
mkdir -p "$ICON_DIR"
ICON_PATH="$ICON_DIR/isolation-bytes.png"

if [ "$LOCAL" = true ] && [ -f "$(dirname "$0")/dist/icon-512.png" ]; then
  cp "$(dirname "$0")/dist/icon-512.png" "$ICON_PATH"
elif command -v curl >/dev/null 2>&1; then
  curl -fsSL "$BASE_URL/static/icon-512.png" -o "$ICON_PATH" 2>/dev/null || true
elif command -v wget >/dev/null 2>&1; then
  wget -q "$BASE_URL/static/icon-512.png" -O "$ICON_PATH" 2>/dev/null || true
fi

# ─── 2. Create launcher script ─────────────────────────────────────────
BIN_DIR="$HOME/.local/bin"
mkdir -p "$BIN_DIR"
LAUNCHER="$BIN_DIR/isolation-bytes"

cat > "$LAUNCHER" << 'LAUNCHER_EOF'
#!/bin/bash
URL="${ISOLATION_BYTES_URL:-https://isolation-bytes.com/}"
# Try Chromium-based browsers in app mode first, then fallback
for cmd in \
  "chromium --app=$URL" \
  "google-chrome --app=$URL" \
  "google-chrome-stable --app=$URL" \
  "chromium-browser --app=$URL" \
  "microsoft-edge --app=$URL" \
  "epiphany --app-mode --profile=isolbytes $URL" \
  "falkon $URL" \
  "midori $URL" \
  "firefox -P isolationbytes $URL" \
  "xdg-open $URL"; do
  binary=$(echo "$cmd" | awk '{print $1}')
  if command -v "$binary" >/dev/null 2>&1; then
    exec $cmd
  fi
done
echo "No suitable browser found. Please install Chromium or Firefox." >&2
exit 1
LAUNCHER_EOF
chmod +x "$LAUNCHER"

# ─── 3. Create .desktop entry ──────────────────────────────────────────
APPS_DIR="$HOME/.local/share/applications"
mkdir -p "$APPS_DIR"
DESKTOP_FILE="$APPS_DIR/isolation-bytes.desktop"

cat > "$DESKTOP_FILE" << EOF
[Desktop Entry]
Type=Application
Name=Isolation Bytes
Comment=Isolation Bytes Antivirus - Web-based security dashboard
Exec=$LAUNCHER
Icon=isolation-bytes
Terminal=false
Categories=Security;Network;Utility;
StartupNotify=true
StartupWMClass=isolation-bytes
EOF

# ─── 4. Update desktop database ────────────────────────────────────────
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$APPS_DIR" 2>/dev/null || true
fi

# ─── 5. Create desktop shortcut ────────────────────────────────────────
DESKTOP_DIR="$HOME/Desktop"
if [ -d "$DESKTOP_DIR" ]; then
  cp "$DESKTOP_FILE" "$DESKTOP_DIR/isolation-bytes.desktop"
  chmod +x "$DESKTOP_DIR/isolation-bytes.desktop"
  echo "Desktop shortcut created."
fi

# ─── 6. Install the network monitoring agent ───────────────────────────
AGENT_DIR="$HOME/.isolation-bytes"
mkdir -p "$AGENT_DIR"

echo "Installing network monitoring agent..."

# Download the agent
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$BASE_URL/download/standalone_agent.py" -o "$AGENT_DIR/standalone_agent.py" 2>/dev/null || true
elif command -v wget >/dev/null 2>&1; then
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
  # Install psutil and requests if not present
  "$PYTHON_BIN" -c "import psutil" 2>/dev/null || "$PYTHON_BIN" -m pip install --user psutil requests 2>/dev/null || true
  "$PYTHON_BIN" -c "import requests" 2>/dev/null || "$PYTHON_BIN" -m pip install --user requests 2>/dev/null || true

  # Create the agent launch script
  cat > "$AGENT_DIR/start_agent.sh" << AGENT_EOF
#!/bin/bash
export ISOLATION_BYTES_SERVER="${BASE_URL}"
exec "$PYTHON_BIN" "$AGENT_DIR/standalone_agent.py" --server "${BASE_URL}" --key=af5caf8d3d8080f8a8686f72dfa52eb92dad9ef95ebfdcd6f6494cf99ed6b909 --auto-start
AGENT_EOF
  chmod +x "$AGENT_DIR/start_agent.sh"

  # Update the launcher to also start the agent
  cat > "$LAUNCHER" << 'LAUNCHER_FULL'
#!/bin/bash
URL="${ISOLATION_BYTES_URL:-https://isolation-bytes.com/}"
AGENT_DIR="$HOME/.isolation-bytes"

# Start the network monitoring agent in the background if not already running
if [ -f "$AGENT_DIR/start_agent.sh" ] && ! pgrep -f "standalone_agent.py" >/dev/null 2>&1; then
  nohup "$AGENT_DIR/start_agent.sh" >/dev/null 2>&1 &
fi

# Try Chromium-based browsers in app mode first, then fallback
for cmd in \
  "chromium --app=$URL" \
  "google-chrome --app=$URL" \
  "google-chrome-stable --app=$URL" \
  "chromium-browser --app=$URL" \
  "microsoft-edge --app=$URL" \
  "epiphany --app-mode --profile=isolbytes $URL" \
  "falkon $URL" \
  "midori $URL" \
  "firefox -P isolationbytes $URL" \
  "xdg-open $URL"; do
  binary=$(echo "$cmd" | awk '{print $1}')
  if command -v "$binary" >/dev/null 2>&1; then
    exec $cmd
  fi
done
echo "No suitable browser found. Please install Chromium or Firefox." >&2
exit 1
LAUNCHER_FULL
  chmod +x "$LAUNCHER"

  # Create systemd user service for auto-start on login
  SYSTEMD_DIR="$HOME/.config/systemd/user"
  mkdir -p "$SYSTEMD_DIR"
  cat > "$SYSTEMD_DIR/isolation-bytes-agent.service" << SERVICE_EOF
[Unit]
Description=Isolation Bytes Network Monitoring Agent
After=network-online.target

[Service]
Type=simple
ExecStart=$AGENT_DIR/start_agent.sh
Restart=always
RestartSec=10
Environment=ISOLATION_BYTES_SERVER=${BASE_URL}

[Install]
WantedBy=default.target
SERVICE_EOF

  # Enable the service
  if command -v systemctl >/dev/null 2>&1; then
    systemctl --user daemon-reload 2>/dev/null || true
    systemctl --user enable isolation-bytes-agent.service 2>/dev/null || true
    systemctl --user start isolation-bytes-agent.service 2>/dev/null || true
  fi

  echo "Network monitoring agent installed and configured to start on login."
else
  echo "WARNING: Python not found or agent download failed."
  echo "         Network monitoring (C2 detection, connection scanning) will not work."
  echo "         Install Python 3 with: sudo apt install python3 python3-pip"
fi

echo ""
echo "Installation complete!"
echo "Isolation Bytes is in your application menu (Security category)."
echo "You can also run it from terminal: isolation-bytes"
echo ""
echo "Network monitoring agent features:"
echo "  - Scans all network connections on this Linux machine"
echo "  - Reports all running processes"
echo "  - C2 detection and suspicious connection flagging"
echo "  - Auto-blocks flagged connections when enabled"
echo "  - Reports to the cloud dashboard at $BASE_URL"
echo ""
echo "The agent starts automatically on login via systemd and runs in the background."

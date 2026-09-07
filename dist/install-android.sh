#!/data/data/com.termux/files/usr/bin/bash
# Isolation Bytes Agent — Android (Termux)
# Installs and starts the monitoring agent on Android via Termux.
#
# Prerequisites:
#   1. Install Termux from F-Droid (not Play Store — Play Store version is outdated)
#   2. Run: pkg install python
#   3. Run: bash install-android.sh

BASE_URL="${ISOLATION_BYTES_URL:-https://isolation-bytes.com}"
AGENT_DIR="$HOME/.isolation-bytes"
mkdir -p "$AGENT_DIR"

echo "=== Isolation Bytes Agent — Android ==="
echo "Server: $BASE_URL"
echo ""

# Check Termux
if [ ! -d "/data/data/com.termux" ]; then
  echo "ERROR: This script must be run inside Termux."
  echo "Install Termux from F-Droid: https://f-droid.org/packages/com.termux/"
  exit 1
fi

# Install Python if needed
if ! command -v python >/dev/null 2>&1; then
  echo "Installing Python..."
  pkg install -y python || { echo "ERROR: Could not install Python"; exit 1; }
fi

# Install dependencies
echo "Installing dependencies..."
python -m pip install psutil requests --quiet 2>/dev/null || true

# Download the agent
echo "Downloading agent..."
AGENT_PATH="$AGENT_DIR/standalone_agent.py"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$BASE_URL/download/standalone_agent.py" -o "$AGENT_PATH" 2>/dev/null
elif command -v wget >/dev/null 2>&1; then
  wget -q "$BASE_URL/download/standalone_agent.py" -O "$AGENT_PATH" 2>/dev/null
fi

if [ ! -f "$AGENT_PATH" ]; then
  echo "ERROR: Could not download agent. Check your internet connection."
  exit 1
fi

# Create start script
cat > "$AGENT_DIR/start_agent.sh" << EOF
#!/data/data/com.termux/files/usr/bin/bash
exec python "$AGENT_PATH" --server "$BASE_URL" --key=af5caf8d3d8080f8a8686f72dfa52eb92dad9ef95ebfdcd6f6494cf99ed6b909 --auto-start
EOF
chmod +x "$AGENT_DIR/start_agent.sh"

# Install Termux:Boot for auto-start on device boot
if [ ! -d "/data/data/com.termux.boot" ]; then
  echo ""
  echo "NOTE: For auto-start on boot, install Termux:Boot from F-Droid:"
  echo "  https://f-droid.org/packages/com.termux.boot/"
  echo ""
fi

# Set up auto-start via Termux:Boot if available
BOOT_DIR="$HOME/.termux/boot"
if [ -d "$HOME/.termux" ]; then
  mkdir -p "$BOOT_DIR"
  cat > "$BOOT_DIR/isolationbytes-agent.sh" << EOF
#!/data/data/com.termux/files/usr/bin/bash
termux-wake-lock
bash "$AGENT_DIR/start_agent.sh" &
EOF
  chmod +x "$BOOT_DIR/isolationbytes-agent.sh"
  echo "Auto-start configured via Termux:Boot."
fi

# Acquire wake lock so the agent keeps running when screen is off
termux-wake-lock 2>/dev/null || true

# Start the agent now
if ! pgrep -f "standalone_agent.py" >/dev/null 2>&1; then
  echo "Starting agent..."
  nohup bash "$AGENT_DIR/start_agent.sh" > "$AGENT_DIR/agent.log" 2>&1 &
  sleep 2
  if pgrep -f "standalone_agent.py" >/dev/null 2>&1; then
    echo "Agent is running!"
  else
    echo "Agent may have failed to start. Check: $AGENT_DIR/agent.log"
  fi
else
  echo "Agent is already running."
fi

echo ""
echo "=== Agent installed ==="
echo "  Log file:    $AGENT_DIR/agent.log"
echo "  Start script: $AGENT_DIR/start_agent.sh"
echo "  Auto-start:  $BOOT_DIR/isolationbytes-agent.sh"
echo ""
echo "The agent monitors:"
echo "  - Network connections"
echo "  - Running processes"
echo "  - Local network devices"
echo "  - C2/suspicious connection detection"
echo ""
echo "To stop: pkill -f standalone_agent.py"
echo "To restart: bash $AGENT_DIR/start_agent.sh"

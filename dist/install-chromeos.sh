#!/bin/bash
# Isolation Bytes Agent — ChromeOS (Linux container / Crostini)
# ChromeOS can run Linux apps via the Crostini container.
# This script installs the agent inside the Linux container.
#
# Prerequisites:
#   1. Enable Linux development environment in ChromeOS Settings
#   2. Open the Terminal app
#   3. Run: bash install-chromeos.sh

BASE_URL="${ISOLATION_BYTES_URL:-https://isolation-bytes.com}"
AGENT_DIR="$HOME/.isolation-bytes"
mkdir -p "$AGENT_DIR"

echo "=== Isolation Bytes Agent — ChromeOS (Linux) ==="
echo "Server: $BASE_URL"
echo ""

# Detect the Linux distro inside the Crostini container
if [ -f "/etc/os-release" ]; then
  . /etc/os-release
  echo "Container: $PRETTY_NAME"
fi

# Install Python if needed
PYTHON_BIN=""
for cmd in python3 python; do
  if command -v $cmd >/dev/null 2>&1; then
    PYTHON_BIN=$(command -v $cmd)
    break
  fi
done

if [ -z "$PYTHON_BIN" ]; then
  echo "Installing Python..."
  if command -v apt >/dev/null 2>&1; then
    sudo apt update -qq && sudo apt install -y python3 python3-pip
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y python3 python3-pip
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -S --noconfirm python python-pip
  fi
  PYTHON_BIN=$(command -v python3 || command -v python)
fi

if [ -z "$PYTHON_BIN" ]; then
  echo "ERROR: Could not install Python."
  exit 1
fi

echo "Python: $PYTHON_BIN"

# Install dependencies
echo "Installing dependencies..."
$PYTHON_BIN -m pip install --user psutil requests --quiet 2>/dev/null || true

# Download the agent
echo "Downloading agent..."
AGENT_PATH="$AGENT_DIR/standalone_agent.py"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$BASE_URL/download/standalone_agent.py" -o "$AGENT_PATH" 2>/dev/null
elif command -v wget >/dev/null 2>&1; then
  wget -q "$BASE_URL/download/standalone_agent.py" -O "$AGENT_PATH" 2>/dev/null
fi

if [ ! -f "$AGENT_PATH" ]; then
  echo "ERROR: Could not download agent."
  exit 1
fi

# Create start script
cat > "$AGENT_DIR/start_agent.sh" << EOF
#!/bin/bash
exec $PYTHON_BIN "$AGENT_PATH" --server "$BASE_URL" --key=af5caf8d3d8080f8a8686f72dfa52eb92dad9ef95ebfdcd6f6494cf99ed6b909 --auto-start
EOF
chmod +x "$AGENT_DIR/start_agent.sh"

# Set up systemd user service for auto-start
SYSTEMD_DIR="$HOME/.config/systemd/user"
mkdir -p "$SYSTEMD_DIR"
cat > "$SYSTEMD_DIR/isolation-bytes-agent.service" << EOF
[Unit]
Description=Isolation Bytes Network Monitoring Agent
After=network-online.target

[Service]
Type=simple
ExecStart=$AGENT_DIR/start_agent.sh
Restart=always
RestartSec=10
Environment=ISOLATION_BYTES_SERVER=$BASE_URL

[Install]
WantedBy=default.target
EOF

systemctl --user daemon-reload 2>/dev/null || true
systemctl --user enable isolation-bytes-agent.service 2>/dev/null || true

# Start the agent now
if ! pgrep -f "standalone_agent.py" >/dev/null 2>&1; then
  echo "Starting agent..."
  systemctl --user start isolation-bytes-agent.service 2>/dev/null || \
    nohup bash "$AGENT_DIR/start_agent.sh" > "$AGENT_DIR/agent.log" 2>&1 &
  sleep 2
  if pgrep -f "standalone_agent.py" >/dev/null 2>&1; then
    echo "Agent is running!"
  else
    echo "Agent started in background. Check: $AGENT_DIR/agent.log"
  fi
else
  echo "Agent is already running."
fi

echo ""
echo "=== Agent installed ==="
echo "  The agent monitors the Linux container's:"
echo "  - Network connections"
echo "  - Running processes"
echo "  - Local network devices (shared with ChromeOS)"
echo "  - C2/suspicious connection detection"
echo ""
echo "  Note: ChromeOS host processes are not visible from the Linux"
echo "  container. Only container processes/connections are monitored."
echo ""
echo "  To stop: systemctl --user stop isolation-bytes-agent.service"
echo "  To check: systemctl --user status isolation-bytes-agent.service"

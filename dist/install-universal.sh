#!/bin/bash
# Isolation Bytes — Universal Bootstrap Installer (macOS / Linux / ChromeOS)
# No Python required — this script installs Python 3.11+ if missing,
# then downloads and runs the universal launcher.
#
# Usage:
#   bash install-universal.sh
#   curl -fsSL https://isolation-bytes.com/download/install-universal.sh | bash

set -e

BASE_URL="${ISOLATION_BYTES_SERVER:-https://isolation-bytes.com}"
LAUNCHER_URL="$BASE_URL/download/universal_launcher.py"
PYTHON_MIN_VERSION="3.11"

echo "=== Isolation Bytes — Universal Installer ==="
echo "Platform: $(uname -s) $(uname -m)"

# ─── 1. Check if Python 3.11+ is installed ─────────────────────────────
PYTHON=""
for cmd in python3.11 python3.12 python3.13 python3.14 python3 python; do
  if command -v "$cmd" >/dev/null 2>&1; then
    VERSION=$("$cmd" --version 2>&1 | awk '{print $2}')
    VERSION_MAJOR=$(echo "$VERSION" | cut -d. -f1)
    VERSION_MINOR=$(echo "$VERSION" | cut -d. -f2)
    if [ "$VERSION_MAJOR" -ge 3 ] && [ "$VERSION_MINOR" -ge 11 ] 2>/dev/null; then
      PYTHON="$cmd"
      echo "Found Python $VERSION at: $(command -v "$cmd")"
      break
    fi
  fi
done

# ─── 2. Install Python 3.11+ if missing ────────────────────────────────
if [ -z "$PYTHON" ]; then
  echo "Python 3.11+ not found. Installing..."

  OS_TYPE=$(uname -s)

  if [ "$OS_TYPE" = "Darwin" ]; then
    # macOS — try Homebrew first
    if command -v brew >/dev/null 2>&1; then
      echo "Installing Python 3.11 via Homebrew..."
      brew install python@3.11
      PYTHON="python3.11"
    else
      # Install Homebrew, then Python
      echo "Installing Homebrew first..."
      /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
      echo "Installing Python 3.11 via Homebrew..."
      brew install python@3.11
      PYTHON="python3.11"
    fi

  elif [ "$OS_TYPE" = "Linux" ]; then
    # Linux — detect package manager and install Python 3.11+
    if command -v apt >/dev/null 2>&1; then
      echo "Installing Python 3.11 via apt..."
      sudo apt update
      # Try python3.11 first, fall back to python3
      sudo apt install -y python3.11 python3-pip 2>/dev/null || sudo apt install -y python3 python3-pip
      PYTHON=$(command -v python3.11 || command -v python3)

    elif command -v dnf >/dev/null 2>&1; then
      echo "Installing Python 3.11 via dnf..."
      sudo dnf install -y python3.11 python3-pip 2>/dev/null || sudo dnf install -y python3 python3-pip
      PYTHON=$(command -v python3.11 || command -v python3)

    elif command -v yum >/dev/null 2>&1; then
      echo "Installing Python 3 via yum..."
      sudo yum install -y python3 python3-pip
      PYTHON="python3"

    elif command -v pacman >/dev/null 2>&1; then
      echo "Installing Python via pacman..."
      sudo pacman -S --noconfirm python python-pip
      PYTHON="python3"

    elif command -v apk >/dev/null 2>&1; then
      echo "Installing Python via apk (Alpine)..."
      sudo apk add python3 py3-pip
      PYTHON="python3"

    elif command -v zypper >/dev/null 2>&1; then
      echo "Installing Python via zypper (SUSE)..."
      sudo zypper install -y python3 python3-pip
      PYTHON="python3"

    elif command -v emerge >/dev/null 2>&1; then
      echo "Installing Python via emerge (Gentoo)..."
      sudo emerge -av dev-lang/python
      PYTHON="python3"

    elif command -v xbps-install >/dev/null 2>&1; then
      echo "Installing Python via xbps (Void)..."
      sudo xbps-install -Sy python3 python3-pip
      PYTHON="python3"

    elif command -v pkg >/dev/null 2>&1; then
      # FreeBSD / ChromeOS Linux container (Crostini might have apt)
      echo "Installing Python via pkg..."
      sudo pkg install -y python3
      PYTHON="python3"

    else
      echo "No supported package manager found." >&2
      echo "Please install Python 3.11+ manually from https://www.python.org/downloads/" >&2
      exit 1
    fi
  fi

  # Verify installation
  if [ -z "$PYTHON" ] || ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "Python installation failed. Please install Python 3.11+ manually." >&2
    exit 1
  fi
  echo "Python installed: $($PYTHON --version)"
fi

# ─── 3. Download the universal launcher ─────────────────────────────────
LAUNCHER_PATH="/tmp/isolationbytes_launcher.py"
echo "Downloading universal launcher..."
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$LAUNCHER_URL" -o "$LAUNCHER_PATH"
elif command -v wget >/dev/null 2>&1; then
  wget -q "$LAUNCHER_URL" -O "$LAUNCHER_PATH"
else
  echo "Neither curl nor wget is available. Cannot download launcher." >&2
  exit 1
fi

# ─── 4. Run the launcher (install + launch) ─────────────────────────────
echo "Launching Isolation Bytes installer..."
"$PYTHON" "$LAUNCHER_PATH" --install "$@"
INSTALL_EXIT=$?

if [ $INSTALL_EXIT -ne 0 ]; then
  echo ""
  echo "Installation encountered an error (exit code $INSTALL_EXIT)."
  echo "Check the log file for details."
  rm -f "$LAUNCHER_PATH"
  exit 1
fi

# ─── 5. Install the network monitoring agent ───────────────────────────
AGENT_DIR="$HOME/.isolation-bytes"
mkdir -p "$AGENT_DIR"

echo "Installing network monitoring agent..."
AGENT_URL="$BASE_URL/download/standalone_agent.py"
if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$AGENT_URL" -o "$AGENT_DIR/standalone_agent.py" 2>/dev/null || true
elif command -v wget >/dev/null 2>&1; then
  wget -q "$AGENT_URL" -O "$AGENT_DIR/standalone_agent.py" 2>/dev/null || true
fi

if [ -f "$AGENT_DIR/standalone_agent.py" ]; then
  # Install dependencies
  "$PYTHON" -c "import psutil" 2>/dev/null || "$PYTHON" -m pip install --user psutil requests 2>/dev/null || true
  "$PYTHON" -c "import requests" 2>/dev/null || "$PYTHON" -m pip install --user requests 2>/dev/null || true

  # Create the agent launch script
  cat > "$AGENT_DIR/start_agent.sh" << AGENT_EOF
#!/bin/bash
export ISOLATION_BYTES_SERVER="${BASE_URL}"
exec "$PYTHON" "$AGENT_DIR/standalone_agent.py" --server "${BASE_URL}" --key=af5caf8d3d8080f8a8686f72dfa52eb92dad9ef95ebfdcd6f6494cf99ed6b909 --auto-start
AGENT_EOF
  chmod +x "$AGENT_DIR/start_agent.sh"

  # Start the agent now
  if ! pgrep -f "standalone_agent.py" >/dev/null 2>&1; then
    nohup "$AGENT_DIR/start_agent.sh" >/dev/null 2>&1 &
    echo "Network monitoring agent started."
  fi

  # Set up auto-start on login
  OS_TYPE=$(uname -s)
  if [ "$OS_TYPE" = "Darwin" ]; then
    # macOS — LaunchAgent
    mkdir -p "$HOME/Library/LaunchAgents"
    cat > "$HOME/Library/LaunchAgents/com.soluzka.isolationbytes.agent.plist" << PLIST_EOF
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
</dict>
</plist>
PLIST_EOF
  else
    # Linux — systemd user service
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
    systemctl --user daemon-reload 2>/dev/null || true
    systemctl --user enable isolation-bytes-agent.service 2>/dev/null || true
    systemctl --user start isolation-bytes-agent.service 2>/dev/null || true
  fi

  echo "Network monitoring agent installed and configured to start on login."
  echo "  - Scans all network connections"
  echo "  - Reports all running processes"
  echo "  - C2 detection and suspicious connection flagging"
  echo "  - Reports to the cloud dashboard at $BASE_URL"
else
  echo "WARNING: Agent download failed. Network monitoring will not work."
fi

echo ""
echo "=== Installation complete! ==="
echo ""
echo "Launching Isolation Bytes..."
"$PYTHON" "$LAUNCHER_PATH" --launch

echo ""
echo "Press Enter to close..."
read -r

rm -f "$LAUNCHER_PATH"

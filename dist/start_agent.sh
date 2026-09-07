#!/usr/bin/env bash
# Universal Isolation Bytes agent launcher for macOS, Linux, ChromeOS Linux,
# Git Bash, WSL, and Windows Python environments. Pass a pairing code once
# with --pair-code CODE.
set -euo pipefail

BASE_URL="${ISOLATION_BYTES_SERVER:-https://isolation-bytes.com}"
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PAIR_CODE="${ISOLATION_BYTES_PAIR_CODE:-}"
AUTO_START=1
BACKGROUND=0
SERVER_ARGS=(--server "$BASE_URL" --auto-start)

while [ "$#" -gt 0 ]; do
    case "$1" in
        --pair-code)
            [ "$#" -ge 2 ] || { echo "Missing value for --pair-code" >&2; exit 2; }
            PAIR_CODE="$2"
            shift 2
            ;;
        --server)
            [ "$#" -ge 2 ] || { echo "Missing value for --server" >&2; exit 2; }
            BASE_URL="$2"
            SERVER_ARGS=(--server "$BASE_URL" --auto-start)
            shift 2
            ;;
        --no-auto-start)
            AUTO_START=0
            SERVER_ARGS=("${SERVER_ARGS[@]/--auto-start}")
            shift
            ;;
        --background)
            BACKGROUND=1
            shift
            ;;
        *)
            SERVER_ARGS+=("$1")
            shift
            ;;
    esac
done

AGENT_EXE="${ISOLATION_BYTES_AGENT_EXE:-}"
if [ -z "$AGENT_EXE" ]; then
    if [ -x "$HOME/IsolationBytesAgent" ]; then
        AGENT_EXE="$HOME/IsolationBytesAgent"
    elif [ -f "$HOME/IsolationBytesAgent.exe" ]; then
        AGENT_EXE="$HOME/IsolationBytesAgent.exe"
    elif [ -x "$HOME/.local/bin/IsolationBytesAgent" ]; then
        AGENT_EXE="$HOME/.local/bin/IsolationBytesAgent"
    elif [ -x "$SCRIPT_DIR/IsolationBytesAgent" ]; then
        AGENT_EXE="$SCRIPT_DIR/IsolationBytesAgent"
    elif [ -f "$SCRIPT_DIR/IsolationBytesAgent.exe" ]; then
        AGENT_EXE="$SCRIPT_DIR/IsolationBytesAgent.exe"
    fi
fi
UNAME_S="$(uname -s 2>/dev/null || true)"
if [ -z "$AGENT_EXE" ] && { case "$UNAME_S" in MINGW*|MSYS*|CYGWIN*) true ;; *) [ -n "${WINDIR:-}" ] ;; esac; }; then
    AGENT_EXE="${LOCALAPPDATA:-$HOME/AppData/Local}/IsolationBytes/IsolationBytesAgent.exe"
    mkdir -p "$(dirname "$AGENT_EXE")"
    if [ ! -f "$AGENT_EXE" ]; then
        echo "IsolationBytesAgent.exe not found. Downloading it..."
        if command -v curl >/dev/null 2>&1; then
            curl --fail --location --silent --show-error "$BASE_URL/download/IsolationBytesAgent.exe" -o "$AGENT_EXE"
        elif command -v wget >/dev/null 2>&1; then
            wget --quiet --output-document="$AGENT_EXE" "$BASE_URL/download/IsolationBytesAgent.exe"
        else
            rm -f "$AGENT_EXE"
        fi
    fi
    [ -f "$AGENT_EXE" ] || AGENT_EXE=""
fi
if [ -n "$AGENT_EXE" ]; then
    set -- "${SERVER_ARGS[@]}"
    [ -n "$PAIR_CODE" ] && set -- "$@" --pair-code "$PAIR_CODE"
    [ -n "${ISOLATION_BYTES_CREDENTIAL_FILE:-}" ] && set -- "$@" --credential-file "$ISOLATION_BYTES_CREDENTIAL_FILE"
    if [ "$BACKGROUND" -eq 1 ]; then
        nohup "$AGENT_EXE" "$@" >/dev/null 2>&1 &
        echo "Isolation Bytes agent started in the background."
        exit 0
    fi
    exec "$AGENT_EXE" "$@"
fi

PYTHON_BIN="${PYTHON:-python3}"
AGENT_SCRIPT="${ISOLATION_BYTES_AGENT_SCRIPT:-$SCRIPT_DIR/standalone_agent.py}"
if [ ! -f "$AGENT_SCRIPT" ]; then
    AGENT_SCRIPT="$HOME/standalone_agent.py"
fi
if [ ! -f "$AGENT_SCRIPT" ]; then
    command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || {
        echo "curl or wget is required to download the agent." >&2
        exit 1
    }
    AGENT_SCRIPT="$HOME/standalone_agent.py"
    mkdir -p "$(dirname "$AGENT_SCRIPT")"
    if command -v curl >/dev/null 2>&1; then
        curl --fail --location --silent --show-error "$BASE_URL/download/standalone_agent.py" -o "$AGENT_SCRIPT"
    else
        wget --quiet --output-document="$AGENT_SCRIPT" "$BASE_URL/download/standalone_agent.py"
    fi
fi
command -v "$PYTHON_BIN" >/dev/null 2>&1 || {
    echo "Python 3.8+ is required to run the universal agent." >&2
    exit 1
}
set -- "${SERVER_ARGS[@]}"
[ -n "$PAIR_CODE" ] && set -- "$@" --pair-code "$PAIR_CODE"
[ -n "${ISOLATION_BYTES_CREDENTIAL_FILE:-}" ] && set -- "$@" --credential-file "$ISOLATION_BYTES_CREDENTIAL_FILE"
if [ "$BACKGROUND" -eq 1 ]; then
    nohup "$PYTHON_BIN" "$AGENT_SCRIPT" "$@" >/dev/null 2>&1 &
    echo "Isolation Bytes agent started in the background."
    exit 0
fi
exec "$PYTHON_BIN" "$AGENT_SCRIPT" "$@"

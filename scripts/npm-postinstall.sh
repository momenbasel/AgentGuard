#!/usr/bin/env bash
# AgentGuard npm package setup helper
# Installs the Python package and configures Claude Code hooks

set -e

echo "=== AgentGuard Setup ==="
echo ""

# Check if pip is available
if command -v pip3 &> /dev/null; then
    PIP="pip3"
elif command -v pip &> /dev/null; then
    PIP="pip"
else
    echo "Error: pip not found. Install Python 3.9+ first."
    echo "  brew install python3  (macOS)"
    echo "  apt install python3-pip  (Ubuntu/Debian)"
    exit 1
fi

echo "[1/3] Installing agentguard Python package..."
$PIP install agentguard --quiet

echo "[2/3] Installing Claude Code hook..."
agentguard install --global

echo "[3/3] Verifying installation..."
agentguard --version

echo ""
echo "AgentGuard is active. Every Bash command in Claude Code will be scanned."
echo ""
echo "Optional: Enable VirusTotal scanning:"
echo "  export VT_API_KEY='your-key'"
echo "  agentguard config init  # then set check_virustotal: true"
echo ""
echo "Docs: https://github.com/momenbasel/AgentGuard"

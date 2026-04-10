#!/bin/bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

RED='\033[0;31m'
YLW='\033[1;33m'
GRN='\033[0;32m'
NC='\033[0m'

ok()   { echo -e "${GRN}[OK]${NC}    $1"; }
warn() { echo -e "${YLW}[WARN]${NC}  $1"; }
fail() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

echo ""
echo "  PhishLab"
echo "  --------"
echo ""

command -v python3 &>/dev/null || fail "python3 not found. Install Python 3.10+."
ok "python3 found ($(python3 --version 2>&1))"

command -v node &>/dev/null || fail "node not found. Install Node.js 18+."
ok "node found ($(node --version))"

command -v npm &>/dev/null || fail "npm not found."
ok "npm found ($(npm --version))"

command -v docker &>/dev/null || fail "docker not found. Install Docker Desktop."
docker info &>/dev/null || fail "Docker is not running. Start Docker Desktop and try again."
ok "docker running"

command -v ollama &>/dev/null || warn "ollama not found — LLM analysis will not work. Install from https://ollama.com"

echo ""

if [ ! -d "$DIR/venv" ]; then
    echo "[SETUP] Creating virtual environment..."
    python3 -m venv "$DIR/venv"
fi

echo "[SYSTEM] Using virtual environment at $DIR/venv"
"$DIR/venv/bin/python" "$DIR/launcher.py"

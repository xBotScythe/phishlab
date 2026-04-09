#!/bin/bash

# Simple wrapper for the PhishLab launcher
# usage: ./run.sh

# Get the directory of this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# Check for python3
if ! command -v python3 &> /dev/null
then
    echo "python3 could not be found. Please install Python 3.10+."
    exit 1
fi

# Manage virtual environment
if [ ! -d "$DIR/venv" ]; then
    echo "[SYSTEM] Virtual environment not found. Creating one..."
    python3 -m venv "$DIR/venv"
fi

# Run the launcher using the venv's python
echo "[SYSTEM] Using virtual environment at $DIR/venv"
"$DIR/venv/bin/python" "$DIR/launcher.py"

#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
VENV="$BACKEND_DIR/venv"

# Create venv if missing
if [ ! -d "$VENV" ]; then
  echo "Creating virtual environment..."
  python3 -m venv "$VENV"
fi

# Install/update deps
echo "Checking dependencies..."
"$VENV/bin/pip" install -q -r "$BACKEND_DIR/requirements.txt"

# Copy .env.example if no .env exists
if [ ! -f "$BACKEND_DIR/.env" ]; then
  cp "$BACKEND_DIR/.env.example" "$BACKEND_DIR/.env"
  echo ""
  echo "  ⚠  Created backend/.env from template."
  echo "     Add your API keys there for full functionality:"
  echo "       VIRUSTOTAL_API_KEY   — https://www.virustotal.com/gui/user/apikey"
  echo "       ABUSEIPDB_API_KEY    — https://www.abuseipdb.com/account/api"
  echo "       IPINFO_TOKEN         — https://ipinfo.io/account/token (optional)"
  echo ""
fi

echo "Starting CyberCheck on http://localhost:8000"
echo "Press Ctrl+C to stop."
echo ""

cd "$BACKEND_DIR"
"$VENV/bin/uvicorn" main:app --host 127.0.0.1 --port 8000 --reload

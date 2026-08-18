#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/web"
if [[ ! -d node_modules ]]; then
  npm install
fi
cd "$ROOT"
probe_listen="${XGC_LAN_PANEL_LISTEN:-127.0.0.1:3400}"
go run ./cmd/xgc2-lan-panel probe --listen "$probe_listen" &
probe_pid=$!
cleanup() {
  kill "$probe_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM
cd "$ROOT/web"
echo "probe API http://$probe_listen  vite http://127.0.0.1:3401/"
npm run dev

#!/usr/bin/env bash
# ============================================================
# RETRO_INTEL one-command dev startup
#   - Backend:  FastAPI on http://127.0.0.1:8000
#   - Frontend: Vite on     http://127.0.0.1:5173
# Logs are written to backend.log / frontend.log in the repo root.
# Stop everything with ./stop_dev.sh
# ============================================================
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- 1. Backend -------------------------------------------------
port_in_use() { netstat -ano 2>/dev/null | grep -E ":$1\s" | grep -i LISTEN >/dev/null 2>&1; }

if port_in_use 8000; then
  echo "[start] Backend already running on :8000 (skipping)"
else
  cd "$ROOT/backend"
  # Prefer the venv, but fall back to system python if venv is missing uvicorn.
  PY=""
  if [ -x "venv/Scripts/python.exe" ] && "venv/Scripts/python.exe" -c "import uvicorn" >/dev/null 2>&1; then
    PY="venv/Scripts/python.exe"
  elif [ -x "venv/bin/python" ] && "venv/bin/python" -c "import uvicorn" >/dev/null 2>&1; then
    PY="venv/bin/python"
  else
    PY="python"
  fi
  echo "[start] Backend using: $PY"
  nohup "$PY" -m uvicorn main:app --host 127.0.0.1 --port 8000 > "$ROOT/backend.log" 2>&1 < /dev/null &
fi

# --- 2. Frontend ------------------------------------------------
if port_in_use 5173; then
  echo "[start] Frontend already running on :5173 (skipping)"
else
  cd "$ROOT/front_end"
  echo "[start] Frontend: npm run dev"
  nohup npm run dev > "$ROOT/frontend.log" 2>&1 < /dev/null &
fi

# --- 3. Wait for both servers -----------------------------------
echo "[start] Waiting for backend on :8000 ..."
for _ in $(seq 1 60); do
  if curl -s -o /dev/null http://127.0.0.1:8000/api/v1/features; then
    echo "[start] Backend ready  -> http://127.0.0.1:8000"
    break
  fi
  sleep 1
done

echo "[start] Waiting for frontend on :5173 ..."
for _ in $(seq 1 60); do
  if curl -s -o /dev/null http://127.0.0.1:5173/; then
    echo "[start] Frontend ready -> http://127.0.0.1:5173"
    break
  fi
  sleep 1
done

# --- 4. Open the dashboard --------------------------------------
if command -v xdg-open >/dev/null 2>&1; then
  xdg-open "http://127.0.0.1:5173"
elif command -v open >/dev/null 2>&1; then
  open "http://127.0.0.1:5173"
elif command -v explorer.exe >/dev/null 2>&1; then
  explorer.exe "http://127.0.0.1:5173"
else
  echo "[start] Open http://127.0.0.1:5173 in your browser"
fi

echo "[start] Done. Logs: backend.log / frontend.log (stop with ./stop_dev.sh)"
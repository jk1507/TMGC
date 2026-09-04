#!/usr/bin/env bash
# Stops the dev servers started by ./start_dev.sh (ports 8000 and 5173).
set -u

echo "[stop] Stopping backend  (:8000) ..."
for pid in $(netstat -ano 2>/dev/null | grep ":8000" | grep LISTENING | awk '{print $NF}' | sort -u); do
  taskkill //F //PID "$pid" 2>/dev/null || kill "$pid" 2>/dev/null
done

echo "[stop] Stopping frontend (:5173) ..."
for pid in $(netstat -ano 2>/dev/null | grep ":5173" | grep LISTENING | awk '{print $NF}' | sort -u); do
  taskkill //F //PID "$pid" 2>/dev/null || kill "$pid" 2>/dev/null
done

echo "[stop] Done."
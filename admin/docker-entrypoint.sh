#!/bin/sh
set -eu

find /app/vpn/admin -type d -name "__pycache__" -prune -exec rm -rf {} + 2>/dev/null || true

python -m flask --app app wait-services
python -m flask --app app init-db

if [ "$#" -eq 0 ]; then
  if [ "${ADMIN_SERVER:-simple}" = "gunicorn" ]; then
    exec gunicorn \
      -w "${GUNICORN_WORKERS:-1}" \
      --threads "${GUNICORN_THREADS:-2}" \
      --timeout "${GUNICORN_TIMEOUT:-120}" \
      -b "0.0.0.0:${PORT:-8088}" \
      wsgi:app
  fi
  exec python app.py
fi

exec "$@"

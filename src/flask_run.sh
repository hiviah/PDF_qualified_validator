#!/usr/bin/env bash
#
# Run the SigViewer web app with Flask's built-in development server:
#   * unprivileged port 8080 (override with $PORT)
#   * multithreaded  (--with-threads): polling + the background job run together
#   * debug mode     (--debug): auto-reloader + interactive in-browser debugger
#
# Development only. For production run the SAME app under a real WSGI server:
#   gunicorn -w 1 --threads 8 webapp:app          # Linux, typically behind nginx
#   waitress-serve --port=8080 webapp:app          # cross-platform, no nginx
#
set -euo pipefail

export FLASK_APP=webapp
export PORT="${PORT:-8080}"

exec flask run --host 127.0.0.1 --port "${PORT}" --debug --with-threads

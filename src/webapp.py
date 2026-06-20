#!/usr/bin/env python3
"""
SigViewer web interface
=======================
A single-page Flask app that wraps the Qt-free core: upload a PDF, run
``build_signature_data`` on a background thread, poll progress every 500 ms,
and render the same opaque display tree the PyQt GUI shows.

This module exposes a standard WSGI ``app`` object, so the *same code* runs
under Flask's dev server and under a production server with no changes:

    Development (auto-reload + debugger):   ./flask_run.sh
                                            (or: python webapp.py)
    Production (Linux, behind nginx):       gunicorn -w 1 --threads 8 webapp:app
    Production (cross-platform, no nginx):  waitress-serve --port=8080 webapp:app

NOTE on workers: job state is kept in-process, so run the production server
with a SINGLE worker process and multiple THREADS (``-w 1 --threads N``).
Multiple worker *processes* wouldn't share the job dictionary, so a poll could
hit a worker that never saw the job.
"""

from __future__ import annotations

import os
import time
import uuid
import tempfile
import threading

from flask import Flask, request, jsonify, abort, render_template
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

from check_eu_signatures import (
    build_signature_data, build_display_tree, default_cache_dir,
)
from i18n import _, install_language

# Activate the UI language once, at process start. SIGVIEWER_LANG (if set) wins;
# otherwise install_language(None) falls back to the server's $LANG/$LC_* env,
# and to English if no matching catalog exists. This is server-wide: a web
# server's locale is per-process, not per browser request.
install_language(os.environ.get("SIGVIEWER_LANG") or None)

app = Flask(__name__)
# Behind a trusted reverse proxy (nginx): honour X-Forwarded-* headers, so the
# app can be mounted under a subpath (X-Forwarded-Prefix) and generate correct
# URLs. Only enable this when actually behind a proxy you control.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
#: Reject uploads larger than this (bytes) — a simple abuse guard.
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB

#: Port used by the built-in dev server (override with $PORT).
PORT = int(os.environ.get("PORT", "8080"))

#: How long a finished/abandoned job is retained before pruning (seconds).
JOB_TTL = 600

# In-process job store: job_id -> dict(state, done, total, tree, error, created).
# Guarded by a lock because the dev/prod servers are multi-threaded.
_jobs: dict[str, dict] = {}
_jobs_lock = threading.Lock()


def _prune_jobs() -> None:
    """Drop jobs older than ``JOB_TTL`` so the store doesn't grow unbounded."""
    now = time.time()
    with _jobs_lock:
        stale = [jid for jid, j in _jobs.items() if now - j["created"] > JOB_TTL]
        for jid in stale:
            _jobs.pop(jid, None)


def _set(job_id: str, **fields) -> None:
    """Atomically update fields of a job if it still exists."""
    with _jobs_lock:
        if job_id in _jobs:
            _jobs[job_id].update(fields)


def _run_job(job_id: str, pdf_path: str, opts: dict) -> None:
    """Background worker: analyse the PDF and store the resulting display tree.

    Args:
        job_id: the job's id in ``_jobs``.
        pdf_path: temp file to analyse (deleted when done).
        opts: keyword options for ``build_signature_data``.
    """
    def progress(done: int, total: int) -> None:
        # total == 0 → indeterminate/busy phase (fetching the LOTL).
        _set(job_id, done=done, total=total)

    try:
        data = build_signature_data(pdf_path, progress=progress, **opts)
        _set(job_id, state="done", tree=build_display_tree(data))
    except Exception as e:  # noqa: BLE001 — surface any failure to the client
        _set(job_id, state="error", error=str(e))
    finally:
        try:
            os.unlink(pdf_path)
            os.rmdir(os.path.dirname(pdf_path))
        except OSError:
            pass


@app.get("/")
def index() -> str:
    """Serve the single-page UI (templates/index.html + static/ assets)."""
    return render_template(
        "index.html",
        t_open=_("Open PDF…"),
        t_validate=_("Validate against EU Trusted Lists"),
    )


@app.post("/analyze")
def analyze():
    """Accept a PDF upload, start a background analysis, return its job id."""
    _prune_jobs()
    f = request.files.get("pdf")
    if f is None or f.filename == "":
        abort(400, "No PDF uploaded.")

    # "validate" checkbox; unchecked → offline parse (no TL download).
    do_validate = request.form.get("validate", "true") != "false"

    # Save under the original (sanitised) basename inside a private temp dir, so
    # the "N signature(s) found in <name>" header shows the real filename.
    safe_name = secure_filename(f.filename) or "upload.pdf"
    if not safe_name.lower().endswith(".pdf"):
        safe_name += ".pdf"
    tmpdir = tempfile.mkdtemp(prefix="sigviewer-")
    path = os.path.join(tmpdir, safe_name)
    f.save(path)

    job_id = uuid.uuid4().hex
    with _jobs_lock:
        _jobs[job_id] = {
            "state": "running", "done": 0, "total": 0,
            "tree": None, "error": None, "created": time.time(),
        }

    opts = dict(do_validate=do_validate, cache_dir=default_cache_dir())
    threading.Thread(target=_run_job, args=(job_id, path, opts), daemon=True).start()
    return jsonify(job_id=job_id)


@app.get("/status/<job_id>")
def status(job_id: str):
    """Return a job's progress/result. Polled by the page every 500 ms."""
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            abort(404, "Unknown job.")
        resp = {k: job[k] for k in ("state", "done", "total", "error")}
        if job["state"] == "done":
            resp["tree"] = job["tree"]
    return jsonify(resp)

if __name__ == "__main__":
    # Flask's built-in dev server: threaded so polling and the background job
    # run concurrently; debug enables the reloader + interactive debugger.
    app.run(host="127.0.0.1", port=PORT, debug=True, threaded=True)
